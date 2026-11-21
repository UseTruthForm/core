package translate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

const (
	typPG  = "Microsoft.DBforPostgreSQL/flexibleServers"
	typSQL = "Microsoft.Sql/servers"
)

func subnetRef(group, vnet, sn string) string {
	return "{{truthform|ref|Microsoft.Network/virtualNetworks/subnets|" + group + "|" + vnet + "/" + sn + "|id}}"
}

func pgConf(server, name, value, source string) snapshot.Object {
	return az(typPG+"/configurations", "data", server+"/"+name, pr(map[string]any{"value": value, "source": source}))
}

func fw(typ, server, name, start, end string) snapshot.Object {
	return az(typ+"/firewallRules", "data", server+"/"+name, pr(map[string]any{"startIpAddress": start, "endIpAddress": end}))
}

// dbFixture is a made-up estate: a network with a subnet delegated to
// PostgreSQL, a private and a public PostgreSQL server, one the map does
// not size, a replica, and a public Azure SQL server with two databases;
// with children each rule reads, loses or refuses.
func dbFixture() snapshot.Snapshot {
	subnet := func(name, prefix string, extra map[string]any) map[string]any {
		p := map[string]any{"addressPrefix": prefix}
		for k, v := range extra {
			p[k] = v
		}
		return map[string]any{"name": name, "properties": p}
	}
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.Network/virtualNetworks", "net", "core", map[string]any{"location": "westeurope", "properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.20.0.0/16"}},
			"subnets": []any{
				subnet("app", "10.20.1.0/24", nil),
				subnet("db", "10.20.2.0/24", map[string]any{"delegations": []any{map[string]any{"name": "pg", "properties": map[string]any{"serviceName": "Microsoft.DBforPostgreSQL/flexibleServers"}}}}),
				subnet("db2", "10.20.3.0/24", nil),
			},
		}}),
		// Private, in its delegated subnet, encrypted with its own key.
		az(typPG, "data", "shop-pg", map[string]any{"location": "westeurope", "tags": map[string]any{"env": "dev", "Cost Center": "42"},
			"sku":      map[string]any{"name": "Standard_D2ds_v5", "tier": "GeneralPurpose"},
			"identity": map[string]any{"type": "UserAssigned", "userAssignedIdentities": map[string]any{"x": map[string]any{}}},
			"properties": map[string]any{
				"administratorLogin": "shopadmin", "version": "16",
				"storage":        map[string]any{"storageSizeGB": 128, "autoGrow": "Enabled", "tier": "P10", "iops": 500, "type": "Premium_LRS"},
				"authConfig":     map[string]any{"activeDirectoryAuth": "Enabled", "passwordAuth": "Enabled", "tenantId": "t"},
				"dataEncryption": map[string]any{"type": "AzureKeyVault", "primaryKeyURI": "https://kv.example/keys/pg"},
				"backup":         map[string]any{"backupRetentionDays": 14, "geoRedundantBackup": "Enabled"},
				"network": map[string]any{"publicNetworkAccess": "Disabled", "delegatedSubnetResourceId": subnetRef("net", "core", "db"),
					"privateDnsZoneArmResourceId": "{{truthform|ref|Microsoft.Network/privateDnsZones|net|shop.postgres.database.azure.com|id}}"},
				"highAvailability":  map[string]any{"mode": "ZoneRedundant"},
				"maintenanceWindow": map[string]any{"customWindow": "Disabled"},
				"replicationRole":   "Primary",
			}}),
		pgConf("shop-pg", "require_secure_transport", "on", "system-default"),
		pgConf("shop-pg", "max_connections", "859", "system-default"),
		pgConf("shop-pg", "work_mem", "8192", "user-override"),
		pgConf("shop-pg", "log_connections", "on", "user-override"),
		pgConf("shop-pg", "shared_preload_libraries", "pg_stat_statements", "user-override"),
		pgConf("shop-pg", "password_encryption", "scram-sha-256", "user-override"),
		pgConf("shop-pg", "azure.extensions", "PGCRYPTO,UUID-OSSP", "user-override"),
		pgConf("shop-pg", "made_up_param", "x", "user-override"),
		pgConf("shop-pg", "pgaudit.log", "ddl", "user-override"),
		az(typPG+"/databases", "data", "shop-pg/orders", pr(map[string]any{"charset": "UTF8", "collation": "en_US.utf8"})),
		az(typPG+"/databases", "data", "shop-pg/postgres", pr(map[string]any{"charset": "UTF8", "collation": "en_US.utf8"})),
		az(typPG+"/administrators", "data", "shop-pg/00000000-0000-0000-0000-000000000001", pr(map[string]any{"principalType": "Group", "principalName": "dba"})),
		az(typPG+"/advancedThreatProtectionSettings", "data", "shop-pg/Default", pr(map[string]any{"state": "Enabled"})),
		az(typPG+"/backups", "data", "shop-pg/before-upgrade", pr(nil)),
		// Public, behind its firewall, plain text allowed.
		az(typPG, "data", "reports-pg", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Standard_B2s", "tier": "Burstable"},
			"properties": map[string]any{
				"administratorLogin": "reports", "version": "15",
				"storage":          map[string]any{"storageSizeGB": 64, "autoGrow": "Disabled"},
				"backup":           map[string]any{"backupRetentionDays": 7, "geoRedundantBackup": "Disabled"},
				"network":          map[string]any{"publicNetworkAccess": "Enabled"},
				"highAvailability": map[string]any{"mode": "Disabled"},
			}}),
		pgConf("reports-pg", "require_secure_transport", "off", "user-override"),
		fw(typPG, "reports-pg", "office", "203.0.113.0", "203.0.113.255"),
		fw(typPG, "reports-pg", "home", "198.51.100.7", "198.51.100.7"),
		fw(typPG, "reports-pg", "partner", "192.0.2.10", "192.0.2.20"),
		fw(typPG, "reports-pg", "AllowAllAzureServicesAndResourcesWithinAzureIps", "0.0.0.0", "0.0.0.0"),
		// One the map does not size, and a replica.
		az(typPG, "data", "legacy-pg", map[string]any{"sku": map[string]any{"name": "Standard_D4ds_v5", "tier": "GeneralPurpose"},
			"properties": map[string]any{"administratorLogin": "legacy", "version": "16", "storage": map[string]any{"storageSizeGB": 32}, "network": map[string]any{"publicNetworkAccess": "Enabled"}}}),
		az(typPG, "data", "shop-pg-replica", map[string]any{"properties": map[string]any{"version": "16", "replicationRole": "AsyncReplica",
			"sourceServerResourceId": "{{truthform|ref|Microsoft.DBforPostgreSQL/flexibleServers|data|shop-pg|id}}"}}),
		// Azure SQL: public, a firewall range, the Azure services rule and
		// a subnet; soft delete; Entra ID admins beside SQL logins.
		az(typSQL, "data", "shop-sql", map[string]any{"location": "westeurope", "tags": map[string]any{"env": "dev"},
			"properties": map[string]any{
				"administratorLogin": "sqladmin", "version": "12.0", "minimalTlsVersion": "1.2", "publicNetworkAccess": "Enabled",
				"administrators":                map[string]any{"administratorType": "ActiveDirectory", "login": "dba-group", "sid": "s", "tenantId": "t", "azureADOnlyAuthentication": false},
				"restrictOutboundNetworkAccess": "Disabled", "retentionDays": 7,
			}}),
		fw(typSQL, "shop-sql", "office", "203.0.113.0", "203.0.113.255"),
		fw(typSQL, "shop-sql", "AllowAllWindowsAzureIps", "0.0.0.0", "0.0.0.0"),
		az(typSQL+"/virtualNetworkRules", "data", "shop-sql/app", pr(map[string]any{"virtualNetworkSubnetId": subnetRef("net", "core", "app"), "ignoreMissingVnetServiceEndpoint": false})),
		az(typSQL+"/databases", "data", "shop-sql/master", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "System"}, "properties": map[string]any{"maxSizeBytes": 32 << 30}}),
		az(typSQL+"/databases", "data", "shop-sql/catalog", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "S0", "tier": "Standard"},
			"properties": map[string]any{"maxSizeBytes": 250 << 30, "collation": "SQL_Latin1_General_CP1_CI_AS", "catalogCollation": "SQL_Latin1_General_CP1_CI_AS",
				"zoneRedundant": false, "readScale": "Disabled", "requestedBackupStorageRedundancy": "Local", "licenseType": "LicenseIncluded"}}),
		az(typSQL+"/databases", "data", "shop-sql/orders", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "GP_Gen5_2", "tier": "GeneralPurpose"},
			"properties": map[string]any{"maxSizeBytes": 32 << 30, "collation": "SQL_Latin1_General_CP1_CI_AS", "zoneRedundant": false,
				"requestedBackupStorageRedundancy": "Geo", "isLedgerOn": true}}),
		az(typSQL+"/databases/backupShortTermRetentionPolicies", "data", "shop-sql/catalog/default", pr(map[string]any{"retentionDays": 14, "diffBackupIntervalInHours": 12})),
		az(typSQL+"/databases/backupShortTermRetentionPolicies", "data", "shop-sql/orders/default", pr(map[string]any{"retentionDays": 7, "diffBackupIntervalInHours": 12})),
		az(typSQL+"/databases/transparentDataEncryption", "data", "shop-sql/catalog/current", pr(map[string]any{"state": "Enabled"})),
		az(typSQL+"/auditingSettings", "data", "shop-sql/default", pr(map[string]any{"state": "Enabled", "retentionDays": 30, "isAzureMonitorTargetEnabled": true})),
		az(typSQL+"/securityAlertPolicies", "data", "shop-sql/Default", pr(map[string]any{"state": "Disabled"})),
		az(typSQL+"/encryptionProtector", "data", "shop-sql/current", map[string]any{"kind": "servicemanaged", "properties": map[string]any{"serverKeyName": "ServiceManaged", "serverKeyType": "ServiceManaged"}}),
		az(typSQL+"/connectionPolicies", "data", "shop-sql/default", pr(map[string]any{"connectionType": "Default"})),
		az(typSQL+"/elasticPools", "data", "shop-sql/pool1", map[string]any{"sku": map[string]any{"name": "StandardPool"}}),
		az(typSQL+"/failoverGroups", "data", "shop-sql/shop-fg", pr(nil)),
		az(typSQL+"/administrators", "data", "shop-sql/ActiveDirectory", pr(map[string]any{"login": "dba-group"})),
		az(typSQL+"/databases/advisors", "data", "shop-sql/catalog/CreateIndex", pr(nil)),
		az(typSQL+"/jobAgents/jobs", "data", "shop-sql/agent/nightly", pr(nil)),
	}}
}

func dbMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Zone: "eu-west-1a", Zones: map[string]string{"net/core/db2": "eu-west-1b"}}}
	a.Destinations.Network, a.Destinations.Databases = "vpc", "rds"
	a.Databases = map[string]DatabaseMap{
		"data/shop-pg":         {InstanceClass: "db.m6g.large", Subnets: []string{"net/core/db2"}, KMSKey: "arn:aws:kms:eu-west-1:222222222222:key/0f1e2d3c-made-up"},
		"data/reports-pg":      {InstanceClass: "db.t4g.medium", Subnets: []string{"net/core/app", "net/core/db2"}},
		"data/shop-pg-replica": {InstanceClass: "db.m6g.large"},
		"data/shop-sql": {InstanceClass: "db.m6i.xlarge", Edition: "sqlserver-se", LicenseModel: "license-included", Version: "16.00.4185.3.v1",
			Subnets: []string{"net/core/app", "net/core/db2"}},
	}
	g := Map{To: "gcp", Region: "europe-west1"}
	g.Destinations.Network, g.Destinations.Databases = "vpc", "cloud-sql"
	g.Databases = map[string]DatabaseMap{
		"data/shop-pg":    {Tier: "db-custom-2-8192", KMSKey: "projects/keys/locations/europe-west1/keyRings/db/cryptoKeys/shop-pg"},
		"data/reports-pg": {Tier: "db-custom-1-3840"},
		"data/shop-sql":   {Tier: "db-custom-4-16384", Version: "SQLSERVER_2022_STANDARD"},
	}
	return map[string]Map{"aws": a, "gcp": g}
}

func runDB(t *testing.T, s snapshot.Snapshot, m Map) Result {
	t.Helper()
	r, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ruleStrings(t *testing.T, r Result, sg string) []string {
	t.Helper()
	var got []string
	for _, x := range list(object(t, r, "aws", awsSG, sg)["SecurityGroupIngress"]) {
		m := obj(x)
		got = append(got, fmt.Sprintf("%v/%v-%v %v", m["IpProtocol"], m["FromPort"], m["ToPort"], m["CidrIp"]))
	}
	sort.Strings(got)
	return got
}

func TestDatabaseGolden(t *testing.T) {
	for name, m := range dbMaps() {
		r := runDB(t, dbFixture(), m)
		golden(t, "databases-"+name, r)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
		}
		for _, o := range dbFixture().Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
	}
}

func TestPostgresToRDS(t *testing.T) {
	r := runDB(t, dbFixture(), dbMaps()["aws"])
	db := object(t, r, "aws", awsDB, "shop-pg")
	for k, want := range map[string]any{
		"Engine": "postgres", "EngineVersion": "16", "DBInstanceClass": "db.m6g.large", "AllocatedStorage": "128",
		"MaxAllocatedStorage": azPGMaxStorageGB, "BackupRetentionPeriod": 14, "MultiAZ": true, "StorageEncrypted": true,
		"KmsKeyId": "arn:aws:kms:eu-west-1:222222222222:key/0f1e2d3c-made-up", "PubliclyAccessible": false,
		"ManageMasterUserPassword": true, "MasterUsername": "shopadmin",
		"DBSubnetGroupName":    awsRef(awsDBSubnets, "shop-pg-subnets", "identifier"),
		"DBParameterGroupName": awsRef(awsDBParams, "shop-pg-params", "identifier"),
	} {
		if fmt.Sprint(db[k]) != fmt.Sprint(want) {
			t.Errorf("shop-pg %s: %v, want %v", k, db[k], want)
		}
	}
	for _, k := range []string{"MasterUserPassword", "DeletionProtection", "AvailabilityZone"} {
		if _, ok := db[k]; ok {
			t.Errorf("shop-pg sets %s", k)
		}
	}
	// Its delegated subnet and the map's second, in two zones.
	if ids := fmt.Sprint(object(t, r, "aws", awsDBSubnets, "shop-pg-subnets")["SubnetIds"]); ids != fmt.Sprint([]any{awsRef(awsSN, "core-db2", "SubnetId"), awsRef(awsSN, "core-db", "SubnetId")}) {
		t.Errorf("subnets: %s", ids)
	}
	// Private: the network reaches its port, and nothing else does.
	if got := ruleStrings(t, r, "shop-pg-db"); strings.Join(got, ",") != "tcp/5432-5432 10.20.0.0/16" {
		t.Errorf("shop-pg ingress: %v", got)
	}
	ps := obj(object(t, r, "aws", awsDBParams, "shop-pg-params")["Parameters"])
	want := map[string]any{"rds.force_ssl": "1", "ssl_min_protocol_version": "TLSv1.2", "work_mem": "8192", "log_connections": "1",
		"shared_preload_libraries": "pg_stat_statements", "password_encryption": "scram-sha-256"}
	if canonJSON(ps) != canonJSON(want) {
		t.Errorf("parameters: %v", ps)
	}
	if f := object(t, r, "aws", awsDBParams, "shop-pg-params")["Family"]; f != "postgres16" {
		t.Errorf("family %v", f)
	}
	if l := hasLoss(entry(t, r, typPG+"/configurations data/shop-pg/made_up_param"), "properties.value"); l == nil || l.Widens {
		t.Errorf("an unknown parameter: %+v", l)
	}
	if e := entry(t, r, typPG+"/configurations data/shop-pg/max_connections"); len(e.Losses) != 0 || !strings.Contains(e.Reason, "default") {
		t.Errorf("a default: %+v", e)
	}
	// Public: its firewall's ranges exactly, never Azure's services.
	rp := object(t, r, "aws", awsDB, "reports-pg")
	if rp["PubliclyAccessible"] != true || rp["MaxAllocatedStorage"] != nil || rp["DBParameterGroupName"] != nil || rp["MultiAZ"] != false {
		t.Errorf("reports-pg: %v", rp)
	}
	got := ruleStrings(t, r, "reports-pg-db")
	wantR := []string{"tcp/5432-5432 192.0.2.10/31", "tcp/5432-5432 192.0.2.12/30", "tcp/5432-5432 192.0.2.16/30", "tcp/5432-5432 192.0.2.20/32",
		"tcp/5432-5432 198.51.100.7/32", "tcp/5432-5432 203.0.113.0/24"}
	if strings.Join(got, ",") != strings.Join(wantR, ",") {
		t.Errorf("reports-pg ingress:\n%v\nwant\n%v", got, wantR)
	}
	if l := lossAbout(entry(t, r, typPG+"/firewallRules data/reports-pg/AllowAll"), "every Azure service"); l == nil || l.Widens {
		t.Errorf("the Azure services rule: %+v", l)
	}
	if !anyRequirement(r, "internet gateway") || !anyRequirement(r, "Secrets Manager") || !anyRequirement(r, "Create database orders (UTF8, en_US.utf8)") ||
		!anyRequirement(r, "pgcrypto, uuid-ossp") || !anyRequirement(r, "Microsoft Entra ID") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
	if anyRequirement(r, "database postgres") {
		t.Error("Azure's own database is to be created")
	}
	e := entry(t, r, typPG+" data/shop-pg")
	if l := hasLoss(e, "properties.backup.geoRedundantBackup"); l == nil || l.Widens {
		t.Errorf("geo backup: %+v", l)
	}
	if hasLoss(e, "properties.dataEncryption") != nil {
		t.Error("a key the map names is lost")
	}
}

func TestPostgresToCloudSQL(t *testing.T) {
	r := runDB(t, dbFixture(), dbMaps()["gcp"])
	in := object(t, r, "gcp", gcpSQL, gcpProject+"/instances/shop-pg")
	st := obj(in["settings"])
	if in["databaseVersion"] != "POSTGRES_16" || in["region"] != "europe-west1" || st["tier"] != "db-custom-2-8192" || st["edition"] != "ENTERPRISE" ||
		st["dataDiskSizeGb"] != "128" || st["storageAutoResize"] != true || st["availabilityType"] != "REGIONAL" {
		t.Errorf("shop-pg: %v", in)
	}
	bc := obj(st["backupConfiguration"])
	if bc["transactionLogRetentionDays"] != 7 || obj(bc["backupRetentionSettings"])["retainedBackups"] != 14 || bc["pointInTimeRecoveryEnabled"] != true {
		t.Errorf("backups: %v", bc)
	}
	if l := hasLoss(entry(t, r, typPG+" data/shop-pg"), "backup retention"); l == nil || l.Widens {
		t.Errorf("a shorter point-in-time window: %+v", l)
	}
	ip := obj(st["ipConfiguration"])
	if ip["ipv4Enabled"] != false || ip["privateNetwork"] != gcpProject+"/global/networks/core" || ip["sslMode"] != "ENCRYPTED_ONLY" || ip["authorizedNetworks"] != nil {
		t.Errorf("shop-pg ip: %v", ip)
	}
	if k := obj(in["diskEncryptionConfiguration"])["kmsKeyName"]; k != dbMaps()["gcp"].Databases["data/shop-pg"].KMSKey {
		t.Errorf("key: %v", k)
	}
	flags := canonJSON(st["databaseFlags"])
	if flags != `[{"name":"log_connections","value":"on"},{"name":"work_mem","value":"8192"}]` {
		t.Errorf("flags: %s", flags)
	}
	if l := hasLoss(entry(t, r, typPG+"/configurations data/shop-pg/password_encryption"), "properties.value"); l == nil || !l.Widens {
		t.Errorf("a password setting Cloud SQL cannot take: %+v", l)
	}
	if l := hasLoss(entry(t, r, typPG+"/configurations data/shop-pg/shared_preload_libraries"), "properties.value"); l == nil || l.Widens {
		t.Errorf("preload libraries: %+v", l)
	}
	if labels := canonJSON(st["userLabels"]); labels != `{"env":"dev"}` {
		t.Errorf("labels: %s", labels)
	}
	if l := hasLoss(entry(t, r, typPG+" data/shop-pg"), "tags.Cost Center"); l == nil {
		t.Error("a tag that is no label is not named")
	}
	rp := obj(object(t, r, "gcp", gcpSQL, gcpProject+"/instances/reports-pg")["settings"])
	rip := obj(rp["ipConfiguration"])
	if rip["ipv4Enabled"] != true || rip["sslMode"] != nil || rp["storageAutoResize"] != false || rp["availabilityType"] != "ZONAL" {
		t.Errorf("reports-pg: %v", rp)
	}
	var nets []string
	for _, x := range list(rip["authorizedNetworks"]) {
		nets = append(nets, fmt.Sprint(obj(x)["value"]))
	}
	sort.Strings(nets)
	if strings.Join(nets, ",") != "192.0.2.10/31,192.0.2.12/30,192.0.2.16/30,192.0.2.20/32,198.51.100.7/32,203.0.113.0/24" {
		t.Errorf("authorized networks: %v", nets)
	}
	if !anyRequirement(r, "Private services access") || !anyRequirement(r, "Create user shopadmin") || !anyRequirement(r, "cloudsql.instances.connect") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
}

func TestSQLServerToRDSAndCloudSQL(t *testing.T) {
	r := runDB(t, dbFixture(), dbMaps()["aws"])
	db := object(t, r, "aws", awsDB, "shop-sql")
	for k, want := range map[string]any{
		"Engine": "sqlserver-se", "EngineVersion": "16.00.4185.3.v1", "LicenseModel": "license-included", "AllocatedStorage": "282",
		"BackupRetentionPeriod": 14, "DeletionProtection": true, "MultiAZ": false, "PubliclyAccessible": true, "MasterUsername": "sqladmin",
	} {
		if fmt.Sprint(db[k]) != fmt.Sprint(want) {
			t.Errorf("shop-sql %s: %v, want %v", k, db[k], want)
		}
	}
	pg := object(t, r, "aws", awsDBParams, "shop-sql-params")
	if pg["Family"] != "sqlserver-se-16.0" || canonJSON(pg["Parameters"]) != `{"rds.force_ssl":"1","rds.tls10":"disabled","rds.tls11":"disabled"}` {
		t.Errorf("shop-sql parameters: %v", pg)
	}
	// The firewall range, and the subnet its virtual network rule named.
	if got := ruleStrings(t, r, "shop-sql-db"); strings.Join(got, ",") != "tcp/1433-1433 10.20.1.0/24,tcp/1433-1433 203.0.113.0/24" {
		t.Errorf("shop-sql ingress: %v", got)
	}
	if !anyRequirement(r, "Create database orders (SQL_Latin1_General_CP1_CI_AS, WITH LEDGER = ON)") || anyRequirement(r, "database master") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
	if l := hasLoss(entry(t, r, typSQL+"/databases data/shop-sql/orders"), "properties.requestedBackupStorageRedundancy"); l == nil || l.Widens {
		t.Errorf("geo backups: %+v", l)
	}
	g := runDB(t, dbFixture(), dbMaps()["gcp"])
	in := object(t, g, "gcp", gcpSQL, gcpProject+"/instances/shop-sql")
	st := obj(in["settings"])
	if in["databaseVersion"] != "SQLSERVER_2022_STANDARD" || st["dataDiskSizeGb"] != "282" || st["deletionProtectionEnabled"] != true ||
		obj(st["ipConfiguration"])["sslMode"] != "ENCRYPTED_ONLY" || st["storageAutoResize"] != false {
		t.Errorf("shop-sql: %v", in)
	}
	if nets := canonJSON(obj(st["ipConfiguration"])["authorizedNetworks"]); nets != `[{"name":"office","value":"203.0.113.0/24"}]` {
		t.Errorf("authorized networks: %s", nets)
	}
	if l := hasLoss(entry(t, g, typSQL+"/virtualNetworkRules data/shop-sql/app"), "properties.virtualNetworkSubnetId"); l == nil || l.Widens {
		t.Errorf("a subnet Cloud SQL's public IP cannot allow: %+v", l)
	}
	if !anyRequirement(g, "rootPassword") {
		t.Errorf("requirements: %v", g.Report.Requirements)
	}
}

// Every loss that leaves the target less protected is named as widening,
// and nothing else is.
func TestDatabaseWidens(t *testing.T) {
	want := map[string][]string{
		"aws": {
			typPG + "/advancedThreatProtectionSettings data/shop-pg/Default properties.state",
			typPG + "/configurations data/shop-pg/pgaudit.log properties.value",
			typSQL + "/auditingSettings data/shop-sql/default properties.state",
		},
		"gcp": {
			typPG + " data/shop-pg configurations/ssl_min_protocol_version",
			typPG + "/advancedThreatProtectionSettings data/shop-pg/Default properties.state",
			typPG + "/configurations data/shop-pg/password_encryption properties.value",
			typPG + "/configurations data/shop-pg/pgaudit.log properties.value",
			typSQL + " data/shop-sql properties.minimalTlsVersion",
			typSQL + "/auditingSettings data/shop-sql/default properties.state",
		},
	}
	for name, m := range dbMaps() {
		got := widening(runDB(t, dbFixture(), m))
		if strings.Join(got, "\n") != strings.Join(want[name], "\n") {
			t.Errorf("%s widens:\n%s\nwant\n%s", name, strings.Join(got, "\n"), strings.Join(want[name], "\n"))
		}
	}
	// A server's own key, with no key in the map.
	for name, m := range dbMaps() {
		d := m.Databases["data/shop-pg"]
		d.KMSKey = ""
		m.Databases["data/shop-pg"] = d
		if l := hasLoss(entry(t, runDB(t, dbFixture(), m), typPG+" data/shop-pg"), "properties.dataEncryption"); l == nil || !l.Widens {
			t.Errorf("%s: the customer's key: %+v", name, l)
		}
	}
	// TLS 1.3 only: RDS for SQL Server takes 1.2 as well.
	s := dbFixture()
	setProp(s, typSQL, "shop-sql", "minimalTlsVersion", "1.3")
	if l := hasLoss(entry(t, runDB(t, s, dbMaps()["aws"]), typSQL+" data/shop-sql"), "properties.minimalTlsVersion"); l == nil || !l.Widens {
		t.Errorf("TLS 1.3: %+v", l)
	}
	// Immutable backups, FIPS, an outbound restriction.
	s = dbFixture()
	obj(obj(spec(find(s, typPG, "shop-pg"))["properties"])["backup"])["immutableBackup"] = "Enabled"
	setProp(s, typPG, "shop-pg", "fipsMode", "Enabled")
	setProp(s, typSQL, "shop-sql", "restrictOutboundNetworkAccess", "Enabled")
	for name, m := range dbMaps() {
		r := runDB(t, s, m)
		for src, f := range map[string]string{typPG + " data/shop-pg": "properties.backup.immutableBackup", typPG + " data/shop-pg ": "properties.fipsMode", typSQL + " data/shop-sql": "properties.restrictOutboundNetworkAccess"} {
			if l := hasLoss(entry(t, r, strings.TrimSpace(src)), f); l == nil || !l.Widens {
				t.Errorf("%s: %s: %+v", name, f, l)
			}
		}
	}
}

func widening(r Result) []string {
	var out []string
	for _, e := range r.Report.Entries {
		for _, l := range e.Losses {
			if l.Widens {
				out = append(out, e.Source+" "+l.Field)
			}
		}
	}
	sort.Strings(out)
	return out
}

func find(s snapshot.Snapshot, kind, name string) snapshot.Object {
	for _, o := range s.Objects {
		if o.Kind() == kind && o.Name() == name {
			return o
		}
	}
	panic(kind + " " + name)
}

func setProp(s snapshot.Snapshot, kind, name, k string, v any) {
	obj(spec(find(s, kind, name))["properties"])[k] = v
}

// What the map does not choose is refused, naming the key, never filled
// in; what has no target is refused with its reason.
func TestDatabasesNeedTheirChoices(t *testing.T) {
	for name, m := range dbMaps() {
		r := runDB(t, dbFixture(), m)
		size := map[string]string{"aws": "databases.data/legacy-pg.instanceClass", "gcp": "databases.data/legacy-pg.tier"}[name]
		if e := entry(t, r, typPG+" data/legacy-pg"); e.State != Refused || !strings.Contains(e.Reason, size) || !strings.Contains(e.Reason, "Standard_D4ds_v5 (GeneralPurpose)") {
			t.Errorf("%s: no size: %s %s", name, e.State, e.Reason)
		}
		if e := entry(t, r, typPG+" data/shop-pg-replica"); e.State != Refused || !strings.Contains(e.Reason, "replica") {
			t.Errorf("%s: replica: %s %s", name, e.State, e.Reason)
		}
		for src, why := range map[string]string{
			typPG + "/administrators data/shop-pg/":     "identity",
			typSQL + "/administrators data/shop-sql/":   "identity",
			typPG + "/backups data/shop-pg/":            "data, which is not moved",
			typSQL + "/elasticPools data/shop-sql/":     "elastic pool has no peer",
			typSQL + "/failoverGroups data/shop-sql/":   "not translated yet",
			typSQL + "/jobAgents/jobs data/shop-sql/":   "Elastic Jobs",
			typSQL + "/databases/advisors data/shop-sq": "no descriptor",
		} {
			if e := entry(t, r, src); (e.State != Refused && e.State != NotLooked) || !strings.Contains(e.Reason, why) {
				t.Errorf("%s: %s: %s %s", name, src, e.State, e.Reason)
			}
		}
		// The children of a refused server are refused with it.
		if e := entry(t, r, typPG+"/firewallRules data/reports-pg/office"); e.State == Refused {
			t.Errorf("%s: a child of a mapped server is refused", name)
		}
		if !r.Report.Failed() {
			t.Errorf("%s: a translation with refusals is not failed", name)
		}
	}
	none := Map{To: "aws", Region: "eu-west-1"}
	r := runDB(t, dbFixture(), none)
	if e := entry(t, r, typPG+" data/shop-pg"); e.State != Refused || !strings.Contains(e.Reason, "destinations.databases") {
		t.Errorf("no destination: %s %s", e.State, e.Reason)
	}
	if e := entry(t, r, typPG+"/databases data/shop-pg/orders"); e.State != Refused || !strings.Contains(e.Reason, "is refused") {
		t.Errorf("a child of a refused server: %s %s", e.State, e.Reason)
	}
	// SQL Server's choices, one at a time.
	for field, clear := range map[string]func(*DatabaseMap){
		"edition":      func(d *DatabaseMap) { d.Edition = "" },
		"licenseModel": func(d *DatabaseMap) { d.LicenseModel = "" },
		"version":      func(d *DatabaseMap) { d.Version = "" },
	} {
		m := dbMaps()["aws"]
		d := m.Databases["data/shop-sql"]
		clear(&d)
		m.Databases["data/shop-sql"] = d
		if e := entry(t, runDB(t, dbFixture(), m), typSQL+" data/shop-sql"); e.State != Refused || !strings.Contains(e.Reason, "databases.data/shop-sql."+field) {
			t.Errorf("no %s: %s %s", field, e.State, e.Reason)
		}
	}
	g := dbMaps()["gcp"]
	d := g.Databases["data/shop-sql"]
	d.Version = ""
	g.Databases["data/shop-sql"] = d
	if e := entry(t, runDB(t, dbFixture(), g), typSQL+" data/shop-sql"); e.State != Refused || !strings.Contains(e.Reason, "databases.data/shop-sql.version") {
		t.Errorf("gcp no version: %s %s", e.State, e.Reason)
	}
	// One zone only: RDS needs two.
	a := dbMaps()["aws"]
	a.Network.Zones = nil
	if e := entry(t, runDB(t, dbFixture(), a), typPG+" data/shop-pg"); e.State != Refused || !strings.Contains(e.Reason, "two availability zones") || !strings.Contains(e.Reason, "databases.data/shop-pg.subnets") {
		t.Errorf("one zone: %s %s", e.State, e.Reason)
	}
	// Public on AWS with no subnets: no VPC to hold its security group.
	a = dbMaps()["aws"]
	d = a.Databases["data/reports-pg"]
	d.Subnets = nil
	a.Databases["data/reports-pg"] = d
	if e := entry(t, runDB(t, dbFixture(), a), typPG+" data/reports-pg"); e.State != Refused || !strings.Contains(e.Reason, "databases.data/reports-pg.subnets") {
		t.Errorf("public with no subnets: %s %s", e.State, e.Reason)
	}
	// Private with no subnet anywhere.
	s := dbFixture()
	delete(obj(obj(spec(find(s, typPG, "shop-pg"))["properties"])["network"]), "delegatedSubnetResourceId")
	g = dbMaps()["gcp"]
	if e := entry(t, runDB(t, s, g), typPG+" data/shop-pg"); e.State != Refused || !strings.Contains(e.Reason, "reached privately") {
		t.Errorf("private with no subnet: %s %s", e.State, e.Reason)
	}
	// A subnet the snapshot does not have.
	a = dbMaps()["aws"]
	d = a.Databases["data/shop-pg"]
	d.Subnets = []string{"net/other/db"}
	a.Databases["data/shop-pg"] = d
	if e := entry(t, runDB(t, dbFixture(), a), typPG+" data/shop-pg"); e.State != Refused || !strings.Contains(e.Reason, "net/other/db is not a subnet") {
		t.Errorf("a missing subnet: %s %s", e.State, e.Reason)
	}
	// A version the target does not offer, and Entra ID sign-in only.
	s = dbFixture()
	setProp(s, typPG, "shop-pg", "version", "12")
	obj(obj(spec(find(s, typPG, "reports-pg"))["properties"]))["authConfig"] = map[string]any{"activeDirectoryAuth": "Enabled", "passwordAuth": "Disabled"}
	r = runDB(t, s, dbMaps()["aws"])
	if e := entry(t, r, typPG+" data/shop-pg"); e.State != Refused || !strings.Contains(e.Reason, `"12" is not a version RDS offers`) {
		t.Errorf("PostgreSQL 12: %s %s", e.State, e.Reason)
	}
	if e := entry(t, r, typPG+" data/reports-pg"); e.State != Refused || !strings.Contains(e.Reason, "Entra ID sign-in only") {
		t.Errorf("Entra ID only: %s %s", e.State, e.Reason)
	}
	// Choices that do not go with the target.
	bad := map[string]func(*Map){
		"databases with no destination": func(m *Map) { m.Destinations.Databases = "" },
		"rds on gcp":                    func(m *Map) { m.To = "gcp"; m.Network = nil },
		"a tier on aws":                 func(m *Map) { m.Databases["x/y"] = DatabaseMap{Tier: "db-custom-1-3840"} },
		"an unknown edition":            func(m *Map) { m.Databases["x/y"] = DatabaseMap{Edition: "sqlserver-dev"} },
		"a class that is none":          func(m *Map) { m.Databases["x/y"] = DatabaseMap{InstanceClass: "m6g.large"} },
		"a subnet that is no subnet":    func(m *Map) { m.Databases["x/y"] = DatabaseMap{Subnets: []string{"db"}} },
		"an unknown destination":        func(m *Map) { m.Destinations.Databases = "aurora" },
	}
	for what, f := range bad {
		m := dbMaps()["aws"]
		f(&m)
		if _, err := Translate(dbFixture(), m, targets(t)); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	g = dbMaps()["gcp"]
	g.Databases["x/y"] = DatabaseMap{InstanceClass: "db.m6g.large"}
	if _, err := Translate(dbFixture(), g, targets(t)); err == nil {
		t.Error("an instance class on gcp: accepted")
	}
}

// A delegated subnet behind an NSG: on AWS the instance takes the NSG's
// security group; on GCP nothing filters on the instance's side.
func TestDelegatedSubnetNSG(t *testing.T) {
	s := dbFixture()
	vn := obj(spec(find(s, "Microsoft.Network/virtualNetworks", "core"))["properties"])
	obj(list(vn["subnets"])[1])["properties"].(map[string]any)["networkSecurityGroup"] = nsgRef("net", "db-nsg")
	s.Objects = append(s.Objects, az("Microsoft.Network/networkSecurityGroups", "net", "db-nsg", map[string]any{"location": "westeurope",
		"properties": map[string]any{"securityRules": []any{rule("deny-app", "Deny", "Inbound", 100, "*", "10.20.1.0/24", "*", "*")}}}))
	r := runDB(t, s, dbMaps()["aws"])
	if sg := object(t, r, "aws", awsDB, "shop-pg")["VPCSecurityGroups"]; fmt.Sprint(sg) != fmt.Sprint([]any{awsRef(awsSG, "db-nsg", "GroupId")}) {
		t.Errorf("shop-pg's security groups: %v", sg)
	}
	for _, o := range r.Snapshots["aws"].Objects {
		if o.Kind() == awsSG && o.Name() == "shop-pg-db" {
			t.Error("a security group of its own beside the NSG's")
		}
	}
	g := runDB(t, s, dbMaps()["gcp"])
	if l := hasLoss(entry(t, g, typPG+" data/shop-pg"), "properties.network.delegatedSubnetResourceId"); l == nil || !l.Widens {
		t.Errorf("gcp: %+v", l)
	}
}

func TestDatabasesRestore(t *testing.T) {
	tg := targets(t)
	s := runDB(t, dbFixture(), dbMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("aws %s: %s", res.Key, res.Detail)
		}
	}
	if c := f.Count(); c[awsDB] != 3 || c[awsDBSubnets] != 3 || c[awsDBParams] != 2 || c[awsSG] != 3 {
		t.Errorf("aws created %v", c)
	}
	for _, id := range f.IDs(awsDB) {
		p := f.Stored(awsDB, id)
		if g, _ := p["DBSubnetGroupName"].(string); !strings.HasSuffix(g, "-subnets") {
			t.Errorf("%s's subnet group is %v", id, p["DBSubnetGroupName"])
		}
		for _, sg := range list(p["VPCSecurityGroups"]) {
			if !strings.HasPrefix(fmt.Sprint(sg), "securitygroup-") {
				t.Errorf("%s's security group is %v", id, sg)
			}
		}
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runDB(t, dbFixture(), dbMaps()["gcp"]).Snapshots["gcp"]
	gf := gcp.NewWorld(tg.GCP).Project("target-project", "123456789")
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK {
			t.Errorf("gcp %s: %s", res.Key, res.Detail)
		}
	}
	got, err := gf.Call(context.Background(), "GET", "https://sqladmin.googleapis.com/v1/projects/target-project/instances/shop-pg", nil)
	if err != nil || obj(obj(got["settings"])["ipConfiguration"])["privateNetwork"] != "projects/target-project/global/networks/core" {
		t.Errorf("shop-pg in the target: %v %v", got, err)
	}
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("gcp again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
}

// Every field a Cloud SQL instance is written with, at any depth, is one
// its Discovery schema declares and the server does not set: out.add
// checks the top level only.
func TestCloudSQLFieldsAreDeclared(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "gcp", "sqladmin_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc gcp.Doc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var walk func(path string, v any, s *gcp.Schema)
	walk = func(path string, v any, s *gcp.Schema) {
		for s != nil && s.Ref != "" {
			s = doc.Schemas[s.Ref]
		}
		switch c := v.(type) {
		case map[string]any:
			for k, x := range c {
				p := s.Properties[k]
				if p == nil && s.AdditionalProperties != nil {
					walk(path+"."+k, x, s.AdditionalProperties)
					continue
				}
				if p == nil {
					t.Errorf("%s.%s is not declared", path, k)
					continue
				}
				if p.ReadOnly || strings.HasPrefix(p.Description, "Output only") || strings.HasPrefix(p.Description, "[Output Only]") {
					t.Errorf("%s.%s is set by the server", path, k)
				}
				walk(path+"."+k, x, p)
			}
		case []any:
			for _, x := range c {
				walk(path+"[]", x, s.Items)
			}
		}
	}
	r := runDB(t, dbFixture(), dbMaps()["gcp"])
	for _, o := range r.Snapshots["gcp"].Objects {
		if o.Kind() == gcpSQL {
			walk(o.Name(), o.Body["spec"], &gcp.Schema{Ref: "DatabaseInstance"})
		}
	}
}
