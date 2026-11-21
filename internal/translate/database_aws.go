package translate

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Database servers on AWS: an RDS DB instance each, in a DB subnet group
// over the translated network's subnets, behind a security group that
// allows what the server's firewall allowed (or the NSG of its delegated
// subnet), with a parameter group for the server parameters RDS takes by
// the same name. The master password is never carried over: RDS makes one
// and keeps it in Secrets Manager.

const (
	awsDB        = "AWS::RDS::DBInstance"
	awsDBSubnets = "AWS::RDS::DBSubnetGroup"
	awsDBParams  = "AWS::RDS::DBParameterGroup"
)

var (
	rdsName = regexp.MustCompile(`^[a-z]([a-z0-9]|-[a-z0-9])*$`)
	// rdsPG are the PostgreSQL major versions RDS offers under standard
	// support; an older one is refused, not moved to a newer one.
	rdsPG = map[string]bool{"13": true, "14": true, "15": true, "16": true, "17": true}
)

// pgCommon are PostgreSQL's own parameters that RDS's parameter groups
// and Cloud SQL's database flags both take by the same name and meaning.
var pgCommon = []string{
	"work_mem", "maintenance_work_mem", "max_connections", "statement_timeout", "idle_in_transaction_session_timeout",
	"lock_timeout", "deadlock_timeout", "log_min_duration_statement", "log_statement", "log_connections", "log_disconnections",
	"log_lock_waits", "log_temp_files", "log_checkpoints", "log_autovacuum_min_duration", "random_page_cost",
	"default_statistics_target", "autovacuum", "autovacuum_vacuum_scale_factor", "autovacuum_analyze_scale_factor",
	"autovacuum_naptime", "autovacuum_max_workers", "autovacuum_vacuum_cost_limit", "autovacuum_vacuum_cost_delay",
	"track_activity_query_size", "track_io_timing", "pg_stat_statements.track", "temp_file_limit", "max_wal_size",
	"min_wal_size", "checkpoint_timeout", "max_parallel_workers_per_gather", "max_parallel_workers", "max_worker_processes",
	"max_locks_per_transaction", "max_prepared_transactions", "effective_cache_size",
}

var (
	rdsPGParams = names(append([]string{"shared_preload_libraries", "password_encryption", "shared_buffers", "wal_buffers",
		"timezone", "effective_io_concurrency", "default_transaction_isolation"}, pgCommon...))
	gcpPGFlags = names(pgCommon)
)

func names(l []string) map[string]bool {
	m := map[string]bool{}
	for _, n := range l {
		m[n] = true
	}
	return m
}

// guardedParam reports a parameter whose loss leaves the target less
// protected: how passwords are kept, what is audited.
func guardedParam(n string) bool {
	return n == "password_encryption" || strings.HasPrefix(n, "pgaudit.")
}

type rdsWriter struct{ m Map }

func (d rdsWriter) server(s *dbServer, o *out) (Entry, string) {
	key := s.mapKey()
	dm, _ := d.m.database(key)
	if dm.InstanceClass == "" {
		return Entry{}, fmt.Sprintf("the map gives no instance class for it (databases.%s.instanceClass): its Azure SKU, %s, names Azure's hardware, not an RDS size", key, s.sku)
	}
	name := d.m.name(s.src, strings.ToLower(s.name))
	if !rdsName.MatchString(name) || len(name) > 63 {
		return Entry{}, fmt.Sprintf("%q is not an RDS instance identifier (a letter, then letters, digits and single hyphens, at most 63): give it one in the map's names (%s)", name, s.src)
	}
	if s.admin == "" {
		return Entry{}, "its administrator login is not in the snapshot, and RDS needs a master user name"
	}
	spec := map[string]any{
		"DBInstanceIdentifier": name, "DBInstanceClass": dm.InstanceClass,
		"MasterUsername": s.admin, "ManageMasterUserPassword": true,
		"StorageEncrypted": true, "MultiAZ": s.ha,
	}
	e := Entry{Source: s.src, State: Mapped, Losses: append([]Loss(nil), s.losses...)}
	var params map[string]any
	var family string
	if s.sql {
		switch {
		case dm.Edition == "":
			return Entry{}, fmt.Sprintf("the map gives no SQL Server edition for it (databases.%s.edition: sqlserver-ex, -web, -se or -ee): Azure SQL Database has none", key)
		case dm.LicenseModel == "":
			return Entry{}, fmt.Sprintf("the map gives no license model for it (databases.%s.licenseModel: license-included or bring-your-own-media)", key)
		case dm.Version == "":
			return Entry{}, fmt.Sprintf("the map gives no SQL Server version for it (databases.%s.version, an RDS engine version such as 16.00.4185.3.v1): Azure SQL Database has none", key)
		case s.ha && (dm.Edition == "sqlserver-ex" || dm.Edition == "sqlserver-web"):
			return Entry{}, fmt.Sprintf("a database of it is zone redundant, and RDS runs %s in one zone only (MultiAZ needs sqlserver-se or sqlserver-ee)", dm.Edition)
		}
		major, err := strconv.Atoi(strings.SplitN(dm.Version, ".", 2)[0])
		if err != nil {
			return Entry{}, fmt.Sprintf("databases.%s.version: %q is not an RDS SQL Server engine version (16.00.4185.3.v1)", key, dm.Version)
		}
		storage := dm.StorageGB
		if storage == 0 {
			storage = s.storageGB
		}
		if storage == 0 {
			return Entry{}, fmt.Sprintf("its databases give no maximum size, and the map gives no storage for it (databases.%s.storageGB)", key)
		}
		spec["Engine"], spec["EngineVersion"], spec["LicenseModel"] = dm.Edition, dm.Version, dm.LicenseModel
		spec["AllocatedStorage"] = strconv.Itoa(storage)
		family = fmt.Sprintf("%s-%d.0", dm.Edition, major)
		params = d.sqlParams(s, &e)
	} else {
		if !rdsPG[s.version] {
			return Entry{}, fmt.Sprintf("PostgreSQL %q is not a version RDS offers here (13 to 17); it is not moved to another", s.version)
		}
		if s.storageGB == 0 {
			return Entry{}, "its storage size is not in the snapshot"
		}
		spec["Engine"], spec["EngineVersion"] = "postgres", s.version
		spec["AllocatedStorage"] = strconv.Itoa(s.storageGB)
		if s.autoGrow {
			spec["MaxAllocatedStorage"] = max(azPGMaxStorageGB, s.storageGB+1)
		}
		family = "postgres" + s.version
		params = d.pgParams(s, &e)
	}
	if s.backupDays > 0 {
		spec["BackupRetentionPeriod"] = s.backupDays
	} else if s.sql {
		e.Losses = append(e.Losses, Loss{Field: "databases/*/backupShortTermRetentionPolicies", Why: "how long its backups were kept is not in the snapshot: RDS keeps them as long as its default says"})
	}
	switch {
	case dm.KMSKey != "":
		spec["KmsKeyId"] = dm.KMSKey
		o.require(fmt.Sprintf("KMS key %s lets RDS use it for %s (its key policy): Azure reached its key through the server's managed identity, which is not translated", dm.KMSKey, name))
	case s.cmk:
		e.Losses = append(e.Losses, Loss{Field: s.cmkField, Widens: true,
			Why: fmt.Sprintf("it was encrypted with the customer's own key; the instance is encrypted with RDS's AWS managed key until the map names one (databases.%s.kmsKey)", key)})
	}
	if s.softDelete > 0 {
		spec["DeletionProtection"] = true
		e.Losses = append(e.Losses, Loss{Field: "properties.retentionDays",
			Why: fmt.Sprintf("Azure kept the server %d days after it was deleted; RDS refuses to delete the instance while deletion protection is on, which is stricter: turn it off to delete it", s.softDelete)})
	}
	tags, tl := rdsTags(s.tags)
	e.Losses = append(e.Losses, tl...)
	if len(tags) > 0 {
		spec["Tags"] = tags
	}

	pl, why := s.place(d.m, o, true)
	if why != "" {
		return Entry{}, why
	}
	vpc := awsNet{d.m}.vpcName(pl.vnet)
	var ids []any
	var sns []string
	zones := map[string]bool{}
	for _, sn := range pl.subnets {
		n := vpc + "-" + sn.name
		if o.written("aws", awsSN, n) == nil {
			return Entry{}, "subnet " + sn.name + " of " + pl.vnet.src + " is not translated (its network is refused, or destinations.network is not chosen)"
		}
		zones[d.m.zoneFor(pl.vnet.group+"/"+pl.vnet.name+"/"+sn.name)] = true
		ids = append(ids, awsRef(awsSN, n, "SubnetId"))
		sns = append(sns, sn.name)
	}
	if len(zones) < 2 {
		return Entry{}, fmt.Sprintf("RDS needs subnets in two availability zones at least, and its subnets (%s) are in one: add a subnet in another zone to databases.%s.subnets", strings.Join(sns, ", "), key)
	}
	sgs, public, why := d.access(s, pl, name, vpc, o, &e)
	if why != "" {
		return Entry{}, why
	}
	group := name + "-subnets"
	e.Targets = append(e.Targets, o.add("aws", s.src, awsObject(awsDBSubnets, group, map[string]any{
		"DBSubnetGroupName": group, "DBSubnetGroupDescription": "From Azure database server " + s.mapKey(), "SubnetIds": ids,
	})))
	// A reference to a name someone chose is to its identifier, as a
	// capture writes it.
	spec["DBSubnetGroupName"] = awsRef(awsDBSubnets, group, "identifier")
	spec["VPCSecurityGroups"] = sgs
	spec["PubliclyAccessible"] = public
	if public {
		o.require(fmt.Sprintf("Subnets %s of VPC %s need a route to an internet gateway for %s to be reached from the internet (not translated)", strings.Join(sns, ", "), vpc, name))
	}
	if len(params) > 0 {
		pg := name + "-params"
		e.Targets = append(e.Targets, o.add("aws", s.src, awsObject(awsDBParams, pg, map[string]any{
			"DBParameterGroupName": pg, "Family": family, "Description": "From Azure database server " + s.mapKey(), "Parameters": params,
		})))
		spec["DBParameterGroupName"] = awsRef(awsDBParams, pg, "identifier")
	}
	e.Targets = append(e.Targets, o.add("aws", s.src, awsObject(awsDB, name, spec)))
	o.require(fmt.Sprintf("RDS keeps the master user password of %s in Secrets Manager (ManageMasterUserPassword): apps read it from there; no password is carried over", name))
	s.requirements(o, name, "RDS instance")
	return e, ""
}

// access is the instance's security groups. A private server is reached
// from its network, filtered by the NSG of its delegated subnet when it
// has one; a public one from what its firewall rules allowed.
func (d rdsWriter) access(s *dbServer, pl *placement, name, vpc string, o *out, e *Entry) ([]any, bool, string) {
	vpcRef := awsRef(awsVPC, vpc, "VpcId")
	var ranges []netip.Prefix
	public := false
	if !s.public {
		if sn := o.subnets[s.subnet]; s.subnet != "" && sn != nil && sn.nsg != "" {
			if sg := nsgGroup(o, sn.nsg, vpcRef); sg != "" {
				return []any{awsRef(awsSG, sg, "GroupId")}, false, ""
			}
			return nil, false, "the network security group on its delegated subnet is not translated, so nothing would filter its traffic as it did"
		}
		ranges = append(ranges, pl.vnet.prefixes...)
	} else {
		for _, r := range s.firewall {
			if r.azure {
				s.childLoss(r.child, Loss{Field: "properties", Why: "0.0.0.0 allows every Azure service, anyone's: it has no addresses on AWS, so it is not carried over (apps in Azure that reached it are allowed by their own addresses)"})
				continue
			}
			ranges = append(ranges, r.prefixes...)
			public = true
		}
		for _, r := range s.vnetRules {
			sn := o.subnets[r.subnet]
			if sn == nil || sn.vnet != pl.vnet || !sn.prefix.IsValid() {
				s.childLoss(r.child, Loss{Field: "properties.virtualNetworkSubnetId", Why: r.subnet + " is not a subnet of the instance's network: it is not allowed on the target"})
				continue
			}
			ranges = append(ranges, sn.prefix)
		}
	}
	var rules []any
	for _, p := range aggregate(ranges) {
		rules = append(rules, map[string]any{"IpProtocol": "tcp", "FromPort": s.port(), "ToPort": s.port(), "CidrIp": p.String()})
	}
	sg := name + "-db"
	tags, _ := awsTags(sg, nil)
	spec := map[string]any{"GroupDescription": "Who reaches Azure database server " + s.mapKey(), "VpcId": vpcRef, "Tags": tags}
	if len(rules) > 0 {
		spec["SecurityGroupIngress"] = rules
	}
	e.Targets = append(e.Targets, o.add("aws", s.src, awsObject(awsSG, sg, spec)))
	return []any{awsRef(awsSG, sg, "GroupId")}, public, ""
}

// nsgGroup is the security group the network family wrote for an NSG
// (group/name, lower case) in a VPC, or "".
func nsgGroup(o *out, nsg, vpcRef string) string {
	for _, x := range o.objects["aws"] {
		sp, _ := x.Body["spec"].(map[string]any)
		if x.Kind() == awsSG && strings.EqualFold(fmt.Sprint(sp["GroupDescription"]), "From Azure network security group "+nsg) && sp["VpcId"] == vpcRef {
			return x.Name()
		}
	}
	return ""
}

func (s *dbServer) childLoss(i int, l Loss) {
	s.children[i].Losses = append(s.children[i].Losses, l)
}

// pgParams are the parameter group's: TLS as the server took it, and each
// parameter a person set that RDS takes by the same name.
func (d rdsWriter) pgParams(s *dbServer, e *Entry) map[string]any {
	ps := map[string]any{}
	if s.tls {
		ps["rds.force_ssl"] = "1"
	}
	if s.tls || s.tlsMinSet {
		ps["ssl_min_protocol_version"] = s.tlsMin
	}
	for _, p := range s.params {
		n := strings.ToLower(p.name)
		if !rdsPGParams[n] {
			s.childLoss(p.child, Loss{Field: "properties.value", Widens: guardedParam(n),
				Why: p.value + ": RDS for PostgreSQL has no parameter " + p.name + " this translation knows to mean the same; not carried over"})
			continue
		}
		ps[n] = rdsValue(p.value)
	}
	return ps
}

// sqlParams are SQL Server's: encrypted connections only, as Azure SQL
// takes them, and the oldest TLS version.
func (d rdsWriter) sqlParams(s *dbServer, e *Entry) map[string]any {
	ps := map[string]any{"rds.force_ssl": "1"}
	switch s.tlsMin {
	case "1.1":
		ps["rds.tls10"] = "disabled"
	case "1.2":
		ps["rds.tls10"], ps["rds.tls11"] = "disabled", "disabled"
	case "1.3":
		ps["rds.tls10"], ps["rds.tls11"] = "disabled", "disabled"
		e.Losses = append(e.Losses, Loss{Field: "properties.minimalTlsVersion", Widens: true,
			Why: "1.3: RDS for SQL Server cannot refuse TLS 1.2, so it takes TLS 1.2 and later"})
	}
	return ps
}

// rdsValue is a value as RDS takes it: on and off as 1 and 0.
func rdsValue(v string) string {
	switch strings.ToLower(v) {
	case "on", "true":
		return "1"
	case "off", "false":
		return "0"
	}
	return v
}

func rdsTags(tags map[string]string) ([]any, []Loss) {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []any
	var losses []Loss
	for _, k := range keys {
		if strings.HasPrefix(strings.ToLower(k), "aws:") {
			losses = append(losses, Loss{Field: "tags." + k, Why: "AWS reserves tags that begin aws:"})
			continue
		}
		out = append(out, map[string]any{"Key": k, "Value": tags[k]})
	}
	return out, losses
}
