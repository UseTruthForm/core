package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Database servers on GCP: a Cloud SQL instance each. A public server
// keeps its public IP with its firewall ranges as authorized networks; a
// private one gets a private IP in the translated VPC network, and no
// public one. Server parameters Cloud SQL takes by the same name become
// database flags. Users carry passwords, so none is written.

const gcpSQL = "sqladmin.googleapis.com/Instance" // Cloud Asset Inventory's name

var (
	gcpSQLName = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])?$`)
)

type cloudSQLWriter struct{ m Map }

// sqlInstance is a Cloud SQL instance as a capture writes one.
func sqlInstance(name string, spec map[string]any) snapshot.Object {
	s := map[string]any{"name": name}
	for k, v := range spec {
		s[k] = v
	}
	return snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": gcpSQL,
		"metadata": map[string]any{"name": gcpProject + "/instances/" + name, "annotations": map[string]any{
			"truthform.org/discovery":  "sqladmin/v1",
			"truthform.org/schema":     "DatabaseInstance",
			"truthform.org/collection": "instances",
			"truthform.org/parent":     gcpProject,
		}}, "spec": s}}
}

// sqlEdition is the edition a tier belongs to: Enterprise Plus's are
// db-perf-optimized-*, and a tier of one edition is refused by the other.
func sqlEdition(tier string) string {
	if strings.HasPrefix(tier, "db-perf-optimized-") {
		return "ENTERPRISE_PLUS"
	}
	return "ENTERPRISE"
}

func (d cloudSQLWriter) server(s *dbServer, o *out) (Entry, string) {
	key := s.mapKey()
	dm, _ := d.m.database(key)
	if dm.Tier == "" {
		return Entry{}, fmt.Sprintf("the map gives no tier for it (databases.%s.tier): its Azure SKU, %s, names Azure's hardware, not a Cloud SQL tier", key, s.sku)
	}
	if d.m.Region == "" {
		return Entry{}, "the map names no region (region): a Cloud SQL instance is regional"
	}
	name := d.m.name(s.src, strings.ToLower(s.name))
	if !gcpSQLName.MatchString(name) || len(name) > 63 {
		return Entry{}, fmt.Sprintf("%q is not a Cloud SQL instance name (a letter, then letters, digits and hyphens, at most 63): give it one in the map's names (%s)", name, s.src)
	}
	e := Entry{Source: s.src, State: Mapped, Losses: append([]Loss(nil), s.losses...)}
	doc, err := o.tg.GCP.DocFor("sqladmin", "v1")
	if err != nil {
		return Entry{}, "Cloud SQL's definition could not be read, so its versions are not known: " + err.Error()
	}
	// The versions Cloud SQL takes are its definition's, not a list kept
	// here: those it lists and does not mark deprecated.
	offered := map[string]bool{}
	for _, v := range doc.Allowed("DatabaseInstance", "databaseVersion") {
		offered[v] = true
	}
	var version string
	storage := s.storageGB
	if s.sql {
		switch {
		case dm.Version == "":
			return Entry{}, fmt.Sprintf("the map gives no SQL Server version for it (databases.%s.version, such as SQLSERVER_2022_STANDARD): Azure SQL Database has none", key)
		case !strings.HasPrefix(dm.Version, "SQLSERVER_") || !offered[dm.Version]:
			return Entry{}, fmt.Sprintf("databases.%s.version: %q is not a SQL Server version Cloud SQL's definition offers (SQLSERVER_2022_STANDARD)", key, dm.Version)
		}
		version = dm.Version
		if dm.StorageGB > 0 {
			storage = dm.StorageGB
		}
		if storage == 0 {
			return Entry{}, fmt.Sprintf("its databases give no maximum size, and the map gives no storage for it (databases.%s.storageGB)", key)
		}
	} else {
		if !offered["POSTGRES_"+s.version] {
			return Entry{}, fmt.Sprintf("PostgreSQL %q is not a version Cloud SQL's definition offers (POSTGRES_%s); it is not moved to another", s.version, s.version)
		}
		if storage == 0 {
			return Entry{}, "its storage size is not in the snapshot"
		}
		version = "POSTGRES_" + s.version
	}
	edition := sqlEdition(dm.Tier)
	settings := map[string]any{
		"tier": dm.Tier, "edition": edition, "dataDiskSizeGb": strconv.Itoa(storage),
		"storageAutoResize": s.autoGrow, "availabilityType": "ZONAL",
	}
	if s.ha {
		settings["availabilityType"] = "REGIONAL"
	}
	bc := map[string]any{"enabled": true, "pointInTimeRecoveryEnabled": true}
	if s.backupDays > 0 {
		logDays, limit := s.backupDays, 7
		if edition == "ENTERPRISE_PLUS" {
			limit = 35
		}
		if logDays > limit {
			logDays = limit
			e.Losses = append(e.Losses, Loss{Field: "backup retention", Why: fmt.Sprintf("it could be restored to any point in the last %d days; Cloud SQL %s keeps transaction logs %d days at most, so a point in time goes back %d (daily backups are kept %d)", s.backupDays, edition, limit, limit, s.backupDays)})
		}
		bc["transactionLogRetentionDays"] = logDays
		bc["backupRetentionSettings"] = map[string]any{"retentionUnit": "COUNT", "retainedBackups": s.backupDays}
	} else if s.sql {
		e.Losses = append(e.Losses, Loss{Field: "databases/*/backupShortTermRetentionPolicies", Why: "how long its backups were kept is not in the snapshot: Cloud SQL keeps them as long as its default says"})
	}
	settings["backupConfiguration"] = bc
	sp := map[string]any{"region": d.m.Region, "databaseVersion": version, "settings": settings}

	ip := map[string]any{}
	if s.tls {
		ip["sslMode"] = "ENCRYPTED_ONLY"
	}
	var tlsFlag map[string]any
	switch {
	case s.tlsMin == "" || !(s.tls || s.tlsMinSet) || strings.HasSuffix(s.tlsMin, "1.0"):
	case !s.sql:
		// Cloud SQL for PostgreSQL takes PostgreSQL's own
		// ssl_min_protocol_version as a database flag (TLSv1 to TLSv1.3).
		tlsFlag = map[string]any{"name": "ssl_min_protocol_version", "value": s.tlsMin}
	case dm.AcceptTLSFloor:
		e.Losses = append(e.Losses, Loss{Field: "properties.minimalTlsVersion",
			Why: s.tlsMin + ": Cloud SQL for SQL Server has no setting for the oldest TLS version it takes; the map accepts the floor Google keeps (databases." + key + ".acceptTlsFloor), so it is named, not counted as widening"})
	default:
		e.Losses = append(e.Losses, Loss{Field: "properties.minimalTlsVersion", Widens: true,
			Why: s.tlsMin + ": Cloud SQL for SQL Server has no setting for the oldest TLS version it takes, so it may take older ones than the source did; once its floor is checked on the target, databases." + key + ".acceptTlsFloor accepts it"})
	}
	if s.public {
		ip["ipv4Enabled"] = true
		var nets []any
		for _, r := range s.firewall {
			if r.azure {
				s.childLoss(r.child, Loss{Field: "properties", Why: "0.0.0.0 allows every Azure service, anyone's: it has no addresses on GCP, so it is not carried over (apps in Azure that reached it are allowed by their own addresses)"})
				continue
			}
			for i, p := range r.prefixes {
				n := r.name
				if len(r.prefixes) > 1 {
					n = fmt.Sprintf("%s-%d", r.name, i+1)
				}
				nets = append(nets, map[string]any{"name": n, "value": p.String()})
			}
		}
		for _, r := range s.vnetRules {
			s.childLoss(r.child, Loss{Field: "properties.virtualNetworkSubnetId", Why: r.subnet + ": a Cloud SQL public IP takes public addresses, and these are private, so the subnet is not allowed (less than the source); its clients reach the instance once it has a private IP (not translated)"})
		}
		if len(nets) > 0 {
			ip["authorizedNetworks"] = nets
		}
		o.require(fmt.Sprintf("Cloud SQL instance %s's public IP also takes the Cloud SQL Auth Proxy and connectors, from any principal with cloudsql.instances.connect, whatever its authorized networks: grant that only to the apps (identity is not translated, #32)", name))
	} else {
		pl, why := s.place(d.m, o, false)
		if why != "" {
			return Entry{}, why
		}
		net := gcpNet{d.m}.netName(pl.vnet)
		if o.written("gcp", gcpNetwork, gcpProject+"/global/networks/"+net) == nil {
			return Entry{}, "its network " + pl.vnet.src + " is not translated (it is refused, or destinations.network is not chosen)"
		}
		ip["ipv4Enabled"] = false
		ip["privateNetwork"] = gcpProject + "/global/networks/" + net
		if sn := o.subnets[s.subnet]; s.subnet != "" && sn != nil && sn.nsg != "" {
			e.Losses = append(e.Losses, Loss{Field: "properties.network.delegatedSubnetResourceId", Widens: true,
				Why: "the network security group on its subnet filtered who reached it; Cloud SQL's private IP takes connections from the whole network, since no firewall rule applies on its side"})
		}
		o.require(fmt.Sprintf("Private services access (an allocated range and a servicenetworking connection) exists on network %s before Cloud SQL instance %s is made: its private IP comes from it (not translated)", net, name))
	}
	settings["ipConfiguration"] = ip

	var flags []any
	if tlsFlag != nil {
		flags = append(flags, tlsFlag)
	}
	for _, p := range s.params {
		n := strings.ToLower(p.name)
		if !gcpPGFlags[n] {
			s.childLoss(p.child, Loss{Field: "properties.value", Widens: guardedParam(n),
				Why: p.value + ": Cloud SQL has no database flag " + p.name + " this translation knows to mean the same; not carried over"})
			continue
		}
		flags = append(flags, map[string]any{"name": n, "value": p.value})
	}
	sort.Slice(flags, func(i, j int) bool {
		return flags[i].(map[string]any)["name"].(string) < flags[j].(map[string]any)["name"].(string)
	})
	if len(flags) > 0 {
		settings["databaseFlags"] = flags
	}
	labels, ll := gcpLabels(s.tags)
	e.Losses = append(e.Losses, ll...)
	if len(labels) > 0 {
		settings["userLabels"] = labels
	}
	switch {
	case dm.KMSKey != "":
		sp["diskEncryptionConfiguration"] = map[string]any{"kmsKeyName": dm.KMSKey}
		o.require(fmt.Sprintf("Cloud KMS key %s lets Cloud SQL's service agent use it for %s (roles/cloudkms.cryptoKeyEncrypterDecrypter): Azure reached its key through the server's managed identity, which is not translated", dm.KMSKey, name))
	case s.cmk:
		e.Losses = append(e.Losses, Loss{Field: s.cmkField, Widens: true,
			Why: fmt.Sprintf("it was encrypted with the customer's own key; the instance is encrypted with Google's key until the map names a Cloud KMS key (databases.%s.kmsKey)", key)})
	}
	if s.softDelete > 0 {
		settings["deletionProtectionEnabled"] = true
		e.Losses = append(e.Losses, Loss{Field: "properties.retentionDays",
			Why: fmt.Sprintf("Azure kept the server %d days after it was deleted; Cloud SQL refuses to delete the instance while deletion protection is on, which is stricter: turn it off to delete it", s.softDelete)})
	}
	e.Targets = append(e.Targets, o.add("gcp", s.src, sqlInstance(name, sp)))
	if s.sql {
		o.require(fmt.Sprintf("Cloud SQL for SQL Server takes the sqlserver user's password when %s is made (rootPassword): supply it from a secret source then; no password is in a snapshot", name))
	}
	if s.admin != "" {
		o.require(fmt.Sprintf("Create user %s on Cloud SQL instance %s, with a password from a secret source: no user or password is written", s.admin, name))
	}
	s.requirements(o, name, "Cloud SQL instance")
	return e, ""
}

// gcpLabels are tags as Cloud SQL's user labels, where they fit.
