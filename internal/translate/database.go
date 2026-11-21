package translate

import (
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Azure Database for PostgreSQL flexible servers and Azure SQL servers,
// read into a model the RDS and Cloud SQL writers share. Configuration
// only: no row of data is read, and none is moved.
//
// A server becomes one instance. What Azure cannot say about the target
// (its size, and for SQL Server the edition, license and version, which
// Azure SQL Database does not have) is the map's, and a server the map
// does not size is refused: an Azure SKU names Azure's hardware. A
// server's children (its databases, server parameters, firewall rules)
// are read with it, as if inline, and share its fate.

const (
	azPG  = "microsoft.dbforpostgresql/flexibleservers"
	azSQL = "microsoft.sql/servers"

	pgPort  = 5432
	sqlPort = 1433

	// azPGMaxStorageGB is how far Azure grows a flexible server's storage
	// when autogrow is on: to its largest disk, 32 TiB. RDS grows to the
	// limit it is given.
	azPGMaxStorageGB = 32768
)

type databases struct{}

func (databases) claims(kind string) bool {
	return kind == azPG || strings.HasPrefix(kind, azPG+"/") || kind == azSQL || strings.HasPrefix(kind, azSQL+"/")
}

type dbServer struct {
	src, group, name string
	key              string // group/name, lower case
	sql              bool   // Azure SQL; else PostgreSQL
	sku              string // Azure's SKU, named in a refusal as a hint
	version          string // PostgreSQL's major version
	admin            string
	storageGB        int
	autoGrow         bool
	backupDays       int // 0: not in the snapshot
	ha               bool
	public           bool
	subnet           string // a PostgreSQL server's delegated subnet, group/network/subnet
	firewall         []fwRule
	vnetRules        []vnetRule
	cmk              bool   // encrypted with the customer's own key
	cmkField         string // where the report names it
	tls              bool   // only TLS connections are taken
	tlsMin           string // PostgreSQL: TLSv1.2; SQL: 1.2
	tlsMinSet        bool   // a person chose it (PostgreSQL)
	params           []pgParam
	extensions       []string
	dbs              []dbDatabase
	softDelete       int // days a deleted server is kept (SQL)
	entra            bool
	tags             map[string]string
	losses           []Loss
	refuse           string
	children         []Entry // read with the server; they share its fate
}

type fwRule struct {
	name     string
	prefixes []netip.Prefix
	azure    bool // 0.0.0.0: every Azure service, anyone's
	child    int  // its entry in children
}

type vnetRule struct {
	subnet string // group/network/subnet, lower case
	child  int
}

type pgParam struct {
	name, value string
	child       int
}

type dbDatabase struct {
	name, charset, collation string
	ledger                   bool
}

// childReader reads a child into its server, and gives its entry's
// reason (empty: "read with its server") and losses.
type childReader func(s *dbServer, name string, sp map[string]any) (string, []Loss)

// dbChild is the decision for one child type: read with its server, or a
// state of its own.
type dbChild struct {
	read   childReader
	state  State
	reason string
}

const (
	whyIdentity = "identity is not translated (#32): Microsoft Entra ID sign-in becomes the target's own (IAM database authentication for PostgreSQL, Active Directory for SQL Server), which is a change to the apps and their users"
	whyBackup   = "a backup is data, which is not moved: the target starts its own backups (#32)"
	whyReplica  = "read replicas and geo-replication are not translated yet: the target instance has none"
)

// pgChildren are the decisions for a flexible server's child types, by
// what follows flexibleServers/.
var pgChildren = map[string]dbChild{
	"databases":                        {read: readPGDatabase},
	"configurations":                   {read: readPGConfig},
	"firewallrules":                    {read: readFirewallRule},
	"advancedthreatprotectionsettings": {read: protection("threat protection (Microsoft Defender for open-source databases)", "GuardDuty RDS Protection, Security Command Center")},
	"administrators":                   {state: Refused, reason: whyIdentity},
	"backups":                          {state: Refused, reason: whyBackup},
	"ltrbackupoperations":              {state: Refused, reason: whyBackup},
	"migrations":                       {state: Refused, reason: "a migration moves data, which is not translated"},
	"maintenanceevents":                {state: Refused, reason: "a record of Azure's maintenance, not a resource"},
	"majorversionupgradeprecheck":      {state: Refused, reason: "a check Azure runs before an upgrade, not a resource"},
	"virtualendpoints":                 {state: Refused, reason: "a read-write endpoint over replicas: " + whyReplica},
	"privateendpointconnections":       {state: Mapped, reason: "made when its private endpoint is created: a private server is placed in the subnets the map names (databases.<group/server>.subnets)"},
	"privatelinkresources":             {state: Mapped, reason: "what a private endpoint can connect to: nothing to carry"},
	"tuningoptions":                    {state: NotLooked, reason: "no descriptor for Azure's tuning recommendations yet"},
}

// sqlChildren are the decisions for an Azure SQL server's child types, by
// what follows servers/; a key ending in / decides everything under it.
var sqlChildren = map[string]dbChild{
	"databases":                                  {read: readSQLDatabase},
	"firewallrules":                              {read: readFirewallRule},
	"virtualnetworkrules":                        {read: readVNetRule},
	"ipv6firewallrules":                          {read: readIPv6Rule},
	"encryptionprotector":                        {read: readProtector},
	"databases/transparentdataencryption":        {read: readTDE},
	"databases/backupshorttermretentionpolicies": {read: readDBRetention},
	"databases/geobackuppolicies":                {read: readGeoBackup},
	"auditingsettings":                           {read: protection("auditing", "the SQLSERVER_AUDIT option (RDS), Cloud SQL's SQL Server audit")},
	"extendedauditingsettings":                   {read: protection("auditing", "the SQLSERVER_AUDIT option (RDS), Cloud SQL's SQL Server audit")},
	"devopsauditingsettings":                     {read: protection("auditing of Microsoft's support operations", "nothing")},
	"databases/auditingsettings":                 {read: protection("auditing", "the SQLSERVER_AUDIT option (RDS), Cloud SQL's SQL Server audit")},
	"databases/extendedauditingsettings":         {read: protection("auditing", "the SQLSERVER_AUDIT option (RDS), Cloud SQL's SQL Server audit")},
	"securityalertpolicies":                      {read: protection("threat detection", "GuardDuty RDS Protection, Security Command Center")},
	"databases/securityalertpolicies":            {read: protection("threat detection", "GuardDuty RDS Protection, Security Command Center")},
	"advancedthreatprotectionsettings":           {read: protection("threat protection", "GuardDuty RDS Protection, Security Command Center")},
	"databases/advancedthreatprotectionsettings": {read: protection("threat protection", "GuardDuty RDS Protection, Security Command Center")},
	"vulnerabilityassessments":                   {read: assessment},
	"databases/vulnerabilityassessments":         {read: assessment},
	"sqlvulnerabilityassessments":                {read: protection("vulnerability assessment", "Security Hub, Security Command Center")},
	"databases/sqlvulnerabilityassessments":      {read: protection("vulnerability assessment", "Security Hub, Security Command Center")},
	"databases/vulnerabilityassessments/":        {state: Mapped, reason: "a scan or baseline of a vulnerability assessment, which is not translated (its own entry says so)"},
	"databases/sqlvulnerabilityassessments/":     {state: Mapped, reason: "a scan or baseline of a vulnerability assessment, which is not translated (its own entry says so)"},
	"databases/backuplongtermretentionpolicies":  {read: readLTR},
	"keys":                                   {state: Mapped, reason: "a key vault key the server may encrypt with: on the target the key is the map's (databases.<group/server>.kmsKey)"},
	"connectionpolicies":                     {state: Mapped, reason: "how clients pass Azure's gateway (proxy or redirect): the target has no gateway, and clients connect to the instance"},
	"outboundfirewallrules":                  {state: Mapped, reason: "read with its server, whose restrictOutboundNetworkAccess says whether these apply"},
	"dnsaliases":                             {state: Mapped, reason: "a DNS alias for the server: point that name at the target's endpoint (a CNAME); no alias is written"},
	"privateendpointconnections":             {state: Mapped, reason: "made when its private endpoint is created: a private server is placed in the subnets the map names (databases.<group/server>.subnets)"},
	"privatelinkresources":                   {state: Mapped, reason: "what a private endpoint can connect to: nothing to carry"},
	"administrators":                         {state: Refused, reason: whyIdentity},
	"azureadonlyauthentications":             {state: Refused, reason: whyIdentity},
	"elasticpools":                           {state: Refused, reason: "an elastic pool has no peer: on RDS and Cloud SQL the databases of one instance share its size, which the map gives for the server (databases.<group/server>); the pool's own limits are not carried"},
	"failovergroups":                         {state: Refused, reason: "a failover group replicates its databases to another server: " + whyReplica},
	"databases/replicationlinks":             {state: Refused, reason: whyReplica},
	"recoverabledatabases":                   {state: Refused, reason: whyBackup},
	"restorabledroppeddatabases":             {state: Refused, reason: whyBackup},
	"databases/restorepoints":                {state: Refused, reason: whyBackup},
	"databases/extensions":                   {state: Refused, reason: "an import or export of data, not a resource"},
	"syncagents":                             {state: Refused, reason: "SQL Data Sync moves data, which is not translated"},
	"databases/syncgroups":                   {state: Refused, reason: "SQL Data Sync moves data, which is not translated"},
	"databases/syncgroups/":                  {state: Refused, reason: "SQL Data Sync moves data, which is not translated"},
	"jobagents":                              {state: Refused, reason: "Elastic Jobs have no peer: SQL Server Agent (RDS, Cloud SQL) runs jobs, rewritten, not translated"},
	"jobagents/":                             {state: Refused, reason: "Elastic Jobs have no peer: SQL Server Agent (RDS, Cloud SQL) runs jobs, rewritten, not translated"},
	"advisors":                               {state: NotLooked, reason: "no descriptor for Azure's advisors yet"},
	"automatictuning":                        {state: NotLooked, reason: "no descriptor for automatic tuning yet"},
	"databases/advisors":                     {state: NotLooked, reason: "no descriptor for Azure's advisors yet"},
	"databases/advisors/":                    {state: NotLooked, reason: "no descriptor for Azure's advisors yet"},
	"databases/automatictuning":              {state: NotLooked, reason: "no descriptor for automatic tuning yet"},
	"databases/datamaskingpolicies":          {state: NotLooked, reason: "no descriptor for dynamic data masking yet"},
	"databases/datamaskingpolicies/":         {state: NotLooked, reason: "no descriptor for dynamic data masking yet"},
	"databases/ledgerdigestuploads":          {state: NotLooked, reason: "no descriptor for ledger digest uploads yet"},
	"databases/schemas":                      {state: NotLooked, reason: "no descriptor for a database's schemas and sensitivity labels yet"},
	"databases/schemas/":                     {state: NotLooked, reason: "no descriptor for a database's schemas and sensitivity labels yet"},
	"databases/datawarehouseuseractivities":  {state: NotLooked, reason: "no descriptor for dedicated SQL pools yet"},
	"databases/workloadgroups":               {state: NotLooked, reason: "no descriptor for dedicated SQL pools yet"},
	"databases/workloadgroups/":              {state: NotLooked, reason: "no descriptor for dedicated SQL pools yet"},
	"networksecurityperimeterconfigurations": {state: NotLooked, reason: "no descriptor for network security perimeters yet"},
}

// childRule finds the decision for a child kind (lower case), or false.
func childRule(kind string) (dbChild, bool) {
	table, rest := pgChildren, strings.TrimPrefix(kind, azPG+"/")
	if strings.HasPrefix(kind, azSQL+"/") {
		table, rest = sqlChildren, strings.TrimPrefix(kind, azSQL+"/")
	}
	if c, ok := table[rest]; ok {
		return c, true
	}
	best := ""
	for k := range table {
		if strings.HasSuffix(k, "/") && strings.HasPrefix(rest, k) && len(k) > len(best) {
			best = k
		}
	}
	c, ok := table[best]
	return c, ok && best != ""
}

func (databases) translate(objs []snapshot.Object, o *out) {
	servers := map[string]*dbServer{}
	var kids []snapshot.Object
	for _, obj := range objs {
		switch strings.ToLower(obj.Kind()) {
		case azPG:
			s := readPGServer(obj)
			servers[s.key] = s
		case azSQL:
			s := readSQLServer(obj)
			servers[s.key] = s
		default:
			kids = append(kids, obj)
		}
	}
	sort.Slice(kids, func(i, j int) bool { return source(kids[i]) < source(kids[j]) })
	for _, obj := range kids {
		kind := strings.ToLower(obj.Kind())
		rule, ok := childRule(kind)
		if !ok {
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
			continue
		}
		if rule.read == nil && rule.state != Mapped {
			o.entries = append(o.entries, Entry{Source: source(obj), State: rule.state, Reason: rule.reason})
			continue
		}
		parent, name, _ := strings.Cut(obj.Name(), "/")
		s := servers[strings.ToLower(obj.Namespace()+"/"+parent)]
		if s == nil {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: "its server is not in the snapshot"})
			continue
		}
		e := Entry{Source: source(obj), State: Mapped, Reason: rule.reason}
		if rule.read != nil {
			why, losses := rule.read(s, name, spec(obj))
			e.Reason, e.Losses = "read with its server "+s.src, losses
			if why != "" {
				e.Reason = why
			}
		}
		s.children = append(s.children, e)
	}
	var w dbWriter
	switch {
	case o.m.Destinations.Databases == "":
		for _, s := range sortedServers(servers) {
			s.finish(o, false, "the map chooses no destination for databases (destinations.databases)")
		}
		return
	case o.m.To == "aws":
		w = rdsWriter{m: o.m}
	default:
		w = cloudSQLWriter{m: o.m}
	}
	for _, s := range sortedServers(servers) {
		if s.refuse != "" {
			s.finish(o, false, s.refuse)
			continue
		}
		e, why := w.server(s, o)
		if why != "" {
			s.finish(o, false, why)
			continue
		}
		o.entries = append(o.entries, e)
		s.finish(o, true, "")
	}
}

// dbWriter writes a server for one target: its entry, or why it is
// refused.
type dbWriter interface {
	server(s *dbServer, o *out) (Entry, string)
}

// finish reports a server's children, and the server itself when it is
// refused: a child read with a refused server is refused with it.
func (s *dbServer) finish(o *out, ok bool, why string) {
	if !ok {
		o.entries = append(o.entries, Entry{Source: s.src, State: Refused, Reason: why})
	}
	for _, e := range s.children {
		if !ok {
			e = Entry{Source: e.Source, State: Refused, Reason: "its server " + s.src + " is refused"}
		}
		o.entries = append(o.entries, e)
	}
}

func sortedServers(m map[string]*dbServer) []*dbServer {
	out := make([]*dbServer, 0, len(m))
	for _, s := range m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	return out
}

func newServer(o snapshot.Object, sql bool) *dbServer {
	return &dbServer{src: source(o), group: o.Namespace(), name: o.Name(), key: strings.ToLower(o.Namespace() + "/" + o.Name()), sql: sql}
}

// mapKey is how the map names the server: group/server.
func (s *dbServer) mapKey() string { return s.group + "/" + s.name }

func (s *dbServer) port() int {
	if s.sql {
		return sqlPort
	}
	return pgPort
}

// readTop reads what both kinds of server have outside properties.
func (s *dbServer) readTop(top *props) {
	top.quiet("location", "properties", "name")
	s.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	if sku := obj(top.m["sku"]); sku != nil {
		s.sku = fmt.Sprint(sku["name"])
		if t, ok := sku["tier"]; ok {
			s.sku += " (" + fmt.Sprint(t) + ")"
		}
	}
	top.quiet("sku") // a hint for the map, never a target size
	if id := obj(top.m["identity"]); len(id) > 0 && !strings.EqualFold(fmt.Sprint(id["type"]), "None") {
		top.lose("identity", "the server's managed identity is not translated (#32): it is how Azure reached its key vault key; on the target, the key's own policy lets the database service use it", false)
	}
	top.quiet("identity")
}

func readPGServer(o snapshot.Object) *dbServer {
	s := newServer(o, false)
	s.tls, s.tlsMin = true, "TLSv1.2" // Azure's defaults, until a server parameter says otherwise
	top := newProps(spec(o), "")
	s.readTop(top)
	p := newProps(obj(top.m["properties"]), "properties.")
	s.admin = p.str("administratorLogin")
	p.quiet("administratorLoginPassword") // never in a capture, never carried
	s.version = p.str("version")
	st := newProps(obj(p.m["storage"]), "properties.storage.")
	if n := st.integer("storageSizeGB"); n != nil {
		s.storageGB = *n
	}
	s.autoGrow = strings.EqualFold(st.str("autoGrow"), "Enabled")
	for _, k := range []string{"autoGrowMaxThresholdMb", "autoGrowIncrementPercent"} {
		if v, _ := st.take(k); v != nil {
			st.lose(k, fmt.Sprintf("%v: how far and by how much Azure grows storage has no equivalent; the target grows it by its own rule", v), false)
		}
	}
	st.quiet("tier") // the disk's performance tier, which follows its size on Azure
	for _, k := range []string{"iops", "throughput"} {
		if v, _ := st.take(k); v != nil {
			st.lose(k, fmt.Sprintf("%v: provisioned storage performance is not carried over; the target's storage gives its own baseline", v), false)
		}
	}
	st.unlessDefault("type", "Premium_LRS", "Azure's disk type has no equivalent: the target's storage is its own")
	p.quiet("storage")
	a := newProps(obj(p.m["authConfig"]), "properties.authConfig.")
	if strings.EqualFold(a.str("activeDirectoryAuth"), "Enabled") {
		s.entra = true
	}
	if strings.EqualFold(a.str("passwordAuth"), "Disabled") {
		s.refuse = "it takes Microsoft Entra ID sign-in only: " + whyIdentity + ", and the target would take passwords, which the source did not"
	}
	a.quiet("tenantId")
	p.quiet("authConfig")
	enc := newProps(obj(p.m["dataEncryption"]), "properties.dataEncryption.")
	if strings.EqualFold(enc.str("type"), "AzureKeyVault") {
		s.cmk, s.cmkField = true, "properties.dataEncryption"
	}
	enc.quiet("primaryKeyURI", "primaryUserAssignedIdentityId", "geoBackupKeyURI", "geoBackupUserAssignedIdentityId",
		"primaryFederatedIdentityClientId", "geoBackupFederatedIdentityClientId") // the key itself is the map's
	p.quiet("dataEncryption")
	b := newProps(obj(p.m["backup"]), "properties.backup.")
	if n := b.integer("backupRetentionDays"); n != nil {
		s.backupDays = *n
	}
	if strings.EqualFold(b.str("geoRedundantBackup"), "Enabled") {
		b.lose("geoRedundantBackup", "its backups were copied to the paired region; the target keeps them in its own region until cross-region backup copies (AWS) or a backup location (GCP) are set up (not translated)", false)
	}
	if strings.EqualFold(b.str("immutableBackup"), "Enabled") {
		b.lose("immutableBackup", "its backups could not be deleted before their retention ended; the target's automated backups can be (not translated: AWS Backup vault lock, GCP backup vaults)", true)
	}
	p.quiet("backup")
	n := newProps(obj(p.m["network"]), "properties.network.")
	s.public = !strings.EqualFold(n.str("publicNetworkAccess"), "Disabled")
	if d := n.str("delegatedSubnetResourceId"); d != "" {
		s.subnet = subnetKey(d)
		if s.subnet == "" {
			s.refuse = "its delegated subnet could not be read from the reference " + d
		}
	}
	if z := n.str("privateDnsZoneArmResourceId"); z != "" {
		n.lose("privateDnsZoneArmResourceId", "its name was resolved in a private DNS zone; the target's endpoint has the target's own name, which apps must use", false)
	}
	p.quiet("network")
	h := newProps(obj(p.m["highAvailability"]), "properties.highAvailability.")
	switch mode := h.str("mode"); mode {
	case "ZoneRedundant":
		s.ha = true
	case "SameZone":
		s.ha = true
		h.lose("mode", "its standby was in its own zone; the target's is in another", false)
	}
	h.unlessDefault("standbyAvailabilityZone", "", "Azure's zone numbers name no zone on the target: the target picks")
	p.quiet("highAvailability")
	mw := newProps(obj(p.m["maintenanceWindow"]), "properties.maintenanceWindow.")
	if strings.EqualFold(mw.str("customWindow"), "Enabled") {
		mw.lose("customWindow", "its maintenance window is not carried over: the target's own window applies until one is set", false)
	}
	mw.quiet("startHour", "startMinute", "dayOfWeek")
	p.quiet("maintenanceWindow")
	p.unlessDefault("availabilityZone", "", "Azure's zone numbers name no zone on the target: the target picks")
	for _, k := range []string{"replicationRole"} {
		if r := p.str(k); r != "" && r != "None" && r != "Primary" {
			s.refuse = "it is a replica (" + r + "): " + whyReplica
		}
	}
	rp := newProps(obj(p.m["replica"]), "properties.replica.")
	if r := rp.str("role"); r != "" && r != "None" && r != "Primary" {
		s.refuse = "it is a replica (" + r + "): " + whyReplica
	}
	rp.quiet("promoteMode", "promoteOption")
	p.quiet("replica")
	switch cm := p.str("createMode"); cm {
	case "", "Default", "Create", "Update":
	case "Replica":
		s.refuse = "it is a replica: " + whyReplica
	default:
		p.lose("createMode", cm+": it was made from another server's backup; the target starts empty, since data is not moved", false)
	}
	p.quiet("sourceServerResourceId", "pointInTimeUTC") // with createMode
	if c := obj(p.m["cluster"]); c != nil {
		if size := newProps(c, "").integer("clusterSize"); size != nil && *size > 0 {
			s.refuse = "it is an elastic cluster, sharded over nodes: RDS and Cloud SQL have no peer"
		}
	}
	p.quiet("cluster")
	if strings.EqualFold(p.str("fipsMode"), "Enabled") {
		p.lose("fipsMode", "it used FIPS-validated cryptography only; the target is not set to (not translated)", true)
	}
	for _, x := range []*props{top, p, st, a, enc, b, n, h, mw, rp} {
		s.losses = append(s.losses, x.rest()...)
	}
	return s
}

func readSQLServer(o snapshot.Object) *dbServer {
	s := newServer(o, true)
	s.tls = true // Azure SQL takes encrypted connections only
	top := newProps(spec(o), "")
	s.readTop(top)
	p := newProps(obj(top.m["properties"]), "properties.")
	s.admin = p.str("administratorLogin")
	p.quiet("administratorLoginPassword") // never in a capture, never carried
	p.quiet("version")                    // 12.0: Azure SQL Database's version is nominal
	switch v := p.str("minimalTlsVersion"); v {
	case "", "None", "1.0":
	default:
		s.tlsMin = v
	}
	switch pna := p.str("publicNetworkAccess"); pna {
	case "Disabled":
	case "SecuredByPerimeter":
		p.lose("publicNetworkAccess", "a network security perimeter decided who reached it; it is not translated, and the target is reached privately only", false)
	default:
		s.public = true
	}
	p.quiet("primaryUserAssignedIdentityId", "federatedClientId") // identity, named with it
	if k := p.str("keyId"); k != "" {
		s.cmk, s.cmkField = true, "properties.keyId"
	}
	ad := newProps(obj(p.m["administrators"]), "properties.administrators.")
	if ad.str("login") != "" {
		s.entra = true
	}
	if ad.boolean("azureADOnlyAuthentication") {
		s.refuse = "it takes Microsoft Entra ID sign-in only: " + whyIdentity + ", and the target would take passwords, which the source did not"
	}
	ad.quiet("administratorType", "principalType", "sid", "tenantId")
	p.quiet("administrators")
	if strings.EqualFold(p.str("restrictOutboundNetworkAccess"), "Enabled") {
		p.lose("restrictOutboundNetworkAccess", "it could connect out only to the names its outbound firewall rules allow; the target is not restricted (not translated)", true)
	}
	if strings.EqualFold(p.str("isIPv6Enabled"), "Enabled") {
		p.lose("isIPv6Enabled", "it answered on IPv6 too; the target answers on IPv4 only, so IPv6 clients lose it", false)
	}
	if d := p.integer("retentionDays"); d != nil && *d > 0 {
		s.softDelete = *d
	}
	switch cm := p.str("createMode"); cm {
	case "", "Normal":
	default:
		p.lose("createMode", cm+": it was restored from a deleted server; the target starts empty, since data is not moved", false)
	}
	for _, x := range []*props{top, p, ad} {
		s.losses = append(s.losses, x.rest()...)
	}
	return s
}

var subnetRefRE = regexp.MustCompile(`^\{\{truthform\|ref\|(?i:Microsoft\.Network/virtualNetworks/subnets)\|([^|{}]*)\|([^|{}]+)\|[^|{}]*\}\}$`)

// subnetKey is the group/network/subnet a subnet reference names, lower
// case: a captured token or a resource ID.
func subnetKey(ref string) string {
	if m := subnetRefRE.FindStringSubmatch(ref); m != nil && strings.Count(m[2], "/") == 1 {
		return strings.ToLower(m[1] + "/" + m[2])
	}
	parts := strings.Split(ref, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			for j := i + 2; j+3 < len(parts); j++ {
				if strings.EqualFold(parts[j], "virtualNetworks") && strings.EqualFold(parts[j+2], "subnets") {
					return strings.ToLower(parts[i+1] + "/" + parts[j+1] + "/" + parts[j+3])
				}
			}
		}
	}
	return ""
}

// pgSystemDBs are the databases Azure makes on every flexible server.
var pgSystemDBs = map[string]bool{"postgres": true, "azure_maintenance": true, "azure_sys": true}

func readPGDatabase(s *dbServer, name string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	d := dbDatabase{name: name, charset: p.str("charset"), collation: p.str("collation")}
	if pgSystemDBs[strings.ToLower(name)] {
		return "one of the databases Azure makes on every server: the target makes its own", append(top.rest(), p.rest()...)
	}
	s.dbs = append(s.dbs, d)
	return "", append(top.rest(), p.rest()...)
}

// readPGConfig reads a server parameter. One left at Azure's default is
// not carried over: the target's default stands, as the source's did.
func readPGConfig(s *dbServer, name string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	value, src := p.str("value"), p.str("source")
	set := src != "system-default"
	losses := append(top.rest(), p.rest()...)
	switch n := strings.ToLower(name); {
	case n == "require_secure_transport":
		s.tls = !offValue(value)
		return "read with its server: whether it takes plain-text connections", losses
	case n == "ssl_min_protocol_version":
		if set {
			s.tlsMin, s.tlsMinSet = value, true
		}
		return "read with its server: the oldest TLS version it takes", losses
	case !set:
		return "left at Azure's default: the target's default stands", losses
	case n == "azure.extensions":
		for _, x := range strings.Split(value, ",") {
			if x = strings.ToLower(strings.TrimSpace(x)); x != "" {
				s.extensions = append(s.extensions, x)
			}
		}
		return "Azure's allow-list of extensions: the target has none, and the extensions are created in its databases (see the requirements)", losses
	case strings.HasPrefix(n, "azure.") || strings.HasPrefix(n, "pgms_") || strings.HasPrefix(n, "metrics.") || strings.HasPrefix(n, "pgbouncer."):
		return "", append(losses, Loss{Field: "properties.value", Why: value + ": an Azure parameter, with no equivalent on the target"})
	}
	s.params = append(s.params, pgParam{name: name, value: value, child: len(s.children)})
	return "", losses
}

func offValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off", "0", "false":
		return true
	}
	return false
}

// readFirewallRule reads an allowed range of addresses. A range that
// cannot be read allows nothing on the target: less than the source.
func readFirewallRule(s *dbServer, name string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	a, b := p.str("startIpAddress"), p.str("endIpAddress")
	losses := append(top.rest(), p.rest()...)
	lo, err1 := netip.ParseAddr(a)
	hi, err2 := netip.ParseAddr(b)
	switch {
	case err1 != nil || err2 != nil || !lo.Is4() || !hi.Is4() || hi.Less(lo):
		return "", append(losses, Loss{Field: "properties", Why: fmt.Sprintf("%s-%s is not an IPv4 range; nothing is allowed for it on the target", a, b)})
	case a == "0.0.0.0" && b == "0.0.0.0":
		s.firewall = append(s.firewall, fwRule{name: name, azure: true, child: len(s.children)})
	default:
		s.firewall = append(s.firewall, fwRule{name: name, prefixes: rangePrefixes(lo, hi), child: len(s.children)})
	}
	return "", losses
}

func readVNetRule(s *dbServer, name string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	ref := p.str("virtualNetworkSubnetId")
	p.quiet("ignoreMissingVnetServiceEndpoint")
	losses := append(top.rest(), p.rest()...)
	if k := subnetKey(ref); k != "" {
		s.vnetRules = append(s.vnetRules, vnetRule{subnet: k, child: len(s.children)})
		return "", losses
	}
	return "", append(losses, Loss{Field: "properties.virtualNetworkSubnetId", Why: ref + " could not be read as a subnet; nothing is allowed for it on the target"})
}

func readIPv6Rule(_ *dbServer, _ string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	a, b := p.str("startIPv6Address"), p.str("endIPv6Address")
	return "", append(append(top.rest(), p.rest()...), Loss{Field: "properties", Why: a + "-" + b + ": the target answers on IPv4 only, so this range is not allowed (less than the source)"})
}

func readProtector(s *dbServer, _ string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties", "kind")
	p := newProps(obj(sp["properties"]), "properties.")
	if strings.EqualFold(p.str("serverKeyType"), "AzureKeyVault") {
		s.cmk, s.cmkField = true, "encryptionProtector"
	}
	p.quiet("serverKeyName", "autoRotationEnabled") // the key itself is the map's
	return "read with its server: which key encrypts its databases", append(top.rest(), p.rest()...)
}

func readTDE(_ *dbServer, _ string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	var losses []Loss
	if strings.EqualFold(p.str("state"), "Disabled") {
		losses = append(losses, Loss{Field: "properties.state", Why: "Disabled: the target encrypts the instance's storage whatever this said"})
	}
	p.quiet("scanState")
	return "read with its server, whose instance is encrypted at rest", append(append(top.rest(), p.rest()...), losses...)
}

func readDBRetention(s *dbServer, _ string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	if d := p.integer("retentionDays"); d != nil && *d > s.backupDays {
		s.backupDays = *d
	}
	p.unlessDefault("diffBackupIntervalInHours", 12, "how often Azure takes differential backups has no equivalent: the target backs up on its own schedule")
	return "read with its server: the instance keeps backups as long as the longest of its databases did", append(top.rest(), p.rest()...)
}

func readGeoBackup(_ *dbServer, _ string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	var losses []Loss
	if strings.EqualFold(p.str("state"), "Enabled") {
		losses = append(losses, Loss{Field: "properties.state", Why: "its backups were copied to the paired region; the target keeps them in its own region (not translated)"})
	}
	return "", append(append(top.rest(), p.rest()...), losses...)
}

func readLTR(_ *dbServer, _ string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	var kept []string
	for _, k := range []string{"weeklyRetention", "monthlyRetention", "yearlyRetention"} {
		if v := p.str(k); v != "" && v != "PT0S" {
			kept = append(kept, k+" "+v)
		}
	}
	p.quiet("weekOfYear", "timeBasedImmutabilityMode")
	immutable := strings.EqualFold(p.str("timeBasedImmutability"), "Enabled")
	var losses []Loss
	if len(kept) > 0 {
		losses = append(losses, Loss{Field: "properties", Why: strings.Join(kept, ", ") + ": long-term backups are not translated; AWS Backup or Cloud SQL's own retention is set on its own"})
	}
	if immutable && len(kept) > 0 {
		losses = append(losses, Loss{Field: "properties.timeBasedImmutability", Widens: true, Why: "its long-term backups could not be deleted before they expired; the target has none (not translated)"})
	}
	return "", append(append(top.rest(), p.rest()...), losses...)
}

// protection reads a setting that protects the server (auditing, threat
// detection): on, it is lost, and the target is less watched than the
// source was. Its other settings say how it reported, and go with it.
func protection(what, nearest string) childReader {
	return func(_ *dbServer, _ string, sp map[string]any) (string, []Loss) {
		top := newProps(sp, "")
		top.quiet("name", "properties", "kind")
		p := newProps(obj(sp["properties"]), "properties.")
		on := strings.EqualFold(p.str("state"), "Enabled")
		for k := range p.m {
			p.quiet(k) // where and how it reported: lost with it
		}
		losses := append(top.rest(), p.rest()...)
		if !on {
			return "off on the source: nothing to carry", losses
		}
		return "", append(losses, Loss{Field: "properties.state", Widens: true,
			Why: "Enabled: " + what + " is not translated, and the target is not watched as the source was until its own (" + nearest + ") is set up"})
	}
}

// assessment is the classic vulnerability assessment: on when it scans
// on a schedule or has somewhere to write.
func assessment(_ *dbServer, _ string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties")
	p := newProps(obj(sp["properties"]), "properties.")
	rs := newProps(obj(p.m["recurringScans"]), "properties.recurringScans.")
	on := rs.boolean("isEnabled") || p.str("storageContainerPath") != ""
	rs.quiet("emailSubscriptionAdmins", "emails")
	p.quiet("recurringScans", "storageContainerSasKey", "storageAccountAccessKey")
	losses := append(append(top.rest(), p.rest()...), rs.rest()...)
	if !on {
		return "off on the source: nothing to carry", losses
	}
	return "", append(losses, Loss{Field: "properties", Widens: true,
		Why: "vulnerability assessment is not translated, and the target is not scanned as the source was until its own (Security Hub, Security Command Center) is set up"})
}

// sqlSystemDBs are the databases every Azure SQL server has.
var sqlSystemDBs = map[string]bool{"master": true}

func readSQLDatabase(s *dbServer, name string, sp map[string]any) (string, []Loss) {
	top := newProps(sp, "")
	top.quiet("name", "properties", "location", "kind", "managedBy")
	if sku := obj(top.m["sku"]); sku != nil && !sqlSystemDBs[strings.ToLower(name)] {
		top.lose("sku", fmt.Sprintf("%v: each Azure SQL database has its own size; on the target the databases share the instance's, which the map gives", sku["name"]), false)
	}
	top.quiet("sku")
	if t := stringTags(top.m["tags"]); len(t) > 0 {
		top.lose("tags", "a database's tags have nowhere to go: the instance carries the server's", false)
	}
	top.quiet("tags")
	if id := obj(top.m["identity"]); len(id) > 0 && !strings.EqualFold(fmt.Sprint(id["type"]), "None") {
		top.lose("identity", "the database's managed identity is not translated (#32)", false)
	}
	top.quiet("identity")
	p := newProps(obj(sp["properties"]), "properties.")
	d := dbDatabase{name: name, collation: p.str("collation")}
	if sqlSystemDBs[strings.ToLower(name)] {
		for k := range p.m {
			p.quiet(k)
		}
		return "the server's system database: the target has its own", append(top.rest(), p.rest()...)
	}
	switch cm := p.str("createMode"); cm {
	case "", "Default":
	default:
		p.lose("createMode", cm+": it was made from another database or a backup; the target's starts empty, since data is not moved", false)
	}
	p.quiet("sourceDatabaseId", "restorePointInTime", "sourceDatabaseDeletionDate", "recoveryServicesRecoveryPointId",
		"longTermRetentionBackupResourceId", "recoverableDatabaseId", "restorableDroppedDatabaseId", "sourceResourceId",
		"secondaryType", "manualCutover", "performCutover", "elasticPoolId", "federatedClientId", "licenseType")
	if n := p.integer("maxSizeBytes"); n != nil {
		s.storageGB += int(math.Ceil(float64(*n) / (1 << 30)))
	}
	if c := p.str("sampleName"); c != "" {
		p.lose("sampleName", c+": a sample database's data is not made on the target", false)
	}
	p.unlessDefault("catalogCollation", "SQL_Latin1_General_CP1_CI_AS", "the catalog collation is set when the database is created (see the requirements)")
	if p.boolean("zoneRedundant") {
		s.ha = true
	}
	p.unlessDefault("readScale", "Disabled", "a read-only replica is not translated: reads go to the instance")
	if n := p.integer("highAvailabilityReplicaCount"); n != nil && *n > 0 {
		p.lose("highAvailabilityReplicaCount", fmt.Sprintf("%d replica(s) for high availability are not translated: the instance's own standby (MultiAZ, REGIONAL) is set by its zone redundancy", *n), false)
	}
	for _, k := range []string{"autoPauseDelay", "minCapacity"} {
		if v, _ := p.take(k); v != nil {
			p.lose(k, fmt.Sprintf("%v: serverless scaling and pausing are not translated: the instance runs at the map's size", v), false)
		}
	}
	switch r := p.str("requestedBackupStorageRedundancy"); r {
	case "Geo", "GeoZone":
		p.lose("requestedBackupStorageRedundancy", r+": its backups were copied to the paired region; the target keeps them in its own region (not translated)", false)
	}
	p.unlessDefault("maintenanceConfigurationId", "", "its maintenance window is not carried over: the target's own applies")
	if p.boolean("isLedgerOn") {
		d.ledger = true
	}
	if p.str("encryptionProtector") != "" || len(obj(p.m["keys"])) > 0 {
		s.cmk, s.cmkField = true, "databases/"+name+": properties.encryptionProtector"
	}
	p.quiet("keys", "encryptionProtector", "encryptionProtectorAutoRotation")
	p.unlessDefault("preferredEnclaveType", "Default", "Always Encrypted with secure enclaves (VBS) is not available on the target: queries that used the enclave fail")
	if p.boolean("useFreeLimit") {
		p.lose("useFreeLimit", "Azure's free offer has no equivalent", false)
	}
	p.quiet("freeLimitExhaustionBehavior")
	p.unlessDefault("availabilityZone", "NoPreference", "Azure's zone numbers name no zone on the target: the target picks")
	s.dbs = append(s.dbs, d)
	return "", append(top.rest(), p.rest()...)
}

// rangePrefixes is an IPv4 range as the fewest prefixes that hold
// exactly its addresses.
func rangePrefixes(lo, hi netip.Addr) []netip.Prefix {
	a := lo.As4()
	b := hi.As4()
	x := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
	y := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	var out []netip.Prefix
	for x <= y {
		bits := 32
		for bits > 0 {
			size := uint64(1) << (32 - (bits - 1))
			if x%size != 0 || x+size-1 > y {
				break
			}
			bits--
		}
		addr := netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
		out = append(out, netip.PrefixFrom(addr, bits))
		x += uint64(1) << (32 - bits)
	}
	return out
}

// placement is where a server goes in a translated network: its delegated
// subnet first, then the map's.
type placement struct {
	vnet    *vnet
	subnets []*subnet
}

// place finds the server's subnets in what the network family read. need
// says whether the target needs them when the server is public.
func (s *dbServer) place(m Map, o *out, publicNeeds bool) (*placement, string) {
	dm, _ := m.database(s.mapKey())
	field := "databases." + s.mapKey() + ".subnets"
	pl := &placement{}
	add := func(k, what string) string {
		sn := o.subnets[strings.ToLower(k)]
		if sn == nil {
			return what + " " + k + " is not a subnet of a network in the snapshot"
		}
		if pl.vnet != nil && sn.vnet != pl.vnet {
			return fmt.Sprintf("%s %s is in %s, and the instance's other subnets in %s: an instance is in one network", what, k, sn.vnet.src, pl.vnet.src)
		}
		for _, x := range pl.subnets {
			if x == sn {
				return ""
			}
		}
		pl.vnet = sn.vnet
		pl.subnets = append(pl.subnets, sn)
		return ""
	}
	if s.subnet != "" {
		if why := add(s.subnet, "its delegated subnet"); why != "" {
			return nil, why
		}
	}
	for _, k := range dm.Subnets {
		if why := add(k, field+" names"); why != "" {
			return nil, why
		}
	}
	if len(pl.subnets) == 0 {
		switch {
		case !s.public:
			return nil, "it is reached privately (public network access is disabled), and the map names no subnet to place it in (" + field + ")"
		case publicNeeds:
			return nil, "RDS places an instance in a VPC, where a security group holds its firewall rules, and the map names no subnets for it (" + field + ", in two availability zones)"
		}
		return nil, ""
	}
	return pl, ""
}

// requirements are what every target needs for a server: its databases,
// extensions and sign-in.
func (s *dbServer) requirements(o *out, instance, what string) {
	for _, d := range s.dbs {
		var with []string
		for _, x := range []string{d.charset, d.collation} {
			if x != "" {
				with = append(with, x)
			}
		}
		if d.ledger {
			with = append(with, "WITH LEDGER = ON")
		}
		w := ""
		if len(with) > 0 {
			w = " (" + strings.Join(with, ", ") + ")"
		}
		o.require(fmt.Sprintf("Create database %s%s on %s %s, with its owner, then move its data (a dump and restore, or a database migration service): no database or data is written", d.name, w, what, instance))
	}
	if len(s.extensions) > 0 {
		o.require(fmt.Sprintf("Create the extensions %s in the databases of %s %s that used them (CREATE EXTENSION): Azure allow-listed them, and the target has no allow-list", strings.Join(s.extensions, ", "), what, instance))
	}
	if s.entra {
		to := "IAM database authentication"
		switch {
		case s.sql && what == "RDS instance":
			to = "Windows authentication through AWS Managed Microsoft AD (RDS for SQL Server has no IAM database authentication)"
		case s.sql:
			to = "Windows authentication through Managed Microsoft AD, or Cloud SQL's own Microsoft Entra ID setting (entraidConfig)"
		}
		o.require(fmt.Sprintf("Users who signed in to %s with Microsoft Entra ID move to %s on %s %s: identity is not translated (#32)", s.src, to, what, instance))
	}
}
