package translate

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Azure storage accounts and their blob containers, read into a model the
// AWS and GCP writers share.
//
// A blob container becomes a bucket: an S3 bucket (AWS) or a Cloud Storage
// bucket (GCP). The account is not a bucket. What it says (encryption,
// network access, TLS, redundancy, access tier, immutability) applies to
// each of its containers, so it is written into each container's bucket,
// and the account's entry names what of it each target loses. Bucket names
// are global on both targets: a container's is <account>-<container>
// unless the map names it.
//
// Public access is never written: a public container would need a bucket
// policy granting everyone read (AWS) or allUsers on the bucket's IAM
// (GCP), and access grants are identity, which is not translated (#32). A
// public container is refused; every bucket written blocks public access.
// Files, queues and tables are not buckets: their services are named, not
// translated.

const (
	azStorage      = "microsoft.storage/storageaccounts"
	azBlobSvc      = azStorage + "/blobservices"
	azContainer    = azBlobSvc + "/containers"
	azImmutability = azContainer + "/immutabilitypolicies"
	azScope        = azStorage + "/encryptionscopes"
	azLocalUser    = azStorage + "/localusers"
)

type storage struct{}

func (storage) claims(kind string) bool {
	return kind == azStorage || strings.HasPrefix(kind, azStorage+"/")
}

// stAccount is one storage account and what it says about all its
// containers' buckets.
type stAccount struct {
	src, group, name string
	key              string // group/name, lower case
	tags             map[string]string
	sku              string // Standard_LRS, Standard_GRS, ...
	tier             string // Hot, Cool, Cold, Premium, Smart
	publicBlob       bool   // allowBlobPublicAccess
	httpsOnly        bool
	tls              string // TLS1_0 ... TLS1_3, "" when unset
	// private says why the public endpoint is closed, "" when open;
	// closed is set when nothing but private endpoints reach it.
	private string
	closed  bool
	// The firewall, when it denies by default: the public address ranges
	// it allows, and what else it lets through that the targets cannot.
	ranges     []string
	vnetRules  int
	bypass     string
	resRules   int
	cmk, infra bool
	keys       bool // shared key access
	hns        bool
	sftp, nfs  bool
	worm       *stWORM // version-level immutability on the account
	losses     []Loss  // target-independent
	blob       *stBlob
	containers []*stContainer
	scopes     map[string]*stScope // by name, lower case
	refuse     string
}

// stWORM is version-level immutability: its default retention, if any.
type stWORM struct {
	days    *int
	state   string // Unlocked, Locked, Disabled
	appends bool
}

// stBlob is an account's blob service.
type stBlob struct {
	src        string
	versioning bool
	softDelete *stRetention // deleted and overwritten blobs
	softBucket *stRetention // deleted containers
	changeFeed bool
	restore    *int // point-in-time restore, days
	lastAccess bool
	cors       []stCORS
	website    bool
	losses     []Loss
}

type stRetention struct {
	days      int
	permanent bool // a soft-deleted item may be deleted for good early
}

type stCORS struct {
	origins, methods, allowed, exposed []string
	maxAge                             int
}

// stContainer is a blob container: one bucket.
type stContainer struct {
	src, group, account, name string
	key                       string // group/account/container, for names
	public                    string // Blob, Container; "" when private
	versionWORM               bool
	policy                    *stPolicy // time-based retention
	legalHold                 bool
	scope                     string // default encryption scope; "" for the account's
	losses                    []Loss
}

// stPolicy is a container's time-based retention policy.
type stPolicy struct {
	src     string
	days    int
	state   string // Locked, Unlocked; "" when the snapshot does not say
	appends bool
	unread  []Loss // what no rule reads, named on its container
}

type stScope struct {
	src        string
	cmk, infra bool
	losses     []Loss
}

// stDefaultScope is the account's own encryption, the default every
// container has.
const stDefaultScope = "$account-encryption-key"

func (storage) translate(objs []snapshot.Object, o *out) {
	accts := map[string]*stAccount{}
	var blobs, conts, pols, scopes, rest []snapshot.Object
	for _, obj := range objs {
		switch strings.ToLower(obj.Kind()) {
		case azStorage:
			a := readAccount(obj)
			accts[a.key] = a
		case azBlobSvc:
			blobs = append(blobs, obj)
		case azContainer:
			conts = append(conts, obj)
		case azImmutability:
			pols = append(pols, obj)
		case azScope:
			scopes = append(scopes, obj)
		default:
			rest = append(rest, obj)
		}
	}
	acctOf := func(obj snapshot.Object) *stAccount {
		name, _, _ := strings.Cut(obj.Name(), "/")
		return accts[strings.ToLower(obj.Namespace()+"/"+name)]
	}
	stOthers(rest, objs, o)
	// Children a capture keeps as objects of their own are read with their
	// account, as if inline.
	var orphans []Entry
	orphan := func(obj snapshot.Object, why string) {
		orphans = append(orphans, Entry{Source: source(obj), State: Refused, Reason: why})
	}
	for _, obj := range scopes {
		a := acctOf(obj)
		if a == nil {
			orphan(obj, "its storage account is not in the snapshot")
			continue
		}
		_, name, _ := strings.Cut(obj.Name(), "/")
		a.scopes[strings.ToLower(name)] = readScope(obj)
	}
	for _, obj := range blobs {
		a := acctOf(obj)
		if a == nil {
			orphan(obj, "its storage account is not in the snapshot")
			continue
		}
		a.blob = readBlobService(obj)
	}
	conByKey := map[string]*stContainer{}
	for _, obj := range conts {
		a := acctOf(obj)
		if a == nil {
			orphan(obj, "its storage account is not in the snapshot")
			continue
		}
		c := readContainer(obj)
		a.containers = append(a.containers, c)
		conByKey[strings.ToLower(c.key)] = c
	}
	for _, obj := range pols {
		parts := strings.Split(obj.Name(), "/")
		var c *stContainer
		if len(parts) == 4 { // account/default/container/default
			c = conByKey[strings.ToLower(obj.Namespace()+"/"+parts[0]+"/"+parts[2])]
		}
		if c == nil {
			orphan(obj, "its container is not in the snapshot")
			continue
		}
		c.policy = readImmutability(obj)
	}
	o.entries = append(o.entries, orphans...)
	var w bucketWriter
	switch {
	case o.m.Destinations.Storage == "":
		why := "the map chooses no destination for storage (destinations.storage)"
		for _, a := range sortedAccounts(accts) {
			for _, src := range a.sources() {
				o.entries = append(o.entries, Entry{Source: src, State: Refused, Reason: why})
			}
		}
		return
	case o.m.To == "aws":
		w = awsBuckets{m: o.m}
	case o.m.To == "gcp":
		w = gcpBuckets{m: o.m}
	}
	for _, a := range sortedAccounts(accts) {
		writeAccount(a, w, o)
	}
}

// sources are the report names of an account and what is read with it.
func (a *stAccount) sources() []string {
	out := []string{a.src}
	if a.blob != nil {
		out = append(out, a.blob.src)
	}
	for _, c := range a.containers {
		out = append(out, c.src)
		if c.policy != nil {
			out = append(out, c.policy.src)
		}
	}
	for _, k := range sortedKeys(a.scopes) {
		out = append(out, a.scopes[k].src)
	}
	return out
}

func sortedAccounts(m map[string]*stAccount) []*stAccount {
	out := make([]*stAccount, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	return out
}

// stOthers decides the account's children that are not blob storage.
func stOthers(rest, all []snapshot.Object, o *out) {
	// A service with nothing in it is only its settings, which apply to
	// items there are none of.
	held := map[string]bool{}
	for _, obj := range all {
		k := strings.ToLower(obj.Kind())
		for _, svc := range []string{"fileservices", "queueservices", "tableservices"} {
			if strings.HasPrefix(k, azStorage+"/"+svc+"/") && k != azStorage+"/fileservices/usages" {
				acct, _, _ := strings.Cut(obj.Name(), "/")
				held[strings.ToLower(svc+"|"+obj.Namespace()+"/"+acct)] = true
			}
		}
	}
	hint := map[string]string{
		"fileservices":  "file shares are not buckets (the nearest equivalents are Amazon EFS or FSx, and Filestore)",
		"queueservices": "storage queues are not buckets (the nearest equivalents are SQS and Pub/Sub)",
		"tableservices": "tables are not buckets (the nearest equivalents are DynamoDB, and Firestore or Bigtable)",
	}
	for _, obj := range rest {
		k := strings.ToLower(obj.Kind())
		child := strings.TrimPrefix(k, azStorage+"/")
		svc, item, nested := strings.Cut(child, "/")
		e := Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"}
		switch {
		case hint[svc] != "" && !nested:
			acct, _, _ := strings.Cut(obj.Name(), "/")
			if held[strings.ToLower(svc+"|"+obj.Namespace()+"/"+acct)] {
				e.Reason += ": " + hint[svc]
			} else {
				e.State, e.Reason = Mapped, "a service with nothing of its own in the snapshot: its settings apply to items there are none of, so nothing is written"
			}
		case hint[svc] != "" && item != "":
			e.Reason += ": " + hint[svc]
		case k == azLocalUser:
			e.State, e.Reason = Refused, "a local user (SFTP or NFS, with its own keys or password): identity is not translated (#32)"
			o.require("Local users of a storage account (SFTP, NFS) are identity and are not translated (#32): give each client an IAM or workload identity on the target, or a managed file transfer service (AWS Transfer Family)")
		case k == azStorage+"/managementpolicies":
			e.Reason += ": lifecycle rules are not translated (the nearest equivalents are an S3 lifecycle configuration and Cloud Storage lifecycle rules)"
		case k == azStorage+"/inventorypolicies":
			e.Reason += ": blob inventory is not translated (the nearest equivalents are S3 Inventory and Storage Insights inventory reports)"
		case k == azStorage+"/objectreplicationpolicies":
			e.Reason += ": object replication is not translated (the nearest equivalents are S3 Replication and the Storage Transfer Service)"
		case k == azStorage+"/privateendpointconnections":
			e.Reason += ": a private endpoint into the account; the buckets' network access is in the account's entry"
		}
		o.entries = append(o.entries, e)
	}
}

func readAccount(o snapshot.Object) *stAccount {
	a := &stAccount{src: source(o), group: o.Namespace(), name: o.Name(), key: strings.ToLower(o.Namespace() + "/" + o.Name()), scopes: map[string]*stScope{}}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name")
	a.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	if s := obj2props(top, "sku", "sku."); s != nil {
		a.sku = s.str("name")
		s.quiet("tier") // what the name says
		a.losses = append(a.losses, s.rest()...)
	}
	switch k := top.str("kind"); k {
	case "", "StorageV2", "BlobStorage", "BlockBlobStorage", "Storage", "FileStorage":
	default:
		top.lose("kind", k+": not a kind of account this reads", false)
	}
	if el, _ := top.take("extendedLocation"); len(obj(el)) > 0 {
		top.lose("extendedLocation", "an edge zone has no equivalent here: the buckets are written to the map's region", false)
	}
	if z, _ := top.take("zones"); len(list(z)) > 0 {
		top.lose("zones", "a zonal account has no equivalent: a bucket is regional", false)
	}
	if pl, _ := top.take("placement"); len(obj(pl)) > 0 {
		top.lose("placement", "zone placement has no equivalent: a bucket is regional", false)
	}
	if id := obj(top.m["identity"]); len(id) > 0 && !strings.EqualFold(fmt.Sprint(id["type"]), "None") {
		top.lose("identity", "the account's managed identity is not translated (identity is a separate design, #32)", false)
	}
	top.quiet("identity")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "primaryEndpoints", "secondaryEndpoints", "primaryLocation", "secondaryLocation",
		"statusOfPrimary", "statusOfSecondary", "creationTime", "lastGeoFailoverTime", "keyCreationTime",
		"privateEndpointConnections", "geoReplicationStats", "isSkuConversionBlocked", "accountMigrationInProgress",
		"blobRestoreStatus", "storageAccountSkuConversionStatus", "failoverInProgress")
	if s := p.str("allowedCopyScope"); s != "" && s != "All" {
		p.lose("allowedCopyScope", s+": copies into the account were limited to its own tenant or private links; nothing on the target limits where a copy comes from", true)
	}
	if sp := obj2props(p, "sasPolicy", "properties.sasPolicy."); sp != nil {
		sp.quiet("sasExpirationPeriod", "expirationAction", "requireUserBoundUserDelegationSas", "requireUserBoundUserDelegationSasAction")
		a.losses = append(a.losses, sp.rest()...)
		p.lose("sasPolicy", "a policy on shared access signatures: no SAS is carried over, and the target's presigned or signed URLs last 7 days at most", false)
	}
	if kp := obj2props(p, "keyPolicy", "properties.keyPolicy."); kp != nil {
		kp.quiet("keyExpirationPeriodInDays")
		a.losses = append(a.losses, kp.rest()...)
		p.lose("keyPolicy", "a reminder to rotate the account keys: no account key is carried over", false)
	}
	if cd := obj(p.m["customDomain"]); len(cd) > 0 {
		p.lose("customDomain", fmt.Sprintf("the blob endpoint answered on %v; a bucket answers on its cloud's own name until a CDN or load balancer is put in front (not translated)", cd["name"]), false)
	}
	p.quiet("customDomain")
	a.readEncryption(p)
	a.readNetwork(p)
	a.tier = p.str("accessTier")
	if t := obj(p.m["turboTier"]); len(t) > 0 {
		p.lose("turboTier", "a performance tier with no equivalent here", false)
	}
	p.quiet("turboTier")
	if f := obj(p.m["azureFilesIdentityBasedAuthentication"]); len(f) > 0 {
		p.lose("azureFilesIdentityBasedAuthentication", "sign-in for file shares: file shares are not translated", false)
	}
	p.quiet("azureFilesIdentityBasedAuthentication")
	a.httpsOnly = true // Azure's default
	if v, ok := p.take("supportsHttpsTrafficOnly"); ok && v != nil {
		a.httpsOnly, _ = v.(bool)
	}
	a.sftp = p.boolean("isSftpEnabled")
	if p.boolean("isLocalUserEnabled") {
		p.lose("isLocalUserEnabled", "local users are identity, not translated (#32)", false)
	}
	if p.boolean("enableExtendedGroups") {
		p.lose("enableExtendedGroups", "local users' extended groups: local users are not translated (#32)", false)
	}
	a.hns = p.boolean("isHnsEnabled")
	p.unlessDefault("largeFileSharesState", "Disabled", "large file shares: file shares are not translated")
	if r := obj(p.m["routingPreference"]); len(r) > 0 {
		p.lose("routingPreference", "how traffic reaches the account (Microsoft or internet routing, extra endpoints) has no equivalent: a bucket answers on its cloud's endpoints", false)
	}
	p.quiet("routingPreference")
	// Both targets answer on IPv6 too: S3's dual-stack endpoints, and
	// Cloud Storage's own.
	p.quiet("dualStackEndpointPreference")
	a.publicBlob = p.boolean("allowBlobPublicAccess") // unset is false, Azure's default
	a.tls = p.str("minimumTlsVersion")
	a.keys = true // unset is allowed, Azure's default
	if v, ok := p.take("allowSharedKeyAccess"); ok && v != nil {
		a.keys, _ = v.(bool)
	}
	if sk := obj(p.m["allowSharedKeyAccessForServices"]); len(sk) > 0 && !a.keys {
		// Shared keys allowed again for some services: the blob one counts.
		if b := obj(sk["blob"]); b != nil {
			if on, _ := b["enabled"].(bool); on {
				a.keys = true
			}
		}
	}
	p.quiet("allowSharedKeyAccessForServices")
	a.nfs = p.boolean("isNfsV3Enabled")
	if p.boolean("allowCrossTenantReplication") {
		p.lose("allowCrossTenantReplication", "object replication across tenants: replication is not translated", false)
	}
	p.quiet("defaultToOAuthAuthentication") // the portal's default sign-in, not the account's
	if iw := obj(p.m["immutableStorageWithVersioning"]); iw != nil {
		w := newProps(iw, "properties.immutableStorageWithVersioning.")
		if w.boolean("enabled") {
			a.worm = &stWORM{}
			if pol := obj(w.m["immutabilityPolicy"]); pol != nil {
				pp := newProps(pol, "properties.immutableStorageWithVersioning.immutabilityPolicy.")
				a.worm.days = pp.integer("immutabilityPeriodSinceCreationInDays")
				a.worm.state = pp.str("state")
				a.worm.appends = pp.boolean("allowProtectedAppendWrites")
				if strings.EqualFold(a.worm.state, "Disabled") {
					a.worm.days = nil
				}
				a.losses = append(a.losses, pp.rest()...)
			}
		}
		w.quiet("immutabilityPolicy")
		a.losses = append(a.losses, w.rest()...)
	}
	p.quiet("immutableStorageWithVersioning")
	p.unlessDefault("dnsEndpointType", "Standard", "endpoints in an Azure DNS zone have no equivalent: a bucket answers on its cloud's name")
	if g := obj(p.m["geoPriorityReplicationStatus"]); g != nil {
		if on, _ := g["isBlobEnabled"].(bool); on {
			p.lose("geoPriorityReplicationStatus", "prioritized replication to the secondary region: replication to another region is not translated", false)
		}
	}
	p.quiet("geoPriorityReplicationStatus")
	if dc := obj(p.m["dataCollaborationPolicyProperties"]); dc != nil {
		for _, k := range sortedKeys(dc) {
			if on, _ := dc[k].(bool); on {
				p.lose("dataCollaborationPolicyProperties."+k, "allows a sharing feature (connectors, access points, data shares) that is not translated", false)
			}
		}
	}
	p.quiet("dataCollaborationPolicyProperties")
	p.quiet("allowCrossTenantDelegationSas") // no SAS is carried over
	a.losses = append(append(top.rest(), p.rest()...), a.losses...)
	return a
}

// obj2props reads a nested object as its own settings, or nil when unset.
func obj2props(p *props, k, prefix string) *props {
	v, _ := p.take(k)
	m := obj(v)
	if len(m) == 0 {
		return nil
	}
	return newProps(m, prefix)
}

func (a *stAccount) readEncryption(p *props) {
	e := obj2props(p, "encryption", "properties.encryption.")
	if e == nil {
		return
	}
	// Which services the account's key covers, and whether a queue's or
	// table's key is the account's: Azure encrypts every service, and only
	// blobs are written here.
	e.quiet("services")
	switch ks := e.str("keySource"); ks {
	case "", "Microsoft.Storage":
	case "Microsoft.Keyvault":
		a.cmk = true
	default:
		e.lose("keySource", ks+": not a key source this reads", true)
	}
	e.quiet("keyvaultproperties", "identity") // the customer's key, and who reads it: with keySource
	a.infra = e.boolean("requireInfrastructureEncryption")
	a.losses = append(a.losses, e.rest()...)
}

func (a *stAccount) readNetwork(p *props) {
	switch pna := p.str("publicNetworkAccess"); pna {
	case "Disabled":
		a.private, a.closed = "public network access is disabled: it answers only on private endpoints", true
	case "SecuredByPerimeter":
		a.private, a.closed = "public network access is decided by a network security perimeter", true
	}
	n := obj2props(p, "networkAcls", "properties.networkAcls.")
	if n == nil {
		return
	}
	deny := strings.EqualFold(n.str("defaultAction"), "Deny")
	for _, k := range []string{"ipRules", "ipv6Rules"} {
		for _, x := range list(n.m[k]) {
			v := fmt.Sprint(obj(x)["value"])
			if act, _ := obj(x)["action"].(string); act != "" && !strings.EqualFold(act, "Allow") {
				n.lose(k, fmt.Sprintf("%s: %s is not an action this reads; the range is not allowed", v, act), false)
				continue
			}
			pf, err := netip.ParsePrefix(v)
			if err != nil {
				ad, err2 := netip.ParseAddr(v)
				if err2 != nil {
					n.lose(k, v+" is not an address or range; it is not allowed", false)
					continue
				}
				pf = netip.PrefixFrom(ad, ad.BitLen())
			}
			a.ranges = append(a.ranges, pf.Masked().String())
		}
		n.quiet(k)
	}
	a.vnetRules = len(list(n.m["virtualNetworkRules"]))
	a.resRules = len(list(n.m["resourceAccessRules"]))
	n.quiet("virtualNetworkRules", "resourceAccessRules")
	if b := n.str("bypass"); b != "" && !strings.EqualFold(b, "None") {
		a.bypass = b
	}
	a.losses = append(a.losses, n.rest()...)
	if deny && !a.closed {
		a.private = fmt.Sprintf("its firewall denies by default and allows %d address range(s) and %d virtual network subnet(s)", len(a.ranges), a.vnetRules)
	}
	if !deny {
		a.ranges, a.vnetRules, a.resRules, a.bypass = nil, 0, 0, ""
	}
}

func readScope(o snapshot.Object) *stScope {
	s := &stScope{src: source(o)}
	top := newProps(spec(o), "")
	top.quiet("properties")
	p := newProps(obj(top.m["properties"]), "properties.")
	switch src := p.str("source"); src {
	case "", "Microsoft.Storage":
	case "Microsoft.KeyVault":
		s.cmk = true
	default:
		p.lose("source", src+": not a key source this reads", true)
	}
	p.quiet("keyVaultProperties", "creationTime", "lastModifiedTime")
	p.unlessDefault("state", "Enabled", "a disabled scope encrypts nothing new; its container is written with the bucket's default encryption")
	s.infra = p.boolean("requireInfrastructureEncryption")
	s.losses = append(top.rest(), p.rest()...)
	return s
}

func readBlobService(o snapshot.Object) *stBlob {
	b := &stBlob{src: source(o)}
	top := newProps(spec(o), "")
	top.quiet("properties", "name", "sku")
	p := newProps(obj(top.m["properties"]), "properties.")
	if c := obj2props(p, "cors", "properties.cors."); c != nil {
		for i, x := range list(c.m["corsRules"]) {
			r := newProps(obj(x), fmt.Sprintf("properties.cors.corsRules[%d].", i))
			strs := func(k string) []string {
				v, _ := r.take(k)
				var out []string
				for _, s := range list(v) {
					out = append(out, fmt.Sprint(s))
				}
				return out
			}
			rule := stCORS{origins: strs("allowedOrigins"), methods: strs("allowedMethods"), allowed: strs("allowedHeaders"), exposed: strs("exposedHeaders")}
			if n := r.integer("maxAgeInSeconds"); n != nil {
				rule.maxAge = *n
			}
			b.cors = append(b.cors, rule)
			b.losses = append(b.losses, r.rest()...)
		}
		c.quiet("corsRules")
		b.losses = append(b.losses, c.rest()...)
	}
	p.quiet("defaultServiceVersion") // the API version Azure answers anonymous requests with
	b.softDelete = readRetention(p, "deleteRetentionPolicy", &b.losses)
	b.softBucket = readRetention(p, "containerDeleteRetentionPolicy", &b.losses)
	if w := obj2props(p, "staticWebsite", "properties.staticWebsite."); w != nil {
		b.website = w.boolean("enabled")
		w.quiet("indexDocument", "defaultIndexDocumentPath", "errorDocument404Path")
		b.losses = append(b.losses, w.rest()...)
	}
	b.versioning = p.boolean("isVersioningEnabled")
	p.unlessDefault("automaticSnapshotPolicyEnabled", false, "a retired setting with no equivalent")
	if cf := obj2props(p, "changeFeed", "properties.changeFeed."); cf != nil {
		b.changeFeed = cf.boolean("enabled")
		cf.quiet("retentionInDays")
		b.losses = append(b.losses, cf.rest()...)
	}
	if rp := obj2props(p, "restorePolicy", "properties.restorePolicy."); rp != nil {
		if rp.boolean("enabled") {
			b.restore = rp.integer("days")
			if b.restore == nil {
				b.restore = new(int)
			}
		}
		rp.quiet("days", "minRestoreTime", "lastEnabledTime")
		b.losses = append(b.losses, rp.rest()...)
	}
	if la := obj2props(p, "lastAccessTimeTrackingPolicy", "properties.lastAccessTimeTrackingPolicy."); la != nil {
		b.lastAccess = la.boolean("enable")
		la.quiet("name", "trackingGranularityInDays", "blobType")
		b.losses = append(b.losses, la.rest()...)
	}
	b.losses = append(append(top.rest(), p.rest()...), b.losses...)
	return b
}

func readRetention(p *props, k string, losses *[]Loss) *stRetention {
	r := obj2props(p, k, "properties."+k+".")
	if r == nil {
		return nil
	}
	defer func() { *losses = append(*losses, r.rest()...) }()
	if !r.boolean("enabled") {
		r.quiet("days", "allowPermanentDelete")
		return nil
	}
	out := &stRetention{permanent: r.boolean("allowPermanentDelete")}
	if d := r.integer("days"); d != nil {
		out.days = *d
	} else {
		r.lose("days", "enabled with no number of days: Azure keeps deleted items 7 days, and so does this", false)
		out.days = 7
	}
	return out
}

func readContainer(o snapshot.Object) *stContainer {
	parts := strings.Split(o.Name(), "/")
	c := &stContainer{src: source(o), group: o.Namespace(), account: parts[0], name: parts[len(parts)-1]}
	c.key = c.group + "/" + c.account + "/" + c.name
	top := newProps(spec(o), "")
	top.quiet("properties", "name")
	p := newProps(obj(top.m["properties"]), "properties.")
	// What Azure sets and a capture keeps in status, should a spec have
	// kept it.
	p.quiet("version", "deleted", "deletedTime", "remainingRetentionDays", "lastModifiedTime", "leaseStatus",
		"leaseState", "leaseDuration", "immutabilityPolicy", "legalHold", "hasImmutabilityPolicy", "hasLegalHold")
	if s := p.str("defaultEncryptionScope"); s != "" && s != stDefaultScope {
		c.scope = s
	}
	if p.boolean("denyEncryptionScopeOverride") {
		p.lose("denyEncryptionScopeOverride", "on Azure a blob could not name its own encryption scope; on the target a writer may name its own encryption for an object", false)
	}
	switch pa := p.str("publicAccess"); pa {
	case "", "None":
	case "Blob", "Container":
		c.public = pa
	default:
		p.lose("publicAccess", pa+": not a level of public access this reads; the bucket is private", false)
	}
	if md := obj(p.m["metadata"]); len(md) > 0 {
		p.lose("metadata", fmt.Sprintf("%d metadata pair(s) on the container: a bucket has no metadata (its tags or labels come from the account's)", len(md)), false)
	}
	p.quiet("metadata")
	if iw := obj2props(p, "immutableStorageWithVersioning", "properties.immutableStorageWithVersioning."); iw != nil {
		c.versionWORM = iw.boolean("enabled")
		iw.quiet("timeStamp", "migrationState")
		c.losses = append(c.losses, iw.rest()...)
	}
	for _, k := range []string{"enableNfsV3RootSquash", "enableNfsV3AllSquash"} {
		if p.boolean(k) {
			p.lose(k, "NFS 3.0 access is not translated: the target has no NFS endpoint for a bucket", false)
		}
	}
	if ap := obj(p.m["blobAccessPointConfiguration"]); len(ap) > 0 {
		p.lose("blobAccessPointConfiguration", "a blob access point is not translated", false)
	}
	p.quiet("blobAccessPointConfiguration")
	// A legal hold is set by an action, not a PUT, so a capture keeps it
	// with Azure's own values.
	st, _ := o.Body["status"].(map[string]any)
	if h, _ := st["properties.hasLegalHold"].(bool); h {
		c.legalHold = true
	}
	if h, _ := obj(p.m["legalHold"])["hasLegalHold"].(bool); h {
		c.legalHold = true
	}
	c.losses = append(append(top.rest(), p.rest()...), c.losses...)
	return c
}

func readImmutability(o snapshot.Object) *stPolicy {
	pol := &stPolicy{src: source(o)}
	top := newProps(spec(o), "")
	top.quiet("properties", "name", "etag")
	p := newProps(obj(top.m["properties"]), "properties.")
	if d := p.integer("immutabilityPeriodSinceCreationInDays"); d != nil {
		pol.days = *d
	}
	appends, all := p.boolean("allowProtectedAppendWrites"), p.boolean("allowProtectedAppendWritesAll")
	pol.appends = appends || all
	pol.state = p.str("state")
	if st, _ := o.Body["status"].(map[string]any); pol.state == "" {
		pol.state, _ = st["properties.state"].(string)
	}
	p.quiet("updateHistory")
	for _, l := range append(top.rest(), p.rest()...) {
		l.Field = "immutabilityPolicies/default: " + l.Field
		pol.unread = append(pol.unread, l)
	}
	return pol
}

// bucketWriter writes the model for one target.
type bucketWriter interface {
	// account names what the target loses of the account's settings,
	// once, and the requirements they make.
	account(a *stAccount, o *out) []Loss
	// blob names what it loses of the blob service's.
	blob(a *stAccount, b *stBlob) []Loss
	// badName says why a bucket name is not one the target takes, or "".
	badName(n string) string
	// bucket writes one container's bucket and returns its targets and
	// the container's losses.
	bucket(a *stAccount, c *stContainer, name string, o *out) ([]string, []Loss)
	// refuse says why nothing of the account can be written, or "".
	refuse(a *stAccount) string
}

func writeAccount(a *stAccount, w bucketWriter, o *out) {
	if why := w.refuse(a); why != "" {
		for _, src := range a.sources() {
			o.entries = append(o.entries, Entry{Source: src, State: Refused, Reason: why})
		}
		return
	}
	acct := Entry{Source: a.src, State: Mapped, Reason: "the account is not a bucket: its settings apply to each of its containers' buckets"}
	written := 0
	var blobEntry *Entry
	if a.blob != nil {
		blobEntry = &Entry{Source: a.blob.src, State: Mapped, Reason: "read with its account " + a.src + ": its settings apply to each of the account's buckets",
			Losses: append(append([]Loss(nil), a.blob.losses...), w.blob(a, a.blob)...)}
	}
	sort.Slice(a.containers, func(i, j int) bool { return a.containers[i].src < a.containers[j].src })
	for _, c := range a.containers {
		e := Entry{Source: c.src, State: Mapped, Losses: append([]Loss(nil), c.losses...)}
		var polEntry *Entry
		if c.policy != nil {
			polEntry = &Entry{Source: c.policy.src, State: Mapped, Reason: "read with its container " + c.src}
			e.Losses = append(e.Losses, c.policy.unread...)
		}
		finish := func() {
			o.entries = append(o.entries, e)
			if polEntry != nil {
				if e.State == Refused {
					polEntry.State, polEntry.Reason = Refused, "its container is refused"
				}
				o.entries = append(o.entries, *polEntry)
			}
		}
		if c.name == "$logs" {
			e.Reason = "Azure's own container for Storage Analytics logs, which Azure writes: not a bucket. Logging is not translated (the target's are S3 server access logs and Cloud Audit Logs)"
			finish()
			continue
		}
		name := o.m.name(c.key, a.name+"-"+c.name)
		switch {
		case c.name == "$web" && a.blob != nil && a.blob.website:
			e.State, e.Reason = Refused, "it holds the account's static website, which Azure serves to anyone: a website bucket is public, and public access needs a bucket policy (AWS) or allUsers on the bucket (GCP), which is identity and is not translated (#32)"
		case c.public != "" && a.publicBlob:
			e.State, e.Reason = Refused, fmt.Sprintf("public read access (%s): anyone may read its blobs without signing in. Writing that needs a bucket policy granting everyone read (AWS) or allUsers on the bucket's IAM (GCP), which is identity and is not translated (#32); every bucket written here blocks public access", c.public)
		case w.badName(name) != "":
			e.State, e.Reason = Refused, fmt.Sprintf("its bucket name %q %s: give it one in the map's names, keyed %s (bucket names are global, so it must also be free)", name, w.badName(name), c.key)
		}
		if e.State == Refused {
			finish()
			continue
		}
		if c.public != "" {
			// The account forbids public access, so Azure keeps the
			// container private whatever it says, and so does the bucket.
			e.Reason = "its public access setting (" + c.public + ") has no effect: the account forbids public access"
		}
		targets, losses := w.bucket(a, c, name, o)
		e.Targets = targets
		e.Losses = append(e.Losses, losses...)
		acct.Targets = append(acct.Targets, targets...)
		finish()
		written++
	}
	if written == 0 {
		acct.Reason = "it has no blob container in the snapshot that becomes a bucket, so nothing is written: the account is not a bucket, and its settings apply only to its containers'"
		for _, l := range a.losses {
			if l.Unread {
				acct.Losses = append(acct.Losses, l)
			}
		}
	} else {
		acct.Losses = append(append([]Loss(nil), a.losses...), w.account(a, o)...)
		o.require("Blobs are not copied: each bucket is written empty. Copy each container's blobs into its bucket (AWS DataSync or S3 Batch Operations; the Storage Transfer Service), with their versions, metadata and per-blob tiers and holds, which this translation does not carry")
		o.require("Who may read and write each bucket is IAM. With destinations.identity: workload, a managed identity's Storage Blob Data role on the account or a container is carried to its bucket; a person's, a pipeline's or a custom role's is not: grant those on the target")
	}
	o.entries = append(o.entries, acct)
	if blobEntry != nil {
		if written == 0 {
			blobEntry.Losses = nil
			for _, l := range a.blob.losses {
				if l.Unread {
					blobEntry.Losses = append(blobEntry.Losses, l)
				}
			}
		}
		o.entries = append(o.entries, *blobEntry)
	}
	for _, k := range sortedKeys(a.scopes) {
		s := a.scopes[k]
		e := Entry{Source: s.src, State: Mapped, Reason: "read with the containers that name it as their default; a blob that names it itself is data, which is not copied", Losses: append([]Loss(nil), s.losses...)}
		if s.cmk {
			e.Losses = append(e.Losses, Loss{Field: "properties.source", Widens: true,
				Why: "the scope encrypts with the customer's own key; the buckets written here use the cloud's managed keys until a key is named (not translated yet)"})
		}
		o.entries = append(o.entries, e)
	}
}

// scopeLosses names what a container's default encryption scope makes the
// target lose: infra is whether the target writes it double encrypted.
func scopeLosses(a *stAccount, c *stContainer, infra bool) []Loss {
	if c.scope == "" {
		return nil
	}
	s := a.scopes[strings.ToLower(c.scope)]
	switch {
	case s == nil:
		return []Loss{{Field: "properties.defaultEncryptionScope", Widens: true,
			Why: "its encryption scope " + c.scope + " is not in the snapshot, so whose key it used cannot be told: the bucket uses the cloud's managed keys"}}
	case s.cmk:
		return []Loss{{Field: "properties.defaultEncryptionScope", Widens: true,
			Why: "its encryption scope " + c.scope + " uses the customer's own key; the bucket uses the cloud's managed keys until a key is named (not translated yet)"}}
	case s.infra && !infra:
		return []Loss{{Field: "properties.defaultEncryptionScope", Widens: true,
			Why: "its encryption scope " + c.scope + " encrypts twice (infrastructure encryption); the bucket is encrypted once"}}
	}
	return nil
}

// tlsAtLeast12 reports a minimum TLS version of 1.2 or more.
func tlsAtLeast12(v string) bool { return v == "TLS1_2" || v == "TLS1_3" }

// tlsNumber is a minimum TLS version as a number (TLS1_2: 1.2).
func tlsNumber(v string) string { return strings.ReplaceAll(strings.TrimPrefix(v, "TLS"), "_", ".") }

// geo reports a SKU that replicates to a second region.
func geo(sku string) bool { return strings.Contains(sku, "GRS") || strings.Contains(sku, "GZRS") }

// corsMethods are the methods both targets' CORS rules take.
var corsMethods = map[string]bool{"GET": true, "PUT": true, "HEAD": true, "POST": true, "DELETE": true}

// corsRule splits a rule's methods into those both targets take and the
// rest. OPTIONS is the preflight itself, which every rule answers.
func (r stCORS) split() (keep, lost []string) {
	for _, m := range r.methods {
		switch u := strings.ToUpper(m); {
		case corsMethods[u]:
			keep = append(keep, u)
		case u == "OPTIONS":
		default:
			lost = append(lost, u)
		}
	}
	return keep, lost
}

var ipName = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

func stTagLosses(tags map[string]string, ok func(k, v string) bool, what string) (kept map[string]string, losses []Loss) {
	kept = map[string]string{}
	for _, k := range sortedKeys(tags) {
		if ok(k, tags[k]) {
			kept[k] = tags[k]
		} else {
			losses = append(losses, Loss{Field: "tags." + k, Why: "not a " + what + " the target takes; it is not carried over"})
		}
	}
	return kept, losses
}
