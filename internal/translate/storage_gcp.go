package translate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Storage on GCP: a Cloud Storage bucket per blob container, in the map's
// region. Every bucket takes uniform bucket-level access (IAM only, no
// object ACLs, as Azure has none) and enforces public access prevention.
// A firewall that denies by default becomes the bucket's IP filter: the
// same public ranges, and nothing else.

const (
	gcsBucket        = "storage.googleapis.com/Bucket"
	gcsMinSoftDelete = 7  // days
	gcsMaxSoftDelete = 90 // days
	gcsMaxRetention  = 3155760000
)

var (
	gcsPart  = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$`)
	gcsKey   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	gcsValue = regexp.MustCompile(`^[a-z0-9_-]{0,63}$`)
)

type gcpBuckets struct{ m Map }

// gcsObject is a bucket as a GCP capture writes it: named by its ID alone,
// with no parent.
func gcsObject(name string, spec map[string]any) snapshot.Object {
	s := map[string]any{"name": name}
	for k, v := range spec {
		s[k] = v
	}
	return snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": gcsBucket,
		"metadata": map[string]any{"name": name, "annotations": map[string]any{
			"truthform.org/discovery":  "storage/v1",
			"truthform.org/schema":     "Bucket",
			"truthform.org/collection": "buckets",
			"truthform.org/parent":     "",
		}}, "spec": s}}
}

func (d gcpBuckets) refuse(*stAccount) string {
	if d.m.Region == "" {
		return "the map names no region (region): a bucket has a location"
	}
	return ""
}

func (gcpBuckets) badName(n string) string {
	parts := strings.Split(n, ".")
	ok := len(n) >= 3 && (len(n) <= 63 || (len(parts) > 1 && len(n) <= 222)) && !ipName.MatchString(n)
	for _, p := range parts {
		ok = ok && gcsPart.MatchString(p)
	}
	switch {
	case !ok:
		return "is not a Cloud Storage bucket name (3 to 63 lower-case letters, digits, hyphens and underscores, starting and ending with a letter or digit)"
	case strings.HasPrefix(n, "goog"), strings.Contains(n, "google"), strings.Contains(n, "g00gle"):
		return "begins with goog or holds google, which Cloud Storage refuses"
	}
	return ""
}

func (d gcpBuckets) account(a *stAccount, o *out) []Loss {
	var ls []Loss
	if a.cmk {
		ls = append(ls, Loss{Field: "properties.encryption.keySource", Widens: true,
			Why: "blobs are encrypted with the customer's own key; the buckets use Google's keys until a Cloud KMS key is named (not translated yet)"})
	}
	if a.infra {
		ls = append(ls, Loss{Field: "properties.encryption.requireInfrastructureEncryption",
			Why: "Azure encrypted twice, by the service and its infrastructure; Google encrypts data at rest in more than one layer by itself, and there is no setting for it"})
	}
	switch {
	case tlsAtLeast12(a.tls):
		ls = append(ls, Loss{Field: "properties.minimumTlsVersion", Widens: true,
			Why: "TLS " + tlsNumber(a.tls) + " at least on the source; a bucket has no minimum TLS version of its own: Google's floor applies until an organization policy (gcp.restrictTLSVersion) raises it (not translated)"})
	case a.tls != "" && a.tls != "TLS1_0" && a.tls != "TLS1_1":
		ls = append(ls, Loss{Field: "properties.minimumTlsVersion", Widens: true, Why: a.tls + ": not a TLS version this reads"})
	}
	if !a.httpsOnly {
		ls = append(ls, Loss{Field: "properties.supportsHttpsTrafficOnly", Why: "the account took plain HTTP; Cloud Storage's JSON API takes HTTPS only"})
	}
	switch {
	case geo(a.sku):
		ls = append(ls, Loss{Field: "sku.name", Why: fmt.Sprintf("%s copies the account to a second region; a bucket in %s keeps its objects across that region's zones, and a dual- or multi-region location would be a choice the map does not make", a.sku, d.m.Region)})
	case strings.HasPrefix(a.sku, "Premium"):
		ls = append(ls, Loss{Field: "sku.name", Why: a.sku + ": premium performance (low latency) has no bucket equivalent; the bucket is Standard"})
	}
	switch a.tier {
	case "Premium":
		ls = append(ls, Loss{Field: "properties.accessTier", Why: "Premium: the bucket's class is STANDARD"})
	case "Smart":
		ls = append(ls, Loss{Field: "properties.accessTier", Why: "Smart: Autoclass moves objects down as far as Nearline, where Azure's smart tier went to Cold"})
	case "", "Hot", "Cool", "Cold":
	default:
		ls = append(ls, Loss{Field: "properties.accessTier", Why: a.tier + ": not a tier this reads; the bucket's class is STANDARD"})
	}
	if a.sftp {
		ls = append(ls, Loss{Field: "properties.isSftpEnabled", Why: "SFTP access: a bucket has no SFTP endpoint (not translated)"})
	}
	if a.nfs {
		ls = append(ls, Loss{Field: "properties.isNfsV3Enabled", Why: "NFS 3.0 access: a bucket has no NFS endpoint (Cloud Storage FUSE mounts one, not translated)"})
	}
	if a.worm != nil {
		ls = append(ls, Loss{Field: "properties.immutableStorageWithVersioning", Widens: true,
			Why: "version-level immutability: Cloud Storage's object retention lock is turned on when a bucket is created, by a request parameter the restore does not send, and a default retention would rule out versioning (not translated yet)"})
	}
	nets, over := a.gcsNetworks(o)
	if over != "" {
		ls = append(ls, Loss{Field: "properties.networkAcls", Why: over})
	}
	switch {
	case a.closed && len(nets) == 0:
		ls = append(ls, Loss{Field: "properties.publicNetworkAccess", Why: a.private + "; " + lockNoPath + ", so the bucket's IP filter admits no network"})
		o.require("Buckets from a storage account that answered only on private endpoints (" + a.src + ") admit no network: add the VPC networks that may reach them to each bucket's IP filter (ipFilter.vpcNetworkSources)")
	case a.private != "":
		instead := "on Cloud Storage only the networks written for a private endpoint are admitted"
		if len(nets) == 0 {
			instead = "on Cloud Storage no network is admitted until it is named in each bucket's IP filter (ipFilter.vpcNetworkSources)"
			if a.vnetRules > 0 {
				o.require("Buckets from a storage account that allowed virtual network subnets (" + a.src + ") admit only its public ranges: add the VPC networks that may reach them to each bucket's IP filter (ipFilter.vpcNetworkSources)")
			}
		}
		ls = append(ls, stNetworkLosses(a, instead)...)
	}
	if a.private != "" {
		// The filter covers the bucket's own settings too: "Users and
		// service accounts with administrative roles don't bypass bucket
		// IP filtering rules by default"
		// (https://docs.cloud.google.com/storage/docs/ip-filtering-overview),
		// unless they hold storage.buckets.exemptFromIpFilter, which lets
		// them get, update and delete the bucket and no object
		// (https://docs.cloud.google.com/storage/docs/bypass-ip-filter).
		o.require("Buckets from a storage account that limited its network (" + a.src + ") have an IP filter, which also refuses reading and changing the bucket's own settings from elsewhere: grant whoever restores and captures them storage.buckets.exemptFromIpFilter (a custom role; it reaches the bucket's settings, never its objects), or run them from an admitted network")
		if len(nets) > 0 {
			o.require("Buckets from " + a.src + " admit the VPC network(s) " + strings.Join(sortedKeys(nets), ", ") + " by their own address ranges, as the private endpoints' network: a peered or on-premises network that reached the private endpoints is not admitted until its ranges are added (ipFilter.vpcNetworkSources)")
		}
	}
	_, tl := gcsLabels(a.tags)
	ls = append(ls, tl...)
	if a.keys {
		o.require("Apps that sign in to Azure Storage with account keys, SAS tokens or connection strings must move to the target's identity (IAM roles, workload identity); no key or SAS is carried over")
	}
	o.require("Apps move from the Azure Blob SDK to the Cloud Storage client: each container is a bucket, named <account>-<container> unless the map names it")
	return ls
}

// A bucket's IP filter takes 25 VPC networks and 200 ranges at most
// (https://docs.cloud.google.com/storage/docs/ip-filtering-overview).
const (
	gcsMaxFilterNetworks = 25
	gcsMaxFilterRanges   = 200
)

// gcsNetworks are the VPC networks a private account's buckets admit: those
// that had a private endpoint to it, with their address ranges. over says
// why none is admitted when they are more than a filter takes.
func (a *stAccount) gcsNetworks(o *out) (nets map[string][]string, over string) {
	p := o.privatePathOf(azStorage, a.group, a.name)
	if a.private == "" || p == nil || len(p.networks) == 0 {
		return nil, ""
	}
	n := 0
	if !a.closed {
		n = len(a.ranges)
	}
	for _, rs := range p.networks {
		n += len(rs)
	}
	if len(p.networks) > gcsMaxFilterNetworks || n > gcsMaxFilterRanges {
		return nil, fmt.Sprintf("%d network(s) and %d range(s) reached it; a bucket's IP filter takes %d networks and %d ranges at most, so no VPC network is admitted", len(p.networks), n, gcsMaxFilterNetworks, gcsMaxFilterRanges)
	}
	return p.networks, ""
}

// gcsLabels are the account's tags a bucket takes as labels, and the
// losses of the rest.
func gcsLabels(tags map[string]string) (map[string]string, []Loss) {
	return stTagLosses(tags, func(k, v string) bool { return gcsKey.MatchString(k) && gcsValue.MatchString(v) }, "label (lower-case letters, digits, _ and -)")
}

func (gcpBuckets) blob(a *stAccount, b *stBlob) []Loss {
	var ls []Loss
	if r := b.softDelete; r != nil {
		switch {
		case r.days < gcsMinSoftDelete:
			ls = append(ls, Loss{Field: "properties.deleteRetentionPolicy.days", Why: fmt.Sprintf("%d day(s) on the source; Cloud Storage keeps soft-deleted objects %d days at least", r.days, gcsMinSoftDelete)})
		case r.days > gcsMaxSoftDelete:
			ls = append(ls, Loss{Field: "properties.deleteRetentionPolicy.days", Widens: true, Why: fmt.Sprintf("%d days on the source; Cloud Storage keeps soft-deleted objects %d days at most", r.days, gcsMaxSoftDelete)})
		}
		if r.permanent {
			ls = append(ls, Loss{Field: "properties.deleteRetentionPolicy.allowPermanentDelete", Why: "a soft-deleted blob could be deleted for good early; a soft-deleted object cannot"})
		}
	}
	if b.softBucket != nil {
		ls = append(ls, Loss{Field: "properties.containerDeleteRetentionPolicy", Why: "a deleted container could be restored; Cloud Storage deletes only an empty bucket, so its objects are deleted first, and kept as the soft delete policy says"})
	}
	ls = append(ls, stBlobLosses(b, "Pub/Sub notifications for the bucket or Cloud Audit Logs", "Autoclass")...)
	if b.website {
		ls = append(ls, Loss{Field: "properties.staticWebsite", Why: "the static website is not translated: its content is public, and public access is not written (its $web container is refused)"})
	}
	for i, r := range b.cors {
		if keep, lost := r.split(); len(lost) > 0 {
			why := fmt.Sprintf("methods %s are not allowed: the rule keeps GET, PUT, HEAD, POST and DELETE", strings.Join(lost, ", "))
			if len(keep) == 0 {
				why = fmt.Sprintf("methods %s only: the rule is not written", strings.Join(lost, ", "))
			}
			ls = append(ls, Loss{Field: fmt.Sprintf("properties.cors.corsRules[%d].allowedMethods", i), Why: why})
		}
		if len(r.allowed) > 0 && strings.Join(r.allowed, ",") != strings.Join(r.exposed, ",") {
			ls = append(ls, Loss{Field: fmt.Sprintf("properties.cors.corsRules[%d].allowedHeaders", i),
				Why: "a Cloud Storage CORS rule names one list of headers for both what a request may send and what a response shows; the exposed headers are written, and a request header not among them is refused"})
		}
	}
	return ls
}

func (d gcpBuckets) bucket(a *stAccount, c *stContainer, name string, o *out) ([]string, []Loss) {
	var ls []Loss
	// Google encrypts data at rest in more than one layer by itself: a
	// scope that encrypted twice loses no layer.
	ls = append(ls, scopeLosses(a, c, true)...)
	if s := a.scopes[strings.ToLower(c.scope)]; c.scope != "" && s != nil && s.infra && !s.cmk {
		ls = append(ls, Loss{Field: "properties.defaultEncryptionScope", Why: "its scope encrypted twice, by the service and its infrastructure; Google encrypts data at rest in more than one layer by itself, and there is no setting for it"})
	}
	b := a.blob
	if b == nil {
		b = &stBlob{}
	}
	class := map[string]string{"": "STANDARD", "Hot": "STANDARD", "Cool": "NEARLINE", "Cold": "COLDLINE"}[a.tier]
	if class == "" {
		class = "STANDARD"
	}
	spec := map[string]any{
		"location":     strings.ToUpper(d.m.Region),
		"storageClass": class,
		"iamConfiguration": map[string]any{
			"uniformBucketLevelAccess": map[string]any{"enabled": true},
			"bucketPolicyOnly":         map[string]any{"enabled": true},
			"publicAccessPrevention":   "enforced",
		},
	}
	if a.tier == "Smart" {
		spec["autoclass"] = map[string]any{"enabled": true, "terminalStorageClass": "NEARLINE"}
	}
	soft := "0"
	if r := b.softDelete; r != nil {
		soft = strconv.Itoa(int(clamp(float64(r.days), gcsMinSoftDelete, gcsMaxSoftDelete)) * 86400)
	}
	spec["softDeletePolicy"] = map[string]any{"retentionDurationSeconds": soft}
	versioned := b.versioning
	retained := false
	if p := c.policy; p != nil && p.days > 0 {
		sec := int64(p.days) * 86400
		if sec > gcsMaxRetention {
			ls = append(ls, Loss{Field: "immutabilityPolicies/default: properties.immutabilityPeriodSinceCreationInDays", Widens: true, Why: fmt.Sprintf("%d days on the source; a bucket's retention period is 100 years at most", p.days)})
			sec = gcsMaxRetention
		}
		spec["retentionPolicy"] = map[string]any{"retentionPeriod": strconv.FormatInt(sec, 10)}
		retained = true
		switch p.state {
		case "Unlocked":
		case "Locked":
			ls = append(ls, Loss{Field: "immutabilityPolicies/default: properties.state", Widens: true,
				Why: "the policy is locked: nobody can shorten or remove it. The bucket's is written unlocked, and is locked only by buckets.lockRetentionPolicy, once the data is in (it cannot be undone)"})
			o.require("Buckets whose container had a locked retention policy are written unlocked: lock each one (buckets.lockRetentionPolicy) once its data is copied")
		default:
			ls = append(ls, Loss{Field: "immutabilityPolicies/default: properties.state", Widens: true,
				Why: "the snapshot does not say whether the retention policy is locked; it is written unlocked: if it was locked, it was stricter"})
		}
		if p.appends {
			ls = append(ls, Loss{Field: "immutabilityPolicies/default: properties.allowProtectedAppendWrites", Why: "appends to protected append blobs: Cloud Storage has no append, so a retained object cannot be appended to"})
		}
		if versioned {
			versioned = false
			ls = append(ls, Loss{Field: "blobServices/default: properties.isVersioningEnabled", Widens: true,
				Why: "a bucket with a retention policy cannot be versioned: an object is kept for the retention period, and once it ends an overwritten or deleted object's earlier versions are not kept"})
		}
	}
	if c.versionWORM && a.worm == nil {
		ls = append(ls, Loss{Field: "properties.immutableStorageWithVersioning", Widens: true,
			Why: "version-level immutability: Cloud Storage's object retention lock is turned on when a bucket is created, by a request parameter the restore does not send (not translated yet)"})
	}
	if versioned {
		spec["versioning"] = map[string]any{"enabled": true}
	}
	if a.hns {
		if versioned || retained {
			ls = append(ls, Loss{Field: "properties.isHnsEnabled", Why: "a hierarchical namespace (Data Lake Storage) cannot go with versioning or a retention policy on Cloud Storage; the bucket's namespace is flat, and POSIX ACLs on paths are identity and are not translated (#32)"})
		} else {
			spec["hierarchicalNamespace"] = map[string]any{"enabled": true}
			ls = append(ls, Loss{Field: "properties.isHnsEnabled", Why: "the bucket has a hierarchical namespace too; POSIX ACLs on paths are identity and are not translated (#32)"})
		}
	}
	if a.private != "" {
		f := map[string]any{"mode": "Enabled", "allowAllServiceAgentAccess": false, "allowCrossOrgVpcs": false}
		if !a.closed && len(a.ranges) > 0 {
			f["publicNetworkSource"] = map[string]any{"allowedIpCidrRanges": anyStrings(a.ranges)}
		}
		// The networks that had a private endpoint to the account, each
		// with the ranges a request may come from inside it: the
		// network's own.
		nets, _ := a.gcsNetworks(o)
		var srcs []any
		for _, n := range sortedKeys(nets) {
			srcs = append(srcs, map[string]any{"network": gcpProject + "/global/networks/" + n, "allowedIpCidrRanges": anyStrings(nets[n])})
		}
		if len(srcs) > 0 {
			f["vpcNetworkSources"] = srcs
		}
		spec["ipFilter"] = f
	}
	if c.legalHold {
		ls = append(ls, Loss{Field: "properties.hasLegalHold", Widens: true,
			Why: "a legal hold keeps every blob from being changed or deleted; Cloud Storage holds an object only once it is put under a temporary hold, so put each copied object under one"})
		o.require("Containers under a legal hold become buckets without one: put each copied object under an Object Lock legal hold (S3) or a temporary hold (Cloud Storage) before anything else can delete it")
	}
	var rules []any
	for _, r := range b.cors {
		keep, _ := r.split()
		if len(keep) == 0 {
			continue
		}
		rule := map[string]any{"origin": anyStrings(r.origins), "method": anyStrings(keep)}
		if len(r.exposed) > 0 {
			rule["responseHeader"] = anyStrings(r.exposed)
		}
		if r.maxAge > 0 {
			rule["maxAgeSeconds"] = r.maxAge
		}
		rules = append(rules, rule)
	}
	if len(rules) > 0 {
		spec["cors"] = rules
	}
	labels, _ := gcsLabels(a.tags)
	if len(labels) > 0 {
		lm := map[string]any{}
		for k, v := range labels {
			lm[k] = v
		}
		spec["labels"] = lm
	}
	return []string{o.add("gcp", c.src, gcsObject(name, spec))}, ls
}
