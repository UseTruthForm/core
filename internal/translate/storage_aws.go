package translate

import (
	"fmt"
	"regexp"
	"strings"
)

// Storage on AWS: an S3 bucket per blob container, in the region the
// restore runs in. Every bucket blocks public access and takes no ACLs, as
// an Azure container with public access off; it is encrypted with S3's
// keys (SSE-S3), or twice (DSSE-KMS with AWS's own key) where Azure
// encrypted twice. HTTPS-only and a minimum TLS version are written as a
// bucket policy that only denies: requests over plain HTTP, or an older
// TLS. It grants nobody anything, so no identity is written.

const (
	awsBucket       = "AWS::S3::Bucket"
	awsBucketPolicy = "AWS::S3::BucketPolicy"
)

var s3Name = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

type awsBuckets struct{ m Map }

func (awsBuckets) refuse(*stAccount) string { return "" }

func (awsBuckets) badName(n string) string {
	switch {
	case !s3Name.MatchString(n):
		return "is not an S3 bucket name (3 to 63 lower-case letters, digits, dots and hyphens, starting and ending with a letter or digit)"
	case strings.Contains(n, ".."), ipName.MatchString(n):
		return "is not an S3 bucket name (no two dots in a row, and not an IP address)"
	}
	for _, p := range []string{"xn--", "sthree-", "amzn-s3-demo-"} {
		if strings.HasPrefix(n, p) {
			return "begins with " + p + ", which S3 reserves"
		}
	}
	for _, s := range []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"} {
		if strings.HasSuffix(n, s) {
			return "ends with " + s + ", which S3 reserves"
		}
	}
	return ""
}

func (awsBuckets) account(a *stAccount, o *out) []Loss {
	var ls []Loss
	if a.private != "" {
		field := "properties.networkAcls"
		if a.closed {
			field = "properties.publicNetworkAccess"
		}
		ls = append(ls, Loss{Field: field, Widens: true,
			Why: a.private + "; S3 answers on its public endpoint, guarded by IAM alone, until a bucket policy on aws:SourceIp or aws:SourceVpce (with a VPC endpoint) limits where requests come from (a resource policy: not translated, #32)"})
	}
	if a.cmk {
		ls = append(ls, Loss{Field: "properties.encryption.keySource", Widens: true,
			Why: "blobs are encrypted with the customer's own key; the buckets use S3's keys until a KMS key is named (not translated yet)"})
	}
	switch {
	case a.tls == "TLS1_0" || a.tls == "TLS1_1":
		ls = append(ls, Loss{Field: "properties.minimumTlsVersion", Why: "TLS " + tlsNumber(a.tls) + " at least on the source; S3 takes TLS 1.2 at least, so older clients cannot connect"})
	case a.tls != "" && !tlsAtLeast12(a.tls):
		ls = append(ls, Loss{Field: "properties.minimumTlsVersion", Widens: true, Why: a.tls + ": not a TLS version this reads; no minimum is written"})
	}
	switch {
	case geo(a.sku):
		ls = append(ls, Loss{Field: "sku.name", Why: a.sku + " copies the account to a second region; an S3 bucket keeps its objects in at least three availability zones of one region, and a copy in another region (S3 Replication) is not translated"})
	case strings.HasPrefix(a.sku, "Premium"):
		ls = append(ls, Loss{Field: "sku.name", Why: a.sku + ": premium performance (low latency) has no general purpose bucket equivalent (S3 Express One Zone is another kind of bucket)"})
	}
	switch a.tier {
	case "", "Hot":
	case "Cool", "Cold":
		ls = append(ls, Loss{Field: "properties.accessTier", Why: a.tier + ": S3 has no default storage class per bucket; objects are written STANDARD unless the writer names a class (STANDARD_IA, GLACIER_IR) or a lifecycle rule moves them (not translated)"})
	case "Smart":
		ls = append(ls, Loss{Field: "properties.accessTier", Why: "Smart: S3 Intelligent-Tiering is chosen per object by the writer, or by a lifecycle rule (not translated)"})
	default:
		ls = append(ls, Loss{Field: "properties.accessTier", Why: a.tier + ": S3 has no default storage class per bucket"})
	}
	if a.hns {
		ls = append(ls, Loss{Field: "properties.isHnsEnabled", Why: "a hierarchical namespace (Data Lake Storage): a general purpose bucket's namespace is flat, so renaming a directory renames each object, and POSIX ACLs on paths are identity and are not translated (#32)"})
	}
	if a.sftp {
		ls = append(ls, Loss{Field: "properties.isSftpEnabled", Why: "SFTP access: a bucket has no SFTP endpoint until AWS Transfer Family serves it (not translated)"})
	}
	if a.nfs {
		ls = append(ls, Loss{Field: "properties.isNfsV3Enabled", Why: "NFS 3.0 access: a bucket has no NFS endpoint"})
	}
	if a.worm != nil && a.worm.appends {
		ls = append(ls, Loss{Field: "properties.immutableStorageWithVersioning.immutabilityPolicy.allowProtectedAppendWrites", Why: "appends to protected append blobs: S3 has no append, so a protected object cannot be appended to"})
	}
	ls = append(ls, stNetworkLosses(a, "S3")...)
	_, tl := awsBucketTags(a.tags)
	ls = append(ls, tl...)
	if a.keys {
		o.require("Apps that sign in to Azure Storage with account keys, SAS tokens or connection strings must move to the target's identity (IAM roles, workload identity); no key or SAS is carried over")
	}
	if a.private != "" {
		o.require("Buckets from a storage account that limited its network (" + a.src + ") answer on S3's public endpoint: add a VPC endpoint for S3 and a bucket policy that denies requests not from it, or not from the allowed ranges")
	}
	o.require("Apps move from the Azure Blob SDK to the S3 API: each container is a bucket, named <account>-<container> unless the map names it")
	return ls
}

// stNetworkLosses names what the firewall allowed that no target can say
// as Azure did: narrower, never wider.
func stNetworkLosses(a *stAccount, target string) []Loss {
	var ls []Loss
	if a.vnetRules > 0 {
		ls = append(ls, Loss{Field: "properties.networkAcls.virtualNetworkRules", Why: fmt.Sprintf("%d virtual network subnet(s) were allowed; on %s none is until the networks it may come from are named (not translated)", a.vnetRules, target)})
	}
	if a.resRules > 0 {
		ls = append(ls, Loss{Field: "properties.networkAcls.resourceAccessRules", Why: fmt.Sprintf("%d Azure resource instance(s) were allowed through the firewall; they are not Azure's on the target", a.resRules)})
	}
	if a.bypass != "" {
		ls = append(ls, Loss{Field: "properties.networkAcls.bypass", Why: a.bypass + " passed the firewall; Azure's trusted services are not the target's"})
	}
	return ls
}

func (awsBuckets) blob(a *stAccount, b *stBlob) []Loss {
	var ls []Loss
	if b.softDelete != nil {
		why := "S3 has no soft delete: the bucket is versioned, so a deleted or overwritten object is kept as a noncurrent version"
		if b.versioning {
			why += ", which versioning keeps until it is deleted"
		} else {
			why += fmt.Sprintf(" for %d day(s), as Azure kept it", b.softDelete.days)
		}
		if !b.softDelete.permanent {
			ls = append(ls, Loss{Field: "properties.deleteRetentionPolicy", Widens: true,
				Why: why + "; on Azure nobody could delete it for good before then, and on S3 whoever may s3:DeleteObjectVersion can: deny that in IAM"})
		} else {
			ls = append(ls, Loss{Field: "properties.deleteRetentionPolicy", Why: why})
		}
	}
	if b.softBucket != nil {
		ls = append(ls, Loss{Field: "properties.containerDeleteRetentionPolicy", Why: "a deleted container could be restored; S3 deletes only an empty bucket, so its objects (and their versions) are deleted first, one by one"})
	}
	ls = append(ls, stBlobLosses(b, "S3 Event Notifications or CloudTrail data events", "S3 Inventory or Intelligent-Tiering")...)
	if b.website {
		ls = append(ls, Loss{Field: "properties.staticWebsite", Why: "the static website is not translated: its content is public, and public access is not written (its $web container is refused)"})
	}
	for i, r := range b.cors {
		if keep, lost := r.split(); len(lost) > 0 {
			why := fmt.Sprintf("methods %s: an S3 CORS rule takes GET, PUT, HEAD, POST and DELETE; they are not allowed", strings.Join(lost, ", "))
			if len(keep) == 0 {
				why = fmt.Sprintf("methods %s only: an S3 CORS rule takes none of them, so the rule is not written", strings.Join(lost, ", "))
			}
			ls = append(ls, Loss{Field: fmt.Sprintf("properties.cors.corsRules[%d].allowedMethods", i), Why: why})
		}
	}
	return ls
}

// stBlobLosses are the blob service's losses both targets share.
func stBlobLosses(b *stBlob, feed, access string) []Loss {
	var ls []Loss
	if b.changeFeed {
		ls = append(ls, Loss{Field: "properties.changeFeed", Why: "the change feed (a log of every change) is not translated; the nearest equivalent is " + feed})
	}
	if b.restore != nil {
		ls = append(ls, Loss{Field: "properties.restorePolicy", Why: fmt.Sprintf("point-in-time restore (%d days) has no equivalent: earlier versions are kept, and are restored one object at a time", *b.restore)})
	}
	if b.lastAccess {
		ls = append(ls, Loss{Field: "properties.lastAccessTimeTrackingPolicy", Why: "last access times are not tracked per object; the nearest equivalent is " + access})
	}
	return ls
}

func (d awsBuckets) bucket(a *stAccount, c *stContainer, name string, o *out) ([]string, []Loss) {
	var ls []Loss
	sse := "AES256"
	if a.infra || (c.scope != "" && a.scopes[strings.ToLower(c.scope)] != nil && a.scopes[strings.ToLower(c.scope)].infra) {
		sse = "aws:kms:dsse" // two layers of encryption, with AWS's own key for S3
	}
	ls = append(ls, scopeLosses(a, c, sse == "aws:kms:dsse")...)
	spec := map[string]any{
		"BucketName": name,
		"PublicAccessBlockConfiguration": map[string]any{
			"BlockPublicAcls": true, "BlockPublicPolicy": true, "IgnorePublicAcls": true, "RestrictPublicBuckets": true,
		},
		"OwnershipControls": map[string]any{"Rules": []any{map[string]any{"ObjectOwnership": "BucketOwnerEnforced"}}},
		"BucketEncryption": map[string]any{"ServerSideEncryptionConfiguration": []any{
			map[string]any{"ServerSideEncryptionByDefault": map[string]any{"SSEAlgorithm": sse}},
		}},
	}
	b := a.blob
	if b == nil {
		b = &stBlob{}
	}
	versioned := b.versioning || b.softDelete != nil
	// Object Lock: time-based retention on the container, or a default
	// one for version-level immutability.
	var days *int
	mode, state := "", ""
	if c.policy != nil {
		days, state = &c.policy.days, c.policy.state
		if c.policy.appends {
			ls = append(ls, Loss{Field: "immutabilityPolicies/default: properties.allowProtectedAppendWrites", Why: "appends to protected append blobs: S3 has no append, so a protected object cannot be appended to"})
		}
	} else if a.worm != nil && a.worm.days != nil {
		days, state = a.worm.days, a.worm.state
	}
	lock := c.policy != nil || c.versionWORM || a.worm != nil
	if lock {
		spec["ObjectLockEnabled"] = true
		lc := map[string]any{"ObjectLockEnabled": "Enabled"}
		if days != nil && *days > 0 {
			switch state {
			case "Locked":
				mode = "COMPLIANCE"
			case "Unlocked":
				mode = "GOVERNANCE"
			default:
				mode = "GOVERNANCE"
				ls = append(ls, Loss{Field: "immutabilityPolicies/default: properties.state", Widens: true,
					Why: "the snapshot does not say whether the retention policy is locked; it is written in governance mode, which whoever may s3:BypassGovernanceRetention can shorten: if it was locked, it was stricter"})
			}
			lc["Rule"] = map[string]any{"DefaultRetention": map[string]any{"Mode": mode, "Days": *days}}
		}
		spec["ObjectLockConfiguration"] = lc
		if !versioned {
			ls = append(ls, Loss{Field: "properties.immutableStorageWithVersioning", Why: "S3 Object Lock needs versioning, so the bucket is versioned: an overwritten object is kept as a noncurrent version"})
		}
		versioned = true
	}
	if versioned {
		spec["VersioningConfiguration"] = map[string]any{"Status": "Enabled"}
	}
	if b.softDelete != nil && !b.versioning {
		spec["LifecycleConfiguration"] = map[string]any{"Rules": []any{map[string]any{
			"Id": "soft-delete", "Status": "Enabled",
			"NoncurrentVersionExpiration": map[string]any{"NoncurrentDays": b.softDelete.days},
		}}}
	}
	if c.legalHold {
		ls = append(ls, Loss{Field: "properties.hasLegalHold", Widens: true,
			Why: "a legal hold keeps every blob from being changed or deleted; S3 holds an object only once it is put under an Object Lock legal hold, so put each copied object under one"})
		o.require("Containers under a legal hold become buckets without one: put each copied object under an Object Lock legal hold (S3) or a temporary hold (Cloud Storage) before anything else can delete it")
	}
	var rules []any
	for _, r := range b.cors {
		keep, _ := r.split()
		if len(keep) == 0 {
			continue
		}
		rule := map[string]any{"AllowedOrigins": anyStrings(r.origins), "AllowedMethods": anyStrings(keep)}
		if len(r.allowed) > 0 {
			rule["AllowedHeaders"] = anyStrings(r.allowed)
		}
		if len(r.exposed) > 0 {
			rule["ExposedHeaders"] = anyStrings(r.exposed)
		}
		if r.maxAge > 0 {
			rule["MaxAge"] = r.maxAge
		}
		rules = append(rules, rule)
	}
	if len(rules) > 0 {
		spec["CorsConfiguration"] = map[string]any{"CorsRules": rules}
	}
	tags, _ := awsBucketTags(a.tags)
	if len(tags) > 0 {
		var ts []any
		for _, k := range sortedKeys(tags) {
			ts = append(ts, map[string]any{"Key": k, "Value": tags[k]})
		}
		spec["Tags"] = ts
	}
	targets := []string{o.add("aws", c.src, awsObject(awsBucket, name, spec))}
	var deny []any
	arn := awsRef(awsBucket, name, "Arn")
	res := []any{arn, arn + "/*"}
	if a.httpsOnly {
		deny = append(deny, map[string]any{"Sid": "DenyPlainHTTP", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": res,
			"Condition": map[string]any{"Bool": map[string]any{"aws:SecureTransport": "false"}}})
	}
	if tlsAtLeast12(a.tls) {
		deny = append(deny, map[string]any{"Sid": "DenyOldTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": res,
			"Condition": map[string]any{"NumericLessThan": map[string]any{"s3:TlsVersion": tlsNumber(a.tls)}}})
	}
	if len(deny) > 0 {
		targets = append(targets, o.add("aws", c.src, awsObject(awsBucketPolicy, name, map[string]any{
			"Bucket": name, "PolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": deny},
		})))
	}
	return targets, ls
}

// awsBucketTags are the account's tags a bucket takes, and the losses of
// the rest.
func awsBucketTags(tags map[string]string) (map[string]string, []Loss) {
	return stTagLosses(tags, func(k, v string) bool {
		return !strings.HasPrefix(strings.ToLower(k), "aws:") && len(k) <= 128 && len(v) <= 256
	}, "tag")
}

func anyStrings(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
