package translate

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

const (
	stAcct  = "Microsoft.Storage/storageAccounts"
	stBlobT = stAcct + "/blobServices"
	stCont  = stBlobT + "/containers"
)

func cont(acct, name string, p map[string]any) snapshot.Object {
	return az(stCont, "shop", acct+"/default/"+name, pr(p))
}

// stFixture is made-up storage: an account behind a firewall with the
// containers people make (private, public, retained, the static website,
// one whose name is too long for a bucket, one under a customer key's
// scope), a private account with a customer key, a Data Lake account, an
// empty one, and the services and children that are not buckets.
func stFixture() snapshot.Snapshot {
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az(stAcct, "shop", "shopassets", map[string]any{"location": "westeurope", "kind": "StorageV2",
			"sku": map[string]any{"name": "Standard_RAGRS", "tier": "Standard"}, "tags": map[string]any{"env": "prod", "Owner": "Shop Team"},
			"properties": map[string]any{
				"accessTier": "Hot", "minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": true, "allowBlobPublicAccess": true,
				"allowSharedKeyAccess": true, "publicNetworkAccess": "Enabled",
				"networkAcls": map[string]any{"defaultAction": "Deny", "bypass": "AzureServices",
					"ipRules":             []any{map[string]any{"value": "203.0.113.0/24", "action": "Allow"}, map[string]any{"value": "198.51.100.7", "action": "Allow"}},
					"virtualNetworkRules": []any{map[string]any{"id": "{{truthform|ref|Microsoft.Network/virtualNetworks/subnets|net|core/app|id}}", "action": "Allow"}}},
				"encryption": map[string]any{"keySource": "Microsoft.Storage", "requireInfrastructureEncryption": true,
					"services": map[string]any{"blob": map[string]any{"enabled": true, "keyType": "Account"}}},
				"dnsEndpointType": "Standard", "isHnsEnabled": false, "isSftpEnabled": false, "largeFileSharesState": "Disabled",
			}}),
		az(stBlobT, "shop", "shopassets/default", pr(map[string]any{
			"isVersioningEnabled":            false,
			"deleteRetentionPolicy":          map[string]any{"enabled": true, "days": 14, "allowPermanentDelete": false},
			"containerDeleteRetentionPolicy": map[string]any{"enabled": true, "days": 7},
			"changeFeed":                     map[string]any{"enabled": true, "retentionInDays": 30},
			"staticWebsite":                  map[string]any{"enabled": true, "indexDocument": "index.html"},
			"cors": map[string]any{"corsRules": []any{map[string]any{
				"allowedOrigins": []any{"https://shop.example"}, "allowedMethods": []any{"GET", "PUT", "OPTIONS", "MERGE"},
				"allowedHeaders": []any{"*"}, "exposedHeaders": []any{"*"}, "maxAgeInSeconds": 600}}},
		})),
		cont("shopassets", "images", map[string]any{"publicAccess": "None", "defaultEncryptionScope": "$account-encryption-key"}),
		cont("shopassets", "catalog", map[string]any{"publicAccess": "Blob"}),
		cont("shopassets", "$web", map[string]any{"publicAccess": "None"}),
		cont("shopassets", "monthly-reconciliation-exports-for-the-finance-team-archive", map[string]any{"publicAccess": "None"}),
		cont("shopassets", "ledger", map[string]any{"publicAccess": "None", "defaultEncryptionScope": "tenantkey", "metadata": map[string]any{"team": "finance"}}),
		func() snapshot.Object {
			o := cont("shopassets", "records", map[string]any{"publicAccess": "None"})
			o.Body["status"] = map[string]any{"properties.hasLegalHold": true}
			return o
		}(),
		func() snapshot.Object {
			o := az(stCont+"/immutabilityPolicies", "shop", "shopassets/default/records/default", pr(map[string]any{
				"immutabilityPeriodSinceCreationInDays": 365, "allowProtectedAppendWrites": false}))
			o.Body["status"] = map[string]any{"properties.state": "Locked"}
			return o
		}(),
		az(stAcct+"/encryptionScopes", "shop", "shopassets/tenantkey", pr(map[string]any{"source": "Microsoft.KeyVault", "state": "Enabled",
			"keyVaultProperties": map[string]any{"keyUri": "https://shop-kv.vault.azure.net/keys/tenant"}})),
		az(stAcct+"/managementPolicies", "shop", "shopassets/default", pr(map[string]any{"policy": map[string]any{"rules": []any{}}})),
		az(stAcct+"/fileServices", "shop", "shopassets/default", pr(map[string]any{})),
		az(stAcct+"/queueServices", "shop", "shopassets/default", pr(map[string]any{})),
		az(stAcct+"/queueServices/queues", "shop", "shopassets/default/jobs", pr(map[string]any{})),
		az(stAcct+"/localUsers", "shop", "shopassets/uploader", pr(map[string]any{"hasSshKey": true})),

		// Private, with the customer's key: nothing reaches it but its
		// private endpoints.
		az(stAcct, "shop", "shopvault", map[string]any{"location": "westeurope", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_ZRS"},
			"identity": map[string]any{"type": "SystemAssigned"},
			"properties": map[string]any{
				"accessTier": "Cool", "minimumTlsVersion": "TLS1_0", "publicNetworkAccess": "Disabled", "allowSharedKeyAccess": false,
				"networkAcls": map[string]any{"defaultAction": "Deny", "bypass": "None"},
				"encryption":  map[string]any{"keySource": "Microsoft.Keyvault", "keyvaultproperties": map[string]any{"keyname": "vault", "keyvaulturi": "https://shop-kv.vault.azure.net"}},
				"immutableStorageWithVersioning": map[string]any{"enabled": true,
					"immutabilityPolicy": map[string]any{"immutabilityPeriodSinceCreationInDays": 30, "state": "Unlocked", "allowProtectedAppendWrites": false}},
			}}),
		az(stBlobT, "shop", "shopvault/default", pr(map[string]any{
			"isVersioningEnabled":   true,
			"deleteRetentionPolicy": map[string]any{"enabled": true, "days": 120, "allowPermanentDelete": true},
		})),
		cont("shopvault", "backups", map[string]any{"publicAccess": "Container", "immutableStorageWithVersioning": map[string]any{"enabled": true}}),

		// Data Lake, with SFTP and the smart tier.
		az(stAcct, "shop", "shoplake", map[string]any{"location": "westeurope", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"},
			"properties": map[string]any{"accessTier": "Smart", "isHnsEnabled": true, "isSftpEnabled": true, "isLocalUserEnabled": true,
				"minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": false, "allowSharedKeyAccess": false}}),
		cont("shoplake", "raw", map[string]any{"publicAccess": "None"}),

		az(stAcct, "shop", "shopempty", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Standard_LRS"},
			"properties": map[string]any{"allowBlobPublicAccess": false, "publicNetworkAccess": "Disabled"}}),
	}}
}

func stMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1"}
	a.Destinations.Storage = "buckets"
	g := Map{To: "gcp", Region: "europe-west1"}
	g.Destinations.Storage = "buckets"
	return map[string]Map{"aws": a, "gcp": g}
}

func runSt(t *testing.T, m Map) Result {
	t.Helper()
	r, err := Translate(stFixture(), m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func src(kind, name string) string { return kind + " shop/" + name }

func wantLoss(t *testing.T, e Entry, about string, widens bool) {
	t.Helper()
	l := lossAbout(e, about)
	switch {
	case l == nil:
		t.Errorf("%s: no loss about %q in %+v", e.Source, about, e.Losses)
	case l.Widens != widens:
		t.Errorf("%s: %s widens %v, want %v: %s", e.Source, l.Field, l.Widens, widens, l.Why)
	}
}

func refused(t *testing.T, r Result, source, about string) {
	t.Helper()
	if e := entry(t, r, source); e.State != Refused || !strings.Contains(e.Reason, about) {
		t.Errorf("%s: %s %q, want refused about %q", source, e.State, e.Reason, about)
	}
}

// Each source is reported once, and the whole translation is pinned.
func TestStorageGolden(t *testing.T) {
	for name, m := range stMaps() {
		r := runSt(t, m)
		golden(t, "storage-"+name, r)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
		}
		for _, o := range stFixture().Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
	}
}

// What both targets refuse: public containers, the static website, a
// name that is not a bucket's, local users. What is not a bucket is named.
func TestStorageRefusals(t *testing.T) {
	for name, m := range stMaps() {
		r := runSt(t, m)
		refused(t, r, src(stCont, "shopassets/default/catalog"), "#32")
		refused(t, r, src(stCont, "shopassets/default/catalog"), "public read access (Blob)")
		refused(t, r, src(stCont, "shopassets/default/$web"), "static website")
		refused(t, r, src(stCont, "shopassets/default/monthly-reconciliation-exports-for-the-finance-team-archive"), "map's names, keyed shop/shopassets/monthly")
		refused(t, r, src(stAcct+"/localUsers", "shopassets/uploader"), "identity")
		for _, s := range []string{src(stAcct+"/managementPolicies", "shopassets/default"), src(stAcct+"/queueServices", "shopassets/default"), src(stAcct+"/queueServices/queues", "shopassets/default/jobs")} {
			if e := entry(t, r, s); e.State != NotLooked {
				t.Errorf("%s: %s: %s", name, s, e.State)
			}
		}
		if e := entry(t, r, src(stAcct+"/queueServices/queues", "shopassets/default/jobs")); !strings.Contains(e.Reason, "SQS and Pub/Sub") {
			t.Errorf("%s: the queue's hint: %q", name, e.Reason)
		}
		if e := entry(t, r, src(stAcct+"/fileServices", "shopassets/default")); e.State != Mapped {
			t.Errorf("%s: an empty file service: %s", name, e.State)
		}
		// Public access on a container whose account forbids it is private.
		if e := entry(t, r, src(stCont, "shopvault/default/backups")); e.State == Refused {
			t.Errorf("%s: backups is refused: %s", name, e.Reason)
		}
		// An empty account writes nothing, and loses nothing.
		if e := entry(t, r, src(stAcct, "shopempty")); e.State != Mapped || len(e.Losses) != 0 || !strings.Contains(e.Reason, "nothing is written") {
			t.Errorf("%s: shopempty: %+v", name, e)
		}
		if e := entry(t, r, src(stAcct, "shopassets")); e.State != WithLosses || !strings.Contains(e.Reason, "not a bucket") {
			t.Errorf("%s: shopassets: %s %q", name, e.State, e.Reason)
		}
		if !anyRequirement(r, "Blobs are not copied") || !anyRequirement(r, "account keys") {
			t.Errorf("%s: requirements: %v", name, r.Report.Requirements)
		}
		for _, o := range r.Snapshots[m.To].Objects {
			if strings.Contains(o.Name(), "catalog") || strings.Contains(o.Name(), "web") || strings.Contains(o.Name(), "monthly") {
				t.Errorf("%s: a refused container is written: %s", name, o.Key())
			}
		}
	}
	// A name from the map is taken, and checked.
	m := stMaps()["aws"]
	m.Names = map[string]string{"shop/shopassets/monthly-reconciliation-exports-for-the-finance-team-archive": "shop-recon", "shop/shopassets/images": "Bad_Name"}
	r, err := Translate(stFixture(), m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	if e := entry(t, r, src(stCont, "shopassets/default/monthly")); e.State == Refused || fmt.Sprint(e.Targets) != "[AWS::S3::Bucket shop-recon AWS::S3::BucketPolicy shop-recon]" {
		t.Errorf("named: %s %v %s", e.State, e.Targets, e.Reason)
	}
	refused(t, r, src(stCont, "shopassets/default/images"), "not an S3 bucket name")
	// No region on GCP, no destination: refused, never filled in.
	g := stMaps()["gcp"]
	g.Region = ""
	r, err = Translate(stFixture(), g, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	refused(t, r, src(stCont, "shopassets/default/images"), "(region)")
	refused(t, r, src(stAcct, "shopassets"), "(region)")
	r, err = Translate(stFixture(), Map{To: "gcp", Region: "europe-west1"}, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	refused(t, r, src(stAcct, "shopassets"), "destinations.storage")
	refused(t, r, src(stCont, "shopassets/default/images"), "destinations.storage")
	if len(r.Snapshots) != 0 {
		t.Errorf("no destination writes %v", r.Snapshots)
	}
}

func TestStorageOnAWS(t *testing.T) {
	r := runSt(t, stMaps()["aws"])
	b := object(t, r, "aws", awsBucket, "shopassets-images")
	if fmt.Sprint(b["PublicAccessBlockConfiguration"]) != "map[BlockPublicAcls:true BlockPublicPolicy:true IgnorePublicAcls:true RestrictPublicBuckets:true]" {
		t.Errorf("public access block: %v", b["PublicAccessBlockConfiguration"])
	}
	if !strings.Contains(canonJSON(b["OwnershipControls"]), "BucketOwnerEnforced") {
		t.Errorf("ownership: %v", b["OwnershipControls"])
	}
	// Encrypted twice where Azure encrypted twice.
	if !strings.Contains(canonJSON(b["BucketEncryption"]), `"aws:kms:dsse"`) {
		t.Errorf("encryption: %v", b["BucketEncryption"])
	}
	if !strings.Contains(canonJSON(object(t, r, "aws", awsBucket, "shoplake-raw")["BucketEncryption"]), `"AES256"`) {
		t.Error("an account encrypted once is not SSE-S3")
	}
	// Soft delete: versioned, noncurrent versions kept as long.
	if fmt.Sprint(b["VersioningConfiguration"]) != "map[Status:Enabled]" || !strings.Contains(canonJSON(b["LifecycleConfiguration"]), `"NoncurrentDays":14`) {
		t.Errorf("soft delete: %v %v", b["VersioningConfiguration"], b["LifecycleConfiguration"])
	}
	if got := canonJSON(b["CorsConfiguration"]); !strings.Contains(got, `"AllowedMethods":["GET","PUT"]`) || !strings.Contains(got, `"MaxAge":600`) {
		t.Errorf("cors: %s", got)
	}
	if got := canonJSON(b["Tags"]); !strings.Contains(got, `"env"`) || !strings.Contains(got, `"Owner"`) {
		t.Errorf("tags: %s", got)
	}
	// HTTPS only and TLS 1.2: a policy that only denies.
	pol := canonJSON(object(t, r, "aws", awsBucketPolicy, "shopassets-images"))
	for _, want := range []string{`"aws:SecureTransport":"false"`, `"s3:TlsVersion":"1.2"`, `"Effect":"Deny"`} {
		if !strings.Contains(pol, want) {
			t.Errorf("policy lacks %s: %s", want, pol)
		}
	}
	if strings.Contains(pol, `"Allow"`) {
		t.Errorf("the policy grants: %s", pol)
	}
	// shoplake took plain HTTP: no deny of it; TLS 1.2 still.
	if pol := canonJSON(object(t, r, "aws", awsBucketPolicy, "shoplake-raw")); strings.Contains(pol, "SecureTransport") || !strings.Contains(pol, "TlsVersion") {
		t.Errorf("shoplake policy: %s", pol)
	}
	// shopvault takes TLS 1.0, and S3 takes 1.2: no TLS deny, a narrower
	// loss. It takes HTTPS only, Azure's default.
	if pol := canonJSON(object(t, r, "aws", awsBucketPolicy, "shopvault-backups")); !strings.Contains(pol, "SecureTransport") || strings.Contains(pol, "TlsVersion") {
		t.Errorf("shopvault policy: %s", pol)
	}
	// A locked retention policy is compliance mode; an unlocked default
	// on the account, governance.
	if got := canonJSON(object(t, r, "aws", awsBucket, "shopassets-records")["ObjectLockConfiguration"]); !strings.Contains(got, `"Mode":"COMPLIANCE"`) || !strings.Contains(got, `"Days":365`) {
		t.Errorf("records lock: %s", got)
	}
	bk := object(t, r, "aws", awsBucket, "shopvault-backups")
	if got := canonJSON(bk["ObjectLockConfiguration"]); !strings.Contains(got, `"Mode":"GOVERNANCE"`) || !strings.Contains(got, `"Days":30`) || bk["ObjectLockEnabled"] != true {
		t.Errorf("backups lock: %s", got)
	}
	if bk["LifecycleConfiguration"] != nil {
		t.Errorf("versioned with soft delete: versions are kept, not expired: %v", bk["LifecycleConfiguration"])
	}

	acct := entry(t, r, src(stAcct, "shopassets"))
	// Its firewall's ranges are the buckets' policy; what still passes it
	// passed Azure's too (bypass AzureServices).
	wantLoss(t, acct, "only from 203.0.113.0/24, 198.51.100.7/32", false)
	wantLoss(t, acct, "Standard_RAGRS", false)
	wantLoss(t, acct, "virtualNetworkRules", false)
	wantLoss(t, acct, "bypass", false)
	vault := entry(t, r, src(stAcct, "shopvault"))
	wantLoss(t, vault, "answers only on private endpoints", true)
	wantLoss(t, vault, "customer's own key", true)
	wantLoss(t, vault, "S3 takes TLS 1.2", false)
	wantLoss(t, vault, "Cool", false)
	wantLoss(t, vault, "managed identity", false)
	lake := entry(t, r, src(stAcct, "shoplake"))
	wantLoss(t, lake, "isHnsEnabled", false)
	wantLoss(t, lake, "isSftpEnabled", false)
	wantLoss(t, lake, "Intelligent-Tiering", false)
	wantLoss(t, lake, "isLocalUserEnabled", false)
	blob := entry(t, r, src(stBlobT, "shopassets/default"))
	wantLoss(t, blob, "s3:DeleteObjectVersion", true)
	wantLoss(t, blob, "containerDeleteRetentionPolicy", false)
	wantLoss(t, blob, "changeFeed", false)
	wantLoss(t, blob, "MERGE", false)
	wantLoss(t, blob, "staticWebsite", false)
	// Soft-deleted blobs the source let be deleted early: no widening.
	if l := lossAbout(entry(t, r, src(stBlobT, "shopvault/default")), "deleteRetentionPolicy"); l == nil || l.Widens {
		t.Errorf("shopvault soft delete: %+v", l)
	}
	wantLoss(t, entry(t, r, src(stCont, "shopassets/default/records")), "legal hold", true)
	wantLoss(t, entry(t, r, src(stCont, "shopassets/default/ledger")), "tenantkey uses the customer's own key", true)
	wantLoss(t, entry(t, r, src(stCont, "shopassets/default/ledger")), "metadata", false)
	wantLoss(t, entry(t, r, src(stAcct+"/encryptionScopes", "shopassets/tenantkey")), "customer's own key", true)
	if e := entry(t, r, src(stCont+"/immutabilityPolicies", "shopassets/default/records/default")); e.State != Mapped {
		t.Errorf("immutability policy: %s", e.State)
	}
	if !anyRequirement(r, "VPC endpoint for S3") || !anyRequirement(r, "legal hold") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
}

func TestStorageOnGCP(t *testing.T) {
	r := runSt(t, stMaps()["gcp"])
	b := object(t, r, "gcp", gcsBucket, "shopassets-images")
	if b["location"] != "EUROPE-WEST1" || b["storageClass"] != "STANDARD" {
		t.Errorf("location, class: %v %v", b["location"], b["storageClass"])
	}
	if got := canonJSON(b["iamConfiguration"]); !strings.Contains(got, `"publicAccessPrevention":"enforced"`) || !strings.Contains(got, `"uniformBucketLevelAccess":{"enabled":true}`) {
		t.Errorf("iam configuration: %s", got)
	}
	if got := canonJSON(b["softDeletePolicy"]); got != `{"retentionDurationSeconds":"1209600"}` {
		t.Errorf("soft delete: %s", got)
	}
	// The firewall's public ranges, and nothing else.
	if got := canonJSON(b["ipFilter"]); got != `{"allowAllServiceAgentAccess":false,"allowCrossOrgVpcs":false,"mode":"Enabled","publicNetworkSource":{"allowedIpCidrRanges":["203.0.113.0/24","198.51.100.7/32"]}}` {
		t.Errorf("ip filter: %s", got)
	}
	if b["versioning"] != nil {
		t.Errorf("versioning: %v", b["versioning"])
	}
	if got := canonJSON(b["cors"]); got != `[{"maxAgeSeconds":600,"method":["GET","PUT"],"origin":["https://shop.example"],"responseHeader":["*"]}]` {
		t.Errorf("cors: %s", got)
	}
	if got := canonJSON(b["labels"]); got != `{"env":"prod"}` {
		t.Errorf("labels: %s", got)
	}
	if got := canonJSON(object(t, r, "gcp", gcsBucket, "shopassets-records")["retentionPolicy"]); got != `{"retentionPeriod":"31536000"}` {
		t.Errorf("retention: %s", got)
	}
	// Private: an IP filter that admits no network.
	v := object(t, r, "gcp", gcsBucket, "shopvault-backups")
	if got := canonJSON(v["ipFilter"]); got != `{"allowAllServiceAgentAccess":false,"allowCrossOrgVpcs":false,"mode":"Enabled"}` {
		t.Errorf("private ip filter: %s", got)
	}
	if v["storageClass"] != "NEARLINE" || canonJSON(v["versioning"]) != `{"enabled":true}` || canonJSON(v["softDeletePolicy"]) != `{"retentionDurationSeconds":"7776000"}` {
		t.Errorf("shopvault: %v %v %v", v["storageClass"], v["versioning"], v["softDeletePolicy"])
	}
	lake := object(t, r, "gcp", gcsBucket, "shoplake-raw")
	if canonJSON(lake["hierarchicalNamespace"]) != `{"enabled":true}` || canonJSON(lake["autoclass"]) != `{"enabled":true,"terminalStorageClass":"NEARLINE"}` {
		t.Errorf("lake: %v %v", lake["hierarchicalNamespace"], lake["autoclass"])
	}
	if lake["ipFilter"] != nil || canonJSON(lake["softDeletePolicy"]) != `{"retentionDurationSeconds":"0"}` {
		t.Errorf("lake: %v %v", lake["ipFilter"], lake["softDeletePolicy"])
	}

	acct := entry(t, r, src(stAcct, "shopassets"))
	wantLoss(t, acct, "gcp.restrictTLSVersion", true)
	wantLoss(t, acct, "requireInfrastructureEncryption", false)
	wantLoss(t, acct, "virtualNetworkRules", false)
	wantLoss(t, acct, "dual- or multi-region", false)
	wantLoss(t, acct, "tags.Owner", false)
	if l := lossAbout(acct, "aws:SourceIp"); l != nil {
		t.Errorf("the firewall widens on GCP: %+v", l)
	}
	vault := entry(t, r, src(stAcct, "shopvault"))
	wantLoss(t, vault, "customer's own key", true)
	wantLoss(t, vault, "admits no network", false)
	wantLoss(t, vault, "version-level immutability", true)
	wantLoss(t, entry(t, r, src(stAcct, "shoplake")), "HTTPS only", false)
	wantLoss(t, entry(t, r, src(stAcct, "shoplake")), "Autoclass", false)
	wantLoss(t, entry(t, r, src(stBlobT, "shopvault/default")), "90 days at most", true)
	wantLoss(t, entry(t, r, src(stBlobT, "shopvault/default")), "allowPermanentDelete", false)
	if l := lossAbout(entry(t, r, src(stBlobT, "shopassets/default")), "s3:DeleteObjectVersion"); l != nil {
		t.Errorf("an AWS loss on GCP: %+v", l)
	}
	rec := entry(t, r, src(stCont, "shopassets/default/records"))
	wantLoss(t, rec, "lockRetentionPolicy", true)
	wantLoss(t, rec, "temporary hold", true)
	wantLoss(t, entry(t, r, src(stCont, "shopassets/default/ledger")), "tenantkey uses the customer's own key", true)
	if !anyRequirement(r, "vpcNetworkSources") || !anyRequirement(r, "lockRetentionPolicy") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
}

// What can be written exactly is; what cannot errs toward less access.
// The widenings are the ones named, and no other.
func TestStorageWidens(t *testing.T) {
	want := map[string][]string{
		"aws": {
			"shopvault properties.publicNetworkAccess", "shopvault properties.encryption.keySource",
			"shopassets/default properties.deleteRetentionPolicy", "shopassets/default/records properties.hasLegalHold",
			"shopassets/default/ledger properties.defaultEncryptionScope", "shopassets/tenantkey properties.source",
		},
		"gcp": {
			"shopassets properties.minimumTlsVersion", "shoplake properties.minimumTlsVersion", "shopvault properties.encryption.keySource",
			"shopvault properties.immutableStorageWithVersioning", "shopvault/default properties.deleteRetentionPolicy.days",
			"shopassets/default/records properties.hasLegalHold", "shopassets/default/records immutabilityPolicies/default: properties.state",
			"shopassets/default/ledger properties.defaultEncryptionScope", "shopassets/tenantkey properties.source",
		},
	}
	for name, m := range stMaps() {
		got := map[string]bool{}
		for _, e := range runSt(t, m).Report.Entries {
			for _, l := range e.Losses {
				if l.Unread {
					t.Errorf("%s: %s %s is unread", name, e.Source, l.Field)
				}
				if l.Widens {
					got[strings.TrimPrefix(e.Source[strings.Index(e.Source, " ")+1:], "shop/")+" "+l.Field] = true
				}
			}
		}
		for _, w := range want[name] {
			if !got[w] {
				t.Errorf("%s: %s does not widen", name, w)
			}
			delete(got, w)
		}
		for g := range got {
			t.Errorf("%s: %s widens, and is not one of the named", name, g)
		}
	}
}

// A container whose retention policy's lock state the snapshot does not
// give is written the weaker way and named; GCP drops versioning beside a
// retention policy, and a hierarchical namespace beside either.
func TestStorageRetentionEdges(t *testing.T) {
	s := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{
		az(stAcct, "shop", "shoparch", map[string]any{"location": "westeurope", "properties": map[string]any{"isHnsEnabled": true, "supportsHttpsTrafficOnly": true}}),
		az(stBlobT, "shop", "shoparch/default", pr(map[string]any{"isVersioningEnabled": true})),
		cont("shoparch", "keep", map[string]any{}),
		az(stCont+"/immutabilityPolicies", "shop", "shoparch/default/keep/default", pr(map[string]any{"immutabilityPeriodSinceCreationInDays": 10})),
		az(stCont+"/immutabilityPolicies", "shop", "shoparch/default/gone/default", pr(map[string]any{"immutabilityPeriodSinceCreationInDays": 10})),
		cont("shopnone", "orphan", map[string]any{}),
	}}
	for name, m := range stMaps() {
		r, err := Translate(s, m, targets(t))
		if err != nil {
			t.Fatal(err)
		}
		e := entry(t, r, src(stCont, "shoparch/default/keep"))
		wantLoss(t, e, "does not say whether the retention policy is locked", true)
		refused(t, r, src(stCont+"/immutabilityPolicies", "shoparch/default/gone/default"), "container is not in the snapshot")
		refused(t, r, src(stCont, "shopnone/default/orphan"), "storage account is not in the snapshot")
		if name == "gcp" {
			wantLoss(t, e, "cannot be versioned", true)
			wantLoss(t, e, "cannot go with versioning", false)
			b := object(t, r, "gcp", gcsBucket, "shoparch-keep")
			if b["versioning"] != nil || b["hierarchicalNamespace"] != nil {
				t.Errorf("gcp: %v %v", b["versioning"], b["hierarchicalNamespace"])
			}
		} else {
			b := object(t, r, "aws", awsBucket, "shoparch-keep")
			if !strings.Contains(canonJSON(b["ObjectLockConfiguration"]), `"Mode":"GOVERNANCE"`) {
				t.Errorf("aws: %v", b["ObjectLockConfiguration"])
			}
		}
	}
}

func TestStorageRestores(t *testing.T) {
	tg := targets(t)
	s := runSt(t, stMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("aws %s: %s", res.Key, res.Detail)
		}
	}
	if c := f.Count(); c[awsBucket] != 5 || c[awsBucketPolicy] != 5 {
		t.Errorf("aws created %v", c)
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runSt(t, stMaps()["gcp"]).Snapshots["gcp"]
	gf := gcp.NewWorld(tg.GCP).Project("target-project", "123456789")
	n := 0
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK {
			t.Errorf("gcp %s: %s", res.Key, res.Detail)
		}
		n++
	}
	if n != 5 {
		t.Errorf("gcp restored %d buckets", n)
	}
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("gcp again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
}

// Each target's bucket name rules.
func TestBucketNames(t *testing.T) {
	for _, c := range []struct {
		name     string
		aws, gcp bool // valid
	}{
		{"shop-assets", true, true},
		{"ab", false, false},
		{"shop..assets", false, false},
		{"192.168.1.10", false, false},
		{"shop_assets", false, true},
		{"Shop-assets", false, false},
		{"xn--shop", false, true},
		{"shop-assets-s3alias", false, true},
		{"google-shop", true, false},
		{"goog-shop", true, false},
		{"-shop", false, false},
		{strings.Repeat("a", 64), false, false},
	} {
		if got := (awsBuckets{}).badName(c.name) == ""; got != c.aws {
			t.Errorf("aws %q: valid %v, want %v", c.name, got, c.aws)
		}
		if got := (gcpBuckets{}).badName(c.name) == ""; got != c.gcp {
			t.Errorf("gcp %q: valid %v, want %v", c.name, got, c.gcp)
		}
	}
}
