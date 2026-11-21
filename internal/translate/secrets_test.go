package translate

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

const neverOnDisk = "s3cr3t-never-written"

// kvFixture is a made-up pair of vaults: one locked down (a firewall,
// purge protection, access policies), one open with RBAC and no soft
// delete; secrets of the shapes people keep, and the children a vault
// can have that do not move.
func kvFixture() snapshot.Snapshot {
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.KeyVault/vaults", "app", "shop", map[string]any{"location": "westeurope", "tags": map[string]any{"env": "dev"},
			"properties": map[string]any{
				"tenantId": "00000000-0000-0000-0000-000000000001", "sku": map[string]any{"family": "A", "name": "premium"},
				"accessPolicies": []any{
					map[string]any{"tenantId": "00000000-0000-0000-0000-000000000001", "objectId": "00000000-0000-0000-0000-0000000000aa", "permissions": map[string]any{"secrets": []any{"get"}}},
					map[string]any{"tenantId": "00000000-0000-0000-0000-000000000001", "objectId": "00000000-0000-0000-0000-0000000000bb", "permissions": map[string]any{"secrets": []any{"get", "list"}}},
				},
				"vaultUri": "https://shop.vault.azure.net/", "enabledForDeployment": false, "enabledForDiskEncryption": false, "enabledForTemplateDeployment": true,
				"enableSoftDelete": true, "softDeleteRetentionInDays": 30, "enablePurgeProtection": true, "enableRbacAuthorization": false,
				"publicNetworkAccess": "Enabled",
				"networkAcls": map[string]any{"bypass": "AzureServices", "defaultAction": "Deny",
					"ipRules": []any{map[string]any{"value": "203.0.113.0/24"}}, "virtualNetworkRules": []any{}},
				"provisioningState": "Succeeded",
			}}),
		az("Microsoft.KeyVault/vaults/secrets", "app", "shop/db-password", map[string]any{
			"tags": map[string]any{"env": "dev", "Owner Team": "data", "Name": "db"},
			"properties": map[string]any{"contentType": "text/plain", "attributes": map[string]any{"enabled": true, "exp": float64(1893456000), "created": float64(1700000000)},
				"secretUri": "https://shop.vault.azure.net/secrets/db-password"}}),
		az("Microsoft.KeyVault/vaults/secrets", "app", "shop/legacy", pr(map[string]any{"value": neverOnDisk, "attributes": map[string]any{"enabled": false}})),
		az("Microsoft.KeyVault/vaults/secrets", "app", "shop/api-abc123", pr(map[string]any{"attributes": map[string]any{"enabled": true}})),
		az("Microsoft.KeyVault/vaults/keys", "app", "shop/signing", pr(map[string]any{"kty": "RSA-HSM", "keySize": 2048})),
		az("Microsoft.KeyVault/vaults/keys/versions", "app", "shop/signing/0123", pr(map[string]any{})),
		az("Microsoft.KeyVault/vaults/accessPolicies", "app", "shop/add", pr(map[string]any{"accessPolicies": []any{}})),
		az("Microsoft.KeyVault/vaults/privateEndpointConnections", "app", "shop/pe-1", pr(map[string]any{})),
		az("Microsoft.KeyVault/vaults", "app", "open", map[string]any{"location": "westeurope",
			"properties": map[string]any{"tenantId": "00000000-0000-0000-0000-000000000001", "sku": map[string]any{"family": "A", "name": "standard"},
				"enableRbacAuthorization": true, "enableSoftDelete": false, "publicNetworkAccess": "Enabled"}}),
		az("Microsoft.KeyVault/vaults/secrets", "app", "open/token", pr(map[string]any{"attributes": map[string]any{"enabled": true, "nbf": float64(1700000000)}})),
		// A secret whose vault the capture did not hold.
		az("Microsoft.KeyVault/vaults/secrets", "app", "gone/orphan", pr(map[string]any{})),
	}}
}

func kvMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1"}
	a.Destinations.Secrets = "secret-manager"
	g := Map{To: "gcp", Secrets: &SecretsMap{Replication: "user-managed", Locations: []string{"europe-west1", "europe-west4"}}}
	g.Destinations.Secrets = "secret-manager"
	return map[string]Map{"aws": a, "gcp": g}
}

func runKV(t *testing.T, s snapshot.Snapshot, m Map) Result {
	t.Helper()
	r, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const (
	kvShop  = "Microsoft.KeyVault/vaults app/shop"
	kvOpen  = "Microsoft.KeyVault/vaults app/open"
	kvDB    = "Microsoft.KeyVault/vaults/secrets app/shop/db-password"
	kvOld   = "Microsoft.KeyVault/vaults/secrets app/shop/legacy"
	kvToken = "Microsoft.KeyVault/vaults/secrets app/open/token"
)

func TestSecretsGolden(t *testing.T) {
	for name, m := range kvMaps() {
		r := runKV(t, kvFixture(), m)
		golden(t, "secrets-"+name, r)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
			// The fixture holds only settings a rule reads.
			for _, l := range e.Losses {
				if l.Unread {
					t.Errorf("%s: %s: %s is unread", name, e.Source, l.Field)
				}
			}
		}
		for _, o := range kvFixture().Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
		if len(seen) != len(kvFixture().Objects) {
			t.Errorf("%s: %d entries for %d objects", name, len(seen), len(kvFixture().Objects))
		}
		// A value is never written, whatever the source held.
		for _, o := range r.Snapshots[m.To].Objects {
			if strings.Contains(canonJSON(o.Body), neverOnDisk) {
				t.Errorf("%s: %s holds the secret's value", name, o.Key())
			}
		}
		if l := hasLoss(entry(t, r, kvOld), "properties.value"); l == nil || l.Widens {
			t.Errorf("%s: a value in the source: %+v", name, entry(t, r, kvOld).Losses)
		}
	}
}

func TestSecretsOnAWS(t *testing.T) {
	r := runKV(t, kvFixture(), kvMaps()["aws"])
	db := object(t, r, "aws", awsSecret, "shop/db-password")
	if db["Name"] != "shop/db-password" || db["Description"] != "From Azure Key Vault app/shop, secret db-password; content type text/plain" {
		t.Errorf("db-password: %v", db)
	}
	want := []any{map[string]any{"Key": "Owner Team", "Value": "data"}, map[string]any{"Key": "env", "Value": "dev"}}
	if !reflect.DeepEqual(db["Tags"], want) {
		t.Errorf("tags: %v", db["Tags"])
	}
	for _, k := range []string{"SecretString", "GenerateSecretString", "KmsKeyId"} {
		if _, ok := db[k]; ok {
			t.Errorf("db-password has %s", k)
		}
	}
	e := entry(t, r, kvDB)
	if l := hasLoss(e, "tags.Name"); l == nil || l.Widens {
		t.Errorf("a Name tag: %+v", e.Losses)
	}
	if l := hasLoss(e, "properties.attributes.exp"); l == nil || l.Widens || !strings.Contains(l.Why, "2030-01-01T00:00:00Z") {
		t.Errorf("exp: %+v", e.Losses)
	}
	object(t, r, "aws", awsSecret, "open/token")
	if l := lossAbout(entry(t, r, "Microsoft.KeyVault/vaults/secrets app/shop/api-abc123"), "partial ARN"); l == nil || l.Widens {
		t.Errorf("a name AWS advises against: %+v", l)
	}
	if !anyRequirement(r, "--values (AWS::SecretsManager::Secret/<name>") || !anyRequirement(r, "shop/api-abc123, shop/db-password, shop/legacy") {
		t.Errorf("no value requirement: %v", r.Report.Requirements)
	}
	if !anyRequirement(r, "2 access policies") || !anyRequirement(r, "secretsmanager:GetSecretValue") || !anyRequirement(r, "Azure RBAC role assignments") {
		t.Errorf("no identity requirement: %v", r.Report.Requirements)
	}
	if !anyRequirement(r, "Secret shop/legacy was disabled") {
		t.Errorf("no requirement for the disabled secret: %v", r.Report.Requirements)
	}
	if l := hasLoss(entry(t, r, kvOld), "properties.attributes.enabled"); l == nil || l.Widens {
		t.Errorf("disabled: %+v", l)
	}
}

func TestSecretsOnGCP(t *testing.T) {
	r := runKV(t, kvFixture(), kvMaps()["gcp"])
	db := object(t, r, "gcp", gcpSecret, gcpProject+"/secrets/shop_db-password")
	repl := map[string]any{"userManaged": map[string]any{"replicas": []any{map[string]any{"location": "europe-west1"}, map[string]any{"location": "europe-west4"}}}}
	if !reflect.DeepEqual(db["replication"], repl) {
		t.Errorf("replication: %v", db["replication"])
	}
	if !reflect.DeepEqual(db["labels"], map[string]any{"env": "dev"}) || !reflect.DeepEqual(db["annotations"], map[string]any{"content-type": "text/plain"}) {
		t.Errorf("db-password: %v", db)
	}
	if _, ok := db["name"]; ok {
		t.Error("a Secret's name is output only")
	}
	if _, ok := db["expireTime"]; ok {
		t.Error("an expiry Key Vault only records would delete the secret")
	}
	e := entry(t, r, kvDB)
	for _, k := range []string{"tags.Owner Team", "tags.Name"} {
		if l := hasLoss(e, k); l == nil || l.Widens {
			t.Errorf("%s: %+v", k, e.Losses)
		}
	}
	if l := hasLoss(entry(t, r, kvToken), "properties.attributes.nbf"); l == nil || l.Widens {
		t.Errorf("nbf: %+v", entry(t, r, kvToken).Losses)
	}
	if !anyRequirement(r, "gcloud secrets versions add") || !anyRequirement(r, "roles/secretmanager.secretAccessor") || !anyRequirement(r, "Secret shop_legacy was disabled") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
	a := kvMaps()["gcp"]
	a.Secrets = &SecretsMap{Replication: "automatic"}
	if got := object(t, runKV(t, kvFixture(), a), "gcp", gcpSecret, gcpProject+"/secrets/open_token")["replication"]; !reflect.DeepEqual(got, map[string]any{"automatic": map[string]any{}}) {
		t.Errorf("automatic: %v", got)
	}
}

// A vault that answered only some networks, or kept a deleted secret
// out of reach, is less protected on the target; the rest is not.
func TestVaultLossesThatWiden(t *testing.T) {
	want := map[string]map[string][]string{
		"aws": {kvShop: {"properties.networkAcls", "properties.enablePurgeProtection"}, kvOpen: nil},
		"gcp": {kvShop: {"properties.networkAcls", "properties.enableSoftDelete", "properties.enablePurgeProtection"}, kvOpen: nil},
	}
	for name, m := range kvMaps() {
		r := runKV(t, kvFixture(), m)
		for _, e := range r.Report.Entries {
			var got []string
			for _, l := range e.Losses {
				if l.Widens {
					got = append(got, l.Field)
				}
			}
			if w := want[name][e.Source]; !reflect.DeepEqual(got, w) && (len(got) > 0 || len(w) > 0) {
				t.Errorf("%s: %s widens %v, want %v", name, e.Source, got, w)
			}
		}
		shop := entry(t, r, kvShop)
		for _, f := range []string{"properties.sku.name", "properties.accessPolicies", "properties.enabledForTemplateDeployment", "tags"} {
			if l := hasLoss(shop, f); l == nil || l.Widens {
				t.Errorf("%s: %s: %+v", name, f, shop.Losses)
			}
		}
		if l := hasLoss(entry(t, r, kvOpen), "properties.enableRbacAuthorization"); l == nil || l.Widens {
			t.Errorf("%s: rbac: %+v", name, entry(t, r, kvOpen).Losses)
		}
	}
	// Soft delete is on unless the vault says otherwise: Azure no longer
	// lets it be turned off.
	s := kvFixture()
	for _, o := range s.Objects {
		if source(o) == kvOpen {
			delete(o.Body["spec"].(map[string]any)["properties"].(map[string]any), "enableSoftDelete")
		}
	}
	if l := hasLoss(entry(t, runKV(t, s, kvMaps()["gcp"]), kvOpen), "properties.enableSoftDelete"); l == nil || !l.Widens || !strings.Contains(l.Why, "90 days") {
		t.Errorf("gcp, soft delete by default: %+v", l)
	}
	if l := hasLoss(entry(t, runKV(t, s, kvMaps()["aws"]), kvOpen), "properties.softDeleteRetentionInDays"); l == nil || l.Widens {
		t.Errorf("aws, soft delete by default: %+v", l)
	}
	// A private endpoint only is private too.
	for _, o := range s.Objects {
		if source(o) == kvOpen {
			o.Body["spec"].(map[string]any)["properties"].(map[string]any)["publicNetworkAccess"] = "Disabled"
		}
	}
	for name, m := range kvMaps() {
		if l := hasLoss(entry(t, runKV(t, s, m), kvOpen), "properties.networkAcls"); l == nil || !l.Widens || !strings.Contains(l.Why, "private endpoints only") {
			t.Errorf("%s: public access disabled: %+v", name, l)
		}
	}
}

func TestSecretsRefused(t *testing.T) {
	for name, m := range kvMaps() {
		r := runKV(t, kvFixture(), m)
		for src, why := range map[string]string{
			"Microsoft.KeyVault/vaults/keys app/shop/signing":            "never leaves its vault",
			"Microsoft.KeyVault/vaults/keys/versions app/shop/signing/0": "never leaves its vault",
			"Microsoft.KeyVault/vaults/accessPolicies app/shop/add":      "identity is not translated",
			"Microsoft.KeyVault/vaults/secrets app/gone/orphan":          "vault is not in the snapshot",
		} {
			if e := entry(t, r, src); e.State != Refused || !strings.Contains(e.Reason, why) {
				t.Errorf("%s: %s: %s %q", name, src, e.State, e.Reason)
			}
		}
		kms := map[string]string{"aws": "AWS KMS", "gcp": "Cloud KMS"}[name]
		if e := entry(t, r, "Microsoft.KeyVault/vaults/keys app/shop/signing"); !strings.Contains(e.Reason, kms) {
			t.Errorf("%s: no %s hint: %q", name, kms, e.Reason)
		}
		if e := entry(t, r, "Microsoft.KeyVault/vaults/privateEndpointConnections"); e.State != NotLooked {
			t.Errorf("%s: private endpoint connection: %s", name, e.State)
		}
		if e := entry(t, r, kvDB); e.State != WithLosses {
			t.Errorf("%s: db-password: %s", name, e.State)
		}
		if !r.Report.Failed() {
			t.Errorf("%s: not failed", name)
		}
		// A name the map gives must be one the target takes.
		m.Names = map[string]string{"app/shop/db-password": "has space"}
		if e := entry(t, runKV(t, kvFixture(), m), kvDB); e.State != Refused || !strings.Contains(e.Reason, "app/shop/db-password") {
			t.Errorf("%s: a bad name: %s %q", name, e.State, e.Reason)
		}
		m.Names = map[string]string{"app/shop/db-password": "db"}
		r = runKV(t, kvFixture(), m)
		if len(entry(t, r, kvDB).Targets) != 1 || !strings.HasSuffix(entry(t, r, kvDB).Targets[0], "db") {
			t.Errorf("%s: a given name: %v", name, entry(t, r, kvDB).Targets)
		}
	}
}

// What the map does not choose is refused, never filled in.
func TestSecretsNeedTheirChoices(t *testing.T) {
	none := Map{To: "aws", Region: "eu-west-1"}
	r := runKV(t, kvFixture(), none)
	for _, src := range []string{kvShop, kvDB, kvToken} {
		if e := entry(t, r, src); e.State != Refused || !strings.Contains(e.Reason, "destinations.secrets") {
			t.Errorf("no destination: %s: %s %q", src, e.State, e.Reason)
		}
	}
	if len(r.Snapshots) != 0 {
		t.Errorf("no destination wrote %d snapshots", len(r.Snapshots))
	}
	g := kvMaps()["gcp"]
	g.Secrets = nil
	r = runKV(t, kvFixture(), g)
	for _, src := range []string{kvShop, kvDB} {
		if e := entry(t, r, src); e.State != Refused || !strings.Contains(e.Reason, "secrets.replication") {
			t.Errorf("no replication: %s: %s %q", src, e.State, e.Reason)
		}
	}
	bad := map[string]Map{}
	m := kvMaps()["aws"]
	m.Secrets = &SecretsMap{Replication: "automatic"}
	bad["replication on aws"] = m
	m = kvMaps()["gcp"]
	m.Secrets = &SecretsMap{Replication: "user-managed"}
	bad["user-managed with no locations"] = m
	m = kvMaps()["gcp"]
	m.Secrets = &SecretsMap{Replication: "automatic", Locations: []string{"x"}}
	bad["locations with automatic"] = m
	m = kvMaps()["gcp"]
	m.Secrets = &SecretsMap{Replication: "everywhere"}
	bad["an unknown replication"] = m
	m = kvMaps()["gcp"]
	m.Destinations.Secrets = ""
	bad["replication with no destination"] = m
	m = kvMaps()["aws"]
	m.Destinations.Secrets = "vault"
	bad["an unknown destination"] = m
	for name, m := range bad {
		if _, err := Translate(kvFixture(), m, targets(t)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !kvMaps()["aws"].NeedsAWS() || kvMaps()["aws"].NeedsGCP() || !kvMaps()["gcp"].NeedsGCP() || kvMaps()["gcp"].NeedsAWS() {
		t.Error("secrets do not load their target's definitions")
	}
}

func TestSecretsRestore(t *testing.T) {
	tg := targets(t)
	s := runKV(t, kvFixture(), kvMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || !strings.Contains(res.Detail, "write-only, not supplied") {
			t.Errorf("aws %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	if c := f.Count(); c[awsSecret] != 4 {
		t.Errorf("aws created %v", c)
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runKV(t, kvFixture(), kvMaps()["gcp"]).Snapshots["gcp"]
	gf := gcp.NewWorld(tg.GCP).Project("target-project", "123456789")
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK {
			t.Errorf("gcp %s: %s", res.Key, res.Detail)
		}
	}
	got, err := gf.Call(context.Background(), "GET", "https://secretmanager.googleapis.com/v1/projects/target-project/secrets/shop_db-password", nil)
	if err != nil || got["annotations"] == nil {
		t.Errorf("shop_db-password: %v %v", got, err)
	}
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("gcp again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
}
