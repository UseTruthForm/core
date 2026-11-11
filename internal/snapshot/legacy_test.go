package snapshot

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// testdata/format1 was written by the last build before the rename
// (StackDNA v0.1.0-beta.20's Write), so this reads what is really on disk
// from that time, not what this build thinks it wrote.
//
// The failure it pins: with only the names changed in code, a format 1
// snapshot loaded without error and every annotation and placeholder in it
// was silently not found.
func TestAFormat1SnapshotIsReadUnderTheNewNames(t *testing.T) {
	s, err := Read("testdata/format1")
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Object{}
	for _, o := range s.Objects {
		by[o.Kind()+"/"+o.Name()] = o
	}
	ann := func(o Object) map[string]any { return meta(o.Body)["annotations"].(map[string]any) }

	ra := by["Microsoft.Authorization/roleAssignments/ra-app"]
	if got := ra.APIVersion(); got != "azure.truthform.org/v1" {
		t.Errorf("apiVersion %q, want Truthform's own group renamed", got)
	}
	want := map[string]any{
		"truthform.org/api-version": "2022-04-01",
		"truthform.org/after":       []any{"Microsoft.ManagedIdentity/userAssignedIdentities|rg-app/id-app"},
		"truthform.org/id":          "/subscriptions/{{truthform|subscription}}/providers/Microsoft.Authorization/roleAssignments/ra-app",
	}
	if got := ann(ra); !reflect.DeepEqual(got, want) {
		t.Errorf("annotations\n got %v\nwant %v", got, want)
	}
	props := ra.Body["spec"].(map[string]any)["properties"].(map[string]any)
	for k, want := range map[string]string{
		"principalId": "{{truthform|ref|Microsoft.ManagedIdentity/userAssignedIdentities|rg-app/id-app|properties.principalId}}",
		"scope":       "/subscriptions/{{truthform|subscription}}",
		"description": "tenant {{truthform|tenant}} reader",
	} {
		if props[k] != want {
			t.Errorf("%s = %q, want %q", k, props[k], want)
		}
	}

	// What the captured system itself called by the old name stays as it
	// was: a tag, a label, a value that only looks like an annotation key,
	// and a CRD's own API group, which a restore must ask the cluster for
	// under the name the cluster knows.
	rg := by["Microsoft.Resources/resourceGroups/rg-app"]
	if got := rg.Body["spec"].(map[string]any)["tags"].(map[string]any)["owner"]; got != "stackdna-team" {
		t.Errorf("tag %q was rewritten", got)
	}
	sec := by["Secret/shop-db"]
	if got := meta(sec.Body)["labels"].(map[string]any)["app.kubernetes.io/managed-by"]; got != "stackdna" {
		t.Errorf("label %q was rewritten", got)
	}
	if got := ann(sec); !reflect.DeepEqual(got, map[string]any{"truthform.org/withheld-keys": "password", "example.com/owner": "stackdna.org/not-ours-as-a-value"}) {
		t.Errorf("secret annotations %v", got)
	}
	if got := by["Widget/blue-widget"].APIVersion(); got != "example.stackdna.org/v1" {
		t.Errorf("a CRD's group became %q", got)
	}

	schemas := map[string]bool{}
	for _, ts := range s.Schemas {
		schemas[ts.APIVersion+" "+ts.Kind] = true
	}
	if !schemas["azure.truthform.org/v1 Microsoft.Resources/resourceGroups@2025-04-01"] || !schemas["example.stackdna.org/v1 Widget"] {
		t.Errorf("schemas %v", schemas)
	}
}

// A format 1 snapshot and the same system captured today compare as equal:
// the rename alone is not drift.
func TestAFormat1SnapshotComparesEqualToItsRewrite(t *testing.T) {
	old, err := Read("testdata/format1")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := old.Write(dir); err != nil {
		t.Fatal(err)
	}
	now, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ch := Compare(old, now); len(ch) != 0 {
		t.Errorf("changes %v", ch)
	}
	if d, _ := Digest(dir); d == "sha256:7e11bce13c02b933ef964762c840a13cfc88fc685ea59dd4cbaf024bc6e4fad5" {
		t.Error("the rewritten snapshot kept format 1's digest: nothing was renamed on disk")
	}
}

// A snapshot edited after capture is still refused when it is format 1: the
// digest is checked over the files as written, before anything is renamed.
func TestATamperedFormat1SnapshotIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("testdata/format1")); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(dir+"/objects/core/v1/Secret/shop/shop-db.yaml", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("extra: true\n")
	f.Close()
	if _, err := Read(dir); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("want a digest mismatch, got %v", err)
	}
}

// Only a key whose whole prefix is the old domain is ours. One that merely
// contains it belongs to the captured system and is left alone.
func TestOnlyKeysUnderTheOldDomainAreRenamed(t *testing.T) {
	got := legacyValue(map[string]any{
		"stackdna.org/id":                 "a",
		"corp.example/stackdna.org/owner": "b",
		"notstackdna.org/id":              "c",
	})
	want := map[string]any{
		"truthform.org/id":                "a",
		"corp.example/stackdna.org/owner": "b",
		"notstackdna.org/id":              "c",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// AWS and GCP name a resource that has no name from a hash of its spec, and
// the spec holds placeholders. After the rename the same resource hashes to
// another name (the AWS drill's two API Gateway resources did), so a format
// 1 snapshot from either is refused: translated, it would diff as missing
// and extra, and a restore could create the resource a second time.
func TestAFormat1SnapshotWithGeneratedNamesIsRefused(t *testing.T) {
	for platform, refuse := range map[string]bool{"aws": true, "gcp": true, "azure": false, "kubernetes": false, "github": false, "cloudflare": false} {
		dir := t.TempDir()
		if err := os.CopyFS(dir, os.DirFS("testdata/format1")); err != nil {
			t.Fatal(err)
		}
		mb, err := os.ReadFile(dir + "/snapshot.yaml")
		if err != nil {
			t.Fatal(err)
		}
		// The digest covers the objects and the coverage report, not the
		// manifest, so the platform can be changed here.
		if err := os.WriteFile(dir+"/snapshot.yaml", []byte(strings.Replace(string(mb), "platform: azure", "platform: "+platform, 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err = Read(dir)
		if refuse && (err == nil || !strings.Contains(err.Error(), "Capture the source again")) {
			t.Errorf("%s: want a refusal that says to capture again, got %v", platform, err)
		}
		if !refuse && err != nil {
			t.Errorf("%s: %v", platform, err)
		}
	}
}
