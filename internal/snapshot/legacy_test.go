package snapshot

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// testdata/format1-azure and testdata/format1-kubernetes were written by
// the last build before the rename (StackDNA v0.1.0-beta.20's Write), so
// these read what is really on disk from that time, not what this build
// thinks it wrote.

func legacyObjects(t *testing.T, dir string) (Snapshot, map[string]Object) {
	t.Helper()
	s, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Object{}
	for _, o := range s.Objects {
		by[o.Kind()+"/"+o.Name()] = o
	}
	return s, by
}

func dig(v any, path ...string) any {
	for _, p := range path {
		m, _ := v.(map[string]any)
		v = m[p]
	}
	return v
}

// The failure this pins: with only the names changed in code, a format 1
// snapshot loaded without error and every annotation and placeholder in it
// was silently not found.
//
// A review then found two more. A placeholder that is a map key (a
// user-assigned identity's ID) was left under the old name, so a diff
// reported an unchanged site as changed and a restore sent the literal
// placeholder to Azure as the identity. And a placeholder inside a list was
// translated but nothing pinned it.
func TestAFormat1AzureSnapshotIsReadUnderTheNewNames(t *testing.T) {
	s, by := legacyObjects(t, "testdata/format1-azure")

	site := by["Microsoft.Web/sites/web"]
	if got := site.APIVersion(); got != "azure.truthform.org/v1" {
		t.Errorf("apiVersion %q, want Truthform's own group renamed", got)
	}
	wantAnn := map[string]any{
		"truthform.org/api-version": "2024-04-01",
		"truthform.org/after":       []any{"Microsoft.ManagedIdentity/userAssignedIdentities|rg-app/id-app"},
		"truthform.org/id":          "/subscriptions/{{truthform|subscription}}/resourceGroups/rg-app/providers/Microsoft.Web/sites/web",
	}
	if got := dig(site.Body, "metadata", "annotations"); !reflect.DeepEqual(got, wantAnn) {
		t.Errorf("annotations\n got %v\nwant %v", got, wantAnn)
	}
	wantIDs := map[string]any{"/subscriptions/{{truthform|subscription}}/resourceGroups/rg-app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-app": map[string]any{}}
	if got := dig(site.Body, "spec", "identity", "userAssignedIdentities"); !reflect.DeepEqual(got, wantIDs) {
		t.Errorf("a placeholder that is a map key was not renamed: %v", got)
	}

	props := dig(by["Microsoft.Authorization/roleDefinitions/rd-app"].Body, "spec", "properties")
	wantProps := map[string]any{
		"assignableScopes": []any{"/subscriptions/{{truthform|subscription}}", []any{"/tenants/{{truthform|tenant}}"}},
		"description":      "tenant {{truthform|tenant}} reader",
		"principalId":      "{{truthform|ref|Microsoft.ManagedIdentity/userAssignedIdentities|rg-app/id-app|properties.principalId}}",
	}
	if !reflect.DeepEqual(props, wantProps) {
		t.Errorf("properties\n got %v\nwant %v", props, wantProps)
	}

	// The resource group's tags are the customer's, old name or not: a tag
	// key under the old domain is a key in spec, not an annotation.
	wantTags := map[string]any{"owner": "stackdna-team", "stackdna.org/costcentre": "42"}
	if got := dig(by["Microsoft.Resources/resourceGroups/rg-app"].Body, "spec", "tags"); !reflect.DeepEqual(got, wantTags) {
		t.Errorf("tags were rewritten: %v", got)
	}

	if len(s.Schemas) != 1 || s.Schemas[0].APIVersion != "azure.truthform.org/v1" {
		t.Errorf("schemas %v", s.Schemas)
	}
	const reason = "managed by /subscriptions/{{truthform|subscription}}/resourceGroups/rg-app"
	if len(s.Skips) != 1 || s.Skips[0].Reason != reason || s.Coverage[0].Skipped[reason] != 1 || len(s.Coverage[0].Skipped) != 1 {
		t.Errorf("coverage still quotes the old placeholder: %v %v", s.Skips, s.Coverage)
	}
	for _, o := range s.Objects {
		b, _ := encodeYAML(o.Body)
		if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(string(b), "stackdna-team", ""), "stackdna.org/costcentre", ""), "stackdna") {
			t.Errorf("%s still holds the old name:\n%s", o.Key(), b)
		}
	}
}

// A Kubernetes capture added two annotations to an object's own metadata
// and nothing else. Everything else in the snapshot is the cluster's, and
// is left exactly as captured.
//
// The failure this pins, found in review: the translation renamed every key
// under the old domain and every placeholder-looking string on every
// platform, so a label "stackdna.org/tier" became another label (and with
// it the Deployment's selector, which cannot change) and a ConfigMap's text
// was edited.
func TestAFormat1KubernetesSnapshotKeepsWhatIsTheClusters(t *testing.T) {
	s, by := legacyObjects(t, "testdata/format1-kubernetes")

	dep := by["Deployment/shop-api"].Body
	wantAnn := map[string]any{"truthform.org/withheld-env": "api/DB_PASSWORD", "stackdna.org/owner": "platform team"}
	if got := dig(dep, "metadata", "annotations"); !reflect.DeepEqual(got, wantAnn) {
		t.Errorf("annotations\n got %v\nwant %v", got, wantAnn)
	}
	labels := map[string]any{"stackdna.org/tier": "web"}
	for _, p := range [][]string{{"metadata", "labels"}, {"spec", "selector", "matchLabels"}, {"spec", "template", "metadata", "labels"}} {
		if got := dig(dep, p...); !reflect.DeepEqual(got, labels) {
			t.Errorf("%s was rewritten: %v", strings.Join(p, "."), got)
		}
	}
	if got := dig(dep, "spec", "template", "metadata", "annotations"); !reflect.DeepEqual(got, map[string]any{"stackdna.org/withheld-env": "not ours here"}) {
		t.Errorf("the pod template's annotations were rewritten: %v", got)
	}
	if got := dig(by["Secret/shop-db"].Body, "metadata", "annotations"); !reflect.DeepEqual(got, map[string]any{"truthform.org/withheld-keys": "password"}) {
		t.Errorf("secret annotations %v", got)
	}
	wantData := map[string]any{"readme": "ids look like /subscriptions/{{stackdna|subscription}}", "{{stackdna|key}}": "v"}
	if got := dig(by["ConfigMap/notes"].Body, "data"); !reflect.DeepEqual(got, wantData) {
		t.Errorf("a ConfigMap's content was rewritten: %v", got)
	}
	// A CRD's group is asked of the cluster under the name the cluster
	// knows, even one spelled like a group Truthform writes elsewhere.
	if got := by["Widget/blue-widget"].APIVersion(); got != "azure.stackdna.org/v1" {
		t.Errorf("a CRD's group became %q", got)
	}
	if len(s.Schemas) != 1 || s.Schemas[0].APIVersion != "azure.stackdna.org/v1" {
		t.Errorf("schemas %v", s.Schemas)
	}
}

// A format 1 snapshot, written again by this build, compares as equal to
// itself and gets another digest. This shows the translation is stable and
// that format 2 really is written under the new names. It does not show
// that a new capture of the same system matches: that is for each
// platform's own tests.
func TestAFormat1SnapshotComparesEqualToItsRewrite(t *testing.T) {
	old, err := Read("testdata/format1-azure")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := old.Write(out); err != nil {
		t.Fatal(err)
	}
	now, err := Read(out)
	if err != nil {
		t.Fatal(err)
	}
	if ch := Compare(old, now); len(ch) != 0 {
		t.Errorf("changes %v", ch)
	}
	if d, _ := Digest(out); d == "sha256:5a37a0b53373d6795ae5fd950a77109492636c751d5c880d113483ae9f3a2124" {
		t.Error("the rewritten snapshot kept format 1's digest: nothing was renamed on disk")
	}
}

// A snapshot edited after capture is still refused when it is format 1.
func TestATamperedFormat1SnapshotIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("testdata/format1-kubernetes")); err != nil {
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

// AWS and GCP name a resource that has no name from a hash of its spec, and
// the spec holds placeholders. After the rename the same resource hashes to
// another name (the AWS drill's two API Gateway resources did), so a format
// 1 snapshot from either is refused: translated, it would diff as missing
// and extra, and a restore could create the resource a second time.
func TestAFormat1SnapshotWithGeneratedNamesIsRefused(t *testing.T) {
	for platform, refuse := range map[string]bool{"aws": true, "gcp": true, "azure": false, "kubernetes": false, "saas/github": false, "saas/cloudflare": false} {
		dir := t.TempDir()
		if err := os.CopyFS(dir, os.DirFS("testdata/format1-azure")); err != nil {
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

// On a SaaS platform the old build wrote one placeholder, for the account,
// and sent every other string as captured. Only that one is renamed: a
// record that quotes a placeholder is the customer's text, and renaming it
// would show the record as changed and restore it with other content.
//
// There is no SaaS snapshot written by the old build among the fixtures, so
// this builds one in memory. It also pins that a type left out of a capture
// keeps a readable reason, which nothing else covered.
func TestOnASaaSPlatformOnlyTheAccountPlaceholderIsRenamed(t *testing.T) {
	s := Snapshot{Platform: "saas/cloudflare",
		Objects: []Object{{Body: map[string]any{"apiVersion": "saas.stackdna.org/v1", "kind": "DNSRecord",
			"metadata": map[string]any{"name": "docs", "annotations": map[string]any{"stackdna.org/parent": "accounts/{{stackdna|account}}/zones/example.com"}},
			"spec": map[string]any{
				"content":                "see {{stackdna|subscription}} in the guide",
				"owner":                  "accounts/{{stackdna|account}}",
				"{{stackdna|account}}/k": "accounts/{{stackdna|ref|x}}",
			}}}},
		Coverage: []Coverage{{Resource: "rulesets", Kind: "Ruleset", NotCaptured: "not readable for accounts/{{stackdna|account}}"}},
	}
	fromLegacy(&s)
	b := s.Objects[0].Body
	want := map[string]any{"apiVersion": "saas.truthform.org/v1", "kind": "DNSRecord",
		"metadata": map[string]any{"name": "docs", "annotations": map[string]any{"truthform.org/parent": "accounts/{{truthform|account}}/zones/example.com"}},
		"spec": map[string]any{
			"content":                 "see {{stackdna|subscription}} in the guide",
			"owner":                   "accounts/{{truthform|account}}",
			"{{truthform|account}}/k": "accounts/{{stackdna|ref|x}}",
		}}
	if !reflect.DeepEqual(b, want) {
		t.Errorf("\n got %v\nwant %v", b, want)
	}
	if got := s.Coverage[0].NotCaptured; got != "not readable for accounts/{{truthform|account}}" {
		t.Errorf("notCaptured %q", got)
	}
}
