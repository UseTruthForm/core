package gcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureKinds are the types the tests use: free to hold and creatable in a
// project without billing, so the real drill can use them too. Monitoring
// notification channels are here because the server assigns their IDs.
var fixtureKinds = map[string][]string{ // api/version -> collections (dotted)
	"iam/v1":     {"projects.serviceAccounts", "projects.roles"},
	"logging/v2": {"projects.metrics"},
	// Alert policies reference channels by their server-assigned names.
	// Fake only: Cloud Monitoring charges for alerting conditions, so the
	// real drill does not create them.
	"monitoring/v3": {"projects.notificationChannels", "projects.alertPolicies"},
}

const fixtureDir = "../../testdata/gcp/discovery"

// TestRegenerateFixtures rebuilds testdata/gcp/discovery from Google's
// published documents, keeping only the collections above and the schemas
// they reach. STACKDNA_REGEN_GCP_FIXTURES=1 go test -run Regenerate.
func TestRegenerateFixtures(t *testing.T) {
	if os.Getenv("STACKDNA_REGEN_GCP_FIXTURES") == "" {
		t.Skip("set STACKDNA_REGEN_GCP_FIXTURES=1 to rebuild the GCP fixtures")
	}
	for _, av := range sortedKeys(fixtureKinds) {
		api, ver, _ := strings.Cut(av, "/")
		docs := FetchDocs(t.TempDir(), time.Hour)
		b, err := docs.load(api, ver)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		keepRes := map[string]any{}
		refs := map[string]bool{}
		for _, coll := range fixtureKinds[av] {
			parts := strings.Split(coll, ".")
			src := raw["resources"].(map[string]any)
			dst := keepRes
			for i, p := range parts {
				node := src[p].(map[string]any)
				out, _ := dst[p].(map[string]any)
				if out == nil {
					out = map[string]any{}
					dst[p] = out
				}
				if i == len(parts)-1 {
					out["methods"] = node["methods"]
					collectRefs(node["methods"], refs)
				} else {
					if out["resources"] == nil {
						out["resources"] = map[string]any{}
					}
					dst = out["resources"].(map[string]any)
					src = node["resources"].(map[string]any)
				}
			}
		}
		schemas := raw["schemas"].(map[string]any)
		for changed := true; changed; {
			changed = false
			for name := range refs {
				before := len(refs)
				collectRefs(schemas[name], refs)
				changed = changed || len(refs) != before
			}
		}
		keepSchemas := map[string]any{}
		for name := range refs {
			keepSchemas[name] = schemas[name]
		}
		out := map[string]any{"name": raw["name"], "version": raw["version"], "rootUrl": raw["rootUrl"],
			"servicePath": raw["servicePath"], "schemas": keepSchemas, "resources": keepRes}
		data, _ := json.MarshalIndent(out, "", " ")
		if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(fixtureDir, docFile(api, ver))
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: kept %d of %d schemas, %d bytes", path, len(keepSchemas), len(schemas), len(data))
	}
}

func collectRefs(v any, refs map[string]bool) {
	switch c := v.(type) {
	case map[string]any:
		if r, ok := c["$ref"].(string); ok {
			refs[r] = true
		}
		for _, x := range c {
			collectRefs(x, refs)
		}
	case []any:
		for _, x := range c {
			collectRefs(x, refs)
		}
	}
}
