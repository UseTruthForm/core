package saas

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestRegenerateFixtures rebuilds testdata/saas from each provider's
// published description, keeping the operations the descriptors use and
// the components they reach. STACKDNA_REGEN_SAAS_FIXTURES=1 go test -run Regenerate.
func TestRegenerateFixtures(t *testing.T) {
	if os.Getenv("STACKDNA_REGEN_SAAS_FIXTURES") == "" {
		t.Skip("set STACKDNA_REGEN_SAAS_FIXTURES=1 to rebuild the SaaS fixtures")
	}
	for _, p := range []Provider{GitHub, Cloudflare} {
		full, err := FetchSpec(p, t.TempDir(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		d := full.doc
		paths := map[string][]string{}
		for _, c := range p.Collections {
			paths[c.List] = append(paths[c.List], "get")
			paths[c.Create] = append(paths[c.Create], "post")
			if c.Get != "" {
				paths[c.Get] = append(paths[c.Get], "get")
			}
			if c.Update != "" {
				paths[c.Update] = append(paths[c.Update], "patch")
			}
		}
		out := map[string]any{"openapi": d["openapi"], "info": d["info"], "servers": d["servers"], "paths": map[string]any{}}
		comps := map[string]map[string]any{}
		srcComps, _ := d["components"].(map[string]any)
		var walk func(v any)
		walk = func(v any) {
			switch c := v.(type) {
			case map[string]any:
				if r, ok := c["$ref"].(string); ok && strings.HasPrefix(r, "#/components/") {
					p := strings.SplitN(strings.TrimPrefix(r, "#/components/"), "/", 2)
					if comps[p[0]] == nil {
						comps[p[0]] = map[string]any{}
					}
					if _, done := comps[p[0]][p[1]]; !done {
						kind, _ := srcComps[p[0]].(map[string]any)
						comps[p[0]][p[1]] = kind[p[1]]
						walk(kind[p[1]])
					}
				}
				for _, x := range c {
					walk(x)
				}
			case []any:
				for _, x := range c {
					walk(x)
				}
			}
		}
		srcPaths, _ := d["paths"].(map[string]any)
		for _, path := range sortedKeys(paths) {
			pi, _ := srcPaths[path].(map[string]any)
			kept := map[string]any{}
			ms := paths[path]
			sort.Strings(ms)
			for _, m := range ms {
				kept[m] = pi[m]
				walk(pi[m])
			}
			if ps, ok := pi["parameters"]; ok {
				kept["parameters"] = ps
				walk(ps)
			}
			out["paths"].(map[string]any)[path] = kept
		}
		out["components"] = comps
		b, _ := json.MarshalIndent(out, "", " ")
		dst := filepath.Join("../../testdata/saas", p.Spec)
		if err := os.WriteFile(dst, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d paths, %d bytes", dst, len(paths), len(b))
	}
}
