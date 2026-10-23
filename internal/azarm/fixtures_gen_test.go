package azarm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// fixtureTypes are the types the tests use, at stable API versions. The
// first six are free to hold in a real subscription, for the drill there;
// the VM is only for the secret-property tests (its adminPassword).
var fixtureTypes = []string{
	"Microsoft.Resources/resourceGroups@2024-11-01",
	"Microsoft.Network/virtualNetworks@2025-07-01",
	"Microsoft.Network/networkSecurityGroups@2025-07-01",
	"Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31",
	"Microsoft.Storage/storageAccounts@2025-08-01",
	"Microsoft.Web/serverfarms@2024-11-01",
	"Microsoft.Web/sites@2024-11-01",
	"Microsoft.Compute/virtualMachines@2025-04-01",
	// Extension resources, which the subscription's resource list does not
	// return, and children found through their parent.
	"Microsoft.Authorization/roleAssignments@2022-04-01",
	"Microsoft.Authorization/roleDefinitions@2022-04-01",
	"Microsoft.Authorization/locks@2020-05-01",
	"Microsoft.Authorization/policyAssignments@2025-11-01",
	"Microsoft.Insights/diagnosticSettings@2016-09-01",
	"Microsoft.Storage/storageAccounts/blobServices@2025-08-01",
	"Microsoft.Storage/storageAccounts/blobServices/containers@2025-08-01",
	"Microsoft.Network/virtualNetworks/subnets@2025-07-01",
	"Microsoft.Network/networkSecurityGroups/securityRules@2025-07-01",
	// Azure creates these with every NSG and no one can PUT them
	// (writableScopes 0): capture must leave them out.
	"Microsoft.Network/networkSecurityGroups/defaultSecurityRules@2025-07-01",
}

const fixtureDir = "../../testdata/azure/types"

// TestRegenerateFixtures rebuilds testdata/azure/types from Azure's
// published definitions, keeping only what fixtureTypes reach. It runs only
// when asked: STACKDNA_REGEN_AZURE_FIXTURES=1 go test -run Regenerate.
func TestRegenerateFixtures(t *testing.T) {
	if os.Getenv("STACKDNA_REGEN_AZURE_FIXTURES") == "" {
		t.Skip("set STACKDNA_REGEN_AZURE_FIXTURES=1 to rebuild the Azure fixtures")
	}
	src, err := FetchDefinitions(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string][]string{} // file -> "type@version" whose root lives there
	for _, tv := range fixtureTypes {
		loc, ok := src.index[strings.ToLower(tv)]
		if !ok {
			t.Fatalf("%s not in the published index", tv)
		}
		file, _, _ := strings.Cut(loc, "#")
		byFile[file] = append(byFile[file], tv)
	}
	index := map[string]map[string]string{}
	for _, file := range sortedKeys(byFile) {
		b, err := src.load(file)
		if err != nil {
			t.Fatal(err)
		}
		var all []any
		if err := json.Unmarshal(b, &all); err != nil {
			t.Fatal(err)
		}
		var roots []int
		for _, tv := range byFile[file] {
			_, frag, _ := strings.Cut(src.index[strings.ToLower(tv)], "#")
			roots = append(roots, ref{Ref: "#" + frag}.index())
		}
		kept, renum := reachable(all, roots)
		out := make([]any, len(kept))
		for i, old := range kept {
			out[i] = rewrite(all[old], renum)
		}
		data, _ := json.MarshalIndent(out, "", " ")
		path := filepath.Join(fixtureDir, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		for i, tv := range byFile[file] {
			index[tv] = map[string]string{"$ref": fmt.Sprintf("%s#/%d", file, renum[roots[i]])}
		}
		t.Logf("%s: kept %d of %d entries", file, len(kept), len(all))
	}
	data, _ := json.MarshalIndent(map[string]any{"resources": index}, "", " ")
	if err := os.WriteFile(filepath.Join(fixtureDir, "index.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// reachable returns the entries reachable from roots, in their original
// order, and the old-to-new index mapping.
func reachable(all []any, roots []int) ([]int, map[int]int) {
	seen := map[int]bool{}
	var visit func(i int)
	var walk func(v any)
	walk = func(v any) {
		switch c := v.(type) {
		case map[string]any:
			if r, ok := c["$ref"].(string); ok && strings.HasPrefix(r, "#/") {
				visit(ref{Ref: r}.index())
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
	visit = func(i int) {
		if !seen[i] {
			seen[i] = true
			walk(all[i])
		}
	}
	for _, r := range roots {
		visit(r)
	}
	var kept []int
	for i := range seen {
		kept = append(kept, i)
	}
	sort.Ints(kept)
	renum := map[int]int{}
	for n, old := range kept {
		renum[old] = n
	}
	return kept, renum
}

func rewrite(v any, renum map[int]int) any {
	switch c := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range c {
			if r, ok := x.(string); ok && k == "$ref" && strings.HasPrefix(r, "#/") {
				out[k] = fmt.Sprintf("#/%d", renum[ref{Ref: r}.index()])
				continue
			}
			out[k] = rewrite(x, renum)
		}
		return out
	case []any:
		out := make([]any, len(c))
		for i, x := range c {
			out[i] = rewrite(x, renum)
		}
		return out
	}
	return v
}
