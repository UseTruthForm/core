package kube

import (
	"strings"
	"testing"
)

// A miniature of the Kubernetes OpenAPI v3 shape: types referenced through
// allOf-wrapped $refs, a map, an array, and a type that contains itself.
func testDefs() map[string]map[string]any {
	return map[string]map[string]any{
		"Widget": {"properties": map[string]any{
			"spec":     map[string]any{"allOf": []any{map[string]any{"$ref": "#/components/schemas/WidgetSpec"}}},
			"metadata": map[string]any{"$ref": "#/components/schemas/Meta"},
		}},
		"WidgetSpec": {"properties": map[string]any{
			"size":   map[string]any{"type": "integer"},
			"tags":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"labels": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			"tree":   map[string]any{"$ref": "#/components/schemas/Node"},
		}},
		"Meta": {"properties": map[string]any{"name": map[string]any{"type": "string"}}},
		"Node": {"properties": map[string]any{
			"value":    map[string]any{"type": "string"},
			"children": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Node"}},
		}},
	}
}

func TestFlattenFollowsRefsMapsArraysAndStopsRecursion(t *testing.T) {
	defs := testDefs()
	var got []string
	flatten(defs["Widget"], "", 0, defs, map[string]bool{}, &got)
	joined := "\n" + strings.Join(got, "\n") + "\n"
	for _, want := range []string{
		"\nspec\n", "\nspec.size\n", "\nspec.tags\n", "\nspec.labels.*\n",
		"\nmetadata.name\n", "\nspec.tree.value\n", "\nspec.tree.children\n",
		"\nspec.tree.children[].(recursive Node)\n",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in:%s", strings.TrimSpace(want), joined)
		}
	}
	// A plain array of strings is a leaf: it must not be marked as cut off.
	if strings.Contains(joined, "tags[]...") {
		t.Fatal("leaf array wrongly marked as truncated")
	}
}
