package kube

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/usetruthform/core/internal/snapshot"
)

// This is the reflection half of Truthform. Other IaC tools compile each API's
// fields into a provider release, so a field the API added last month does
// not exist for them until someone ships a new provider. Truthform never holds
// a field list in code: capture reads whatever the live API returns, and the
// schema the server publishes at that moment is fingerprinted into the
// snapshot. New fields are therefore captured automatically, and schema-diff
// shows exactly what an API added or removed between two captures (a cluster
// upgrade, an operator upgrade) without anyone maintaining a list.

// maxDepth bounds schema flattening as a backstop; real recursion (a type
// that contains itself, like JSONSchemaProps) is caught by tracking $refs.
// Past this depth a path ends with "..." only if there is more structure
// below, so the cut is visible rather than silent, and a plain leaf is never
// marked as if it were truncated.
const maxDepth = 24

// typeSchemas returns, for each captured type, the field paths of its live
// schema. Types whose schema the server does not publish are returned with no
// fields and a note, so "no schema" never looks like "schema with no fields".
func typeSchemas(c *Clients, captured map[schema.GroupVersionKind]bool) ([]snapshot.TypeSchema, error) {
	paths, err := c.Discovery.OpenAPIV3().Paths()
	if err != nil {
		return nil, fmt.Errorf("read OpenAPI v3 index: %w", err)
	}
	found := map[schema.GroupVersionKind][]string{}
	for path, gv := range paths {
		if !strings.HasPrefix(path, "api/") && !strings.HasPrefix(path, "apis/") {
			continue
		}
		raw, err := gv.Schema("application/json")
		if err != nil {
			continue // reported below as "not published" for the types we needed
		}
		var doc struct {
			Components struct {
				Schemas map[string]map[string]any `json:"schemas"`
			} `json:"components"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue
		}
		for _, s := range doc.Components.Schemas {
			for _, g := range list(s["x-kubernetes-group-version-kind"]) {
				m, _ := g.(map[string]any)
				gvk := schema.GroupVersionKind{Group: strOf(m["group"]), Version: strOf(m["version"]), Kind: strOf(m["kind"])}
				if !captured[gvk] || found[gvk] != nil {
					continue
				}
				var fields []string
				flatten(s, "", 0, doc.Components.Schemas, map[string]bool{}, &fields)
				sort.Strings(fields)
				found[gvk] = dedupe(fields)
			}
		}
	}

	out := make([]snapshot.TypeSchema, 0, len(captured))
	for gvk := range captured {
		ts := snapshot.TypeSchema{APIVersion: gvk.GroupVersion().String(), Kind: gvk.Kind}
		if f, ok := found[gvk]; ok {
			ts.Fields = f
			ts.Digest = fieldsDigest(f)
		} else {
			ts.Note = "the server publishes no OpenAPI schema for this type; field changes cannot be tracked"
		}
		out = append(out, ts)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].APIVersion+out[i].Kind < out[j].APIVersion+out[j].Kind })
	return out, nil
}

// flatten walks a schema into dotted field paths: "spec.replicas",
// "spec.template.spec.containers[].image", "data.*" for maps.
func flatten(s map[string]any, prefix string, depth int, defs map[string]map[string]any, seen map[string]bool, out *[]string) {
	s, ref := deref(s, defs)
	if depth > maxDepth {
		if hasChildren(s) {
			*out = append(*out, prefix+"...")
		}
		return
	}
	if ref != "" {
		if seen[ref] {
			*out = append(*out, join(prefix, "(recursive "+ref+")"))
			return
		}
		seen = copySet(seen)
		seen[ref] = true
	}
	if props, ok := s["properties"].(map[string]any); ok {
		for name, p := range props {
			ps, _ := p.(map[string]any)
			path := join(prefix, name)
			*out = append(*out, path)
			flatten(ps, path, depth+1, defs, seen, out)
		}
	}
	if items, ok := s["items"].(map[string]any); ok {
		flatten(items, prefix+"[]", depth+1, defs, seen, out)
	}
	if ap, ok := s["additionalProperties"].(map[string]any); ok {
		path := join(prefix, "*")
		*out = append(*out, path)
		flatten(ap, path, depth+1, defs, seen, out)
	}
	if b, _ := s["x-kubernetes-preserve-unknown-fields"].(bool); b {
		*out = append(*out, join(prefix, "(any fields)"))
	}
}

func hasChildren(s map[string]any) bool {
	_, p := s["properties"].(map[string]any)
	_, i := s["items"].(map[string]any)
	_, a := s["additionalProperties"].(map[string]any)
	return p || i || a
}

// deref follows "$ref", or an "allOf" holding a single "$ref" (how the
// Kubernetes OpenAPI wraps referenced types), to the referenced schema. It
// returns the schema and the name of the last type it followed.
func deref(s map[string]any, defs map[string]map[string]any) (map[string]any, string) {
	last := ""
	for i := 0; i < 8; i++ {
		name := ""
		if r := strOf(s["$ref"]); r != "" {
			name = r
		} else if all := list(s["allOf"]); len(all) == 1 {
			if m, ok := all[0].(map[string]any); ok {
				name = strOf(m["$ref"])
			}
		}
		if name == "" {
			return s, last
		}
		name = strings.TrimPrefix(name, "#/components/schemas/")
		target, ok := defs[name]
		if !ok {
			return s, last
		}
		s, last = target, name
	}
	return s, last
}

func fieldsDigest(fields []string) string {
	h := sha256.New()
	for _, f := range fields {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func copySet(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m)+1)
	for k, v := range m {
		c[k] = v
	}
	return c
}

func join(p, k string) string {
	if p == "" {
		return k
	}
	return p + "." + k
}
