// Package saas captures and restores the configuration of SaaS providers
// (GitHub, Cloudflare) through their REST APIs, driven by the OpenAPI
// descriptions the providers publish.
//
// An OpenAPI description says how to call each endpoint but not which ones
// hold configuration (a repository's settings) rather than activity (its
// issues), so each provider has a short descriptor naming its
// configuration collections. Everything else comes from the description:
// what a captured item keeps is what the create or update operation
// accepts. GitHub flags 0 of the 105 fields of a repository read-only, so
// flags cannot be relied on; a field the API returns but no write accepts
// (stargazers_count, created_at) is computed by the server by definition.
package saas

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Spec is an OpenAPI 3 description, kept as decoded JSON.
type Spec struct {
	doc map[string]any
}

// FetchSpec downloads a provider's published description, keeping it in
// cacheDir for maxAge, so captures follow the provider's API as it changes.
func FetchSpec(p Provider, cacheDir string, maxAge time.Duration) (*Spec, error) {
	path := filepath.Join(cacheDir, p.Spec)
	if st, err := os.Stat(path); err != nil || time.Since(st.ModTime()) > maxAge {
		resp, err := http.Get(p.SpecURL) //nolint:gosec // the provider's own published URL
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", p.SpecURL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("download %s: HTTP %d", p.SpecURL, resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			return nil, err
		}
	}
	return LoadSpec(path)
}

// LoadSpec reads an OpenAPI description from a JSON file.
func LoadSpec(path string) (*Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Spec{doc: d}, nil
}

func (s *Spec) resolve(v any) map[string]any {
	m, _ := v.(map[string]any)
	for i := 0; m != nil && i < 16; i++ {
		r, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		var cur any = s.doc
		for _, p := range strings.Split(strings.TrimPrefix(r, "#/"), "/") {
			cm, _ := cur.(map[string]any)
			cur = cm[p]
		}
		m, _ = cur.(map[string]any)
	}
	return m
}

func (s *Spec) operation(path, method string) map[string]any {
	paths, _ := s.doc["paths"].(map[string]any)
	p, _ := paths[path].(map[string]any)
	op, _ := p[strings.ToLower(method)].(map[string]any)
	return op
}

// RequestFields is the field tree an operation's JSON body accepts, or nil
// if it takes none.
func (s *Spec) RequestFields(path, method string) *Fields {
	op := s.operation(path, method)
	rb := s.resolve(op["requestBody"])
	content, _ := rb["content"].(map[string]any)
	js, _ := content["application/json"].(map[string]any)
	if js == nil {
		return nil
	}
	return s.fields(js["schema"], 0)
}

// Required lists the top-level fields an operation's body requires.
func (s *Spec) Required(path, method string) []string {
	op := s.operation(path, method)
	rb := s.resolve(op["requestBody"])
	content, _ := rb["content"].(map[string]any)
	js, _ := content["application/json"].(map[string]any)
	sch := s.resolve(js["schema"])
	var out []string
	for _, r := range anyList(sch["required"]) {
		if str, ok := r.(string); ok {
			out = append(out, str)
		}
	}
	sort.Strings(out)
	return out
}

func anyList(v any) []any { l, _ := v.([]any); return l }

// ResponseSchema is the success response schema of an operation.
func (s *Spec) ResponseSchema(path, method string) map[string]any {
	op := s.operation(path, method)
	resps, _ := op["responses"].(map[string]any)
	for _, code := range []string{"200", "201"} {
		r := s.resolve(resps[code])
		content, _ := r["content"].(map[string]any)
		if js, ok := content["application/json"].(map[string]any); ok {
			return s.resolve(js["schema"])
		}
	}
	return nil
}

// Has reports whether the description has an operation.
func (s *Spec) Has(path, method string) bool { return s.operation(path, method) != nil }

// Fields is a tree of field names. A nil Children with Any set means any
// value is accepted there (a free-form object or map), so it is kept whole.
type Fields struct {
	Children  map[string]*Fields
	Items     *Fields
	Any       bool
	WriteOnly bool
}

const maxDepth = 12

// fields merges every alternative of a schema (allOf, oneOf, anyOf): a
// field any variant accepts is a field the write accepts. A Cloudflare DNS
// record is one of a dozen record types, each with its own fields.
func (s *Spec) fields(v any, depth int) *Fields {
	m := s.resolve(v)
	f := &Fields{}
	if m == nil || depth > maxDepth {
		f.Any = true
		return f
	}
	if w, _ := m["writeOnly"].(bool); w {
		f.WriteOnly = true
	}
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		alts, _ := m[k].([]any)
		for _, a := range alts {
			f.merge(s.fields(a, depth+1))
		}
	}
	if items, ok := m["items"]; ok {
		f.Items = s.fields(items, depth+1)
	}
	if props, ok := m["properties"].(map[string]any); ok {
		if f.Children == nil {
			f.Children = map[string]*Fields{}
		}
		for k, p := range props {
			pf := s.fields(p, depth+1)
			if f.Children[k] != nil {
				f.Children[k].merge(pf)
			} else {
				f.Children[k] = pf
			}
		}
	}
	if ap, ok := m["additionalProperties"]; ok && ap != false {
		f.Any = true
	}
	if t, _ := m["type"].(string); t == "object" && m["properties"] == nil && m["allOf"] == nil && m["oneOf"] == nil && m["anyOf"] == nil {
		f.Any = true
	}
	return f
}

func (f *Fields) merge(o *Fields) {
	if o == nil {
		return
	}
	f.Any = f.Any || o.Any
	f.WriteOnly = f.WriteOnly || o.WriteOnly
	if o.Items != nil {
		if f.Items == nil {
			f.Items = &Fields{}
		}
		f.Items.merge(o.Items)
	}
	for k, c := range o.Children {
		if f.Children == nil {
			f.Children = map[string]*Fields{}
		}
		if f.Children[k] == nil {
			f.Children[k] = &Fields{}
		}
		f.Children[k].merge(c)
	}
}

// union combines the fields of several writes (create, then update).
func union(fs ...*Fields) *Fields {
	out := &Fields{}
	for _, f := range fs {
		out.merge(f)
	}
	return out
}

// Paths flattens a field tree for schema-diff.
func (f *Fields) Paths() []string {
	var out []string
	var walk func(f *Fields, prefix string, depth int)
	walk = func(f *Fields, prefix string, depth int) {
		if f == nil || depth > maxDepth {
			return
		}
		if f.Items != nil {
			walk(f.Items, prefix+"[]", depth+1)
		}
		for k, c := range f.Children {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			out = append(out, p)
			walk(c, p, depth+1)
		}
	}
	walk(f, "", 0)
	sort.Strings(out)
	return out
}

// keep returns v reduced to what the write accepts. Masked values (GitHub
// answers a webhook secret as "********") are never kept: their paths are
// returned so a restore can say what it was not given.
func keep(v any, f *Fields, path string, masked *[]string) (any, bool) {
	if f == nil {
		return nil, false
	}
	if s, ok := v.(string); ok && len(s) >= 3 && strings.Trim(s, "*") == "" {
		*masked = append(*masked, path)
		return nil, false
	}
	if f.WriteOnly {
		*masked = append(*masked, path)
		return nil, false
	}
	switch c := v.(type) {
	case map[string]any:
		if f.Children == nil && f.Any {
			return c, true
		}
		out := map[string]any{}
		for _, k := range sortedKeys(c) {
			child, ok := f.Children[k]
			if !ok {
				continue
			}
			p := k
			if path != "" {
				p = path + "." + k
			}
			if x, ok := keep(c[k], child, p, masked); ok {
				out[k] = x
			}
		}
		return out, true
	case []any:
		if f.Items == nil {
			return c, f.Any || f.Children == nil
		}
		out := make([]any, 0, len(c))
		for _, x := range c {
			if y, ok := keep(x, f.Items, path+"[]", masked); ok {
				out = append(out, y)
			}
		}
		return out, true
	}
	return v, true
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
