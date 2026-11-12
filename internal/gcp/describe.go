package gcp

import (
	"fmt"
	"strings"

	"github.com/usetruthform/core/internal/describe"
)

// Collections lists a Discovery document's collections that TruthForm can
// capture (they have a get) and says which it can create.
func (ds *Docs) Collections(api, ver string) ([]string, error) {
	d, err := ds.Doc(docURL(api, ver), "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range d.collections() {
		if c.schema == "" {
			continue
		}
		create := ""
		if createMethod(c.methods) == nil {
			create = ", no create: capture only"
		}
		out = append(out, c.path+" ("+c.schema+create+")")
	}
	return out, nil
}

// Describe reports a collection's resource (projects.serviceAccounts, or
// networks for Compute) from the Discovery document: every field path to
// maxDepth levels, output-only fields as the document flags or words them,
// and the AIP field-behavior words Google writes into descriptions
// ("Required.", "Immutable.").
func (ds *Docs) Describe(api, ver, collection string, maxDepth int) (describe.Type, error) {
	d, err := ds.Doc(docURL(api, ver), "")
	if err != nil {
		return describe.Type{}, err
	}
	var c *coll
	for _, x := range d.collections() {
		if x.path == collection {
			x := x
			c = &x
		}
	}
	if c == nil || c.schema == "" {
		return describe.Type{}, fmt.Errorf("%s %s has no collection %s with a get method", api, ver, collection)
	}
	t := describe.Type{Platform: "gcp", Name: api + ".googleapis.com/" + c.schema, Version: ver}
	if d.DocumentationLink != "" {
		t.Docs = append(t.Docs, d.DocumentationLink)
	}
	t.Docs = append(t.Docs, docURL(api, ver))
	var walk func(s *Schema, prefix string, depth int, seen map[string]bool)
	walk = func(s *Schema, prefix string, depth int, seen map[string]bool) {
		if s == nil || depth > maxDepth {
			return
		}
		if s.Ref != "" {
			if seen[s.Ref] {
				return
			}
			seen = copySet(seen)
			seen[s.Ref] = true
			s = d.resolve(s)
			if s == nil {
				return
			}
		}
		if s.Items != nil {
			walk(s.Items, prefix+"[]", depth, seen)
			return
		}
		for _, k := range sortedKeys(s.Properties) {
			p := s.Properties[k]
			r := d.resolve(p)
			desc := strings.TrimSpace(p.Description)
			typ := p.Type
			if typ == "" && r != nil {
				typ = r.Type
			}
			path := join(prefix, k)
			t.Fields = append(t.Fields, describe.Field{Path: path, Type: typ,
				ReadOnly: outputOnly(p), Required: strings.HasPrefix(desc, "Required"),
				CreateOnly:  strings.HasPrefix(desc, "Immutable") || strings.Contains(desc, "Immutable."),
				Description: describe.Short(desc, 160)})
			walk(p, path, depth+1, seen)
		}
	}
	walk(&Schema{Ref: c.schema}, "", 1, map[string]bool{})
	if createMethod(c.methods) == nil {
		t.Notes = append(t.Notes, "The document declares no create method: TruthForm captures this collection but cannot restore it.")
	}
	if m := c.methods["patch"]; m != nil {
		t.Notes = append(t.Notes, "restore --update uses "+m.ID+".")
	} else if m := c.methods["update"]; m != nil {
		t.Notes = append(t.Notes, "restore --update uses "+m.ID+".")
	}
	return t, nil
}
