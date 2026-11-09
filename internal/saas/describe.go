package saas

import (
	"fmt"
	"strings"

	"github.com/stackdna/core/internal/describe"
)

// Kinds lists the provider's collections, derived ones included.
func (c *Client) Kinds() []string {
	out := make([]string, 0, len(c.P.Collections))
	for _, col := range c.P.Collections {
		out = append(out, col.Kind)
	}
	return out
}

// Describe reports a collection from the provider's OpenAPI description:
// the fields its writes accept (what a snapshot keeps), the fields only its
// read returns (the server's), what its create requires, and the
// provider's documentation for the operations.
func (c *Client) Describe(kind string, maxDepth int) (describe.Type, error) {
	var col *Collection
	for i := range c.P.Collections {
		if c.P.Collections[i].Kind == kind {
			col = &c.P.Collections[i]
		}
	}
	if col == nil {
		return describe.Type{}, fmt.Errorf("the %s descriptor has no collection %s", c.P.Name, kind)
	}
	t := describe.Type{Platform: c.P.Name, Name: kind, Version: specVersion(c.Spec)}
	for _, op := range [][2]string{{col.Create, col.createMethod()}, {col.List, "GET"}, {col.Update, col.updateMethod()}} {
		if op[0] == "" {
			continue
		}
		if ed, ok := c.Spec.operation(op[0], op[1])["externalDocs"].(map[string]any); ok {
			if u, _ := ed["url"].(string); u != "" && !hasString(t.Docs, u) {
				t.Docs = append(t.Docs, u)
			}
		}
	}
	required := c.Spec.Required(col.Create, col.createMethod())
	var walk func(f *Fields, prefix string, depth int, ro bool)
	walk = func(f *Fields, prefix string, depth int, ro bool) {
		if f == nil || depth > maxDepth {
			return
		}
		if f.Items != nil {
			walk(f.Items, prefix+"[]", depth, ro)
			return
		}
		for _, k := range sortedKeys(f.Children) {
			ch := f.Children[k]
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			t.Fields = append(t.Fields, describe.Field{Path: p, ReadOnly: ro, WriteOnly: ch.WriteOnly,
				Required: prefix == "" && hasString(required, k)})
			walk(ch, p, depth+1, ro)
		}
	}
	w := c.writes(col)
	walk(w, "", 1, false)
	// What only the read returns is the server's: counters, IDs, URLs.
	var read *Fields
	if r := c.Spec.ResponseSchema(col.Get, "get"); col.Get != "" && r != nil {
		read = c.Spec.fields(r, 0)
	}
	if read != nil && w != nil {
		for _, k := range sortedKeys(read.Children) {
			if w.Children[k] != nil {
				continue
			}
			// A field that names the item is input even when no body
			// carries it: an environment created by PUT .../environments/
			// {name} reads back its name, and capture keeps it. Listed as
			// read-only, the first real describe said the opposite.
			if hasString(col.Name, k) {
				t.Fields = append(t.Fields, describe.Field{Path: k, Required: true, Description: "Names the item; a restore sends it in the path."})
				continue
			}
			t.Fields = append(t.Fields, describe.Field{Path: k, ReadOnly: true})
		}
	}
	if u, why := c.unreadableChecked(col); len(u) > 0 {
		t.Notes = append(t.Notes, "Accepted on write but never read back in that form, so no snapshot holds them: "+strings.Join(u, ", ")+".")
	} else if why != "" {
		t.Notes = append(t.Notes, "Not checked for fields the read never returns: "+why+".")
	}
	if col.Singleton {
		t.Notes = append(t.Notes, "A setting, not a list: captured as one item named \"settings\".")
	}
	return t, nil
}
