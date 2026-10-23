package azarm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/describe"
)

// Names lists every resource type with a published definition, as Azure
// spells it, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.names))
	for _, n := range r.names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Describe reports a type at an API version (the newest when version is
// empty) from its definition: every field path to maxDepth levels, with
// the definition's flags (required, read-only, write-only), secrets
// (write-only or sensitive), and the template reference page for it.
func (r *Registry) Describe(resourceType, version string, maxDepth int) (describe.Type, error) {
	if version == "" {
		vs := r.Versions(resourceType)
		if len(vs) == 0 {
			return describe.Type{}, fmt.Errorf("no published definition for %s", resourceType)
		}
		version = vs[0]
	}
	s, err := r.Schema(resourceType, version)
	if err != nil {
		return describe.Type{}, err
	}
	name := resourceType
	if n, ok := r.names[strings.ToLower(resourceType)]; ok {
		name = n
	}
	d := describe.Type{Platform: "azure", Name: name, Version: version,
		Docs: []string{"https://learn.microsoft.com/azure/templates/" + strings.ToLower(name[:strings.Index(name, "/")]) + "/" + version +
			"/" + strings.ToLower(name[strings.Index(name, "/")+1:]) + "?pivots=deployment-language-arm-template"}}
	var walk func(i int, prefix string, depth int, seen map[int]bool)
	walk = func(i int, prefix string, depth int, seen map[int]bool) {
		if depth > maxDepth || seen[i] {
			return
		}
		seen = copySet(seen)
		seen[i] = true
		e := s.file[i]
		if e.Kind == "ArrayType" && e.ItemType != nil {
			walk(e.ItemType.index(), prefix+"[]", depth, seen)
			return
		}
		props, _, ok := s.object(i, nil)
		if !ok {
			return
		}
		for _, k := range sortedKeys(props) {
			p := props[k]
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			d.Fields = append(d.Fields, describe.Field{Path: path, Type: s.typeName(p.Type.index()),
				Required: p.Flags&flagRequired != 0, ReadOnly: p.Flags&flagReadOnly != 0, WriteOnly: p.Flags&flagWriteOnly != 0,
				Secret: s.secret(p), Description: describe.Short(p.Description, 160)})
			walk(p.Type.index(), path, depth+1, seen)
		}
	}
	walk(s.body, "", 1, map[int]bool{})
	if !s.Writable {
		d.Notes = append(d.Notes, "Azure defines this type and no one can PUT it: StackDNA does not capture it.")
	}
	d.Notes = append(d.Notes, "A restore PUTs the whole body; secret fields are never in a snapshot and come from --values.")
	return d, nil
}

// typeName is a definition entry's kind in plain words.
func (s *Schema) typeName(i int) string {
	e := s.file[i]
	switch e.Kind {
	case "StringType", "StringLiteralType":
		return "string"
	case "IntegerType":
		return "integer"
	case "BooleanType":
		return "boolean"
	case "ArrayType":
		return "array"
	case "ObjectType", "DiscriminatedObjectType":
		return "object"
	case "UnionType":
		return "enum"
	}
	return strings.TrimSuffix(e.Kind, "Type")
}
