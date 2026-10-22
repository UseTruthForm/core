// Package describe is what StackDNA knows about a resource type, in one
// shape for every platform: its fields, what each one is (required, set by
// the platform, never returned, fixed at creation, secret), and where the
// platform documents it. It is read from the same schemas capture and
// restore are driven by, so what an agent is told is what StackDNA does.
package describe

import "strings"

// Field is one field path (properties.addressSpace.addressPrefixes[],
// SecurityGroupIngress[].CidrIp).
type Field struct {
	Path string `json:"path"`
	Type string `json:"type,omitempty"`
	// Required on create, within its parent object: a nested field is
	// required only when its parent is given.
	Required bool `json:"required,omitempty"`
	// ReadOnly is set by the platform: never sent, kept as status.
	ReadOnly bool `json:"readOnly,omitempty"`
	// WriteOnly is accepted and never returned, so no snapshot holds it.
	WriteOnly bool `json:"writeOnly,omitempty"`
	// CreateOnly is fixed at creation; changing it replaces the resource,
	// which StackDNA refuses to do.
	CreateOnly bool `json:"createOnly,omitempty"`
	// Secret is never written to a snapshot; restore takes it from --values.
	Secret      bool   `json:"secret,omitempty"`
	Description string `json:"description,omitempty"`
}

// Type is one resource type.
type Type struct {
	Platform string   `json:"platform"`
	Name     string   `json:"name"`
	Version  string   `json:"version,omitempty"`
	Docs     []string `json:"docs,omitempty"`
	Notes    []string `json:"notes,omitempty"`
	Fields   []Field  `json:"fields"`
}

// Short trims a description to its first sentence, at most n characters:
// a type can have hundreds of fields, and an agent needs the gist, with
// the docs link for the rest.
func Short(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i > 0 && i < n {
		s = s[:i+1]
	}
	if len(s) > n {
		s = s[:n-3] + "..."
	}
	return s
}

// Depth is how many levels a field path goes down ("a.b[].c" is 3).
func Depth(path string) int {
	return strings.Count(strings.ReplaceAll(path, "[]", ""), ".") + 1
}
