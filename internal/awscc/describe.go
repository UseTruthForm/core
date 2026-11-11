package awscc

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/describe"
)

// Names lists the registry's type names, sorted.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.Types))
	for n := range r.Types {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Describe reports a type from its registry schema: every field path, with
// the schema's own markings (required, readOnlyProperties,
// writeOnlyProperties, createOnlyProperties), and the CloudFormation
// reference page for it.
func (r *Registry) Describe(name string) (describe.Type, error) {
	t := r.Types[name]
	if t == nil {
		return describe.Type{}, fmt.Errorf("%s is not in the registry", name)
	}
	var raw struct {
		DocumentationURL string `json:"documentationUrl"`
		SourceURL        string `json:"sourceUrl"`
	}
	_ = json.Unmarshal(t.Raw, &raw)
	d := describe.Type{Platform: "aws", Name: name}
	// The reference page's address follows the type name; the schema's
	// own documentationUrl is rare (19 of 1,498 in us-east-2).
	d.Docs = append(d.Docs, "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-"+
		strings.ToLower(t.Service())+"-"+strings.ToLower(t.Short())+".html")
	for _, u := range []string{raw.DocumentationURL, raw.SourceURL} {
		if u != "" && u != d.Docs[0] {
			d.Docs = append(d.Docs, u)
		}
	}
	marked := func(ptrs []string, path string) bool {
		p := "/properties/" + strings.ReplaceAll(strings.ReplaceAll(path, "[]", "/*"), ".", "/")
		for _, x := range ptrs {
			if p == x || strings.HasPrefix(p, x+"/") {
				return true
			}
		}
		return false
	}
	for _, path := range t.Fields() {
		f := describe.Field{Path: path,
			ReadOnly: marked(t.ReadOnly, path), WriteOnly: marked(t.WriteOnly, path), CreateOnly: marked(t.CreateOnly, path)}
		if !strings.ContainsAny(path, ".[*") {
			f.Required = hasString(t.Required, path)
			p, _ := t.Properties[path].(map[string]any)
			p, _ = derefCFN(p, t.Definitions)
			f.Type, _ = p["type"].(string)
			f.Description = describe.Short(fmt.Sprint(p["description"]), 160)
			if f.Description == "<nil>" {
				f.Description = ""
			}
		}
		d.Fields = append(d.Fields, f)
	}
	if !t.Handlers["create"] {
		d.Notes = append(d.Notes, "Cloud Control cannot create this type: Truthform captures it but cannot restore it.")
	}
	if !t.Capturable() {
		d.Notes = append(d.Notes, "Cloud Control cannot list or read this type: Truthform cannot capture it.")
	}
	if len(t.CreateOnly) > 0 {
		d.Notes = append(d.Notes, "createOnly fields are fixed at creation: restore --update refuses to change them rather than replace the resource.")
	}
	return d, nil
}
