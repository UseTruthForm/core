package gcp

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// coll is a Discovery collection with the schema its get method returns.
type coll struct {
	path    string
	schema  string
	methods map[string]*Method
}

func (d *Doc) collections() []coll {
	var out []coll
	var walk func(prefix string, cs map[string]*Collection)
	walk = func(prefix string, cs map[string]*Collection) {
		for _, name := range sortedKeys(cs) {
			c := cs[name]
			path := join(prefix, name)
			schema := ""
			if g := c.Methods["get"]; g != nil && g.Response != nil {
				schema = g.Response.Ref
			}
			out = append(out, coll{path: path, schema: schema, methods: c.Methods})
			walk(path, c.Resources)
		}
	}
	walk("", d.Resources)
	return out
}

func (d *Doc) collectionMethods(path string) map[string]*Method {
	for _, c := range d.collections() {
		if c.path == path {
			return c.methods
		}
	}
	return nil
}

func (ds *Docs) loaded() []*Doc {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	var out []*Doc
	for _, k := range sortedKeys(ds.cache) {
		out = append(out, ds.cache[k])
	}
	return out
}

// wrap turns a captured spec into a create request, as the type's create
// method declares it:
//
//   - the request is the resource itself (logging metrics): the spec is the
//     body, and an ID query parameter (AIP-133: ?secretId=) gets the ID;
//   - the request wraps the resource (IAM: CreateServiceAccountRequest
//     holds serviceAccount and accountId): the spec goes in the property
//     that holds the resource, and the wrapper's *Id field gets the ID.
//
// id is the last segment of the resource name, or "" when the server
// assigns it.
func wrap(d *Doc, schema string, m *Method, spec map[string]any, id string) (map[string]any, url.Values, error) {
	q := url.Values{}
	if m.Request == nil {
		return nil, nil, fmt.Errorf("%s has no request body", m.ID)
	}
	// When the ID travels on its own (a *Id query parameter or wrapper
	// field), the resource's name is its identity and must not be sent:
	// IAM answered "Must not specify service_account.name" in the first
	// real drill. When it does not (a log metric), the name is the input.
	if m.Request.Ref == schema {
		body := deepCopy(spec)
		if id != "" {
			for _, p := range sortedKeys(m.Parameters) {
				if m.Parameters[p].Location == "query" && idParam(p) {
					q.Set(p, id)
					delete(body, "name")
				}
			}
		}
		return body, q, nil
	}
	w := d.Schemas[m.Request.Ref]
	if w == nil {
		return nil, nil, fmt.Errorf("%s: request schema %s not in the document", m.ID, m.Request.Ref)
	}
	holder := ""
	for _, k := range sortedKeys(w.Properties) {
		if w.Properties[k].Ref == schema {
			holder = k
		}
	}
	if holder == "" {
		return nil, nil, fmt.Errorf("%s: request %s does not hold a %s", m.ID, m.Request.Ref, schema)
	}
	res := deepCopy(spec)
	body := map[string]any{holder: res}
	if id != "" {
		for _, k := range idFields(w) {
			body[k] = id
			delete(res, "name")
		}
	}
	return body, q, nil
}

// idParam reports a create's resource-ID query parameter (AIP-133:
// secretId, metricId). requestId is not one: it is AIP-155's idempotency
// token, a UUID, which Compute and many AIP APIs take on every write.
// Read as the ID it would have sent the resource's name as the token and
// dropped the name from the body.
func idParam(p string) bool { return strings.HasSuffix(p, "Id") && p != "requestId" }

// unwrap is wrap's inverse, for the fake: the resource body and its ID.
func unwrap(d *Doc, schema string, m *Method, body map[string]any) (map[string]any, string, error) {
	if m.Request != nil && m.Request.Ref == schema {
		id := ""
		if n, _ := body["name"].(string); n != "" && !generatedID(n) {
			id = n[strings.LastIndex(n, "/")+1:]
		}
		return body, id, nil
	}
	w := d.Schemas[m.Request.Ref]
	for _, k := range sortedKeys(w.Properties) {
		if w.Properties[k].Ref == schema {
			res, _ := body[k].(map[string]any)
			if res == nil {
				return nil, "", fmt.Errorf("INVALID_ARGUMENT: %s needs %s", m.Request.Ref, k)
			}
			if _, named := res["name"]; named && len(idFields(w)) > 0 {
				return nil, "", fmt.Errorf("INVALID_ARGUMENT: Must not specify %s.name", k)
			}
			id := ""
			for _, f := range idFields(w) {
				id, _ = body[f].(string)
			}
			if id == "" {
				return nil, "", fmt.Errorf("INVALID_ARGUMENT: %s needs its ID field", m.Request.Ref)
			}
			return res, id, nil
		}
	}
	return nil, "", fmt.Errorf("INVALID_ARGUMENT: %s does not hold a %s", m.Request.Ref, schema)
}

// idFields are a wrapper's string fields that carry the new resource's ID
// (accountId, roleId).
func idFields(w *Schema) []string {
	var out []string
	for _, k := range sortedKeys(w.Properties) {
		if strings.HasSuffix(k, "Id") && w.Properties[k].Type == "string" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// walkStrings calls fn for every string in v and replaces it with the result.
func walkStrings(v any, fn func(string) string) any {
	switch c := v.(type) {
	case map[string]any:
		for k, x := range c {
			c[k] = walkStrings(x, fn)
		}
		return c
	case []any:
		for i, x := range c {
			c[i] = walkStrings(x, fn)
		}
		return c
	case string:
		return fn(c)
	}
	return v
}

// rewriteAll is walkStrings for map keys too.
func rewriteAll(v any, fn func(string) string) any {
	switch c := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(c))
		for k, x := range c {
			out[fn(k)] = rewriteAll(x, fn)
		}
		return out
	case []any:
		for i, x := range c {
			c[i] = rewriteAll(x, fn)
		}
		return c
	case string:
		return fn(c)
	}
	return v
}
