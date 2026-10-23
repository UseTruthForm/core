package gcp

import (
	"context"
	"fmt"
	neturl "net/url"
	"sort"
	"strings"
	"sync"
)

// World is a set of fake projects. A create that carries another project's
// ID is refused, as Google refuses a reference to a project the caller
// cannot see; without that, a restore that forgot to replace the project
// would pass here and fail against Google.
type World struct {
	mu       sync.Mutex
	docs     *Docs
	projects map[string]string // id -> number
	seq      int
}

// NewWorld creates an empty world that serves the documents' types.
func NewWorld(docs *Docs) *World { return &World{docs: docs, projects: map[string]string{}} }

// Fake is one project. It knows no Google type: it reads, creates and
// validates through each type's Discovery document, the same way the real
// adapter drives Google.
type Fake struct {
	w           *World
	id, number  string
	res         map[string]fakeRes // relName -> resource
	Unavailable map[string]bool    // asset types whose API is disabled
	// AfterCreate lets a test add what Google does on create beyond the
	// document (naming an alert policy's conditions). It runs with the
	// world locked and must not call back into the fake.
	AfterCreate func(schema string, stored map[string]any)
	// InventoryName names an asset the way Cloud Asset Inventory does when
	// that differs from the resource's own name (service accounts by their
	// numeric uniqueId).
	InventoryName func(rel string, data map[string]any) string
	// Updates counts applied patches and updates.
	Updates int
}

type fakeRes struct {
	asset Asset
	data  map[string]any
}

// Project returns a new empty project in the world.
func (w *World) Project(id, number string) *Fake {
	w.mu.Lock()
	w.projects[id] = number
	w.mu.Unlock()
	return &Fake{w: w, id: id, number: number, res: map[string]fakeRes{}, Unavailable: map[string]bool{}}
}

func (f *Fake) Project() string                               { return f.id }
func (f *Fake) ProjectNumber(context.Context) (string, error) { return f.number, nil }

// Assets lists in reverse name order: callers must not depend on order.
func (f *Fake) Assets(context.Context) ([]Asset, error) {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	var out []Asset
	for rel, r := range f.res {
		if f.Unavailable[r.asset.Type] {
			continue
		}
		a := r.asset
		if f.InventoryName != nil {
			if n := f.InventoryName(rel, r.data); n != "" {
				a.Name = "//" + strings.SplitN(strings.TrimPrefix(a.Name, "//"), "/", 2)[0] + "/" + n
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Call serves GET by URL and POST through the type's create method.
func (f *Fake) Call(_ context.Context, method, url string, body any) (map[string]any, error) {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	switch method {
	case "GET":
		for rel, r := range f.res {
			alias := ""
			if f.InventoryName != nil {
				alias = f.InventoryName(rel, r.data)
			}
			if strings.HasSuffix(url, "/"+rel) || (alias != "" && strings.HasSuffix(url, "/"+alias)) {
				return deepCopy(r.data), nil
			}
		}
		return nil, fmt.Errorf("%s: %w", url, ErrNotFound)
	case "POST":
		return f.create(url, body.(map[string]any))
	case "PATCH", "PUT":
		return f.update(method, url, body.(map[string]any))
	}
	return nil, fmt.Errorf("fake: unsupported method %s", method)
}

// Seed creates through the same path a restore uses, for test setup.
func (f *Fake) Seed(api, ver, typ, schema, collection, parent string, body map[string]any) (string, error) {
	doc, err := f.w.docs.Doc(docURL(api, ver), "")
	if err != nil {
		return "", err
	}
	m := doc.collectionMethods(collection)["create"]
	if m == nil {
		return "", fmt.Errorf("no create method on %s", collection)
	}
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	out, err := f.createWith(doc, typ, schema, collection, m, parent, body, "")
	if err != nil {
		return "", err
	}
	return out["name"].(string), nil
}

// create finds the create method the URL belongs to, in any loaded
// document, by matching its path against the URL.
func (f *Fake) create(url string, body map[string]any) (map[string]any, error) {
	url, rawQuery, _ := strings.Cut(url, "?")
	queryID := ""
	for _, kv := range strings.Split(rawQuery, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.HasSuffix(k, "Id") {
			queryID = v
		}
	}
	for _, d := range f.w.docs.loaded() {
		for _, c := range d.collections() {
			m := c.methods["create"]
			if m == nil {
				continue
			}
			prefix := d.RootURL + d.ServicePath
			path := strings.TrimPrefix(url, prefix)
			if path == url {
				continue
			}
			tmpl := m.Path
			open, close := strings.Index(tmpl, "{"), strings.Index(tmpl, "}")
			if open < 0 || close < 0 || !strings.HasPrefix(path, tmpl[:open]) || !strings.HasSuffix(path, tmpl[close+1:]) {
				continue
			}
			parent := strings.TrimSuffix(strings.TrimPrefix(path, tmpl[:open]), tmpl[close+1:])
			schema := c.schema
			typ := d.Name + ".googleapis.com/" + schema
			return f.createWith(d, typ, schema, c.path, m, parent, body, queryID)
		}
	}
	return nil, fmt.Errorf("fake: no create method matches %s", url)
}

func (f *Fake) createWith(d *Doc, typ, schema, collection string, m *Method, parent string, body map[string]any, queryID string) (map[string]any, error) {
	res, id, err := unwrap(d, schema, m, body)
	if err != nil {
		return nil, err
	}
	if queryID != "" {
		id = queryID
	}
	for k, p := range d.Schemas[schema].Properties {
		if _, set := res[k]; set && outputOnly(p) && k != "name" {
			return nil, fmt.Errorf("INVALID_ARGUMENT: %s.%s is output only", schema, k)
		}
	}
	var bad error
	walkStrings(deepCopy(res), func(s string) string {
		if bad == nil && strings.Contains(s, "{{stackdna") {
			bad = fmt.Errorf("INVALID_ARGUMENT: unresolved StackDNA reference %q sent to Google", s)
		}
		for other := range f.w.projects {
			if bad == nil && other != f.id && (strings.Contains(s, "projects/"+other+"/") || strings.Contains(s, "@"+other+".")) {
				bad = fmt.Errorf("PERMISSION_DENIED: %q refers to project %s, which this one cannot see", s, other)
			}
		}
		return s
	})
	if bad != nil {
		return nil, bad
	}
	if id == "" {
		f.w.seq++
		id = fmt.Sprintf("%d%06d", 1000+len(f.w.projects), f.w.seq) // server-assigned, numeric
	}
	coll := collection[strings.LastIndex(collection, ".")+1:]
	rel := parent + "/" + coll + "/" + id
	if _, dup := f.res[rel]; dup {
		return nil, fmt.Errorf("ALREADY_EXISTS: %s", rel)
	}
	stored := deepCopy(res)
	stored["name"] = rel
	for k, p := range d.Schemas[schema].Properties {
		if outputOnly(p) && (p.Type == "string" || p.Type == "") && k != "name" {
			f.w.seq++
			stored[k] = fmt.Sprintf("%s-%s-%d", strings.ToLower(k), f.id, f.w.seq)
			if strings.HasSuffix(k, "Id") {
				stored[k] = fmt.Sprintf("1%019d", f.w.seq*7919+len(f.id)) // Google's IDs are numbers
			}
		}
	}
	f.w.seq++
	stored["etag"] = fmt.Sprintf("e%d", f.w.seq)
	if f.AfterCreate != nil {
		f.AfterCreate(schema, stored)
	}
	f.res[rel] = fakeRes{asset: Asset{Name: "//" + d.Name + ".googleapis.com/" + rel, Type: typ,
		DiscoveryURI: docURL(d.Name, d.Version), Version: d.Version, DiscoveryName: schema}, data: stored}
	return deepCopy(stored), nil
}

// update applies a patch (with its mask) or a full update, through the
// method the resource's document declares for it. Masked fields absent
// from the body are cleared, as Google clears them; output-only fields
// are refused, and so are references Google could not resolve.
func (f *Fake) update(method, u string, body map[string]any) (map[string]any, error) {
	path, rawQuery, _ := strings.Cut(u, "?")
	var rel string
	for r := range f.res {
		if strings.HasSuffix(path, "/"+r) {
			rel = r
		}
	}
	if rel == "" {
		return nil, fmt.Errorf("%s: %w", path, ErrNotFound)
	}
	cur := f.res[rel]
	d, err := f.w.docs.Doc(cur.asset.DiscoveryURI, cur.asset.Version)
	if err != nil {
		return nil, err
	}
	schema := cur.asset.DiscoveryName
	var m *Method
	for _, c := range d.collections() {
		for _, k := range []string{"patch", "update"} {
			if x := c.methods[k]; x != nil && m == nil && c.schema == schema && x.HTTPMethod == method {
				m = x
			}
		}
	}
	if m == nil {
		return nil, fmt.Errorf("fake: no %s method for %s", method, schema)
	}
	res, maskStr := body, ""
	if m.Request.Ref != schema {
		w := d.Schemas[m.Request.Ref]
		for _, k := range sortedKeys(w.Properties) {
			if w.Properties[k].Ref == schema {
				res, _ = body[k].(map[string]any)
			}
		}
		if res == nil {
			return nil, fmt.Errorf("INVALID_ARGUMENT: %s holds no %s", m.Request.Ref, schema)
		}
		maskStr, _ = body["updateMask"].(string)
	}
	if q, err := neturl.ParseQuery(rawQuery); err == nil && q.Get("updateMask") != "" {
		maskStr = q.Get("updateMask")
	}
	// A method that takes a mask gets one: without it a patch would be
	// read as "every field", which is not what StackDNA means to send.
	_, inQuery := m.Parameters["updateMask"]
	_, inBody := d.Schemas[m.Request.Ref].Properties["updateMask"]
	if (inQuery || inBody) && maskStr == "" {
		return nil, fmt.Errorf("INVALID_ARGUMENT: %s needs an updateMask", m.ID)
	}
	props := d.Schemas[schema].Properties
	for k := range res {
		if p, ok := props[k]; !ok {
			return nil, fmt.Errorf("INVALID_ARGUMENT: %s has no field %s", schema, k)
		} else if outputOnly(p) && k != "name" {
			return nil, fmt.Errorf("INVALID_ARGUMENT: %s.%s is output only", schema, k)
		}
	}
	var bad error
	walkStrings(deepCopy(res), func(s string) string {
		if bad == nil && strings.Contains(s, "{{stackdna") {
			bad = fmt.Errorf("INVALID_ARGUMENT: unresolved StackDNA reference %q sent to Google", s)
		}
		return s
	})
	if bad != nil {
		return nil, bad
	}
	next := deepCopy(cur.data)
	if maskStr != "" {
		for _, k := range strings.Split(maskStr, ",") {
			if v, ok := res[k]; ok {
				next[k] = v
			} else {
				delete(next, k)
			}
		}
	} else {
		for k, p := range props {
			if outputOnly(p) || k == "name" {
				continue
			}
			if v, ok := res[k]; ok {
				next[k] = v
			} else {
				delete(next, k)
			}
		}
	}
	f.w.seq++
	next["etag"] = fmt.Sprintf("e%d", f.w.seq)
	f.res[rel] = fakeRes{asset: cur.asset, data: next}
	f.Updates++
	return deepCopy(next), nil
}

// Count is the number of resources held.
func (f *Fake) Count() int {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	return len(f.res)
}

// Names lists the relative names held.
func (f *Fake) Names() []string {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	return sortedKeys(f.res)
}

var _ API = (*Fake)(nil)
