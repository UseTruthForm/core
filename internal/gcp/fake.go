package gcp

import (
	"context"
	"fmt"
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
	for _, r := range f.res {
		if !f.Unavailable[r.asset.Type] {
			out = append(out, r.asset)
		}
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
			if strings.HasSuffix(url, "/"+rel) {
				return deepCopy(r.data), nil
			}
		}
		return nil, fmt.Errorf("%s: %w", url, ErrNotFound)
	case "POST":
		return f.create(url, body.(map[string]any))
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
