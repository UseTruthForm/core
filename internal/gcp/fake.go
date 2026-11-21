package gcp

import (
	"context"
	"fmt"
	neturl "net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
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
	// WriteDelay makes each write take this long, outside the lock, so
	// writes running at once overlap as Google's long-running ones do.
	WriteDelay time.Duration
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
	if method != "GET" {
		time.Sleep(f.WriteDelay)
	}
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
	case "PUT":
		if out, ok, err := f.createAtName(url, body.(map[string]any)); ok {
			return out, err
		}
		return f.update(method, url, body.(map[string]any))
	case "PATCH":
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
	m := createMethod(doc.collectionMethods(collection))
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
	query, _ := neturl.ParseQuery(rawQuery)
	for _, kv := range strings.Split(rawQuery, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok && idParam(k) {
			queryID = v
		}
	}
	for _, d := range f.w.docs.loaded() {
		for _, c := range d.collections() {
			m := createMethod(c.methods)
			if m == nil {
				continue
			}
			prefix := d.RootURL + d.ServicePath
			path := strings.TrimPrefix(url, prefix)
			if path == url {
				continue
			}
			parent, ok := createParent(m.Path, path)
			if !ok {
				continue
			}
			// A create that names no parent takes the project as a query
			// parameter, and Google refuses one without it.
			if p, ok := m.Parameters["project"]; ok && p.Location == "query" && p.Required && query.Get("project") != f.id {
				return nil, fmt.Errorf("INVALID_ARGUMENT: %s needs project=%s, got %q", m.ID, f.id, query.Get("project"))
			}
			schema := c.schema
			typ := d.Name + ".googleapis.com/" + schema
			return f.createWith(d, typ, schema, c.path, m, parent, body, queryID)
		}
	}
	return nil, fmt.Errorf("fake: no create method matches %s", url)
}

// createAtName is a PUT create at the resource's own name (Pub/Sub's
// PUT v1/{+name}), when nothing is there yet and a document declares one
// whose path matches; ok is false otherwise, and the PUT is an update.
func (f *Fake) createAtName(url string, body map[string]any) (map[string]any, bool, error) {
	for r := range f.res {
		if strings.HasSuffix(url, "/"+r) {
			return nil, false, nil
		}
	}
	for _, d := range f.w.docs.loaded() {
		prefix := d.RootURL + d.ServicePath
		path := strings.TrimPrefix(url, prefix)
		if path == url {
			continue
		}
		for _, c := range d.collections() {
			m := c.methods["create"]
			if m == nil || m.HTTPMethod != "PUT" {
				continue
			}
			lead, _, _ := strings.Cut(m.Path, "{")
			rel := strings.TrimPrefix(path, lead)
			if rel == path || !matchesName(m, rel) {
				continue
			}
			coll := c.path[strings.LastIndex(c.path, ".")+1:]
			parent, id, ok := strings.Cut(rel, "/"+coll+"/")
			if !ok {
				continue
			}
			if n, _ := body["name"].(string); n != "" && n != rel {
				return nil, true, fmt.Errorf("INVALID_ARGUMENT: the name in the body, %s, is not %s", n, rel)
			}
			out, err := f.createWith(d, d.Name+".googleapis.com/"+c.schema, c.schema, c.path, m, parent, body, id)
			return out, true, err
		}
	}
	return nil, false, nil
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
		if bad == nil && strings.Contains(s, "{{truthform") {
			bad = fmt.Errorf("INVALID_ARGUMENT: unresolved TruthForm reference %q sent to Google", s)
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
	if ref := f.missingRef(res); ref != "" {
		return nil, fmt.Errorf("NOT_FOUND: The resource '%s' was not found", ref)
	}
	if id == "" {
		f.w.seq++
		id = fmt.Sprintf("%d%06d", 1000+len(f.w.projects), f.w.seq) // server-assigned, numeric
	}
	coll := collection[strings.LastIndex(collection, ".")+1:]
	rel := parent + "/" + coll + "/" + id
	if parent == "" {
		rel = id // a resource with no parent in its name (a Cloud Storage bucket)
	}
	if _, dup := f.res[rel]; dup {
		return nil, fmt.Errorf("ALREADY_EXISTS: %s", rel)
	}
	stored := deepCopy(res)
	stored["name"] = rel
	// Compute's resources, created through a template that names each
	// segment, carry their short name and a selfLink, as Google returns
	// them; storing the full name here hid an update that sent one.
	if !strings.Contains(m.Path, "{+") {
		stored["name"] = id
	}
	for k, p := range d.Schemas[schema].Properties {
		if outputOnly(p) && (p.Type == "string" || p.Type == "") && k != "name" {
			f.w.seq++
			stored[k] = fmt.Sprintf("%s-%s-%d", strings.ToLower(k), f.id, f.w.seq)
			if strings.HasSuffix(k, "Id") {
				stored[k] = fmt.Sprintf("1%019d", f.w.seq*7919+len(f.id)) // Google's IDs are numbers
			}
		}
	}
	if _, ok := d.Schemas[schema].Properties["selfLink"]; ok {
		stored["selfLink"] = d.RootURL + d.ServicePath + rel
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
	// read as "every field", which is not what TruthForm means to send.
	_, inQuery := m.Parameters["updateMask"]
	_, inBody := d.Schemas[m.Request.Ref].Properties["updateMask"]
	if (inQuery || inBody) && maskStr == "" {
		return nil, fmt.Errorf("INVALID_ARGUMENT: %s needs an updateMask", m.ID)
	}
	props := d.Schemas[schema].Properties
	if n, ok := res["name"].(string); ok && n != cur.data["name"] {
		return nil, fmt.Errorf("INVALID_ARGUMENT: name %q does not match the resource's %q", n, cur.data["name"])
	}
	for k := range res {
		if p, ok := props[k]; !ok {
			return nil, fmt.Errorf("INVALID_ARGUMENT: %s has no field %s", schema, k)
		} else if outputOnly(p) && k != "name" {
			return nil, fmt.Errorf("INVALID_ARGUMENT: %s.%s is output only", schema, k)
		}
	}
	var bad error
	walkStrings(deepCopy(res), func(s string) string {
		if bad == nil && strings.Contains(s, "{{truthform") {
			bad = fmt.Errorf("INVALID_ARGUMENT: unresolved TruthForm reference %q sent to Google", s)
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
	} else if method == "PATCH" {
		// No mask: a JSON merge patch. What the body leaves out is kept;
		// null clears.
		for k, v := range res {
			if k == "name" {
				continue
			}
			if v == nil {
				delete(next, k)
			} else {
				next[k] = v
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

// createMethod is a collection's create, or Compute's insert.
func createMethod(ms map[string]*Method) *Method {
	if m := ms["create"]; m != nil {
		return m
	}
	if m := ms["insert"]; m != nil && m.HTTPMethod == "POST" {
		return m
	}
	return nil
}

// createParent matches a create URL's path against its method's template
// and returns the parent the new resource goes under: what fills a single
// {+parent}, or, for a template naming each segment (Compute's
// projects/{project}/global/networks), everything before the collection.
func createParent(tmpl, path string) (string, bool) {
	var b strings.Builder
	last := 0
	for _, loc := range pathParamRE.FindAllStringSubmatchIndex(tmpl, -1) {
		b.WriteString(regexp.QuoteMeta(tmpl[last:loc[0]]))
		if strings.HasPrefix(tmpl[loc[0]:], "{+") {
			b.WriteString("(.+)")
		} else {
			b.WriteString("([^/]+)")
		}
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(tmpl[last:]))
	re := regexp.MustCompile("^" + b.String() + "$")
	m := re.FindStringSubmatch(path)
	if m == nil {
		return "", false
	}
	if strings.Contains(tmpl, "{+") {
		return m[1], true
	}
	if !strings.Contains(path, "/") {
		return "", true // the collection alone (Cloud Storage's b): no parent
	}
	return path[:strings.LastIndex(path, "/")], true
}

// missingRef finds a reference to a resource of this project that the
// fake serves a collection for and does not hold: Google refuses a firewall
// whose network does not exist yet, so restore order matters here too.
func (f *Fake) missingRef(body map[string]any) string {
	served := map[string]bool{}
	for _, d := range f.w.docs.loaded() {
		for _, c := range d.collections() {
			served[collLast(c.path)] = true
		}
	}
	missing := ""
	refs := deepCopy(body)
	delete(refs, "name") // its own name, not a reference
	walkStrings(refs, func(s string) string {
		i := strings.Index(s, "projects/"+f.id+"/")
		if i < 0 || missing != "" {
			return s
		}
		rel := s[i:]
		parts := strings.Split(rel, "/")
		if len(parts) >= 4 && served[parts[len(parts)-2]] {
			if _, ok := f.res[rel]; !ok {
				missing = rel
			}
		}
		return s
	})
	return missing
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
