package saas

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// fake is one account of a provider, served over HTTP from the
// descriptor and the OpenAPI description: it knows no provider by code.
// It routes by the description's path templates, refuses body fields no
// write accepts, adds the fields a server computes (id, created_at,
// stargazers_count), returns secrets masked, pages two at a time, wraps
// responses in the provider's envelope, and refuses any body that names a
// different account.
type fake struct {
	p       Provider
	spec    *Spec
	account string
	others  []string // accounts this one must never see in a body
	srv     *httptest.Server
	mu      sync.Mutex
	colls   map[string][]map[string]any // concrete collection path -> items
	single  map[string]map[string]any   // singleton path -> settings
	byPath  map[string]map[string]any   // item path (its Get or Update path) -> item
	seq     int
	// onCreate lets a test add what the provider does beyond the
	// description (GitHub creates default labels with a repository).
	onCreate func(f *fake, kind string, item map[string]any)
	// refuse answers GET of paths ending in a key with 403 and the message,
	// as GitHub refuses features the plan lacks.
	refuse map[string]string
	// writes counts every request that is not a GET, so a test can prove
	// a restore sent nothing.
	writes int
}

func newFake(t *testing.T, p Provider, spec *Spec, account string) *fake {
	f := &fake{p: p, spec: spec, account: account, colls: map[string][]map[string]any{}, byPath: map[string]map[string]any{}, single: map[string]map[string]any{}}
	// The fake serves the collections a client would use, derived ones
	// included.
	f.p = NewClient(p, spec, account, "", false).P
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// params matches a path against a template.
func params(tmpl, path string) (map[string]string, bool) {
	re := regexp.MustCompile("^" + paramRE.ReplaceAllStringFunc(tmpl, func(m string) string {
		return `(?P<` + m[1:len(m)-1] + `>[^/]+)`
	}) + "$")
	m := re.FindStringSubmatch(path)
	if m == nil {
		return nil, false
	}
	out := map[string]string{}
	for i, n := range re.SubexpNames() {
		if n != "" {
			out[n] = m[i]
		}
	}
	return out, true
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	if r.Method != "GET" {
		f.writes++
	}
	var body map[string]any
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 {
			if err := json.Unmarshal(b, &body); err != nil {
				f.fail(w, 400, "bad JSON")
				return
			}
		}
	}
	for suffix, msg := range f.refuse {
		if r.Method == "GET" && strings.HasSuffix(path, suffix) {
			f.fail(w, 403, msg)
			return
		}
	}
	for i := range f.p.Collections {
		col := &f.p.Collections[i]
		switch r.Method {
		case "GET":
			if _, ok := params(col.List, path); ok {
				if col.Singleton {
					v := f.single[path]
					if v == nil {
						v = map[string]any{}
					}
					f.reply(w, 200, v, nil)
					return
				}
				f.page(w, r, f.colls[path], col.Array)
				return
			}
		case "POST", "PUT":
			if ps, ok := params(col.Create, path); ok && r.Method == col.createMethod() {
				if col.Singleton {
					if !f.accepts(w, col, body) {
						return
					}
					f.single[path] = body
					w.WriteHeader(204)
					return
				}
				if col.createMethod() == "PUT" {
					// PUT .../{name}: the item lives in the list one level up,
					// and the path names it.
					list := path[:strings.LastIndex(path, "/")]
					name := path[strings.LastIndex(path, "/")+1:]
					if body == nil {
						body = map[string]any{}
					}
					for _, it := range f.colls[list] {
						if namesOf(col, it) == name {
							for k, v := range body {
								it[k] = v
							}
							f.reply(w, 200, f.masked(it), nil)
							return
						}
					}
					if !f.accepts(w, col, body) {
						return
					}
					body[col.Name[0]] = name
					f.seq++
					it := map[string]any{"id": float64(f.seq), "created_at": "2026-10-22T00:00:00Z"}
					for k, v := range body {
						it[k] = v
					}
					f.colls[list] = append(f.colls[list], it)
					f.byPath[path] = it
					f.reply(w, 201, f.masked(it), nil)
					return
				}
				f.create(w, col, path, ps, body)
				return
			}
		}
	}
	if it, ok := f.byPath[path]; ok {
		switch r.Method {
		case "GET":
			f.reply(w, 200, f.masked(it), nil)
			return
		case "PATCH":
			// Only what the update operation accepts, as the API refuses
			// the rest.
			for i := range f.p.Collections {
				col := &f.p.Collections[i]
				if _, ok := params(col.Update, path); !ok || col.Update == "" {
					continue
				}
				accepted := f.spec.RequestFields(col.Update, col.updateMethod())
				for k := range body {
					if accepted == nil || (accepted.Children[k] == nil && !accepted.Any) {
						f.fail(w, 422, k+" is not a field of this update")
						return
					}
				}
			}
			for k, v := range body {
				it[k] = v
			}
			f.reply(w, 200, f.masked(it), nil)
			return
		}
	}
	f.fail(w, 404, "Not Found: "+r.Method+" "+path)
}

// accepts refuses a body with a field the write does not define or
// without one it requires.
func (f *fake) accepts(w http.ResponseWriter, col *Collection, body map[string]any) bool {
	accepted := f.spec.RequestFields(col.Create, col.createMethod())
	for _, r := range f.spec.Required(col.Create, col.createMethod()) {
		if _, ok := body[r]; !ok {
			f.fail(w, 422, fmt.Sprintf("%s requires %q", col.Create, r))
			return false
		}
	}
	for k := range body {
		if accepted == nil || (accepted.Children[k] == nil && !accepted.Any) {
			f.fail(w, 422, fmt.Sprintf("%s does not accept %q", col.Create, k))
			return false
		}
	}
	return true
}

func (f *fake) create(w http.ResponseWriter, col *Collection, path string, ps map[string]string, body map[string]any) {
	if !f.accepts(w, col, body) {
		return
	}
	raw, _ := json.Marshal(body)
	// A reference to another account (an exact value, a path or URL
	// segment) is refused; the name appearing in prose is not a reference.
	var foreign string
	rewrite(body, func(v string) string {
		for _, o := range f.others {
			if v == o || regexp.MustCompile(`(^|/)`+regexp.QuoteMeta(o)+`(/|$)`).MatchString(v) {
				foreign = o
			}
		}
		return v
	})
	if foreign != "" {
		f.fail(w, 403, fmt.Sprintf("body refers to account %s, which this one cannot see", foreign))
		return
	}
	if strings.Contains(string(raw), "{{stackdna") {
		f.fail(w, 422, "unresolved StackDNA token sent to the provider")
		return
	}
	for _, it := range f.colls[path] {
		if namesOf(col, it) == namesOf(col, body) {
			f.fail(w, 422, "already exists: "+namesOf(col, body))
			return
		}
	}
	f.seq++
	it := map[string]any{}
	for k, v := range body {
		it[k] = v
	}
	// What a server computes; a capture must drop all of it.
	it["id"] = float64(f.seq)
	it["node_id"] = fmt.Sprintf("N_%d", f.seq)
	it["created_at"] = "2026-10-22T00:00:00Z"
	it["url"] = f.srv.URL + path + fmt.Sprint("/", f.seq)
	f.colls[path] = append(f.colls[path], it)
	for _, tmpl := range []string{col.Get, col.Update} {
		if tmpl == "" {
			continue
		}
		vals := map[string]string{}
		for k, v := range ps {
			vals[k] = v
		}
		ip := paramRE.ReplaceAllStringFunc(tmpl, func(m string) string {
			name := m[1 : len(m)-1]
			src := col.Bind[name]
			switch {
			case src == "account":
				return f.account
			case strings.HasPrefix(src, "item:"):
				return stringOf(field(it, src[5:]))
			}
			return vals[name]
		})
		f.byPath[ip] = it
	}
	if f.onCreate != nil {
		f.onCreate(f, col.Kind, it)
	}
	f.reply(w, 201, f.masked(it), nil)
}

func namesOf(col *Collection, it map[string]any) string {
	var n []string
	for _, k := range col.Name {
		n = append(n, stringOf(field(it, k)))
	}
	return strings.Join(n, " ")
}

// masked returns an item as the API would: only fields its response
// schema has (a secret's encrypted_value is accepted on write and never
// returned), and secrets masked, as GitHub returns a webhook's
// config.secret.
func (f *fake) masked(it map[string]any) map[string]any {
	b, _ := json.Marshal(it)
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	if rf := f.responseFields(it); rf != nil {
		for k := range c {
			if rf.Children[k] == nil && !rf.Any {
				delete(c, k)
			}
		}
	}
	if cfg, ok := c["config"].(map[string]any); ok {
		if _, has := cfg["secret"]; has {
			cfg["secret"] = "********"
		}
	}
	return c
}

// responseFields is the item schema of the collection an item belongs to,
// inside the provider's envelope and the list's array.
func (f *fake) responseFields(it map[string]any) *Fields {
	for i := range f.p.Collections {
		col := &f.p.Collections[i]
		for path, items := range f.colls {
			if _, ok := params(col.List, path); !ok {
				continue
			}
			for _, x := range items {
				if fmt.Sprint(x["id"]) != fmt.Sprint(it["id"]) || namesOf(col, x) != namesOf(col, it) {
					continue
				}
				list := col.Get == ""
				src := col.Get
				if list {
					src = col.List
				}
				fs := f.spec.fields(f.spec.ResponseSchema(src, "get"), 0)
				if f.p.Envelope != "" && fs.Children[f.p.Envelope] != nil {
					fs = fs.Children[f.p.Envelope]
				}
				if list {
					if col.Array != "" && fs.Children[col.Array] != nil {
						fs = fs.Children[col.Array]
					}
					fs = fs.Items
				}
				return fs
			}
		}
	}
	return nil
}

func (f *fake) page(w http.ResponseWriter, r *http.Request, items []map[string]any, array string) {
	const size = 2
	pg := 1
	fmt.Sscanf(r.URL.Query().Get("page"), "%d", &pg)
	total := (len(items) + size - 1) / size
	if total == 0 {
		total = 1
	}
	lo, hi := (pg-1)*size, pg*size
	if lo > len(items) {
		lo = len(items)
	}
	if hi > len(items) {
		hi = len(items)
	}
	var out []any
	for _, it := range items[lo:hi] {
		out = append(out, f.masked(it))
	}
	if out == nil {
		out = []any{}
	}
	h := map[string]string{}
	if f.p.Paging == "link" && pg < total {
		q := r.URL.Query()
		q.Set("page", fmt.Sprint(pg+1))
		h["Link"] = fmt.Sprintf(`<%s%s?%s>; rel="next"`, f.srv.URL, r.URL.Path, q.Encode())
	}
	var v any = out
	if array != "" {
		v = map[string]any{"total_count": len(items), array: out}
	}
	f.reply(w, 200, v, map[string]any{"page": pg, "per_page": size, "total_pages": total, "count": len(out)}, h)
}

func (f *fake) reply(w http.ResponseWriter, code int, v any, info map[string]any, headers ...map[string]string) {
	for _, h := range headers {
		for k, x := range h {
			w.Header().Set(k, x)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if f.p.Envelope != "" {
		env := map[string]any{"success": true, "errors": []any{}, "messages": []any{}, f.p.Envelope: v}
		if info != nil {
			env["result_info"] = info
		}
		v = env
	}
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fake) fail(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	if f.p.Envelope != "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"message": msg}}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"message": msg})
}

// client points a provider at the fake.
func (f *fake) client(readOnly bool) *Client {
	p := f.p
	p.Base = f.srv.URL
	return NewClient(p, f.spec, f.account, "test-token", readOnly)
}

// seed creates an item through the fake's own API, as a person would.
func (f *fake) seed(t *testing.T, path string, body map[string]any) map[string]any {
	t.Helper()
	c := f.client(false)
	v, _, err := c.do(t.Context(), "POST", path, body)
	if err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
	m, _ := v.(map[string]any)
	return m
}
