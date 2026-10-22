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
	byPath  map[string]map[string]any   // item path (its Get or Update path) -> item
	seq     int
	// onCreate lets a test add what the provider does beyond the
	// description (GitHub creates default labels with a repository).
	onCreate func(f *fake, kind string, item map[string]any)
	// refuse answers GET of paths ending in a key with 403 and the message,
	// as GitHub refuses features the plan lacks.
	refuse map[string]string
}

func newFake(t *testing.T, p Provider, spec *Spec, account string) *fake {
	f := &fake{p: p, spec: spec, account: account, colls: map[string][]map[string]any{}, byPath: map[string]map[string]any{}}
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
				f.page(w, r, f.colls[path])
				return
			}
		case "POST":
			if ps, ok := params(col.Create, path); ok {
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
			for k, v := range body {
				it[k] = v
			}
			f.reply(w, 200, f.masked(it), nil)
			return
		}
	}
	f.fail(w, 404, "Not Found: "+r.Method+" "+path)
}

func (f *fake) create(w http.ResponseWriter, col *Collection, path string, ps map[string]string, body map[string]any) {
	accepted := f.spec.RequestFields(col.Create, "POST")
	for k := range body {
		if accepted == nil || accepted.Children[k] == nil {
			f.fail(w, 422, fmt.Sprintf("%s does not accept %q", col.Create, k))
			return
		}
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

// masked returns an item with secrets hidden, as GitHub returns a
// webhook's config.secret.
func (f *fake) masked(it map[string]any) map[string]any {
	b, _ := json.Marshal(it)
	var c map[string]any
	_ = json.Unmarshal(b, &c)
	if cfg, ok := c["config"].(map[string]any); ok {
		if _, has := cfg["secret"]; has {
			cfg["secret"] = "********"
		}
	}
	return c
}

func (f *fake) page(w http.ResponseWriter, r *http.Request, items []map[string]any) {
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
	f.reply(w, 200, out, map[string]any{"page": pg, "per_page": size, "total_pages": total, "count": len(out)}, h)
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
