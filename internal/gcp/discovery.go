// Package gcp captures and restores Google Cloud resources, driven by the
// Discovery documents Google publishes for every API.
//
// As with AWS and Azure, no Google type has code here. Cloud Asset
// Inventory says what exists and names each resource's Discovery document
// and schema. That document says which fields are output-only, gives every
// field path for schema-diff, and declares how to read and create the
// resource: the get method, the create method, its parent parameter, and
// whether the body is the resource itself or a request that wraps it.
package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Schema is one entry of a Discovery document's schemas (or an inline
// property schema).
type Schema struct {
	ID                   string             `json:"id"`
	Type                 string             `json:"type"`
	Ref                  string             `json:"$ref"`
	Description          string             `json:"description"`
	ReadOnly             bool               `json:"readOnly"`
	Properties           map[string]*Schema `json:"properties"`
	Items                *Schema            `json:"items"`
	AdditionalProperties *Schema            `json:"additionalProperties"`
}

// Method is a Discovery method.
type Method struct {
	ID         string               `json:"id"`
	Path       string               `json:"path"`
	HTTPMethod string               `json:"httpMethod"`
	Parameters map[string]Parameter `json:"parameters"`
	Request    *Schema              `json:"request"`
	Response   *Schema              `json:"response"`
}

// Parameter is a method parameter.
type Parameter struct {
	Location string `json:"location"`
	Required bool   `json:"required"`
	Pattern  string `json:"pattern"`
	Type     string `json:"type"`
}

// Collection is a Discovery resource: its methods and nested collections.
type Collection struct {
	Methods   map[string]*Method     `json:"methods"`
	Resources map[string]*Collection `json:"resources"`
}

// Doc is a Discovery document.
type Doc struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	RootURL     string                 `json:"rootUrl"`
	ServicePath string                 `json:"servicePath"`
	Schemas     map[string]*Schema     `json:"schemas"`
	Resources   map[string]*Collection `json:"resources"`
	Digest      string                 `json:"-"`
}

// auditTypes are schemas a service uses only for records it writes itself.
// Cloud Monitoring's MutationRecord (who changed a channel or policy, and
// when) is flagged output-only nowhere; a restored notification channel
// diffed on creationRecord.mutateTime and mutationRecords in the first real
// GCP drill (2026-10-21).
var auditTypes = map[string]bool{"MutationRecord": true}

// outputOnly reports a field the server sets. Most documents flag it
// (readOnly); some only say so in prose, which is the convention Google's
// API guidelines require ("Output only." / "[Output Only]").
func outputOnly(s *Schema) bool {
	if s.ReadOnly || auditTypes[s.Ref] || (s.Items != nil && auditTypes[s.Items.Ref]) {
		return true
	}
	d := strings.TrimSpace(s.Description)
	return strings.HasPrefix(d, "Output only") || strings.HasPrefix(d, "[Output Only]") || strings.HasPrefix(d, "Output Only")
}

func (d *Doc) resolve(s *Schema) *Schema {
	for i := 0; s != nil && s.Ref != "" && i < 8; i++ {
		s = d.Schemas[s.Ref]
	}
	return s
}

// Docs loads Discovery documents by URI, from a directory of fixtures or
// from Google with a cache.
type Docs struct {
	load  func(api, ver string) ([]byte, error)
	mu    sync.Mutex
	cache map[string]*Doc
}

// Google serves documents in two URI styles, and Cloud Asset Inventory
// reports either, with the version separately:
//
//	https://www.googleapis.com/discovery/v1/apis/compute/v1/rest
//	https://iam.googleapis.com/$discovery/rest   (version v1)
//
// docKey reduces both to the API and version; docFile names the cache or
// fixture file after them (iam_v1.json).
func docKey(uri, version string) (api, ver string, err error) {
	if i := strings.Index(uri, "/discovery/v1/apis/"); i >= 0 {
		p := strings.Split(strings.TrimSuffix(uri[i+len("/discovery/v1/apis/"):], "/rest"), "/")
		if len(p) == 2 {
			return p[0], p[1], nil
		}
	}
	if strings.Contains(uri, "/$discovery/rest") && version != "" {
		host := strings.TrimPrefix(uri, "https://")
		return host[:strings.Index(host, ".")], version, nil
	}
	return "", "", fmt.Errorf("not a Google Discovery URI: %q (version %q)", uri, version)
}

func docFile(api, ver string) string { return api + "_" + ver + ".json" }

// docURL is where a document is fetched from.
func docURL(api, ver string) string {
	return "https://www.googleapis.com/discovery/v1/apis/" + api + "/" + ver + "/rest"
}

// LoadDocs reads documents from dir (fixtures named like iam_v1.json).
func LoadDocs(dir string) *Docs {
	return &Docs{cache: map[string]*Doc{}, load: func(api, ver string) ([]byte, error) {
		return os.ReadFile(filepath.Join(dir, docFile(api, ver)))
	}}
}

// FetchDocs downloads documents from Google, caching each for maxAge.
func FetchDocs(cacheDir string, maxAge time.Duration) *Docs {
	return &Docs{cache: map[string]*Doc{}, load: func(api, ver string) ([]byte, error) {
		path := filepath.Join(cacheDir, docFile(api, ver))
		if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) < maxAge {
			return os.ReadFile(path)
		}
		u := docURL(api, ver)
		resp, err := http.Get(u) //nolint:gosec // fixed googleapis.com host; api and version come from Cloud Asset Inventory
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", u, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("download %s: HTTP %d", u, resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, err
		}
		return b, os.WriteFile(path, b, 0o644)
	}}
}

// Doc returns the document an asset names.
func (ds *Docs) Doc(uri, version string) (*Doc, error) {
	api, ver, err := docKey(uri, version)
	if err != nil {
		return nil, err
	}
	ds.mu.Lock()
	defer ds.mu.Unlock()
	key := api + "/" + ver
	if d, ok := ds.cache[key]; ok {
		return d, nil
	}
	b, err := ds.load(api, ver)
	if err != nil {
		return nil, err
	}
	var d Doc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parse %s: %w", uri, err)
	}
	h := sha256.Sum256(b)
	d.Digest = "sha256:" + hex.EncodeToString(h[:])
	ds.cache[key] = &d
	return &d, nil
}

// Kind is how a resource is read and created, found in a document.
type Kind struct {
	Doc    *Doc
	Schema string // the resource's schema name (ServiceAccount)
	Get    *Method
	Create *Method
	// Collection is the dotted path of the Discovery resource (projects.serviceAccounts).
	Collection string
}

// Kind finds the collection whose get method returns the schema and whose
// name pattern matches the resource's relative name. Several collections
// can return one schema (projects.x and organizations.x); the pattern picks
// the right one.
func (d *Doc) Kind(schema, relName string) (*Kind, error) {
	var found []*Kind
	var walk func(prefix string, cs map[string]*Collection)
	walk = func(prefix string, cs map[string]*Collection) {
		for _, name := range sortedKeys(cs) {
			c := cs[name]
			path := join(prefix, name)
			if g := c.Methods["get"]; g != nil && g.Response != nil && g.Response.Ref == schema && matchesName(g, relName) {
				k := &Kind{Doc: d, Schema: schema, Get: g, Collection: path}
				for _, mn := range sortedKeys(c.Methods) {
					m := c.Methods[mn]
					if m.HTTPMethod == "POST" && (mn == "create" || mn == "insert") {
						k.Create = m
					}
				}
				found = append(found, k)
			}
			walk(path, c.Resources)
		}
	}
	walk("", d.Resources)
	if len(found) == 0 {
		// Cloud Asset Inventory's schema name can differ from the
		// document's: it reports Service Usage's services as "Service",
		// the document calls the schema GoogleApiServiceusageV1Service. The
		// name pattern alone then decides, if exactly one get matches.
		for _, c := range d.collections() {
			if g := c.methods["get"]; g != nil && g.Response != nil && matchesName(g, relName) {
				k := &Kind{Doc: d, Schema: g.Response.Ref, Get: g, Collection: c.path}
				for _, mn := range []string{"create", "insert"} {
					if m := c.methods[mn]; m != nil && m.HTTPMethod == "POST" {
						k.Create = m
					}
				}
				found = append(found, k)
			}
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("%s %s: the document names %d collections that read %s at this name", d.Name, d.Version, len(found), schema)
	}
	return found[0], nil
}

// matchesName checks the get method's {+name}-style parameter pattern.
func matchesName(m *Method, relName string) bool {
	for _, p := range m.Parameters {
		if p.Location == "path" && p.Pattern != "" {
			re, err := regexp.Compile(p.Pattern)
			return err == nil && re.MatchString(relName)
		}
	}
	return false
}

// URL expands a method path with one path parameter value, the way
// Discovery's {+param} (reserved expansion: slashes kept) works.
func (d *Doc) URL(m *Method, value string) string {
	re := regexp.MustCompile(`\{\+?[A-Za-z]+\}`)
	return d.RootURL + d.ServicePath + re.ReplaceAllString(m.Path, value)
}

// Fields flattens a schema into dotted field paths for schema-diff.
func (d *Doc) Fields(schema string) []string {
	var out []string
	var walk func(s *Schema, prefix string, depth int, seen map[string]bool)
	walk = func(s *Schema, prefix string, depth int, seen map[string]bool) {
		if s == nil || depth > 24 {
			return
		}
		if s.Ref != "" {
			if seen[s.Ref] {
				out = append(out, prefix+" (recursive)")
				return
			}
			seen = copySet(seen)
			seen[s.Ref] = true
			s = d.resolve(s)
			if s == nil {
				return
			}
		}
		if s.Items != nil {
			walk(s.Items, prefix+"[]", depth+1, seen)
		}
		if s.AdditionalProperties != nil {
			out = append(out, join(prefix, "*"))
			walk(s.AdditionalProperties, join(prefix, "*"), depth+1, seen)
		}
		for _, k := range sortedKeys(s.Properties) {
			p := join(prefix, k)
			out = append(out, p)
			walk(s.Properties[k], p, depth+1, seen)
		}
	}
	walk(&Schema{Ref: schema}, "", 0, map[string]bool{})
	sort.Strings(out)
	return dedupe(out)
}

// normalize removes output-only fields, walking the data with the schema.
// Scalars removed are returned by dotted path for people. A field the
// schema does not know is kept: the API is newer than its document, and
// dropping the field could lose configuration without a word.
func (d *Doc) normalize(schema string, data map[string]any) (map[string]any, map[string]any) {
	spec := deepCopy(data)
	ro := map[string]any{}
	d.clean(spec, d.Schemas[schema], "", ro)
	return spec, ro
}

func (d *Doc) clean(v any, s *Schema, path string, ro map[string]any) {
	s = d.resolve(s)
	if s == nil {
		return
	}
	switch c := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(c) {
			p, known := s.Properties[k]
			full := join(path, k)
			switch {
			case standardOutput[k]:
				if isScalar(c[k]) {
					ro[full] = c[k]
				}
				delete(c, k)
			case !known && s.AdditionalProperties != nil:
				d.clean(c[k], s.AdditionalProperties, join(path, "*"), ro)
			case !known:
			// The property's own flag and description decide, not those of
			// the schema it refers to: they sit beside its $ref.
			case outputOnly(p):
				if isScalar(c[k]) {
					ro[full] = c[k]
				}
				delete(c, k)
			default:
				d.clean(c[k], p, full, ro)
			}
		}
	case []any:
		for _, x := range c {
			d.clean(x, s.Items, path+"[]", ro)
		}
	}
}

// standardOutput are the fields Google's API guidelines (AIP-148) define
// as output only on every resource, flagged or not. An unflagged etag would
// otherwise read as drift on every capture.
var standardOutput = map[string]bool{"createTime": true, "updateTime": true, "deleteTime": true, "uid": true, "etag": true}

func isScalar(v any) bool {
	switch v.(type) {
	case string, float64, bool, nil:
		return true
	}
	return false
}

func deepCopy(m map[string]any) map[string]any {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func copySet(m map[string]bool) map[string]bool {
	c := make(map[string]bool, len(m)+1)
	for k, v := range m {
		c[k] = v
	}
	return c
}

func join(p, k string) string {
	if p == "" {
		return k
	}
	return p + "." + k
}

// FieldsDigest is the fingerprint stored in the snapshot.
func FieldsDigest(fields []string) string {
	h := sha256.New()
	for _, f := range fields {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func canon(v any) string { b, _ := json.Marshal(v); return string(b) }
