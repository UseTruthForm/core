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
	neturl "net/url"
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
	Deprecated           bool               `json:"deprecated"`
	Properties           map[string]*Schema `json:"properties"`
	Items                *Schema            `json:"items"`
	AdditionalProperties *Schema            `json:"additionalProperties"`
	Enum                 []string           `json:"enum"`
	EnumDeprecated       []bool             `json:"enumDeprecated"`
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
	Name        string             `json:"name"`
	Version     string             `json:"version"`
	RootURL     string             `json:"rootUrl"`
	ServicePath string             `json:"servicePath"`
	Schemas     map[string]*Schema `json:"schemas"`
	// DocumentationLink is the API's reference documentation.
	DocumentationLink string                 `json:"documentationLink"`
	Resources         map[string]*Collection `json:"resources"`
	Digest            string                 `json:"-"`
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
		b, err := download(docURLs(api, ver))
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, err
		}
		return b, os.WriteFile(path, b, 0o644)
	}}
}

var apiName = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

// docURLs are where a document is published: Google's directory, then the
// service's own endpoint. Some APIs are only at the second (Artifact
// Registry's directory entry answers 404), so translating to them failed
// before any object was checked.
var docURLs = func(api, ver string) []string {
	urls := []string{docURL(api, ver)}
	if apiName.MatchString(api) {
		urls = append(urls, "https://"+api+".googleapis.com/$discovery/rest?version="+neturl.QueryEscape(ver))
	}
	return urls
}

// download reads the first URL that answers 200; a 404 tries the next.
func download(urls []string) ([]byte, error) {
	var last error
	for _, u := range urls {
		resp, err := http.Get(u) //nolint:gosec // fixed googleapis.com hosts; api and version come from Cloud Asset Inventory or a translation
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", u, err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case err != nil:
			return nil, fmt.Errorf("download %s: %w", u, err)
		case resp.StatusCode == http.StatusOK:
			return b, nil
		case resp.StatusCode == http.StatusNotFound:
			last = fmt.Errorf("download %s: HTTP 404", u)
			continue
		default:
			return nil, fmt.Errorf("download %s: HTTP %d", u, resp.StatusCode)
		}
	}
	return nil, last
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
	d.flagUndeclaredOutput()
	d.liftVersion()
	ds.cache[key] = &d
	return &d, nil
}

// undeclaredOutput are fields the server sets that a document flags
// nowhere, not even in prose, by API, schema and dotted path. Cloud
// Storage's Bucket says "The URI of this bucket" of its selfLink and "The
// creation time" of timeCreated: kept as configuration, every bucket would
// differ from its own snapshot on them, and a create sending them is
// refused.
var undeclaredOutput = map[string]map[string][]string{
	"storage": {"Bucket": {
		"id", "kind", "selfLink", "projectNumber", "timeCreated", "updated", "metageneration", "generation",
		"owner", "locationType", "satisfiesPZS", "satisfiesPZI", "softDeleteTime", "hardDeleteTime",
		"softDeletePolicy.effectiveTime", "softDeletePolicy.hardDeletePause.effectiveTime",
		"retentionPolicy.effectiveTime", "retentionPolicy.isLocked",
		"iamConfiguration.uniformBucketLevelAccess.lockedTime", "iamConfiguration.bucketPolicyOnly.lockedTime",
		"autoclass.toggleTime", "autoclass.terminalStorageClassUpdateTime",
		"encryption.googleManagedEncryptionEnforcementConfig.effectiveTime",
		"encryption.customerManagedEncryptionEnforcementConfig.effectiveTime",
		"encryption.customerSuppliedEncryptionEnforcementConfig.effectiveTime",
	}},
}

// flagUndeclaredOutput marks undeclaredOutput's fields read-only in the
// document, so capture, restore, the fake and a translation's check all
// read them as the server's.
func (d *Doc) flagUndeclaredOutput() {
	for schema, paths := range undeclaredOutput[d.Name] {
		for _, path := range paths {
			s := d.Schemas[schema]
			keys := strings.Split(path, ".")
			for i, k := range keys {
				s = d.resolve(s)
				if s == nil || s.Properties[k] == nil {
					break
				}
				if i == len(keys)-1 {
					s.Properties[k].ReadOnly = true
				}
				s = s.Properties[k]
			}
		}
	}
}

// liftVersion moves a version that begins every method path into the
// service path. Cloud SQL's document has an empty servicePath and paths
// like v1/projects/{project}/instances/{instance}: matched against a
// resource name (projects/p/instances/i), no path matched, and an insert's
// URL was built as if the version were a parameter's value, so its
// instances could be neither read nor created. Every URL stays the same.
func (d *Doc) liftVersion() {
	if d.ServicePath != "" || d.Version == "" {
		return
	}
	lead := d.Version + "/"
	var all []*Method
	var walk func(cs map[string]*Collection)
	walk = func(cs map[string]*Collection) {
		for _, c := range cs {
			for _, m := range c.Methods {
				all = append(all, m)
			}
			walk(c.Resources)
		}
	}
	walk(d.Resources)
	if len(all) == 0 {
		return
	}
	for _, m := range all {
		if !strings.HasPrefix(m.Path, lead) {
			return
		}
	}
	for _, m := range all {
		m.Path = strings.TrimPrefix(m.Path, lead)
	}
	d.ServicePath = lead
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

var pathParamRE = regexp.MustCompile(`\{\+?([A-Za-z]+)\}`)

// nameTemplate is the part of a segment-style template that holds the
// resource's name: from the word before its first parameter on. Most
// documents put their version in the service path (Compute's
// compute/v1/), and the template is all name; Cloud DNS's service path is
// empty and its templates start dns/v1/, which no name holds.
func nameTemplate(tmpl string) string {
	segs := strings.Split(tmpl, "/")
	for i, seg := range segs {
		if pathParamRE.MatchString(seg) {
			if i == 0 {
				return tmpl
			}
			return strings.Join(segs[i-1:], "/")
		}
	}
	return tmpl
}

// segmentwise reports a template that names segments, filled one by one:
// not reserved expansion ({+name} takes the whole name), and starting with
// the same word as the name (projects/{project}/global/networks for
// projects/p/global). A one-segment projects/{project} counts too: the
// first rule, a parameter followed by more path, missed it and built
// .../projects/projects/my-proj, which a capture then took for a resource
// deleted between list and read (review, 2026-10-22).
func segmentwise(tmpl, value string) bool {
	if strings.Contains(tmpl, "{+") || !pathParamRE.MatchString(tmpl) {
		return false
	}
	first, _, _ := strings.Cut(tmpl, "/")
	vfirst, _, _ := strings.Cut(value, "/")
	return !pathParamRE.MatchString(first) && first == vfirst
}

// matchesName checks a relative name against a get method. Most documents
// take the whole name as one {+name} parameter with a pattern for it;
// Compute names each segment ({project}, {region}, {subnetwork}), so its
// template is matched whole, each parameter by its own pattern.
func matchesName(m *Method, relName string) bool {
	if strings.Contains(m.Path, "{+") {
		for _, p := range m.Parameters {
			if p.Location == "path" && p.Pattern != "" {
				re, err := regexp.Compile(p.Pattern)
				return err == nil && re.MatchString(relName)
			}
		}
		return false
	}
	if p, ok := bareID(m); ok && !strings.Contains(relName, "/") {
		re, err := regexp.Compile("^(?:" + p + ")$")
		return err == nil && re.MatchString(relName)
	}
	tmpl := nameTemplate(m.Path)
	var b strings.Builder
	last := 0
	for _, loc := range pathParamRE.FindAllStringSubmatchIndex(tmpl, -1) {
		b.WriteString(regexp.QuoteMeta(tmpl[last:loc[0]]))
		pat := `[^/]+`
		if p, ok := m.Parameters[tmpl[loc[2]:loc[3]]]; ok && p.Pattern != "" {
			pat = p.Pattern
		}
		b.WriteString("(?:" + pat + ")")
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(tmpl[last:]))
	re, err := regexp.Compile("^" + b.String() + "$")
	return err == nil && re.MatchString(relName)
}

// bareID reports a get whose path is one word and the resource's ID (Cloud
// Storage's b/{bucket}): such a resource belongs to no parent in its name,
// and Cloud Asset Inventory names it by its ID alone (//storage.googleapis.com/b1).
// It returns the ID's pattern.
func bareID(m *Method) (string, bool) {
	locs := pathParamRE.FindAllStringSubmatchIndex(m.Path, -1)
	if len(locs) != 1 || strings.Contains(m.Path, "{+") || locs[0][1] != len(m.Path) {
		return "", false
	}
	lead := m.Path[:locs[0][0]]
	if strings.Count(lead, "/") != 1 || !strings.HasSuffix(lead, "/") || pathParamRE.MatchString(lead) {
		return "", false
	}
	pat := `[^/]+`
	if p, ok := m.Parameters[m.Path[locs[0][2]:locs[0][3]]]; ok && p.Pattern != "" {
		pat = p.Pattern
	}
	return pat, true
}

// URL expands a method path with a name: the whole value into a single
// {+param} (reserved expansion: slashes kept), or, for a template that
// names each segment (Compute), segment by segment, the template's own
// words filling in what the value stops short of. A get takes the item's
// name (projects/p/global/networks/n); an insert takes its parent
// (projects/p/global) and the template adds "networks".
func (d *Doc) URL(m *Method, value string) string {
	tmpl := nameTemplate(m.Path)
	if !segmentwise(tmpl, value) {
		return d.RootURL + d.ServicePath + pathParamRE.ReplaceAllString(m.Path, value)
	}
	vals := strings.Split(value, "/")
	var out []string
	i := 0
	for _, seg := range strings.Split(tmpl, "/") {
		switch {
		case pathParamRE.MatchString(seg) && i < len(vals):
			out = append(out, vals[i])
			i++
		case i < len(vals) && vals[i] == seg:
			out = append(out, seg)
			i++
		default:
			out = append(out, seg)
		}
	}
	return d.RootURL + d.ServicePath + strings.TrimSuffix(m.Path, tmpl) + strings.Join(out, "/")
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
			case standardOutput[k] || (k == "selfLink" && path == ""):
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
// otherwise read as drift on every capture. A resource's own selfLink is
// the server's too (Cloud SQL does not flag it): kept, it named the source
// project's API path, and a translated instance, which has none, read as
// differing from itself once restored.
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

// DocFor loads an API's document by name and version (pubsub, v1).
func (ds *Docs) DocFor(api, ver string) (*Doc, error) { return ds.Doc(docURL(api, ver), "") }

// Allowed are the values a schema's field takes, as the document lists
// them, leaving out those it marks deprecated; nil when the field is not
// an enum. A translation checks a version against these rather than a list
// of its own, so a version Google adds or retires is known on the day.
func (d *Doc) Allowed(schema, field string) []string {
	s := d.resolve(d.Schemas[schema])
	if s == nil || s.Properties[field] == nil {
		return nil
	}
	f := d.resolve(s.Properties[field])
	var out []string
	for i, v := range f.Enum {
		if i < len(f.EnumDeprecated) && f.EnumDeprecated[i] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// CheckSpec refuses a field a request cannot set: one the schema does not
// declare, or one the server sets, by the document's flag or the prose
// Google's API guidelines require (outputOnly). A translation checks what it
// writes with it, so its objects are what capture would keep.
func (d *Doc) CheckSpec(schema string, spec map[string]any) error {
	s := d.Schemas[schema]
	if s == nil {
		return fmt.Errorf("%s %s declares no schema %s", d.Name, d.Version, schema)
	}
	for _, k := range sortedKeys(spec) {
		p := s.Properties[k]
		switch {
		case p == nil:
			return fmt.Errorf("%s: %s is not a field of %s %s", schema, k, d.Name, d.Version)
		case outputOnly(p):
			return fmt.Errorf("%s: %s is set by the server (%s %s)", schema, k, d.Name, d.Version)
		}
	}
	return nil
}
