// Package awscc captures and restores AWS resources through the Cloud Control
// API, driven entirely by the CloudFormation registry's resource schemas.
//
// No AWS type has code here. Each type's identifiers, read-only and
// write-only properties, required properties, supported operations and
// parent relationships come from the schema AWS publishes for it, and the
// same schemas become the field fingerprints that schema-diff compares. When
// AWS adds a property or a whole type, the next capture picks it up from the
// refreshed schema; nobody edits StackDNA.
package awscc

import (
	"archive/zip"
	"bytes"
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
	"time"
)

// TypeInfo is what StackDNA needs to know about one resource type, all of it
// read from the type's registry schema.
type TypeInfo struct {
	Name string // AWS::S3::Bucket
	// PrimaryIdentifier lists the top-level properties that identify a
	// resource (BucketName; RestApiId+ResourceId for nested types).
	PrimaryIdentifier []string
	ReadOnly          []string // JSON pointers, e.g. /properties/Arn
	WriteOnly         []string // values AWS accepts but never returns
	// CreateOnly are set at creation; changing one replaces the resource.
	CreateOnly []string
	Required   []string
	Handlers   map[string]bool // create, read, update, delete, list
	// ListRequires names the properties a list call needs (the parent's ID
	// for parent-scoped types such as AWS::ApiGateway::Resource).
	ListRequires []string
	// Properties and Definitions are the schema's own, kept for flattening
	// field paths and for insertionOrder (set-like arrays).
	Properties  map[string]any
	Definitions map[string]any
	Raw         []byte
}

// Service is the second segment of the type name (S3 in AWS::S3::Bucket).
func (t *TypeInfo) Service() string { return part(t.Name, 1) }

// Short is the last segment (Bucket).
func (t *TypeInfo) Short() string { return part(t.Name, 2) }

func part(name string, i int) string {
	p := strings.Split(name, "::")
	if i < len(p) {
		return p[i]
	}
	return ""
}

// Capturable reports whether Cloud Control can enumerate and read the type.
func (t *TypeInfo) Capturable() bool { return t.Handlers["list"] && t.Handlers["read"] }

// IsReadOnly reports whether a top-level property is read-only.
func (t *TypeInfo) IsReadOnly(prop string) bool { return hasPointer(t.ReadOnly, prop) }

// IsWriteOnly reports whether a top-level property is write-only.
func (t *TypeInfo) IsWriteOnly(prop string) bool { return hasPointer(t.WriteOnly, prop) }

func hasPointer(ptrs []string, prop string) bool {
	for _, p := range ptrs {
		if p == "/properties/"+prop {
			return true
		}
	}
	return false
}

// GeneratedID reports whether AWS chooses the identifier (VpcId) rather than
// the user (BucketName). Generated IDs differ in every account, so such
// resources need a logical name and their references must be remapped.
func (t *TypeInfo) GeneratedID() bool {
	for _, p := range t.PrimaryIdentifier {
		if t.IsReadOnly(p) {
			return true
		}
	}
	return false
}

// Registry is a set of loaded type schemas plus the digest of the bundle
// they came from, so a snapshot records exactly which schemas shaped it.
type Registry struct {
	Types  map[string]*TypeInfo
	Digest string
}

// regionRE is the shape of an AWS region name (us-east-1, us-gov-west-1,
// ap-southeast-2). A region goes into a host name and a cache file name;
// unchecked, "x@attacker.example/../../tmp/owned" made the download come
// from another host and the cache file land outside the cache directory
// (review of the MCP server, 2026-10-22).
var regionRE = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

// CheckRegion refuses anything that is not a region name.
func CheckRegion(region string) error {
	if !regionRE.MatchString(region) {
		return fmt.Errorf("%q is not an AWS region name", region)
	}
	return nil
}

// BundleURL is AWS's public, unauthenticated registry schema bundle for a
// region. It is refreshed by AWS as types change.
func BundleURL(region string) string {
	return "https://schema.cloudformation." + region + ".amazonaws.com/CloudformationSchema.zip"
}

// LoadBundle downloads (or reads from the cache) a region's schema bundle.
// The cache is refreshed after maxAge, so captures follow AWS's schema
// updates without anyone shipping a StackDNA release.
func LoadBundle(region, cacheDir string, maxAge time.Duration) (*Registry, error) {
	if err := CheckRegion(region); err != nil {
		return nil, err
	}
	path := filepath.Join(cacheDir, "aws-schemas-"+region+".zip")
	if st, err := os.Stat(path); err != nil || time.Since(st.ModTime()) > maxAge {
		resp, err := http.Get(BundleURL(region)) //nolint:gosec // fixed AWS URL
		if err != nil {
			return nil, fmt.Errorf("download schema bundle: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("download schema bundle: HTTP %d from %s", resp.StatusCode, BundleURL(region))
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if _, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err != nil {
			return nil, fmt.Errorf("download schema bundle: not a zip: %w", err)
		}
		if err := writeAtomic(cacheDir, path, b); err != nil {
			return nil, err
		}
	}
	return ReadBundle(path)
}

// writeAtomic writes through a temporary file and a rename, so parallel
// targets of one environment refreshing the same cache never read a
// half-written file.
func writeAtomic(dir, path string, b []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), path)
}

// ReadBundle loads a schema bundle zip.
func ReadBundle(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("read schema bundle %s: %w", path, err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		files[f.Name] = data
	}
	return parse(files)
}

// ReadDir loads every *.json schema in a directory (test fixtures, or a
// hand-picked set for an offline capture).
func ReadDir(dir string) (*Registry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, err
			}
			files[e.Name()] = b
		}
	}
	return parse(files)
}

func parse(files map[string][]byte) (*Registry, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no schemas found")
	}
	reg := &Registry{Types: map[string]*TypeInfo{}}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write(files[n])
		var s struct {
			TypeName             string         `json:"typeName"`
			PrimaryIdentifier    []string       `json:"primaryIdentifier"`
			ReadOnlyProperties   []string       `json:"readOnlyProperties"`
			WriteOnlyProperties  []string       `json:"writeOnlyProperties"`
			CreateOnlyProperties []string       `json:"createOnlyProperties"`
			Required             []string       `json:"required"`
			Properties           map[string]any `json:"properties"`
			Definitions          map[string]any `json:"definitions"`
			Handlers             map[string]struct {
				HandlerSchema struct {
					Required []string `json:"required"`
				} `json:"handlerSchema"`
			} `json:"handlers"`
		}
		if err := json.Unmarshal(files[n], &s); err != nil {
			return nil, fmt.Errorf("parse %s: %w", n, err)
		}
		if s.TypeName == "" {
			continue
		}
		t := &TypeInfo{
			Name: s.TypeName, ReadOnly: s.ReadOnlyProperties, WriteOnly: s.WriteOnlyProperties, CreateOnly: s.CreateOnlyProperties,
			Required: s.Required, Properties: s.Properties, Definitions: s.Definitions,
			Handlers: map[string]bool{}, Raw: files[n],
		}
		for _, p := range s.PrimaryIdentifier {
			t.PrimaryIdentifier = append(t.PrimaryIdentifier, strings.TrimPrefix(p, "/properties/"))
		}
		for name, hd := range s.Handlers {
			t.Handlers[name] = true
			if name == "list" {
				t.ListRequires = hd.HandlerSchema.Required
			}
		}
		reg.Types[t.Name] = t
	}
	reg.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return reg, nil
}

// ListPlan is how a type's list calls are made. Most types list with no
// input. The rest need properties that come from a parent resource
// (RestApiId for AWS::ApiGateway::Resource) or from a fixed set of values
// the schema enumerates (Scope: REGIONAL or CLOUDFRONT for WAFv2).
type ListPlan struct {
	ParentType string            // "" when no parent is needed
	FromParent map[string]string // list property -> the parent's property holding it
	Enums      map[string][]string
}

var idSuffix = regexp.MustCompile(`(?i)(Id|Arn|Name|Identifier)$`)

// Plan derives a type's ListPlan from the schemas alone. A required list
// property whose schema is an enum is listed once per value. The others
// must all be found on one parent type: a type in the same service whose
// short name is the property minus its suffix (AppId -> App) or whose sole
// identifier is that property, and which carries every remaining property
// too (AppConfig::Deployment needs ApplicationId and EnvironmentId, both on
// AppConfig::Environment). When no single parent fits, Plan returns the
// reason, so the type is reported as not captured instead of skipped.
func (r *Registry) Plan(t *TypeInfo) (ListPlan, string) {
	plan := ListPlan{FromParent: map[string]string{}, Enums: map[string][]string{}}
	var params []string
	for _, p := range t.ListRequires {
		if vals := enumValues(t, p); len(vals) > 0 {
			plan.Enums[p] = vals
		} else {
			params = append(params, p)
		}
	}
	if len(params) == 0 {
		return plan, ""
	}
	cands := map[string]*TypeInfo{}
	for _, p := range params {
		for _, o := range r.parentCandidates(t, p) {
			cands[o.Name] = o
		}
	}
	var fits []*TypeInfo
	for _, n := range sortedKeys(cands) {
		o := cands[n]
		ok := true
		for _, p := range params {
			ok = ok && parentProperty(o, p) != ""
		}
		if ok {
			fits = append(fits, o)
		}
	}
	if len(fits) != 1 {
		return plan, fmt.Sprintf("list needs %s, and the schemas name %d parent types carrying all of it", strings.Join(params, "+"), len(fits))
	}
	plan.ParentType = fits[0].Name
	for _, p := range params {
		plan.FromParent[p] = parentProperty(fits[0], p)
	}
	return plan, ""
}

func (r *Registry) parentCandidates(t *TypeInfo, param string) []*TypeInfo {
	base := strings.ToLower(idSuffix.ReplaceAllString(param, ""))
	var byName, byID []*TypeInfo
	for _, n := range sortedKeys(r.Types) {
		o := r.Types[n]
		if o.Name == t.Name || o.Service() != t.Service() {
			continue
		}
		if strings.ToLower(o.Short()) == base {
			byName = append(byName, o)
		}
		if len(o.PrimaryIdentifier) == 1 && o.PrimaryIdentifier[0] == param {
			byID = append(byID, o)
		}
	}
	if len(byName) > 0 {
		return byName
	}
	return byID
}

// parentProperty is the parent's property that holds a list property: the
// same name, or, for the parent's own ID under another name, its identifier
// (a parent's "Id" passed as "RestApiId").
func parentProperty(parent *TypeInfo, param string) string {
	if _, ok := parent.Properties[param]; ok {
		return param
	}
	if len(parent.PrimaryIdentifier) == 1 && strings.EqualFold(idSuffix.ReplaceAllString(param, ""), parent.Short()) {
		return parent.PrimaryIdentifier[0]
	}
	return ""
}

func enumValues(t *TypeInfo, prop string) []string {
	ps, _ := t.Properties[prop].(map[string]any)
	ps, _ = derefCFN(ps, t.Definitions)
	var out []string
	for _, v := range list(ps["enum"]) {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Fields flattens a type's schema into dotted field paths for schema-diff,
// the same shape the Kubernetes adapter produces.
func (t *TypeInfo) Fields() []string {
	var out []string
	flattenCFN(map[string]any{"properties": t.Properties}, "", 0, t.Definitions, map[string]bool{}, &out)
	sort.Strings(out)
	return dedupe(out)
}

const maxDepth = 24

func flattenCFN(s map[string]any, prefix string, depth int, defs map[string]any, seen map[string]bool, out *[]string) {
	s, ref := derefCFN(s, defs)
	if ref != "" {
		if seen[ref] {
			*out = append(*out, join(prefix, "(recursive "+ref+")"))
			return
		}
		seen = copySet(seen)
		seen[ref] = true
	}
	if depth > maxDepth {
		*out = append(*out, prefix+"...")
		return
	}
	if props, ok := s["properties"].(map[string]any); ok {
		for name, p := range props {
			ps, _ := p.(map[string]any)
			path := join(prefix, name)
			*out = append(*out, path)
			flattenCFN(ps, path, depth+1, defs, seen, out)
		}
	}
	if items, ok := s["items"].(map[string]any); ok {
		flattenCFN(items, prefix+"[]", depth+1, defs, seen, out)
	}
	if pp, ok := s["patternProperties"].(map[string]any); ok {
		for _, p := range pp {
			ps, _ := p.(map[string]any)
			path := join(prefix, "*")
			*out = append(*out, path)
			flattenCFN(ps, path, depth+1, defs, seen, out)
		}
	}
	for _, key := range []string{"oneOf", "anyOf", "allOf"} {
		for _, alt := range list(s[key]) {
			if m, ok := alt.(map[string]any); ok {
				flattenCFN(m, prefix, depth+1, defs, seen, out)
			}
		}
	}
}

func derefCFN(s map[string]any, defs map[string]any) (map[string]any, string) {
	last := ""
	for i := 0; i < 8; i++ {
		r, _ := s["$ref"].(string)
		if !strings.HasPrefix(r, "#/definitions/") {
			return s, last
		}
		name := strings.TrimPrefix(r, "#/definitions/")
		target, ok := defs[name].(map[string]any)
		if !ok {
			return s, last
		}
		s, last = target, name
	}
	return s, last
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

func list(v any) []any { l, _ := v.([]any); return l }
