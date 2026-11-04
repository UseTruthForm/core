// Package azarm captures and restores Azure resources through Azure Resource
// Manager, driven by the type definitions Azure publishes for Bicep
// (github.com/Azure/bicep-types-az, generated from the Azure REST API specs).
//
// As with AWS, no Azure type has code here. Which properties are read-only,
// write-only or secret, which are required, and every field path come from
// those definitions; which API versions exist comes live from the
// subscription's provider registrations. A new property or API version
// arrives with the next refresh of the definitions, not with a release.
package azarm

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

// Property flags, as bicep-types defines ObjectTypePropertyFlags.
const (
	flagRequired  = 1
	flagReadOnly  = 2
	flagWriteOnly = 4
)

type ref struct {
	Ref string `json:"$ref"`
}

func (r ref) index() int {
	var n int
	fmt.Sscanf(strings.TrimPrefix(r.Ref, "#/"), "%d", &n)
	return n
}

type prop struct {
	Type        ref    `json:"type"`
	Flags       int    `json:"flags"`
	Description string `json:"description"`
}

// entry is one element of a bicep-types types.json array.
type entry struct {
	Kind                 string          `json:"$type"`
	Name                 string          `json:"name"`
	Body                 *ref            `json:"body"`
	WritableScopes       int             `json:"writableScopes"`
	Properties           map[string]prop `json:"properties"`
	AdditionalProperties *ref            `json:"additionalProperties"`
	ItemType             *ref            `json:"itemType"`
	Discriminator        string          `json:"discriminator"`
	BaseProperties       map[string]prop `json:"baseProperties"`
	Elements             json.RawMessage `json:"elements"`
	Sensitive            bool            `json:"sensitive"`
	Value                string          `json:"value"` // a StringLiteralType's value
}

// Registry resolves "Microsoft.Network/virtualNetworks" at an API version to
// its type definition, loading definition files only when first needed (the
// full set is several hundred files).
type Registry struct {
	index map[string]string // lower("type@version") -> "file#/n"
	names map[string]string // lower(type) -> the type as Azure spells it
	load  func(file string) ([]byte, error)

	mu    sync.Mutex
	files map[string][]entry
	sums  map[string]string
}

// DefinitionsURL is where Azure publishes the generated definitions.
const DefinitionsURL = "https://raw.githubusercontent.com/Azure/bicep-types-az/main/generated/"

// LoadDefinitions reads the definitions from dir (a copy of the repo's
// generated/ folder, or a test fixture laid out the same way).
func LoadDefinitions(dir string) (*Registry, error) {
	return newRegistry(func(f string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, filepath.FromSlash(f))) })
}

// FetchDefinitions downloads definitions from Azure's repository on demand,
// keeping each file in cacheDir for maxAge.
func FetchDefinitions(cacheDir string, maxAge time.Duration) (*Registry, error) {
	return newRegistry(func(f string) ([]byte, error) {
		path := filepath.Join(cacheDir, filepath.FromSlash(f))
		if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()) < maxAge {
			return os.ReadFile(path)
		}
		resp, err := http.Get(DefinitionsURL + f) //nolint:gosec // fixed Azure URL
		if err != nil {
			return nil, fmt.Errorf("download type definitions %s: %w", f, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("download type definitions %s: HTTP %d", f, resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		return b, os.WriteFile(path, b, 0o644)
	})
}

func newRegistry(load func(string) ([]byte, error)) (*Registry, error) {
	b, err := load("index.json")
	if err != nil {
		return nil, err
	}
	var idx struct {
		Resources map[string]ref `json:"resources"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("parse type index: %w", err)
	}
	r := &Registry{index: map[string]string{}, names: map[string]string{}, load: load, files: map[string][]entry{}, sums: map[string]string{}}
	for k, v := range idx.Resources {
		r.index[strings.ToLower(k)] = v.Ref
		// One type can be spelled two ways across versions
		// (authorizationRules, AuthorizationRules); the first in sort order
		// is kept, not whichever the map gave last, so a snapshot's kinds
		// do not change between runs (review of #63).
		if t, _, ok := strings.Cut(k, "@"); ok {
			if cur, seen := r.names[strings.ToLower(t)]; !seen || t < cur {
				r.names[strings.ToLower(t)] = t
			}
		}
	}
	return r, nil
}

// Versions lists the API versions with definitions for a resource type,
// newest first.
func (r *Registry) Versions(resourceType string) []string {
	prefix := strings.ToLower(resourceType) + "@"
	var out []string
	for k := range r.index {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k[len(prefix):])
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

// Children lists the immediate child types with a definition, as Azure
// spells them. A provider's registration does not list every child it serves:
// Microsoft.CognitiveServices/accounts/deployments has a definition and
// answers a list, and the registration names no such type.
func (r *Registry) Children(resourceType string) []string {
	prefix := strings.ToLower(resourceType) + "/"
	var out []string
	for k, t := range r.names {
		if strings.HasPrefix(k, prefix) && !strings.Contains(k[len(prefix):], "/") {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// Schema is one resource type at one API version.
type Schema struct {
	Type, Version string
	file          []entry
	body          int
	// Digest identifies the definition file, so a snapshot records which
	// definitions shaped it.
	Digest string
	// Writable is false for types no one can PUT (an NSG's
	// defaultSecurityRules, which Azure defines). They are never captured:
	// every restore of them would fail.
	Writable bool
}

// Schema loads a type's definition.
func (r *Registry) Schema(resourceType, version string) (*Schema, error) {
	loc, ok := r.index[strings.ToLower(resourceType+"@"+version)]
	if !ok {
		return nil, fmt.Errorf("no type definition for %s@%s", resourceType, version)
	}
	file, frag, _ := strings.Cut(loc, "#")
	r.mu.Lock()
	defer r.mu.Unlock()
	entries, ok := r.files[file]
	if !ok {
		b, err := r.load(file)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &entries); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		h := sha256.Sum256(b)
		r.files[file], r.sums[file] = entries, "sha256:"+hex.EncodeToString(h[:])
	}
	rt := entries[ref{Ref: "#" + frag}.index()]
	if rt.Body == nil {
		return nil, fmt.Errorf("%s@%s: definition has no body", resourceType, version)
	}
	return &Schema{Type: resourceType, Version: version, file: entries, body: rt.Body.index(), Digest: r.sums[file], Writable: rt.WritableScopes != 0}, nil
}

// object returns the properties of an object type, resolving a
// discriminated type by the discriminator value in v (if any).
func (s *Schema) object(i int, v map[string]any) (map[string]prop, *ref, bool) {
	e := s.file[i]
	switch e.Kind {
	case "ObjectType":
		return e.Properties, e.AdditionalProperties, true
	case "DiscriminatedObjectType":
		props := map[string]prop{}
		for k, p := range e.BaseProperties {
			props[k] = p
		}
		var elems map[string]ref
		_ = json.Unmarshal(e.Elements, &elems)
		if d, ok := v[e.Discriminator].(string); ok {
			if el, ok := elems[d]; ok {
				if sub := s.file[el.index()]; sub.Kind == "ObjectType" {
					for k, p := range sub.Properties {
						props[k] = p
					}
				}
			}
		}
		props[e.Discriminator] = prop{}
		return props, nil, true
	case "UnionType":
		// Unions of objects are rare in resource bodies; the first object
		// member is used for classification.
		var elems []ref
		_ = json.Unmarshal(e.Elements, &elems)
		for _, el := range elems {
			if p, a, ok := s.object(el.index(), v); ok {
				return p, a, true
			}
		}
	}
	return nil, nil, false
}

// kinds lists the values the definition names for a resource's kind, for
// a collection Azure lists one kind at a time. A union that also allows
// any string means Azure may hold kinds not named here; those cannot be
// listed.
func (s *Schema) kinds() []string {
	props, _, ok := s.object(s.body, nil)
	if !ok {
		return nil
	}
	p, ok := props["kind"]
	if !ok {
		return nil
	}
	var out []string
	switch e := s.file[p.Type.index()]; e.Kind {
	case "StringLiteralType":
		out = append(out, e.Value)
	case "UnionType":
		var elems []ref
		_ = json.Unmarshal(e.Elements, &elems)
		for _, el := range elems {
			if x := s.file[el.index()]; x.Kind == "StringLiteralType" {
				out = append(out, x.Value)
			}
		}
	}
	sort.Strings(out)
	return out
}

// secret reports a property whose value Azure never returns: flagged
// write-only, or a string type marked sensitive (x-ms-secret: a VM's
// adminPassword is sensitive, not write-only).
func (s *Schema) secret(p prop) bool {
	return p.Flags&flagWriteOnly != 0 || s.file[p.Type.index()].Sensitive
}

// credential reports a property a restore needs given to it. Everything never
// returned counts, except what only says how a resource was made: a key vault's
// createMode and a database's sourceDatabaseId need nothing, and counted they
// refused --update on every such resource and reported each one as restored
// without its secret. It is a list of those and not of credentials, because what
// a list misses should be noise: a web app's siteConfig is write-only and has no
// credential's name, and a rule by name lost it without a word.
func (s *Schema) credential(name string, p prop) bool {
	return s.file[p.Type.index()].Sensitive || !howItWasMadeRE.MatchString(name)
}

var howItWasMadeRE = regexp.MustCompile(`^(createMode|managedInstanceCreateMode|cloningInfo|restorePointInTime|source[A-Z]\w*|crossSubscription\w*|longTermRetentionBackupResourceId|recoverableDatabaseId|restorableDroppedDatabaseId|recoveryServicesRecoveryPointId|sampleName|autoCompleteRestore|lastBackupName|testConnection|createDnsRecord)$`)

// Fields flattens the type into dotted field paths for schema-diff.
func (s *Schema) Fields() []string {
	var out []string
	s.flatten(s.body, "", 0, map[int]bool{}, &out)
	sort.Strings(out)
	return dedupe(out)
}

const maxDepth = 24

func (s *Schema) flatten(i int, prefix string, depth int, seen map[int]bool, out *[]string) {
	if seen[i] {
		*out = append(*out, prefix+" (recursive)")
		return
	}
	if depth > maxDepth {
		*out = append(*out, prefix+"...")
		return
	}
	seen = copySet(seen)
	seen[i] = true
	e := s.file[i]
	switch e.Kind {
	case "ArrayType":
		if e.ItemType != nil {
			s.flatten(e.ItemType.index(), prefix+"[]", depth+1, seen, out)
		}
		return
	case "DiscriminatedObjectType":
		var elems map[string]ref
		_ = json.Unmarshal(e.Elements, &elems)
		for _, k := range sortedKeys(e.BaseProperties) {
			p := join(prefix, k)
			*out = append(*out, p)
			s.flatten(e.BaseProperties[k].Type.index(), p, depth+1, seen, out)
		}
		for _, d := range sortedKeys(elems) {
			s.flatten(elems[d].index(), prefix, depth+1, seen, out)
		}
		return
	}
	props, add, ok := s.object(i, nil)
	if !ok {
		return
	}
	for _, k := range sortedKeys(props) {
		p := join(prefix, k)
		*out = append(*out, p)
		s.flatten(props[k].Type.index(), p, depth+1, seen, out)
	}
	if add != nil {
		*out = append(*out, join(prefix, "*"))
		s.flatten(add.index(), join(prefix, "*"), depth+1, seen, out)
	}
}

// Required lists the required top-level properties and, separately, the
// required properties under "properties".
func (s *Schema) Required() []string {
	var out []string
	top, _, _ := s.object(s.body, nil)
	for _, k := range sortedKeys(top) {
		if top[k].Flags&flagRequired != 0 && !envelope[k] {
			out = append(out, k)
		}
	}
	if p, ok := top["properties"]; ok {
		inner, _, _ := s.object(p.Type.index(), nil)
		for _, k := range sortedKeys(inner) {
			if inner[k].Flags&flagRequired != 0 && inner[k].Flags&flagReadOnly == 0 {
				out = append(out, "properties."+k)
			}
		}
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

func copySet(m map[int]bool) map[int]bool {
	c := make(map[int]bool, len(m)+1)
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
