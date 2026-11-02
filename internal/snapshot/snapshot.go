// Package snapshot is StackDNA's on-disk backup format: one YAML document per
// live object, plus a manifest and a coverage report.
//
// The format exists so that a backup can be recreated without any state file.
// The live system is the source of truth, and the snapshot is what it looked
// like, normalised. Two properties are deliberate and must not be traded away:
//
//   - Deterministic: the same live state always writes byte-identical files.
//     That is what lets CI regenerate a snapshot and show only real changes.
//     So nothing time- or machine-dependent (capture time, kubeconfig context
//     name, tool build) is ever written into the snapshot itself.
//   - Honest coverage: everything the capture did not take is listed with a
//     reason. A backup that silently omits a resource type reads as complete
//     and is worse than no backup.
package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	yaml3 "go.yaml.in/yaml/v3"
	"sigs.k8s.io/yaml"
)

// FormatVersion is bumped on any change a reader of older snapshots must know about.
const FormatVersion = 1

// manifestFile marks a directory as a StackDNA snapshot. Write refuses to
// replace the contents of a non-empty directory without it, so pointing --out
// at the wrong folder cannot delete someone's files.
const manifestFile = "snapshot.yaml"

// Object is one captured resource, already normalised. Body is the full
// object as the API returns it (apiVersion, kind, metadata, spec, ...).
type Object struct {
	Body map[string]any
}

// APIVersion, Kind, Namespace and Name read the object's identity from Body.
func (o Object) APIVersion() string { return str(o.Body, "apiVersion") }

// Kind returns the object's kind.
func (o Object) Kind() string { return str(o.Body, "kind") }

// Namespace returns the object's namespace, or "" for cluster-scoped objects.
func (o Object) Namespace() string { return str(meta(o.Body), "namespace") }

// Name returns the object's name.
func (o Object) Name() string { return str(meta(o.Body), "name") }

// Key identifies an object uniquely within a snapshot.
func (o Object) Key() string {
	return strings.Join([]string{o.APIVersion(), o.Kind(), o.Namespace(), o.Name()}, "|")
}

// Skip records one object the capture saw and deliberately did not take.
type Skip struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
}

// Coverage summarises one resource type: how many objects were captured, how
// many were skipped and why, and whether the type could not be read at all.
type Coverage struct {
	Resource string         `json:"resource"`
	Kind     string         `json:"kind"`
	Captured int            `json:"captured"`
	Skipped  map[string]int `json:"skipped,omitempty"`
	// NotCaptured explains why a whole type was left out (no list verb,
	// excluded by policy, list failed). Empty means the type was read.
	NotCaptured string `json:"notCaptured,omitempty"`
}

// TypeSchema is the fingerprint of one type's live schema at capture time:
// its flattened field paths and their digest. Fields come from the API
// itself, never from a list in code, so schema-diff can show what an API
// added or removed between two captures.
type TypeSchema struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Digest     string   `json:"digest,omitempty"`
	Note       string   `json:"note,omitempty"`
	Fields     []string `json:"fields,omitempty"`
}

// Snapshot is a complete capture of one system.
type Snapshot struct {
	Platform      string
	ServerVersion string
	// Policy names the capture rules used ("default", "include-system").
	// Comparing snapshots taken under different policies would report the
	// policy difference as drift, so diff refuses to.
	Policy   string
	Objects  []Object
	Coverage []Coverage
	Skips    []Skip
	Schemas  []TypeSchema
	// Unwell is what a capture saw that is configured as it should be and is
	// not working (Azure's provisioningState Failed). It is never written: it
	// says how the system is now, not what it is, and two captures of an
	// unchanged system must match. Compare reports it.
	Unwell []string
}

type manifest struct {
	Format        int    `json:"format"`
	Platform      string `json:"platform"`
	ServerVersion string `json:"serverVersion,omitempty"`
	Policy        string `json:"policy"`
	Objects       int    `json:"objects"`
	// Digest covers every object file and the coverage report, so two
	// snapshots can be compared for equality without reading them.
	Digest string `json:"digest"`
}

type coverageDoc struct {
	Types []Coverage `json:"types"`
	Skips []Skip     `json:"skips,omitempty"`
}

// Write replaces dir with the snapshot. The objects directory is rebuilt from
// scratch every time: reusing it would keep files for objects that have since
// been deleted, and a restore would bring them back.
func (s Snapshot) Write(dir string) error {
	if err := ensureOwnedOrEmpty(dir); err != nil {
		return err
	}
	for _, sub := range []string{"objects", "schemas"} {
		if err := os.RemoveAll(filepath.Join(dir, sub)); err != nil {
			return fmt.Errorf("clear old %s: %w", sub, err)
		}
	}

	files := map[string][]byte{}
	seen := map[string]bool{}
	for _, o := range s.Objects {
		if seen[o.Key()] {
			return fmt.Errorf("duplicate object %s", o.Key())
		}
		seen[o.Key()] = true
		b, err := encodeYAML(o.Body)
		if err != nil {
			return fmt.Errorf("encode %s: %w", o.Key(), err)
		}
		files[objectPath(o)] = b
	}

	for _, ts := range s.Schemas {
		b, err := encodeYAML(ts)
		if err != nil {
			return fmt.Errorf("encode schema %s %s: %w", ts.APIVersion, ts.Kind, err)
		}
		files[schemaPath(ts)] = b
	}

	cov := coverageDoc{Types: append([]Coverage(nil), s.Coverage...), Skips: append([]Skip(nil), s.Skips...)}
	sort.Slice(cov.Types, func(i, j int) bool { return cov.Types[i].Resource < cov.Types[j].Resource })
	sort.Slice(cov.Skips, func(i, j int) bool {
		a, b := cov.Skips[i], cov.Skips[j]
		// The reason too: skips recorded per owner all have the name "*".
		return a.Resource+"|"+a.Namespace+"|"+a.Name+"|"+a.Reason < b.Resource+"|"+b.Namespace+"|"+b.Name+"|"+b.Reason
	})
	cb, err := encodeYAML(cov)
	if err != nil {
		return fmt.Errorf("encode coverage: %w", err)
	}
	files["coverage.yaml"] = cb

	for rel, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
	}

	m := manifest{Format: FormatVersion, Platform: s.Platform, ServerVersion: s.ServerVersion, Policy: s.Policy, Objects: len(s.Objects), Digest: digest(files)}
	mb, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, manifestFile), mb, 0o644)
}

// Read loads a snapshot written by Write. It refuses a directory without a
// manifest and verifies the digest, so a hand-edited or half-copied snapshot
// is reported rather than restored as if it were whole.
func Read(dir string) (Snapshot, error) {
	mb, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%s is not a StackDNA snapshot: %w", dir, err)
	}
	var m manifest
	if err := yaml.Unmarshal(mb, &m); err != nil {
		return Snapshot{}, fmt.Errorf("read manifest: %w", err)
	}
	if m.Format != FormatVersion {
		return Snapshot{}, fmt.Errorf("snapshot format %d, this build reads %d", m.Format, FormatVersion)
	}

	files := map[string][]byte{}
	s := Snapshot{Platform: m.Platform, ServerVersion: m.ServerVersion, Policy: m.Policy}
	objDir := filepath.Join(dir, "objects")
	err = filepath.WalkDir(objDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)] = b
		body := map[string]any{}
		if err := yaml.Unmarshal(b, &body); err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		s.Objects = append(s.Objects, Object{Body: body})
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Snapshot{}, err
	}
	schDir := filepath.Join(dir, "schemas")
	err = filepath.WalkDir(schDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)] = b
		var ts TypeSchema
		if err := yaml.Unmarshal(b, &ts); err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		s.Schemas = append(s.Schemas, ts)
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Snapshot{}, err
	}
	cb, err := os.ReadFile(filepath.Join(dir, "coverage.yaml"))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read coverage: %w", err)
	}
	files["coverage.yaml"] = cb
	var cov coverageDoc
	if err := yaml.Unmarshal(cb, &cov); err != nil {
		return Snapshot{}, fmt.Errorf("parse coverage: %w", err)
	}
	s.Coverage, s.Skips = cov.Types, cov.Skips

	if got := digest(files); got != m.Digest {
		return Snapshot{}, fmt.Errorf("snapshot %s does not match its manifest digest (have %s, manifest says %s): files were changed, added or removed after capture", dir, got, m.Digest)
	}
	if len(s.Objects) != m.Objects {
		return Snapshot{}, fmt.Errorf("snapshot has %d objects, manifest says %d", len(s.Objects), m.Objects)
	}
	sort.Slice(s.Objects, func(i, j int) bool { return s.Objects[i].Key() < s.Objects[j].Key() })
	return s, nil
}

// Digest returns the snapshot's manifest digest, for comparing two snapshots.
func Digest(dir string) (string, error) {
	mb, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return "", err
	}
	var m manifest
	if err := yaml.Unmarshal(mb, &m); err != nil {
		return "", err
	}
	return m.Digest, nil
}

// A string is written unquoted only if every YAML reader would read it back
// as that exact string. Go's encoders reason in YAML 1.2, but YAML 1.1 readers
// (sigs.k8s.io/yaml, which StackDNA itself reads with; PyYAML; many CI tools)
// resolve more plain words: "yes"/"on"/"no" become booleans, "=" is the value
// tag, "<<" the merge key. Found when a CRD enum containing "=" made a whole
// snapshot unreadable to PyYAML; the test for that then showed "yes" being
// written bare, which would have restored as the boolean true.
var yaml11Special = map[string]bool{"=": true, "<<": true}

// YAML 1.1 also resolves base-60 numbers ("12:30" is 750) and dates
// ("2001-12-14"). Go's parsers implement neither, so asking them cannot catch
// these; PyYAML does implement them, so they are matched explicitly.
var (
	yaml11Sexagesimal = regexp.MustCompile(`^[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?$`)
	yaml11Timestamp   = regexp.MustCompile(`^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}`)
)

func needsQuote(v string) bool {
	if yaml11Special[v] || yaml11Sexagesimal.MatchString(v) || yaml11Timestamp.MatchString(v) {
		return true
	}
	if strings.Contains(v, "\n") {
		return false // written as a literal block, never resolved
	}
	var a any
	if err := yaml.Unmarshal([]byte(v), &a); err != nil || a != any(v) {
		return true
	}
	var b any
	if err := yaml3.Unmarshal([]byte(v), &b); err != nil || b != any(v) {
		return true
	}
	return false
}

// encodeYAML writes v as YAML with sorted keys (from JSON), two-space
// indentation, and every ambiguous string quoted, so a snapshot opens in any
// YAML tool, reads back identically, and the bytes are stable.
func encodeYAML(v any) ([]byte, error) {
	j, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var n yaml3.Node
	if err := yaml3.Unmarshal(yamlReadable(j), &n); err != nil {
		return nil, err
	}
	setStyles(&n)
	var buf bytes.Buffer
	enc := yaml3.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&n); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// yamlReadable escapes the characters JSON leaves raw but a YAML reader
// refuses or misreads: DEL, the C1 controls (NEL among them, which YAML
// reads as a line break), the byte-order mark and the two
// noncharacters. A full AWS capture failed after 32 minutes, unable to write
// any of it, on one AWS-published SSM document that contained such a
// character. JSON strings may hold \uXXXX escapes, and so may YAML
// double-quoted strings, so the text stays valid for both and the emitter
// writes the value back out escaped.
func yamlReadable(j []byte) []byte {
	var out []byte
	for i, r := range string(j) {
		if r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0xfeff || r == 0xfffe || r == 0xffff {
			if out == nil {
				out = append([]byte(nil), j[:i]...)
			}
			out = fmt.Appendf(out, `\u%04x`, r)
			continue
		}
		if out != nil {
			out = utf8.AppendRune(out, r)
		}
	}
	if out == nil {
		return j
	}
	return out
}

// setStyles turns the JSON-shaped tree (flow collections, every string
// double-quoted) into block YAML that quotes only where needed.
func setStyles(n *yaml3.Node) {
	switch n.Kind {
	case yaml3.MappingNode, yaml3.SequenceNode:
		n.Style = 0
	case yaml3.ScalarNode:
		if n.Tag == "!!str" {
			if needsQuote(n.Value) {
				n.Style = yaml3.DoubleQuotedStyle
			} else {
				n.Style = 0
			}
		}
	}
	for _, c := range n.Content {
		setStyles(c)
	}
}

func digest(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00%d\x00", n, len(files[n]))
		h.Write(files[n])
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// objectPath is objects/<group>/<version>/<kind>/<namespace|_cluster>/<name>.yaml.
func objectPath(o Object) string {
	group, version := "core", o.APIVersion()
	if i := strings.LastIndex(version, "/"); i >= 0 {
		group, version = version[:i], version[i+1:]
	}
	ns := o.Namespace()
	if ns == "" {
		ns = "_cluster"
	}
	return strings.Join([]string{"objects", seg(group), seg(version), seg(o.Kind()), seg(ns), seg(o.Name()) + ".yaml"}, "/")
}

func schemaPath(ts TypeSchema) string {
	group, version := "core", ts.APIVersion
	if i := strings.LastIndex(version, "/"); i >= 0 {
		group, version = version[:i], version[i+1:]
	}
	return strings.Join([]string{"schemas", seg(group), seg(version), seg(ts.Kind) + ".yaml"}, "/")
}

// seg makes a path segment safe on every OS. Kubernetes names can contain ':'
// (system:auth-delegator), which Windows forbids, so anything outside a small
// safe set is percent-encoded. The encoding is reversible and deterministic.
func seg(s string) string {
	var b bytes.Buffer
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		out = "%" + hex.EncodeToString([]byte(s))
	}
	return out
}

func ensureOwnedOrEmpty(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return os.MkdirAll(dir, 0o755)
	}
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, manifestFile)); err != nil {
		return fmt.Errorf("%s is not empty and is not a StackDNA snapshot; refusing to overwrite it", dir)
	}
	return nil
}

func meta(body map[string]any) map[string]any {
	m, _ := body["metadata"].(map[string]any)
	return m
}

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}
