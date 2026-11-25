// Package snapshot is TruthForm's on-disk backup format: one YAML document per
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

// KubernetesCaptureRules is the version of the rules for what a Kubernetes
// capture leaves out and why (kube.CaptureRules). A snapshot under a later
// version was written by a newer build, and this one refuses it rather
// than read it under rules it does not know. 1: a self-applying GitOps root,
// and the source a self-applying Kustomization reads from, are captured.
// 2: a release's Helm history is listed as a family, apart from a Secret
// listed by its own name (HelmHistoryFamily). 3: an object whose labels name
// a Flux Kustomization, a Flux HelmRelease or an Argo CD application that
// the cluster does not hold is captured.
const KubernetesCaptureRules = 3

// AzureCaptureRules is the version of the rules for how an Azure capture
// names what it leaves out. 1: a skip names a resource by its group and its
// name as the snapshot keys it ("g/name", "g/providers/…" for an extension,
// "g/g" for a group). Under 0 an extension was named by its group and last
// name alone, the same as one of that name on the group or another resource.
const AzureCaptureRules = 1

// maxRules is the highest capture rules version this build knows, per
// platform; a platform not named has none.
var maxRules = map[string]int{"kubernetes": KubernetesCaptureRules, "azure": AzureCaptureRules}

// checkRules refuses a capture rules version this build cannot read.
func checkRules(platform string, rules int) error {
	if rules < 0 {
		return fmt.Errorf("capture rules %d is not a version", rules)
	}
	if max := maxRules[platform]; rules > max {
		return fmt.Errorf("captured under %s capture rules %d, and this build knows up to %d: read it with a newer TruthForm", platform, rules, max)
	}
	return nil
}

// FormatVersion is bumped on any change a reader of older snapshots must know about.
//
// 2: the tool was renamed. Annotations moved to truthform.org, placeholders
// to {{truthform|...}} and TruthForm's own API groups to *.truthform.org.
// Format 1 is still read (see legacy.go); a build from before the rename
// refuses format 2 rather than reading it without its annotations.
const FormatVersion = 2

// manifestFile marks a directory as a TruthForm snapshot. Write refuses to
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

// FoldsCase reports whether a platform's names, groups and types ignore case,
// so that one object can be returned in a different case from one read to the
// next. Azure's do: Log Analytics returned one table as
// ACSCallAutomationStreamingUsage on one day and AcsCallAutomationStreamingUsage
// on the next, and each capture wrote it to a file of its own. Kubernetes and
// GCP names are case-sensitive; AWS differs by service and is left as it is.
func FoldsCase(platform string) bool { return platform == "azure" }

// IdentityKey is Key as the platform matches objects: folded where its names
// ignore case.
func (o Object) IdentityKey(platform string) string {
	if FoldsCase(platform) {
		return strings.ToLower(o.Key())
	}
	return o.Key()
}

// Skip records one object the capture saw and deliberately did not take.
type Skip struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
	// Names are the objects a skip named "*" stands for, where a capture
	// lists them: the Services an object owns, whose names do not change
	// from one day to the next as its pods' do.
	Names []string `json:"names,omitempty"`
	// Selectors are, for each of Names that has one, the Service's
	// selector: what answers behind a Service that is not in the
	// snapshot can then be looked for among the workloads that are.
	Selectors map[string]map[string]string `json:"selectors,omitempty"`
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
	Policy string
	// Rules is the version of the platform's rules for what a capture leaves
	// out and why (KubernetesCaptureRules), 0 where the capture did not say:
	// every snapshot written before it was recorded, beta.23's among them.
	// Compare uses it only to say where a difference may come from an older
	// build's rules. It is written to the manifest, outside the digest: it
	// says which rules made the files, not what the system holds.
	Rules    int
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
	Rules         int    `json:"rules,omitempty"`
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

	fold := FoldsCase(s.Platform)
	files := map[string][]byte{}
	seen := map[string]string{}
	for _, o := range s.Objects {
		// Where names ignore case, two spellings are one object.
		if prev, ok := seen[o.IdentityKey(s.Platform)]; ok {
			if prev != o.Key() {
				return fmt.Errorf("duplicate object %s (also as %s; %s names ignore case)", o.Key(), prev, s.Platform)
			}
			return fmt.Errorf("duplicate object %s", o.Key())
		}
		seen[o.IdentityKey(s.Platform)] = o.Key()
		b, err := encodeYAML(o.Body)
		if err != nil {
			return fmt.Errorf("encode %s: %w", o.Key(), err)
		}
		files[objectPath(o, fold)] = b
	}

	for _, ts := range s.Schemas {
		b, err := encodeYAML(ts)
		if err != nil {
			return fmt.Errorf("encode schema %s %s: %w", ts.APIVersion, ts.Kind, err)
		}
		files[schemaPath(ts, fold)] = b
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

	// Outside the digest, like REPORT.md: it says how to store the files, not
	// what was captured.
	if err := os.WriteFile(filepath.Join(dir, gitattributesFile), []byte(gitattributes), 0o644); err != nil {
		return err
	}
	m := manifest{Format: FormatVersion, Platform: s.Platform, ServerVersion: s.ServerVersion, Policy: s.Policy, Rules: s.Rules, Objects: len(s.Objects), Digest: digest(files)}
	mb, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, manifestFile), mb, 0o644)
}

// gitattributes keeps git from changing a snapshot's line endings. Git for
// Windows converts text files to CRLF on checkout by default
// (core.autocrlf=true): this build reads them back (asWritten), and an
// earlier one, or any tool that compares the bytes, does not. -text, not
// binary: a diff of two captures still shows the lines.
const (
	gitattributesFile = ".gitattributes"
	gitattributes     = "# Written by TruthForm: git keeps these files as they were written.\n* -text\n"
)

// Read loads a snapshot written by Write. It refuses a directory without a
// manifest and verifies the digest, so a hand-edited or half-copied snapshot
// is reported rather than restored as if it were whole.
func Read(dir string) (Snapshot, error) {
	mb, err := os.ReadFile(filepath.Join(dir, manifestFile))
	if err != nil {
		return Snapshot{}, fmt.Errorf("%s is not a TruthForm snapshot: %w", dir, err)
	}
	var m manifest
	if err := yaml.Unmarshal(mb, &m); err != nil {
		return Snapshot{}, fmt.Errorf("read manifest: %w", err)
	}
	if m.Format != FormatVersion && m.Format != legacyFormat {
		return Snapshot{}, fmt.Errorf("snapshot format %d, this build reads %d and %d", m.Format, legacyFormat, FormatVersion)
	}

	if err := checkRules(m.Platform, m.Rules); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %s: %w", dir, err)
	}

	if m.Format == legacyFormat && legacyNamesDiffer[m.Platform] {
		return Snapshot{}, fmt.Errorf("snapshot %s was captured before the tool was renamed, and on %s that changes the names it generates for resources with none of their own; a diff would report each as missing and extra, and a restore could create it twice. Capture the source again with this build, or use the build that wrote the snapshot", dir, m.Platform)
	}

	files := map[string][]byte{}
	// Each file's path as Write names it, where the platform's names ignore
	// case: a check of the digest that does not depend on the case of a path.
	canonical := map[string]string{}
	s := Snapshot{Platform: m.Platform, ServerVersion: m.ServerVersion, Policy: m.Policy, Rules: m.Rules}
	objDir := filepath.Join(dir, "objects")
	err = filepath.WalkDir(objDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		b = asWritten(b)
		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)] = b
		body := map[string]any{}
		if err := yaml.Unmarshal(b, &body); err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		s.Objects = append(s.Objects, Object{Body: body})
		canonical[filepath.ToSlash(rel)] = objectPath(Object{Body: body}, true)
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
		b = asWritten(b)
		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)] = b
		var ts TypeSchema
		if err := yaml.Unmarshal(b, &ts); err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		s.Schemas = append(s.Schemas, ts)
		canonical[filepath.ToSlash(rel)] = schemaPath(ts, true)
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Snapshot{}, err
	}
	cb, err := os.ReadFile(filepath.Join(dir, "coverage.yaml"))
	if err != nil {
		return Snapshot{}, fmt.Errorf("read coverage: %w", err)
	}
	cb = asWritten(cb)
	files["coverage.yaml"] = cb
	var cov coverageDoc
	if err := yaml.Unmarshal(cb, &cov); err != nil {
		return Snapshot{}, fmt.Errorf("parse coverage: %w", err)
	}
	s.Coverage, s.Skips = cov.Types, cov.Skips

	if got := digest(files); got != m.Digest && !(FoldsCase(m.Platform) && digestFolded(files, canonical) == m.Digest) {
		return Snapshot{}, fmt.Errorf("snapshot %s does not match its manifest digest (have %s, manifest says %s): files were changed, added or removed after capture", dir, got, m.Digest)
	}
	if len(s.Objects) != m.Objects {
		return Snapshot{}, fmt.Errorf("snapshot has %d objects, manifest says %d", len(s.Objects), m.Objects)
	}
	// After the digest check, which is over the files as they were written.
	if m.Format == legacyFormat {
		fromLegacy(&s)
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
// (sigs.k8s.io/yaml, which TruthForm itself reads with; PyYAML; many CI tools)
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

// asWritten undoes what a checkout that converts line endings did: CRLF back
// to LF. TruthForm never writes a carriage return (YAML escapes it as \r), so
// a CRLF in a snapshot file is git's (core.autocrlf, Git for Windows'
// default) or an editor's, and the bytes back are exactly the bytes written.
// Without it, a snapshot cloned on Windows matched no digest and every
// command refused it as changed after capture.
func asWritten(b []byte) []byte {
	if !bytes.Contains(b, []byte("\r\n")) {
		return b
	}
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// digestFolded is the digest of files under the paths Write gives them where
// names ignore case, for each file whose path differs from that one only in
// case. On a filesystem that ignores case (Windows, macOS), git keeps the case
// a path was first committed in: Azure snapshots from before paths were
// written in lower case came back from a clone under the old paths, with this
// build's contents, and were refused as changed after capture.
func digestFolded(files map[string][]byte, canonical map[string]string) string {
	out := make(map[string][]byte, len(files))
	for rel, b := range files {
		if c, ok := canonical[rel]; ok && strings.EqualFold(c, rel) {
			rel = c
		}
		out[rel] = b
	}
	return digest(out)
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

// objectPath is objects/<group>/<version>/<kind>/<namespace|_cluster>/<name>.yaml,
// in lower case where the platform's names ignore case (fold): the file an
// object is in must not change when the API returns its name in another
// case, or the snapshot holds it twice and its digest moves each time. The
// file itself keeps the case the API returned.
func objectPath(o Object, fold bool) string {
	group, version := "core", o.APIVersion()
	if i := strings.LastIndex(version, "/"); i >= 0 {
		group, version = version[:i], version[i+1:]
	}
	ns := o.Namespace()
	if ns == "" {
		ns = "_cluster"
	}
	return pathOf(fold, "objects", group, version, o.Kind(), ns, o.Name())
}

func schemaPath(ts TypeSchema, fold bool) string {
	group, version := "core", ts.APIVersion
	if i := strings.LastIndex(version, "/"); i >= 0 {
		group, version = version[:i], version[i+1:]
	}
	return pathOf(fold, "schemas", group, version, ts.Kind)
}

// pathOf joins dir and the segments, made safe, and names a YAML file.
func pathOf(fold bool, dir string, segs ...string) string {
	out := []string{dir}
	for _, s := range segs {
		if fold {
			s = strings.ToLower(s)
		}
		out = append(out, seg(s))
	}
	return strings.Join(out, "/") + ".yaml"
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
		return fmt.Errorf("%s is not empty and is not a TruthForm snapshot; refusing to overwrite it", dir)
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
