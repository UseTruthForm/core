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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

// Snapshot is a complete capture of one system.
type Snapshot struct {
	Platform      string
	ServerVersion string
	// Policy names the capture rules used ("default", "include-system").
	// Comparing snapshots taken under different policies would report the
	// policy difference as drift, so diff refuses to.
	Policy  string
	Objects       []Object
	Coverage      []Coverage
	Skips         []Skip
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
	if err := os.RemoveAll(filepath.Join(dir, "objects")); err != nil {
		return fmt.Errorf("clear old objects: %w", err)
	}

	files := map[string][]byte{}
	seen := map[string]bool{}
	for _, o := range s.Objects {
		if seen[o.Key()] {
			return fmt.Errorf("duplicate object %s", o.Key())
		}
		seen[o.Key()] = true
		b, err := yaml.Marshal(o.Body)
		if err != nil {
			return fmt.Errorf("encode %s: %w", o.Key(), err)
		}
		files[objectPath(o)] = b
	}

	cov := coverageDoc{Types: append([]Coverage(nil), s.Coverage...), Skips: append([]Skip(nil), s.Skips...)}
	sort.Slice(cov.Types, func(i, j int) bool { return cov.Types[i].Resource < cov.Types[j].Resource })
	sort.Slice(cov.Skips, func(i, j int) bool {
		a, b := cov.Skips[i], cov.Skips[j]
		return a.Resource+"|"+a.Namespace+"|"+a.Name < b.Resource+"|"+b.Namespace+"|"+b.Name
	})
	cb, err := yaml.Marshal(cov)
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
