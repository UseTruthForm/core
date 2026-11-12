package kube

import (
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A snapshot restored into another environment than the one it was taken
// from (a drill beside the source, a rebuild of dev as test) needs two
// things changed and nothing else: objects that must not arrive there (the
// GitOps root, which would have the new cluster sync the old one's path),
// and where its Secrets are read from (the other environment's vault).

// LeaveOut returns the snapshot without the objects the entries name, and
// those objects' keys. An entry is Kind/namespace/name, or Kind/name for
// an object with no namespace; Kind may be Kind.group where two APIs share
// one, and "*" stands for any kind, namespace or name. An entry that names
// nothing is an error: a mistyped one would otherwise restore what it was
// written to hold back.
func LeaveOut(s snapshot.Snapshot, entries []string) (snapshot.Snapshot, error) {
	type pattern struct{ kind, ns, name string }
	pats := make([]pattern, len(entries))
	for i, e := range entries {
		parts := strings.Split(e, "/")
		switch len(parts) {
		case 2:
			pats[i] = pattern{parts[0], "", parts[1]}
		case 3:
			pats[i] = pattern{parts[0], parts[1], parts[2]}
		default:
			return s, fmt.Errorf("%q is not Kind/namespace/name, or Kind/name for an object with no namespace", e)
		}
		if pats[i].kind == "" || pats[i].name == "" || (len(parts) == 3 && pats[i].ns == "") {
			return s, fmt.Errorf("%q has an empty part; \"*\" stands for any", e)
		}
	}
	is := func(pat, v string) bool { return pat == "*" || pat == v }
	matched := make([]bool, len(pats))
	out := s
	out.Objects = nil
	for _, o := range s.Objects {
		group, _, versioned := strings.Cut(o.APIVersion(), "/")
		if !versioned {
			group = ""
		}
		left := false
		for i, p := range pats {
			kind := p.kind == "*" || p.kind == o.Kind() || p.kind == o.Kind()+"."+group
			// Kind/name is an object with no namespace only: "*" for the
			// namespace is how to reach into every one.
			if kind && p.ns == o.Namespace() || kind && p.ns == "*" && o.Namespace() != "" {
				if is(p.name, o.Name()) {
					matched[i], left = true, true
				}
			}
		}
		if !left {
			out.Objects = append(out.Objects, o)
		}
	}
	var none []string
	for i, ok := range matched {
		if !ok {
			none = append(none, entries[i])
		}
	}
	if len(none) > 0 {
		return s, fmt.Errorf("these name nothing in the snapshot: %s", strings.Join(none, ", "))
	}
	return out, nil
}

// externalSecretRefs are where an ExternalSecret says what it reads.
var externalSecretRefs = []string{"secretStoreRef.name", "data[].remoteRef.key", "dataFrom[].extract.key"}

// storeRefs are the fields of an object that say where in a secret store
// it reads: what differs when the same objects are to read another
// environment's items.
func storeRefs(o snapshot.Object) []string {
	group, _, _ := strings.Cut(o.APIVersion(), "/")
	for _, r := range storeReaders {
		if r.group == group && r.kind == o.Kind() {
			if r.refs != nil {
				return r.refs
			}
			return r.item
		}
	}
	if group != "external-secrets.io" {
		return nil
	}
	var out []string
	switch o.Kind() {
	case "ExternalSecret":
		for _, f := range externalSecretRefs {
			out = append(out, "spec."+f)
		}
	case "ClusterExternalSecret":
		for _, f := range externalSecretRefs {
			out = append(out, "spec.externalSecretSpec."+f)
		}
	case "SecretStore", "ClusterSecretStore":
		// Which vault a store is: the one field of each provider that has
		// one, where the store and not each reader says it.
		out = []string{"spec.provider.azurekv.vaultUrl", "spec.provider.vault.server", "spec.provider.vault.path", "spec.provider.gcpsm.projectID"}
	}
	return out
}

// RenameStores rewrites where the snapshot's objects read their Secrets
// from. names maps the start of a reference to what replaces it ("vaults/
// apps/" to "vaults/apps-test/"; a whole reference is its own start), and
// the longest start that fits a reference is the one applied. Only the
// fields that name a store or an item in it are touched. It returns how
// many references changed. A start that fits none is an error.
func RenameStores(s snapshot.Snapshot, names map[string]string) (snapshot.Snapshot, int, error) {
	starts := make([]string, 0, len(names))
	for k := range names {
		if k == "" {
			return s, 0, fmt.Errorf("an empty start would rewrite every reference")
		}
		starts = append(starts, k)
	}
	// Longest first; among equals, in order, so that the result is one.
	sort.Slice(starts, func(i, j int) bool {
		if len(starts[i]) != len(starts[j]) {
			return len(starts[i]) > len(starts[j])
		}
		return starts[i] < starts[j]
	})
	used := map[string]bool{}
	changed := 0
	out := s
	out.Objects = make([]snapshot.Object, len(s.Objects))
	for i, o := range s.Objects {
		out.Objects[i] = o
		refs := storeRefs(o)
		if len(refs) == 0 {
			continue
		}
		body := deepCopy(o.Body)
		n := 0
		for _, path := range refs {
			n += setFields(body, path, func(v string) string {
				for _, st := range starts {
					if strings.HasPrefix(v, st) {
						used[st] = true
						return names[st] + strings.TrimPrefix(v, st)
					}
				}
				return v
			})
		}
		if n > 0 {
			out.Objects[i].Body = body
			changed += n
		}
	}
	var none []string
	for _, st := range starts {
		if !used[st] {
			none = append(none, st)
		}
	}
	sort.Strings(none)
	if len(none) > 0 {
		return s, 0, fmt.Errorf("no store reference in the snapshot starts with: %s", strings.Join(none, ", "))
	}
	return out, changed, nil
}

// setFields passes each string at a dotted path (as fields reads them) to
// f and stores what it returns, and counts those that changed.
func setFields(body map[string]any, path string, f func(string) string) int {
	names := strings.Split(path, ".")
	var walk func(v any, rest []string) int
	walk = func(v any, rest []string) int {
		m, _ := v.(map[string]any)
		if m == nil {
			return 0
		}
		name := strings.TrimSuffix(rest[0], "[]")
		child, ok := m[name]
		if !ok {
			return 0
		}
		if strings.HasSuffix(rest[0], "[]") {
			n := 0
			l := list(child)
			for i, el := range l {
				if len(rest) == 1 {
					if sv, ok := el.(string); ok {
						if nv := f(sv); nv != sv {
							l[i] = nv
							n++
						}
					}
					continue
				}
				n += walk(el, rest[1:])
			}
			return n
		}
		if len(rest) > 1 {
			return walk(child, rest[1:])
		}
		if sv, ok := child.(string); ok {
			if nv := f(sv); nv != sv {
				m[name] = nv
				return 1
			}
		}
		return 0
	}
	return walk(body, names)
}
