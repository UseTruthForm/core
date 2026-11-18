package snapshot

import (
	"fmt"
	"reflect"
	"sort"
)

// Result is the outcome of restoring one object. Restore never drops an
// object quietly: every object in the snapshot ends up as applied or not.
type Result struct {
	Key    string
	OK     bool
	Detail string
}

// Change is one difference between two snapshots.
type Change struct {
	Key string
	// Kind is "missing" (in want, not in got), "extra" (in got, not in want),
	// "changed", or "not working" (got.Unwell: Key says what and why).
	Kind   string
	Fields []string // for "changed": the paths that differ
	// Skipped is, for "missing" or "extra", why the other side left the
	// object out, where it did. It explains the difference and never
	// removes it: an object left out on one side may have been edited.
	Skipped *SkippedOtherSide
}

// Compare reports how got differs from want. Both must have been normalised
// the same way (captured with the same policy); then an empty result means
// got recreates want.
func Compare(want, got Snapshot) []Change {
	w, g := index(want), index(got)
	var out []Change
	var wantSkips, gotSkips *skipIndex
	// Here, so a diff, an environment's diff and --json all say it, and exit 0
	// means the target can be relied on.
	for _, u := range got.Unwell {
		out = append(out, Change{Key: u, Kind: "not working"})
	}
	for k, wo := range w {
		gobj, ok := g[k]
		if !ok {
			if gotSkips == nil {
				gotSkips = indexSkips(got)
			}
			out = append(out, Change{Key: k, Kind: "missing", Skipped: gotSkips.note(wo)})
			continue
		}
		var fields []string
		diffValue("", withoutStatus(wo.Body), withoutStatus(gobj.Body), &fields)
		if len(fields) > 0 {
			sort.Strings(fields)
			out = append(out, Change{Key: k, Kind: "changed", Fields: fields})
		}
	}
	for k, gobj := range g {
		if _, ok := w[k]; !ok {
			if wantSkips == nil {
				wantSkips = indexSkips(want)
			}
			out = append(out, Change{Key: k, Kind: "extra", Skipped: wantSkips.note(gobj)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// withoutStatus drops the top-level "status" block. Kubernetes objects never
// carry one in a snapshot (normalize strips it); other platforms keep observed
// read-only values there (ARNs, generated IDs) to map references during
// restore. Those always differ between two accounts or clusters, so they are
// not drift.
func withoutStatus(b map[string]any) map[string]any {
	if _, ok := b["status"]; !ok {
		return b
	}
	c := make(map[string]any, len(b))
	for k, v := range b {
		if k != "status" {
			c[k] = v
		}
	}
	return c
}

func index(s Snapshot) map[string]Object {
	m := make(map[string]Object, len(s.Objects))
	for _, o := range s.Objects {
		m[o.Key()] = o
	}
	return m
}

func diffValue(path string, a, b any, out *[]string) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		for k := range keys {
			diffValue(join(path, k), am[k], bm[k], out)
		}
		return
	}
	al, alok := a.([]any)
	bl, blok := b.([]any)
	if alok && blok && len(al) == len(bl) {
		for i := range al {
			diffValue(fmt.Sprintf("%s[%d]", path, i), al[i], bl[i], out)
		}
		return
	}
	if !reflect.DeepEqual(normNum(a), normNum(b)) {
		*out = append(*out, path)
	}
}

// normNum makes 2 (from YAML) and 2.0 (from JSON) compare equal.
func normNum(v any) any {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float32:
		return float64(n)
	}
	return v
}

func join(p, k string) string {
	if p == "" {
		return k
	}
	return p + "." + k
}

// SchemaChange is how one type's live schema differs between two snapshots.
type SchemaChange struct {
	Type    string // apiVersion Kind
	Kind    string // "added type", "removed type", "changed", "untracked"
	Added   []string
	Removed []string
}

// CompareSchemas reports what each API added or removed between old and new.
// This is how TruthForm keeps up with APIs without anyone maintaining field
// lists: the fields are whatever the live API publishes, and this shows the
// difference.
func CompareSchemas(old, new Snapshot) []SchemaChange {
	idx := func(s Snapshot) map[string]TypeSchema {
		m := map[string]TypeSchema{}
		for _, t := range s.Schemas {
			m[t.APIVersion+" "+t.Kind] = t
		}
		return m
	}
	o, n := idx(old), idx(new)
	var out []SchemaChange
	for k, nt := range n {
		ot, ok := o[k]
		switch {
		case !ok:
			out = append(out, SchemaChange{Type: k, Kind: "added type"})
		case nt.Digest == "" || ot.Digest == "":
			if nt.Digest != ot.Digest {
				out = append(out, SchemaChange{Type: k, Kind: "untracked"})
			}
		case nt.Digest != ot.Digest:
			out = append(out, SchemaChange{Type: k, Kind: "changed", Added: minus(nt.Fields, ot.Fields), Removed: minus(ot.Fields, nt.Fields)})
		}
	}
	for k := range o {
		if _, ok := n[k]; !ok {
			out = append(out, SchemaChange{Type: k, Kind: "removed type"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

func minus(a, b []string) []string {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	var out []string
	for _, x := range a {
		if !in[x] {
			out = append(out, x)
		}
	}
	return out
}
