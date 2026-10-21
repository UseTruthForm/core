package snapshot

import (
	"fmt"
	"reflect"
	"sort"
)

// Change is one difference between two snapshots.
type Change struct {
	Key string
	// Kind is "missing" (in want, not in got), "extra" (in got, not in want)
	// or "changed".
	Kind   string
	Fields []string // for "changed": the paths that differ
}

// Compare reports how got differs from want. Both must have been normalised
// the same way (captured with the same policy); then an empty result means
// got recreates want.
func Compare(want, got Snapshot) []Change {
	w, g := index(want), index(got)
	var out []Change
	for k, wo := range w {
		gobj, ok := g[k]
		if !ok {
			out = append(out, Change{Key: k, Kind: "missing"})
			continue
		}
		var fields []string
		diffValue("", wo.Body, gobj.Body, &fields)
		if len(fields) > 0 {
			sort.Strings(fields)
			out = append(out, Change{Key: k, Kind: "changed", Fields: fields})
		}
	}
	for k := range g {
		if _, ok := w[k]; !ok {
			out = append(out, Change{Key: k, Kind: "extra"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
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
