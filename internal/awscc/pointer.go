package awscc

import (
	"encoding/json"
	"strings"
)

// The registry marks read-only and write-only properties with JSON pointers
// that may be nested and may cross arrays with "*":
//
//	/properties/Code/ZipFile
//	/properties/LifecycleConfiguration/Rules/*/Transition
//
// Handling only top-level names would leave nested write-only values in a
// snapshot and nested read-only values in a create request, so every pointer
// is applied in full.

func segments(ptr string) []string {
	return strings.Split(strings.TrimPrefix(ptr, "/properties/"), "/")
}

// removePointer deletes every value the pointer matches and prunes objects
// it empties, so a property whose fields are all write-only (Lambda's Code)
// disappears instead of surviving as an empty {} that a restore would send.
func removePointer(m map[string]any, ptr string) {
	removeAt(m, segments(ptr))
}

func removeAt(v any, segs []string) {
	switch c := v.(type) {
	case map[string]any:
		if len(segs) == 1 {
			delete(c, segs[0])
			return
		}
		if segs[0] == "*" {
			for _, x := range c {
				removeAt(x, segs[1:])
			}
			return
		}
		child, ok := c[segs[0]]
		if !ok {
			return
		}
		removeAt(child, segs[1:])
		if empty(child) {
			delete(c, segs[0])
		}
	case []any:
		if segs[0] != "*" {
			return
		}
		for _, x := range c {
			if len(segs) > 1 {
				removeAt(x, segs[1:])
			}
		}
	}
}

func empty(v any) bool {
	m, ok := v.(map[string]any)
	return ok && len(m) == 0
}

// lookupPointer returns the single value at a pointer without wildcards.
func lookupPointer(m map[string]any, ptr string) (any, bool) {
	var cur any = m
	for _, s := range segments(ptr) {
		mm, ok := cur.(map[string]any)
		if !ok || s == "*" {
			return nil, false
		}
		if cur, ok = mm[s]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// deepCopy returns an independent copy through JSON, which also gives every
// value the types a decoded API response has (float64 numbers, []any), so
// the fake and the real API look the same to the rest of the package.
func deepCopy(m map[string]any) map[string]any {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err) // only JSON-decoded values reach here
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// walkStrings calls fn for every string in v and replaces it with the result.
func walkStrings(v any, fn func(string) string) any {
	switch c := v.(type) {
	case map[string]any:
		for k, x := range c {
			c[k] = walkStrings(x, fn)
		}
		return c
	case []any:
		for i, x := range c {
			c[i] = walkStrings(x, fn)
		}
		return c
	case string:
		return fn(c)
	}
	return v
}

// walkKeyed is walkStrings that also gives the key of the map entry a
// string is under (a list's strings are under their list's key).
func walkKeyed(v any, key string, fn func(key, s string) string) any {
	switch c := v.(type) {
	case map[string]any:
		for k, x := range c {
			c[k] = walkKeyed(x, k, fn)
		}
		return c
	case []any:
		for i, x := range c {
			c[i] = walkKeyed(x, key, fn)
		}
		return c
	case string:
		return fn(key, c)
	}
	return v
}
