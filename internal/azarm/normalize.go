package azarm

import (
	"encoding/json"
	"sort"
)

// envelope keys ARM returns on every resource that are not configuration.
// They are dropped by name because some definitions do not mark them
// read-only: systemData (who changed it and when) differs on every write
// and would be drift in every diff; name, id and type are the identity,
// which the snapshot keeps in metadata.
var envelope = map[string]bool{"id": true, "name": true, "type": true, "systemData": true, "etag": true, "apiVersion": true}

// serverSet are properties ARM's resource-provider contract has the server
// set wherever they appear. When a definition does not declare one, it is
// still read-only: the first real drill (2026-10-21) diffed a restored VNet
// on subnets[0].properties.resourceGuid, which Azure returns but the subnet
// definition (2026-03-01) does not declare. Any other undeclared field is
// kept, see normalize.
var serverSet = map[string]bool{"provisioningState": true, "resourceGuid": true}

// split is what normalize removed from a resource body.
type split struct {
	readOnly map[string]any // scalar read-only values by dotted path, for people
	secrets  []string       // paths of properties Azure never returns
}

// normalize returns the configured part of a GET response, walking it
// together with the type definition: read-only values are removed (scalars
// are kept in split.readOnly), secret and write-only values are removed and
// their paths listed. A property the definition does not know is kept: an
// API returning a field its definition lacks is newer than the definition,
// and dropping the field would lose configuration without a word.
func (s *Schema) normalize(body map[string]any) (map[string]any, split) {
	sp := split{readOnly: map[string]any{}}
	spec := deepCopy(body)
	for k := range envelope {
		delete(spec, k)
	}
	s.clean(spec, s.body, "", &sp)
	sort.Strings(sp.secrets)
	return spec, sp
}

func (s *Schema) clean(v any, t int, path string, sp *split) {
	switch c := v.(type) {
	case map[string]any:
		props, add, ok := s.object(t, c)
		if !ok {
			return
		}
		for _, k := range sortedKeys(c) {
			p, known := props[k]
			full := join(path, k)
			switch {
			case !known && add != nil:
				s.clean(c[k], add.index(), join(path, "*"), sp)
			case !known && serverSet[k]:
				if isScalar(c[k]) {
					sp.readOnly[full] = c[k]
				}
				delete(c, k)
			case !known:
				// kept, see normalize
			case p.Flags&flagReadOnly != 0:
				// A read-only object (a managed identity's whole properties
				// block) keeps its scalars for status. Dropping them lost
				// the identity's principalId, so a role assignment for it
				// could never be remapped to the restored identity.
				recordScalars(c[k], full, sp)
				delete(c, k)
			case s.secret(p):
				sp.secrets = append(sp.secrets, full)
				delete(c, k)
			default:
				before := -1
				if m, ok := c[k].(map[string]any); ok {
					before = len(m)
				}
				s.clean(c[k], p.Type.index(), full, sp)
				// An object emptied by stripping (properties whose every
				// field is read-only) is removed, so a restore does not send
				// an empty object Azure never received. One that arrived
				// empty is kept as it was.
				if m, ok := c[k].(map[string]any); ok && before > 0 && len(m) == 0 {
					delete(c, k)
				}
			}
		}
	case []any:
		if e := s.file[t]; e.Kind == "ArrayType" && e.ItemType != nil {
			for _, x := range c {
				s.clean(x, e.ItemType.index(), path+"[]", sp)
			}
		}
	}
}

// secretPaths lists every secret property the definition declares at any
// depth reachable from the body, whether or not a value is present. These
// are what a restore must be given; Azure returns none of them.
func (s *Schema) secretPaths() []string {
	var out []string
	var walk func(i int, prefix string, depth int, seen map[int]bool)
	walk = func(i int, prefix string, depth int, seen map[int]bool) {
		if seen[i] || depth > maxDepth {
			return
		}
		seen = copySet(seen)
		seen[i] = true
		e := s.file[i]
		if e.Kind == "ArrayType" && e.ItemType != nil {
			walk(e.ItemType.index(), prefix+"[]", depth+1, seen)
			return
		}
		props, _, ok := s.object(i, nil)
		if !ok {
			return
		}
		for _, k := range sortedKeys(props) {
			p := props[k]
			if p.Flags&flagReadOnly != 0 {
				continue
			}
			if s.secret(p) {
				out = append(out, join(prefix, k))
				continue
			}
			walk(p.Type.index(), join(prefix, k), depth+1, seen)
		}
	}
	walk(s.body, "", 0, map[int]bool{})
	sort.Strings(out)
	return out
}

// recordScalars keeps every scalar under v by dotted path. Arrays are not
// followed: their positions are not stable names.
func recordScalars(v any, path string, sp *split) {
	if isScalar(v) {
		sp.readOnly[path] = v
		return
	}
	if m, ok := v.(map[string]any); ok {
		for _, k := range sortedKeys(m) {
			recordScalars(m[k], join(path, k), sp)
		}
	}
}

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

// rewriteAll is walkStrings for map keys too. Azure keys some maps by
// resource ID (a site's identity.userAssignedIdentities), so a subscription
// left in a key would point a restored resource at the source subscription.
func rewriteAll(v any, fn func(string) string) any {
	switch c := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(c))
		for k, x := range c {
			out[fn(k)] = rewriteAll(x, fn)
		}
		return out
	case []any:
		for i, x := range c {
			c[i] = rewriteAll(x, fn)
		}
		return c
	case string:
		return fn(c)
	}
	return v
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
