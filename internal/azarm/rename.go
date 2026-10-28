package azarm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/snapshot"
)

// Rename gives resources new names in a snapshot, before a restore or a
// diff: a storage account, a key vault, a container registry and many
// others have names that are unique across all of Azure, so a restore into
// another subscription fails while the source still exists. The map is
// keyed "Type/name" (Microsoft.Storage/storageAccounts/shopassets01) and
// gives the new name. A child is renamed with its parent (a SQL server's
// databases), and every reference to a renamed resource follows: other
// resources' IDs and references, extensions on it (a role assignment, a
// lock, a diagnostic setting), and its own ID.
//
// It returns the renamed snapshot, and a warning for each object whose spec
// still mentions an old name as text outside an ID or a reference (a host
// name such as name.blob.core.windows.net): those are not changed, since
// what such text means is the resource's, not StackDNA's, to know.
func Rename(s snapshot.Snapshot, names map[string]string) (snapshot.Snapshot, []string, error) {
	if len(names) == 0 {
		return s, nil, nil
	}
	m := map[string]string{} // lower("Type/name") -> new name
	for k, v := range names {
		i := strings.LastIndex(k, "/")
		if i <= 0 || v == "" || strings.Contains(v, "/") {
			return s, nil, fmt.Errorf("rename %q: %q: want Type/name: newname, the new name without a /", k, v)
		}
		m[strings.ToLower(k)] = v
	}
	// Every entry must name a resource in the snapshot, and no new name may
	// already be taken by another resource of its type in its group.
	seen := map[string]bool{}
	taken := map[string]bool{}
	for _, o := range s.Objects {
		rid := objectID(o, tokSub)
		if rid.Scope != "" {
			continue
		}
		seen[strings.ToLower(rid.Type+"/"+rid.Name)] = true
		taken[strings.ToLower(rid.ResourceGroup+"|"+rid.Type+"/"+rid.Name)] = true
	}
	var unknown []string
	for k := range names {
		if !seen[strings.ToLower(k)] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return s, nil, fmt.Errorf("rename: not in the snapshot: %s", strings.Join(unknown, ", "))
	}
	for _, o := range s.Objects {
		rid := objectID(o, tokSub)
		if v, ok := m[strings.ToLower(rid.Type+"/"+rid.Name)]; ok && rid.Scope == "" && taken[strings.ToLower(rid.ResourceGroup+"|"+rid.Type+"/"+v)] {
			return s, nil, fmt.Errorf("rename %s/%s to %s: the snapshot already has a %s of that name in %s", rid.Type, rid.Name, v, rid.Type, rid.ResourceGroup)
		}
	}

	out := snapshot.Snapshot{Platform: s.Platform, ServerVersion: s.ServerVersion, Policy: s.Policy, Coverage: s.Coverage, Skips: s.Skips, Schemas: s.Schemas}
	var warnings []string
	for _, o := range s.Objects {
		body := deepCopy(o.Body)
		md, _ := body["metadata"].(map[string]any)
		ann, _ := md["annotations"].(map[string]any)
		if id, _ := ann[annID].(string); id != "" {
			newID := renameID(id, m)
			ann[annID] = newID
			if rid, err := ParseID(newID); err == nil {
				md["name"] = rid.LocalName()
			}
		}
		for _, sect := range []string{"spec", "status"} {
			if v, ok := body[sect].(map[string]any); ok {
				body[sect] = walkStrings(v, func(v string) string { return renameText(v, m) })
			}
		}
		for k, v := range names {
			old := k[strings.LastIndex(k, "/")+1:]
			if mentions(body["spec"], old) {
				warnings = append(warnings, fmt.Sprintf("%s %s still mentions %q (renamed to %s) outside an ID or a reference; check it after the restore", o.Kind(), md["name"], old, v))
			}
		}
		out.Objects = append(out.Objects, snapshot.Object{Body: body})
	}
	sort.Strings(warnings)
	return out, slicesCompact(warnings), nil
}

// renameID renames, in one resource ID, every Type/name segment the map
// names, whatever it sits under: the resource itself, a parent of it, or
// the scope of an extension on it.
func renameID(id string, m map[string]string) string {
	parts := strings.Split(id, "/")
	typ := ""
	for i := 0; i < len(parts); i++ {
		if !strings.EqualFold(parts[i], "providers") || i+3 >= len(parts) {
			continue
		}
		// After /providers/: namespace, then type/name pairs, until the
		// next /providers/ (an extension's own path).
		typ = parts[i+1]
		for j := i + 2; j+1 < len(parts) && !strings.EqualFold(parts[j], "providers"); j += 2 {
			typ += "/" + parts[j]
			if v, ok := m[strings.ToLower(typ+"/"+parts[j+1])]; ok {
				parts[j+1] = v
			}
			i = j
		}
	}
	return strings.Join(parts, "/")
}

// refAnyRE is a reference token, which names a resource by type and name.
var refAnyRE = regexp.MustCompile(`\{\{stackdna\|ref\|([^|{}]+)\|([^|{}]*)\|([^|{}]+)\|([^|{}]*)\}\}`)

// renameText renames resource IDs and reference tokens inside a string.
func renameText(v string, m map[string]string) string {
	v = idRE.ReplaceAllStringFunc(v, func(id string) string { return renameID(id, m) })
	return refAnyRE.ReplaceAllStringFunc(v, func(tok string) string {
		g := refAnyRE.FindStringSubmatch(tok)
		typ, rg, name, path := g[1], g[2], g[3], g[4]
		ns, rest, _ := strings.Cut(typ, "/")
		types, names := strings.Split(rest, "/"), strings.Split(name, "/")
		if strings.HasPrefix(name, "providers/") {
			// An extension's name is a path below its scope
			// (providers/.../storageAccounts/x/providers/.../roleAssignments/y).
			return refPrefix + typ + "|" + rg + "|" + strings.TrimPrefix(renameID("/"+name, m), "/") + "|" + path + "}}"
		}
		if len(types) != len(names) {
			return tok
		}
		id := "/providers/" + ns
		for i := range types {
			id += "/" + types[i] + "/" + names[i]
		}
		renamed := strings.Split(renameID(id, m), "/")
		var out []string
		for i := range names {
			out = append(out, renamed[3+2*i+1])
		}
		return refPrefix + typ + "|" + rg + "|" + strings.Join(out, "/") + "|" + path + "}}"
	})
}

// mentions reports a string in v, other than an ID or a reference, that
// contains name as a word.
func mentions(v any, name string) bool {
	word := regexp.MustCompile(`(?i)(^|[^A-Za-z0-9-])` + regexp.QuoteMeta(name) + `([^A-Za-z0-9-]|$)`)
	found := false
	walkStrings(deepCopyAny(v), func(s string) string {
		rest := refAnyRE.ReplaceAllString(idRE.ReplaceAllString(s, ""), "")
		if word.MatchString(rest) {
			found = true
		}
		return s
	})
	return found
}

func deepCopyAny(v any) any {
	if m, ok := v.(map[string]any); ok {
		return deepCopy(m)
	}
	return v
}

func slicesCompact(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// RenameValues renames the keys of a --values file ("Kind/resourceGroup/
// name") as Rename renames the resources, so the file can be written with
// the names the snapshot has.
func RenameValues(values map[string]map[string]any, names map[string]string) map[string]map[string]any {
	if len(names) == 0 || values == nil {
		return values
	}
	m := map[string]string{}
	for k, v := range names {
		m[strings.ToLower(k)] = v
	}
	out := map[string]map[string]any{}
	for k, v := range values {
		out[renameValueKey(k, m)] = v
	}
	return out
}

// renameValueKey renames one "Kind/resourceGroup/name" key. The kind is
// Namespace/type[/child...], so the group is the segment after the kind
// whose types match the name's segments one for one.
func renameValueKey(k string, m map[string]string) string {
	segs := strings.Split(k, "/")
	for i := 2; i < len(segs)-1; i++ {
		kind, rg, name := segs[:i], segs[i], segs[i+1:]
		if len(kind)-1 != len(name) {
			continue
		}
		id := "/subscriptions/x/resourceGroups/" + rg + "/providers/" + kind[0]
		for j, n := range name {
			id += "/" + kind[j+1] + "/" + n
		}
		if rid, err := ParseID(renameID(id, m)); err == nil {
			return strings.Join(kind, "/") + "/" + rg + "/" + rid.LocalName()
		}
	}
	return k
}
