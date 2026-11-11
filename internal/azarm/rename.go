package azarm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Rename gives resources new names in a snapshot, before a restore or a
// diff: a storage account, a key vault, a container registry and many
// others have names that are unique across all of Azure, so a restore into
// another subscription fails while the source still exists. The map is
// keyed "Type/name" (Microsoft.Storage/storageAccounts/shopassets01, or
// Microsoft.Sql/servers/databases/srv/db for a child) and gives the new
// name, without its parent's. An entry renames that resource in every
// group that has one. A child is renamed with its parent (a SQL server's
// databases), and every reference to a renamed resource follows: other
// resources' IDs (also as map keys) and references, extensions on it (a
// role assignment, a lock, a diagnostic setting), and its own ID. Resource
// groups and extension resources cannot be renamed.
//
// It returns the renamed snapshot, and a warning for each object whose spec
// still mentions an old name as text outside an ID or a reference (a host
// name such as name.blob.core.windows.net): those are not changed, since
// what such text means is the resource's, not Truthform's, to know.
func Rename(s snapshot.Snapshot, names map[string]string) (snapshot.Snapshot, []string, error) {
	if len(names) == 0 {
		return s, nil, nil
	}
	m := map[string]string{} // lower("Type/name") -> new name
	for k, v := range names {
		if _, _, ok := splitKey(k); !ok || v == "" || strings.Contains(v, "/") {
			return s, nil, fmt.Errorf("rename %q: %q: want Type/name: newname, the new name without a /", k, v)
		}
		m[strings.ToLower(k)] = v
	}
	// Every entry must name a resource in the snapshot that can be renamed.
	seen := map[string]bool{}
	for _, o := range s.Objects {
		rid := objectID(o, tokSub)
		if rid.Scope != "" || rid.ResourceGroup == "" {
			continue
		}
		k := strings.ToLower(rid.Type + "/" + rid.Name)
		if strings.EqualFold(rid.Type, groupType) {
			if _, ok := m[k]; ok {
				return s, nil, fmt.Errorf("rename %s/%s: resource groups cannot be renamed", rid.Type, rid.Name)
			}
			continue
		}
		seen[k] = true
	}
	var unknown []string
	for k := range names {
		if !seen[strings.ToLower(k)] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return s, nil, fmt.Errorf("rename: not in the snapshot, or not a resource that can be renamed: %s", strings.Join(unknown, ", "))
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
		if after, _ := ann[annAfter].(string); after != "" {
			ann[annAfter] = renameID(after, m)
		}
		for _, sect := range []string{"spec", "status"} {
			if v, ok := body[sect].(map[string]any); ok {
				body[sect] = rewriteAll(v, func(v string) string { return renameText(v, m) })
			}
		}
		if w := renameDerived(objectID(o, tokSub), body, m); w != "" {
			warnings = append(warnings, w)
		}
		for k, v := range names {
			old := k[strings.LastIndex(k, "/")+1:]
			if mentions(body["spec"], old) {
				warnings = append(warnings, fmt.Sprintf("%s %s still mentions %q (renamed to %s) outside an ID or a reference; check it after the restore", o.Kind(), md["name"], old, v))
			}
		}
		out.Objects = append(out.Objects, snapshot.Object{Body: body})
	}
	// No rename may give two objects one ID (two entries given one new name,
	// or a new name another resource has); a swap is fine. A new name
	// that a resource of the type has in another group is allowed but
	// warned about: for a type whose names are unique across Azure, the
	// restore would fail.
	byKey := map[string]struct {
		was     string
		renamed bool
	}{}
	inGroups := map[string][]string{}
	for i, o := range out.Objects {
		rid, was := objectID(o, tokSub), objectID(s.Objects[i], tokSub)
		k := strings.ToLower(rid.String())
		if prev, ok := byKey[k]; ok && (prev.renamed || !strings.EqualFold(k, was.String())) {
			return s, nil, fmt.Errorf("rename: %s/%s and %s would both be %s/%s in %s", was.Type, was.Name, prev.was, rid.Type, rid.Name, rid.ResourceGroup)
		}
		byKey[k] = struct {
			was     string
			renamed bool
		}{was.Type + "/" + was.Name, !strings.EqualFold(k, was.String())}
		if rid.Scope == "" && rid.ResourceGroup != "" {
			n := strings.ToLower(rid.Type + "/" + rid.Name)
			inGroups[n] = append(inGroups[n], rid.ResourceGroup)
		}
	}
	for k, v := range names {
		typ, name, _ := splitKey(k)
		if i := strings.LastIndex(name, "/"); i >= 0 {
			v = name[:i+1] + v
		}
		gs := inGroups[strings.ToLower(typ+"/"+v)]
		sort.Strings(gs)
		if gs = slicesCompact(gs); len(gs) > 1 {
			warnings = append(warnings, fmt.Sprintf("%s: the new name %q is in more than one group (%s); a name unique across Azure cannot be", k, v, strings.Join(gs, ", ")))
		}
	}
	warnings = append(warnings, derivedTaken(out)...)
	sort.Strings(warnings)
	return out, slicesCompact(warnings), nil
}

// derivedNames are properties that hold a name unique across Azure other than
// the resource's own: an AI Services account's customSubDomainName is its
// endpoint's host name. Renamed with the account, the subdomain stayed, and a
// restore beside the source would have failed on it.
var derivedNames = map[string][]string{
	"microsoft.cognitiveservices/accounts": {"properties", "customSubDomainName"},
}

var subdomainRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// derivedTaken warns about a derived name two objects of a type now hold: a
// rename to a subdomain another account already has (review of #64).
func derivedTaken(s snapshot.Snapshot) []string {
	held := map[string][]string{}
	for _, o := range s.Objects {
		path := derivedNames[strings.ToLower(o.Kind())]
		if path == nil {
			continue
		}
		spec, _ := o.Body["spec"].(map[string]any)
		v, _ := lookup(spec, path)
		if name, _ := v.(string); name != "" {
			k := strings.ToLower(o.Kind() + "|" + name)
			held[k] = append(held[k], o.Namespace()+"/"+o.Name())
		}
	}
	var out []string
	for _, k := range sortedKeys(held) {
		if len(held[k]) > 1 {
			typ, name, _ := strings.Cut(k, "|")
			out = append(out, fmt.Sprintf("%s: %q is the %s of %s; it is unique across Azure, so a restore fails on all but one", typ, name, strings.Join(derivedNames[typ], "."), strings.Join(held[k], ", ")))
		}
	}
	return out
}

// renameDerived gives a renamed resource's derived name its new name when it
// was the old one (in the old one's case, lower or as written). One that was
// something else cannot be guessed, and is warned about.
func renameDerived(was ResourceID, body map[string]any, m map[string]string) string {
	path := derivedNames[strings.ToLower(was.Type)]
	if path == nil || was.ResourceGroup == "" || was.Scope != "" {
		return ""
	}
	newName, ok := m[strings.ToLower(was.Type+"/"+was.Name)]
	if !ok {
		return ""
	}
	parent, _ := body["spec"].(map[string]any)
	for _, k := range path[:len(path)-1] {
		parent, _ = parent[k].(map[string]any)
	}
	key := path[len(path)-1]
	cur, _ := parent[key].(string)
	switch {
	case cur == "":
		return ""
	case cur == strings.ToLower(was.Name), strings.EqualFold(cur, was.Name):
		v := newName
		if cur == strings.ToLower(was.Name) {
			v = strings.ToLower(newName)
		}
		parent[key] = v
		// An account's name may hold what a host name cannot (review of #64).
		if !subdomainRE.MatchString(v) {
			return fmt.Sprintf("%s %s: its %s became %q, which is not a valid host name (letters, digits and hyphens, not at either end); a restore fails on it", was.Type, was.Name, strings.Join(path, "."), v)
		}
	default:
		return fmt.Sprintf("%s %s: its %s %q is unique across Azure too and is not its name, so it was not renamed; a restore beside the source fails on it", was.Type, was.Name, strings.Join(path, "."), cur)
	}
	return ""
}

// splitKey splits "Namespace/type[/child...]/name[/childname...]" into the
// type and the name path: a type of n segments after the namespace has a
// name of n.
func splitKey(k string) (typ, name string, ok bool) {
	segs := strings.Split(k, "/")
	if len(segs) < 3 || len(segs)%2 == 0 {
		return "", "", false
	}
	n := (len(segs) - 1) / 2
	return strings.Join(segs[:1+n], "/"), strings.Join(segs[1+n:], "/"), true
}

// renameID renames, in one resource ID, every Type/name segment the map
// names, whatever it sits under: the resource itself, a parent of it, or
// the scope of an extension on it.
func renameID(id string, m map[string]string) string {
	parts := strings.Split(id, "/")
	for i := 0; i < len(parts); i++ {
		if !strings.EqualFold(parts[i], "providers") || i+3 >= len(parts) {
			continue
		}
		// After /providers/: namespace, then type/name pairs, until the
		// next /providers/ (an extension's own path).
		typ, name := parts[i+1], ""
		for j := i + 2; j+1 < len(parts) && !strings.EqualFold(parts[j], "providers"); j += 2 {
			typ += "/" + parts[j]
			name = strings.TrimPrefix(name+"/"+parts[j+1], "/")
			if v, ok := m[strings.ToLower(typ+"/"+name)]; ok {
				parts[j+1] = v
			}
			i = j
		}
	}
	return strings.Join(parts, "/")
}

// anyIDRE is idRE for renaming: any case (a captured ID can say
// resourcegroups), and a segment stops at a comma or a space, so IDs joined
// into one string are found one by one.
var anyIDRE = regexp.MustCompile(`(?i)/subscriptions/\{\{truthform\|subscription\}\}/resourceGroups/[^/",;\s]+(/providers/[^/",;\s]+(/[^/",;\s]+/[^/",;\s]+)+)?`)

// refAnyRE is a reference token, which names a resource by type and name.
var refAnyRE = regexp.MustCompile(`\{\{truthform\|ref\|([^|{}]+)\|([^|{}]*)\|([^|{}]+)\|([^|{}]*)\}\}`)

// renameText renames resource IDs and reference tokens inside a string.
func renameText(v string, m map[string]string) string {
	v = anyIDRE.ReplaceAllStringFunc(v, func(id string) string { return renameID(id, m) })
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
	rewriteAll(deepCopyAny(v), func(s string) string {
		rest := refAnyRE.ReplaceAllString(anyIDRE.ReplaceAllString(s, ""), "")
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
	// An extension's key is Kind/group/providers/...: its name is a path.
	for i := 2; i+1 < len(segs); i++ {
		if strings.EqualFold(segs[i+1], "providers") {
			return strings.Join(segs[:i+1], "/") + "/" + strings.TrimPrefix(renameID("/"+strings.Join(segs[i+1:], "/"), m), "/")
		}
	}
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
