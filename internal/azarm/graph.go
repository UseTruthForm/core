package azarm

import (
	_ "embed"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/stackdna/core/internal/snapshot"
)

// A Graph is a snapshot as resources and the relationships between them,
// for a tool that maps an estate (an asset inventory, a security graph)
// rather than recreates it. It is derived from the snapshot alone: no
// request is made, and since a snapshot holds no secret values, neither
// does its graph.
type Graph struct {
	Format         int         `json:"format"`
	Platform       string      `json:"platform"`
	Generator      string      `json:"generator,omitempty"`
	SnapshotDigest string      `json:"snapshotDigest,omitempty"`
	Projection     string      `json:"projection"`
	Nodes          []GraphNode `json:"nodes"`
	Edges          []GraphEdge `json:"edges"`
}

// A GraphNode is one resource. Properties holds the projection's fields,
// keyed by their path in the resource ("properties.publicNetworkAccess");
// a path through a list ("properties.securityRules[].name") gives a list.
// External is a resource something in the snapshot refers to that the
// snapshot does not hold (another subscription's network, a shared
// gallery): only its ID, type and name are known. ManagedBy is a resource
// capture left out because that resource manages it (an AKS cluster's load
// balancers and public IPs): it exists, but only its ID, type and name are
// known, so no property on it means not read, not not set.
type GraphNode struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Group      string            `json:"group,omitempty"`
	Location   string            `json:"location,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Properties map[string]any    `json:"properties,omitempty"`
	External   bool              `json:"external,omitempty"`
	ManagedBy  string            `json:"managedBy,omitempty"`
}

// A GraphEdge runs from the resource that holds a relationship to the one
// it names. Kind is one of:
//   - references: a field of From names To (Path is the field);
//   - child-of: From is a child resource of To (a subnet of its network);
//   - extension-of: From is attached to To (a role assignment, a lock, a
//     diagnostic setting on it);
//   - depends-on: From is created by To and must come after it;
//   - managed-by: capture left From out because To manages it. Not depends-on:
//     a VM manages a data disk attached to it without creating it.
//
// A reference to a part of a resource that ARM keeps inside it (a
// network's subnet, a load balancer's backend pool, a security group's
// rule) goes to that resource, and Subresource names the part
// (subnets/app).
type GraphEdge struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Kind        string `json:"kind"`
	Path        string `json:"path,omitempty"`
	Subresource string `json:"subresource,omitempty"`
}

// skippedManagedBy returns the manager's ID from a skip's reason, or "" for a
// skip of any other kind. A reason holds the ID as ARM gave it, with the real
// subscription, and nothing in the snapshot says which that is. A manager is
// assumed to be in the subscription of what it manages, as an AKS cluster is,
// so the placeholder goes in and a graph without --subscription names none.
func skippedManagedBy(reason string) string {
	for _, prefix := range []string{reasonManagedGroup, reasonManagedBy} {
		if by, ok := strings.CutPrefix(reason, prefix); ok {
			by, _, _ = strings.Cut(by, ",")
			return managerSubRE.ReplaceAllString(by, "/subscriptions/"+tokSub)
		}
	}
	return ""
}

var managerSubRE = regexp.MustCompile(`(?i)^/?subscriptions/[^/]+`)

// A Projection chooses, type by type, which fields a node carries. A type
// it does not list is a node with no properties, so relationships through
// it hold; Drop leaves a type out, with every edge to or from it.
type Projection struct {
	Version int                       `json:"version"`
	Types   map[string]ProjectionType `json:"types"`
}

type ProjectionType struct {
	Fields []string `json:"fields"`
	Drop   bool     `json:"drop"`
}

//go:embed graph_security.yaml
var securityProjection []byte

// LoadProjection reads a projection: "security" (the built-in one: network
// exposure, identity and access, encryption, public access, private
// endpoints, diagnostics), "none" (no properties, every type), or a YAML
// file in the same format.
func LoadProjection(name string, read func(string) ([]byte, error)) (Projection, string, error) {
	var b []byte
	switch name {
	case "", "security":
		b, name = securityProjection, "security"
	case "none":
		return Projection{Version: 1}, "none", nil
	default:
		var err error
		if b, err = read(name); err != nil {
			return Projection{}, "", err
		}
		// The name goes in the export, which leaves this machine; the path to
		// it says whose machine that was.
		name = path.Base(strings.ReplaceAll(name, `\`, "/"))
	}
	var p Projection
	if err := yaml.UnmarshalStrict(b, &p); err != nil {
		return Projection{}, "", fmt.Errorf("projection %s: %w", name, err)
	}
	if p.Version != 1 {
		return Projection{}, "", fmt.Errorf("projection %s: version %d, want 1", name, p.Version)
	}
	seen := map[string]string{}
	for typ, t := range p.Types {
		if prev, ok := seen[strings.ToLower(typ)]; ok {
			return Projection{}, "", fmt.Errorf("projection %s: %s and %s are one type", name, prev, typ)
		}
		seen[strings.ToLower(typ)] = typ
		if t.Drop && len(t.Fields) > 0 {
			return Projection{}, "", fmt.Errorf("projection %s: %s is dropped and has fields", name, typ)
		}
		for _, f := range t.Fields {
			for _, seg := range strings.Split(f, ".") {
				if strings.TrimSuffix(seg, "[]") == "" {
					return Projection{}, "", fmt.Errorf("projection %s: %s: field %q has an empty segment", name, typ, f)
				}
			}
		}
	}
	return p, name, nil
}

func (p Projection) of(typ string) ProjectionType {
	for k, v := range p.Types {
		if strings.EqualFold(k, typ) {
			return v
		}
	}
	return ProjectionType{}
}

// BuildGraph turns an Azure snapshot into a graph. sub and tenant, when
// given, replace the snapshot's placeholders in IDs and values, for a
// graph of the real estate; left empty, the placeholders stay, so the
// graph names none of the captured subscription's IDs (another
// subscription a resource refers to keeps its real ID either way).
func BuildGraph(s snapshot.Snapshot, p Projection, projection, sub, tenant string) Graph {
	real := func(v string) string {
		if sub != "" {
			v = strings.ReplaceAll(v, tokSub, sub)
		}
		if tenant != "" {
			v = strings.ReplaceAll(v, tokTenant, tenant)
		}
		return v
	}
	g := Graph{Format: 1, Platform: "azure", Projection: projection, Nodes: []GraphNode{}, Edges: []GraphEdge{}}

	// Every object by its ID, case-insensitively: Azure IDs are, and
	// references to one resource come in more than one case.
	ids := map[string]string{}            // lower(ID) -> ID of a held node
	dropped := map[string]bool{}          // lower(ID) of a resource the projection leaves out
	status := map[string]map[string]any{} // lower(ID) -> the values others refer to
	typeCase := map[string]string{}       // lower(type) -> the type as the snapshot spells it
	for _, o := range s.Objects {
		rid := objectID(o, tokSub)
		if !wellFormed(rid) {
			continue
		}
		id := strings.ToLower(rid.String())
		if _, ok := typeCase[strings.ToLower(rid.Type)]; !ok {
			typeCase[strings.ToLower(rid.Type)] = rid.Type
		}
		if p.of(rid.Type).Drop {
			dropped[id] = true
			continue
		}
		ids[id] = rid.String()
		status[id], _ = o.Body["status"].(map[string]any)
	}
	// What capture left out because something else makes and replaces it is
	// still running: an AKS cluster's load balancers and public IPs live in
	// its node group. Without these nodes a graph with no public IP reads as
	// nothing exposed, when the one that matters was never looked at. The
	// skip gives only type and name, so ManagedBy marks them as not read.
	var managed []GraphNode
	for _, sk := range s.Skips {
		by := skippedManagedBy(sk.Reason)
		if by == "" {
			continue
		}
		group, name, _ := strings.Cut(sk.Name, "/")
		rid := ResourceID{Subscription: tokSub, ResourceGroup: group, Type: sk.Resource, Name: name}
		if name == "" || !wellFormed(rid) {
			continue
		}
		id := strings.ToLower(rid.String())
		if ids[id] != "" {
			continue
		}
		if p.of(rid.Type).Drop {
			dropped[id] = true
			continue
		}
		ids[id] = rid.String()
		if strings.EqualFold(rid.Type, groupType) {
			group = ""
		}
		managed = append(managed, GraphNode{ID: rid.String(), Type: rid.Type, Name: name, Group: group, ManagedBy: by})
	}
	// What the snapshot does not hold, by lower(ID); of the spellings seen,
	// the least is kept, so the graph does not depend on the order seen.
	others := map[string]GraphNode{}
	other := func(id, typ, name, group string, external bool) {
		if t, ok := typeCase[strings.ToLower(typ)]; ok {
			typ = t
		}
		k := strings.ToLower(id)
		if cur, ok := others[k]; ok && cur.ID <= id {
			return
		}
		others[k] = GraphNode{ID: id, Type: typ, Name: name, Group: group, External: external}
	}
	type pending struct{ from, to, kind, path, sub string } // to is lower(ID)
	edges := map[pending]bool{}
	edge := func(from, to, kind, path string) {
		target, part := resolveTarget(to, ids, dropped, p, other)
		if target == "" || target == strings.ToLower(from) {
			return // left out, not an ID, or a resource's own part
		}
		edges[pending{from, target, kind, path, part}] = true
	}
	// A reference token's value, from the status of the resource it names:
	// a principal ID, not "{{stackdna|ref|...}}", for whatever joins on it.
	resolve := func(v string) string {
		return refAnyRE.ReplaceAllStringFunc(v, func(tok string) string {
			m := refAnyRE.FindStringSubmatch(tok)
			if to := refTarget(m[1], m[2], m[3]); to != "" {
				if x, ok := status[strings.ToLower(to)][m[4]].(string); ok && x != "" {
					return x
				}
			}
			return tok
		})
	}

	for _, o := range s.Objects {
		rid := objectID(o, tokSub)
		if !wellFormed(rid) {
			continue
		}
		pt := p.of(rid.Type)
		if pt.Drop {
			continue
		}
		id := rid.String()
		spec, _ := o.Body["spec"].(map[string]any)
		n := GraphNode{ID: real(id), Type: rid.Type, Name: rid.Name, Group: rid.ResourceGroup}
		if strings.EqualFold(rid.Type, groupType) {
			n.Group = ""
		}
		n.Location, _ = spec["location"].(string)
		if tags, ok := spec["tags"].(map[string]any); ok && len(tags) > 0 {
			n.Tags = map[string]string{}
			for k, v := range tags {
				n.Tags[real(k)] = real(resolve(fmt.Sprint(v)))
			}
		}
		for _, f := range pt.Fields {
			if v, ok := project(spec, strings.Split(f, ".")); ok {
				if n.Properties == nil {
					n.Properties = map[string]any{}
				}
				n.Properties[f] = rewriteAll(deepCopyAny(v), func(v string) string { return real(resolve(v)) })
			}
		}
		g.Nodes = append(g.Nodes, n)

		// Structure: the scope an extension is attached to, the parent of a
		// child, and what this was created after.
		switch {
		case rid.Scope != "":
			edge(id, rid.Scope, "extension-of", "")
		case extensionTypes[strings.ToLower(rid.Type)] && rid.ResourceGroup != "":
			edge(id, "/subscriptions/"+rid.Subscription+"/resourceGroups/"+rid.ResourceGroup, "extension-of", "")
		case extensionTypes[strings.ToLower(rid.Type)]:
			edge(id, "/subscriptions/"+rid.Subscription, "extension-of", "")
		case strings.Count(rid.Type, "/") > 1 && strings.Count(rid.Type, "/") == strings.Count(rid.Name, "/")+1:
			parent := rid
			parent.Type = rid.Type[:strings.LastIndex(rid.Type, "/")]
			parent.Name = rid.Name[:strings.LastIndex(rid.Name, "/")]
			edge(id, parent.String(), "child-of", "")
		}
		if ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any); ann != nil {
			if after, _ := ann[annAfter].(string); after != "" {
				edge(id, after, "depends-on", "")
			}
		}
		// Every resource the spec names: a raw ID (in any case, joined to
		// others in one string, or as a map key) or a reference token. A
		// token to who created or changed something is an observation, not
		// a relationship.
		refs(spec, "", func(path, v string) {
			for _, m := range findIDs(v) {
				edge(id, m, "references", path)
			}
			for _, m := range refAnyRE.FindAllStringSubmatch(v, -1) {
				if to := refTarget(m[1], m[2], m[3]); to != "" && !audit(m[4]) {
					edge(id, to, "references", path)
				}
			}
		})
	}
	for _, n := range managed {
		edge(n.ID, n.ManagedBy, "managed-by", "")
		if rid, err := ParseID(n.ID); err == nil && strings.Count(rid.Type, "/") > 1 && strings.Count(rid.Type, "/") == strings.Count(rid.Name, "/")+1 {
			parent := rid
			parent.Type = rid.Type[:strings.LastIndex(rid.Type, "/")]
			parent.Name = rid.Name[:strings.LastIndex(rid.Name, "/")]
			edge(n.ID, parent.String(), "child-of", "")
		}
		// As the manager's node spells it, so the two join: ARM's own spelling
		// can differ in case from the ID the graph gives that node.
		k := strings.ToLower(n.ManagedBy)
		if id := ids[k]; id != "" {
			n.ManagedBy = id
		} else if o, ok := others[k]; ok {
			n.ManagedBy = o.ID
		}
		n.ID, n.ManagedBy = real(n.ID), real(n.ManagedBy)
		g.Nodes = append(g.Nodes, n)
	}
	for _, n := range others {
		n.ID, n.Name = real(n.ID), real(n.Name)
		g.Nodes = append(g.Nodes, n)
	}
	for e := range edges {
		to := ids[e.to]
		if to == "" {
			to = others[e.to].ID
		}
		g.Edges = append(g.Edges, GraphEdge{From: real(e.from), To: real(to), Kind: e.kind, Path: e.path, Subresource: e.sub})
	}
	sort.Slice(g.Nodes, func(i, j int) bool {
		a, b := strings.ToLower(g.Nodes[i].ID), strings.ToLower(g.Nodes[j].ID)
		return a < b || a == b && g.Nodes[i].ID < g.Nodes[j].ID
	})
	sort.Slice(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		return a.From+"\x00"+a.To+"\x00"+a.Kind+"\x00"+a.Path+"\x00"+a.Subresource < b.From+"\x00"+b.To+"\x00"+b.Kind+"\x00"+b.Path+"\x00"+b.Subresource
	})
	return g
}

// wellFormed reports an ID whose type and name match segment for segment:
// an object without its ID annotation can have a child's kind and a bare
// name, which would make a node with its parent's ID.
func wellFormed(rid ResourceID) bool {
	return strings.EqualFold(rid.Type, groupType) || strings.Count(rid.Type, "/") == strings.Count(rid.Name, "/")+1
}

// extensionTypes are attached to whatever scope they sit at: a lock or a
// role assignment on a group or the subscription is that scope's.
var extensionTypes = map[string]bool{
	"microsoft.authorization/locks":             true,
	"microsoft.authorization/roleassignments":   true,
	"microsoft.authorization/policyassignments": true,
	"microsoft.authorization/policyexemptions":  true,
	"microsoft.insights/diagnosticsettings":     true,
}

// resolveTarget finds the node an ID found in a spec is, as lower(ID), and
// the part of it the ID names: the nearest resource the snapshot holds,
// going up from a part ARM keeps inside one (a subnet); or failing that,
// the resource outside the snapshot, recorded by other. "" when the ID is
// not one, or names something the projection leaves out.
func resolveTarget(to string, ids map[string]string, dropped map[string]bool, p Projection, other func(id, typ, name, group string, external bool)) (string, string) {
	if strings.HasPrefix(strings.ToLower(to), "/providers/") {
		// Tenant level: a built-in role or policy definition, a management
		// group.
		segs := strings.Split(strings.Trim(to, "/"), "/")
		i := len(segs) - 1
		for i > 0 && !strings.EqualFold(segs[i], "providers") {
			i--
		}
		rest := segs[i+1:]
		if len(rest) < 3 || len(rest)%2 == 0 {
			return "", ""
		}
		typ, name := rest[0], ""
		for j := 1; j+1 < len(rest); j += 2 {
			typ += "/" + rest[j]
			name = strings.TrimPrefix(name+"/"+rest[j+1], "/")
		}
		if p.of(typ).Drop {
			return "", ""
		}
		id := "/" + strings.Join(segs, "/")
		if strings.EqualFold(typ, "Microsoft.Authorization/roleDefinitions") && i == 0 {
			// A role definition is one by either form; role assignments use
			// the subscription's.
			return resolveTarget("/subscriptions/"+tokSub+id, ids, dropped, p, other)
		}
		other(id, typ, name, "", true)
		return strings.ToLower(id), ""
	}
	if m := subscriptionRE.FindStringSubmatch(to); m != nil {
		id := "/subscriptions/" + m[1]
		other(id, "Microsoft.Resources/subscriptions", m[1], "", m[1] != tokSub)
		return strings.ToLower(id), ""
	}
	rid, err := ParseID(trimToResource(to))
	if err != nil {
		return "", ""
	}
	part := ""
	for cur := rid; ; {
		id := cur.String()
		k := strings.ToLower(id)
		if dropped[k] || p.of(cur.Type).Drop {
			return "", "" // the projection leaves it out
		}
		if _, held := ids[k]; held {
			return k, part
		}
		if cur.Scope != "" || strings.Count(cur.Type, "/") < 2 || strings.EqualFold(cur.Type, groupType) ||
			strings.Count(cur.Type, "/") != strings.Count(cur.Name, "/")+1 {
			group := cur.ResourceGroup
			if strings.EqualFold(cur.Type, groupType) {
				group = ""
			}
			other(id, cur.Type, cur.Name, group, true)
			return k, part
		}
		i, j := strings.LastIndex(cur.Type, "/"), strings.LastIndex(cur.Name, "/")
		part = strings.TrimSuffix(cur.Type[i+1:]+"/"+cur.Name[j+1:]+"/"+part, "/")
		cur.Type, cur.Name = cur.Type[:i], cur.Name[:j]
	}
}

// IsGUID reports a subscription or tenant ID's form.
func IsGUID(s string) bool { return guidRE.MatchString(s) }

var subscriptionRE = regexp.MustCompile(`(?i)^/subscriptions/([^/]+)/?$`)

// graphIDRE is a resource ID: in any subscription (another subscription's
// network is still a relationship), in or outside a resource group, or at
// tenant level (a built-in role definition); in any case. A segment stops
// where an ID in text does: at a separator between joined IDs, a quote,
// a URL's query, a bracket.
var graphIDRE = regexp.MustCompile(`(?i)` +
	`/subscriptions/(?:\{\{stackdna\|subscription\}\}|` + idSeg + `+)(?:/resourceGroups/` + idSeg + `+)?/providers/` + idSeg + `+(?:/` + idSeg + `+/` + idSeg + `+)+` +
	`|/subscriptions/(?:\{\{stackdna\|subscription\}\}|` + idSeg + `+)/resourceGroups/` + idSeg + `+` +
	`|/providers/Microsoft\.(?:Authorization|Management)/` + idSeg + `+/` + idSeg + `+(?:/` + idSeg + `+/` + idSeg + `+)*`)

// findIDs is every resource ID in a string, outside reference tokens (an
// extension's token holds providers/... text that is no ID of its own),
// each starting where a word does, not inside a longer path.
func findIDs(v string) []string {
	v = refAnyRE.ReplaceAllString(v, " ")
	var out []string
	for _, m := range graphIDRE.FindAllStringIndex(v, -1) {
		if i := m[0]; i > 0 && !urlBeforeRE.MatchString(v[:i]) && (v[i-1] == '/' || v[i-1] == '_' || v[i-1] == '-' || v[i-1] == '.' ||
			'a' <= v[i-1] && v[i-1] <= 'z' || 'A' <= v[i-1] && v[i-1] <= 'Z' || '0' <= v[i-1] && v[i-1] <= '9') {
			continue
		}
		out = append(out, v[m[0]:m[1]])
	}
	return out
}

// urlBeforeRE is what may come right before an ID in a URL: a host
// (https://management.azure.com/subscriptions/...) or the portal's
// /resource path.
var urlBeforeRE = regexp.MustCompile(`(?i)(?:https?://[^/\s"']+|/resource)$`)

const idSeg = `[^/"',;\s?#()\[\]{}<>|]`

// refTarget is the ID a reference token names: its type, group and name,
// where an extension's name is its path below the group.
func refTarget(typ, rg, name string) string {
	base := "/subscriptions/" + tokSub
	if rg != "" {
		base += "/resourceGroups/" + rg
	}
	if strings.HasPrefix(name, "providers/") {
		return base + "/" + name
	}
	if strings.EqualFold(typ, groupType) {
		return "/subscriptions/" + tokSub + "/resourceGroups/" + name
	}
	r := ResourceID{Subscription: tokSub, ResourceGroup: rg, Type: typ, Name: name}
	if strings.Count(typ, "/") != strings.Count(name, "/")+1 {
		return ""
	}
	return r.String()
}

// refs calls fn with every string in v and every map key, and the field's
// path: a.b for a key, a[] for a list's elements, a{} for a map's keys.
func refs(v any, path string, fn func(path, v string)) {
	join := func(k string) string {
		if path == "" {
			return k
		}
		return path + "." + k
	}
	switch c := v.(type) {
	case map[string]any:
		for k, x := range c {
			if strings.HasPrefix(k, "/") || strings.HasPrefix(k, "{{") || strings.Contains(strings.ToLower(k), "/subscriptions/") {
				fn(path+"{}", k)
			}
			refs(x, join(k), fn)
		}
	case []any:
		for _, x := range c {
			refs(x, path+"[]", fn)
		}
	case string:
		fn(path, c)
	}
}

// project reads one projection path from a spec. A segment ending in []
// goes through every element of a list, and the result is the list of
// what each element holds there.
func project(v any, segs []string) (any, bool) {
	if len(segs) == 0 {
		return v, v != nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	seg := segs[0]
	list := strings.HasSuffix(seg, "[]")
	x, ok := m[strings.TrimSuffix(seg, "[]")]
	if !ok {
		return nil, false
	}
	if !list {
		return project(x, segs[1:])
	}
	items, ok := x.([]any)
	if !ok {
		return nil, false
	}
	// One entry per element, null where an element lacks the field, so
	// two fields of one list (x[].name, x[].sshAccess) line up.
	out, found := make([]any, len(items)), false
	for i, it := range items {
		if y, ok := project(it, segs[1:]); ok {
			out[i], found = y, true
		}
	}
	return out, found
}
