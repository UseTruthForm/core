package azarm

import (
	_ "embed"
	"fmt"
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
// gallery): only its ID, type and name are known.
type GraphNode struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Group      string            `json:"group,omitempty"`
	Location   string            `json:"location,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Properties map[string]any    `json:"properties,omitempty"`
	External   bool              `json:"external,omitempty"`
}

// A GraphEdge runs from the resource that holds a relationship to the one
// it names. Kind is one of:
//   - references: a field of From names To (Path is the field);
//   - child-of: From is a child resource of To (a subnet of its network);
//   - extension-of: From is attached to To (a role assignment, a lock, a
//     diagnostic setting on it);
//   - depends-on: From is created by To and must come after it.
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
	}
	var p Projection
	if err := yaml.UnmarshalStrict(b, &p); err != nil {
		return Projection{}, "", fmt.Errorf("projection %s: %w", name, err)
	}
	if p.Version != 1 {
		return Projection{}, "", fmt.Errorf("projection %s: version %d, want 1", name, p.Version)
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
// graph names no subscription.
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

	// Every object's ID, case-insensitively: Azure IDs are, and references
	// to one resource come in more than one case.
	ids := map[string]string{}      // lower(ID) -> ID of a node
	dropped := map[string]bool{}    // lower(ID) of a resource the projection leaves out
	objs := map[string]ResourceID{} // ID -> parsed
	for _, o := range s.Objects {
		rid := objectID(o, tokSub)
		id := rid.String()
		if p.of(rid.Type).Drop {
			dropped[strings.ToLower(id)] = true
			continue
		}
		ids[strings.ToLower(id)] = id
		objs[id] = rid
	}
	node := func(target string) (string, bool) {
		k := strings.ToLower(target)
		if dropped[k] {
			return "", false
		}
		if id, ok := ids[k]; ok {
			return id, true
		}
		return target, true
	}
	externals := map[string]GraphNode{}
	edges := map[GraphEdge]bool{}
	edge := func(from, to, kind, path string) {
		rid, err := ParseID(trimToResource(to))
		if err != nil {
			return
		}
		// Up to the nearest resource the snapshot holds; failing that, the
		// top-level resource, outside the snapshot.
		sub, target := "", ""
		for cur := rid; ; {
			id := cur.String()
			if t, ok := node(id); !ok {
				return // the projection leaves it out
			} else if _, known := objs[t]; known {
				target = t
				break
			}
			if cur.Scope != "" || strings.Count(cur.Type, "/") < 2 || strings.EqualFold(cur.Type, groupType) {
				target = id
				externals[strings.ToLower(id)] = GraphNode{ID: real(id), Type: cur.Type, Name: cur.Name, Group: cur.ResourceGroup, External: true}
				break
			}
			i, j := strings.LastIndex(cur.Type, "/"), strings.LastIndex(cur.Name, "/")
			sub = strings.TrimPrefix(cur.Type[i+1:]+"/"+cur.Name[j+1:]+"/"+sub, "/")
			sub = strings.TrimSuffix(sub, "/")
			cur.Type, cur.Name = cur.Type[:i], cur.Name[:j]
		}
		if strings.EqualFold(target, from) {
			return // a resource's own part (a load balancer's rule naming its pool)
		}
		edges[GraphEdge{From: real(from), To: real(target), Kind: kind, Path: path, Subresource: sub}] = true
	}

	for _, o := range s.Objects {
		rid := objectID(o, tokSub)
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
				n.Tags[k] = real(fmt.Sprint(v))
			}
		}
		for _, f := range pt.Fields {
			if v, ok := project(spec, strings.Split(f, ".")); ok {
				if n.Properties == nil {
					n.Properties = map[string]any{}
				}
				n.Properties[f] = rewriteAll(deepCopyAny(v), real)
			}
		}
		g.Nodes = append(g.Nodes, n)

		// Structure: the scope an extension is attached to, the parent of a
		// child, and what this was created after.
		switch {
		case rid.Scope != "":
			edge(id, rid.Scope, "extension-of", "")
		case strings.Count(rid.Type, "/") > 1 && !strings.EqualFold(rid.Type, groupType):
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
		// others in one string, or as a map key) or a reference token.
		refs(spec, "", func(path, v string) {
			for _, m := range graphIDRE.FindAllString(v, -1) {
				if r, err := ParseID(trimToResource(m)); err == nil {
					edge(id, r.String(), "references", path)
				}
			}
			for _, m := range refAnyRE.FindAllStringSubmatch(v, -1) {
				if to := refTarget(m[1], m[2], m[3]); to != "" {
					edge(id, to, "references", path)
				}
			}
		})
	}
	for _, n := range externals {
		g.Nodes = append(g.Nodes, n)
	}
	for e := range edges {
		g.Edges = append(g.Edges, e)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return strings.ToLower(g.Nodes[i].ID) < strings.ToLower(g.Nodes[j].ID) })
	sort.Slice(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		return a.From+"\x00"+a.To+"\x00"+a.Kind+"\x00"+a.Path < b.From+"\x00"+b.To+"\x00"+b.Kind+"\x00"+b.Path
	})
	return g
}

// graphIDRE is a resource ID in any subscription (another subscription's
// network is still a relationship), in or outside a resource group, in any
// case, stopping at a comma or a space between joined IDs.
var graphIDRE = regexp.MustCompile(`(?i)/subscriptions/[^/",;\s]+(?:/resourceGroups/[^/",;\s]+)?/providers/[^/",;\s]+(?:/[^/",;\s]+/[^/",;\s]+)+|(?i)/subscriptions/[^/",;\s]+/resourceGroups/[^/",;\s]+`)

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
			if strings.HasPrefix(k, "/") || strings.HasPrefix(k, "{{") {
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
	out := []any{}
	for _, it := range items {
		if y, ok := project(it, segs[1:]); ok {
			out = append(out, y)
		}
	}
	return out, len(out) > 0
}
