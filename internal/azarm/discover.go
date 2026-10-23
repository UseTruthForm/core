package azarm

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// extensionLists are extension types ARM lists across a whole subscription.
// The subscription's resource list returns none of them, yet in a real
// subscription they are some of the most important configuration: who may
// do what (role assignments, custom roles), what may not be deleted
// (locks), and which policies apply. Each entry is data, a path to list;
// how each item is read, normalized and restored is the same as for every
// other type.
var extensionLists = []struct {
	typ string
	// skip names items that are not this subscription's to restore.
	skip func(item map[string]any) string
}{
	{"Microsoft.Authorization/roleAssignments", nil},
	{"Microsoft.Authorization/roleDefinitions", func(item map[string]any) string {
		props, _ := item["properties"].(map[string]any)
		if t, _ := props["type"].(string); !strings.EqualFold(t, "CustomRole") {
			return builtInRole
		}
		return ""
	}},
	{"Microsoft.Authorization/locks", nil},
	{"Microsoft.Authorization/policyAssignments", nil},
}

// builtInRole is recorded as a count, not per item: a subscription lists
// several hundred built-in roles, identical in every tenant.
const builtInRole = "built-in role, the same in every tenant"

const (
	diagnosticType = "Microsoft.Insights/diagnosticSettings"
	// childDepth bounds how far below a captured resource children are
	// followed (storageAccounts/blobServices/containers is depth 2).
	childDepth = 3
)

// found is one resource read by discovery, or the reason it was not taken.
type found struct {
	c      *captured
	typ    string
	name   string
	reason string // set: skipped with this reason
	count  bool   // reason is counted in coverage only (builtInRole)
}

// discover reads what the subscription's resource list does not return:
// extension resources listed across the subscription, diagnostic settings
// on the subscription and on every tracked resource, and the children of
// every captured resource, found through the provider registrations.
func discover(ctx context.Context, api ARM, v *versions, tenant string, roots []*captured, par int) []found {
	var mu sync.Mutex
	var out []found
	add := func(f found) {
		mu.Lock()
		out = append(out, f)
		mu.Unlock()
	}
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			f()
		}()
	}
	sub := "/subscriptions/" + api.Subscription()

	for _, e := range extensionLists {
		run(func() {
			for _, f := range listOf(ctx, api, v, tenant, e.typ, sub+"/providers/"+e.typ, e.skip) {
				add(f)
			}
		})
	}
	scopes := []string{sub}
	for _, r := range roots {
		if tracked(r.rid) {
			scopes = append(scopes, r.rid.String())
		}
	}
	for _, s := range scopes {
		run(func() {
			for _, f := range listOf(ctx, api, v, tenant, diagnosticType, s+"/providers/"+diagnosticType, nil) {
				add(f)
			}
		})
	}
	var children func(parent *captured, depth int)
	children = func(parent *captured, depth int) {
		if depth > childDepth {
			return
		}
		for _, ct := range v.childTypes(parent.rid.Type) {
			coll := ct[strings.LastIndex(ct, "/")+1:]
			// A child the parent manages inline (a VNet's subnets, an
			// NSG's securityRules) is already in the parent's spec;
			// listing it too would capture it twice.
			if props, _ := parent.spec["properties"].(map[string]any); props != nil {
				if _, inline := props[coll].([]any); inline {
					continue
				}
			}
			run(func() {
				for _, f := range listOf(ctx, api, v, tenant, ct, parent.rid.String()+"/"+coll, nil) {
					add(f)
					if f.c != nil {
						children(f.c, depth+1)
					}
				}
			})
		}
	}
	for _, r := range roots {
		if !strings.EqualFold(r.rid.Type, groupType) {
			children(r, 1)
		}
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].typ+"|"+out[i].name < out[j].typ+"|"+out[j].name })
	return out
}

// listOf lists one collection and turns each item into a found. A
// collection the resource or type does not have is "none here", not an
// error; any other failure is reported, so a gap is never silent.
func listOf(ctx context.Context, api ARM, v *versions, tenant, typ, path string, skip func(map[string]any) string) []found {
	ver, err := v.pick(typ)
	if err != nil {
		if errors.Is(err, errNoVersion) {
			return nil // the subscription does not offer the type
		}
		return []found{{typ: typ, name: path, reason: Unreadable + err.Error()}}
	}
	s, err := v.reg.Schema(typ, ver)
	if err != nil {
		return []found{{typ: typ, name: path, reason: Unreadable + err.Error()}}
	}
	if !s.Writable {
		return nil // defined by Azure (defaultSecurityRules); no one can PUT it
	}
	items, err := api.List(ctx, path, ver)
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNotApplicable):
		return nil
	case err != nil:
		return []found{{typ: typ, name: path, reason: Unreadable + err.Error()}}
	}
	var out []found
	for _, item := range items {
		id, _ := item["id"].(string)
		rid, err := ParseID(id)
		if err != nil {
			// Assigned at a management group or the tenant root: inherited
			// by this subscription, not its to restore.
			out = append(out, found{typ: typ, name: id, reason: "assigned above this subscription; inherited, not restored with it"})
			continue
		}
		if !strings.EqualFold(rid.Subscription, api.Subscription()) {
			out = append(out, found{typ: typ, name: id, reason: "belongs to another subscription"})
			continue
		}
		if skip != nil {
			if why := skip(item); why != "" {
				out = append(out, found{typ: typ, name: rid.LocalName(), reason: why, count: why == builtInRole})
				continue
			}
		}
		out = append(out, found{typ: typ, name: rid.LocalName(), c: process(api, tenant, rid, ver, s, item)})
	}
	return out
}

// childTypes lists the immediate child types the subscription offers for
// a type: Microsoft.Storage/storageAccounts gives .../blobServices,
// .../fileServices, and so on, from the provider registration.
func (v *versions) childTypes(typ string) []string {
	ns := strings.ToLower(Namespace(typ))
	v.mu.Lock()
	offered, ok := v.cache[ns]
	v.mu.Unlock()
	if !ok {
		if _, err := v.pick(typ); err != nil && !errors.Is(err, errNoVersion) {
			return nil
		}
		v.mu.Lock()
		offered = v.cache[ns]
		v.mu.Unlock()
	}
	prefix := strings.ToLower(typ) + "/"
	var out []string
	for t := range offered {
		if strings.HasPrefix(t, prefix) && !strings.Contains(t[len(prefix):], "/") {
			out = append(out, typ+t[len(typ):])
		}
	}
	sort.Strings(out)
	return out
}

var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// principalRefs replaces, in every spec, a GUID that another captured
// resource generated (an identity's properties.principalId) with a
// reference restore resolves to the value the target generated. Restoring
// an identity creates a new principal with a new object ID; a role
// assignment restored with the old ID would grant access to no one.
func principalRefs(cs []*captured) {
	owners := map[string]string{} // GUID -> token
	for _, c := range cs {
		for _, k := range sortedKeys(c.status) {
			s, ok := c.status[k].(string)
			if !ok || !guidRE.MatchString(s) || k == "id" {
				continue
			}
			if _, taken := owners[strings.ToLower(s)]; !taken {
				owners[strings.ToLower(s)] = refToken(c, k)
			}
		}
	}
	if len(owners) == 0 {
		return
	}
	for _, c := range cs {
		self := refToken(c, "")
		c.spec = rewriteAll(c.spec, func(s string) string {
			if tok, ok := owners[strings.ToLower(s)]; ok && !strings.HasPrefix(tok, strings.TrimSuffix(self, "}}")) {
				return tok
			}
			return s
		}).(map[string]any)
	}
}

const refPrefix = "{{stackdna|ref|"

var refRE = regexp.MustCompile(`\{\{stackdna\|ref\|([^|{}]+)\|([^|{}]*)\|([^|{}]+)\|([^|{}]*)\}\}`)

// refToken names a value of a captured object: kind, group, name, path.
func refToken(c *captured, path string) string {
	ns := c.rid.ResourceGroup
	if strings.EqualFold(c.rid.Type, groupType) {
		ns = ""
	}
	return refPrefix + c.rid.Type + "|" + ns + "|" + c.rid.LocalName() + "|" + path + "}}"
}
