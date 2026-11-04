package azarm

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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
		// Only what says it is Azure's: one with no type at all is captured, since
		// nothing is recorded of what is skipped here, and it would vanish.
		if t, _ := props["type"].(string); strings.EqualFold(t, "BuiltInRole") {
			return builtInRole
		}
		return ""
	}},
	{"Microsoft.Authorization/locks", nil},
	{"Microsoft.Authorization/policyAssignments", nil},
	// An assignment of a custom policy was restored with nothing to point at.
	// Asked for by filter: a subscription lists thousands of Azure's own.
	{"Microsoft.Authorization/policyDefinitions?$filter=policyType%20eq%20%27Custom%27", nil},
	{"Microsoft.Authorization/policySetDefinitions?$filter=policyType%20eq%20%27Custom%27", nil},
}

// builtInRole marks Azure's own roles, which a subscription lists by the
// hundred, identical in every tenant. Capture records none of them: see Capture.
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
func discover(ctx context.Context, api ARM, v *versions, tenant string, roots []*captured, par int, leftOut map[string]bool) []found {
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
			typ, _, _ := strings.Cut(e.typ, "?")
			for _, f := range listOf(ctx, api, v, tenant, typ, sub+"/providers/"+e.typ, e.skip) {
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
	// A resource can be both a root and another root's child (a SQL
	// database is tracked and its server's child). Its children are listed
	// once, from the root: listed twice, every failure among them was
	// reported twice, and every call made twice. Roots are marked before
	// any walk starts, so which walk reaches one first does not matter.
	rootIDs := map[string]bool{}
	for _, r := range roots {
		rootIDs[strings.ToLower(r.rid.String())] = true
	}
	var children func(parent *captured, depth int)
	children = func(parent *captured, depth int) {
		if depth > childDepth || (depth > 1 && rootIDs[strings.ToLower(parent.rid.String())]) {
			return
		}
		cts, err := v.childTypes(parent.rid.Type)
		if err != nil {
			// Nothing below the parent is read: said, so a gap is never silent.
			add(found{typ: parent.rid.Type, name: parent.rid.LocalName(), reason: Unreadable + "its child types could not be read: " + err.Error()})
			return
		}
		inlined := inlineCollections(parent)
		for _, ct := range cts {
			coll := ct[strings.LastIndex(ct, "/")+1:]
			// A child the parent manages inline (a VNet's subnets, an
			// NSG's securityRules, a cluster's agent pools) is already in
			// the parent's spec; listing it too would capture it twice.
			// A network's peerings are made their own objects from its
			// GET: listed again, a failed list was a gap for what the
			// snapshot held (review of #63).
			// A registered child is skipped only as it was before children
			// came from definitions: its collection under its registered
			// spelling. Matched more widely, ones read on their own before
			// (an NSG's securityRules) would have left every snapshot that
			// had them (review of #63).
			if strings.EqualFold(ct, vnetType+"/virtualNetworkPeerings") {
				continue
			}
			if v.registered(ct) {
				if props, _ := parent.spec["properties"].(map[string]any); props != nil {
					if _, inline := props[coll].([]any); inline {
						continue
					}
				}
			} else if inlined[strings.ToLower(coll)] {
				continue
			}
			run(func() {
				for _, f := range listOf(ctx, api, v, tenant, ct, parent.rid.String()+"/"+coll, childSkip) {
					// Left out as what something else manages, and reached
					// again as a child: a SQL server's master database was
					// skipped and captured both, with its own children.
					if f.c != nil && leftOut[strings.ToLower(f.c.rid.String())] {
						continue
					}
					add(f)
					if f.c == nil {
						continue
					}
					children(f.c, depth+1)
					if ownDiagnostics[strings.ToLower(f.typ)] {
						scope := f.c.rid.String()
						run(func() {
							for _, d := range listOf(ctx, api, v, tenant, diagnosticType, scope+"/providers/"+diagnosticType, nil) {
								add(d)
							}
						})
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

// ownDiagnostics are children with diagnostic settings of their own. A storage
// account's logs are set on its blob, file, queue and table services, not on the
// account: the settings were never read, and nothing said so.
var ownDiagnostics = map[string]bool{
	"microsoft.storage/storageaccounts/blobservices":  true,
	"microsoft.storage/storageaccounts/fileservices":  true,
	"microsoft.storage/storageaccounts/queueservices": true,
	"microsoft.storage/storageaccounts/tableservices": true,
	"microsoft.sql/servers/databases":                 true,
}

// childSkip names children something else makes, seen on a real estate. A
// private endpoint connection comes when its endpoint is created, and a record a
// DNS zone group wrote comes when that is. Restored, the first has no endpoint
// to name and its name holds the old endpoint's GUID, and the second holds the
// old network's address.
func childSkip(item map[string]any) string {
	typ, _ := item["type"].(string)
	if why := superseded[strings.ToLower(typ)]; why != "" {
		return why
	}
	if strings.HasSuffix(strings.ToLower(typ), "/privateendpointconnections") {
		return "made when its private endpoint is created"
	}
	props, _ := item["properties"].(map[string]any)
	// Azure's own content filters (Microsoft.Default, Microsoft.DefaultV2),
	// on every AI Services account, made with it and refused a PUT.
	if t, _ := props["type"].(string); strings.EqualFold(t, "SystemManaged") {
		return systemManaged
	}
	md, _ := props["metadata"].(map[string]any)
	if c, _ := md["creator"].(string); strings.HasPrefix(c, "created by private endpoint ") {
		return "written by a private endpoint's DNS zone group, which writes it again with the new address"
	}
	return ""
}

const systemManaged = "Azure's own, made with its parent"

// superseded are child types Azure still answers for with a retired API's view
// of what a newer type holds: a SQL server's auditingPolicies (table auditing,
// 2014-04-01) show the state its auditingSettings already capture.
var superseded = map[string]string{
	"microsoft.sql/servers/auditingpolicies":           "retired table auditing; the same state is in auditingSettings",
	"microsoft.sql/servers/databases/auditingpolicies": "retired table auditing; the same state is in auditingSettings",
}

// issuerRefs turns a federated credential's issuer into a reference to the
// cluster it names. It is a plain setting, so it was restored as it was: it went
// on trusting the source cluster, the target's workloads could not sign in, and
// a diff was clean. One naming a cluster outside the snapshot stays as it is.
func issuerRefs(cs []*captured) {
	const issuerPath = "properties.oidcIssuerProfile.issuerURL"
	clusters := map[string]*captured{}
	for _, c := range cs {
		if strings.EqualFold(c.rid.Type, managedClusterType) {
			if u, _ := c.status[issuerPath].(string); u != "" {
				clusters[u] = c
			}
		}
	}
	for _, c := range cs {
		if !strings.EqualFold(c.rid.Type, federatedCredentialType) {
			continue
		}
		props, _ := c.spec["properties"].(map[string]any)
		if issuer, _ := props["issuer"].(string); clusters[issuer] != nil {
			props["issuer"] = refToken(clusters[issuer], issuerPath)
		}
	}
}

// listOf lists one collection and turns each item into a found. A
// collection the resource or type does not have is "none here", not an
// error; any other failure is reported, so a gap is never silent.
func listOf(ctx context.Context, api ARM, v *versions, tenant, typ, path string, skip func(map[string]any) string) []found {
	ver, err := v.pick(typ)
	if err != nil {
		// A type the registration offers, with no version defined, is one
		// the subscription does not offer us. A child it does not list is
		// read at its parent's versions; with none of those defined for it,
		// it went unread with no word, beside a parent that may have some
		// (review of beta.14).
		if errors.Is(err, errNoVersion) && v.registered(typ) {
			return nil
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
	// Refused for its version at this scope: the others are tried, and the
	// one that answers is the version these items are read and restored
	// at. Before, the refusal read as "none here" and the subscription's
	// diagnostic settings were never checked.
	if errors.Is(err, ErrAPIVersion) {
		for _, alt := range v.all(typ) {
			if alt == ver {
				continue
			}
			if items, err = api.List(ctx, path, alt); !errors.Is(err, ErrAPIVersion) {
				ver = alt
				if s, err = v.reg.Schema(typ, ver); err != nil {
					return []found{{typ: typ, name: path, reason: Unreadable + err.Error()}}
				}
				break
			}
		}
	}
	// Listed only one kind at a time (a Log Analytics workspace's data
	// sources): each kind the definition names is listed on its own.
	// Before, the whole collection read as failed.
	generated := 0
	if errors.Is(err, ErrNeedsKind) {
		items, generated, err = listByKind(ctx, api, path, ver, s.kinds(), !v.registered(typ))
	}
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNotApplicable):
		return nil
	// Read only because it has a definition: a 400 says this resource does
	// not serve it, and before, it was not read at all.
	case errors.Is(err, ErrBadRequest) && !v.registered(typ):
		return nil
	case err != nil:
		return []found{{typ: typ, name: path, reason: Unreadable + err.Error()}}
	}
	var out []found
	for range generated {
		out = append(out, found{typ: typ, name: path, reason: generatedEachRead, count: true})
	}
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

// generatedEachRead is counted in coverage, not listed: the items have a new
// name every time they are read.
const generatedEachRead = "generated by Azure on every read: a new name each time, so no one made it, and it cannot be restored or compared"

// listByKind lists a collection once per kind, with ARM's
// $filter=kind eq '…'. A kind the collection cannot hold is none here; any
// other refusal fails the collection, so a gap is never silent.
//
// What a real workspace does, each handled here: several kinds the
// definition names are refused (501 DataSourceNotImplemented, or
// KindNotSpecified again for Office365); some filters return another
// kind's items (ChangeTrackingRegistry returns the
// ChangeTrackingDefaultRegistry ones), so an item of another named kind is
// left to that kind's own list, and each item is kept once; and some items
// are made up on every read, with a new GUID in their name each time (the
// change-tracking default registry keys), and a GET by that name answers
// Not Found. Each kind that returned anything is read again, and once more
// if anything was missing: an item from the first read is kept if either
// later read has it, so a list that lags once does not drop real
// configuration (review of #34); one in neither is counted as generated.
//
// For a type read only because it has a definition, a 400 for one kind is
// none of that kind, as it is for the whole list in listOf: the kinds that
// answered are kept (review of #63).
func listByKind(ctx context.Context, api ARM, path, ver string, kinds []string, unlisted bool) (items []map[string]any, generated int, err error) {
	if len(kinds) == 0 {
		return nil, 0, fmt.Errorf("%s: %w, and the definition names no kinds", path, ErrNeedsKind)
	}
	read := func(k string) ([]map[string]any, error) {
		// %20, not +: an OData filter is not form data.
		got, err := api.List(ctx, path+"?$filter="+strings.ReplaceAll(url.QueryEscape("kind eq '"+k+"'"), "+", "%20"), ver)
		switch {
		case errors.Is(err, ErrNotFound), errors.Is(err, ErrNotApplicable), errors.Is(err, ErrNeedsKind),
			unlisted && errors.Is(err, ErrBadRequest):
			return nil, nil
		case err != nil:
			return nil, fmt.Errorf("kind %s: %w", k, err)
		}
		return got, nil
	}
	idOf := func(item map[string]any) string { id, _ := item["id"].(string); return strings.ToLower(id) }
	named := map[string]bool{}
	for _, k := range kinds {
		named[strings.ToLower(k)] = true
	}
	seen := map[string]bool{}
	for _, k := range kinds {
		var first []map[string]any
		got, err := read(k)
		if err != nil {
			return nil, 0, err
		}
		for _, item := range got {
			// Another named kind's item, returned by this filter too: that
			// kind's own list keeps or counts it, once.
			if ik, _ := item["kind"].(string); ik != "" && !strings.EqualFold(ik, k) && named[strings.ToLower(ik)] {
				continue
			}
			first = append(first, item)
		}
		if len(first) == 0 {
			continue
		}
		again := map[string]bool{}
		for n := 0; n < 2; n++ {
			later, err := read(k)
			if err != nil {
				return nil, 0, err
			}
			for _, item := range later {
				again[idOf(item)] = true
			}
			missing := false
			for _, item := range first {
				missing = missing || !again[idOf(item)]
			}
			if !missing {
				break
			}
		}
		for _, item := range first {
			id := idOf(item)
			switch {
			case seen[id]:
			case !again[id]:
				generated++
			default:
				seen[id] = true
				items = append(items, item)
			}
		}
	}
	return items, generated, nil
}

// childTypes lists the immediate child types of a type: those the provider
// registration offers (Microsoft.Storage/storageAccounts gives
// .../blobServices, .../fileServices, and so on), and those with a definition
// that the registration does not list. An AI Services account's model
// deployments are only the second kind: listed from the registration alone,
// they were never read, and coverage did not say so.
func (v *versions) childTypes(typ string) ([]string, error) {
	ns := strings.ToLower(Namespace(typ))
	v.mu.Lock()
	offered, ok := v.cache[ns]
	v.mu.Unlock()
	if !ok {
		if _, err := v.pick(typ); err != nil && !errors.Is(err, errNoVersion) {
			return nil, err
		}
		v.mu.Lock()
		offered = v.cache[ns]
		v.mu.Unlock()
	}
	prefix := strings.ToLower(typ) + "/"
	seen := map[string]bool{}
	var out []string
	for t := range offered {
		if strings.HasPrefix(t, prefix) && !strings.Contains(t[len(prefix):], "/") {
			seen[t] = true
			out = append(out, typ+t[len(typ):])
		}
	}
	for _, t := range v.reg.Children(typ) {
		if !seen[strings.ToLower(t)] {
			out = append(out, typ+t[len(typ):])
		}
	}
	sort.Strings(out)
	return out, nil
}

// registered says whether the provider registration lists the type itself.
func (v *versions) registered(typ string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.cache[strings.ToLower(Namespace(typ))][strings.ToLower(typ)]
	return ok
}

// inlineAs are child collections a parent's GET returns under another name,
// with nothing in them to say so: a cluster's agent pools are its
// agentPoolProfiles, which carry no IDs.
var inlineAs = map[string]string{
	"microsoft.containerservice/managedclusters/agentpools": "agentPoolProfiles",
}

// inlineCollections are the child collections already in a parent's spec, in
// lower case: one under its own name (a network's subnets), one inlineAs
// names, and one whose items are the parent's children by ID, whatever the
// property is called (a VPN gateway's connections are its vpnConnections).
func inlineCollections(parent *captured) map[string]bool {
	out := map[string]bool{}
	props, _ := parent.spec["properties"].(map[string]any)
	self, _ := parent.status["id"].(string)
	prefix := strings.ToLower(self) + "/"
	for k, v := range props {
		items, ok := v.([]any)
		if !ok {
			continue
		}
		out[strings.ToLower(k)] = true
		for _, it := range items {
			m, _ := it.(map[string]any)
			if id, _ := m["id"].(string); self != "" && strings.HasPrefix(strings.ToLower(id), prefix) {
				coll, _, _ := strings.Cut(strings.ToLower(id)[len(prefix):], "/")
				out[coll] = true
			}
		}
	}
	for child, prop := range inlineAs {
		if _, ok := props[prop].([]any); ok && strings.HasPrefix(child, strings.ToLower(parent.rid.Type)+"/") {
			out[child[len(parent.rid.Type)+1:]] = true
		}
	}
	return out
}

// nilGUID is what ARM writes for "none" (a policy assignment's instanceId,
// a SQL server's storageAccountSubscriptionId). Nothing generated it, so
// no resource owns it: taken for a reference, one resource's "none" became
// a dependency on another's.
const nilGUID = "00000000-0000-0000-0000-000000000000"

var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// principalRefs replaces, in every spec, a GUID that another captured
// resource generated (an identity's properties.principalId) with a
// reference restore resolves to the value the target generated. Restoring
// an identity creates a new principal with a new object ID; a role
// assignment restored with the old ID would grant access to no one.
func principalRefs(cs []*captured) {
	// A GUID can appear in several objects' status: an identity's own
	// properties.principalId, and every VM or web app that uses it, under
	// identity.userAssignedIdentities.*.principalId. The first seen used to
	// win, in ARM's list order, which made the snapshot depend on that
	// order and could pick a "*" path no restore can resolve (review,
	// 2026-10-22). A path through a map key never owns a value; of the
	// rest, the shortest path wins (the identity's own), then the token.
	owners := map[string]string{} // GUID -> token
	best := map[string]string{}   // GUID -> its owner's path
	for _, c := range cs {
		for _, k := range sortedKeys(c.status) {
			s, ok := c.status[k].(string)
			if !ok || !guidRE.MatchString(s) || s == nilGUID || k == "id" || strings.Contains(k, "*") {
				continue
			}
			g, tok := strings.ToLower(s), refToken(c, k)
			if cur, taken := owners[g]; taken {
				if p := best[g]; len(k) > len(p) || (len(k) == len(p) && tok > cur) {
					continue
				}
			}
			owners[g], best[g] = tok, k
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
