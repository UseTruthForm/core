package azarm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// World is a set of fake subscriptions, each in its own tenant. A PUT that
// carries another subscription's resource ID is refused, as ARM refuses a
// reference it cannot resolve (LinkedAuthorizationFailed): without that, a
// restore that forgot to replace the subscription would pass here and fail
// against Azure.
type World struct {
	mu   sync.Mutex
	reg  *Registry
	subs map[string]bool
	seq  int
	// owner maps each GUID the world generated (a principalId) to the
	// subscription it belongs to. A PUT carrying another subscription's
	// GUID is refused as PrincipalNotFound: a role assignment restored
	// with the source identity's principal would grant access to no one.
	owner map[string]string
	// roles are the custom roles made, by tenant and ID: in a tenant, a role's
	// ID answers wherever it is asked for by that ID alone.
	roles map[string]map[string]any
}

// NewWorld creates an empty world whose subscriptions serve the registry's
// types at the versions it has definitions for.
func NewWorld(reg *Registry) *World {
	return &World{reg: reg, subs: map[string]bool{}, owner: map[string]string{}, roles: map[string]map[string]any{}}
}

// Fake is one subscription. It is schema driven and knows no Azure type:
// it rejects properties the definition does not have and values for
// read-only properties, generates read-only values, keeps secrets but never
// returns them, requires a resource's group and parent to exist, and
// refuses references to other subscriptions.
type Fake struct {
	w           *World
	sub, tenant string
	res         map[string]stored // lower(id) -> resource
	ManagedBy   map[string]string // lower(id) -> managedBy, as ARM reports it
	AfterCreate func(id string, body map[string]any)
	// Puts counts accepted PUTs, so a test can prove none was sent.
	Puts int
	// RefuseVersion refuses a list at an API version, as ARM refuses the
	// subscription's diagnostic settings at their newest stable version.
	RefuseVersion func(path, version string) bool
	// BadRequest answers a list with a plain 400, as a resource answers for
	// a child type it has a definition for and does not serve.
	BadRequest func(path string) bool
	// PutDelay makes each PUT take this long, outside the lock, so PUTs
	// running at once overlap as ARM's long-running ones do.
	PutDelay time.Duration
	// AlsoTracked lists child types ARM's resource list returns as well
	// (a SQL server's databases are both), so capture meets them twice.
	AlsoTracked map[string]bool
	// CheckReferences refuses IDs that name nothing here, as Azure refuses most.
	// Only for a target: a test seeding a source may build it in any order.
	CheckReferences bool
	// ByKind lists collections, by their last path segment in lower case
	// ("datasources"), that answer only a list filtered by kind, as ARM
	// answers a Log Analytics workspace's data sources.
	ByKind map[string]bool
}

type stored struct {
	id, typ, version string
	body             map[string]any
}

// Subscription returns a new empty subscription in the world.
func (w *World) Subscription(sub, tenant string) *Fake {
	w.mu.Lock()
	w.subs[strings.ToLower(sub)] = true
	w.mu.Unlock()
	return &Fake{w: w, sub: sub, tenant: tenant, res: map[string]stored{}, ManagedBy: map[string]string{}}
}

func (f *Fake) Subscription() string                          { return f.sub }
func (f *Fake) Tenant(context.Context) (string, error)        { return f.tenant, nil }
func (f *Fake) ResourceGroups(context.Context) ([]Ref, error) { return f.list(true), nil }
func (f *Fake) Resources(context.Context) ([]Ref, error)      { return f.list(false), nil }

func (f *Fake) list(groups bool) []Ref {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	var out []Ref
	for k, r := range f.res {
		rid, _ := ParseID(r.id)
		if (r.typ == "Microsoft.Resources/resourceGroups") != groups || (!groups && !tracked(rid) && !f.AlsoTracked[rid.Type]) {
			continue
		}
		loc, _ := r.body["location"].(string)
		tags, _ := r.body["tags"].(map[string]any)
		out = append(out, Ref{ID: r.id, Type: r.typ, Location: loc, ManagedBy: f.ManagedBy[k], Tags: tags})
	}
	// Reverse order: callers must not depend on the order ARM lists in.
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

// APIVersions offers every version the registry has a definition for.
func (f *Fake) APIVersions(_ context.Context, namespace string) (map[string][]string, error) {
	out := map[string][]string{}
	prefix := strings.ToLower(namespace) + "/"
	for k := range f.w.reg.index {
		typ, ver, _ := strings.Cut(k, "@")
		if strings.HasPrefix(typ, prefix) && !unregistered[typ] {
			out[typ] = append(out[typ], ver)
		}
	}
	return out, nil
}

// unregistered are types that have definitions and that ARM's provider
// registration does not list, seen on two real subscriptions: a network's
// peerings and subnets. Offering them here let discovery find peerings as
// children, which a real subscription never does, and hid their loss.
// An AI Services account's model deployments and content filters are not
// listed either, and its registration answers for neither.
var unregistered = map[string]bool{
	"microsoft.network/virtualnetworks/virtualnetworkpeerings": true,
	"microsoft.network/virtualnetworks/subnets":                true,
	"microsoft.cognitiveservices/accounts/deployments":         true,
	"microsoft.cognitiveservices/accounts/raipolicies":         true,
}

// Get returns the resource without its secrets.
func (f *Fake) Get(_ context.Context, id, version string) (map[string]any, error) {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	if name, ok := strings.CutPrefix(strings.ToLower(id), "/providers/microsoft.authorization/roledefinitions/"); ok {
		if r, ok := f.w.roles[f.tenant+"|"+name]; ok {
			return deepCopy(r), nil
		}
		return nil, fmt.Errorf("%s: %w", id, ErrNotFound)
	}
	r, ok := f.res[strings.ToLower(id)]
	if !ok {
		return nil, fmt.Errorf("%s: %w", id, ErrNotFound)
	}
	s, err := f.w.reg.Schema(r.typ, version)
	if err != nil {
		return nil, err
	}
	out := deepCopy(r.body)
	spec, _ := s.normalize(out)
	// Put back what ARM returns besides configuration: identity and the
	// read-only values generated at PUT. Only secrets stay out.
	for _, k := range []string{"id", "name", "type", "etag"} {
		if v, ok := r.body[k]; ok {
			spec[k] = v
		}
	}
	restoreReadOnly(spec, r.body, s)
	// normalize takes out what is not configuration, and ARM returns it: a
	// network's peerings inline, each as written to the network or as its own
	// resource, and what setByAzure names at the top of properties.
	stored, _ := r.body["properties"].(map[string]any)
	if p, _ := spec["properties"].(map[string]any); p != nil {
		if strings.EqualFold(r.typ, vnetType) {
			var inline []any
			if l, ok := stored["virtualNetworkPeerings"].([]any); ok {
				inline = append(inline, deepCopy(map[string]any{"v": l})["v"].([]any)...)
			}
			for _, k := range sortedKeys(f.res) {
				if c := f.res[k]; strings.EqualFold(c.typ, vnetType+"/virtualNetworkPeerings") && strings.HasPrefix(k, strings.ToLower(r.id)+"/") {
					inline = append(inline, deepCopy(c.body))
				}
			}
			if inline != nil {
				p["virtualNetworkPeerings"] = inline
			}
		}
		for k := range setByAzure[strings.ToLower(r.typ)] {
			if v, ok := stored[k]; ok {
				p[k] = v
			}
		}
	}
	return spec, nil
}

// restoreReadOnly copies read-only values from stored into out.
func restoreReadOnly(out, stored map[string]any, s *Schema) {
	_, sp := s.normalize(stored)
	for path, v := range sp.readOnly {
		setPath(out, strings.Split(path, "."), v)
	}
}

func setPath(m map[string]any, p []string, v any) {
	for i, k := range p {
		if i == len(p)-1 {
			m[k] = v
			return
		}
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
}

// Put validates and stores the resource.
func (f *Fake) Put(_ context.Context, id, version string, body map[string]any) (map[string]any, error) {
	rid, err := ParseID(id)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(rid.Subscription, f.sub) {
		return nil, fmt.Errorf("SubscriptionNotFound: %s is not this subscription", rid.Subscription)
	}
	s, err := f.w.reg.Schema(rid.Type, version)
	if err != nil {
		return nil, fmt.Errorf("NoRegisteredProviderFound: %w", err)
	}
	if !s.Writable {
		return nil, fmt.Errorf("InvalidResourceType: %s is defined by Azure and cannot be written", rid.Type)
	}
	time.Sleep(f.PutDelay)
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	if err := f.validate(s, rid, body); err != nil {
		return nil, err
	}
	if strings.EqualFold(rid.Type, "Microsoft.Authorization/roleDefinitions") {
		f.w.roles[f.tenant+"|"+strings.ToLower(lastName(rid.Name))] = deepCopy(body)
	}
	b := deepCopy(body)
	b["id"], b["name"], b["type"] = rid.String(), lastName(rid.Name), rid.Type
	f.Puts++
	f.w.seq++
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", f.sub, f.w.seq)))
	b["etag"] = "W/\"" + hex.EncodeToString(h[:4]) + "\""
	if p, ok := b["properties"].(map[string]any); ok {
		p["provisioningState"] = "Succeeded"
	} else if top, _, _ := s.object(s.body, nil); top["properties"].Type.Ref != "" {
		b["properties"] = map[string]any{"provisioningState": "Succeeded"}
	}
	// A PUT over an existing resource is an update: Azure keeps what it
	// assigned (an identity's principalId), and nothing is created as a
	// side effect. Regenerating them would orphan every role assignment.
	old, existed := f.res[strings.ToLower(rid.String())]
	f.generateIDs(s, b, old.body)
	f.res[strings.ToLower(rid.String())] = stored{id: rid.String(), typ: rid.Type, version: version, body: b}
	if f.AfterCreate != nil && !existed {
		f.w.mu.Unlock()
		f.AfterCreate(rid.String(), b)
		f.w.mu.Lock()
	}
	return deepCopy(b), nil
}

// generateIDs fills read-only string properties named *Id under
// "properties" (an identity's principalId and clientId) with GUIDs this
// subscription owns.
func (f *Fake) generateIDs(s *Schema, b, prev map[string]any) {
	top, _, _ := s.object(s.body, nil)
	pp, ok := top["properties"]
	if !ok {
		return
	}
	props, _, _ := s.object(pp.Type.index(), nil)
	inner, _ := b["properties"].(map[string]any)
	if inner == nil {
		return
	}
	was, _ := prev["properties"].(map[string]any)
	for _, k := range sortedKeys(props) {
		if props[k].Flags&flagReadOnly != 0 && strings.HasSuffix(k, "Id") && s.file[props[k].Type.index()].Kind == "StringType" {
			if v, ok := was[k]; ok {
				inner[k] = v
				continue
			}
			if _, set := inner[k]; !set {
				f.w.seq++
				g := fmt.Sprintf("%08x-0000-4000-8000-%012x", f.w.seq, len(f.sub)*7919+f.w.seq)
				inner[k] = g
				f.w.owner[g] = strings.ToLower(f.sub)
			}
		}
	}
}

func (f *Fake) validate(s *Schema, rid ResourceID, body map[string]any) error {
	top, _, _ := s.object(s.body, nil)
	for k := range body {
		p, ok := top[k]
		if !ok {
			return fmt.Errorf("InvalidRequestContent: %s has no property %q", rid.Type, k)
		}
		if p.Flags&flagReadOnly != 0 {
			return fmt.Errorf("InvalidRequestContent: %s property %q is read-only", rid.Type, k)
		}
	}
	if err := s.checkNested(body, s.body, ""); err != nil {
		return fmt.Errorf("InvalidRequestContent: %s %w", rid.Type, err)
	}
	if f.CheckReferences {
		if err := f.references(body); err != nil {
			return err
		}
	}
	for _, r := range s.Required() {
		if _, ok := lookup(body, strings.Split(r, ".")); !ok {
			return fmt.Errorf("InvalidRequestContent: %s requires %s", rid.Type, r)
		}
	}
	if rid.Type != "Microsoft.Resources/resourceGroups" && rid.ResourceGroup != "" {
		rg := ResourceID{Subscription: rid.Subscription, ResourceGroup: rid.ResourceGroup, Type: "Microsoft.Resources/resourceGroups"}
		if _, ok := f.res[strings.ToLower(rg.String())]; !ok {
			return fmt.Errorf("ResourceGroupNotFound: resource group %s does not exist", rid.ResourceGroup)
		}
	}
	if rid.Scope != "" {
		if _, ok := f.res[strings.ToLower(rid.Scope)]; !ok {
			return fmt.Errorf("ResourceNotFound: scope %s does not exist", rid.Scope)
		}
	}
	if i := strings.LastIndex(rid.Name, "/"); i > 0 {
		parent := ResourceID{Subscription: rid.Subscription, ResourceGroup: rid.ResourceGroup,
			Type: rid.Type[:strings.LastIndex(rid.Type, "/")], Name: rid.Name[:i], Scope: rid.Scope}
		if _, ok := f.res[strings.ToLower(parent.String())]; !ok {
			return fmt.Errorf("ParentResourceNotFound: %s", parent.String())
		}
	}
	var bad error
	// Keys too: some maps are keyed by resource ID.
	rewriteAll(deepCopy(body), func(v string) string {
		if bad == nil && strings.Contains(v, "{{stackdna") {
			bad = fmt.Errorf("InvalidRequestContent: unresolved StackDNA reference %q sent to Azure", v)
		}
		lower := strings.ToLower(v)
		if o, ok := f.w.owner[lower]; ok && bad == nil && o != strings.ToLower(f.sub) {
			bad = fmt.Errorf("PrincipalNotFound: principal %s does not exist in this directory (it belongs to subscription %s)", v, o)
		}
		for other := range f.w.subs {
			if bad == nil && other != strings.ToLower(f.sub) && strings.Contains(lower, "/subscriptions/"+other) {
				bad = fmt.Errorf("LinkedAuthorizationFailed: %q is in subscription %s, which this one cannot reach", v, other)
			}
		}
		return v
	})
	return bad
}

// checkNested refuses, below the top level, what the top level refuses: a
// property the definition does not have, and a value for a read-only one. Only
// top-level keys were checked, so a nested field Azure would turn away reached
// the fake and read as restored.
func (s *Schema) checkNested(v any, t int, path string) error {
	switch c := v.(type) {
	case map[string]any:
		props, add, ok := s.object(t, c)
		if !ok {
			return nil
		}
		for _, k := range sortedKeys(c) {
			p, known := props[k]
			full := join(path, k)
			switch {
			case !known && add != nil:
				if err := s.checkNested(c[k], add.index(), join(path, "*")); err != nil {
					return err
				}
			case !known:
				return fmt.Errorf("has no property %q", full)
			case p.Flags&flagReadOnly != 0:
				return fmt.Errorf("property %q is read-only", full)
			default:
				if err := s.checkNested(c[k], p.Type.index(), full); err != nil {
					return err
				}
			}
		}
	case []any:
		if e := s.file[t]; e.Kind == "ArrayType" {
			for _, x := range c {
				if err := s.checkNested(x, e.ItemType.index(), path+"[]"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

var wholeIDRE = regexp.MustCompile(`(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/[^/]+/[^/]+(/[^/]+/[^/]+)*$`)

// references refuses an ID in this subscription that names nothing there, or
// names a part of nothing: Azure answers most of these with a failed link, and
// a restore that sent them out of order had read as fine.
func (f *Fake) references(body map[string]any) error {
	var bad error
	sub := "/subscriptions/" + strings.ToLower(f.sub) + "/"
	rewriteAll(deepCopy(body), func(v string) string {
		lower := strings.ToLower(v)
		if bad != nil || !wholeIDRE.MatchString(v) || !strings.HasPrefix(lower, sub) {
			return v
		}
		// A part ARM keeps inside its resource (a subnet) is not held on its
		// own here, so what is checked is the resource it is part of.
		segs := strings.Split(lower, "/")
		top := strings.Join(segs[:min(len(segs), 9)], "/")
		if _, ok := f.res[top]; !ok {
			bad = fmt.Errorf("InvalidResourceReference: %s does not exist", v)
		}
		return v
	})
	return bad
}

func lookup(m map[string]any, p []string) (any, bool) {
	var cur any = m
	for _, k := range p {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[k]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func lastName(n string) string { return n[strings.LastIndex(n, "/")+1:] }

// Tracked are the types ARM's subscription resource list returns: tracked
// resources (they have a location) that are not children. Everything else
// is found through List, as with Azure.
func tracked(rid ResourceID) bool {
	if rid.Extension() || strings.Count(rid.Type, "/") != 1 || strings.EqualFold(rid.Type, diagnosticType) {
		return false
	}
	// Microsoft.Authorization types at group scope (locks, assignments) are
	// extension resources too; ARM's resource list returns none of them.
	return !strings.EqualFold(Namespace(rid.Type), "Microsoft.Authorization")
}

// List serves the collections capture reads: an extension type across the
// subscription, a resource's diagnostic settings, or a child collection.
func (f *Fake) List(ctx context.Context, path, version string) ([]map[string]any, error) {
	path, query, _ := strings.Cut(path, "?")
	if f.RefuseVersion != nil && f.RefuseVersion(path, version) {
		return nil, fmt.Errorf("%s: %w: Invalid api-version query string value", path, ErrAPIVersion)
	}
	if f.BadRequest != nil && f.BadRequest(path) {
		return nil, fmt.Errorf("%s: %w: The requested action is not supported", path, ErrBadRequest)
	}
	kind := ""
	if q, err := url.ParseQuery(query); err == nil {
		if m := kindFilterRE.FindStringSubmatch(q.Get("$filter")); m != nil {
			kind = m[1]
		}
	}
	if f.ByKind[strings.ToLower(lastName(strings.TrimRight(path, "/")))] && kind == "" {
		return nil, fmt.Errorf("%s: %w: Must specify a valid kind filter", path, ErrNeedsKind)
	}
	lower := strings.ToLower(strings.TrimRight(path, "/"))
	subProviders := "/subscriptions/" + strings.ToLower(f.sub) + "/providers/"
	var ids []stored
	f.w.mu.Lock()
	for k, r := range f.res {
		rid, _ := ParseID(r.id)
		switch {
		case strings.HasPrefix(lower, subProviders) && strings.Count(lower[len(subProviders):], "/") == 1 &&
			!strings.EqualFold(path[len(subProviders):], diagnosticType):
			// Subscription-wide list of an extension type. Diagnostic
			// settings are listed per scope: at the subscription, ARM
			// returns only the subscription's own (the next case).
			if strings.EqualFold(rid.Type, path[len(subProviders):]) {
				ids = append(ids, r)
			}
		case strings.HasPrefix(k, lower+"/") && !strings.Contains(k[len(lower)+1:], "/"):
			ids = append(ids, r)
		}
	}
	f.w.mu.Unlock()
	sort.Slice(ids, func(i, j int) bool { return ids[i].id > ids[j].id })
	var out []map[string]any
	for _, r := range ids {
		b, err := f.Get(ctx, r.id, r.version)
		if err != nil {
			return nil, err
		}
		if bk, _ := b["kind"].(string); kind != "" && !strings.EqualFold(bk, kind) {
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

var kindFilterRE = regexp.MustCompile(`(?i)^kind eq '([^']+)'$`)

// SeedAzure stores what Azure itself creates, bypassing validation (an
// NSG's default rules, which no caller can PUT).
func (f *Fake) SeedAzure(id, version string, body map[string]any) {
	rid, _ := ParseID(id)
	b := deepCopy(body)
	b["id"], b["name"], b["type"] = rid.String(), lastName(rid.Name), rid.Type
	f.w.mu.Lock()
	f.res[strings.ToLower(rid.String())] = stored{id: rid.String(), typ: rid.Type, version: version, body: b}
	f.w.mu.Unlock()
}

// Stored returns what the fake holds for an ID, secrets included, so a test
// can prove a secret arrived.
func (f *Fake) Stored(id string) map[string]any {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	return deepCopy(f.res[strings.ToLower(id)].body)
}

// Count is the number of resources held, groups included.
func (f *Fake) Count() int {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	return len(f.res)
}

var _ ARM = (*Fake)(nil)
