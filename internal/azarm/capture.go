package azarm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/stackdna/core/internal/snapshot"
)

// APIVersion is the apiVersion of every Azure object in a snapshot; the ARM
// type is the kind and the resource group is the namespace.
const APIVersion = "azure.stackdna.org/v1"

const (
	annAPIVersion = "stackdna.org/api-version"
	annSecrets    = "stackdna.org/secrets"
	annID         = "stackdna.org/id"
	tokSub        = "{{stackdna|subscription}}"
	tokTenant     = "{{stackdna|tenant}}"
	groupType     = "Microsoft.Resources/resourceGroups"
)

// Policy is the set of capture rules, recorded in the snapshot by Name.
type Policy struct {
	// Types limits the capture to matching types (path.Match patterns such
	// as Microsoft.Network/*). Resource groups are always captured: every
	// resource needs its group to be restored.
	Types []string
	// CaptureManaged also captures resources another resource manages
	// (managedBy: an AKS cluster's node resource group and what is in it).
	// Skipped by default: the manager recreates them.
	CaptureManaged bool
	// Baseline is a capture of a fresh subscription; resources identical
	// to it are Azure's own (NetworkWatcherRG and its watchers).
	Baseline       map[string]map[string]any
	BaselineDigest string
	Parallel       int
}

// WithBaseline adds a baseline snapshot to the policy.
func (p Policy) WithBaseline(b snapshot.Snapshot, digest string) Policy {
	merged := map[string]map[string]any{}
	for k, v := range p.Baseline {
		merged[k] = v
	}
	for _, o := range b.Objects {
		merged[o.Key()] = o.Body
	}
	p.Baseline = merged
	if p.BaselineDigest != "" {
		digest = p.BaselineDigest + "," + digest
	}
	p.BaselineDigest = digest
	return p
}

// Name describes the policy for the snapshot manifest.
func (p Policy) Name() string {
	n := "default"
	if p.CaptureManaged {
		n += "+managed"
	}
	if len(p.Types) > 0 {
		t := append([]string(nil), p.Types...)
		sort.Strings(t)
		n += "+types:" + strings.Join(t, ",")
	}
	if p.BaselineDigest != "" {
		n += "+baseline:" + p.BaselineDigest
	}
	return n
}

func (p Policy) selected(typ string) bool {
	if len(p.Types) == 0 || strings.EqualFold(typ, groupType) {
		return true
	}
	for _, pat := range p.Types {
		if ok, _ := path.Match(strings.ToLower(pat), strings.ToLower(typ)); ok {
			return true
		}
	}
	return false
}

// Unreadable prefixes skip reasons for listed resources whose GET failed.
const Unreadable = "listed but could not be read: "

// captured is one resource as read.
type captured struct {
	rid     ResourceID
	version string
	schema  *Schema
	spec    map[string]any
	status  map[string]any
	secrets []string
}

// Capture reads every selected resource in the subscription.
func Capture(ctx context.Context, api ARM, reg *Registry, p Policy) (snapshot.Snapshot, error) {
	tenant, err := api.Tenant(ctx)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	groups, err := api.ResourceGroups(ctx)
	if err != nil {
		return snapshot.Snapshot{}, fmt.Errorf("list resource groups: %w", err)
	}
	resources, err := api.Resources(ctx)
	if err != nil {
		return snapshot.Snapshot{}, fmt.Errorf("list resources: %w", err)
	}
	snap := snapshot.Snapshot{Platform: "azure", ServerVersion: "arm", Policy: p.Name()}
	cov := map[string]*snapshot.Coverage{}
	cover := func(typ string) *snapshot.Coverage {
		k := strings.ToLower(typ)
		if cov[k] == nil {
			cov[k] = &snapshot.Coverage{Resource: typ, Kind: typ}
		}
		return cov[k]
	}
	skip := func(typ, name, reason string) {
		c := cover(typ)
		if c.Skipped == nil {
			c.Skipped = map[string]int{}
		}
		c.Skipped[strings.SplitN(reason, ": ", 2)[0]]++
		snap.Skips = append(snap.Skips, snapshot.Skip{Resource: typ, Name: name, Reason: reason})
	}

	v := versions{api: api, reg: reg, ctx: ctx, cache: map[string]map[string][]string{}}
	// A resource group another resource manages (an AKS cluster's node
	// group) is skipped, and so is everything in it. Only the group carries
	// managedBy: in a real subscription the cluster's node scale set and
	// each node VM in it were captured, and restoring them would fight the
	// cluster that creates and replaces them.
	managedGroups := map[string]string{}
	for _, g := range groups {
		if g.ManagedBy != "" {
			if rid, err := ParseID(g.ID); err == nil {
				managedGroups[strings.ToLower(rid.Name)] = g.ManagedBy
			}
		}
	}
	var todo []Ref
	for _, r := range append(groups, resources...) {
		rid, err := ParseID(r.ID)
		if err != nil {
			return snapshot.Snapshot{}, err
		}
		if !p.selected(rid.Type) {
			cover(rid.Type).NotCaptured = "not selected (--types)"
			continue
		}
		if r.ManagedBy != "" && !p.CaptureManaged {
			skip(rid.Type, rid.ResourceGroup+"/"+rid.Name, "managed by "+r.ManagedBy+", which recreates it")
			continue
		}
		if by := managedGroups[strings.ToLower(rid.ResourceGroup)]; by != "" && !strings.EqualFold(rid.Type, groupType) && !p.CaptureManaged {
			skip(rid.Type, rid.ResourceGroup+"/"+rid.Name, "in a resource group managed by "+by+", which recreates it")
			continue
		}
		todo = append(todo, r)
	}

	// Reads run in parallel; results are put in order before use.
	out := make([]*captured, len(todo))
	errs := make([]error, len(todo))
	par := p.Parallel
	if par <= 0 {
		par = 8
	}
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	for i, r := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i], errs[i] = read(ctx, api, &v, r, tenant)
		}()
	}
	wg.Wait()

	var caps []*captured
	for i, r := range todo {
		rid, _ := ParseID(r.ID)
		switch {
		case errors.Is(errs[i], errNoVersion):
			cover(rid.Type).NotCaptured = errs[i].Error()
			continue
		case errors.Is(errs[i], ErrNotFound):
			continue // deleted between list and read
		case errs[i] != nil:
			skip(rid.Type, rid.ResourceGroup+"/"+rid.Name, Unreadable+errs[i].Error())
			continue
		}
		caps = append(caps, out[i])
	}
	// What the resource list does not return: extension resources and
	// children. Their own skips go to coverage like any other.
	for _, f := range discover(ctx, api, &v, tenant, caps, par) {
		if !p.selected(f.typ) {
			cover(f.typ).NotCaptured = "not selected (--types)"
			continue
		}
		switch {
		case f.count:
			c := cover(f.typ)
			if c.Skipped == nil {
				c.Skipped = map[string]int{}
			}
			c.Skipped[f.reason]++
		case f.reason != "":
			skip(f.typ, f.name, f.reason)
		// An extension on a resource in a managed group (a lock on one of an
		// AKS cluster's public IPs) goes with that resource: the manager
		// creates its own, under new names. One on the group itself (a role
		// assignment someone granted there) is kept: the group is recreated
		// under the same name.
		case f.c.rid.Scope != "" && managedGroups[strings.ToLower(f.c.rid.ResourceGroup)] != "" && !p.CaptureManaged:
			skip(f.typ, f.name, "on a resource in a resource group managed by "+managedGroups[strings.ToLower(f.c.rid.ResourceGroup)]+", which recreates it")
		default:
			caps = append(caps, f.c)
		}
	}
	// A resource can be reachable two ways (a SQL database is tracked and
	// also its server's child). The first read is kept; a second would be
	// a duplicate object, which the snapshot refuses to write.
	seenID := map[string]bool{}
	unique := caps[:0]
	for _, c := range caps {
		if k := strings.ToLower(c.rid.String()); !seenID[k] {
			seenID[k] = true
			unique = append(unique, c)
		}
	}
	caps = unique
	principalRefs(caps)

	for _, c := range caps {
		rid := c.rid
		obj := toObject(c)
		if p.Baseline != nil {
			if b, ok := p.Baseline[snapshot.Object{Body: obj}.Key()]; ok && sameSpec(obj, b) {
				skip(rid.Type, rid.ResourceGroup+"/"+rid.Name, "identical to the baseline snapshot (already there, or created by Azure)")
				continue
			}
		}
		cover(rid.Type).Captured++
		snap.Objects = append(snap.Objects, snapshot.Object{Body: obj})
	}

	seen := map[string]bool{}
	for _, c := range caps {
		if c == nil || seen[strings.ToLower(c.rid.Type)] {
			continue
		}
		seen[strings.ToLower(c.rid.Type)] = true
		f := c.schema.Fields()
		snap.Schemas = append(snap.Schemas, snapshot.TypeSchema{APIVersion: APIVersion, Kind: c.rid.Type + "@" + c.version, Digest: FieldsDigest(f), Fields: f})
	}
	for _, k := range sortedKeys(cov) {
		snap.Coverage = append(snap.Coverage, *cov[k])
	}
	sort.Slice(snap.Objects, func(i, j int) bool { return snap.Objects[i].Key() < snap.Objects[j].Key() })
	sort.Slice(snap.Skips, func(i, j int) bool {
		a, b := snap.Skips[i], snap.Skips[j]
		return a.Resource+"|"+a.Name < b.Resource+"|"+b.Name
	})
	sort.Slice(snap.Schemas, func(i, j int) bool { return snap.Schemas[i].Kind < snap.Schemas[j].Kind })
	return snap, nil
}

var errNoVersion = errors.New("no API version")

// versions picks, per type, the newest API version that both the
// subscription offers and Azure publishes a definition for, preferring
// stable to preview. Offered versions come live from the provider
// registration, so a capture moves to new versions by itself.
type versions struct {
	api   ARM
	reg   *Registry
	ctx   context.Context
	mu    sync.Mutex
	cache map[string]map[string][]string
}

func (v *versions) pick(typ string) (string, error) {
	ns := strings.ToLower(Namespace(typ))
	v.mu.Lock()
	offered, ok := v.cache[ns]
	v.mu.Unlock()
	if !ok {
		var err error
		if offered, err = v.api.APIVersions(v.ctx, ns); err != nil {
			return "", err
		}
		v.mu.Lock()
		v.cache[ns] = offered
		v.mu.Unlock()
	}
	have := map[string]bool{}
	for _, x := range v.reg.Versions(typ) {
		have[x] = true
	}
	var both []string
	for _, x := range offered[strings.ToLower(typ)] {
		if have[strings.ToLower(x)] {
			both = append(both, x)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(both)))
	for _, x := range both {
		if !strings.Contains(x, "preview") {
			return x, nil
		}
	}
	if len(both) > 0 {
		return both[0], nil
	}
	return "", fmt.Errorf("%w: no API version the subscription offers (%d) has a published definition (%d)",
		errNoVersion, len(offered[strings.ToLower(typ)]), len(have))
}

// all lists every version both offered and defined, the stable ones first
// (newest first), then previews: the order a list falls back through
// when its preferred version is refused at its scope.
func (v *versions) all(typ string) []string {
	if _, err := v.pick(typ); err != nil {
		return nil
	}
	ns := strings.ToLower(Namespace(typ))
	v.mu.Lock()
	offered := v.cache[ns]
	v.mu.Unlock()
	have := map[string]bool{}
	for _, x := range v.reg.Versions(typ) {
		have[x] = true
	}
	var stable, preview []string
	for _, x := range offered[strings.ToLower(typ)] {
		if !have[strings.ToLower(x)] {
			continue
		}
		if strings.Contains(x, "preview") {
			preview = append(preview, x)
		} else {
			stable = append(stable, x)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(stable)))
	sort.Sort(sort.Reverse(sort.StringSlice(preview)))
	return append(stable, preview...)
}

func read(ctx context.Context, api ARM, v *versions, r Ref, tenant string) (*captured, error) {
	rid, _ := ParseID(r.ID)
	ver, err := v.pick(rid.Type)
	if err != nil {
		return nil, err
	}
	s, err := v.reg.Schema(rid.Type, ver)
	if err != nil {
		return nil, err
	}
	body, err := api.Get(ctx, r.ID, ver)
	if err != nil {
		return nil, err
	}
	return process(api, tenant, rid, ver, s, body), nil
}

// process turns a body, however it was read (a GET, or an item of a
// list), into a captured resource.
func process(api ARM, tenant string, rid ResourceID, ver string, s *Schema, body map[string]any) *captured {
	spec, sp := s.normalize(body)
	spec = tokenize(spec, api.Subscription(), tenant)
	status := map[string]any{"id": tokenizeString(rid.String(), api.Subscription(), tenant)}
	for k, x := range sp.readOnly {
		if observed(x) {
			continue
		}
		if str, ok := x.(string); ok {
			x = tokenizeString(str, api.Subscription(), tenant)
		}
		status[k] = x
	}
	return &captured{rid: rid, version: ver, schema: s, spec: spec, status: status, secrets: relevantSecrets(spec, s.secretPaths())}
}

// relevantSecrets keeps the secret paths whose parent object is present:
// a VM with an osProfile can have had an adminPassword, one without cannot.
// Azure returns no secret value, so presence is the only evidence there is.
func relevantSecrets(spec map[string]any, paths []string) []string {
	var out []string
	for _, p := range paths {
		// A secret inside an array (an application gateway's
		// sslCertificates[].properties.password) counts when the array is
		// there. Left out, the update refusal never saw it, and a PUT went
		// out without the secret (review, 2026-10-22). --values cannot
		// supply one element's field, so such a resource is refused for
		// update rather than sent without it.
		if i := strings.Index(p, "[]"); i >= 0 {
			if v, ok := lookup(spec, strings.Split(p[:i], ".")); ok {
				if a, _ := v.([]any); len(a) > 0 {
					out = append(out, p)
				}
			}
			continue
		}
		parts := strings.Split(p, ".")
		if len(parts) == 1 {
			out = append(out, p)
			continue
		}
		if _, ok := lookup(spec, parts[:len(parts)-1]); ok {
			out = append(out, p)
		}
	}
	return out
}

func toObject(c *captured) map[string]any {
	// The ID is kept because an extension resource's scope cannot be
	// rebuilt from its kind and name alone; restore PUTs to it.
	ann := map[string]any{annAPIVersion: c.version, annID: c.status["id"]}
	if len(c.secrets) > 0 {
		ann[annSecrets] = strings.Join(c.secrets, ",")
	}
	meta := map[string]any{"name": c.rid.LocalName(), "annotations": ann}
	if !strings.EqualFold(c.rid.Type, groupType) && c.rid.ResourceGroup != "" {
		meta["namespace"] = c.rid.ResourceGroup
	}
	return map[string]any{"apiVersion": APIVersion, "kind": c.rid.Type, "metadata": meta, "spec": c.spec, "status": c.status}
}

var subRE = regexp.MustCompile(`(?i)/subscriptions/[0-9a-f-]{36}`)

// tokenize makes a spec portable across subscriptions and tenants: the
// subscription in every resource ID, and the tenant wherever it appears,
// become tokens restore fills in for the target. Resource group and
// resource names are kept: in Azure they are chosen by people, the same in
// any subscription.
func tokenize(spec map[string]any, sub, tenant string) map[string]any {
	return rewriteAll(spec, func(s string) string { return tokenizeString(s, sub, tenant) }).(map[string]any)
}

func tokenizeString(s, sub, tenant string) string {
	s = subRE.ReplaceAllStringFunc(s, func(m string) string {
		if strings.EqualFold(m[len("/subscriptions/"):], sub) {
			return "/subscriptions/" + tokSub
		}
		return m
	})
	if strings.EqualFold(s, sub) {
		return tokSub
	}
	if tenant != "" && strings.Contains(strings.ToLower(s), strings.ToLower(tenant)) {
		s = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(tenant)).ReplaceAllString(s, tokTenant)
	}
	return s
}

func sameSpec(obj, base map[string]any) bool {
	norm := func(o map[string]any) any {
		var v any
		_ = json.Unmarshal([]byte(canon(map[string]any{"m": o["metadata"], "s": o["spec"]})), &v)
		return v
	}
	return reflect.DeepEqual(norm(obj), norm(base))
}
