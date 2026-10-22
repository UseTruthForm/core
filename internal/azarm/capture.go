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

	for i, r := range todo {
		rid, _ := ParseID(r.ID)
		c := out[i]
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
	for _, c := range out {
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
	spec, sp := s.normalize(body)
	spec = tokenize(spec, api.Subscription(), tenant)
	status := map[string]any{"id": tokenizeString(r.ID, api.Subscription(), tenant)}
	for k, x := range sp.readOnly {
		if str, ok := x.(string); ok {
			x = tokenizeString(str, api.Subscription(), tenant)
		}
		status[k] = x
	}
	return &captured{rid: rid, version: ver, schema: s, spec: spec, status: status, secrets: relevantSecrets(spec, s.secretPaths())}, nil
}

// relevantSecrets keeps the secret paths whose parent object is present:
// a VM with an osProfile can have had an adminPassword, one without cannot.
// Azure returns no secret value, so presence is the only evidence there is.
func relevantSecrets(spec map[string]any, paths []string) []string {
	var out []string
	for _, p := range paths {
		if strings.Contains(p, "[]") {
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
	ann := map[string]any{annAPIVersion: c.version}
	if len(c.secrets) > 0 {
		ann[annSecrets] = strings.Join(c.secrets, ",")
	}
	meta := map[string]any{"name": c.rid.Name, "annotations": ann}
	if !strings.EqualFold(c.rid.Type, groupType) {
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
