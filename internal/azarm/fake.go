package azarm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
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
}

// NewWorld creates an empty world whose subscriptions serve the registry's
// types at the versions it has definitions for.
func NewWorld(reg *Registry) *World { return &World{reg: reg, subs: map[string]bool{}} }

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
		if (r.typ == "Microsoft.Resources/resourceGroups") != groups {
			continue
		}
		loc, _ := r.body["location"].(string)
		out = append(out, Ref{ID: r.id, Type: r.typ, Location: loc, ManagedBy: f.ManagedBy[k]})
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
		if strings.HasPrefix(typ, prefix) {
			out[typ] = append(out[typ], ver)
		}
	}
	return out, nil
}

// Get returns the resource without its secrets.
func (f *Fake) Get(_ context.Context, id, version string) (map[string]any, error) {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
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
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	if err := f.validate(s, rid, body); err != nil {
		return nil, err
	}
	b := deepCopy(body)
	b["id"], b["name"], b["type"] = rid.String(), lastName(rid.Name), rid.Type
	f.w.seq++
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", f.sub, f.w.seq)))
	b["etag"] = "W/\"" + hex.EncodeToString(h[:4]) + "\""
	if p, ok := b["properties"].(map[string]any); ok {
		p["provisioningState"] = "Succeeded"
	} else if top, _, _ := s.object(s.body, nil); top["properties"].Type.Ref != "" {
		b["properties"] = map[string]any{"provisioningState": "Succeeded"}
	}
	f.res[strings.ToLower(rid.String())] = stored{id: rid.String(), typ: rid.Type, version: version, body: b}
	if f.AfterCreate != nil {
		f.w.mu.Unlock()
		f.AfterCreate(rid.String(), b)
		f.w.mu.Lock()
	}
	return deepCopy(b), nil
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
	for _, r := range s.Required() {
		if _, ok := lookup(body, strings.Split(r, ".")); !ok {
			return fmt.Errorf("InvalidRequestContent: %s requires %s", rid.Type, r)
		}
	}
	if rid.Type != "Microsoft.Resources/resourceGroups" {
		rg := ResourceID{Subscription: rid.Subscription, ResourceGroup: rid.ResourceGroup, Type: "Microsoft.Resources/resourceGroups"}
		if _, ok := f.res[strings.ToLower(rg.String())]; !ok {
			return fmt.Errorf("ResourceGroupNotFound: resource group %s does not exist", rid.ResourceGroup)
		}
	}
	if i := strings.LastIndex(rid.Name, "/"); i > 0 {
		parent := ResourceID{Subscription: rid.Subscription, ResourceGroup: rid.ResourceGroup,
			Type: rid.Type[:strings.LastIndex(rid.Type, "/")], Name: rid.Name[:i]}
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
		for other := range f.w.subs {
			if bad == nil && other != strings.ToLower(f.sub) && strings.Contains(lower, "/subscriptions/"+other) {
				bad = fmt.Errorf("LinkedAuthorizationFailed: %q is in subscription %s, which this one cannot reach", v, other)
			}
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
