package azarm

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/snapshot"
)

// RestoreOptions are the inputs a restore needs beyond the snapshot.
type RestoreOptions struct {
	// Values supplies secrets Azure never returns (a VM's adminPassword),
	// keyed "Kind/resourceGroup/name", merged into the body at PUT time.
	Values map[string]map[string]any
}

// Restore creates every snapshot object missing from the subscription, in
// dependency order: resource groups, then parents before children, then
// every resource after the resources its IDs point at. It never modifies or
// deletes: a resource already present and identical is reported applied,
// one present but different is reported not applied.
func Restore(ctx context.Context, api ARM, reg *Registry, s snapshot.Snapshot, opt RestoreOptions) []snapshot.Result {
	sub := api.Subscription()
	tenant, err := api.Tenant(ctx)
	results := make([]snapshot.Result, 0, len(s.Objects))
	if err != nil {
		for _, o := range s.Objects {
			results = append(results, snapshot.Result{Key: o.Key(), Detail: "cannot identify the target tenant: " + err.Error()})
		}
		return results
	}
	order, cyclic := restoreOrder(s.Objects)
	for _, o := range cyclic {
		results = append(results, snapshot.Result{Key: o.Key(), Detail: "its references form a cycle; no creation order exists"})
	}
	failed := map[string]string{}
	for _, o := range order {
		res := snapshot.Result{Key: o.Key()}
		res.OK, res.Detail = restoreOne(ctx, api, reg, o, sub, tenant, opt, failed)
		if !res.OK {
			failed[strings.ToLower(o.Key())] = res.Detail
		}
		results = append(results, res)
	}
	return results
}

func objectID(o snapshot.Object, sub string) ResourceID {
	if strings.EqualFold(o.Kind(), groupType) {
		return ResourceID{Subscription: sub, ResourceGroup: o.Name(), Type: groupType, Name: o.Name()}
	}
	return ResourceID{Subscription: sub, ResourceGroup: o.Namespace(), Type: o.Kind(), Name: o.Name()}
}

func restoreOne(ctx context.Context, api ARM, reg *Registry, o snapshot.Object, sub, tenant string, opt RestoreOptions, failed map[string]string) (bool, string) {
	for _, d := range deps(o) {
		if why, bad := failed[d]; bad {
			return false, "depends on " + d + ", which was not restored (" + why + ")"
		}
	}
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	ver, _ := ann[annAPIVersion].(string)
	if ver == "" {
		return false, "snapshot object has no " + annAPIVersion + " annotation"
	}
	rid := objectID(o, sub)
	id := rid.String()
	schema, err := reg.Schema(rid.Type, ver)
	if err != nil {
		return false, err.Error()
	}
	spec, _ := o.Body["spec"].(map[string]any)

	existing, err := api.Get(ctx, id, ver)
	switch {
	case err == nil:
		got, _ := schema.normalize(existing)
		got = tokenize(got, sub, tenant)
		ch := snapshot.Compare(snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": o.Body["metadata"], "spec": spec}}}},
			snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": o.Body["metadata"], "spec": got}}}})
		if len(ch) == 0 {
			return true, "already present and identical"
		}
		return false, "already exists and differs (" + strings.Join(ch[0].Fields, ", ") + "); StackDNA does not modify existing resources"
	case !errors.Is(err, ErrNotFound):
		return false, "cannot check whether it exists: " + err.Error()
	}

	desired := rewriteAll(deepCopy(spec), func(v string) string {
		return strings.ReplaceAll(strings.ReplaceAll(v, tokSub, sub), tokTenant, tenant)
	}).(map[string]any)
	ref := o.Kind() + "/" + rid.ResourceGroup + "/" + o.Name()
	if strings.EqualFold(o.Kind(), groupType) {
		ref = o.Kind() + "/" + o.Name()
	}
	vals := opt.Values[ref]
	merge(desired, deepCopy(vals))
	if _, err := api.Put(ctx, id, ver, desired); err != nil {
		return false, err.Error()
	}
	detail := "created " + id
	if s, _ := ann[annSecrets].(string); s != "" {
		var missing []string
		for _, p := range strings.Split(s, ",") {
			if _, ok := lookup(vals, strings.Split(p, ".")); !ok {
				missing = append(missing, p)
			}
		}
		if len(missing) > 0 {
			detail += "; secret, not supplied: " + strings.Join(missing, ", ")
		}
	}
	return true, detail
}

// deps lists the snapshot keys (lower case) an object needs first: its
// resource group, its parent, and every resource its spec's IDs name.
func deps(o snapshot.Object) []string {
	var out []string
	add := func(rid ResourceID) {
		out = append(out, strings.ToLower(keyOf(rid)))
	}
	if !strings.EqualFold(o.Kind(), groupType) {
		add(ResourceID{ResourceGroup: o.Namespace(), Type: groupType, Name: o.Namespace()})
		if i := strings.LastIndex(o.Name(), "/"); i > 0 {
			add(ResourceID{ResourceGroup: o.Namespace(), Type: o.Kind()[:strings.LastIndex(o.Kind(), "/")], Name: o.Name()[:i]})
		}
	}
	for _, m := range idRE.FindAllString(canon(o.Body["spec"]), -1) {
		if rid, err := ParseID(trimToResource(m)); err == nil {
			add(rid)
			// A reference to a child (a subnet) also needs the child's parent.
			for strings.Count(rid.Type, "/") > 1 {
				rid.Type = rid.Type[:strings.LastIndex(rid.Type, "/")]
				rid.Name = rid.Name[:strings.LastIndex(rid.Name, "/")]
				add(rid)
			}
		}
	}
	return out
}

var idRE = regexp.MustCompile(`/subscriptions/\{\{stackdna\|subscription\}\}/resourceGroups/[^/"]+(/providers/[^/"]+(/[^/"]+/[^/"]+)+)?`)

// trimToResource cuts an ID found in text to an even number of segments
// after providers/{namespace}, so a trailing action or sub-path does not
// make it unparseable.
func trimToResource(id string) string {
	p := strings.Split(strings.Trim(id, "/"), "/")
	if len(p) > 4 && len(p)%2 != 0 {
		p = p[:len(p)-1]
	}
	return "/" + strings.Join(p, "/")
}

func keyOf(rid ResourceID) string {
	ns := rid.ResourceGroup
	name := rid.Name
	if strings.EqualFold(rid.Type, groupType) {
		ns, name = "", rid.ResourceGroup
	}
	return APIVersion + "|" + rid.Type + "|" + ns + "|" + name
}

// restoreOrder sorts objects so each comes after what it depends on that is
// in the snapshot; what is not in the snapshot must already exist.
func restoreOrder(objs []snapshot.Object) (order, cyclic []snapshot.Object) {
	by := map[string]snapshot.Object{}
	for _, o := range objs {
		by[strings.ToLower(o.Key())] = o
	}
	keys := sortedKeys(by)
	done := map[string]bool{}
	for progress := true; progress; {
		progress = false
		for _, k := range keys {
			if done[k] {
				continue
			}
			ready := true
			for _, d := range deps(by[k]) {
				if _, in := by[d]; in && d != k && !done[d] {
					ready = false
				}
			}
			if ready {
				done[k] = true
				order = append(order, by[k])
				progress = true
			}
		}
	}
	for _, k := range keys {
		if !done[k] {
			cyclic = append(cyclic, by[k])
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		return strings.EqualFold(order[i].Kind(), groupType) && !strings.EqualFold(order[j].Kind(), groupType)
	})
	return order, cyclic
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		dm, dok := dst[k].(map[string]any)
		sm, sok := v.(map[string]any)
		if dok && sok {
			merge(dm, sm)
			continue
		}
		dst[k] = v
	}
}

// Adapter is the Azure implementation of platform.Platform: one
// subscription, reached through ARM.
type Adapter struct {
	API      ARM
	Registry *Registry
	Policy   Policy
	Options  RestoreOptions
}

// Name identifies the platform.
func (a *Adapter) Name() string { return "azure" }

// Capture captures the subscription.
func (a *Adapter) Capture(ctx context.Context) (snapshot.Snapshot, error) {
	return Capture(ctx, a.API, a.Registry, a.Policy)
}

// Restore restores a snapshot into the subscription.
func (a *Adapter) Restore(ctx context.Context, s snapshot.Snapshot) []snapshot.Result {
	return Restore(ctx, a.API, a.Registry, s, a.Options)
}
