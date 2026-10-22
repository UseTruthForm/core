package azarm

import (
	"context"
	"errors"
	"fmt"
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
	// Update PUTs the snapshot's body over an existing resource that
	// differs. ARM's PUT replaces the resource's configuration in place;
	// a change Azure cannot make in place is refused by Azure, never done
	// by deleting and re-creating.
	Update bool
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
	byKey := map[string]snapshot.Object{}
	for _, o := range s.Objects {
		byKey[strings.ToLower(o.Key())] = o
	}
	order, cyclic := restoreOrder(s.Objects)
	for _, o := range cyclic {
		results = append(results, snapshot.Result{Key: o.Key(), Detail: "its references form a cycle; no creation order exists"})
	}
	failed := map[string]string{}
	// present marks a resource found in the target though not applied (it
	// differs and was left alone). Its dependents can still be restored:
	// they name it by ID, and it is there. Counting it as failed blocked a
	// web app and a role assignment behind an identity whose only
	// difference was a tag.
	present := map[string]bool{}
	for _, o := range order {
		res := snapshot.Result{Key: o.Key()}
		res.OK, res.Detail = restoreOne(ctx, api, reg, o, sub, tenant, opt, failed, byKey, present)
		if !res.OK && !present[strings.ToLower(o.Key())] {
			failed[strings.ToLower(o.Key())] = res.Detail
		}
		results = append(results, res)
	}
	return results
}

func objectID(o snapshot.Object, sub string) ResourceID {
	if ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any); ann != nil {
		if id, _ := ann[annID].(string); id != "" {
			if rid, err := ParseID(strings.ReplaceAll(id, tokSub, sub)); err == nil {
				return rid
			}
		}
	}
	if strings.EqualFold(o.Kind(), groupType) {
		return ResourceID{Subscription: sub, ResourceGroup: o.Name(), Type: groupType, Name: o.Name()}
	}
	return ResourceID{Subscription: sub, ResourceGroup: o.Namespace(), Type: o.Kind(), Name: o.Name()}
}

func restoreOne(ctx context.Context, api ARM, reg *Registry, o snapshot.Object, sub, tenant string, opt RestoreOptions, failed map[string]string, byKey map[string]snapshot.Object, present map[string]bool) (bool, string) {
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
	// References to values the target generated (a restored identity's new
	// principalId) are resolved first, so the comparison below sees what
	// would be sent.
	var missing string
	spec = rewriteAll(deepCopy(spec), func(v string) string {
		return refRE.ReplaceAllStringFunc(v, func(tok string) string {
			got, err := resolveRef(ctx, api, sub, tok, byKey)
			if err != nil {
				missing = err.Error()
				return tok
			}
			return got
		})
	}).(map[string]any)
	if missing != "" {
		return false, missing
	}

	existing, err := api.Get(ctx, id, ver)
	var changed []string
	switch {
	case err == nil:
		present[strings.ToLower(o.Key())] = true
		got, _ := schema.normalize(existing)
		got = tokenize(got, sub, tenant)
		ch := snapshot.Compare(snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": o.Body["metadata"], "spec": spec}}}},
			snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": o.Body["metadata"], "spec": got}}}})
		if len(ch) == 0 {
			return true, "already present and identical"
		}
		if !opt.Update {
			return false, "already exists and differs (" + strings.Join(ch[0].Fields, ", ") + "); not modified (--update modifies it)"
		}
		changed = ch[0].Fields
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
	var unsupplied []string
	if s, _ := ann[annSecrets].(string); s != "" {
		for _, p := range strings.Split(s, ",") {
			if _, ok := lookup(vals, strings.Split(p, ".")); !ok {
				unsupplied = append(unsupplied, p)
			}
		}
	}
	// A PUT replaces the whole configuration, and a secret Azure never
	// returns is not in the snapshot: updating without it would send the
	// resource without its credential.
	if changed != nil && len(unsupplied) > 0 {
		return false, "already exists and differs (" + strings.Join(changed, ", ") + "); not updated: its secret fields (" + strings.Join(unsupplied, ", ") + ") are never returned, so a PUT would send it without them; supply them with --values"
	}
	if _, err := api.Put(ctx, id, ver, desired); err != nil {
		return false, err.Error()
	}
	detail := "created " + id
	if changed != nil {
		detail = "updated " + id + " (" + strings.Join(changed, ", ") + ")"
	}
	if len(unsupplied) > 0 {
		detail += "; secret, not supplied: " + strings.Join(unsupplied, ", ")
	}
	return true, detail
}

// resolveRef reads a referenced value from the target: the referenced
// object's ID in the target, then the value at the token's path.
func resolveRef(ctx context.Context, api ARM, sub, tok string, byKey map[string]snapshot.Object) (string, error) {
	m := refRE.FindStringSubmatch(tok)
	key := strings.ToLower(APIVersion + "|" + m[1] + "|" + m[2] + "|" + m[3])
	r, ok := byKey[key]
	if !ok {
		return "", fmt.Errorf("refers to %s %s/%s, which is not in the snapshot", m[1], m[2], m[3])
	}
	ann, _ := r.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	ver, _ := ann[annAPIVersion].(string)
	body, err := api.Get(ctx, objectID(r, sub).String(), ver)
	if err != nil {
		return "", fmt.Errorf("refers to %s %s/%s: %v", m[1], m[2], m[3], err)
	}
	v, ok := lookup(body, strings.Split(m[4], "."))
	if s, isStr := v.(string); ok && isStr {
		return s, nil
	}
	return "", fmt.Errorf("refers to %s of %s %s/%s, which the target does not have", m[4], m[1], m[2], m[3])
}

// deps lists the snapshot keys (lower case) an object needs first: its
// resource group, its parent, its scope, what its references name, and
// every resource its spec's IDs name.
func deps(o snapshot.Object) []string {
	var out []string
	add := func(rid ResourceID) {
		out = append(out, strings.ToLower(keyOf(rid)))
	}
	for _, m := range refRE.FindAllStringSubmatch(canon(o.Body["spec"]), -1) {
		out = append(out, strings.ToLower(APIVersion+"|"+m[1]+"|"+m[2]+"|"+m[3]))
	}
	extension := false
	if ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any); ann != nil {
		if id, _ := ann[annID].(string); id != "" {
			if rid, err := ParseID(id); err == nil {
				extension = rid.Extension()
				if rid.Scope != "" {
					if sc, err := ParseID(rid.Scope); err == nil {
						add(sc)
					}
				}
			}
		}
	}
	if !strings.EqualFold(o.Kind(), groupType) && o.Namespace() != "" {
		add(ResourceID{ResourceGroup: o.Namespace(), Type: groupType, Name: o.Namespace()})
		// An extension resource's name is a path below its scope, not a
		// parent/child name; its scope, added above, is what it needs.
		if i := strings.LastIndex(o.Name(), "/"); i > 0 && !extension {
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
