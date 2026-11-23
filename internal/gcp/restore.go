package gcp

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/usetruthform/core/internal/schedule"
	"github.com/usetruthform/core/internal/snapshot"
)

var refRE = regexp.MustCompile(`\{\{truthform\|ref\|([^|{}]+)\|([^{}]+)\}\}`)

// RestoreOptions are the choices a restore takes beyond the snapshot.
type RestoreOptions struct {
	// Update patches an existing resource that differs, through the
	// type's own patch (or update) method. Off, a restore only creates.
	Update bool
	// DryRun reads the target and reports each write the restore would
	// make ("would create", "would update", "would add"), and makes none.
	DryRun bool
}

// Restore creates every snapshot object missing from the project, after
// the objects its references name. The target is read first with the same
// rules, so what exists is recognised (by logical name, for resources whose
// IDs the server assigns) and never created twice; with Update, one that
// differs is patched.
func Restore(ctx context.Context, api API, docs *Docs, s snapshot.Snapshot, opt RestoreOptions) []snapshot.Result {
	return restoreWith(ctx, api, docs, s, opt, 8)
}

func restoreWith(ctx context.Context, api API, docs *Docs, s snapshot.Snapshot, opt RestoreOptions, workers int) []snapshot.Result {
	results := make([]snapshot.Result, 0, len(s.Objects))
	fail := func(detail string) []snapshot.Result {
		for _, o := range s.Objects {
			results = append(results, snapshot.Result{Key: o.Key(), Detail: detail})
		}
		return results
	}
	project := api.Project()
	number, err := api.ProjectNumber(ctx)
	if err != nil {
		return fail("cannot identify the target project: " + err.Error())
	}
	need := map[string]bool{}
	for _, o := range s.Objects {
		if o.Kind() != BindingKind {
			need[o.Kind()] = true
		}
	}
	have, _, _, err := inventory(ctx, api, docs, func(t string) bool { return need[t] }, 0)
	if err != nil {
		return fail("cannot read the target: " + err.Error())
	}
	existing := map[string]*res{}
	resolved := &names{m: map[string]string{}, planned: map[string]bool{}} // ref token -> name in the target
	for _, r := range have {
		existing[r.asset.Type+"|"+r.logical] = r
		resolved.set(refToken(r.asset.Type, r.logical), detok(r.rel, project, number))
	}

	// What is outside the project (a service perimeter, which is its
	// access policy's) is in no project's inventory: it is looked for by
	// its own name, and one that cannot be read is not created over.
	unread := map[string]string{}
	for _, o := range s.Objects {
		k := o.Kind() + "|" + o.Name()
		// A binding is a grant on a policy, not a resource: restored on its own.
		if existing[k] != nil || o.Kind() == BindingKind || !outsideProject(o) {
			continue
		}
		switch r, err := readNamed(ctx, api, docs, o, project, number); {
		case errors.Is(err, ErrNotFound):
		case err != nil:
			unread[k] = "cannot tell whether it exists: " + err.Error()
		default:
			existing[k] = r
			resolved.set(refToken(o.Kind(), o.Name()), detok(r.rel, project, number))
		}
	}

	order, cyclic, deps := restoreGraph(s.Objects)
	for _, o := range cyclic {
		results = append(results, snapshot.Result{Key: o.Key(), Detail: "its references form a cycle; no creation order exists"})
	}
	// Each create starts once what it references is done, several at a
	// time; results keep the reference order whatever order they finish in.
	done := make([]snapshot.Result, len(order))
	applies := make([]*pendingApply, len(order))
	locks := &policyLocks{}
	schedule.Run(len(order), deps, workers, func(i int) {
		if why, bad := unread[order[i].Kind()+"|"+order[i].Name()]; bad {
			done[i] = snapshot.Result{Key: order[i].Key(), Detail: why}
			return
		}
		if order[i].Kind() == BindingKind {
			// A grant on a resource's allow policy: added, never created.
			ok, detail := restoreBinding(ctx, api, docs, order[i], project, number, resolved, locks, opt.DryRun)
			done[i] = snapshot.Result{Key: order[i].Key(), OK: ok, Detail: detail}
			return
		}
		ok, detail, apply := restoreOne(ctx, api, docs, order[i], project, number, existing, resolved, opt)
		done[i] = snapshot.Result{Key: order[i].Key(), OK: ok, Detail: detail}
		applies[i] = apply
	})
	// Lists set by a resource's own methods (a network's peerings) are
	// applied once every resource exists, since their items name other
	// resources in both directions; and one at a time: "Google Cloud
	// allows only one peering operation at a time across peered networks"
	// (https://docs.cloud.google.com/vpc/docs/using-vpc-peering).
	for i, a := range applies {
		if a == nil || !done[i].OK {
			continue
		}
		did, err := applyFields(ctx, api, docs, order[i], a.name, a.current, project, number, resolved)
		if did != "" {
			done[i].Detail += "; " + did
		}
		if err != nil {
			done[i].OK = false
			done[i].Detail += "; not finished: " + err.Error()
		}
	}
	return append(results, done...)
}

// pendingApply is a resource whose applied fields are still to be set: its
// name in the target, and its spec there before the restore (nil when the
// restore created it).
type pendingApply struct {
	name    string
	current map[string]any
}

// outsideProject reports an object that belongs to something other than
// the project: its parent is named, and is not under the project.
func outsideProject(o snapshot.Object) bool {
	p := parentOfObject(o)
	return p != "" && !strings.HasPrefix(p, "projects/") && !strings.HasPrefix(o.Name(), "projects/") && !strings.Contains(o.Name(), "/~")
}

// readNamed reads the resource a snapshot object names, as a capture would
// have, from what the object says of its type.
func readNamed(ctx context.Context, api API, docs *Docs, o snapshot.Object, project, number string) (*res, error) {
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	str := func(k string) string { s, _ := ann[k].(string); return s }
	apiName, ver, _ := strings.Cut(str(annDiscovery), "/")
	return read(ctx, api, docs, Asset{Name: "//" + apiName + ".googleapis.com/" + detok(o.Name(), project, number), Type: o.Kind(),
		DiscoveryURI: docURL(apiName, ver), Version: ver, DiscoveryName: str(annSchema)}, project, number)
}

// names maps reference tokens to the names the target gave, shared by the
// creates running at once.
type names struct {
	mu sync.Mutex
	m  map[string]string
	// planned are the names of what a dry run would create: nothing can
	// be read at them.
	planned map[string]bool
}

// plan records what a dry run would create under the name its references
// would be sent with.
func (n *names) plan(k, v string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.m[k] = v
	n.planned[v] = true
}

// isPlanned reports a resource a dry run would create, by its name or the
// name's path under the API's root.
func (n *names) isPlanned(resource string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for p := range n.planned {
		if p == resource || strings.HasSuffix(resource, "/"+p) || strings.HasSuffix(p, "/"+resource) {
			return true
		}
	}
	return false
}

func (n *names) get(k string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	v, ok := n.m[k]
	return v, ok
}

func (n *names) set(k, v string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.m[k] = v
}

func restoreOne(ctx context.Context, api API, docs *Docs, o snapshot.Object, project, number string,
	existing map[string]*res, resolved *names, opt RestoreOptions) (bool, string, *pendingApply) {
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	str := func(k string) string { s, _ := ann[k].(string); return s }
	apiName, ver, _ := strings.Cut(str(annDiscovery), "/")
	spec, _ := o.Body["spec"].(map[string]any)
	self := refToken(o.Kind(), o.Name())
	applied := appliedOfObject(o)

	if ex, ok := existing[o.Kind()+"|"+o.Name()]; ok {
		if sameSpecs(ex.spec, spec, applied) {
			return true, "already present and identical", nil
		}
		ch := snapshot.Compare(snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": map[string]any{"name": o.Name()}, "spec": spec}}}},
			snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": map[string]any{"name": o.Name()}, "spec": ex.spec}}}})
		fields := []string{"spec"}
		if len(ch) > 0 {
			fields = ch[0].Fields
		}
		if !opt.Update {
			return false, "already exists and differs (" + strings.Join(fields, ", ") + "); not modified (--update modifies it)", nil
		}
		var apply *pendingApply
		if len(applied) > 0 {
			apply = &pendingApply{name: detok(ex.rel, project, number), current: ex.spec}
		}
		if opt.DryRun {
			// The lists a resource's own methods set are not applied.
			apply = nil
		}
		if !differsOutsideApplied(spec, ex.spec, applied) {
			if opt.DryRun {
				return true, "would update " + detok(ex.rel, project, number) + " (" + strings.Join(fields, ", ") + ")", nil
			}
			return true, "updated " + apply.name, apply
		}
		ok, detail := update(ctx, api, docs, o, ex, project, number, resolved, opt.DryRun)
		return ok, detail, apply
	}

	doc, err := docs.Doc(docURL(apiName, ver), "")
	if err != nil {
		return false, err.Error(), nil
	}
	create := doc.collectionMethods(str(annCollection))["create"]
	if create == nil {
		create = doc.collectionMethods(str(annCollection))["insert"]
	}
	if create == nil {
		return false, "the " + str(annDiscovery) + " document declares no create method for " + str(annCollection), nil
	}

	// What the resource's own methods set is applied afterwards.
	desired, why := resolveSpec(withoutApplied(spec, applied), resolved, project, number)
	if why != "" {
		return false, why, nil
	}

	id := ""
	if !strings.Contains(o.Name(), "/~") {
		id = detok(o.Name()[strings.LastIndex(o.Name(), "/")+1:], project, number)
		// IAM names a service account by its email but creates it from
		// the email's local part (accountId); no other type uses an email
		// as its ID.
		if i := strings.Index(id, "@"); i > 0 {
			id = id[:i]
		}
	}
	if opt.DryRun {
		if create.HTTPMethod != "PUT" {
			if _, _, werr := wrap(doc, str(annSchema), create, desired, id); werr != nil {
				return false, werr.Error(), nil
			}
		}
		// Its name is the snapshot's unless Google assigns it; either
		// way it is what the references to it would be sent as.
		n := detok(o.Name(), project, number)
		resolved.plan(self, n)
		if strings.Contains(o.Name(), "/~") {
			return true, "would create (Google names it)", nil
		}
		return true, "would create " + n, nil
	}
	var got map[string]any
	if create.HTTPMethod == "PUT" {
		// A create that names the resource in its path (Pub/Sub's
		// PUT v1/{+name}) takes the resource as it is, at its own name.
		got, err = api.Call(ctx, "PUT", doc.URL(create, detok(o.Name(), project, number)), desired)
	} else {
		body, q, werr := wrap(doc, str(annSchema), create, desired, id)
		if werr != nil {
			return false, werr.Error(), nil
		}
		u := doc.URL(create, detok(str(annParent), project, number))
		// A create whose path names no parent takes the project as a
		// query parameter (Cloud Storage's POST b?project=).
		if p, ok := create.Parameters["project"]; ok && p.Location == "query" && p.Required {
			q.Set("project", project)
		}
		if len(q) > 0 {
			u += "?" + q.Encode()
		}
		got, err = api.Call(ctx, "POST", u, body)
	}
	if err != nil {
		return false, err.Error(), nil
	}
	n, _ := got["name"].(string)
	// Compute answers with its short name (net-1); its full name is the
	// path of its selfLink under the API's root.
	if sl, _ := got["selfLink"].(string); !strings.Contains(n, "/") && sl != "" {
		if i := strings.Index(sl, "/projects/"); i >= 0 {
			n = sl[i+1:]
		}
	}
	resolved.set(self, n)
	var apply *pendingApply
	for _, a := range applied {
		if _, order := a.items(spec); len(order) > 0 {
			apply = &pendingApply{name: n}
		}
	}
	return true, "created " + n, apply
}

// resolveSpec replaces reference tokens with the target's names and the
// project tokens with the target project.
func resolveSpec(spec map[string]any, resolved *names, project, number string) (map[string]any, string) {
	var missing string
	desired := rewriteAll(deepCopy(spec), func(s string) string {
		s = refRE.ReplaceAllStringFunc(s, func(tok string) string {
			if n, ok := resolved.get(tok); ok {
				return n
			}
			missing = tok
			return tok
		})
		return detok(s, project, number)
	}).(map[string]any)
	if missing != "" {
		m := refRE.FindStringSubmatch(missing)
		return nil, "depends on " + m[1] + " " + m[2] + ", which is neither restored nor in the target"
	}
	return desired, ""
}

// update patches an existing resource to the snapshot's spec through the
// method its Discovery document declares: patch when there is one, else
// update. The body is what that method takes (the resource, or a request
// holding it), and the mask, where it takes one, names exactly the
// top-level fields that differ, removed ones included, so a field nobody
// captured is never touched and one the snapshot lacks is cleared.
func update(ctx context.Context, api API, docs *Docs, o snapshot.Object, ex *res, project, number string, resolved *names, dryRun bool) (bool, string) {
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	str := func(k string) string { s, _ := ann[k].(string); return s }
	apiName, ver, _ := strings.Cut(str(annDiscovery), "/")
	doc, err := docs.Doc(docURL(apiName, ver), "")
	if err != nil {
		return false, err.Error()
	}
	ms := doc.collectionMethods(str(annCollection))
	m := ms["patch"]
	if m == nil {
		m = ms["update"]
	}
	if m == nil || m.Request == nil {
		return false, "already exists and differs; the " + str(annDiscovery) + " document declares no patch or update method for " + str(annCollection)
	}
	spec, _ := o.Body["spec"].(map[string]any)
	// Without what the resource's own methods set: no patch takes it.
	applied := appliedOfObject(o)
	spec = withoutApplied(spec, applied)
	exSpec := withoutApplied(ex.spec, applied)
	var mask []string
	for _, k := range sortedKeys(spec) {
		if canon(spec[k]) != canon(exSpec[k]) {
			mask = append(mask, k)
		}
	}
	for _, k := range sortedKeys(exSpec) {
		if _, ok := spec[k]; !ok {
			mask = append(mask, k)
		}
	}
	desired, why := resolveSpec(spec, resolved, project, number)
	if why != "" {
		return false, why
	}
	name := detok(ex.rel, project, number)
	// The spec's own name is what the API takes in the body: the full name
	// for AIP resources, the short one for Compute (net-1; its pattern
	// allows no slashes). Only a server-named resource, whose spec has no
	// name, is given the full one.
	if _, ok := desired["name"]; !ok {
		desired["name"] = name
	}
	body := desired
	q := url.Values{}
	masked := false
	if m.Request.Ref != str(annSchema) {
		w := doc.Schemas[m.Request.Ref]
		holder := ""
		for _, k := range sortedKeys(w.Properties) {
			if w.Properties[k].Ref == str(annSchema) {
				holder = k
			}
		}
		if holder == "" {
			return false, m.ID + ": request " + m.Request.Ref + " does not hold a " + str(annSchema)
		}
		body = map[string]any{holder: desired}
		if _, ok := w.Properties["updateMask"]; ok {
			body["updateMask"] = strings.Join(mask, ",")
			masked = true
		}
	} else if _, ok := m.Parameters["updateMask"]; ok {
		q.Set("updateMask", strings.Join(mask, ","))
		masked = true
	}
	// A PATCH with no mask is a JSON merge patch (Compute, Cloud Storage):
	// a field left out of the body is kept, not cleared, so one the
	// snapshot lacks is sent as null. Reported "updated" but not cleared,
	// it would have read as done (review, 2026-10-22). A PUT replaces the
	// whole resource, so leaving it out clears it.
	if !masked && m.HTTPMethod == "PATCH" {
		for _, k := range mask {
			if _, ok := desired[k]; !ok {
				desired[k] = nil
			}
		}
	}
	u := doc.URL(m, name)
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	if dryRun {
		return true, "would update " + name + " (" + strings.Join(mask, ", ") + ")"
	}
	if _, err := api.Call(ctx, m.HTTPMethod, u, body); err != nil {
		return false, err.Error()
	}
	return true, "updated " + name + " (" + strings.Join(mask, ", ") + ")"
}

// namedIn reports a reference to name in s: the name followed by
// something that cannot continue it (a quote, a slash), so net-1 is not
// found inside net-10.
func namedIn(s, name string) bool {
	if !strings.Contains(name, "/") {
		return false
	}
	for i := strings.Index(s, name); i >= 0; {
		end := i + len(name)
		if end == len(s) || !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789-_.", rune(s[end])) {
			return true
		}
		j := strings.Index(s[end:], name)
		if j < 0 {
			return false
		}
		i = end + j
	}
	return false
}

// parentOfObject is the resource an object is created under, as its
// annotation names it: a record set is created after its managed zone.
func parentOfObject(o snapshot.Object) string {
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	p, _ := ann[annParent].(string)
	return p
}

// orderSpec is what decides when an object can be created: its spec and
// its parent, without the lists its own methods set once everything
// exists. Two networks that peer name each other there, which is no cycle.
func orderSpec(o snapshot.Object) string {
	spec, _ := o.Body["spec"].(map[string]any)
	return canon(withoutApplied(spec, appliedOfObject(o))) + "\x00" + parentOfObject(o)
}

func detok(s, project, number string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, tokProject, project), tokNumber, number)
}

func restoreOrder(objs []snapshot.Object) (order, cyclic []snapshot.Object) {
	order, cyclic, _ = restoreGraph(objs)
	return order, cyclic
}

// restoreGraph orders objects so each comes after what it references, and
// gives each one's references as indices into that order.
func restoreGraph(objs []snapshot.Object) (order, cyclic []snapshot.Object, depIdx [][]int) {
	by := map[string]snapshot.Object{}
	for _, o := range objs {
		by[refToken(o.Kind(), o.Name())] = o
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
			spec := orderSpec(by[k])
			for _, tok := range refRE.FindAllString(spec, -1) {
				if _, in := by[tok]; in && tok != k && !done[tok] {
					ready = false
				}
			}
			// A user-named resource is referenced by its name, not a token
			// (a firewall's network: .../global/networks/net-1), and must
			// exist first: by sorted key alone, Firewall came before
			// Network and the fake, as Google, refused it.
			waits := after(by[k])
			for _, other := range keys {
				if other != k && !done[other] && (namedIn(spec, by[other].Name()) || slices.Contains(waits, by[other].Name())) {
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
	at := map[string]int{}
	for i, o := range order {
		at[refToken(o.Kind(), o.Name())] = i
	}
	depIdx = make([][]int, len(order))
	for i, o := range order {
		spec := orderSpec(o)
		for _, tok := range refRE.FindAllString(spec, -1) {
			if j, ok := at[tok]; ok && j != i {
				depIdx[i] = append(depIdx[i], j)
			}
		}
		waits := after(o)
		for j, other := range order {
			if j != i && (namedIn(spec, other.Name()) || slices.Contains(waits, other.Name())) {
				depIdx[i] = append(depIdx[i], j)
			}
		}
	}
	return order, cyclic, depIdx
}

// Adapter is the GCP implementation of platform.Platform: one project.
type Adapter struct {
	API     API
	Docs    *Docs
	Policy  Policy
	Options RestoreOptions
}

// Name identifies the platform.
func (a *Adapter) Name() string { return "gcp" }

// Capture captures the project.
func (a *Adapter) Capture(ctx context.Context) (snapshot.Snapshot, error) {
	return Capture(ctx, a.API, a.Docs, a.Policy)
}

// Restore restores a snapshot into the project.
func (a *Adapter) Restore(ctx context.Context, s snapshot.Snapshot) []snapshot.Result {
	return restoreWith(ctx, a.API, a.Docs, s, a.Options, workers(a.Policy.Parallel))
}

// workers is --parallel for a restore: it was taken by capture only, so
// "--parallel 1" still ran eight creates at once (review of #19).
func workers(n int) int {
	if n <= 0 {
		return 8
	}
	return n
}
