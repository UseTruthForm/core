package gcp

import (
	"context"
	"net/url"
	"regexp"
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
		need[o.Kind()] = true
	}
	have, _, _, err := inventory(ctx, api, docs, func(t string) bool { return need[t] }, 0)
	if err != nil {
		return fail("cannot read the target: " + err.Error())
	}
	existing := map[string]*res{}
	resolved := &names{m: map[string]string{}} // ref token -> name in the target
	for _, r := range have {
		existing[r.asset.Type+"|"+r.logical] = r
		resolved.set(refToken(r.asset.Type, r.logical), detok(r.rel, project, number))
	}

	order, cyclic, deps := restoreGraph(s.Objects)
	for _, o := range cyclic {
		results = append(results, snapshot.Result{Key: o.Key(), Detail: "its references form a cycle; no creation order exists"})
	}
	// Each create starts once what it references is done, several at a
	// time; results keep the reference order whatever order they finish in.
	done := make([]snapshot.Result, len(order))
	schedule.Run(len(order), deps, workers, func(i int) {
		ok, detail := restoreOne(ctx, api, docs, order[i], project, number, existing, resolved, opt)
		done[i] = snapshot.Result{Key: order[i].Key(), OK: ok, Detail: detail}
	})
	return append(results, done...)
}

// names maps reference tokens to the names the target gave, shared by the
// creates running at once.
type names struct {
	mu sync.Mutex
	m  map[string]string
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
	existing map[string]*res, resolved *names, opt RestoreOptions) (bool, string) {
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	str := func(k string) string { s, _ := ann[k].(string); return s }
	apiName, ver, _ := strings.Cut(str(annDiscovery), "/")
	spec, _ := o.Body["spec"].(map[string]any)
	self := refToken(o.Kind(), o.Name())

	if ex, ok := existing[o.Kind()+"|"+o.Name()]; ok {
		if canon(ex.spec) == canon(spec) {
			return true, "already present and identical"
		}
		ch := snapshot.Compare(snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": map[string]any{"name": o.Name()}, "spec": spec}}}},
			snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": map[string]any{"name": o.Name()}, "spec": ex.spec}}}})
		fields := []string{"spec"}
		if len(ch) > 0 {
			fields = ch[0].Fields
		}
		if !opt.Update {
			return false, "already exists and differs (" + strings.Join(fields, ", ") + "); not modified (--update modifies it)"
		}
		return update(ctx, api, docs, o, ex, project, number, resolved)
	}

	doc, err := docs.Doc(docURL(apiName, ver), "")
	if err != nil {
		return false, err.Error()
	}
	create := doc.collectionMethods(str(annCollection))["create"]
	if create == nil {
		create = doc.collectionMethods(str(annCollection))["insert"]
	}
	if create == nil {
		return false, "the " + str(annDiscovery) + " document declares no create method for " + str(annCollection)
	}

	desired, why := resolveSpec(spec, resolved, project, number)
	if why != "" {
		return false, why
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
	var got map[string]any
	if create.HTTPMethod == "PUT" {
		// A create that names the resource in its path (Pub/Sub's
		// PUT v1/{+name}) takes the resource as it is, at its own name.
		got, err = api.Call(ctx, "PUT", doc.URL(create, detok(o.Name(), project, number)), desired)
	} else {
		body, q, werr := wrap(doc, str(annSchema), create, desired, id)
		if werr != nil {
			return false, werr.Error()
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
		return false, err.Error()
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
	return true, "created " + n
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
func update(ctx context.Context, api API, docs *Docs, o snapshot.Object, ex *res, project, number string, resolved *names) (bool, string) {
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
	var mask []string
	for _, k := range sortedKeys(spec) {
		if canon(spec[k]) != canon(ex.spec[k]) {
			mask = append(mask, k)
		}
	}
	for _, k := range sortedKeys(ex.spec) {
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
			spec := canon(by[k].Body["spec"]) + "\x00" + parentOfObject(by[k])
			for _, tok := range refRE.FindAllString(spec, -1) {
				if _, in := by[tok]; in && tok != k && !done[tok] {
					ready = false
				}
			}
			// A user-named resource is referenced by its name, not a token
			// (a firewall's network: .../global/networks/net-1), and must
			// exist first: by sorted key alone, Firewall came before
			// Network and the fake, as Google, refused it.
			for _, other := range keys {
				if other != k && !done[other] && namedIn(spec, by[other].Name()) {
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
		spec := canon(o.Body["spec"]) + "\x00" + parentOfObject(o)
		for _, tok := range refRE.FindAllString(spec, -1) {
			if j, ok := at[tok]; ok && j != i {
				depIdx[i] = append(depIdx[i], j)
			}
		}
		for j, other := range order {
			if j != i && namedIn(spec, other.Name()) {
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
