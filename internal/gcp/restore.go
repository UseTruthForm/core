package gcp

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/stackdna/core/internal/snapshot"
)

var refRE = regexp.MustCompile(`\{\{stackdna\|ref\|([^|{}]+)\|([^{}]+)\}\}`)

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
	resolved := map[string]string{} // ref token -> name in the target
	for _, r := range have {
		existing[r.asset.Type+"|"+r.logical] = r
		resolved[refToken(r.asset.Type, r.logical)] = detok(r.rel, project, number)
	}

	order, cyclic := restoreOrder(s.Objects)
	for _, o := range cyclic {
		results = append(results, snapshot.Result{Key: o.Key(), Detail: "its references form a cycle; no creation order exists"})
	}
	for _, o := range order {
		ok, detail := restoreOne(ctx, api, docs, o, project, number, existing, resolved, opt)
		results = append(results, snapshot.Result{Key: o.Key(), OK: ok, Detail: detail})
	}
	return results
}

func restoreOne(ctx context.Context, api API, docs *Docs, o snapshot.Object, project, number string,
	existing map[string]*res, resolved map[string]string, opt RestoreOptions) (bool, string) {
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
	body, q, err := wrap(doc, str(annSchema), create, desired, id)
	if err != nil {
		return false, err.Error()
	}
	u := doc.URL(create, detok(str(annParent), project, number))
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	got, err := api.Call(ctx, "POST", u, body)
	if err != nil {
		return false, err.Error()
	}
	n, _ := got["name"].(string)
	resolved[self] = n
	return true, "created " + n
}

// resolveSpec replaces reference tokens with the target's names and the
// project tokens with the target project.
func resolveSpec(spec map[string]any, resolved map[string]string, project, number string) (map[string]any, string) {
	var missing string
	desired := rewriteAll(deepCopy(spec), func(s string) string {
		s = refRE.ReplaceAllStringFunc(s, func(tok string) string {
			if n, ok := resolved[tok]; ok {
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
func update(ctx context.Context, api API, docs *Docs, o snapshot.Object, ex *res, project, number string, resolved map[string]string) (bool, string) {
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
	desired["name"] = name
	body := desired
	q := url.Values{}
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
		}
	} else if _, ok := m.Parameters["updateMask"]; ok {
		q.Set("updateMask", strings.Join(mask, ","))
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

func detok(s, project, number string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, tokProject, project), tokNumber, number)
}

func restoreOrder(objs []snapshot.Object) (order, cyclic []snapshot.Object) {
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
			for _, tok := range refRE.FindAllString(canon(by[k].Body["spec"]), -1) {
				if _, in := by[tok]; in && tok != k && !done[tok] {
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
	return order, cyclic
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
	return Restore(ctx, a.API, a.Docs, s, a.Options)
}
