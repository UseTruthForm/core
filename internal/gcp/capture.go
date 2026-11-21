package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/usetruthform/core/internal/snapshot"
)

// APIVersion is the apiVersion of every GCP object in a snapshot; the asset
// type (iam.googleapis.com/ServiceAccount) is the kind.
const APIVersion = "gcp.truthform.org/v1"

const (
	annDiscovery  = "truthform.org/discovery"  // iam/v1
	annSchema     = "truthform.org/schema"     // ServiceAccount
	annCollection = "truthform.org/collection" // projects.serviceAccounts
	annParent     = "truthform.org/parent"     // projects/{{truthform|project}}
	tokProject    = "{{truthform|project}}"
	tokNumber     = "{{truthform|project-number}}"
	refPrefix     = "{{truthform|ref|"
)

// Policy is the set of capture rules, recorded in the snapshot by Name.
type Policy struct {
	Types          []string // asset type patterns (iam.googleapis.com/*)
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
	if len(p.Types) == 0 {
		return true
	}
	for _, pat := range p.Types {
		if ok, _ := path.Match(pat, typ); ok {
			return true
		}
	}
	return false
}

// Prefixes of skip reasons the CLI groups.
const (
	Unreadable   = "listed but could not be read: "
	OwnedByGoog  = "created and owned by Google: "
	ProjectLevel = "project-level, never restored: "
)

// res is one resource as read.
type res struct {
	asset   Asset
	doc     *Doc
	kind    *Kind
	rel     string // tokenized relative name
	logical string // the name used in the snapshot
	spec    map[string]any
	status  map[string]any
}

// Capture reads every selected resource in the project.
func Capture(ctx context.Context, api API, docs *Docs, p Policy) (snapshot.Snapshot, error) {
	rs, cov, skips, err := inventory(ctx, api, docs, p.selected, p.Parallel)
	if err != nil {
		return snapshot.Snapshot{}, err
	}
	snap := snapshot.Snapshot{Platform: "gcp", ServerVersion: "discovery", Policy: p.Name(), Skips: skips}
	seen := map[string]bool{}
	for _, r := range rs {
		obj := toObject(r)
		c := cov[r.asset.Type]
		if p.Baseline != nil {
			if b, ok := p.Baseline[snapshot.Object{Body: obj}.Key()]; ok && sameSpec(obj, b) {
				reason := "identical to the baseline snapshot (already there, or created by Google)"
				snap.Skips = append(snap.Skips, snapshot.Skip{Resource: r.asset.Type, Name: r.logical, Reason: reason})
				if c.Skipped == nil {
					c.Skipped = map[string]int{}
				}
				c.Skipped[reason]++
				continue
			}
		}
		c.Captured++
		snap.Objects = append(snap.Objects, snapshot.Object{Body: obj})
		if !seen[r.asset.Type] {
			seen[r.asset.Type] = true
			f := r.doc.Fields(r.kind.Schema)
			snap.Schemas = append(snap.Schemas, snapshot.TypeSchema{APIVersion: APIVersion, Kind: r.asset.Type, Digest: FieldsDigest(f), Fields: f})
		}
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

// inventory reads, normalizes and names every selected resource. It is
// shared by capture and by restore, which reads the target the same way to
// find what already exists.
func inventory(ctx context.Context, api API, docs *Docs, want func(string) bool, parallel int) ([]*res, map[string]*snapshot.Coverage, []snapshot.Skip, error) {
	number, err := api.ProjectNumber(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	assets, err := api.Assets(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list assets: %w", err)
	}
	project := api.Project()
	cov := map[string]*snapshot.Coverage{}
	var skips []snapshot.Skip
	var mu sync.Mutex
	cover := func(t string) *snapshot.Coverage {
		if cov[t] == nil {
			cov[t] = &snapshot.Coverage{Resource: t, Kind: t}
		}
		return cov[t]
	}
	skip := func(t, name, reason string) {
		mu.Lock()
		defer mu.Unlock()
		c := cover(t)
		if c.Skipped == nil {
			c.Skipped = map[string]int{}
		}
		c.Skipped[strings.SplitN(reason, ": ", 2)[0]]++
		skips = append(skips, snapshot.Skip{Resource: t, Name: name, Reason: reason})
	}

	var todo []Asset
	for _, a := range assets {
		cover(a.Type)
		if !want(a.Type) {
			cov[a.Type].NotCaptured = "not selected (--types)"
			continue
		}
		if why, ok := projectLevel[a.Type]; ok {
			skip(a.Type, tokenizeString(a.RelName(), project, number), ProjectLevel+why)
			continue
		}
		if why := googleOwned(a, project); why != "" {
			skip(a.Type, tokenizeString(a.RelName(), project, number), OwnedByGoog+why)
			continue
		}
		todo = append(todo, a)
	}
	if parallel <= 0 {
		parallel = 8
	}
	out := make([]*res, len(todo))
	errs := make([]error, len(todo))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, a := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i], errs[i] = read(ctx, api, docs, a, project, number)
		}()
	}
	wg.Wait()

	var rs []*res
	for i, a := range todo {
		switch {
		case errors.Is(errs[i], ErrNotFound):
			continue // deleted between list and read
		case errors.As(errs[i], new(ownedError)):
			var oe ownedError
			errors.As(errs[i], &oe)
			skip(a.Type, oe.name, OwnedByGoog+oe.why)
			continue
		case errors.Is(errs[i], ErrUnsupported):
			cover(a.Type).NotCaptured = "API not enabled or not available in this project"
			continue
		case errs[i] != nil:
			skip(a.Type, tokenizeString(a.RelName(), project, number), Unreadable+errs[i].Error())
			continue
		}
		rs = append(rs, out[i])
	}
	name(rs)
	return rs, cov, skips, nil
}

// projectLevel are asset types about the project itself, never restored. A
// restore runs into an existing project and must not create one, and must
// never link billing or enable APIs: both are decisions that spend money,
// for a person to make before restoring.
var projectLevel = map[string]string{
	"cloudresourcemanager.googleapis.com/Project":    "the project itself; restore runs into an existing project",
	"cloudbilling.googleapis.com/ProjectBillingInfo": "the billing link; a person links billing, never a restore",
	"serviceusage.googleapis.com/Service":            "an enabled API; enable APIs before restoring (enabling can start billing)",
}

// googleOwned reports resources Google creates and owns in every project:
// IDs starting with "_" are reserved by the services (Logging's _Default
// and _Required sinks and buckets), and service accounts outside the
// project's own iam.gserviceaccount.com domain are Google's (the Compute
// default account, App Engine's).
func googleOwned(a Asset, project string) string {
	rel := a.RelName()
	id := rel[strings.LastIndex(rel, "/")+1:]
	switch {
	case strings.HasPrefix(id, "_"):
		return "IDs starting with _ are reserved by the service"
	case strings.Contains(id, "@") && !strings.HasSuffix(id, "@"+project+".iam.gserviceaccount.com"):
		return "a service account in Google's domain " + id[strings.Index(id, "@")+1:]
	}
	return ""
}

// ownedError reports a resource found to be Google's only once read.
type ownedError struct{ why, name string }

func (e ownedError) Error() string { return e.why }

func read(ctx context.Context, api API, docs *Docs, a Asset, project, number string) (*res, error) {
	doc, err := docs.Doc(a.DiscoveryURI, a.Version)
	if err != nil {
		return nil, err
	}
	k, err := doc.Kind(a.DiscoveryName, a.RelName())
	if err != nil {
		return nil, err
	}
	data, err := api.Call(ctx, "GET", doc.URL(k.Get, a.RelName()), nil)
	if err != nil {
		return nil, err
	}
	// The resource's own name field is canonical. Cloud Asset Inventory
	// can name it differently: it names service accounts by their numeric
	// uniqueId, IAM by email. Taken from the inventory, every service
	// account looked server-named (and was restored without an accountId),
	// and Google's default accounts passed the domain check unrecognised.
	canonical := a.RelName()
	if n, ok := data["name"].(string); ok && strings.HasPrefix(n, "projects/") && strings.Count(n, "/") == strings.Count(canonical, "/") {
		canonical = n
	}
	if why := googleOwned(Asset{Name: "//x/" + canonical, Type: a.Type}, project); why != "" {
		return nil, ownedError{why: why, name: tokenizeString(canonical, project, number)}
	}
	spec, ro := doc.normalize(k.Schema, data)
	for _, a := range appliedOf(doc.Name, k.Schema) {
		// Each item's state goes to the status under the item's name, and
		// the list is kept in the order of its names, whatever order the
		// server lists it in.
		a.itemStatus(doc, data, ro)
		a.sort(spec)
	}
	rel := tokenizeString(canonical, project, number)
	spec = tokenize(spec, project, number)
	status := map[string]any{"name": rel}
	for k, v := range ro {
		if s, ok := v.(string); ok {
			v = tokenizeString(s, project, number)
		}
		status[k] = v
	}
	r := &res{asset: a, doc: doc, kind: k, rel: rel, spec: spec, status: status, logical: rel}
	if generatedID(canonical) {
		// The server chose this ID; its name differs in every project.
		// "name" in the spec is the same server-chosen value, never input,
		// and so is any name nested under it (an alert policy's conditions:
		// .../alertPolicies/ID/conditions/CID, flagged nowhere). Left in,
		// they would become references to the resource itself.
		delete(r.spec, "name")
		dropUnder(r.spec, rel+"/")
		label, _ := spec["displayName"].(string)
		if label == "" {
			h := sha256.Sum256([]byte(a.Type + "\x00" + canon(spec)))
			label = "h-" + hex.EncodeToString(h[:6])
		}
		r.logical = parentOf(rel) + "/" + collLast(k.Collection) + "/~" + sanitize(label)
	}
	return r, nil
}

// name replaces references to server-assigned names with tokens restore
// resolves to the names the target project assigns, and makes logical
// names unique.
func name(rs []*res) {
	used := map[string]int{}
	sort.Slice(rs, func(i, j int) bool { return rs[i].asset.Type+rs[i].logical < rs[j].asset.Type+rs[j].logical })
	refs := map[string]string{}
	for _, r := range rs {
		if r.logical == r.rel {
			continue
		}
		used[r.asset.Type+r.logical]++
		if n := used[r.asset.Type+r.logical]; n > 1 {
			r.logical = fmt.Sprintf("%s-%d", r.logical, n)
		}
		refs[r.rel] = refToken(r.asset.Type, r.logical)
	}
	if len(refs) == 0 {
		return
	}
	names := sortedKeys(refs)
	sort.SliceStable(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, r := range rs {
		r.spec = walkStrings(r.spec, func(s string) string {
			for _, n := range names {
				if strings.Contains(s, n) {
					s = strings.ReplaceAll(s, n, refs[n])
				}
			}
			return s
		}).(map[string]any)
	}
}

// refToken names a resource relative to its project. A reference must not
// contain the project token itself: nested tokens defeat the pattern that
// finds references, and replacing the inner one alone corrupted the outer
// (the fake refused the result in the first GCP drill).
func refToken(typ, logical string) string {
	return refPrefix + typ + "|" + strings.TrimPrefix(logical, "projects/"+tokProject+"/") + "}}"
}

func toObject(r *res) map[string]any {
	ann := map[string]any{
		annDiscovery:  r.doc.Name + "/" + r.doc.Version,
		annSchema:     r.kind.Schema,
		annCollection: r.kind.Collection,
		annParent:     parentIn(r.rel, r.kind.Create),
	}
	return map[string]any{"apiVersion": APIVersion, "kind": r.asset.Type,
		"metadata": map[string]any{"name": r.logical, "annotations": ann}, "spec": r.spec, "status": r.status}
}

// tokenize makes a spec portable across projects: the project ID (in
// names, and in service account emails) and the project number become
// tokens, in values and in map keys.
func tokenize(spec map[string]any, project, number string) map[string]any {
	return rewriteAll(spec, func(s string) string { return tokenizeString(s, project, number) }).(map[string]any)
}

func tokenizeString(s, project, number string) string {
	s = strings.ReplaceAll(s, "projects/"+project+"/", "projects/"+tokProject+"/")
	if strings.HasSuffix(s, "projects/"+project) {
		s = strings.TrimSuffix(s, project) + tokProject
	}
	s = strings.ReplaceAll(s, "@"+project+".", "@"+tokProject+".")
	// A project's workload identity pool is named after it
	// (PROJECT_ID.svc.id.goog, in a GKE cluster's workloadPool and in the
	// members of that pool): kept, a restored cluster asked for the source
	// project's pool.
	if pool := project + ".svc.id.goog"; strings.Contains(s, pool) {
		s = poolRE(project).ReplaceAllString(s, "${1}"+tokProject+".svc.id.goog")
	}
	if number != "" {
		s = strings.ReplaceAll(s, "projects/"+number+"/", "projects/"+tokNumber+"/")
		if strings.HasSuffix(s, "projects/"+number) {
			s = strings.TrimSuffix(s, number) + tokNumber
		}
	}
	if s == project {
		return tokProject
	}
	if number != "" && s == number {
		return tokNumber
	}
	return s
}

func parentOf(rel string) string {
	p := strings.Split(rel, "/")
	if len(p) < 2 {
		return ""
	}
	return strings.Join(p[:len(p)-2], "/")
}

// parentIn is the resource a resource was created under. A name is
// usually parent/collection/id; one named by several of its fields (a
// Cloud DNS record set: rrsets/<name>/<type>) has a longer tail, so the
// parent is as long as its create method's path says: everything before
// the collection's word. Taken as two segments, a captured record set
// named its parent ".../rrsets", and differed from every snapshot that
// wrote its zone.
func parentIn(rel string, create *Method) string {
	if create != nil && !strings.Contains(create.Path, "{+") {
		n := len(strings.Split(nameTemplate(create.Path), "/")) - 1
		if segs := strings.Split(rel, "/"); n > 0 && n < len(segs) {
			return strings.Join(segs[:n], "/")
		}
	}
	return parentOf(rel)
}

func collLast(c string) string { return c[strings.LastIndex(c, ".")+1:] }

func sanitize(s string) string {
	return strings.NewReplacer("|", "_", "{", "_", "}", "_", "/", "_").Replace(s)
}

func sameSpec(obj, base map[string]any) bool {
	return reflect.DeepEqual(canon(map[string]any{"m": obj["metadata"], "s": obj["spec"]}), canon(map[string]any{"m": base["metadata"], "s": base["spec"]}))
}

// dropUnder removes map entries whose string value is a name under prefix.
func dropUnder(v any, prefix string) {
	switch c := v.(type) {
	case map[string]any:
		for k, x := range c {
			if s, ok := x.(string); ok && strings.HasPrefix(s, prefix) {
				delete(c, k)
				continue
			}
			dropUnder(x, prefix)
		}
	case []any:
		for _, x := range c {
			dropUnder(x, prefix)
		}
	}
}

// poolRE finds a project's workload identity pool where the project ID is
// a whole name, not the end of a longer one.
func poolRE(project string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^a-z0-9-])` + regexp.QuoteMeta(project) + `\.svc\.id\.goog`)
}
