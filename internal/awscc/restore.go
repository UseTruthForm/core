package awscc

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stackdna/core/internal/schedule"
	"github.com/stackdna/core/internal/snapshot"
)

// RestoreOptions are the inputs a restore needs beyond the snapshot.
type RestoreOptions struct {
	// Values supplies write-only properties, keyed by "Kind/name"
	// (AWS::Lambda::Function/shop-api). AWS never returns them, so they are
	// never in a snapshot: Lambda code, secret values, initial passwords.
	// They are merged into the spec at create time and not written anywhere.
	Values map[string]map[string]any
	// Update brings an existing resource that differs in line with the
	// snapshot. Off, a restore only creates what is missing and reports
	// what differs; that stays the default because an update changes a
	// resource someone may depend on as it is.
	Update bool
}

// readBackStep and readBackLimit bound the wait for a created resource to
// become readable. Variables so tests need not wait.
var readBackStep, readBackLimit = 5 * time.Second, 2 * time.Minute

var tokenRE = regexp.MustCompile(`\{\{stackdna\|([^|{}]+)\|([^|{}]+)\|([^|{}]+)\}\}`)

// Restore creates every snapshot object that is missing from the target, in
// reference order, resolving each reference token to the value the target
// generated. It never modifies or deletes what already exists: an object
// already present and identical is reported applied, and one present but
// different is reported not applied, with the fields that differ.
func Restore(ctx context.Context, api CloudControl, reg *Registry, s snapshot.Snapshot, opt RestoreOptions, tun Tuning) []snapshot.Result {
	// The target is read with the same naming rules first, so existing
	// resources (a previous partial restore, the default VPC a token points
	// at) are recognised by logical name instead of being created twice.
	need := map[string]bool{}
	for _, o := range s.Objects {
		need[o.Kind()] = true
		for _, m := range tokenRE.FindAllStringSubmatch(canon(o.Body["spec"]), -1) {
			need[m[1]] = true
		}
	}
	in, err := inventory(ctx, api, reg, func(n string) bool { return need[n] }, tun)
	if err != nil {
		results := make([]snapshot.Result, 0, len(s.Objects))
		for _, o := range s.Objects {
			results = append(results, snapshot.Result{Key: o.Key(), Detail: "cannot read the target: " + err.Error()})
		}
		return results
	}
	existing := map[string]*resource{}
	resolved := &values{m: map[string]map[string]any{}} // Kind/name -> live properties
	resolved.set("account/self", map[string]any{"id": in.account})
	for _, r := range in.named() {
		existing[r.key()] = r
		resolved.set(r.t.Name+"/"+r.name, withID(r.props, r.id))
	}

	order, cyclic := restoreOrder(s.Objects)
	var defs []deferral
	// full holds, for a deferred member already in the target, its whole
	// snapshot object: it is compared whole when it runs. The order and
	// the dependency graph stay those of the stripped copy.
	full := map[string]snapshot.Object{}
	if len(cyclic) > 0 {
		var stripped []snapshot.Object
		stripped, defs, _ = breakCycles(reg, order, cyclic)
		// Ordered again even when some cycle stays unbroken: the cycles
		// that were broken are still restored, and only what is left in
		// (or depends on) an unbroken one is reported and not sent. The
		// first version ordered nothing new then, and the broken cycles'
		// members got no result at all (review of #26).
		order, cyclic = restoreOrder(append(order, stripped...))
		stuck := map[string]bool{}
		for _, o := range cyclic {
			stuck[o.Key()] = true
		}
		// A cycle only constrains what has to be created. One already in
		// the target is compared with its full snapshot, not the stripped
		// copy: compared stripped, a policy present with its Roles was
		// reported as differing (real IAM drill's second restore,
		// 2026-10-24).
		kept := defs[:0:0]
		for _, d := range defs {
			switch {
			case stuck[d.full.Key()]:
			case existing[d.full.Key()] != nil:
				full[d.full.Key()] = d.full
			default:
				kept = append(kept, d)
			}
		}
		defs = kept
	}
	results := make([]snapshot.Result, 0, len(s.Objects))
	for _, o := range cyclic {
		results = append(results, snapshot.Result{Key: o.Key(), Detail: "its references form a cycle that cannot be broken (a property naming the others is required or create-only); no creation order exists"})
	}
	// A create can make others as a side effect: a security group's inline
	// rules are also listed as AWS::EC2::SecurityGroupIngress resources,
	// and a default security group comes with its own. Restoring those
	// separately is refused (AWS answered "InternalFailure Resource Handler
	// Internal Failure" for the duplicate rule, real drill 2026-10-22), so
	// a refused create rereads the target to see whether it is now there.
	reread := func(key string) *resource {
		again, err := inventory(ctx, api, reg, func(n string) bool { return need[n] }, tun)
		if err != nil {
			return nil
		}
		for _, r := range again.named() {
			if r.key() == key {
				return r
			}
		}
		return nil
	}
	inSnap := map[string]bool{}
	for _, o := range s.Objects {
		inSnap[o.Kind()+"/"+o.Name()] = true
	}
	// Each object starts once what its tokens name is done, several at a
	// time; results keep the reference order whatever order they finish.
	at := map[string]int{}
	for i, o := range order {
		at[o.Kind()+"/"+o.Name()] = i
	}
	deps := make([][]int, len(order))
	for i, o := range order {
		for _, m := range tokenRE.FindAllStringSubmatch(canon(o.Body["spec"]), -1) {
			if d, ok := at[m[1]+"/"+m[2]]; ok && d != i {
				deps[i] = append(deps[i], d)
			}
		}
	}
	done := make([]snapshot.Result, len(order))
	workers := tun.Parallel
	if workers <= 0 {
		workers = 8
	}
	schedule.Run(len(order), deps, workers, func(i int) {
		o := order[i]
		if f, ok := full[o.Key()]; ok {
			o = f
		}
		res := snapshot.Result{Key: o.Key()}
		res.OK, res.Detail = restoreOne(ctx, api, reg, in, o, existing, resolved, inSnap, opt, reread)
		done[i] = res
	})
	// The deferred properties, now that everything they name exists: the
	// object is read back and brought in line with its full snapshot, as
	// --update would. One reread for all of them, of only their types and
	// the types they name (the same set the first inventory used for
	// them), rather than a full reread per deferred object.
	var again map[string]*resource
	var rereadErr error
	rereadFailed := map[string]string{} // type -> why it was not read again
	if len(defs) > 0 {
		want := map[string]bool{}
		for _, d := range defs {
			want[d.full.Kind()] = true
			for _, m := range tokenRE.FindAllStringSubmatch(canon(d.full.Body["spec"]), -1) {
				want[m[1]] = true
			}
		}
		again = map[string]*resource{}
		in2, err := inventory(ctx, api, reg, func(n string) bool { return want[n] }, tun)
		rereadErr = err
		if err == nil {
			for _, r := range in2.named() {
				again[r.key()] = r
			}
			for n, c := range in2.cov {
				if c != nil && c.NotCaptured != "" {
					rereadFailed[n] = c.NotCaptured
				}
			}
		}
	}
	for _, d := range defs {
		for i := range done {
			if done[i].Key != d.full.Key() || !done[i].OK {
				continue
			}
			ex := again[d.full.Key()]
			if ex == nil {
				// Said as it is: "not found" would hide a throttled or
				// refused read (review of #26).
				why := "not found again"
				switch {
				case rereadErr != nil:
					why = "the target could not be read again (" + rereadErr.Error() + ")"
				case rereadFailed[d.full.Kind()] != "":
					why = "the target could not be read again (" + rereadFailed[d.full.Kind()] + ")"
				}
				done[i].OK, done[i].Detail = false, done[i].Detail+"; then "+why+" to set "+strings.Join(d.props, ", ")
				break
			}
			upd := opt
			upd.Update = true
			ok, detail := restoreOne(ctx, api, reg, in, d.full, map[string]*resource{d.full.Key(): ex}, resolved, inSnap, upd, reread)
			if !ok {
				done[i].OK, done[i].Detail = false, done[i].Detail+"; then setting "+strings.Join(d.props, ", ")+" failed: "+detail
			} else {
				done[i].Detail += deferredNote(d.props)
			}
			break
		}
	}
	return append(results, done...)
}

// values is what a restore has learned about the target (each restored or
// found object's properties), shared by the creates running at once.
type values struct {
	mu sync.Mutex
	m  map[string]map[string]any
}

func (v *values) get(k string) map[string]any {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.m[k]
}

func (v *values) set(k string, p map[string]any) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.m[k] = p
}

// submitted retries a write refused for throttling before AWS accepted it:
// with many creates at once, the account's rate is shared. Only that is
// retried (ErrNotAccepted): a request AWS accepted may be in progress or
// have done part of its work, and is reported, never sent again. Judging by
// the message alone resent a create whose status poll had been throttled.
// submitBackoff is the first wait between refused submissions (doubling
// to 64 times it). A variable so a test need not wait.
var submitBackoff = time.Second

func submitted(ctx context.Context, f func() error) error {
	for attempt := 0; ; attempt++ {
		err := f()
		if err == nil || !errors.Is(err, ErrNotAccepted) || attempt == throttleRetries {
			return err
		}
		wait := time.Duration(1<<min(attempt, 6)) * submitBackoff
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait + time.Duration(rand.Int64N(int64(wait)))):
		}
	}
}

func restoreOne(ctx context.Context, api CloudControl, reg *Registry, in *inv, o snapshot.Object,
	existing map[string]*resource, resolved *values, inSnap map[string]bool, opt RestoreOptions,
	reread func(key string) *resource) (bool, string) {
	kind, ref := o.Kind(), o.Kind()+"/"+o.Name()
	t := reg.Types[kind]
	if t == nil {
		return false, "type " + kind + " is not in the schema registry"
	}
	if c := in.cov[kind]; c != nil && c.NotCaptured != "" {
		return false, "cannot check the target for an existing one: " + c.NotCaptured
	}
	differs := func(ex *resource) []snapshot.Change {
		return snapshot.Compare(snapshot.Snapshot{Objects: []snapshot.Object{o}}, snapshot.Snapshot{Objects: []snapshot.Object{{Body: toObject(ex)}}})
	}
	ex, exists := existing[o.Key()]
	if exists {
		ch := differs(ex)
		if len(ch) == 0 {
			return true, "already present and identical"
		}
		if !opt.Update {
			return false, "already exists in the target and differs (" + strings.Join(ch[0].Fields, ", ") + "); not modified (--update modifies it)"
		}
		if !t.Handlers["update"] {
			return false, "already exists in the target and differs (" + strings.Join(ch[0].Fields, ", ") + "); Cloud Control cannot update this type"
		}
	} else if !t.Handlers["create"] {
		return false, "Cloud Control cannot create this type"
	}

	spec, _ := o.Body["spec"].(map[string]any)
	desired := deepCopy(spec)
	var missing []string
	walkStrings(desired, func(s string) string {
		return tokenRE.ReplaceAllStringFunc(s, func(tok string) string {
			m := tokenRE.FindStringSubmatch(tok)
			target := m[1] + "/" + m[2]
			v, ok := resolved.get(target)[m[3]].(string)
			if !ok {
				missing = append(missing, target)
				return tok
			}
			return v
		})
	})
	if len(missing) > 0 {
		sort.Strings(missing)
		why := "is not in the target"
		if inSnap[missing[0]] {
			why = "was not restored"
		}
		return false, "depends on " + missing[0] + ", which " + why
	}

	vals := opt.Values[ref]
	merge(desired, deepCopy(vals))
	if exists {
		return update(ctx, api, t, ref, ex, desired, resolved)
	}
	for _, r := range t.Required {
		if _, ok := desired[r]; !ok {
			if hasTop(t.WriteOnly, r) {
				return false, "required property " + r + " is write-only: AWS never returns it, so it is not in the snapshot; supply it in the restore values for " + ref
			}
			return false, "required property " + r + " is missing from the snapshot"
		}
	}

	var id string
	err := submitted(ctx, func() (err error) { id, err = api.Create(ctx, kind, desired); return err })
	if err != nil {
		if ex := reread(o.Key()); ex != nil && len(differs(ex)) == 0 {
			resolved.set(ref, withID(ex.props, ex.id))
			return true, "present and identical once restored resources existed: AWS made it as a side effect (" + ex.id + ")"
		}
		return false, err.Error()
	}
	props, err := readBack(ctx, api, kind, id)
	if err != nil {
		return false, "created " + id + " but could not read it back: " + err.Error()
	}
	resolved.set(ref, withID(props, id))

	detail := "created " + id
	var without []string
	for _, w := range writeOnlyFields(t) {
		if _, ok := vals[strings.FieldsFunc(w, func(r rune) bool { return r == '.' || r == '[' })[0]]; !ok {
			without = append(without, w)
		}
	}
	if len(without) > 0 {
		detail += "; write-only, not supplied: " + strings.Join(without, ", ")
	}
	return true, detail
}

func withID(props map[string]any, id string) map[string]any {
	m := deepCopy(props)
	m["identifier"] = id
	return m
}

func hasTop(ptrs []string, prop string) bool {
	for _, p := range ptrs {
		if segments(p)[0] == prop {
			return true
		}
	}
	return false
}

// merge copies src into dst, recursing into objects present in both.
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

// restoreOrder sorts objects so every object comes after the objects its
// tokens reference. Objects caught in a cycle are returned separately.
func restoreOrder(objs []snapshot.Object) (order, cyclic []snapshot.Object) {
	byRef := map[string]snapshot.Object{}
	for _, o := range objs {
		byRef[o.Kind()+"/"+o.Name()] = o
	}
	deps := map[string][]string{}
	for _, o := range objs {
		self := o.Kind() + "/" + o.Name()
		for _, m := range tokenRE.FindAllStringSubmatch(canon(o.Body["spec"]), -1) {
			if d := m[1] + "/" + m[2]; d != self {
				if _, ok := byRef[d]; ok {
					deps[self] = append(deps[self], d)
				}
			}
		}
	}
	done := map[string]bool{}
	refs := sortedKeys(byRef)
	for progress := true; progress; {
		progress = false
		for _, r := range refs {
			if done[r] {
				continue
			}
			ready := true
			for _, d := range deps[r] {
				ready = ready && done[d]
			}
			if ready {
				done[r] = true
				order = append(order, byRef[r])
				progress = true
			}
		}
	}
	for _, r := range refs {
		if !done[r] {
			cyclic = append(cyclic, byRef[r])
		}
	}
	return order, cyclic
}

// Adapter is the AWS implementation of platform.Platform: one account and
// region, reached through Cloud Control.
type Adapter struct {
	API      CloudControl
	Registry *Registry
	Region   string
	Policy   Policy
	Options  RestoreOptions
	Tuning   Tuning
	// ZoneMap overrides the zone pairing for a restore from another
	// region, by zone ID ("use2-az1": "usw2-az3").
	ZoneMap map[string]string
}

// Name identifies the platform.
func (a *Adapter) Name() string { return "aws" }

// Capture captures the account and region.
func (a *Adapter) Capture(ctx context.Context) (snapshot.Snapshot, error) {
	return Capture(ctx, a.API, a.Registry, a.Region, a.Policy, a.Tuning)
}

// Restore restores a snapshot into the account and region.
func (a *Adapter) Restore(ctx context.Context, s snapshot.Snapshot) []snapshot.Result {
	s, _, err := a.ForRegion(ctx, s)
	if err != nil {
		results := make([]snapshot.Result, 0, len(s.Objects))
		for _, o := range s.Objects {
			results = append(results, snapshot.Result{Key: o.Key(), Detail: "not restored into " + a.Region + ": " + err.Error()})
		}
		return results
	}
	return Restore(ctx, a.API, a.Registry, s, a.Options, a.Tuning)
}

// String is used in errors and logs.
func (a *Adapter) String() string { return fmt.Sprintf("aws %s", a.Region) }

// hasPointerPrefix reports ptr, or a pointer above it, in ptrs.
func hasPointerPrefix(ptrs []string, ptr string) bool {
	for _, p := range ptrs {
		if p == ptr || strings.HasPrefix(ptr, p+"/") {
			return true
		}
	}
	return false
}

// readBack reads a resource just created or updated. Cloud Control
// reported a bucket created, then "Bucket not found" on the read straight
// after (real drill, a bucket recreated minutes after its deletion). A read
// that follows a successful write and finds nothing is eventual
// consistency, so it is retried.
func readBack(ctx context.Context, api CloudControl, kind, id string) (map[string]any, error) {
	props, err := api.Get(ctx, kind, id)
	for wait := time.Duration(0); errors.Is(err, ErrNotFound) && wait < readBackLimit; wait += readBackStep {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(readBackStep):
		}
		props, err = api.Get(ctx, kind, id)
	}
	return props, err
}

// update patches an existing resource to the snapshot's spec. The live
// side is the raw read normalized afresh: the inventory's own spec has its
// references tokenized and desired has them resolved, so only raw values
// compare. A change to a create-only property is refused, not made: AWS
// would replace the resource, deleting what depends on it.
func update(ctx context.Context, api CloudControl, t *TypeInfo, ref string, ex *resource, desired map[string]any, resolved *values) (bool, string) {
	live := normalize(t, ex.id, ex.props).spec
	// The snapshot sorted its sets by the tokens in them; resolved, they
	// can be out of order, and the reordered subnet list of a node group
	// read as a change to a create-only property, so the update was
	// refused (review, 2026-10-22). Sorted as the live side is.
	sortSets(desired, map[string]any{"properties": t.Properties}, t.Definitions)
	ops, replace := planUpdate(t, live, desired)
	if len(replace) > 0 {
		return false, "differs in " + strings.Join(replace, ", ") + ", which AWS can only change by replacing the resource; StackDNA does not replace resources"
	}
	if len(ops) == 0 {
		return true, "already present; it differs only in how references are named"
	}
	if err := submitted(ctx, func() error { return api.Update(ctx, t.Name, ex.id, ops) }); err != nil {
		return false, err.Error()
	}
	props, err := readBack(ctx, api, t.Name, ex.id)
	if err != nil {
		return false, "updated " + ex.id + " but could not read it back: " + err.Error()
	}
	resolved.set(ref, withID(props, ex.id))
	paths := make([]string, len(ops))
	for i, op := range ops {
		paths[i] = strings.TrimPrefix(op.Path, "/")
	}
	return true, "updated " + ex.id + " (" + strings.Join(paths, ", ") + ")"
}

// planUpdate returns the JSON Patch that turns live into desired, one
// operation per top-level property, and the create-only fields that
// differ. A property live has and desired lacks is removed: the snapshot
// was read the same way, so its absence there means it was unset.
func planUpdate(t *TypeInfo, live, desired map[string]any) (ops []PatchOp, replace []string) {
	for _, k := range sortedKeys(desired) {
		lv, ok := live[k]
		switch {
		case !ok:
			ops = append(ops, PatchOp{Op: "add", Path: "/" + k, Value: desired[k]})
		case canon(lv) != canon(desired[k]):
			ops = append(ops, PatchOp{Op: "replace", Path: "/" + k, Value: desired[k]})
		}
	}
	for _, k := range sortedKeys(live) {
		if _, ok := desired[k]; !ok {
			ops = append(ops, PatchOp{Op: "remove", Path: "/" + k})
		}
	}
	return ops, createOnlyChanges(t, live, desired)
}

// createOnlyChanges names the create-only fields whose values differ. A
// pointer through an array ("*") is compared at its top-level property,
// which may over-report but never misses a replacement.
func createOnlyChanges(t *TypeInfo, a, b map[string]any) []string {
	var out []string
	seen := map[string]bool{}
	for _, ptr := range t.CreateOnly {
		// A create-only field that is also write-only is never read back,
		// so it cannot be compared: a value supplied for it would always
		// "differ" and refuse every update.
		if hasPointerPrefix(t.WriteOnly, ptr) {
			continue
		}
		var field string
		if strings.Contains(ptr, "*") {
			top := segments(ptr)[0]
			if canon(a[top]) != canon(b[top]) {
				field = top
			}
		} else {
			x, xok := lookupPointer(a, ptr)
			y, yok := lookupPointer(b, ptr)
			if xok != yok || canon(x) != canon(y) {
				field = strings.Join(segments(ptr), ".")
			}
		}
		if field != "" && !seen[field] {
			seen[field] = true
			out = append(out, field)
		}
	}
	sort.Strings(out)
	return out
}
