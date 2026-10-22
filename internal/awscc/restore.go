package awscc

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/stackdna/core/internal/snapshot"
)

// RestoreOptions are the inputs a restore needs beyond the snapshot.
type RestoreOptions struct {
	// Values supplies write-only properties, keyed by "Kind/name"
	// (AWS::Lambda::Function/shop-api). AWS never returns them, so they are
	// never in a snapshot: Lambda code, secret values, initial passwords.
	// They are merged into the spec at create time and not written anywhere.
	Values map[string]map[string]any
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
	resolved := map[string]map[string]any{} // Kind/name -> live properties
	resolved["account/self"] = map[string]any{"id": in.account}
	for _, r := range in.named() {
		existing[r.key()] = r
		resolved[r.t.Name+"/"+r.name] = withID(r.props, r.id)
	}

	order, cyclic := restoreOrder(s.Objects)
	results := make([]snapshot.Result, 0, len(s.Objects))
	for _, o := range cyclic {
		results = append(results, snapshot.Result{Key: o.Key(), Detail: "its references form a cycle; no creation order exists"})
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
	for _, o := range order {
		res := snapshot.Result{Key: o.Key()}
		res.OK, res.Detail = restoreOne(ctx, api, reg, in, o, existing, resolved, inSnap, opt, reread)
		results = append(results, res)
	}
	return results
}

func restoreOne(ctx context.Context, api CloudControl, reg *Registry, in *inv, o snapshot.Object,
	existing map[string]*resource, resolved map[string]map[string]any, inSnap map[string]bool, opt RestoreOptions,
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
	if ex, ok := existing[o.Key()]; ok {
		ch := differs(ex)
		if len(ch) == 0 {
			return true, "already present and identical"
		}
		return false, "already exists in the target and differs (" + strings.Join(ch[0].Fields, ", ") + "); StackDNA does not modify existing resources"
	}
	if !t.Handlers["create"] {
		return false, "Cloud Control cannot create this type"
	}

	spec, _ := o.Body["spec"].(map[string]any)
	desired := deepCopy(spec)
	var missing []string
	walkStrings(desired, func(s string) string {
		return tokenRE.ReplaceAllStringFunc(s, func(tok string) string {
			m := tokenRE.FindStringSubmatch(tok)
			target := m[1] + "/" + m[2]
			v, ok := resolved[target][m[3]].(string)
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
	for _, r := range t.Required {
		if _, ok := desired[r]; !ok {
			if hasTop(t.WriteOnly, r) {
				return false, "required property " + r + " is write-only: AWS never returns it, so it is not in the snapshot; supply it in the restore values for " + ref
			}
			return false, "required property " + r + " is missing from the snapshot"
		}
	}

	id, err := api.Create(ctx, kind, desired)
	if err != nil {
		if ex := reread(o.Key()); ex != nil && len(differs(ex)) == 0 {
			resolved[ref] = withID(ex.props, ex.id)
			return true, "present and identical once restored resources existed: AWS made it as a side effect (" + ex.id + ")"
		}
		return false, err.Error()
	}
	props, err := api.Get(ctx, kind, id)
	// Cloud Control reported a bucket created, then "Bucket not found" on
	// the read straight after (real drill, a bucket recreated minutes
	// after its deletion). A read that follows a successful create and
	// finds nothing is eventual consistency, so it is retried.
	for wait := time.Duration(0); errors.Is(err, ErrNotFound) && wait < readBackLimit; wait += readBackStep {
		select {
		case <-ctx.Done():
			return false, "created " + id + " but could not read it back: " + ctx.Err().Error()
		case <-time.After(readBackStep):
		}
		props, err = api.Get(ctx, kind, id)
	}
	if err != nil {
		return false, "created " + id + " but could not read it back: " + err.Error()
	}
	resolved[ref] = withID(props, id)

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
}

// Name identifies the platform.
func (a *Adapter) Name() string { return "aws" }

// Capture captures the account and region.
func (a *Adapter) Capture(ctx context.Context) (snapshot.Snapshot, error) {
	return Capture(ctx, a.API, a.Registry, a.Region, a.Policy, a.Tuning)
}

// Restore restores a snapshot into the account and region.
func (a *Adapter) Restore(ctx context.Context, s snapshot.Snapshot) []snapshot.Result {
	return Restore(ctx, a.API, a.Registry, s, a.Options, a.Tuning)
}

// String is used in errors and logs.
func (a *Adapter) String() string { return fmt.Sprintf("aws %s", a.Region) }
