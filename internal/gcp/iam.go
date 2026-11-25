package gcp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/usetruthform/core/internal/snapshot"
)

// IAM role bindings on a resource.
//
// A resource's allow policy is not a resource of its own: nothing creates
// it, and it is read and written whole with the resource's getIamPolicy and
// setIamPolicy methods. A snapshot holds a grant as an object of the kind
// BindingKind: its parent is the resource, and its spec a fragment of a
// policy, the bindings to add:
//
//	spec: {bindings: [{role: roles/pubsub.publisher, members: [serviceAccount:...]}]}
//
// Restoring one is additive and nothing else. The policy is read, each
// member the snapshot names is added to the unconditional binding of its
// role, and the whole policy is written back with the etag it was read
// with, as Google documents ("allow policies are updated using the
// read-modify-write pattern", https://docs.cloud.google.com/iam/docs/allow-policies).
// No member, binding or condition already there is removed or changed: a
// restore never takes away access it did not write. A policy that already
// holds every member is left alone, and reported "already present and
// identical".
//
// A capture does not read allow policies, so a capture of a project holds
// no object of this kind: only a snapshot written by a translation does.
const (
	BindingKind = "iam.googleapis.com/Binding"
	// annAfter names, separated by commas, objects that must exist before
	// a binding is written though its spec does not name them as a
	// reference does: the service account that is its member (named by
	// its email), the cluster that makes the workload identity pool.
	annAfter = "truthform.org/after"
	// iamAttempts is how often a whole read-modify-write is tried.
	iamAttempts = 6
)

// policyLocks serializes the read-modify-writes of one restore on one
// resource: two bindings of the same topic written at once would each read
// the policy and one would lose on the etag.
type policyLocks struct {
	mu sync.Mutex
	m  map[string]*sync.Mutex
}

func (l *policyLocks) of(resource string) *sync.Mutex {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*sync.Mutex{}
	}
	if l.m[resource] == nil {
		l.m[resource] = &sync.Mutex{}
	}
	return l.m[resource]
}

// after are the object names a binding waits for: its resource and what
// its annotation lists.
func after(o snapshot.Object) []string {
	if o.Kind() != BindingKind {
		return nil
	}
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	out := []string{parentOfObject(o)}
	if s, _ := ann[annAfter].(string); s != "" {
		out = append(out, strings.Split(s, ",")...)
	}
	return out
}

// wanted reads a binding object's spec: role -> members, with every token
// resolved. Anything but unconditional bindings is refused: a restore that
// dropped a condition would grant more than the snapshot says.
func wanted(spec map[string]any, resolved *names, project, number string) (map[string][]string, string) {
	desired, why := resolveSpec(spec, resolved, project, number)
	if why != "" {
		return nil, why
	}
	for k := range desired {
		if k != "bindings" {
			return nil, "a binding object holds only bindings; " + k + " is not restored"
		}
	}
	bs, _ := desired["bindings"].([]any)
	if len(bs) == 0 {
		return nil, "it holds no bindings"
	}
	out := map[string][]string{}
	for _, x := range bs {
		b, _ := x.(map[string]any)
		role, _ := b["role"].(string)
		ms, _ := b["members"].([]any)
		if role == "" || len(ms) == 0 {
			return nil, "a binding needs a role and members"
		}
		for k := range b {
			if k != "role" && k != "members" {
				return nil, "a binding with " + k + " is not restored: only unconditional bindings are"
			}
		}
		for _, m := range ms {
			s, _ := m.(string)
			if s == "" {
				return nil, "a member is not a string"
			}
			out[role] = append(out[role], s)
		}
	}
	return out, ""
}

// addMembers adds the wanted members to a policy's unconditional bindings
// and reports what it added. Nothing in the policy is removed.
func addMembers(policy map[string]any, want map[string][]string) []string {
	var added []string
	bs, _ := policy["bindings"].([]any)
	for _, role := range sortedKeys(want) {
		var at map[string]any
		for _, x := range bs {
			b, _ := x.(map[string]any)
			if b["role"] == role && b["condition"] == nil {
				at = b
				break
			}
		}
		have := map[string]bool{}
		if at != nil {
			for _, m := range at["members"].([]any) {
				have[fmt.Sprint(m)] = true
			}
		}
		for _, m := range want[role] {
			if have[m] {
				continue
			}
			have[m] = true
			if at == nil {
				at = map[string]any{"role": role, "members": []any{}}
				bs = append(bs, at)
			}
			at["members"] = append(at["members"].([]any), m)
			added = append(added, role+" to "+m)
		}
	}
	policy["bindings"] = bs
	sort.Strings(added)
	return added
}

// restoreBinding adds a binding object's members to its resource's policy.
func restoreBinding(ctx context.Context, api API, docs *Docs, o snapshot.Object, project, number string, resolved *names, locks *policyLocks, dryRun bool) (bool, string) {
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	str := func(k string) string { s, _ := ann[k].(string); return s }
	apiName, ver, _ := strings.Cut(str(annDiscovery), "/")
	doc, err := docs.Doc(docURL(apiName, ver), "")
	if err != nil {
		return false, err.Error()
	}
	ms := doc.collectionMethods(str(annCollection))
	get, set := ms["getIamPolicy"], ms["setIamPolicy"]
	if get == nil || set == nil || set.Request == nil {
		return false, "the " + str(annDiscovery) + " document declares no getIamPolicy and setIamPolicy for " + str(annCollection)
	}
	spec, _ := o.Body["spec"].(map[string]any)
	want, why := wanted(spec, resolved, project, number)
	if why != "" {
		return false, why
	}
	resource := detok(str(annParent), project, number)
	if resource == "" {
		return false, "it names no resource (" + annParent + ")"
	}
	if dryRun && resolved.isPlanned(resource) {
		// Its resource is not there to read a policy from.
		return true, "would add " + strings.Join(addMembers(map[string]any{}, want), ", ") + " on " + resource + " (once created)"
	}
	l := locks.of(resource)
	l.Lock()
	defer l.Unlock()

	// Version 3 is asked for, so a policy with conditions comes back with
	// them and is written back with them: "If you omit the etag field, then
	// IAM lets you overwrite a version 3 allow policy with a version 1
	// allow policy, which deletes all of the conditions"
	// (https://docs.cloud.google.com/iam/docs/allow-policies). The
	// parameter's name is the method's own (Cloud Storage spells it
	// optionsRequestedPolicyVersion).
	getURL := doc.URL(get, resource)
	var getBody any
	versioned := false
	for _, p := range sortedKeys(get.Parameters) {
		if strings.HasSuffix(strings.ToLower(strings.ReplaceAll(p, ".", "")), "requestedpolicyversion") && get.Parameters[p].Location == "query" {
			getURL += "?" + p + "=3"
			versioned = true
		}
	}
	if get.HTTPMethod == "POST" {
		getBody = map[string]any{}
	}
	var last string
	for attempt := 0; attempt < iamAttempts; attempt++ {
		policy, err := api.Call(ctx, get.HTTPMethod, getURL, getBody)
		if err != nil {
			return false, "cannot read the policy of " + resource + ": " + err.Error()
		}
		if policy == nil {
			policy = map[string]any{}
		}
		etag, _ := policy["etag"].(string)
		added := addMembers(policy, want)
		if len(added) == 0 {
			return true, "already present and identical"
		}
		if etag == "" {
			// Without an etag the write would replace whatever anyone
			// wrote since the read. A dry run says the same.
			return false, "the policy of " + resource + " came without an etag: not written, as a write without one can undo another's"
		}
		if dryRun {
			return true, "would add " + strings.Join(added, ", ") + " on " + resource
		}
		if versioned {
			policy["version"] = 3
		}
		var body map[string]any = policy
		if set.Request.Ref != "Policy" {
			w := doc.Schemas[set.Request.Ref]
			holder := ""
			if w != nil {
				for _, k := range sortedKeys(w.Properties) {
					if w.Properties[k].Ref == "Policy" {
						holder = k
					}
				}
			}
			if holder == "" {
				return false, set.ID + ": request " + set.Request.Ref + " does not hold a Policy"
			}
			body = map[string]any{holder: policy}
		}
		_, err = api.Call(ctx, set.HTTPMethod, doc.URL(set, resource), body)
		if err == nil {
			return true, "added " + strings.Join(added, ", ") + " on " + resource
		}
		last = err.Error()
		switch {
		case conflict(last):
			// "If you receive this error, retry the entire series of
			// operations: read the allow policy again, modify it as
			// needed, and write the updated allow policy."
			continue
		case notYet(last):
			// "After you create a service account, you might need to wait
			// for 60 seconds or more before you use the service account
			// ... you can retry the request with exponential backoff"
			// (https://docs.cloud.google.com/iam/docs/service-accounts-create).
			if werr := sleepCtx(ctx, min(time.Duration(1<<attempt)*time.Second+jitter(), maxBackoff)); werr != nil {
				return false, last + ": " + werr.Error()
			}
			continue
		}
		return false, last
	}
	return false, fmt.Sprintf("gave up after %d tries: %s", iamAttempts, last)
}

// conflict reports IAM's answer to a policy written with a stale etag:
// "For the REST API, you receive the HTTP status code 409 Conflict" with
// status ABORTED (allow-policies); Cloud Storage answers 412 to a failed
// precondition.
func conflict(msg string) bool {
	return strings.Contains(msg, "ABORTED") || strings.Contains(msg, "HTTP 409") || strings.Contains(msg, "HTTP 412")
}

// notYet reports a member Google does not know yet: a service account
// created a moment ago.
func notYet(msg string) bool {
	return strings.Contains(msg, "does not exist") && (strings.Contains(msg, "ervice account") || strings.Contains(msg, "serviceAccount"))
}
