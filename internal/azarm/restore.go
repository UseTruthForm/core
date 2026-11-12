package azarm

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/usetruthform/core/internal/schedule"
	"github.com/usetruthform/core/internal/snapshot"
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
	// Types limits the restore to matching types (Policy.Types' patterns), so a
	// run can be staged. A child goes with its parent's type, and resource groups
	// always come. What a selected resource needs and was not selected must
	// already be there, or Azure refuses it and the resource says so.
	Types []string
}

// NewRoleAssignmentIDs gives each role assignment a new name, the same every
// time for a given target. A role assignment's name is unique across a tenant
// even at a narrower scope, so in the source's tenant each one is refused while
// the source exists, and an AKS cluster's identity loses what it was granted.
// A diff of that target needs the same, or each reads as missing and extra.
func NewRoleAssignmentIDs(s snapshot.Snapshot, target string) snapshot.Snapshot {
	out := s
	out.Objects = make([]snapshot.Object, len(s.Objects))
	for i, o := range s.Objects {
		out.Objects[i] = o
		if !strings.EqualFold(o.Kind(), "Microsoft.Authorization/roleAssignments") {
			continue
		}
		body := deepCopy(o.Body)
		md := body["metadata"].(map[string]any)
		name, _ := md["name"].(string)
		old := name[strings.LastIndex(name, "/")+1:]
		guid := newGUID(target, old)
		md["name"] = strings.TrimSuffix(name, old) + guid
		if ann, _ := md["annotations"].(map[string]any); ann != nil {
			if id, _ := ann[annID].(string); id != "" {
				ann[annID] = strings.TrimSuffix(id, old) + guid
			}
		}
		out.Objects[i] = snapshot.Object{Body: body}
	}
	return out
}

// newGUID is a version 5 style GUID of a target and a name.
func newGUID(target, name string) string {
	h := sha1.Sum([]byte(strings.ToLower(target) + "|" + strings.ToLower(name)))
	h[6], h[8] = h[6]&0x0f|0x50, h[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// selected keeps the objects of the given types. path.Match's * stops at a slash,
// so Microsoft.Network/* alone would drop a network's peerings, with every result
// reading as fine.
func selected(objs []snapshot.Object, types []string) []snapshot.Object {
	if len(types) == 0 {
		return objs
	}
	var out []snapshot.Object
	for _, o := range objs {
		if selectedForRestore(o.Kind(), types) {
			out = append(out, o)
		}
	}
	return out
}

func selectedForRestore(kind string, types []string) bool {
	p := Policy{Types: types}
	for {
		if p.selected(kind) {
			return true
		}
		i := strings.LastIndex(kind, "/")
		if i < 0 || !strings.Contains(kind[:i], "/") {
			return false
		}
		kind = kind[:i]
	}
}

// UnmatchedTypes lists the patterns no object in the snapshot matches. A typo
// restored only the resource groups, with every result reading as fine.
func UnmatchedTypes(s snapshot.Snapshot, types []string) []string {
	var out []string
	for _, t := range types {
		found := false
		for _, o := range s.Objects {
			if !strings.EqualFold(o.Kind(), groupType) && selectedForRestore(o.Kind(), []string{t}) {
				found = true
				break
			}
		}
		if !found {
			out = append(out, t)
		}
	}
	return out
}

// UnmatchedValues lists the --values keys no object in the snapshot has, each
// with the key it was probably meant for when one differs only in case. Such a
// key was ignored, and the restore said "created" with the snapshot's value
// (re-review of #73; keys are matched exactly, as they are looked up).
func UnmatchedValues(s snapshot.Snapshot, values map[string]map[string]any) []string {
	have := map[string]string{}
	for _, o := range s.Objects {
		k := valuesRef(o, objectID(o, tokSub))
		have[k] = k
		have[strings.ToLower(k)] = k
	}
	var out []string
	for k := range values {
		if _, ok := have[k]; ok && have[k] == k {
			continue
		}
		if near, ok := have[strings.ToLower(k)]; ok {
			out = append(out, k+" (the snapshot has "+near+")")
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Restore creates every snapshot object missing from the subscription, in
// dependency order: resource groups, then parents before children, then
// every resource after the resources its IDs point at. It never modifies or
// deletes: a resource already present and identical is reported applied,
// one present but different is reported not applied.
func Restore(ctx context.Context, api ARM, reg *Registry, s snapshot.Snapshot, opt RestoreOptions) []snapshot.Result {
	return restoreWith(ctx, api, reg, s, opt, 8)
}

func restoreWith(ctx context.Context, api ARM, reg *Registry, s snapshot.Snapshot, opt RestoreOptions, workers int) []snapshot.Result {
	sub := api.Subscription()
	tenant, err := api.Tenant(ctx)
	results := make([]snapshot.Result, 0, len(s.Objects))
	if err != nil {
		for _, o := range s.Objects {
			results = append(results, snapshot.Result{Key: o.Key(), Detail: "cannot identify the target tenant: " + err.Error()})
		}
		return results
	}
	// All of them: a reference can name what an earlier stage restored.
	byKey := map[string]snapshot.Object{}
	for _, o := range s.Objects {
		byKey[strings.ToLower(o.Key())] = o
	}
	chosen := selected(s.Objects, opt.Types)
	order, cyclic, deps := restoreGraph(chosen)
	// present marks a resource found in the target though not applied (it
	// differs and was left alone). Its dependents can still be restored:
	// they name it by ID, and it is there. Counting it as failed blocked a
	// web app and a role assignment behind an identity whose only
	// difference was a tag.
	out := &outcomes{failed: map[string]string{}, present: map[string]bool{}, created: map[string]bool{}, partial: len(chosen) != len(s.Objects)}
	for _, o := range cyclic {
		results = append(results, snapshot.Result{Key: o.Key(), Detail: "its references form a cycle; no creation order exists"})
	}
	// Each PUT starts once what it depends on is done, several at a time;
	// results keep the dependency order whatever order they finish in.
	done := make([]snapshot.Result, len(order))
	schedule.Run(len(order), deps, workers, func(i int) {
		o := order[i]
		res := snapshot.Result{Key: o.Key()}
		res.OK, res.Detail = restoreOne(ctx, api, reg, o, sub, tenant, opt, out, byKey)
		if !res.OK {
			out.fail(strings.ToLower(o.Key()), res.Detail)
			out.setNotOK()
		}
		done[i] = res
	})
	return append(results, done...)
}

// outcomes is what the PUTs running at once have learned: what failed
// (its dependents say so), and what is present though not applied.
type outcomes struct {
	mu      sync.Mutex
	failed  map[string]string
	present map[string]bool
	created map[string]bool
	notOK   bool
	partial bool // a staged run: what is held back is still to come
}

func (o *outcomes) setNotOK() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.notOK = true
}

func (o *outcomes) markCreated(k string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.created[k] = true
}

func (o *outcomes) wasCreated(k string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.created[k]
}

// anyNotOK says something was not applied, of any kind. failed will not do: it
// leaves out what is present, so a lock went on after a conflict or a failed
// update, which are what a re-run is for.
func (o *outcomes) anyNotOK() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.notOK
}

func (o *outcomes) fail(k, why string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.present[k] {
		o.failed[k] = why
	}
}

func (o *outcomes) failure(k string) (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	why, bad := o.failed[k]
	return why, bad
}

func (o *outcomes) markPresent(k string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.present[k] = true
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

func restoreOne(ctx context.Context, api ARM, reg *Registry, o snapshot.Object, sub, tenant string, opt RestoreOptions, out *outcomes, byKey map[string]snapshot.Object) (bool, string) {
	for _, d := range deps(o) {
		if why, bad := out.failure(d); bad {
			return false, "depends on " + d + ", which was not restored (" + why + ")"
		}
	}
	// Captured before capture skipped it, it is still not sent: Azure refuses it.
	if why := madeWithParent(o, byKey, opt.Values); why != "" {
		return true, NotSent + why
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
			// Back in the form the rest of the spec is in: an AKS issuer holds
			// the tenant, and a comparison would see every one as changed.
			return tokenizeString(got, sub, tenant)
		})
	}).(map[string]any)
	if missing != "" {
		return false, missing
	}
	// A snapshot written before capture said so leaves it unset too, and one
	// written before capture dropped them holds what Azure sets.
	asCapturedNow(rid.Type, o.Name(), spec)
	// What --values gives is what would be sent, so the comparison sees it
	// too; secrets aside, which Azure never returns. Compared without it,
	// the first real restore reported a cluster whose node size --values
	// had set as differing on every run after.
	if v := opt.Values[valuesRef(o, rid)]; v != nil {
		mergeGiven(spec, v, ann, sub, tenant)
	}

	existing, err := api.Get(ctx, id, ver)
	var changed []string
	switch {
	case err == nil:
		// A resource that failed to provision has the right configuration and
		// does not work. Its spec matches, so this read "already present and
		// identical", and nothing downstream could tell.
		if state := unfinished(existing); state != "" {
			return false, "exists but its provisioning state is " + state + "; " + unfinishedAdvice(state)
		}
		if strings.Contains(notWorking(existing), "Disconnected") {
			return false, "exists but is disconnected from the far side; delete it and run the restore again"
		}
		out.markPresent(strings.ToLower(o.Key()))
		got, _ := schema.normalize(existing)
		got = tokenize(got, sub, tenant)
		labelWithoutSubscription(got, sub)
		shared := strings.EqualFold(rid.Type, roleDefinitionType) && sharedRole(spec, got)
		if strings.EqualFold(rid.Type, vnetType) {
			keepAttached(spec, got, byKey)
		}
		// Compared as a diff compares (ForCompare), on copies: what is sent
		// is the spec as it is.
		cw, cg := deepCopy(spec), deepCopy(got)
		comparable(o.Kind(), cw, cg)
		ch := snapshot.Compare(snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": o.Body["metadata"], "spec": cw}}}},
			snapshot.Snapshot{Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": APIVersion, "kind": o.Kind(), "metadata": o.Body["metadata"], "spec": cg}}}})
		if len(ch) == 0 {
			return true, "already present and identical"
		}
		// Even with --update: a role is one thing across its tenant, so a PUT
		// here changes it for every subscription it can be assigned in.
		if shared {
			return false, "this role is shared with other subscriptions and differs (" + strings.Join(ch[0].Fields, ", ") + "); not modified, since a change would reach them too"
		}
		// Azure makes some children with their parent, with its own defaults (a
		// storage account's blobServices/default). If this run just created the
		// parent, no one else's change can be in the child, and without this
		// every such child was reported as a conflict on a clean target.
		if !opt.Update && !parentCreated(o, out) {
			return false, "already exists and differs (" + strings.Join(ch[0].Fields, ", ") + "); not modified (--update modifies it)"
		}
		changed = ch[0].Fields
	case !errors.Is(err, ErrNotFound):
		return false, "cannot check whether it exists: " + err.Error()
	}

	// Azure makes AzureDiagnostics, and refuses to; its settings go once it is there.
	if err != nil && isDiagnosticsTable(rid.Type, o.Name()) {
		if diagnosticsTableFlagless(spec) {
			return true, NotSent + DiagnosticsTableLater + DiagnosticsTableFlagless
		}
		if diagnosticsTableSet(spec) {
			return true, NotSent + DiagnosticsTableLater
		}
		return true, NotSent + DiagnosticsTableDefault
	}
	desired := rewriteAll(deepCopy(spec), func(v string) string {
		return strings.ReplaceAll(strings.ReplaceAll(v, tokSub, sub), tokTenant, tenant)
	}).(map[string]any)
	vals := opt.Values[valuesRef(o, rid)]
	merge(desired, deepCopy(vals))
	if isAzureTable(rid.Type, o.Name()) {
		diagnosticsTableBody(desired)
	}
	var unsupplied []string
	if s, _ := ann[annSecrets].(string); s != "" {
		for _, p := range strings.Split(s, ",") {
			if _, ok := lookup(vals, strings.Split(p, ".")); !ok && !usesManagedIdentity(spec, p) {
				unsupplied = append(unsupplied, p)
			}
		}
	}
	// A cluster with a windowsProfile is refused without its admin password,
	// though it has no Windows pool: AKS gives every cluster one. In the first
	// real restore of a cluster, Azure answered "The value of parameter
	// windowsProfile.adminPassword is invalid" after the size and add-on were
	// fixed. Said here, with how to give it.
	if changed == nil && strings.EqualFold(rid.Type, managedClusterType) && slices.Contains(unsupplied, "properties.windowsProfile.adminPassword") {
		if props, _ := desired["properties"].(map[string]any); props["windowsProfile"] != nil {
			return false, "Azure makes a cluster with a windowsProfile only with its admin password, even with no Windows pool; it is never returned, so give properties.windowsProfile.adminPassword with --values (any password AKS accepts: 14 to 123 characters, three of lower, upper, digit and symbol)"
		}
	}
	// A PUT replaces the whole configuration, and a secret Azure never
	// returns is not in the snapshot: updating without it would send the
	// resource without its credential.
	if changed != nil && len(unsupplied) > 0 {
		return false, "already exists and differs (" + strings.Join(changed, ", ") + "); not updated: its secret fields (" + strings.Join(unsupplied, ", ") + ") are never returned, so a PUT would send it without them; supply them with --values"
	}
	// Locks go last, so by here everything else has an answer. A ReadOnly lock
	// put on after a failure would refuse the re-run that fixes it, and a
	// CanNotDelete one would stand in the way of clearing the target. One already
	// there and identical was answered above.
	if strings.EqualFold(rid.Type, "Microsoft.Authorization/locks") && (out.partial || out.anyNotOK()) {
		return false, "held back because something else was not applied or is still to come; a lock would block that. A full run applies it"
	}
	// A PUT replaces the whole network, and the snapshot holds its peerings as
	// children: an update without them would cut every peering it has.
	if changed != nil && strings.EqualFold(rid.Type, vnetType) {
		was, _ := existing["properties"].(map[string]any)
		if props, ok := desired["properties"].(map[string]any); ok && was["virtualNetworkPeerings"] != nil {
			props["virtualNetworkPeerings"] = was["virtualNetworkPeerings"]
		}
	}
	// A role's ID is unique across a tenant, and answers at a subscription only
	// if the role can be assigned there. So in the source's tenant this looks
	// absent, and a PUT would take over the source's role, narrowing it to this
	// subscription and breaking what is assigned there.
	if changed == nil && strings.EqualFold(rid.Type, roleDefinitionType) {
		tenantWide := "/providers/Microsoft.Authorization/roleDefinitions/" + lastName(rid.Name)
		switch _, err := api.Get(ctx, tenantWide, ver); {
		case err == nil:
			return false, "a role with this ID already exists in this tenant, for other subscriptions; a restore would change it for them. Add this subscription to its assignableScopes, then run the restore again"
		case !errors.Is(err, ErrNotFound):
			return false, "cannot check whether this role already exists in the tenant: " + err.Error()
		}
	}
	if _, err := api.Put(ctx, id, ver, desired); err != nil {
		// The same principal, role and scope under another name: AKS grants
		// its own identities as it makes a cluster, so in the first real
		// restore of one the snapshot's grant was refused as already there.
		// The access is what the snapshot holds; only the name differs.
		// The code says only that principal, role and scope match; a
		// condition or description may not (review of #73), so the grant
		// there is read and compared before it counts.
		if strings.EqualFold(rid.Type, "Microsoft.Authorization/roleAssignments") && strings.Contains(err.Error(), "RoleAssignmentExists") {
			name := existingAssignment(err.Error())
			if name == "" {
				return false, err.Error()
			}
			other := id[:strings.LastIndex(id, "/")+1] + name
			got, gerr := api.Get(ctx, other, ver)
			if gerr != nil {
				return false, "Azure says the same grant is there as " + name + ", and it cannot be read: " + gerr.Error()
			}
			if differ := grantDiffers(desired, got); len(differ) > 0 {
				return false, "Azure has the same principal, role and scope as " + name + ", with another " + strings.Join(differ, ", ") + "; not changed. Delete that one and run the restore again, or leave this one out"
			}
			return true, "already granted as " + name + " (Azure made it, or someone did); a diff shows this name missing and that one extra"
		}
		// A backup vault not AlwaysON was accepted and then failed in the
		// first real restore of one (BMSUserErrorSoftDeleteStateNotSetToAlwaysON,
		// found only in the activity log; the operation's status answered not
		// found), at 2026-11-01 and 2026-07-01; 2025-02-01 refused the newer
		// body itself. Microsoft does not document the rule, so the vault is
		// sent as captured, and a refusal says what that subscription asked.
		if changed == nil && strings.EqualFold(rid.Type, vaultType) {
			if not := softDeleteNotAlwaysOn(desired); not != "" {
				return false, err.Error() + "; a subscription has refused a new backup vault without soft delete and enhanced security AlwaysON (this one has " + not + "), and its activity log says so (BMSUserErrorSoftDeleteStateNotSetToAlwaysON). AlwaysON cannot be turned off again. To restore it so, give properties.securitySettings.softDeleteSettings.softDeleteState and .enhancedSecurityState as AlwaysON with --values"
			}
		}
		return false, err.Error()
	}
	out.markCreated(strings.ToLower(o.Key()))
	detail := "created " + id
	if changed != nil {
		detail = "updated " + id + " (" + strings.Join(changed, ", ") + ")"
	}
	if len(unsupplied) > 0 {
		detail += "; secret, not supplied: " + strings.Join(unsupplied, ", ")
	}
	return true, detail
}

const roleDefinitionType = "Microsoft.Authorization/roleDefinitions"

// valuesRef is an object's key in --values: Kind/resourceGroup/name, or
// Kind/name for a resource group.
func valuesRef(o snapshot.Object, rid ResourceID) string {
	if strings.EqualFold(o.Kind(), groupType) {
		return o.Kind() + "/" + o.Name()
	}
	return o.Kind() + "/" + rid.ResourceGroup + "/" + o.Name()
}

const vaultType = "Microsoft.RecoveryServices/vaults"

// softDeleteNotAlwaysOn names a vault's soft-delete settings that are not
// AlwaysON, as "softDeleteState Enabled"; "" when both are.
func softDeleteNotAlwaysOn(spec map[string]any) string {
	sd, _ := lookup(spec, strings.Split("properties.securitySettings.softDeleteSettings", "."))
	m, _ := sd.(map[string]any)
	var not []string
	for _, k := range []string{"softDeleteState", "enhancedSecurityState"} {
		if v, _ := m[k].(string); !strings.EqualFold(v, "AlwaysON") {
			if v == "" {
				v = "unset"
			}
			not = append(not, k+" "+v)
		}
	}
	return strings.Join(not, ", ")
}

// existingRE is the name Azure gives in its refusal of a grant already there.
var existingRE = regexp.MustCompile(`(?i)ID of the existing role assignment is ([0-9a-f-]{32,36})`)

// existingAssignment names the grant Azure says is already there, from its
// refusal, as a GUID with its dashes (Azure gives it without); "" when it does
// not say.
func existingAssignment(msg string) string {
	m := existingRE.FindStringSubmatch(msg)
	if m == nil {
		return ""
	}
	h := strings.ReplaceAll(strings.ToLower(m[1]), "-", "")
	if len(h) != 32 {
		return ""
	}
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// grantFields are what two grants of one principal, role and scope can still
// differ in.
var grantFields = []string{"condition", "conditionVersion", "description", "delegatedManagedIdentityResourceId"}

// grantDiffers names the grantFields in which want and got differ.
func grantDiffers(want, got map[string]any) []string {
	w, _ := want["properties"].(map[string]any)
	g, _ := got["properties"].(map[string]any)
	var out []string
	for _, k := range grantFields {
		a, b := w[k], g[k]
		if a == "" {
			a = nil
		}
		if b == "" {
			b = nil
		}
		// A condition's values can be case-sensitive (re-review of #73);
		// the rest are IDs and versions, which are not.
		same := strings.EqualFold(fmt.Sprint(a), fmt.Sprint(b))
		if k == "condition" {
			same = fmt.Sprint(a) == fmt.Sprint(b)
		}
		if !same {
			out = append(out, k)
		}
	}
	return out
}

// sharedRole says a role found here can also be assigned outside this
// subscription, so the source's own scope in the snapshot is not a difference:
// its scopes are taken as they are, and nothing below can narrow them. After a
// refusal, adding this subscription to the role is how a restore goes on. Any
// scope outside it counts, a management group's or "/" as much as another
// subscription's: a PUT from the snapshot would take the role from all of them.
func sharedRole(spec, got map[string]any) bool {
	had, _ := got["properties"].(map[string]any)
	scopes, _ := had["assignableScopes"].([]any)
	here := strings.ToLower("/subscriptions/" + tokSub)
	shared := false
	for _, x := range scopes {
		s, _ := x.(string)
		s = strings.ToLower(s)
		shared = shared || (s != here && !strings.HasPrefix(s, here+"/"))
	}
	want, _ := spec["properties"].(map[string]any)
	if !shared || want == nil {
		return false
	}
	want["assignableScopes"] = scopes
	return true
}

// keepAttached takes a subnet's route table as it is where the snapshot has none:
// a kubenet cluster attaches one it made, capture leaves it out, and a re-run read
// the network as differing, and with --update sent it without its routes. Only a
// table in a group the snapshot does not hold, as a node group is: one in a group
// it does hold was attached by someone, and is a difference like any other.
func keepAttached(spec, got map[string]any, byKey map[string]snapshot.Object) {
	had, _ := got["properties"].(map[string]any)
	wants, _ := spec["properties"].(map[string]any)
	hads, _ := had["subnets"].([]any)
	subnets, _ := wants["subnets"].([]any)
	for _, w := range subnets {
		wm, _ := w.(map[string]any)
		wp, _ := wm["properties"].(map[string]any)
		if wp == nil || wp["routeTable"] != nil {
			continue
		}
		for _, h := range hads {
			hm, _ := h.(map[string]any)
			hp, _ := hm["properties"].(map[string]any)
			table, _ := hp["routeTable"].(map[string]any)
			tableID, _ := table["id"].(string)
			rid, err := ParseID(tableID)
			if hm["name"] != wm["name"] || err != nil {
				continue
			}
			if _, held := byKey[strings.ToLower(keyOf(ResourceID{ResourceGroup: rid.ResourceGroup, Type: groupType, Name: rid.ResourceGroup}))]; !held {
				wp["routeTable"] = table
			}
		}
	}
}

// usesManagedIdentity says a service principal's secret has nothing to hold: a
// cluster with a managed identity has "msi" for a client ID. Counted as missing,
// it refused --update on every such cluster and reported each one as restored
// without its secret.
func usesManagedIdentity(spec map[string]any, secretPath string) bool {
	if !strings.HasSuffix(secretPath, "servicePrincipalProfile.secret") {
		return false
	}
	v, ok := lookup(spec, strings.Split(strings.TrimSuffix(secretPath, "secret")+"clientId", "."))
	s, _ := v.(string)
	return ok && strings.EqualFold(s, "msi")
}

// unfinished returns a resource's provisioning state when it is not a working
// resource, or "" when it is, or the type has no such state. Only states known
// to mean that count: a type with its own word for finished must not be called
// failed.
func unfinished(body map[string]any) string {
	props, _ := body["properties"].(map[string]any)
	state, _ := props["provisioningState"].(string)
	if provisioningFailed(state) || provisioningRunning(state) {
		return state
	}
	return ""
}

func unfinishedAdvice(state string) string {
	if provisioningFailed(state) {
		return "delete it or repair it, then run the restore again"
	}
	return "run the restore again when it has finished"
}

func provisioningFailed(state string) bool {
	s := strings.ToLower(state)
	return strings.HasSuffix(s, "failed") || s == "canceled" || s == "cancelled" || s == "error"
}

// provisioningRunning goes by the word's form, since types have their own
// (Migrating, Scaling). Running says finished. Pending is left out too: a Container
// Apps certificate answers it for as long as its domain goes unvalidated, which
// would hold a restore for the two hours of putTimeout.
func provisioningRunning(state string) bool {
	s := strings.ToLower(state)
	switch s {
	case "running", "pending":
		return false
	case "accepted", "inprogress":
		return true
	}
	return strings.HasSuffix(s, "ing")
}

// NotSent begins the detail of an object a restore does not send because
// Azure makes it.
const NotSent = "not sent: "

// Pending says a result was not sent and its settings wait for Azure to make
// it, so the restore has not kept them yet.
func Pending(detail string) bool { return strings.HasPrefix(detail, NotSent+DiagnosticsTableLater) }

// DiagnosticsTableLater is why a workspace's AzureDiagnostics table is not
// sent, and what keeps its retention.
const DiagnosticsTableLater = "Azure makes AzureDiagnostics when a diagnostic setting first sends to the workspace, and refuses to before; its retention, plan and custom columns are not kept until then: once data has arrived, run the restore again with --update"

// DiagnosticsTableFlagless follows DiagnosticsTableLater for a snapshot that
// cannot tell a retention set by a person from the workspace's default, and is
// read as set: an older one waited on every run, with nothing to say why.
const DiagnosticsTableFlagless = "; this snapshot predates TruthForm keeping whether its retention is the workspace's default, so it is taken as set: capture the source again with this version, and if nothing was set on it, it no longer waits"

// DiagnosticsTableDefault is why one holding only the workspace's defaults is
// not sent: the table Azure makes has them too, so there is nothing to wait
// for. It may never come: no diagnostic setting may send it data.
const DiagnosticsTableDefault = "Azure makes AzureDiagnostics when a diagnostic setting first sends to the workspace, and refuses to before; it has only the workspace's default retention and plan, which the table Azure makes has too, so nothing waits for it"

// KeptOnceAzureMakesIt lists what s holds that a restore cannot make, by
// whether a person set something on it: a workspace's AzureDiagnostics table.
// The first are kept only once Azure has made it; the second hold the
// workspace's defaults, which the table Azure makes has too.
func KeptOnceAzureMakesIt(s snapshot.Snapshot) (set, defaults []string) {
	for _, o := range s.Objects {
		if !isDiagnosticsTable(o.Kind(), o.Name()) {
			continue
		}
		k := o.Kind() + " " + o.Namespace() + "/" + o.Name()
		if spec, _ := o.Body["spec"].(map[string]any); diagnosticsTableSet(spec) {
			if diagnosticsTableFlagless(spec) {
				k += " (this snapshot predates TruthForm keeping whether its retention is the workspace's default, so it is taken as set: capture the source again with this version, and if nothing was set on it, it no longer waits)"
			}
			set = append(set, k)
		} else {
			defaults = append(defaults, k)
		}
	}
	sort.Strings(set)
	sort.Strings(defaults)
	return set, defaults
}

// madeWithParent is madeWith for a snapshot object, with its parent from the
// snapshot as values sets it: a registry given another region is judged there.
func madeWithParent(o snapshot.Object, byKey map[string]snapshot.Object, values map[string]map[string]any) string {
	kind, name := o.Kind(), o.Name()
	i, j := strings.LastIndex(kind, "/"), strings.LastIndex(name, "/")
	if strings.Count(kind, "/") < 2 || j < 0 {
		return ""
	}
	parent := byKey[strings.ToLower(APIVersion+"|"+kind[:i]+"|"+o.Namespace()+"|"+name[:j])]
	ps, _ := parent.Body["spec"].(map[string]any)
	spec, _ := o.Body["spec"].(map[string]any)
	if v := values[leaveOutKey(parent)]; v != nil && parent.Body != nil {
		ps = deepCopy(ps)
		merge(ps, deepCopy(v))
	}
	if v := values[leaveOutKey(o)]; v != nil {
		spec = deepCopy(spec)
		merge(spec, deepCopy(v))
	}
	item := map[string]any{"type": kind, "name": name, "location": spec["location"]}
	return madeWith(ps, item)
}

// AsCapturedNow is s as this version captures: what Azure makes itself is
// left out, and what it sets is taken out of each spec. A diff compares a
// target, captured now, with a snapshot that may be older; without it a
// snapshot from before a fix differed from every target on what the fix took
// out.
func AsCapturedNow(s snapshot.Snapshot) snapshot.Snapshot {
	byKey := map[string]snapshot.Object{}
	for _, o := range s.Objects {
		byKey[strings.ToLower(o.Key())] = o
	}
	out := s
	out.Objects = nil
	for _, o := range s.Objects {
		if madeWithParent(o, byKey, nil) != "" {
			continue
		}
		if spec, ok := o.Body["spec"].(map[string]any); ok {
			body := deepCopy(o.Body)
			spec = body["spec"].(map[string]any)
			asCapturedNow(o.Kind(), o.Name(), spec)
			o = snapshot.Object{Body: body}
		}
		out.Objects = append(out.Objects, o)
	}
	return out
}

// parentCreated says whether this run created the object's parent, or
// grandparent: blobServices/default was made by its account, and its containers
// by no one, but a parent treated this way counts for its own children.
func parentCreated(o snapshot.Object, out *outcomes) bool {
	if rid, err := ParseID(fmt.Sprint(annotation(o, annID))); err == nil && rid.Extension() {
		return false
	}
	kind, name := o.Kind(), o.Name()
	for strings.Count(kind, "/") > 1 && strings.Contains(name, "/") {
		kind, name = kind[:strings.LastIndex(kind, "/")], name[:strings.LastIndex(name, "/")]
		if out.wasCreated(strings.ToLower(APIVersion + "|" + kind + "|" + o.Namespace() + "|" + name)) {
			return true
		}
	}
	return false
}

func annotation(o snapshot.Object, name string) any {
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	return ann[name]
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
	// A reference to a child (a subnet) also needs the child's parent, which
	// is where a subnet is held: nothing in the snapshot is the subnet itself.
	addWithParents := func(rid ResourceID) {
		add(rid)
		for strings.Count(rid.Type, "/") > 1 && strings.Contains(rid.Name, "/") {
			rid.Type = rid.Type[:strings.LastIndex(rid.Type, "/")]
			rid.Name = rid.Name[:strings.LastIndex(rid.Name, "/")]
			add(rid)
		}
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
						addWithParents(sc)
					}
				}
			}
		}
		if after, _ := ann[annAfter].(string); after != "" {
			if rid, err := ParseID(after); err == nil {
				add(rid)
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
			addWithParents(rid)
		}
	}
	return out
}

// namedGroups are the resource groups o names an ID in, lower case.
func namedGroups(o snapshot.Object) []string {
	var out []string
	for _, m := range idRE.FindAllString(canon(o.Body["spec"]), -1) {
		if rid, err := ParseID(trimToResource(m)); err == nil && rid.ResourceGroup != "" {
			out = append(out, strings.ToLower(rid.ResourceGroup))
		}
	}
	return out
}

// Case-insensitive: Azure spells .../resourcegroups/... in some services' IDs (a
// key vault's), and a reference missed here has nothing waiting for it.
var idRE = regexp.MustCompile(`(?i)/subscriptions/\{\{truthform\|subscription\}\}/resourceGroups/[^/"]+(/providers/[^/"]+(/[^/"]+/[^/"]+)+)?`)

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

const federatedCredentialType = "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials"

// grantsToIdentitiesOf lists the role assignments, by key, for the identities a
// cluster's spec names. One that needs the cluster itself (granted on it, or in
// the group it creates) cannot come first, and is left to follow it.
func grantsToIdentitiesOf(cluster, spec string, by map[string]snapshot.Object) []string {
	var out []string
	for k, o := range by {
		if !strings.EqualFold(o.Kind(), "Microsoft.Authorization/roleAssignments") || slices.Contains(deps(o), cluster) {
			continue
		}
		props, _ := o.Body["spec"].(map[string]any)["properties"].(map[string]any)
		principal, _ := props["principalId"].(string)
		m := refRE.FindStringSubmatch(principal)
		if m == nil || !strings.EqualFold(m[1], "Microsoft.ManagedIdentity/userAssignedIdentities") {
			continue
		}
		identity, ok := by[strings.ToLower(APIVersion+"|"+m[1]+"|"+m[2]+"|"+m[3])]
		if !ok {
			continue
		}
		if id, _ := annotation(identity, annID).(string); id != "" && strings.Contains(spec, strings.ToLower(id)) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// restoreOrder sorts objects so each comes after what it depends on that is
// in the snapshot; what is not in the snapshot must already exist.
func restoreOrder(objs []snapshot.Object) (order, cyclic []snapshot.Object) {
	order, cyclic, _ = restoreGraph(objs)
	return order, cyclic
}

// restoreGraph orders objects so each comes after what it depends on, and
// gives each one's dependencies as indices into that order, for running
// independent PUTs at once.
func restoreGraph(objs []snapshot.Object) (order, cyclic []snapshot.Object, depIdx [][]int) {
	by := map[string]snapshot.Object{}
	ids := map[string]string{} // lower(tokenized ID) -> key
	for _, o := range objs {
		k := strings.ToLower(o.Key())
		by[k] = o
		if ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any); ann != nil {
			if id, _ := ann[annID].(string); id != "" {
				ids[strings.ToLower(id)] = k
			}
		}
	}
	keys := sortedKeys(by)
	extra := map[string][]string{}
	nodeGroups := map[string]string{} // lower(node resource group) -> its cluster's key
	for _, k := range keys {
		if strings.EqualFold(by[k].Kind(), managedClusterType) {
			props, _ := by[k].Body["spec"].(map[string]any)["properties"].(map[string]any)
			if g, _ := props["nodeResourceGroup"].(string); g != "" {
				nodeGroups[strings.ToLower(g)] = k
			}
		}
	}
	for _, k := range keys {
		spec := strings.ToLower(canon(by[k].Body["spec"]))
		for id, other := range ids {
			// Any object whose own ID the spec names comes first: idRE
			// sees only IDs under resource groups, so a subscription-level
			// role assignment came before the custom role it uses
			// (review, 2026-10-22).
			if other != k && strings.Contains(spec, id+`"`) {
				extra[k] = append(extra[k], other)
			}
		}
		// An AKS cluster with its own identity needs what that identity was
		// granted before it starts: with a custom private DNS zone, Azure
		// refuses the create without it. Nothing in the cluster names the grant.
		if strings.EqualFold(by[k].Kind(), managedClusterType) {
			extra[k] = append(extra[k], grantsToIdentitiesOf(k, spec, by)...)
		}
		// A lock goes last: a ReadOnly lock refuses every later PUT in its
		// scope (ScopeLocked), and locks sort ahead of most types.
		if strings.EqualFold(by[k].Kind(), "Microsoft.Authorization/locks") {
			for _, other := range keys {
				if !strings.EqualFold(by[other].Kind(), "Microsoft.Authorization/locks") {
					extra[k] = append(extra[k], other)
				}
			}
		}
	}
	// What names something in a cluster's node resource group waits for the
	// cluster, which makes that group and what is in it. Capture skips the
	// group and what AKS made there (its network), so nothing in the
	// snapshot stood between them: in the first real restore of a cluster, a
	// peering to its network and a DNS link to it were sent while the cluster
	// was being made, and refused. Only by what an object names, not where it
	// is: what sits in the node group (the kubelet identity, captured with
	// --capture-managed) and the cluster, which names it, each waited for the
	// other (re-review of #73). Not what the cluster already waits for: a grant
	// to its identity scoped at its node group made a cycle (third review of
	// #73). On the cluster, which names its own node group, this is a wait on
	// itself, which the order below ignores.
	for _, k := range keys {
		for _, g := range namedGroups(by[k]) {
			if c, ok := nodeGroups[g]; ok && !slices.Contains(extra[c], k) {
				extra[k] = append(extra[k], c)
			}
		}
	}
	// An identity takes one write to its federated credentials at a time, and
	// refuses others with a 409, so they go one after another.
	var previous, previousParent string
	for _, k := range keys {
		if !strings.EqualFold(by[k].Kind(), federatedCredentialType) {
			continue
		}
		parent := by[k].Namespace() + "/" + by[k].Name()[:strings.LastIndex(by[k].Name(), "/")+1]
		if strings.EqualFold(parent, previousParent) {
			extra[k] = append(extra[k], previous)
		}
		previous, previousParent = k, parent
	}
	done := map[string]bool{}
	for progress := true; progress; {
		progress = false
		for _, k := range keys {
			if done[k] {
				continue
			}
			ready := true
			for _, d := range append(deps(by[k]), extra[k]...) {
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
	at := map[string]int{}
	for i, o := range order {
		at[strings.ToLower(o.Key())] = i
	}
	depIdx = make([][]int, len(order))
	for i, o := range order {
		k := strings.ToLower(o.Key())
		for _, d := range append(deps(o), extra[k]...) {
			if j, ok := at[d]; ok && j != i {
				depIdx[i] = append(depIdx[i], j)
			}
		}
	}
	return order, cyclic, depIdx
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
	opt := a.Options
	opt.Types = a.Policy.Types
	return restoreWith(ctx, a.API, a.Registry, s, opt, workers(a.Policy.Parallel))
}

// workers is --parallel for a restore: it was taken by capture only, so
// "--parallel 1" still ran eight PUTs at once (review of #19).
func workers(n int) int {
	if n <= 0 {
		return 8
	}
	return n
}
