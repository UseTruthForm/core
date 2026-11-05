package azarm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// The first restore of a real estate into another subscription: Azure refused
// a registry's replication in the registry's own region
// (HomeReplicationCannotBeOperated). Azure makes it with the registry. It is
// not captured, a snapshot from before is not sent it, and a diff of a target
// that has it only implicitly does not call it missing.
func TestWhatAzureMakesWithItsParentIsNotCapturedOrSent(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	registry := put(t, src, "rg", "Microsoft.ContainerRegistry/registries", "reg1", map[string]any{"location": "eastus", "sku": map[string]any{"name": "Premium"}})
	replication := "Microsoft.ContainerRegistry/registries/replications"
	// ARM spells the home region one way on the registry and another here.
	src.SeedAzure(registry+"/replications/eastus", stable(reg, replication), map[string]any{"location": "East US", "properties": map[string]any{}})
	put(t, src, "rg", replication, "reg1/westus", map[string]any{"location": "westus", "properties": map[string]any{}})

	snap := capture(t, src, reg)
	names := map[string]bool{}
	for _, o := range snap.Objects {
		names[o.Name()] = true
	}
	for name, want := range map[string]bool{"reg1/eastus": false, "reg1/westus": true} {
		if names[name] != want {
			t.Errorf("captured %s: %v, want %v", name, names[name], want)
		}
	}
	skipped := map[string]string{}
	for _, s := range snap.Skips {
		skipped[s.Name] = s.Reason
	}
	if !strings.Contains(skipped["reg1/eastus"], "registry's own region") {
		t.Errorf("skips do not say why: %v", skipped)
	}

	// A snapshot from before holds it, as the real one did.
	old := snap
	old.Objects = append([]snapshot.Object(nil), snap.Objects...)
	var moved snapshot.Object
	for _, o := range snap.Objects {
		if o.Name() == "reg1/westus" {
			b := deepCopy(o.Body)
			b["metadata"].(map[string]any)["name"] = "reg1/eastus"
			b["spec"].(map[string]any)["location"] = "eastus"
			moved = snapshot.Object{Body: b}
			old.Objects = append(old.Objects, moved)
		}
	}
	dst.PutError = func(id string, body map[string]any) error {
		if strings.HasSuffix(strings.ToLower(id), "/replications/eastus") {
			return errors.New("HomeReplicationCannotBeOperated")
		}
		return nil
	}
	rs := Restore(ctx, dst, reg, old, RestoreOptions{})
	allApplied(t, rs)
	if r := resultFor(t, rs, "reg1/eastus"); !strings.HasPrefix(r.Detail, NotSent) || Pending(r.Detail) {
		t.Errorf("reg1/eastus: %s", r.Detail)
	}
	if ch := snapshot.Compare(AsCapturedNow(old), capture(t, dst, reg)); len(ch) != 0 {
		t.Errorf("a diff of the target calls what Azure makes missing: %v", ch)
	}
	// A registry --values moves elsewhere has its home there: the old home's
	// replication is one to make, and is sent.
	byKey := map[string]snapshot.Object{}
	for _, o := range old.Objects {
		byKey[strings.ToLower(o.Key())] = o
	}
	vals := map[string]map[string]any{"Microsoft.ContainerRegistry/registries/rg/reg1": {"location": "westus"}}
	if why := madeWithParent(moved, byKey, vals); why != "" {
		t.Errorf("judged against the snapshot's region, not the one given: %s", why)
	}
}

// A workspace's AzureDiagnostics table is made by Azure when a diagnostic
// setting first sends to it, and a real restore was refused it ("cannot create
// or migrate AzureDiagnostics table"). Skipped, its retention was lost with no
// word (review of #72: 90/730 in the source, 30/30 in the target, a clean
// diff). It is captured with what a person sets, not sent while missing, said
// as not finished, and set once Azure has made it. One holding only the
// workspace's defaults does not keep a restore unfinished (re-review of #72:
// every run exited 3), and a retention inherited from the workspace is not
// sent, so an update does not pin it.
func TestAzureDiagnosticsKeepsItsRetentionOnceAzureMakesIt(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	table := tablesType
	defaults := func(plan string) map[string]any {
		return map[string]any{"retentionInDays": 30, "retentionInDaysAsDefault": true, "totalRetentionInDays": 30, "totalRetentionInDaysAsDefault": true, "plan": plan}
	}
	seed := func(ws string, props map[string]any, schema map[string]any) {
		w := put(t, src, "rg", "Microsoft.OperationalInsights/workspaces", ws, map[string]any{"location": "eastus"})
		if schema == nil {
			schema = map[string]any{"name": "AzureDiagnostics"}
		}
		schema["standardColumns"] = []any{map[string]any{"name": "Category", "type": "string"}}
		props["schema"] = schema
		src.SeedAzure(w+"/tables/AzureDiagnostics", stable(reg, table), map[string]any{"properties": props})
	}
	col := func(names ...string) []any {
		var out []any
		for _, n := range names {
			out = append(out, map[string]any{"name": n, "type": "string"})
		}
		return out
	}
	// Analytics retention inherited, total retention set, and a custom column.
	seed("law", map[string]any{"retentionInDays": 30, "retentionInDaysAsDefault": true, "totalRetentionInDays": 730, "totalRetentionInDaysAsDefault": false, "plan": "Analytics"},
		map[string]any{"name": "AzureDiagnostics", "columns": col("Note_CF")})
	// Only the workspace's defaults, the plan however it is spelled.
	seed("plain", defaults("Analytics"), nil)
	seed("lower", defaults("analytics"), nil)
	// Set in one way each: an analytics retention, a plan, a custom column
	// spelled in lower case, with no schema name and beside a column that is
	// not a custom one.
	seed("kept", map[string]any{"retentionInDays": 90, "retentionInDaysAsDefault": false, "totalRetentionInDays": 90, "totalRetentionInDaysAsDefault": true, "plan": "Analytics"}, nil)
	seed("basic", defaults("Basic"), nil)
	seed("noted", defaults("Analytics"), map[string]any{"columns": col("why_cf", "Legacy")})

	snap := capture(t, src, reg)
	specs := map[string]string{}
	for _, o := range snap.Objects {
		specs[o.Name()] = canon(o.Body["spec"])
	}
	got := specs["law/AzureDiagnostics"]
	for _, want := range []string{`"totalRetentionInDays":730`, `"retentionInDaysAsDefault":true`, `"totalRetentionInDaysAsDefault":false`, "Note_CF"} {
		if !strings.Contains(got, want) {
			t.Errorf("captured table lacks %s: %s", want, got)
		}
	}
	if strings.Contains(got, "standardColumns") || strings.Contains(got, `"Category"`) {
		t.Errorf("Azure's own columns captured: %s", got)
	}
	if n := specs["noted/AzureDiagnostics"]; !strings.Contains(n, "why_cf") || strings.Contains(n, "Legacy") || strings.Contains(n, `"name":null`) {
		t.Errorf("a custom column is kept, and only that: %s", n)
	}
	set, plain := KeptOnceAzureMakesIt(snap)
	want := []string{}
	for _, ws := range []string{"basic", "kept", "law", "noted"} {
		want = append(want, tablesType+" rg/"+ws+"/AzureDiagnostics")
	}
	if strings.Join(set, ",") != strings.Join(want, ",") || strings.Join(plain, ",") != tablesType+" rg/lower/AzureDiagnostics,"+tablesType+" rg/plain/AzureDiagnostics" {
		t.Errorf("listed to check: %v, with defaults only: %v", set, plain)
	}

	// PUTs run several at a time.
	var mu sync.Mutex
	sent := map[string]map[string]any{}
	dst.PutError = func(id string, body map[string]any) error {
		if strings.HasSuffix(id, "/tables/AzureDiagnostics") {
			if dst.Stored(id) == nil {
				return errors.New("InvalidParameter: cannot create or migrate AzureDiagnostics table")
			}
			mu.Lock()
			sent[strings.Split(id, "/")[8]] = deepCopy(body)
			mu.Unlock()
		}
		return nil
	}
	rs := Restore(ctx, dst, reg, snap, RestoreOptions{})
	allApplied(t, rs)
	for _, ws := range []string{"law", "kept", "basic", "noted"} {
		if r := resultFor(t, rs, ws+"/AzureDiagnostics"); !Pending(r.Detail) || strings.Contains(r.Detail, "predates") {
			t.Errorf("%s: a missing table with something set: %s", ws, r.Detail)
		}
	}
	for _, ws := range []string{"plain", "lower"} {
		if r := resultFor(t, rs, ws+"/AzureDiagnostics"); !strings.HasPrefix(r.Detail, NotSent) || Pending(r.Detail) {
			t.Errorf("%s: a missing table with only defaults: %s", ws, r.Detail)
		}
	}

	// Azure makes them, with the workspace's defaults: the diff says law's differs.
	for _, ws := range []string{"law", "kept", "noted"} {
		dst.SeedAzure(id(dstSub, "rg", "Microsoft.OperationalInsights/workspaces", ws)+"/tables/AzureDiagnostics", stable(reg, table), map[string]any{"properties": map[string]any{
			"retentionInDays": 30, "retentionInDaysAsDefault": true, "totalRetentionInDays": 30, "totalRetentionInDaysAsDefault": true, "plan": "Analytics",
			"schema": map[string]any{"name": "AzureDiagnostics", "standardColumns": []any{map[string]any{"name": "Other", "type": "string"}}}}})
	}
	var ch []snapshot.Change
	for _, c := range snapshot.Compare(AsCapturedNow(snap), capture(t, dst, reg)) {
		if strings.Contains(c.Key, "law/AzureDiagnostics") {
			ch = append(ch, c)
		}
	}
	if len(ch) != 1 || !strings.Contains(strings.Join(ch[0].Fields, ","), "totalRetentionInDays") {
		t.Errorf("a diff of the made table: %v", ch)
	}
	// Run again with --update, as the restore said: what was set is sent, and
	// what the workspace gives is left to it, not pinned.
	rs = Restore(ctx, dst, reg, snap, RestoreOptions{Update: true})
	if r := resultFor(t, rs, "law/AzureDiagnostics"); !r.OK || Pending(r.Detail) {
		t.Errorf("an update of the made table: %s", r.Detail)
	}
	props := func(ws string) map[string]any { p, _ := sent[ws]["properties"].(map[string]any); return p }
	if p := props("law"); p["totalRetentionInDays"] == nil || p["retentionInDays"] != nil || p["retentionInDaysAsDefault"] != nil || !strings.Contains(canon(p), "Note_CF") {
		t.Errorf("law's update sent: %s", canon(sent["law"]))
	}
	if p := props("kept"); p["retentionInDays"] == nil || p["totalRetentionInDays"] != nil || p["totalRetentionInDaysAsDefault"] != nil {
		t.Errorf("kept's update sent: %s", canon(sent["kept"]))
	}
	if n := canon(sent["noted"]); !strings.Contains(n, "why_cf") || strings.Contains(n, "null") {
		t.Errorf("noted's update sent: %s", n)
	}
}

// Review of #72: a snapshot from before the *AsDefault flags cannot tell a
// retention set from the workspace's default, and is read as set; it waited on
// every run with nothing to say why. It says so, and how to clear it.
func TestAnOlderDiagnosticsTableSaysWhyItWaits(t *testing.T) {
	reg, _, dst := worlds(t)
	sub := "/subscriptions/" + tokSub + "/resourceGroups/rg"
	group := obj(groupType, "", "rg", sub, map[string]any{"location": "eastus"})
	ws := obj("Microsoft.OperationalInsights/workspaces", "rg", "law", sub+"/providers/Microsoft.OperationalInsights/workspaces/law", map[string]any{"location": "eastus"})
	tbl := obj(tablesType, "rg", "law/AzureDiagnostics", sub+"/providers/Microsoft.OperationalInsights/workspaces/law/tables/AzureDiagnostics", map[string]any{
		"properties": map[string]any{"retentionInDays": 30, "totalRetentionInDays": 30, "plan": "Analytics"}})
	for _, o := range []snapshot.Object{group, ws, tbl} {
		o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annAPIVersion] = stable(reg, o.Kind())
	}
	old := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{group, ws, tbl}}
	r := resultFor(t, Restore(context.Background(), dst, reg, old, RestoreOptions{}), "law/AzureDiagnostics")
	if !Pending(r.Detail) || !strings.Contains(r.Detail, "predates") || !strings.Contains(r.Detail, "capture the source again with this version") {
		t.Errorf("an older table: %s", r.Detail)
	}
	if set, _ := KeptOnceAzureMakesIt(old); len(set) != 1 || !strings.Contains(set[0], "predates") || !strings.Contains(set[0], "capture the source again") {
		t.Errorf("listed to check: %v", set)
	}
}

// Re-review of #72: the strip of what Azure sets walked the whole spec, tags
// too, and a cluster's tag "nodeImageVersion: pinned-by-me" was gone from the
// capture, the PUT and the diff. A tag named after each is kept, on a cluster,
// its pool, and a pool read on its own.
func TestATagNamedForWhatAzureSetsIsKept(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	tags := map[string]any{}
	for _, names := range setByAzure {
		for k := range names {
			tags[k] = "pinned-by-me"
		}
	}
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	cluster := id(srcSub, "rg", managedClusterType, "aks")
	src.SeedAzure(cluster, stable(reg, managedClusterType), map[string]any{"location": "eastus", "tags": deepCopy(tags), "properties": map[string]any{
		"dnsPrefix": "aks", "agentPoolProfiles": []any{map[string]any{"name": "sys", "mode": "System", "count": 1, "vmSize": "Standard_D2s_v5",
			"nodeImageVersion": "AKSUbuntu-1", "tags": deepCopy(tags)}}}})
	snap := capture(t, src, reg)
	// The cluster's own tags and its pool's: each name twice.
	check := func(where, spec string, n int) {
		t.Helper()
		for k := range tags {
			if got := strings.Count(spec, `"`+k+`":"pinned-by-me"`); got != n {
				t.Errorf("%s has the tag %s %d times, want %d: %s", where, k, got, n, spec)
			}
		}
	}
	var spec string
	for _, o := range snap.Objects {
		if o.Kind() == managedClusterType {
			spec = canon(o.Body["spec"])
		}
	}
	if strings.Contains(spec, "AKSUbuntu-1") {
		t.Errorf("what Azure sets is captured: %s", spec)
	}
	check("the capture", spec, 2)
	check("an older snapshot made as captured now", canon(AsCapturedNow(snap).Objects), 2)
	allApplied(t, Restore(ctx, dst, reg, snap, RestoreOptions{}))
	check("the PUT", canon(dst.Stored(id(dstSub, "rg", managedClusterType, "aks"))), 2)
	if ch := snapshot.Compare(AsCapturedNow(snap), capture(t, dst, reg)); len(ch) != 0 {
		t.Errorf("a diff: %v", ch)
	}
	pool := obj(managedClusterType+"/agentPools", "rg", "aks/extra", "/subscriptions/"+tokSub+"/resourceGroups/rg/providers/"+managedClusterType+"/aks/agentPools/extra",
		map[string]any{"properties": map[string]any{"nodeImageVersion": "AKSUbuntu-1", "tags": deepCopy(tags)}})
	got := canon(AsCapturedNow(snapshot.Snapshot{Objects: []snapshot.Object{pool}}).Objects)
	if strings.Contains(got, "AKSUbuntu-1") {
		t.Errorf("a pool's node image is kept: %s", got)
	}
	check("a pool on its own", got, 1)
}

// What setByAzure takes from a capture with its definition, setByAzurePaths
// takes from an older snapshot without one: each name has its path.
func TestSetByAzureHasItsPaths(t *testing.T) {
	for typ, names := range setByAzure {
		for k := range names {
			found := false
			for _, p := range setByAzurePaths[typ] {
				found = found || strings.HasSuffix(p, "."+k)
			}
			if !found {
				t.Errorf("%s: %s has no path in setByAzurePaths", typ, k)
			}
		}
	}
}

// Review of #72: AsCapturedNow left out what capture takes by type. An older
// snapshot's data collection endpoint immutableId, TDE scanState and DNS zone
// group etags still differed, and were sent.
func TestAnOlderSnapshotIsComparedAndSentAsCapturedNow(t *testing.T) {
	reg, _, dst := worlds(t)
	ctx := context.Background()
	sub := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/"
	group := obj(groupType, "", "rg", "/subscriptions/"+tokSub+"/resourceGroups/rg", map[string]any{"location": "eastus"})
	dce := obj("Microsoft.Insights/dataCollectionEndpoints", "rg", "dce", sub+"Microsoft.Insights/dataCollectionEndpoints/dce", map[string]any{
		"location": "eastus", "properties": map[string]any{"immutableId": "dce-old", "networkAcls": map[string]any{"publicNetworkAccess": "Enabled"}}})
	for _, o := range []snapshot.Object{group, dce} {
		o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annAPIVersion] = stable(reg, o.Kind())
	}
	tde := obj("Microsoft.Sql/servers/databases/transparentDataEncryption", "rg", "s/d/current", sub+"Microsoft.Sql/servers/s/databases/d/transparentDataEncryption/current", map[string]any{
		"properties": map[string]any{"state": "Enabled", "scanState": "None"}})
	zg := obj("Microsoft.Network/privateEndpoints/privateDnsZoneGroups", "rg", "pe/default", sub+"Microsoft.Network/privateEndpoints/pe/privateDnsZoneGroups/default", map[string]any{
		"properties": map[string]any{"privateDnsZoneConfigs": []any{map[string]any{"name": "c", "etag": `W/"1"`, "properties": map[string]any{"privateDnsZoneId": "z"}}}}})
	old := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{group, dce, tde, zg}}
	now := canon(AsCapturedNow(old).Objects)
	for _, gone := range []string{"dce-old", "scanState", "etag"} {
		if strings.Contains(now, gone) {
			t.Errorf("%s is still in an older snapshot made as captured now: %s", gone, now)
		}
	}
	if !strings.Contains(now, "publicNetworkAccess") || !strings.Contains(now, `"state":"Enabled"`) || !strings.Contains(now, "privateDnsZoneId") {
		t.Errorf("settings went with them: %s", now)
	}
	// Not sent either: the restored endpoint's own comes from Azure.
	allApplied(t, Restore(ctx, dst, reg, snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{group, dce}}, RestoreOptions{}))
	if got := canon(dst.Stored(id(dstSub, "rg", "Microsoft.Insights/dataCollectionEndpoints", "dce"))); strings.Contains(got, "dce-old") {
		t.Errorf("an older snapshot's immutableId was sent: %s", got)
	}
}

// Azure turns on a cluster's extensionManager add-on when an extension is
// installed, and refuses it on create ("Changing property
// 'AddonProfiles.ExtensionManager' is not allowed"): a real restore could not
// make the cluster, nor the 22 objects that needed it. It is not captured, a
// snapshot from before does not send it, and a diff does not see it go.
func TestAzuresExtensionManagerIsNotSentOrCompared(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	cluster := id(srcSub, "rg", managedClusterType, "aks")
	addons := map[string]any{"extensionManager": map[string]any{"enabled": true}, "omsagent": map[string]any{"enabled": true}}
	src.SeedAzure(cluster, stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
		"dnsPrefix": "aks", "addonProfiles": addons,
		"agentPoolProfiles": []any{map[string]any{"name": "sys", "mode": "System", "count": 1, "vmSize": "Standard_D2s_v5"}}}})

	snap := capture(t, src, reg)
	spec := func(s snapshot.Snapshot) string {
		for _, o := range s.Objects {
			if o.Kind() == managedClusterType {
				return canon(o.Body["spec"])
			}
		}
		t.Fatal("no cluster")
		return ""
	}
	if got := spec(snap); strings.Contains(got, "extensionManager") || !strings.Contains(got, "omsagent") {
		t.Errorf("captured add-ons: %s", got)
	}

	// A snapshot from before holds it, as the real one did.
	old := snap
	old.Objects = nil
	for _, o := range snap.Objects {
		if o.Kind() == managedClusterType {
			o = snapshot.Object{Body: deepCopy(o.Body)}
			o.Body["spec"].(map[string]any)["properties"].(map[string]any)["addonProfiles"].(map[string]any)["extensionManager"] = map[string]any{"enabled": true}
		}
		old.Objects = append(old.Objects, o)
	}
	dst.PutError = func(id string, body map[string]any) error {
		if strings.Contains(canon(body), "extensionManager") {
			return errors.New("PropertyChangeNotAllowed: Changing property 'AddonProfiles.ExtensionManager' is not allowed")
		}
		return nil
	}
	allApplied(t, Restore(ctx, dst, reg, old, RestoreOptions{}))
	// Azure turns it on again on the restored cluster.
	i := id(dstSub, "rg", managedClusterType, "aks")
	b := dst.Stored(i)
	b["properties"].(map[string]any)["addonProfiles"].(map[string]any)["extensionManager"] = map[string]any{"enabled": true}
	dst.SeedAzure(i, stable(reg, managedClusterType), b)
	if ch := snapshot.Compare(AsCapturedNow(old), capture(t, dst, reg)); len(ch) != 0 {
		t.Errorf("a diff sees what Azure set: %v", ch)
	}
	if r := resultFor(t, Restore(ctx, dst, reg, old, RestoreOptions{}), "|aks"); r.Detail != "already present and identical" {
		t.Errorf("a resumed restore: %s", r.Detail)
	}
}

// AKS grants its own identities as it makes a cluster. In the first real
// restore of one, the snapshot's grant to the same identity, role and scope was
// refused as RoleAssignmentExists, under another name, and reported as not
// applied. The access is there: it counts as applied, and says under which
// name, once the grant there is read and matches in what the code does not
// promise (review of #73: a condition or description may differ).
func TestAGrantAzureAlreadyMadeIsApplied(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	props := func(f *Fake, desc string) map[string]any {
		return map[string]any{"properties": map[string]any{
			"principalId":      "22222222-2222-2222-2222-222222222222",
			"principalType":    "ServicePrincipal",
			"roleDefinitionId": "/subscriptions/" + f.sub + "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
			"description":      desc,
		}}
	}
	put(t, src, "rg", "Microsoft.Authorization/roleAssignments", "11111111-1111-1111-1111-111111111111", props(src, "pull"))
	snap := capture(t, src, reg)
	put(t, dst, "", groupType, "rg", map[string]any{"location": "eastus"})
	refuse := func(why string) {
		dst.PutError = func(id string, body map[string]any) error {
			if strings.Contains(id, "/roleAssignments/11111111") {
				return errors.New(why)
			}
			return nil
		}
	}
	exists := "RESPONSE 409: RoleAssignmentExists: The role assignment already exists. The ID of the existing role assignment is 3333444455554666877788889999aaaa."
	refuse("")
	put(t, dst, "rg", "Microsoft.Authorization/roleAssignments", "33334444-5555-4666-8777-88889999aaaa", props(dst, "pull"))
	refuse(exists)
	rs := Restore(ctx, dst, reg, snap, RestoreOptions{})
	allApplied(t, rs)
	if r := resultFor(t, rs, "roleAssignments|rg|1111"); !strings.Contains(r.Detail, "already granted as 33334444-5555-4666-8777-88889999aaaa") {
		t.Errorf("does not say it is already granted, and as what: %s", r.Detail)
	}
	// The same principal, role and scope, described otherwise: not the same.
	refuse("")
	put(t, dst, "rg", "Microsoft.Authorization/roleAssignments", "33334444-5555-4666-8777-88889999aaaa", props(dst, "something else"))
	refuse(exists)
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{}), "roleAssignments|rg|1111"); r.OK || !strings.Contains(r.Detail, "description") {
		t.Errorf("a grant that differs counted as applied: %v %s", r.OK, r.Detail)
	}
	// Any other refusal of a grant is still one.
	refuse("RESPONSE 403: AuthorizationFailed")
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{}), "roleAssignments|rg|1111"); r.OK {
		t.Errorf("another refusal of a grant counted as applied: %s", r.Detail)
	}
}

// A new backup vault without soft delete and enhanced security AlwaysON was
// accepted and then failed in the first real restore of one, and the restore
// said only "not found". Microsoft does not document the rule (review of #73),
// so it is sent as captured; a refusal says what to look for and how to give
// AlwaysON, and given it, the vault is sent so.
func TestABackupVaultSaysAzureWantsAlwaysOn(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, src, "rg", vaultType, "vlt", map[string]any{"location": "eastus", "sku": map[string]any{"name": "RS0", "tier": "Standard"},
		"properties": map[string]any{"securitySettings": map[string]any{"softDeleteSettings": map[string]any{"softDeleteState": "Enabled", "enhancedSecurityState": "Enabled", "softDeleteRetentionPeriodInDays": 14}}}})
	snap := capture(t, src, reg)
	// Azure that takes it: sent as captured.
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{}), "|vlt"); !r.OK {
		t.Fatalf("a vault Azure takes was not sent: %s", r.Detail)
	}
	_, _, dst = worlds(t)
	var sent string
	dst.PutError = func(id string, body map[string]any) error {
		if strings.HasSuffix(id, "/vaults/vlt") {
			sent = canon(body)
			if !strings.Contains(sent, `"softDeleteState":"AlwaysON"`) {
				return errors.New("RESPONSE 404: ResourceNotFound")
			}
		}
		return nil
	}
	r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{}), "|vlt")
	if r.OK || !strings.Contains(r.Detail, "ResourceNotFound") || !strings.Contains(r.Detail, "softDeleteState Enabled, enhancedSecurityState Enabled") || !strings.Contains(r.Detail, "BMSUserErrorSoftDeleteStateNotSetToAlwaysON") || !strings.Contains(r.Detail, "--values") {
		t.Errorf("a refused vault: %v %s", r.OK, r.Detail)
	}
	always := map[string]map[string]any{"Microsoft.RecoveryServices/vaults/rg/vlt": {"properties": map[string]any{"securitySettings": map[string]any{"softDeleteSettings": map[string]any{"softDeleteState": "AlwaysON", "enhancedSecurityState": "AlwaysON"}}}}}
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{Values: always}), "|vlt"); !r.OK || !strings.Contains(sent, `"enhancedSecurityState":"AlwaysON"`) {
		t.Errorf("given AlwaysON, the vault is not sent so: %s %s", r.Detail, sent)
	}
	// Another refusal of a vault that is AlwaysON says nothing of it.
	dst.PutError = func(id string, body map[string]any) error {
		if strings.HasSuffix(id, "/vaults/vlt") {
			return errors.New("RESPONSE 400: BadRequest")
		}
		return nil
	}
	_, _, fresh := worlds(t)
	fresh.PutError = dst.PutError
	if r := resultFor(t, Restore(ctx, fresh, reg, snap, RestoreOptions{Values: always}), "|vlt"); strings.Contains(r.Detail, "BMSUserError") {
		t.Errorf("an AlwaysON vault's refusal blames AlwaysON: %s", r.Detail)
	}
}

// AKS gives every cluster a windowsProfile, and refuses to make one without its
// admin password, though no pool runs Windows. In the first real restore of a
// cluster, Azure's answer was only "the value of parameter
// windowsProfile.adminPassword is invalid". The restore says what to give, and
// sends the cluster once it is given.
func TestAClusterSaysItNeedsItsWindowsPassword(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	src.SeedAzure(id(srcSub, "rg", managedClusterType, "aks"), stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
		"dnsPrefix": "aks", "windowsProfile": map[string]any{"adminUsername": "azureuser"},
		"agentPoolProfiles": []any{map[string]any{"name": "sys", "mode": "System", "count": 1, "vmSize": "Standard_D2s_v5"}}}})
	snap := capture(t, src, reg)
	r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{}), "|aks")
	if r.OK || !strings.Contains(r.Detail, "properties.windowsProfile.adminPassword with --values") {
		t.Errorf("a cluster Azure will refuse: %v %s", r.OK, r.Detail)
	}
	pw := map[string]map[string]any{managedClusterType + "/rg/aks": {"properties": map[string]any{"windowsProfile": map[string]any{"adminPassword": "Zz9!" + strings.Repeat("x", 20)}}}}
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{Values: pw}), "|aks"); !r.OK {
		t.Errorf("given its password, the cluster is not sent: %s", r.Detail)
	}
}

// What --values sets is sent, so a resumed restore with the same --values
// must find it identical. In the first real restore of a cluster, the node size
// --values set was compared against the snapshot alone and reported as
// differing on every run after. A secret given the same way is not compared:
// Azure never returns it.
func TestWhatValuesSetIsNotADifferenceOnTheNextRun(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	src.SeedAzure(id(srcSub, "rg", managedClusterType, "aks"), stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
		"dnsPrefix": "aks", "windowsProfile": map[string]any{"adminUsername": "azureuser"},
		"agentPoolProfiles": []any{map[string]any{"name": "sys", "mode": "System", "count": 1, "vmSize": "Standard_D2s_v5"}}}})
	snap := capture(t, src, reg)
	vals := map[string]map[string]any{managedClusterType + "/rg/aks": {"properties": map[string]any{
		"windowsProfile":    map[string]any{"adminPassword": "Zz9!" + strings.Repeat("x", 20)},
		"agentPoolProfiles": []any{map[string]any{"name": "sys", "mode": "System", "count": 1, "vmSize": "Standard_D4s_v5"}}}}}
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{Values: vals}), "|aks"); !r.OK {
		t.Fatalf("first run: %s", r.Detail)
	}
	r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{Values: vals}), "|aks")
	if !r.OK || !strings.Contains(r.Detail, "identical") {
		t.Errorf("a resumed run with the same --values: %v %s", r.OK, r.Detail)
	}
	// Without the --values, the size it set is a difference.
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{}), "|aks"); r.OK || !strings.Contains(r.Detail, "vmSize") {
		t.Errorf("without --values the set size is not a difference: %v %s", r.OK, r.Detail)
	}
}

// A table Azure defines has Azure's schema, as AzureDiagnostics does. Captured
// whole, a first real restore diffed one (AcsCallAutomationStreamingUsage) as
// changed: Azure gave the new workspace's copy another display name and an empty
// column list. Only what a person sets on it is kept; a custom table (_CL) keeps
// its whole schema, which a person made.
func TestATableAzureDefinesKeepsOnlyWhatAPersonSets(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	w := put(t, src, "rg", "Microsoft.OperationalInsights/workspaces", "law", map[string]any{"location": "eastus"})
	retention := func(schema map[string]any) map[string]any {
		return map[string]any{"properties": map[string]any{"retentionInDays": 90, "retentionInDaysAsDefault": false, "totalRetentionInDays": 90, "totalRetentionInDaysAsDefault": true, "plan": "Analytics", "schema": schema}}
	}
	src.SeedAzure(w+"/tables/AppTraces", stable(reg, tablesType), retention(map[string]any{"name": "AppTraces", "displayName": "AppTraces", "columns": []any{}}))
	src.SeedAzure(w+"/tables/Orders_CL", stable(reg, tablesType), retention(map[string]any{"name": "Orders_CL", "columns": []any{map[string]any{"name": "OrderId", "type": "string"}}}))
	snap := capture(t, src, reg)
	specs := map[string]string{}
	for _, o := range snap.Objects {
		specs[o.Name()] = canon(o.Body["spec"])
	}
	if got := specs["law/AppTraces"]; strings.Contains(got, "displayName") || strings.Contains(got, "schema") || !strings.Contains(got, `"retentionInDays":90`) {
		t.Errorf("Azure's table: %s", got)
	}
	if got := specs["law/Orders_CL"]; !strings.Contains(got, "OrderId") {
		t.Errorf("a custom table lost its schema: %s", got)
	}
	// Another workspace's copy, as Azure gives it: the display name in other
	// case and no columns. Not a difference.
	put(t, dst, "", groupType, "rg", map[string]any{"location": "eastus"})
	dw := put(t, dst, "rg", "Microsoft.OperationalInsights/workspaces", "law", map[string]any{"location": "eastus"})
	dst.SeedAzure(dw+"/tables/AppTraces", stable(reg, tablesType), retention(map[string]any{"name": "AppTraces", "displayName": "APPTraces"}))
	dst.SeedAzure(dw+"/tables/Orders_CL", stable(reg, tablesType), retention(map[string]any{"name": "Orders_CL", "columns": []any{map[string]any{"name": "OrderId", "type": "string"}}}))
	for _, ch := range snapshot.Compare(snap, capture(t, dst, reg)) {
		if strings.Contains(ch.Key, "/tables|") || strings.Contains(ch.Key, "law/") {
			t.Errorf("a difference Azure made: %s %v", ch.Key, ch.Fields)
		}
	}
	// An older snapshot holds the whole schema, and is compared as captured now.
	old := snap
	old.Objects = nil
	for _, o := range snap.Objects {
		if o.Name() == "law/AppTraces" {
			o = snapshot.Object{Body: deepCopy(o.Body)}
			o.Body["spec"].(map[string]any)["properties"].(map[string]any)["schema"] = map[string]any{"name": "AppTraces", "displayName": "AppTraces"}
		}
		old.Objects = append(old.Objects, o)
	}
	for _, ch := range snapshot.Compare(AsCapturedNow(old), capture(t, dst, reg)) {
		if strings.Contains(ch.Key, "AppTraces") {
			t.Errorf("an older snapshot's Azure table: %v", ch.Fields)
		}
	}
	_ = ctx
}

// In the first real restore of a cluster, a peering to the cluster's own
// network and a DNS link to it were sent while the cluster was being made, and
// refused: capture skips the node resource group and the network AKS made in
// it, so nothing stood between them (review of #73: a wait on the group did
// nothing under the default capture). What names the node group waits for the
// cluster; the cluster, which names its own node group, does not wait for
// itself (review of #73: a cycle).
func TestWhatNamesAClustersNetworkWaitsForTheCluster(t *testing.T) {
	reg, src, _ := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	cluster := id(srcSub, "rg", managedClusterType, "aks")
	nodes := "/subscriptions/" + srcSub + "/resourceGroups/nodes"
	src.SeedAzure(nodes, stable(reg, groupType), map[string]any{"location": "eastus"})
	src.ManagedBy[strings.ToLower(nodes)] = cluster
	src.SeedAzure(nodes+"/providers/Microsoft.Network/virtualNetworks/aks-vnet", stable(reg, vnetType), map[string]any{"location": "eastus", "tags": map[string]any{"aks-managed-cluster-name": "aks"}, "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.224.0.0/12"}}}})
	src.SeedAzure(cluster, stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
		"dnsPrefix": "aks", "nodeResourceGroup": "nodes",
		"identityProfile":   map[string]any{"kubeletidentity": map[string]any{"resourceId": nodes + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-agentpool"}},
		"agentPoolProfiles": []any{map[string]any{"name": "sys", "mode": "System", "count": 1, "vmSize": "Standard_D2s_v5"}}}})
	hub := put(t, src, "rg", vnetType, "hub", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	src.SeedAzure(hub+"/virtualNetworkPeerings/to-aks", stable(reg, "Microsoft.Network/virtualNetworks/virtualNetworkPeerings"), map[string]any{"properties": map[string]any{
		"remoteVirtualNetwork": map[string]any{"id": nodes + "/providers/Microsoft.Network/virtualNetworks/aks-vnet"}}})
	snap := capture(t, src, reg)
	for _, o := range snap.Objects {
		if strings.EqualFold(o.Namespace(), "nodes") || o.Name() == "nodes" {
			t.Fatalf("the default capture took the node group's %s; the test needs it skipped", o.Key())
		}
	}
	order, cyclic, depIdx := restoreGraph(snap.Objects)
	if len(cyclic) != 0 {
		t.Fatalf("cycle: %v", cyclic)
	}
	waits := false
	for i, o := range order {
		if o.Name() == "hub/to-aks" {
			for _, j := range depIdx[i] {
				waits = waits || order[j].Kind() == managedClusterType
			}
		}
	}
	if !waits {
		t.Error("the peering to the cluster's network does not wait for the cluster")
	}
	_ = ctx
}
