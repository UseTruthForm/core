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
