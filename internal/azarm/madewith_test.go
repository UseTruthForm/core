package azarm

import (
	"context"
	"errors"
	"strings"
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
// as not finished, and set once Azure has made it.
func TestAzureDiagnosticsKeepsItsRetentionOnceAzureMakesIt(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	workspace := put(t, src, "rg", "Microsoft.OperationalInsights/workspaces", "law", map[string]any{"location": "eastus"})
	table := tablesType
	src.SeedAzure(workspace+"/tables/AzureDiagnostics", stable(reg, table), map[string]any{"properties": map[string]any{
		"retentionInDays": 90, "totalRetentionInDays": 730, "plan": "Analytics",
		"schema": map[string]any{"name": "AzureDiagnostics", "columns": []any{map[string]any{"name": "Category_s", "type": "string"}}}}})

	snap := capture(t, src, reg)
	var spec string
	for _, o := range snap.Objects {
		if o.Name() == "law/AzureDiagnostics" {
			spec = canon(o.Body["spec"])
		}
	}
	if !strings.Contains(spec, `"retentionInDays":90`) || !strings.Contains(spec, `"totalRetentionInDays":730`) || strings.Contains(spec, "columns") {
		t.Errorf("captured table: %q", spec)
	}
	if got := KeptOnceAzureMakesIt(snap); len(got) != 1 || !strings.Contains(got[0], "law/AzureDiagnostics") {
		t.Errorf("not listed to check: %v", got)
	}

	tableID := id(dstSub, "rg", "Microsoft.OperationalInsights/workspaces", "law") + "/tables/AzureDiagnostics"
	dst.PutError = func(id string, body map[string]any) error {
		if strings.EqualFold(id, tableID) && dst.Stored(id) == nil {
			return errors.New("InvalidParameter: cannot create or migrate AzureDiagnostics table")
		}
		return nil
	}
	rs := Restore(ctx, dst, reg, snap, RestoreOptions{})
	allApplied(t, rs)
	if r := resultFor(t, rs, "law/AzureDiagnostics"); !Pending(r.Detail) {
		t.Errorf("a missing table: %s", r.Detail)
	}

	// Azure makes it, with its defaults: the diff says the retention differs.
	dst.SeedAzure(tableID, stable(reg, table), map[string]any{"properties": map[string]any{"retentionInDays": 30, "totalRetentionInDays": 30, "plan": "Analytics",
		"schema": map[string]any{"name": "AzureDiagnostics", "columns": []any{map[string]any{"name": "Other_s", "type": "string"}}}}})
	ch := snapshot.Compare(AsCapturedNow(snap), capture(t, dst, reg))
	if len(ch) != 1 || !strings.Contains(strings.Join(ch[0].Fields, ","), "retentionInDays") {
		t.Errorf("a diff of the made table: %v", ch)
	}
	// Run again with --update, as the restore said: the retention is kept.
	r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{Update: true}), "law/AzureDiagnostics")
	if !r.OK || Pending(r.Detail) {
		t.Errorf("an update of the made table: %s", r.Detail)
	}
	if p := dst.Stored(tableID)["properties"].(map[string]any); p["retentionInDays"] != float64(90) && p["retentionInDays"] != 90 {
		t.Errorf("retention not kept: %v", p)
	}
	if ch := snapshot.Compare(AsCapturedNow(snap), capture(t, dst, reg)); len(ch) != 0 {
		t.Errorf("after the update: %v", ch)
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
