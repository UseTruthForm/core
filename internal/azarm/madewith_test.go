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
// (HomeReplicationCannotBeOperated) and a workspace's AzureDiagnostics table
// ("cannot create or migrate AzureDiagnostics table"). Azure makes both. They
// are not captured, a snapshot from before is not sent them, and a diff of a
// target that has them only implicitly does not call them missing.
func TestWhatAzureMakesWithItsParentIsNotCapturedOrSent(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	registry := put(t, src, "rg", "Microsoft.ContainerRegistry/registries", "reg1", map[string]any{"location": "eastus", "sku": map[string]any{"name": "Premium"}})
	replication := "Microsoft.ContainerRegistry/registries/replications"
	// ARM spells the home region one way on the registry and another here.
	src.SeedAzure(registry+"/replications/eastus", stable(reg, replication), map[string]any{"location": "East US", "properties": map[string]any{}})
	put(t, src, "rg", replication, "reg1/westus", map[string]any{"location": "westus", "properties": map[string]any{}})
	workspace := put(t, src, "rg", "Microsoft.OperationalInsights/workspaces", "law", map[string]any{"location": "eastus"})
	table := "Microsoft.OperationalInsights/workspaces/tables"
	src.SeedAzure(workspace+"/tables/AzureDiagnostics", stable(reg, table), map[string]any{"properties": map[string]any{"retentionInDays": 30}})
	put(t, src, "rg", table, "law/Mine_CL", map[string]any{"properties": map[string]any{"retentionInDays": 30}})

	snap := capture(t, src, reg)
	names := map[string]bool{}
	for _, o := range snap.Objects {
		names[o.Name()] = true
	}
	for name, want := range map[string]bool{"reg1/eastus": false, "reg1/westus": true, "law/AzureDiagnostics": false, "law/Mine_CL": true} {
		if names[name] != want {
			t.Errorf("captured %s: %v, want %v", name, names[name], want)
		}
	}
	skipped := map[string]string{}
	for _, s := range snap.Skips {
		skipped[s.Name] = s.Reason
	}
	if !strings.Contains(skipped["reg1/eastus"], "registry's own region") || !strings.Contains(skipped["law/AzureDiagnostics"], "diagnostic setting") {
		t.Errorf("skips do not say why: %v", skipped)
	}

	// A snapshot from before holds both, as the real one did.
	old := snap
	old.Objects = append([]snapshot.Object(nil), snap.Objects...)
	for _, o := range snap.Objects {
		switch o.Name() {
		case "reg1/westus":
			b := deepCopy(o.Body)
			b["metadata"].(map[string]any)["name"] = "reg1/eastus"
			b["spec"].(map[string]any)["location"] = "eastus"
			old.Objects = append(old.Objects, snapshot.Object{Body: b})
		case "law/Mine_CL":
			b := deepCopy(o.Body)
			b["metadata"].(map[string]any)["name"] = "law/AzureDiagnostics"
			old.Objects = append(old.Objects, snapshot.Object{Body: b})
		}
	}
	dst.PutError = func(id string, body map[string]any) error {
		if strings.HasSuffix(strings.ToLower(id), "/replications/eastus") {
			return errors.New("HomeReplicationCannotBeOperated")
		}
		if strings.HasSuffix(id, "/tables/AzureDiagnostics") {
			return errors.New("InvalidParameter: cannot create or migrate AzureDiagnostics table")
		}
		return nil
	}
	rs := Restore(ctx, dst, reg, old, RestoreOptions{})
	allApplied(t, rs)
	for _, part := range []string{"reg1/eastus", "law/AzureDiagnostics"} {
		if r := resultFor(t, rs, part); !strings.HasPrefix(r.Detail, NotSent) {
			t.Errorf("%s: %s", part, r.Detail)
		}
	}
	if ch := snapshot.Compare(AsCapturedNow(old), capture(t, dst, reg)); len(ch) != 0 {
		t.Errorf("a diff of the target calls what Azure makes missing: %v", ch)
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
