package azarm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/stackdna/core/internal/snapshot"
)

// These pin what an audit of the restore found before its first real run into
// a second subscription, each named for what the operator would have seen.

func worlds(t *testing.T) (*Registry, *Fake, *Fake) {
	t.Helper()
	reg := fixtures(t)
	w := NewWorld(reg)
	dst := w.Subscription(dstSub, dstTenant)
	dst.CheckReferences = true
	return reg, w.Subscription(srcSub, srcTenant), dst
}

func capture(t *testing.T, f *Fake, reg *Registry) snapshot.Snapshot {
	t.Helper()
	s, err := Capture(context.Background(), f, reg, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func allApplied(t *testing.T, rs []snapshot.Result) {
	t.Helper()
	for _, r := range rs {
		if !r.OK {
			t.Errorf("not applied: %s: %s", r.Key, r.Detail)
		}
	}
}

func resultFor(t *testing.T, rs []snapshot.Result, part string) snapshot.Result {
	t.Helper()
	for _, r := range rs {
		if strings.Contains(r.Key, part) {
			return r
		}
	}
	t.Fatalf("no result for %s in %v", part, rs)
	return snapshot.Result{}
}

func storageBody() map[string]any {
	return map[string]any{"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"}}
}

// Azure said the account had failed to provision. Its configuration matched,
// so restore said "already present and identical" and a diff said no
// differences.
func TestFailedResourceDoesNotReadAsRestored(t *testing.T) {
	reg, src, dst := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, src, "rg", "Microsoft.Storage/storageAccounts", "st1", storageBody())
	snap := capture(t, src, reg)
	allApplied(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}))

	sid := id(dst.sub, "rg", "Microsoft.Storage/storageAccounts", "st1")
	for state, want := range map[string]string{"Failed": "delete it or repair it", "DeleteFailed": "delete it or repair it", "Creating": "when it has finished"} {
		b := dst.Stored(sid)
		b["properties"].(map[string]any)["provisioningState"] = state
		dst.SeedAzure(sid, stable(reg, "Microsoft.Storage/storageAccounts"), b)

		r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "st1")
		if r.OK || !strings.Contains(r.Detail, want) {
			t.Errorf("%s: ok=%v %s", state, r.OK, r.Detail)
		}
		again := capture(t, dst, reg)
		// Still changing is no fault: a cluster in an upgrade would turn every
		// scheduled diff red.
		if state == "Creating" {
			if len(again.Unwell) != 0 {
				t.Errorf("%s reads as not working: %v", state, again.Unwell)
			}
			continue
		}
		if len(again.Unwell) != 1 || !strings.Contains(again.Unwell[0], state) {
			t.Errorf("%s: a diff is not told: %v", state, again.Unwell)
		}
		// Reported, so a diff, an environment's diff and --json all say it.
		ch := snapshot.Compare(snap, again)
		if len(ch) != 1 || ch[0].Kind != "not working" {
			t.Errorf("%s: %v", state, ch)
		}
		// How the system is now must not reach what is written.
		again.Unwell = nil
		if ch := snapshot.Compare(snap, again); len(ch) != 0 {
			t.Errorf("%s: state reads as drift: %v", state, ch)
		}
	}

	// A word only some type uses for finished is not a failure.
	b := dst.Stored(sid)
	b["properties"].(map[string]any)["provisioningState"] = "Ready"
	dst.SeedAzure(sid, stable(reg, "Microsoft.Storage/storageAccounts"), b)
	if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "st1"); !r.OK {
		t.Errorf("Ready read as unfinished: %s", r.Detail)
	}
}

// Azure makes a storage account's blobServices/default with the account, with
// its own defaults. On a clean target, every such child was a conflict.
func TestAutoCreatedChildIsSetOnlyIfThisRunMadeItsParent(t *testing.T) {
	reg, src, dst := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	st := put(t, src, "rg", "Microsoft.Storage/storageAccounts", "st1", storageBody())
	rawPut(t, src, st+"/blobServices/default", "Microsoft.Storage/storageAccounts/blobServices", map[string]any{"properties": map[string]any{"deleteRetentionPolicy": map[string]any{"enabled": true, "days": 30}}})
	snap := capture(t, src, reg)
	dst.AfterCreate = func(i string, _ map[string]any) {
		if rid, _ := ParseID(i); rid.Type == "Microsoft.Storage/storageAccounts" {
			dst.SeedAzure(i+"/blobServices/default", stable(reg, "Microsoft.Storage/storageAccounts/blobServices"), map[string]any{"properties": map[string]any{"deleteRetentionPolicy": map[string]any{"enabled": false}}})
		}
	}
	rs := Restore(context.Background(), dst, reg, snap, RestoreOptions{})
	allApplied(t, rs)
	if r := resultFor(t, rs, "blobServices"); !strings.HasPrefix(r.Detail, "updated") {
		t.Errorf("a change to something live goes unsaid: %s", r.Detail)
	}
	if ch := snapshot.Compare(snap, capture(t, dst, reg)); len(ch) != 0 {
		t.Errorf("second diff: %v", ch)
	}

	// Its parent was already there: someone may have set the child, so a
	// restore without --update leaves it alone, as it always did.
	dst.SeedAzure(id(dst.sub, "rg", "Microsoft.Storage/storageAccounts", "st1")+"/blobServices/default", stable(reg, "Microsoft.Storage/storageAccounts/blobServices"), map[string]any{"properties": map[string]any{"deleteRetentionPolicy": map[string]any{"enabled": false}}})
	if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "blobServices"); r.OK || !strings.Contains(r.Detail, "--update") {
		t.Errorf("changed a child of what it did not create: %s", r.Detail)
	}
}

type refusesPut struct {
	*Fake
	match string
}

func (f refusesPut) Put(ctx context.Context, i, v string, b map[string]any) (map[string]any, error) {
	if strings.Contains(i, f.match) {
		return nil, errors.New("refused")
	}
	return f.Fake.Put(ctx, i, v, b)
}

// A ReadOnly lock put on after a failure refuses the re-run that would fix it.
func TestLockIsHeldBackAfterAFailure(t *testing.T) {
	reg, src, dst := worlds(t)
	g := put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, src, "rg", "Microsoft.Storage/storageAccounts", "st1", storageBody())
	rawPut(t, src, g+"/providers/Microsoft.Authorization/locks/ro", "Microsoft.Authorization/locks", map[string]any{"properties": map[string]any{"level": "ReadOnly"}})
	snap := capture(t, src, reg)
	rs := Restore(context.Background(), refusesPut{dst, "st1"}, reg, snap, RestoreOptions{})
	if r := resultFor(t, rs, "locks"); r.OK || !strings.Contains(r.Detail, "held back") {
		t.Errorf("lock: ok=%v %s", r.OK, r.Detail)
	}
	allApplied(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}))

	// One already there and identical is no reason to report anything.
	sid := id(dst.sub, "rg", "Microsoft.Storage/storageAccounts", "st1")
	b := dst.Stored(sid)
	b["tags"] = map[string]any{"t": "by hand"}
	dst.SeedAzure(sid, stable(reg, "Microsoft.Storage/storageAccounts"), b)
	if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "locks"); !r.OK {
		t.Errorf("a lock already there: %s", r.Detail)
	}
}

// Not only a failed create: a lock went on after a conflict and a failed update,
// which are what a re-run is for.
func TestLockIsHeldBackAfterAConflictOrAFailedUpdate(t *testing.T) {
	seed := func(t *testing.T) (*Registry, *Fake, snapshot.Snapshot) {
		reg, src, dst := worlds(t)
		g := put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
		put(t, src, "rg", "Microsoft.Storage/storageAccounts", "st1", storageBody())
		rawPut(t, src, g+"/providers/Microsoft.Authorization/locks/ro", "Microsoft.Authorization/locks", map[string]any{"properties": map[string]any{"level": "ReadOnly"}})
		snap := capture(t, src, reg)
		put(t, dst, "", groupType, "rg", map[string]any{"location": "eastus"})
		b := storageBody()
		b["tags"] = map[string]any{"t": "by hand"}
		put(t, dst, "rg", "Microsoft.Storage/storageAccounts", "st1", b)
		return reg, dst, snap
	}
	t.Run("conflict", func(t *testing.T) {
		reg, dst, snap := seed(t)
		if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "locks"); r.OK {
			t.Errorf("lock applied after a conflict: %s", r.Detail)
		}
	})
	t.Run("failed update", func(t *testing.T) {
		reg, dst, snap := seed(t)
		if r := resultFor(t, Restore(context.Background(), refusesPut{dst, "st1"}, reg, snap, RestoreOptions{Update: true}), "locks"); r.OK {
			t.Errorf("lock applied after a failed update: %s", r.Detail)
		}
	})
}

func TestOrderSeesWhatItMissed(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	vnetKey := strings.ToLower(APIVersion + "|Microsoft.Network/virtualNetworks|rg|v")
	// A grant on a subnet ran before its network, even at --parallel 1.
	on := obj("Microsoft.Authorization/roleAssignments", "rg", "a1", sub+"/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s/providers/Microsoft.Authorization/roleAssignments/a1", map[string]any{})
	if d := deps(on); !slices.Contains(d, vnetKey) {
		t.Errorf("a grant on a subnet does not wait for its network: %v", d)
	}
	// Some services return .../resourcegroups/...: nothing waited.
	kv := obj("Microsoft.KeyVault/vaults", "rg", "kv", sub+"/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv", map[string]any{"properties": map[string]any{
		"networkAcls": map[string]any{"virtualNetworkRules": []any{map[string]any{"id": sub + "/resourcegroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s"}}}}})
	if d := deps(kv); !slices.Contains(d, vnetKey) {
		t.Errorf("a lower-case reference has nothing waiting for it: %v", d)
	}
}

func clusterObj(identityID string) snapshot.Object {
	sub := "/subscriptions/" + tokSub
	return obj(managedClusterType, "rg", "aks", sub+"/resourceGroups/rg/providers/"+managedClusterType+"/aks", map[string]any{
		"identity": map[string]any{"type": "UserAssigned", "userAssignedIdentities": map[string]any{identityID: map[string]any{}}}})
}

// With a custom private DNS zone Azure refuses the cluster until its identity
// holds the grant, and nothing in the cluster names the grant.
func TestClusterWaitsForWhatItsIdentityIsGranted(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	idType := "Microsoft.ManagedIdentity/userAssignedIdentities"
	identityID := sub + "/resourceGroups/rg/providers/" + idType + "/cp"
	ref := refPrefix + idType + "|rg|cp|properties.principalId}}"
	identity := obj(idType, "rg", "cp", identityID, map[string]any{})
	grant := obj("Microsoft.Authorization/roleAssignments", "rg", "a1", sub+"/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/z/providers/Microsoft.Authorization/roleAssignments/a1", map[string]any{"properties": map[string]any{"principalId": ref}})
	// Granted on the cluster itself: it cannot come first.
	onCluster := obj("Microsoft.Authorization/roleAssignments", "rg", "a2", sub+"/resourceGroups/rg/providers/"+managedClusterType+"/aks/providers/Microsoft.Authorization/roleAssignments/a2", map[string]any{"properties": map[string]any{"principalId": ref}})
	order, cyclic, depIdx := restoreGraph([]snapshot.Object{clusterObj(identityID), grant, onCluster, identity})
	if len(cyclic) != 0 {
		t.Fatalf("cycle: %v", cyclic)
	}
	// By what it waits for, not where it lands: the grant sorts ahead of the
	// cluster anyway, and running at once would start them together.
	waits := map[string]bool{}
	at := map[string]int{}
	for i, o := range order {
		at[lastName(o.Name())] = i
		if o.Kind() == managedClusterType {
			for _, j := range depIdx[i] {
				waits[lastName(order[j].Name())] = true
			}
		}
	}
	if !waits["a1"] {
		t.Errorf("the cluster does not wait for the grant it needs: %v", waits)
	}
	if waits["a2"] || at["a2"] < at["aks"] {
		t.Errorf("a grant on the cluster comes before the cluster: %v %v", waits, at)
	}
}

// An identity refuses a second write to its credentials while one is running.
func TestFederatedCredentialsGoOneAtATime(t *testing.T) {
	sub := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
	var objs []snapshot.Object
	for _, n := range []string{"a/x", "a/y", "a/z", "b/x"} {
		parent, name, _ := strings.Cut(n, "/")
		objs = append(objs, obj(federatedCredentialType, "rg", n, sub+parent+"/federatedIdentityCredentials/"+name, map[string]any{}))
	}
	order, _, depIdx := restoreGraph(objs)
	waits := func(name string) (out []string) {
		for i, o := range order {
			if o.Name() == name {
				for _, j := range depIdx[i] {
					out = append(out, order[j].Name())
				}
			}
		}
		return out
	}
	if !slices.Contains(waits("a/y"), "a/x") || !slices.Contains(waits("a/z"), "a/y") {
		t.Errorf("siblings can run at once: y %v, z %v", waits("a/y"), waits("a/z"))
	}
	if len(waits("b/x")) != 0 {
		t.Errorf("another identity's credential waits: %v", waits("b/x"))
	}
}

// Two peered networks each waited for the other: "its references form a cycle",
// for them and all that needed them, on every run.
func TestPeeredNetworksRestore(t *testing.T) {
	reg, src, dst := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	net := func(name, peer string) {
		peerID := id(src.sub, "rg", vnetType, peer)
		put(t, src, "rg", vnetType, name, map[string]any{"location": "eastus", "properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
		rawPut(t, src, id(src.sub, "rg", vnetType, name)+"/virtualNetworkPeerings/to-"+peer, vnetType+"/virtualNetworkPeerings", map[string]any{
			"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": peerID}, "allowVirtualNetworkAccess": true}})
	}
	net("hub", "spoke")
	net("spoke", "hub")
	snap := capture(t, src, reg)
	for _, o := range snap.Objects {
		if o.Kind() == vnetType && strings.Contains(canon(o.Body["spec"]), "virtualNetworkPeerings") {
			t.Errorf("peerings left in the network, where they make a cycle: %s", o.Name())
		}
	}
	rs := Restore(context.Background(), dst, reg, snap, RestoreOptions{})
	allApplied(t, rs)
	if resultFor(t, rs, "hub/to-spoke").Detail == "" {
		t.Error("peering not restored")
	}
	if ch := snapshot.Compare(snap, capture(t, dst, reg)); len(ch) != 0 {
		t.Errorf("second diff: %v", ch)
	}
}

// With --update, a PUT of a network without its peerings would cut them all.
func TestUpdatingANetworkKeepsItsPeerings(t *testing.T) {
	reg, src, dst := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, src, "rg", vnetType, "hub", map[string]any{"location": "eastus", "tags": map[string]any{"t": "new"}, "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	snap := capture(t, src, reg)
	allApplied(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}))

	put(t, dst, "rg", vnetType, "spoke", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.1.0.0/16"}}}})
	i := id(dst.sub, "rg", vnetType, "hub")
	b := dst.Stored(i)
	b["tags"] = map[string]any{"t": "old"}
	peering := []any{map[string]any{"name": "p", "properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": id(dst.sub, "rg", vnetType, "spoke")}}}}
	b["properties"].(map[string]any)["virtualNetworkPeerings"] = peering
	dst.SeedAzure(i, stable(reg, vnetType), b)

	allApplied(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{Update: true}))
	got, _ := dst.Stored(i)["properties"].(map[string]any)["virtualNetworkPeerings"].([]any)
	if dst.Stored(i)["tags"].(map[string]any)["t"] != "new" || len(got) != 1 {
		t.Errorf("after update: tags %v, peerings %v", dst.Stored(i)["tags"], got)
	}
}

func clusterWithIssuer(t *testing.T, f *Fake, reg *Registry, issuer string) {
	t.Helper()
	i := id(f.sub, "rg", managedClusterType, "aks")
	f.SeedAzure(i, stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
		"oidcIssuerProfile": map[string]any{"enabled": true, "issuerURL": issuer}}})
}

// An issuer is a plain setting, so it was restored as it was. The credential
// went on trusting the source cluster, the target's workloads could not sign
// in, and a diff was clean.
func TestWorkloadIdentityTrustsTheRestoredCluster(t *testing.T) {
	reg, src, dst := worlds(t)
	srcIssuer := "https://eastus.oic.prod-aks.azure.com/" + srcTenant + "/99999999-aaaa-bbbb-cccc-111111111111/"
	dstIssuer := "https://eastus.oic.prod-aks.azure.com/" + dstTenant + "/88888888-aaaa-bbbb-cccc-222222222222/"
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	clusterWithIssuer(t, src, reg, srcIssuer)
	ident := put(t, src, "rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "wid", map[string]any{"location": "eastus"})
	fic := func(i, name, issuer string) {
		rawPut(t, src, i+"/federatedIdentityCredentials/"+name, federatedCredentialType, map[string]any{
			"properties": map[string]any{"issuer": issuer, "subject": "system:serviceaccount:ns:" + name, "audiences": []any{"api://AzureADTokenExchange"}}})
	}
	fic(ident, "sa", srcIssuer)
	const elsewhere = "https://token.actions.githubusercontent.com"
	fic(ident, "ci", elsewhere)

	snap := capture(t, src, reg)
	var o snapshot.Object
	for _, x := range snap.Objects {
		if strings.HasSuffix(x.Name(), "wid/sa") {
			o = x
		}
	}
	if o.Body == nil {
		t.Fatalf("no credential captured: %v", snap.Objects)
	}
	if got := canon(o.Body["spec"]); !strings.Contains(got, refPrefix+managedClusterType) || strings.Contains(got, "99999999") {
		t.Errorf("issuer: %s", got)
	}

	// The snapshot's cluster stands for itself here: no AKS is made by a fake.
	put(t, dst, "", groupType, "rg", map[string]any{"location": "eastus"})
	clusterWithIssuer(t, dst, reg, dstIssuer)
	var without []snapshot.Object
	for _, x := range snap.Objects {
		if x.Kind() != managedClusterType {
			without = append(without, x)
		}
	}
	all := snap
	all.Objects = without
	for _, x := range snap.Objects {
		if x.Kind() == managedClusterType {
			all.Objects = append(all.Objects, x)
		}
	}
	rs := Restore(context.Background(), dst, reg, all, RestoreOptions{})
	for _, r := range rs {
		if !r.OK && !strings.Contains(r.Key, managedClusterType) {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	credID := id(dst.sub, "rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "wid") + "/federatedIdentityCredentials/"
	if got := dst.Stored(credID + "sa")["properties"].(map[string]any)["issuer"]; got != dstIssuer {
		t.Errorf("restored issuer %v, want the target cluster's %s", got, dstIssuer)
	}
	if got := dst.Stored(credID + "ci")["properties"].(map[string]any)["issuer"]; got != elsewhere {
		t.Errorf("an issuer that is no cluster's changed: %v", got)
	}
	// A second run compares like with like, and a diff sees the reference.
	if r := resultFor(t, Restore(context.Background(), dst, reg, all, RestoreOptions{}), "wid/sa"); !r.OK || r.Detail != "already present and identical" {
		t.Errorf("second restore: %s", r.Detail)
	}
	again := capture(t, dst, reg)
	for _, x := range again.Objects {
		if strings.HasSuffix(x.Name(), "wid/sa") && !strings.Contains(canon(x.Body["spec"]), refPrefix+managedClusterType) {
			t.Errorf("a capture of the target does not see the reference: %s", canon(x.Body["spec"]))
		}
	}
}

// Declared writable, and not configuration: each read as drift no one made.
func TestWhatAzureSetsIsNotCaptured(t *testing.T) {
	reg := fixtures(t)
	for _, tc := range []struct {
		typ  string
		body map[string]any
		gone string
	}{
		{"Microsoft.KeyVault/vaults", map[string]any{"properties": map[string]any{"tenantId": "t", "vaultUri": "https://old.vault.azure.net/"}}, "vaultUri"},
		{managedClusterType, map[string]any{"properties": map[string]any{"agentPoolProfiles": []any{map[string]any{"name": "p", "nodeImageVersion": "AKSUbuntu-2204-1"}}}}, "nodeImageVersion"},
		{"Microsoft.Network/privateDnsZones/SOA", map[string]any{"properties": map[string]any{"soaRecord": map[string]any{"serialNumber": 7, "host": "h"}}}, "serialNumber"},
	} {
		s := schema(t, reg, tc.typ)
		spec, _ := s.normalize(tc.body)
		if strings.Contains(canon(spec), tc.gone) {
			t.Errorf("%s keeps %s: %s", tc.typ, tc.gone, canon(spec))
		}
	}
	// By type: elsewhere these names are settings, and a diff could not see them go.
	spec, _ := schema(t, reg, "Microsoft.Web/sites").normalize(map[string]any{"properties": map[string]any{"vaultUri": "https://mine/", "serialNumber": "1", "peeringState": "x"}})
	for _, name := range []string{"vaultUri", "serialNumber", "peeringState"} {
		if !strings.Contains(canon(spec), name) {
			t.Errorf("%s stripped from another type: %s", name, canon(spec))
		}
	}
}

// A peering's state is out of its configuration, and a dead one read as identical
// with a clean diff. Connected is fine, Initiated carries nothing yet, and
// Disconnected cannot come back by itself.
func TestDeadPeeringIsNotWorking(t *testing.T) {
	reg, src, dst := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	for _, n := range []string{"hub", "spoke"} {
		put(t, src, "rg", vnetType, n, map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	}
	peering := vnetType + "/virtualNetworkPeerings"
	rawPut(t, src, id(src.sub, "rg", vnetType, "hub")+"/virtualNetworkPeerings/p", peering, map[string]any{"properties": map[string]any{
		"remoteVirtualNetwork": map[string]any{"id": id(src.sub, "rg", vnetType, "spoke")}, "peeringState": "Connected"}})
	snap := capture(t, src, reg)
	allApplied(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}))
	i := id(dst.sub, "rg", vnetType, "hub") + "/virtualNetworkPeerings/p"
	for state, restored := range map[string]bool{"Connected": true, "Initiated": true, "Disconnected": false} {
		b := dst.Stored(i)
		b["properties"].(map[string]any)["peeringState"] = state
		dst.SeedAzure(i, stable(reg, peering), b)
		again := capture(t, dst, reg)
		if len(again.Unwell) != map[bool]int{true: 0, false: 1}[state == "Connected"] {
			t.Errorf("%s: diff told %v", state, again.Unwell)
		}
		if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "hub/p"); r.OK != restored {
			t.Errorf("%s: restore ok=%v %s", state, r.OK, r.Detail)
		}
	}
}

// Held apart from their network only for a restore's order, peerings stay part of
// it: a capture of Microsoft.Network/* lost them, with restore and diff clean.
func TestCaptureOfANetworkTypeKeepsItsPeerings(t *testing.T) {
	p := Policy{Types: []string{"Microsoft.Network/*"}}
	if !p.selected(vnetType + "/virtualNetworkPeerings") {
		t.Error("peerings dropped")
	}
	if (Policy{Types: []string{"Microsoft.Storage/*"}}).selected(vnetType + "/virtualNetworkPeerings") {
		t.Error("peerings kept without their network")
	}
	// Asked for by name, to put one back: refused as matching nothing, it was not.
	for _, pat := range []string{vnetType + "/virtualNetworkPeerings", vnetType + "/*"} {
		if !(Policy{Types: []string{pat}}).selected(vnetType + "/virtualNetworkPeerings") {
			t.Errorf("%s does not select a peering", pat)
		}
	}
}

// --update was refused on every key vault for want of its createMode, which
// is write-only and no secret, and each was reported restored without secrets.
func TestOnlyCredentialsCountAsSecrets(t *testing.T) {
	reg := fixtures(t)
	paths := schema(t, reg, "Microsoft.KeyVault/vaults").secretPaths()
	if slices.Contains(paths, "properties.createMode") {
		t.Errorf("createMode counts as a secret: %v", paths)
	}
	// Write-only with no credential's name: a rule by name lost it without a word.
	if site := schema(t, reg, "Microsoft.Web/sites").secretPaths(); !slices.Contains(site, "properties.siteConfig") {
		t.Errorf("a web app's settings stopped being said: %v", site)
	}
	for name, made := range map[string]bool{"createMode": true, "cloningInfo": true, "sourceDatabaseId": true, "restorePointInTime": true, "crossSubscriptionSourceDatabaseId": true,
		"customHeaders": false, "siteConfig": false, "requestedBackupStorageRedundancy": false, "source": false} {
		if howItWasMadeRE.MatchString(name) != made {
			t.Errorf("%s: how it was made = %v", name, !made)
		}
	}
	vm := schema(t, reg, "Microsoft.Compute/virtualMachines").secretPaths()
	if !slices.Contains(vm, "properties.osProfile.adminPassword") {
		t.Errorf("a VM's password stopped counting: %v", vm)
	}
	if !slices.Contains(schema(t, reg, managedClusterType).secretPaths(), "properties.servicePrincipalProfile.secret") {
		t.Error("a service principal's secret stopped counting")
	}
	for spec, want := range map[string]bool{"msi": true, "11111111-0000-0000-0000-000000000000": false} {
		s := map[string]any{"properties": map[string]any{"servicePrincipalProfile": map[string]any{"clientId": spec}}}
		if got := usesManagedIdentity(s, "properties.servicePrincipalProfile.secret"); got != want {
			t.Errorf("clientId %s: %v", spec, got)
		}
	}
	if usesManagedIdentity(map[string]any{"properties": map[string]any{"clientId": "msi"}}, "properties.adminPassword") {
		t.Error("a password is excused")
	}
}

// A kubenet cluster attaches a route table from its node group to a subnet. The
// network comes first, and could not name it, and all behind the network failed.
func TestNetworkDoesNotNameARouteTableInANodeGroup(t *testing.T) {
	reg, src, _ := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	mc := put(t, src, "", groupType, nodeGroup, map[string]any{"location": "eastus"})
	src.ManagedBy[strings.ToLower(mc)] = strings.ReplaceAll(clusterID, "SUB", srcSub)
	own := id(src.sub, "rg", "Microsoft.Network/routeTables", "mine")
	inGroup := id(src.sub, nodeGroup, "Microsoft.Network/routeTables", "aks-agentpool-rt")
	put(t, src, "rg", vnetType, "v", map[string]any{"location": "eastus", "properties": map[string]any{
		"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}},
		"subnets": []any{
			map[string]any{"name": "a", "properties": map[string]any{"addressPrefix": "10.0.1.0/24", "routeTable": map[string]any{"id": inGroup}}},
			map[string]any{"name": "b", "properties": map[string]any{"addressPrefix": "10.0.2.0/24", "routeTable": map[string]any{"id": own}}},
		}}})
	spec := ""
	for _, o := range capture(t, src, reg).Objects {
		if o.Kind() == vnetType {
			spec = canon(o.Body["spec"])
		}
	}
	if strings.Contains(spec, "aks-agentpool-rt") {
		t.Errorf("names what cannot exist yet: %s", spec)
	}
	if !strings.Contains(spec, "routeTables/mine") {
		t.Errorf("lost a route table the snapshot holds: %s", spec)
	}
}

// Restored, a connection has no endpoint to name, and a zone group's record
// holds the old network's address. All 5 such records on a real estate said who
// wrote them; a record a person wrote says nothing and stays.
func TestWhatAPrivateEndpointMakesIsNotCaptured(t *testing.T) {
	reg, src, _ := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	st := put(t, src, "rg", "Microsoft.Storage/storageAccounts", "st1", storageBody())
	src.SeedAzure(st+"/privateEndpointConnections/pe.abc", stable(reg, "Microsoft.Storage/storageAccounts/privateEndpointConnections"), map[string]any{
		"properties": map[string]any{"privateLinkServiceConnectionState": map[string]any{"status": "Approved"}}})
	zone := put(t, src, "rg", "Microsoft.Network/privateDnsZones", "privatelink.blob.core.windows.net", map[string]any{"location": "global"})
	aType := "Microsoft.Network/privateDnsZones/A"
	src.SeedAzure(zone+"/A/st1", stable(reg, aType), map[string]any{"properties": map[string]any{"ttl": 10,
		"metadata": map[string]any{"creator": "created by private endpoint pe with resource guid 00000000-0000-0000-0000-000000000001"}, "aRecords": []any{map[string]any{"ipv4Address": "10.0.0.4"}}}})
	src.SeedAzure(zone+"/A/mine", stable(reg, aType), map[string]any{"properties": map[string]any{"ttl": 10, "aRecords": []any{map[string]any{"ipv4Address": "10.0.0.5"}}}})

	s := capture(t, src, reg)
	names := map[string]bool{}
	for _, o := range s.Objects {
		names[o.Kind()+"|"+lastName(o.Name())] = true
	}
	if !names[aType+"|mine"] {
		t.Errorf("a record a person wrote was dropped: %v", names)
	}
	if names[aType+"|st1"] || names["Microsoft.Storage/storageAccounts/privateEndpointConnections|pe.abc"] {
		t.Errorf("captured what an endpoint makes: %v", names)
	}
	said := map[string]bool{}
	for _, sk := range s.Skips {
		said[strings.ToLower(sk.Resource)] = true
	}
	if !said[strings.ToLower(aType)] || !said["microsoft.storage/storageaccounts/privateendpointconnections"] {
		t.Errorf("left out without a word: %v", s.Skips)
	}
}

// On a real estate all 4 of an endpoint's interfaces have its managedBy. Flagged
// as may-not-come-back, each would be a false alarm in every report.
func TestEndpointInterfaceComesBackWithItsEndpoint(t *testing.T) {
	sub := "/subscriptions/" + srcSub + "/resourceGroups/rg/providers/"
	if !managerRecreates("Microsoft.Network/networkInterfaces", "nic", sub+"Microsoft.Network/privateEndpoints/pe") {
		t.Error("an endpoint's interface reads as lost")
	}
	if managerRecreates("Microsoft.Network/networkInterfaces", "nic", sub+"Microsoft.Compute/virtualMachines/vm") {
		t.Error("a VM's interface is promised back")
	}
}

// SQL's master database was left out by managedBy and captured again as its
// server's child, with its own children.
func TestLeftOutIsNotCapturedAgainAsAChild(t *testing.T) {
	reg, src, _ := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	st := put(t, src, "rg", "Microsoft.Storage/storageAccounts", "st1", storageBody())
	child := st + "/blobServices/default"
	rawPut(t, src, child, "Microsoft.Storage/storageAccounts/blobServices", map[string]any{"properties": map[string]any{}})
	src.AlsoTracked = map[string]bool{"Microsoft.Storage/storageAccounts/blobServices": true}
	src.ManagedBy[strings.ToLower(child)] = st
	s := capture(t, src, reg)
	for _, o := range s.Objects {
		if o.Kind() == "Microsoft.Storage/storageAccounts/blobServices" {
			t.Errorf("skipped and captured both: %s", o.Key())
		}
	}
}

// A storage account's logs are set on its blob, file, queue and table services:
// never read, and nothing said so.
func TestDiagnosticSettingsOnChildrenAreRead(t *testing.T) {
	reg, src, _ := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	st := put(t, src, "rg", "Microsoft.Storage/storageAccounts", "st1", storageBody())
	blob := st + "/blobServices/default"
	rawPut(t, src, blob, "Microsoft.Storage/storageAccounts/blobServices", map[string]any{"properties": map[string]any{}})
	rawPut(t, src, blob+"/providers/Microsoft.Insights/diagnosticSettings/logs", diagnosticType, map[string]any{"location": "eastus", "properties": map[string]any{
		"storageAccountId": st, "logs": []any{map[string]any{"category": "AuditEvent", "enabled": true}}}})
	found := false
	for _, o := range capture(t, src, reg).Objects {
		found = found || (o.Kind() == diagnosticType && strings.HasSuffix(o.Name(), "/logs"))
	}
	if !found {
		t.Error("diagnostic setting on a blob service not captured")
	}
}

// An assignment of a custom policy was restored with nothing to point at. It is
// asked for by filter, so the fake must be shown the filter is on the path.
func TestCustomPolicyDefinitionsAreCaptured(t *testing.T) {
	reg, src, _ := worlds(t)
	typ := "Microsoft.Authorization/policyDefinitions"
	rawPut(t, src, "/subscriptions/"+src.sub+"/providers/"+typ+"/mine", typ, map[string]any{"properties": map[string]any{
		"policyType": "Custom", "mode": "All", "displayName": "mine", "policyRule": map[string]any{"if": map[string]any{}, "then": map[string]any{"effect": "audit"}}}})
	found := false
	for _, o := range capture(t, src, reg).Objects {
		found = found || (o.Kind() == typ && lastName(o.Name()) == "mine")
	}
	if !found {
		t.Error("custom policy definition not captured")
	}
}

// In the source's tenant a role's ID looks absent from the target, and a PUT
// would take over the source's role, narrowing it and breaking what is assigned.
func TestCustomRoleInTheSameTenantIsNotTakenOver(t *testing.T) {
	reg := fixtures(t)
	w := NewWorld(reg)
	src, same, other := w.Subscription(srcSub, srcTenant), w.Subscription(dstSub, srcTenant), w.Subscription("33333333-3333-3333-3333-333333333333", dstTenant)
	typ := "Microsoft.Authorization/roleDefinitions"
	rawPut(t, src, "/subscriptions/"+src.sub+"/providers/"+typ+"/"+customRoleID, typ, map[string]any{"properties": map[string]any{
		"roleName": "shop-reader", "type": "CustomRole", "assignableScopes": []any{"/subscriptions/" + src.sub},
		"permissions": []any{map[string]any{"actions": []any{"*/read"}}}}})
	snap := capture(t, src, reg)
	before := same.Puts
	r := resultFor(t, Restore(context.Background(), same, reg, snap, RestoreOptions{}), customRoleID)
	if r.OK || !strings.Contains(r.Detail, "already exists in this tenant") || same.Puts != before {
		t.Errorf("same tenant: ok=%v puts=%d %s", r.OK, same.Puts-before, r.Detail)
	}
	if r := resultFor(t, Restore(context.Background(), other, reg, snap, RestoreOptions{}), customRoleID); !r.OK {
		t.Errorf("another tenant: %s", r.Detail)
	}
}

func TestNewRoleAssignmentIDs(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	name := "providers/Microsoft.Storage/storageAccounts/st/providers/Microsoft.Authorization/roleAssignments/" + assignmentID
	mk := func() snapshot.Snapshot {
		return snapshot.Snapshot{Objects: []snapshot.Object{
			obj("Microsoft.Authorization/roleAssignments", "rg", name, sub+"/resourceGroups/rg/"+name, map[string]any{}),
			obj("Microsoft.Storage/storageAccounts", "rg", "st", sub+"/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st", map[string]any{}),
		}}
	}
	s := mk()
	got := NewRoleAssignmentIDs(s, dstSub)
	o := got.Objects[0]
	if strings.Contains(o.Name(), assignmentID) || strings.Contains(fmt.Sprint(annotation(o, annID)), assignmentID) {
		t.Errorf("kept the old name: %s %v", o.Name(), annotation(o, annID))
	}
	if !strings.HasPrefix(o.Name(), "providers/Microsoft.Storage/storageAccounts/st/providers/Microsoft.Authorization/roleAssignments/") {
		t.Errorf("lost its scope: %s", o.Name())
	}
	guid := lastName(o.Name())
	if len(guid) != 36 || guid[14] != '5' {
		t.Errorf("not a GUID Azure takes: %s", guid)
	}
	if lastName(NewRoleAssignmentIDs(s, dstSub).Objects[0].Name()) != guid {
		t.Error("not the same each time: a re-run and a diff would not find them")
	}
	if lastName(NewRoleAssignmentIDs(s, "other").Objects[0].Name()) == guid {
		t.Error("the same for two targets")
	}
	if got.Objects[1].Name() != "st" {
		t.Errorf("changed something else: %s", got.Objects[1].Name())
	}
	if !strings.Contains(s.Objects[0].Name(), assignmentID) {
		t.Error("changed the snapshot it was given")
	}
}

func TestRestoreTypesLimitsWhatIsApplied(t *testing.T) {
	reg, src, dst := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, src, "rg", "Microsoft.Storage/storageAccounts", "st1", storageBody())
	put(t, src, "rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "wid", map[string]any{"location": "eastus"})
	snap := capture(t, src, reg)
	rs := Restore(context.Background(), dst, reg, snap, RestoreOptions{Types: []string{"Microsoft.ManagedIdentity/*"}})
	allApplied(t, rs)
	if len(rs) != 2 {
		t.Errorf("want the group and the identity: %v", rs)
	}
	if dst.Stored(id(dst.sub, "rg", "Microsoft.Storage/storageAccounts", "st1"))["kind"] != nil {
		t.Error("restored what was held back, and would have billed for it")
	}
}

// An operation Azure keeps running: one 503 from a poll ended the wait, and the
// resource was reported failed while it went on being created.
func TestPollErrorDoesNotFailAWrite(t *testing.T) {
	oldEvery := pollEvery
	pollEvery = time.Millisecond
	defer func() { pollEvery = oldEvery }()
	var polls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut:
			w.Header().Set("Azure-AsyncOperation", srv.URL+"/op?api-version=1")
			w.WriteHeader(201)
			fmt.Fprint(w, `{"properties":{"provisioningState":"Creating"}}`)
		case strings.HasPrefix(r.URL.Path, "/op"):
			n := polls.Add(1)
			if n >= 2 && n < 8 {
				w.WriteHeader(503)
				fmt.Fprint(w, `{"error":{"code":"ServiceUnavailable","message":"try later"}}`)
				return
			}
			st := "InProgress"
			if n >= 8 {
				st = "Succeeded"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": st})
		default:
			fmt.Fprint(w, `{"properties":{"provisioningState":"Succeeded"}}`)
		}
	}))
	defer srv.Close()
	fast := policy.RetryOptions{MaxRetries: 1, RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond}
	pl := runtime.NewPipeline("x", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{Retry: fast})
	s := &SDK{sub: dstSub, pl: pl, ep: srv.URL}
	if _, err := s.Put(context.Background(), "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Foo/bars/b", "1", map[string]any{}); err != nil {
		t.Errorf("polls=%d: %v", polls.Load(), err)
	}
}

// During an update the old resource reads as fine, so asking it instead of the
// operation said "updated" of a write whose outcome no one knew.
func TestUnknownOutcomeIsNotSuccess(t *testing.T) {
	oldEvery, oldMisses := pollEvery, pollMisses
	pollEvery, pollMisses = time.Millisecond, 3
	defer func() { pollEvery, pollMisses = oldEvery, oldMisses }()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut:
			w.Header().Set("Azure-AsyncOperation", srv.URL+"/op?api-version=1")
			w.WriteHeader(200)
			fmt.Fprint(w, `{"properties":{"provisioningState":"Updating"}}`)
		case strings.HasPrefix(r.URL.Path, "/op"):
			w.WriteHeader(500)
			fmt.Fprint(w, `{"error":{"code":"InternalServerError","message":"no"}}`)
		default:
			fmt.Fprint(w, `{"properties":{"provisioningState":"Succeeded"}}`)
		}
	}))
	defer srv.Close()
	fast := policy.RetryOptions{MaxRetries: 1, RetryDelay: time.Millisecond, MaxRetryDelay: time.Millisecond}
	pl := runtime.NewPipeline("x", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{Retry: fast})
	s := &SDK{sub: dstSub, pl: pl, ep: srv.URL}
	_, err := s.Put(context.Background(), "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Foo/bars/b", "1", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "outcome is unknown") {
		t.Errorf("%v", err)
	}
}

// An operation that ended in failure is still a failure.
func TestFailedOperationStillFails(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut:
			w.Header().Set("Azure-AsyncOperation", srv.URL+"/op?api-version=1")
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(201)
			fmt.Fprint(w, `{"properties":{"provisioningState":"Creating"}}`)
		default:
			fmt.Fprint(w, `{"status":"Failed","error":{"code":"QuotaExceeded","message":"no"}}`)
		}
	}))
	defer srv.Close()
	pl := runtime.NewPipeline("x", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{Retry: retryOptions})
	s := &SDK{sub: dstSub, pl: pl, ep: srv.URL}
	if _, err := s.Put(context.Background(), "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Foo/bars/b", "1", map[string]any{}); err == nil || !strings.Contains(err.Error(), "QuotaExceeded") {
		t.Errorf("%v", err)
	}
}

func TestBusyWritesAreSentAgainAndOthersAreNot(t *testing.T) {
	old := busyWaits
	busyWaits = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { busyWaits = old }()
	for _, tc := range []struct {
		code      string
		wantPuts  int32
		wantError bool
	}{
		{"AnotherOperationInProgress", 3, true}, // refused every time, within its waits
		{"ConcurrentFederatedIdentityCredentialsWritesForSingleManagedIdentity", 3, true},
		{"Conflict", 1, true},
		{"StorageAccountAlreadyTaken", 1, true},
	} {
		var puts atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			puts.Add(1)
			w.WriteHeader(409)
			fmt.Fprintf(w, `{"error":{"code":%q,"message":"m"}}`, tc.code)
		}))
		pl := runtime.NewPipeline("x", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{Retry: retryOptions})
		s := &SDK{sub: dstSub, pl: pl, ep: srv.URL}
		_, err := s.Put(context.Background(), "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Foo/bars/b", "1", map[string]any{})
		if puts.Load() != tc.wantPuts || (err != nil) != tc.wantError {
			t.Errorf("%s: puts=%d err=%v", tc.code, puts.Load(), err)
		}
		srv.Close()
	}
}

// A type with its own word for finished held a restore for two hours.
func TestSettledDoesNotWaitOnAnUnknownState(t *testing.T) {
	for _, tc := range []struct {
		state string
		fails bool
	}{{"Succeeded", false}, {"", false}, {"Ready", false}, {"Pending", false}, {"Running", false}, {"Failed", true}, {"Canceled", true}, {"failed", true}, {"CreateFailed", true}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"properties":{"provisioningState":%q}}`, tc.state)
		}))
		pl := runtime.NewPipeline("x", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{Retry: retryOptions})
		s := &SDK{sub: dstSub, pl: pl, ep: srv.URL}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := s.settled(ctx, "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Foo/bars/b", "1")
		cancel()
		srv.Close()
		if (err != nil) != tc.fails || errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("state %q: %v", tc.state, err)
		}
	}
}

// The fake checked only top-level keys, so a nested field Azure would turn away,
// and a reference to nothing, read as restored.
func TestFakeRefusesWhatAzureWould(t *testing.T) {
	reg, _, dst := worlds(t)
	put(t, dst, "", groupType, "rg", map[string]any{"location": "eastus"})
	netID := id(dst.sub, "rg", vnetType, "v")
	version := stable(reg, "Microsoft.Storage/storageAccounts")
	account := func(props map[string]any) map[string]any {
		b := storageBody()
		b["properties"] = props
		return b
	}
	for name, props := range map[string]map[string]any{
		"has no property": {"notAProperty": true},
		"read-only":       {"creationTime": "2026-01-01T00:00:00Z"},
		"InvalidResourceReference": {"networkAcls": map[string]any{"defaultAction": "Deny", "virtualNetworkRules": []any{
			map[string]any{"id": netID + "/subnets/app"}}}},
	} {
		_, err := dst.Put(context.Background(), id(dst.sub, "rg", "Microsoft.Storage/storageAccounts", "st1"), version, account(props))
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
	put(t, dst, "rg", vnetType, "v", map[string]any{"location": "eastus", "properties": map[string]any{
		"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	if _, err := dst.Put(context.Background(), id(dst.sub, "rg", "Microsoft.Storage/storageAccounts", "st1"), version, account(map[string]any{
		"networkAcls": map[string]any{"defaultAction": "Deny", "virtualNetworkRules": []any{map[string]any{"id": netID + "/subnets/app"}}}})); err != nil {
		t.Errorf("a reference to a part of what exists: %v", err)
	}
}

// Seen on a real subscription: Azure's own Defender assignment has its ID in its
// display name. The snapshot named the real subscription, and a target's own copy
// of the assignment read as already existing and differing.
func TestSubscriptionInADisplayNameIsAPlaceholder(t *testing.T) {
	label := func(sub string, name string) string {
		spec := map[string]any{"properties": map[string]any{"displayName": name}}
		labelWithoutSubscription(spec, sub)
		return spec["properties"].(map[string]any)["displayName"].(string)
	}
	want := "ASC Default (subscription: " + tokSub + ")"
	for _, in := range []string{"ASC Default (subscription: " + srcSub + ")", "ASC Default (subscription: " + strings.ToUpper(srcSub) + ")"} {
		if got := label(srcSub, in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	if got := label(dstSub, "ASC Default (subscription: "+dstSub+")"); got != want {
		t.Errorf("two subscriptions' copies differ: %q", got)
	}
	if got := label(srcSub, "ASC Default (subscription: "+dstSub+")"); got == want {
		t.Errorf("another subscription's ID was taken for this one: %q", got)
	}
}

// A name like this one is the resource's own. Tokenized in its ID and not in its
// key, a clean restore made it under the target's ID, a diff read it as missing
// and extra, and --rename refused what the snapshot showed.
func TestDefaultWorkspaceKeepsItsName(t *testing.T) {
	reg, src, dst := worlds(t)
	name := "DefaultWorkspace-" + src.sub + "-EUS"
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, src, "rg", "Microsoft.OperationalInsights/workspaces", name, map[string]any{"location": "eastus"})
	snap := capture(t, src, reg)
	allApplied(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}))
	if got := dst.Stored(id(dst.sub, "rg", "Microsoft.OperationalInsights/workspaces", name)); got["location"] != "eastus" {
		t.Errorf("not restored under its own name: %v", got)
	}
	if ch := snapshot.Compare(snap, capture(t, dst, reg)); len(ch) != 0 {
		t.Errorf("second diff: %v", ch)
	}
}

// The refusal says to add the target to the role, and then to run again. With
// --update that run stored only the target, taking the role from the source.
func TestASharedRoleIsTakenAsItIsAndNeverNarrowed(t *testing.T) {
	reg := fixtures(t)
	w := NewWorld(reg)
	src, dst := w.Subscription(srcSub, srcTenant), w.Subscription(dstSub, srcTenant)
	typ := "Microsoft.Authorization/roleDefinitions"
	role := func(sub string, name string, scopes ...any) {
		// Seeded: the fake refuses naming another subscription, and a role's
		// scopes may.
		map[string]*Fake{srcSub: src, dstSub: dst}[sub].SeedAzure("/subscriptions/"+sub+"/providers/"+typ+"/"+customRoleID, stable(reg, typ), map[string]any{"properties": map[string]any{
			"roleName": name, "type": "CustomRole", "assignableScopes": scopes, "permissions": []any{map[string]any{"actions": []any{"*/read"}}}}})
	}
	role(srcSub, "shop-reader", "/subscriptions/"+srcSub)
	snap := capture(t, src, reg)
	both := []any{"/subscriptions/" + srcSub, "/subscriptions/" + dstSub}
	role(dstSub, "shop-reader", both...)
	i := "/subscriptions/" + dstSub + "/providers/" + typ + "/" + customRoleID
	for _, update := range []bool{false, true} {
		before := dst.Puts
		r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{Update: update}), customRoleID)
		if !r.OK || dst.Puts != before {
			t.Errorf("update=%v: ok=%v puts=%d %s", update, r.OK, dst.Puts-before, r.Detail)
		}
	}
	if got := dst.Stored(i)["properties"].(map[string]any)["assignableScopes"].([]any); len(got) != 2 {
		t.Errorf("scopes narrowed: %v", got)
	}
	// Any other difference would reach the source too, so not even --update.
	role(dstSub, "another-name", both...)
	before := dst.Puts
	r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{Update: true}), customRoleID)
	if r.OK || !strings.Contains(r.Detail, "shared with other subscriptions") || dst.Puts != before {
		t.Errorf("ok=%v puts=%d %s", r.OK, dst.Puts-before, r.Detail)
	}
	// A management group or the root is as shared as another subscription, with
	// nothing naming this subscription directly.
	for _, scope := range []string{"/", "/providers/Microsoft.Management/managementGroups/mg"} {
		for _, name := range []string{"shop-reader", "another-name"} {
			role(dstSub, name, scope)
			before := dst.Puts
			r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{Update: true}), customRoleID)
			if dst.Puts != before || r.OK != (name == "shop-reader") {
				t.Errorf("%s %s: ok=%v puts=%d %s", scope, name, r.OK, dst.Puts-before, r.Detail)
			}
		}
	}
	// A role only this subscription has, even at a narrower scope too, is an
	// ordinary update.
	role(dstSub, "another-name", "/subscriptions/"+dstSub, "/subscriptions/"+dstSub+"/resourceGroups/rg")
	if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{Update: true}), customRoleID); !r.OK || !strings.HasPrefix(r.Detail, "updated") {
		t.Errorf("own role: %s", r.Detail)
	}
}

// Stages. An identity restored earlier was "not in the snapshot" to a later grant,
// a network's peerings were dropped with every result fine, and so was everything
// on a typo.
func TestStagedRestore(t *testing.T) {
	reg, src, dst := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	ident := put(t, src, "rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "wid", map[string]any{"location": "eastus"})
	g := id(src.sub, "rg", groupType, "rg")
	g = "/subscriptions/" + src.sub + "/resourceGroups/rg"
	principal := src.Stored(ident)["properties"].(map[string]any)["principalId"]
	rawPut(t, src, g+"/providers/Microsoft.Authorization/roleAssignments/"+assignmentID, "Microsoft.Authorization/roleAssignments", map[string]any{"properties": map[string]any{
		"principalId": principal, "principalType": "ServicePrincipal", "roleDefinitionId": "/subscriptions/" + src.sub + "/providers/Microsoft.Authorization/roleDefinitions/" + builtInID}})
	put(t, src, "rg", vnetType, "hub", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	put(t, src, "rg", vnetType, "spoke", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.1.0.0/16"}}}})
	rawPut(t, src, id(src.sub, "rg", vnetType, "hub")+"/virtualNetworkPeerings/p", vnetType+"/virtualNetworkPeerings", map[string]any{"properties": map[string]any{
		"remoteVirtualNetwork": map[string]any{"id": id(src.sub, "rg", vnetType, "spoke")}}})
	snap := capture(t, src, reg)
	stage := func(types ...string) []snapshot.Result {
		return (&Adapter{API: dst, Registry: reg, Policy: Policy{Types: types}}).Restore(context.Background(), snap)
	}
	allApplied(t, stage("Microsoft.ManagedIdentity/*"))
	allApplied(t, stage("Microsoft.Authorization/roleAssignments"))
	rs := stage("Microsoft.Network/*")
	allApplied(t, rs)
	if resultFor(t, rs, "hub/p").Detail == "" {
		t.Error("a network's peering did not go with it")
	}
	// A lock in a stage would refuse the stages after it.
	g2 := "/subscriptions/" + src.sub + "/resourceGroups/rg"
	rawPut(t, src, g2+"/providers/Microsoft.Authorization/locks/ro", "Microsoft.Authorization/locks", map[string]any{"properties": map[string]any{"level": "ReadOnly"}})
	snap = capture(t, src, reg)
	if r := resultFor(t, stage("Microsoft.Authorization/*"), "locks"); r.OK {
		t.Errorf("a lock went on in a stage: %s", r.Detail)
	}
	if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "locks"); !r.OK {
		t.Errorf("a full run: %s", r.Detail)
	}
	if got := UnmatchedTypes(snap, []string{"Microsoft.Network/*", "Microsoft.Netwrk/*", "Microsoft.Resources/*"}); !slices.Equal(got, []string{"Microsoft.Netwrk/*", "Microsoft.Resources/*"}) {
		t.Errorf("unmatched: %v", got)
	}
}

// Once a kubenet cluster has attached its table, a re-run read the network as
// differing, and --update sent it without its routes.
func TestAttachedRouteTableIsKept(t *testing.T) {
	reg, src, dst := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	net := map[string]any{"location": "eastus", "tags": map[string]any{"t": "new"}, "properties": map[string]any{
		"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}},
		"subnets":      []any{map[string]any{"name": "a", "properties": map[string]any{"addressPrefix": "10.0.1.0/24"}}}}}
	put(t, src, "rg", vnetType, "v", net)
	snap := capture(t, src, reg)
	allApplied(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}))
	i := id(dst.sub, "rg", vnetType, "v")
	table := map[string]any{"id": id(dst.sub, "MC_x", "Microsoft.Network/routeTables", "rt")}
	attach := func(tags map[string]any) {
		b := dst.Stored(i)
		b["tags"] = tags
		b["properties"].(map[string]any)["subnets"].([]any)[0].(map[string]any)["properties"].(map[string]any)["routeTable"] = table
		dst.SeedAzure(i, stable(reg, vnetType), b)
	}
	attach(map[string]any{"t": "new"})
	if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "virtualNetworks"); r.Detail != "already present and identical" {
		t.Errorf("reads as differing: %s", r.Detail)
	}
	attach(map[string]any{"t": "old"})
	dst.CheckReferences = false // the table is the cluster's, in a group a fake has not made
	allApplied(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{Update: true}))
	got := dst.Stored(i)["properties"].(map[string]any)["subnets"].([]any)[0].(map[string]any)["properties"].(map[string]any)["routeTable"]
	if got == nil {
		t.Error("--update cut a subnet's route table")
	}
	// In a group the snapshot holds, someone attached it: a difference like any other.
	table = map[string]any{"id": id(dst.sub, "rg", "Microsoft.Network/routeTables", "by-hand")}
	attach(map[string]any{"t": "new"})
	if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "virtualNetworks"); r.OK {
		t.Errorf("a table attached by hand reads as identical: %s", r.Detail)
	}
}

// A cluster with a managed identity has no secret to give, and was reported
// restored without it, and refused --update.
func TestManagedIdentityClusterHasNoSecretToGive(t *testing.T) {
	reg, _, dst := worlds(t)
	put(t, dst, "", groupType, "rg", map[string]any{"location": "eastus"})
	ver := stable(reg, managedClusterType)
	o := obj(managedClusterType, "rg", "aks", "/subscriptions/"+tokSub+"/resourceGroups/rg/providers/"+managedClusterType+"/aks", map[string]any{"location": "eastus",
		"properties": map[string]any{"servicePrincipalProfile": map[string]any{"clientId": "msi"}}})
	ann := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	ann[annAPIVersion], ann[annSecrets] = ver, "properties.servicePrincipalProfile.secret"
	r := resultFor(t, Restore(context.Background(), dst, reg, snapshot.Snapshot{Objects: []snapshot.Object{o}}, RestoreOptions{}), "aks")
	if !r.OK || strings.Contains(r.Detail, "secret") {
		t.Errorf("ok=%v %s", r.OK, r.Detail)
	}
}

// A managerRef with no placeholder is a manager in another subscription, whose
// reason a current release wrote; only one that promises and has none is old.
func TestAnotherSubscriptionsManagerIsNotAnOldSnapshot(t *testing.T) {
	s := snapshot.Snapshot{Skips: []snapshot.Skip{{Resource: "r", Name: "n", Reason: reasonManagedGroup + "/subscriptions/" + srcSub + "/x" + mayNotRecreate}}}
	if PredatesManagedCheck(s) {
		t.Error("a fresh capture reads as not checked")
	}
}

// Through capture and restore, not only the helper: the snapshot holds no real
// subscription, and a target's own copy, with its own ID, reads as the same.
func TestDefenderAssignmentReadsAsTheSameOnATarget(t *testing.T) {
	reg, src, dst := worlds(t)
	typ := "Microsoft.Authorization/policyAssignments"
	seed := func(f *Fake) {
		f.SeedAzure("/subscriptions/"+f.sub+"/providers/"+typ+"/SecurityCenterBuiltIn", stable(reg, typ), map[string]any{"properties": map[string]any{
			"displayName": "ASC Default (subscription: " + f.sub + ")", "policyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/d"}})
	}
	seed(src)
	seed(dst)
	snap := capture(t, src, reg)
	if len(snap.Objects) == 0 {
		t.Fatal("nothing captured")
	}
	for _, o := range snap.Objects {
		if strings.Contains(canon(o.Body["spec"]), src.sub) {
			t.Errorf("names the subscription: %s", canon(o.Body["spec"]))
		}
	}
	if r := resultFor(t, Restore(context.Background(), dst, reg, snap, RestoreOptions{}), "SecurityCenterBuiltIn"); !r.OK || r.Detail != "already present and identical" {
		t.Errorf("a target's own copy: ok=%v %s", r.OK, r.Detail)
	}
}

// path.Match's * stops at a slash, so a pattern for a provider's types alone would
// drop their children, with every result reading as fine. Not peerings: Policy
// keeps those with their network whatever this does.
func TestChildrenGoWithTheirParentsType(t *testing.T) {
	const blob = "Microsoft.Storage/storageAccounts/blobServices/containers"
	if !selectedForRestore(blob, []string{"Microsoft.Storage/*"}) {
		t.Error("a child dropped by its parent's pattern")
	}
	if selectedForRestore(blob, []string{"Microsoft.Web/*"}) {
		t.Error("a child kept by another provider's pattern")
	}
	if selectedForRestore(blob, []string{"Microsoft.Storage/storageAccounts/fileServices"}) {
		t.Error("a child kept by a sibling's pattern")
	}
}

// PollUntilDone honoured a Retry-After, and asking sooner adds to what Azure asked
// to have less of.
func TestPollHonoursRetryAfter(t *testing.T) {
	oldEvery := pollEvery
	pollEvery = time.Millisecond
	defer func() { pollEvery = oldEvery }()
	var polls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut:
			w.Header().Set("Azure-AsyncOperation", srv.URL+"/op?api-version=1")
			w.WriteHeader(201)
			fmt.Fprint(w, `{"properties":{"provisioningState":"Creating"}}`)
		case strings.HasPrefix(r.URL.Path, "/op"):
			w.Header().Set("Retry-After", "1")
			st := "InProgress"
			if polls.Add(1) >= 2 {
				st = "Succeeded"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": st})
		default:
			fmt.Fprint(w, `{"properties":{"provisioningState":"Succeeded"}}`)
		}
	}))
	defer srv.Close()
	pl := runtime.NewPipeline("x", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{Retry: retryOptions})
	s := &SDK{sub: dstSub, pl: pl, ep: srv.URL}
	start := time.Now()
	if _, err := s.Put(context.Background(), "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Foo/bars/b", "1", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took < 900*time.Millisecond {
		t.Errorf("asked again after %v, with Retry-After 1", took)
	}
}

// Found by the first real drill: ARM returns peerings inline on the network and
// does not register them as a child type. Capture took them out of the network
// and read them nowhere else, so a restore lost them while the capture said it was
// complete. Here they exist only inline, as on a real subscription.
func TestPeeringsReturnedOnlyInlineAreCaptured(t *testing.T) {
	reg, src, dst := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	for _, n := range []string{"hub", "spoke"} {
		put(t, src, "rg", vnetType, n, map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	}
	hub := id(src.sub, "rg", vnetType, "hub")
	b := src.Stored(hub)
	b["properties"].(map[string]any)["virtualNetworkPeerings"] = []any{map[string]any{"name": "to-spoke", "id": hub + "/virtualNetworkPeerings/to-spoke",
		"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": id(src.sub, "rg", vnetType, "spoke")}, "allowVirtualNetworkAccess": true, "peeringState": "Connected"}}}
	src.SeedAzure(hub, stable(reg, vnetType), b)

	snap := capture(t, src, reg)
	found := false
	for _, o := range snap.Objects {
		found = found || (o.Kind() == vnetType+"/virtualNetworkPeerings" && o.Name() == "hub/to-spoke")
	}
	if !found {
		t.Fatalf("an inline peering was not captured: %v", snap.Objects)
	}
	rs := Restore(context.Background(), dst, reg, snap, RestoreOptions{})
	allApplied(t, rs)
	if got := dst.Stored(id(dst.sub, "rg", vnetType, "hub") + "/virtualNetworkPeerings/to-spoke"); got["properties"] == nil {
		t.Error("not restored")
	}
}

// With no definition to read them by, peerings are a gap, never dropped quietly.
func TestPeeringsWithNoDefinitionAreAGap(t *testing.T) {
	c := &captured{rid: ResourceID{Subscription: srcSub, ResourceGroup: "rg", Type: vnetType, Name: "hub"}, version: "1999-01-01",
		peerings: []any{map[string]any{"name": "p"}}}
	got, why := peeringsOf(nil, fixtures(t), srcTenant, c)
	if len(got) != 0 || !strings.Contains(why, "no definition") {
		t.Errorf("got %d, %q", len(got), why)
	}
}

// Through capture: the peerings are a gap the capture reports, so a scheduled job
// sees an incomplete capture rather than a network that lost them.
func TestPeeringsWithNoDefinitionMakeTheCaptureIncomplete(t *testing.T) {
	reg, src, _ := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, src, "rg", vnetType, "hub", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	hub := id(src.sub, "rg", vnetType, "hub")
	b := src.Stored(hub)
	b["properties"].(map[string]any)["virtualNetworkPeerings"] = []any{map[string]any{"name": "p", "properties": map[string]any{}}}
	src.SeedAzure(hub, stable(reg, vnetType), b)
	for k := range reg.index {
		if strings.HasPrefix(k, "microsoft.network/virtualnetworks/virtualnetworkpeerings@") {
			delete(reg.index, k)
		}
	}
	s := capture(t, src, reg)
	gap := false
	for _, sk := range s.Skips {
		gap = gap || (strings.HasPrefix(sk.Reason, Unreadable) && strings.Contains(sk.Reason, "peerings"))
	}
	if !gap {
		t.Errorf("peerings dropped without a gap: %v", s.Skips)
	}
}
