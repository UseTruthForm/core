package azarm

import (
	"context"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// What each resource in a real AKS node group carried, with what it was. Every
// skip said the cluster recreates it, so a storage account a StorageClass
// names, which it never would, was reported as safely skipped. Tags alone
// cannot tell: the first three the cluster made and the last two people did,
// and all of them have no tag of the cluster's.
func TestAKSMadeIsRecognisedNotAssumed(t *testing.T) {
	copiedDown := map[string]any{"CreatedBy": "x", "Environment": "x"}
	for _, tc := range []struct {
		typ  string
		tags map[string]any
		want bool
	}{
		{"Microsoft.Network/loadBalancers", nil, true},
		{"Microsoft.Network/virtualNetworks", copiedDown, true},
		{"Microsoft.ManagedIdentity/userAssignedIdentities", copiedDown, true},
		{"Microsoft.Storage/storageAccounts", nil, false},
		{"Microsoft.RecoveryServices/vaults", nil, false},

		{"Microsoft.Compute/virtualMachineScaleSets", map[string]any{"aks-managed-poolName": "x"}, true},
		{"Microsoft.Network/networkSecurityGroups", map[string]any{"aks-managed-cluster-name": "x"}, true},
		{"Microsoft.Network/publicIPAddresses", map[string]any{"aks-managed-type": "x"}, true},
		{"Microsoft.Network/publicIPAddresses", map[string]any{"k8s-azure-service": "x"}, true},
		// A static ingress IP is put there by hand, and has the cluster's tags
		// only if someone copied them.
		{"Microsoft.Network/publicIPAddresses", copiedDown, false},
		{"Microsoft.Compute/disks", map[string]any{"kubernetes.io-created-for-pvc-name": "x"}, true},
		{"Microsoft.Compute/disks", nil, false},
		{"Microsoft.Storage/storageAccounts", map[string]any{"k8s-azure-created-by": "x"}, true},
		{"Microsoft.Storage/storageAccounts", map[string]any{"K8S-Azure-Created-By": "x"}, true},
		{"Microsoft.Compute/virtualMachineScaleSets/extensions", nil, true},
		{"Microsoft.KeyVault/vaults", copiedDown, false},
		{"NotAType", nil, false},
	} {
		if got := aksMade(tc.typ, tc.tags); got != tc.want {
			t.Errorf("aksMade(%s, %v) = %v, want %v", tc.typ, tc.tags, got, tc.want)
		}
	}
}

const (
	nodeGroup = "MC_shop_aks_eastus"
	placedSA  = "placedvolumes01"
	madeSA    = "f0123456789abcdef"
)

// seedNodeGroup holds a cluster's node group with what the cluster made and
// what a person put there.
func seedNodeGroup(t *testing.T, f *Fake, manager string) {
	t.Helper()
	mc := put(t, f, "", groupType, nodeGroup, map[string]any{"location": "eastus"})
	f.ManagedBy[strings.ToLower(mc)] = manager
	put(t, f, nodeGroup, "Microsoft.Network/networkSecurityGroups", "aks-agentpool-nsg", map[string]any{"location": "eastus"})
	put(t, f, nodeGroup, "Microsoft.Storage/storageAccounts", madeSA, map[string]any{
		"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"},
		"tags": map[string]any{"k8s-azure-created-by": "azure"}})
	sa := put(t, f, nodeGroup, "Microsoft.Storage/storageAccounts", placedSA, map[string]any{
		"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"}})
	rawPut(t, f, sa+"/blobServices/default", "Microsoft.Storage/storageAccounts/blobServices", map[string]any{"properties": map[string]any{}})
	rawPut(t, f, sa+"/providers/Microsoft.Authorization/locks/keep", "Microsoft.Authorization/locks", map[string]any{
		"properties": map[string]any{"level": "CanNotDelete"}})
}

func captureNodeGroup(t *testing.T, manager string) (snapshot.Snapshot, *Fake) {
	t.Helper()
	reg := fixtures(t)
	w := NewWorld(reg)
	f := w.Subscription(srcSub, srcTenant)
	seedNodeGroup(t, f, strings.ReplaceAll(manager, "SUB", srcSub))
	s, err := (&Adapter{API: f, Registry: reg}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s, f
}

const clusterID = "/subscriptions/SUB/resourceGroups/shop-rg/providers/Microsoft.ContainerService/managedClusters/aks"

func TestPlacedInANodeGroupIsCapturedAndWaitsForTheCluster(t *testing.T) {
	s, _ := captureNodeGroup(t, clusterID)
	wantAfter := strings.ReplaceAll(clusterID, "SUB", tokSub)
	objs := map[string]snapshot.Object{}
	for _, o := range s.Objects {
		objs[o.Kind()+"|"+o.Name()] = o
	}
	for _, k := range []string{
		"Microsoft.Storage/storageAccounts|" + placedSA,
		"Microsoft.Storage/storageAccounts/blobServices|" + placedSA + "/default",
		// What is on it goes with it, as a lock on the cluster's own goes with theirs.
		"Microsoft.Authorization/locks|providers/Microsoft.Storage/storageAccounts/" + placedSA + "/providers/Microsoft.Authorization/locks/keep",
	} {
		o, ok := objs[k]
		if !ok {
			t.Errorf("not captured: %s; have %v", k, sortedKeys(objs))
			continue
		}
		ann := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		if ann[annAfter] != wantAfter {
			t.Errorf("%s: after %v, want the cluster, which creates its group", k, ann[annAfter])
		}
	}
	for _, k := range []string{"Microsoft.Storage/storageAccounts|" + madeSA, "Microsoft.Network/networkSecurityGroups|aks-agentpool-nsg"} {
		if _, ok := objs[k]; ok {
			t.Errorf("captured what the cluster made: %s", k)
		}
	}
	if got := KeptInManagedGroups(s); len(got) != 3 {
		t.Errorf("KeptInManagedGroups = %v, want what was kept, so a wrong guess can be seen", got)
	}
	for _, sk := range s.Skips {
		if MayNotComeBack(sk.Reason) {
			t.Errorf("%s %s reads as needing a look, though the cluster recreates it: %s", sk.Resource, sk.Name, sk.Reason)
		}
	}
}

// A manager other than AKS: nothing shows what it made and it may refuse a
// write to its group, so everything stays out, and is said to need a look.
func TestOtherManagersContentsAreLeftOutAndFlagged(t *testing.T) {
	s, _ := captureNodeGroup(t, "/subscriptions/SUB/resourceGroups/shop-rg/providers/Microsoft.OperationalInsights/workspaces/logs")
	for _, o := range s.Objects {
		if o.Namespace() == nodeGroup {
			t.Errorf("captured from another manager's group: %s", o.Key())
		}
	}
	flagged := map[string]bool{}
	for _, sk := range s.Skips {
		if MayNotComeBack(sk.Reason) {
			flagged[sk.Name] = true
		}
	}
	for _, name := range []string{nodeGroup + "/" + nodeGroup, nodeGroup + "/" + placedSA, nodeGroup + "/" + madeSA} {
		if !flagged[name] {
			t.Errorf("%s is not flagged; flagged %v", name, flagged)
		}
	}
}

// A managedBy of a VM says nothing of a disk's future: an OS disk returns with
// the VM, a data disk does not. Only what is known to return says so.
func TestManagedByPromisesOnlyWhatIsKnown(t *testing.T) {
	aks := strings.ReplaceAll(clusterID, "SUB", srcSub)
	vm := "/subscriptions/" + srcSub + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	for _, tc := range []struct {
		typ, by string
		want    bool
	}{
		{groupType, aks, true},
		{"Microsoft.Sql/servers/databases", "/subscriptions/" + srcSub + "/resourceGroups/rg/providers/Microsoft.Sql/servers/s", true},
		{"Microsoft.Compute/disks", vm, false},
		{groupType, "/subscriptions/" + srcSub + "/resourceGroups/rg/providers/Microsoft.Databricks/workspaces/w", false},
	} {
		if got := managerRecreates(tc.typ, tc.by); got != tc.want {
			t.Errorf("managerRecreates(%s, %s) = %v, want %v", tc.typ, tc.by, got, tc.want)
		}
	}
}

// coverage.yaml's reasons named the real subscription, in a snapshot whose
// promise is that it does not. The graph must read the new form and the form
// in snapshots already written, which keep the real ID.
func TestSkipReasonsNameNoSubscription(t *testing.T) {
	s, _ := captureNodeGroup(t, clusterID)
	dir := t.TempDir()
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	for _, sk := range s.Skips {
		if strings.Contains(sk.Reason, srcSub) {
			t.Errorf("%s %s: %s", sk.Resource, sk.Name, sk.Reason)
		}
	}
	want := "/subscriptions/" + tokSub + "/resourceGroups/shop-rg/providers/Microsoft.ContainerService/managedClusters/aks"
	for _, reason := range []string{
		reasonManagedGroup + want + ", which recreates it; its children and diagnostic settings are not read",
		reasonManagedGroup + want + mayNotRecreate + "; its children and diagnostic settings are not read",
		reasonManagedBy + want + mayNotRecreate,
	} {
		if got := skippedManagedBy(reason); got != want {
			t.Errorf("skippedManagedBy(%q) = %q", reason, got)
		}
	}
}

// Through the real restore, against the rule that a resource's group must
// exist: what was placed in a node group is refused until the manager has made
// the group. The fixtures have no AKS definition, so a plan stands in for the
// cluster, here making the group as the cluster would. Without the annotation
// this PUT sorts ahead of the plan and fails with no such group.
func TestPlacedRestoresAfterItsManager(t *testing.T) {
	s, _ := captureNodeGroup(t, clusterID)
	reg := fixtures(t)
	w := NewWorld(reg)
	dst := w.Subscription(dstSub, dstTenant)
	put(t, dst, "", groupType, "shop-rg", map[string]any{"location": "eastus"})

	manager := "/subscriptions/" + tokSub + "/resourceGroups/shop-rg/providers/Microsoft.Web/serverfarms/plan"
	body := map[string]any{"apiVersion": APIVersion, "kind": "Microsoft.Web/serverfarms", "metadata": map[string]any{
		"name": "plan", "namespace": "shop-rg", "annotations": map[string]any{annID: manager, annAPIVersion: stable(reg, "Microsoft.Web/serverfarms")}},
		"spec": map[string]any{"location": "eastus", "sku": map[string]any{"name": "F1", "tier": "Free"}}}
	var objs []snapshot.Object
	for _, o := range s.Objects {
		ann := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		if ann[annAfter] != nil {
			ann[annAfter] = manager
			objs = append(objs, o)
		}
	}
	if len(objs) == 0 {
		t.Fatal("nothing placed was captured")
	}
	s.Objects = append(objs, snapshot.Object{Body: body})
	dst.AfterCreate = func(id string, _ map[string]any) {
		if rid, _ := ParseID(id); rid.Type == "Microsoft.Web/serverfarms" {
			dst.SeedAzure("/subscriptions/"+dstSub+"/resourceGroups/"+nodeGroup, stable(reg, groupType), map[string]any{"location": "eastus"})
		}
	}
	for _, r := range (&Adapter{API: dst, Registry: reg}).Restore(context.Background(), s) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	sa := id(dstSub, nodeGroup, "Microsoft.Storage/storageAccounts", placedSA)
	if dst.Stored(sa)["kind"] != "StorageV2" {
		t.Errorf("the placed storage account did not come back: %v", dst.Stored(sa))
	}
}
