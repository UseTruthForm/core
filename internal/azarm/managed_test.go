package azarm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/usetruthform/core/internal/snapshot"
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
		if got := managerRecreates(tc.typ, "s/master", tc.by); got != tc.want {
			t.Errorf("managerRecreates(%s, %s) = %v, want %v", tc.typ, tc.by, got, tc.want)
		}
	}
	// Any other database with a managedBy is not known to return.
	if managerRecreates("Microsoft.Sql/servers/databases", "s/orders", vm) {
		t.Error("a database that is not master is promised back")
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
	// One at a time: in parallel, ignoring the annotation failed only some runs.
	for _, r := range restoreWith(context.Background(), dst, reg, s, RestoreOptions{}, 1) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	sa := id(dstSub, nodeGroup, "Microsoft.Storage/storageAccounts", placedSA)
	if dst.Stored(sa)["kind"] != "StorageV2" {
		t.Errorf("the placed storage account did not come back: %v", dst.Stored(sa))
	}
}

// A lock on what the cluster made was said to come back with it. A person's lock
// does not, and the same is true of one on what another manager holds.
func TestExtensionsOnWhatIsLeftOutAreFlagged(t *testing.T) {
	for name, manager := range map[string]string{"aks": clusterID, "other": "/subscriptions/SUB/resourceGroups/shop-rg/providers/Microsoft.OperationalInsights/workspaces/logs"} {
		reg := fixtures(t)
		f := NewWorld(reg).Subscription(srcSub, srcTenant)
		seedNodeGroup(t, f, strings.ReplaceAll(manager, "SUB", srcSub))
		nsg := id(f.sub, nodeGroup, "Microsoft.Network/networkSecurityGroups", "aks-agentpool-nsg")
		rawPut(t, f, nsg+"/providers/Microsoft.Authorization/locks/mine", "Microsoft.Authorization/locks", map[string]any{"properties": map[string]any{"level": "CanNotDelete"}})
		s, err := Capture(context.Background(), f, reg, Policy{})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, sk := range s.Skips {
			if strings.HasSuffix(sk.Name, "locks/mine") {
				found = MayNotComeBack(sk.Reason)
			}
		}
		if !found {
			t.Errorf("%s: a lock on what is left out is not flagged: %v", name, s.Skips)
		}
	}
}

// A cluster naming a resource in its own group: the resource would wait for the
// cluster and the cluster for it, and all behind them read as a cycle.
func TestWhatTheManagerNamesIsNotKept(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	seedNodeGroup(t, f, strings.ReplaceAll(clusterID, "SUB", srcSub))
	sa := id(f.sub, nodeGroup, "Microsoft.Storage/storageAccounts", placedSA)
	f.SeedAzure(id(f.sub, "shop-rg", managedClusterType, "aks"), stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
		"networkProfile": map[string]any{"loadBalancerProfile": map[string]any{"outboundIPs": map[string]any{"publicIPs": []any{map[string]any{"id": sa}}}}}}})
	s, err := Capture(context.Background(), f, reg, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, cyclic := restoreOrder(s.Objects); len(cyclic) != 0 {
		t.Errorf("cycle: %v", cyclic)
	}
	for _, o := range s.Objects {
		if o.Kind() == "Microsoft.Storage/storageAccounts" && o.Name() == placedSA {
			t.Error("kept what its manager names")
		}
	}
	flagged := false
	for _, sk := range s.Skips {
		flagged = flagged || (strings.HasSuffix(sk.Name, placedSA) && MayNotComeBack(sk.Reason))
	}
	if !flagged {
		t.Errorf("left out without a word: %v", s.Skips)
	}
}

// A link to a kept resource was moved out as if the manager makes a new one, so
// a restore left it off without a word. A link to what is not kept still goes.
func TestLinkToAKeptResourceStays(t *testing.T) {
	sub := "/subscriptions/" + srcSub
	inGroup := sub + "/resourceGroups/" + nodeGroup + "/providers/Microsoft.Storage/storageAccounts/"
	c := &captured{status: map[string]any{}, spec: map[string]any{
		"kept": map[string]any{"resourceId": inGroup + "placed"},
		"gone": map[string]any{"resourceId": inGroup + "made"},
	}}
	got := withoutManaged(c, map[string]string{strings.ToLower(nodeGroup): "m"}, func(id string) bool { return strings.HasSuffix(id, "placed") })
	if _, ok := got["kept"]; !ok {
		t.Errorf("a link to a kept resource was dropped: %v", got)
	}
	if _, ok := got["gone"]; ok {
		t.Errorf("a link to what is not kept stayed: %v", got)
	}
}

// In the capture itself, not only in the helper.
func TestCaptureMovesAClusterLinkToWhatItMade(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	seedNodeGroup(t, f, strings.ReplaceAll(clusterID, "SUB", srcSub))
	kubelet := id(f.sub, nodeGroup, "Microsoft.ManagedIdentity/userAssignedIdentities", "aks-agentpool")
	put(t, f, nodeGroup, "Microsoft.ManagedIdentity/userAssignedIdentities", "aks-agentpool", map[string]any{"location": "eastus"})
	f.SeedAzure(id(f.sub, "shop-rg", managedClusterType, "aks"), stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
		"identityProfile": map[string]any{"kubeletidentity": map[string]any{"resourceId": kubelet}}}})
	s, err := Capture(context.Background(), f, reg, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range s.Objects {
		if o.Kind() == managedClusterType && strings.Contains(canon(o.Body["spec"]), "aks-agentpool") {
			t.Errorf("the cluster names what it makes: %s", canon(o.Body["spec"]))
		}
	}
}

type failsReads struct {
	*Fake
	match string
}

func (f failsReads) Get(ctx context.Context, i, v string) (map[string]any, error) {
	if strings.Contains(i, f.match) {
		return nil, errors.New("GET https://management.azure.com/subscriptions/" + srcSub + "/x: 403 AuthorizationFailed")
	}
	return f.Fake.Get(ctx, i, v)
}

// An error from ARM holds its URL, and so its subscription.
func TestUnreadableReasonNamesNoSubscription(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	seedNodeGroup(t, f, strings.ReplaceAll(clusterID, "SUB", srcSub))
	s, err := Capture(context.Background(), failsReads{f, placedSA}, reg, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	unreadable := false
	for _, sk := range s.Skips {
		unreadable = unreadable || strings.HasPrefix(sk.Reason, Unreadable)
		if strings.Contains(sk.Reason+sk.Name, srcSub) {
			t.Errorf("%s: %s", sk.Name, sk.Reason)
		}
	}
	if !unreadable {
		t.Errorf("the control read nothing as failed: %v", s.Skips)
	}
	dir := t.TempDir()
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
}

// Tags come from the real listing's JSON; the fake hands them over directly, so
// dropping them in sdk.go passed everything.
func TestListingReadsTags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{map[string]any{"id": "/x", "type": "t", "tags": map[string]any{"aks-managed-type": "y", "odd": 1}}}})
	}))
	defer srv.Close()
	pl := runtime.NewPipeline("x", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{Retry: retryOptions})
	s := &SDK{sub: dstSub, pl: pl, ep: srv.URL}
	got, err := s.Resources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Tags["aks-managed-type"] != "y" {
		t.Errorf("%s", fmt.Sprint(got))
	}
}

// Without this, not having looked reads as all clear.
func TestOldSnapshotsSayTheyPredateTheCheck(t *testing.T) {
	old := snapshot.Snapshot{Skips: []snapshot.Skip{{Resource: "r", Name: "n", Reason: reasonManagedGroup + "/subscriptions/" + srcSub + "/x, which recreates it"}}}
	if !PredatesManagedCheck(old) {
		t.Error("an old snapshot reads as checked")
	}
	current := snapshot.Snapshot{Skips: []snapshot.Skip{{Resource: "r", Name: "n", Reason: reasonManagedGroup + "/subscriptions/" + tokSub + "/x, which recreates it"}}}
	if PredatesManagedCheck(current) {
		t.Error("a current snapshot reads as old")
	}
	if PredatesManagedCheck(snapshot.Snapshot{Skips: []snapshot.Skip{{Resource: "r", Name: "n", Reason: "identical to the baseline"}}}) {
		t.Error("a snapshot with no managed skip reads as old")
	}
}

// A volume's disk has the managedBy of the VM it is on, and the cluster makes it.
// A disk with no sign of that may be someone's, and does not come back.
func TestDiskInANodeGroupGoesByItsTags(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	seedNodeGroup(t, f, strings.ReplaceAll(clusterID, "SUB", srcSub))
	vm := id(f.sub, nodeGroup, "Microsoft.Compute/virtualMachines", "node")
	for name, tags := range map[string]map[string]any{"volume": {"kubernetes.io-created-for-pvc-name": "x"}, "someones": nil} {
		i := id(f.sub, nodeGroup, "Microsoft.Compute/disks", name)
		f.SeedAzure(i, "2024-01-01", map[string]any{"location": "eastus", "tags": tags})
		f.ManagedBy[strings.ToLower(i)] = vm
	}
	s, err := Capture(context.Background(), f, reg, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	flagged := map[string]bool{}
	for _, sk := range s.Skips {
		flagged[sk.Name] = MayNotComeBack(sk.Reason)
	}
	if flagged[nodeGroup+"/volume"] {
		t.Error("what the cluster makes is flagged")
	}
	if !flagged[nodeGroup+"/someones"] {
		t.Errorf("a disk that may be someone's reads as coming back: %v", s.Skips)
	}
}

// On a real estate a core network was peered both ways with the cluster's
// network in its node group. The cluster's network is skipped as the cluster's,
// and its half of the pair went with it, unlisted, while the capture said it was
// complete. Read for its peerings, it keeps them, and the report says both halves
// depend on the cluster's network.
func TestPeeringOnAClustersNetworkIsKept(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	seedNodeGroup(t, f, strings.ReplaceAll(clusterID, "SUB", srcSub))
	net := map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}}
	core := put(t, f, "shop-rg", vnetType, "core", net)
	aks := put(t, f, nodeGroup, vnetType, "aks-vnet-1", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.1.0.0/16"}}}})
	peer := vnetType + "/virtualNetworkPeerings"
	rawPut(t, f, core+"/virtualNetworkPeerings/to-aks", peer, map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": aks}}})
	rawPut(t, f, aks+"/virtualNetworkPeerings/to-core", peer, map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": core}}})

	s, err := Capture(context.Background(), f, reg, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]snapshot.Object{}
	for _, o := range s.Objects {
		got[o.Kind()+"|"+o.Name()] = o
	}
	if _, ok := got[vnetType+"|aks-vnet-1"]; ok {
		t.Error("the cluster's network was captured")
	}
	back, ok := got[peer+"|aks-vnet-1/to-core"]
	if !ok {
		t.Fatalf("the cluster's half of the peering was lost: %v", sortedKeys(got))
	}
	if annotation(back, annAfter) == nil {
		t.Error("it does not wait for the cluster, which makes its network")
	}
	if _, ok := got[peer+"|core/to-aks"]; !ok {
		t.Error("the core half was lost")
	}
	across := PeeringsAcrossManagedGroups(s)
	if len(across) != 2 {
		t.Errorf("report lists %v, want both halves", across)
	}
}

// Every way a network is left out as something else's, it keeps its peerings: a
// managedBy of its own, another manager's group, and one the cluster names.
func TestPeeringsSurviveEveryManagedSkip(t *testing.T) {
	for name, setup := range map[string]func(f *Fake, reg *Registry, aks string){
		"own managedBy": func(f *Fake, _ *Registry, aks string) {
			f.ManagedBy[strings.ToLower(aks)] = id(f.sub, "shop-rg", "Microsoft.Network/virtualNetworkGateways", "gw")
		},
		"named by the cluster": func(f *Fake, reg *Registry, aks string) {
			f.SeedAzure(id(f.sub, "shop-rg", managedClusterType, "aks"), stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
				"networkProfile": map[string]any{"loadBalancerProfile": map[string]any{"outboundIPs": map[string]any{"publicIPs": []any{map[string]any{"id": aks}}}}}}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			reg := fixtures(t)
			f := NewWorld(reg).Subscription(srcSub, srcTenant)
			put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
			seedNodeGroup(t, f, strings.ReplaceAll(clusterID, "SUB", srcSub))
			core := put(t, f, "shop-rg", vnetType, "core", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
			aks := put(t, f, nodeGroup, vnetType, "aks-vnet-1", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.1.0.0/16"}}}})
			rawPut(t, f, aks+"/virtualNetworkPeerings/to-core", vnetType+"/virtualNetworkPeerings", map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": core}}})
			setup(f, reg, aks)
			s, err := Capture(context.Background(), f, reg, Policy{})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, o := range s.Objects {
				found = found || o.Name() == "aks-vnet-1/to-core"
				if o.Kind() == vnetType && o.Name() == "aks-vnet-1" {
					t.Error("the managed network was captured")
				}
			}
			if !found {
				t.Errorf("its peering was lost: %v", s.Skips)
			}
		})
	}
	t.Run("another manager's group", func(t *testing.T) {
		reg := fixtures(t)
		f := NewWorld(reg).Subscription(srcSub, srcTenant)
		put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
		seedNodeGroup(t, f, "/subscriptions/"+srcSub+"/resourceGroups/shop-rg/providers/Microsoft.Databricks/workspaces/w")
		core := put(t, f, "shop-rg", vnetType, "core", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
		v := put(t, f, nodeGroup, vnetType, "workers", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.1.0.0/16"}}}})
		rawPut(t, f, v+"/virtualNetworkPeerings/to-core", vnetType+"/virtualNetworkPeerings", map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": core}}})
		s, err := Capture(context.Background(), f, reg, Policy{})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, o := range s.Objects {
			found = found || o.Name() == "workers/to-core"
		}
		if !found {
			t.Errorf("its peering was lost: %v", s.Skips)
		}
	})
}
