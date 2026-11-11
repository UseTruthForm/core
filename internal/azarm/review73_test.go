package azarm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// clusterWithNodeGroup seeds a cluster whose node group is "Nodes" (spelled so
// the group's IDs, in lower case, differ), its kubelet identity there, an AKS
// network there, and a hub network peered to it.
func clusterWithNodeGroup(t *testing.T, src *Fake, reg *Registry) {
	t.Helper()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	cluster := id(srcSub, "rg", managedClusterType, "aks")
	nodes := "/subscriptions/" + srcSub + "/resourceGroups/nodes"
	src.SeedAzure(nodes, stable(reg, groupType), map[string]any{"location": "eastus"})
	src.ManagedBy[strings.ToLower(nodes)] = cluster
	src.SeedAzure(nodes+"/providers/Microsoft.Network/virtualNetworks/aks-vnet", stable(reg, vnetType), map[string]any{"location": "eastus", "tags": map[string]any{"aks-managed-cluster-name": "aks"}, "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.224.0.0/12"}}}})
	kubelet := nodes + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-agentpool"
	src.SeedAzure(kubelet, stable(reg, "Microsoft.ManagedIdentity/userAssignedIdentities"), map[string]any{"location": "eastus"})
	src.SeedAzure(cluster, stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
		"dnsPrefix": "aks", "nodeResourceGroup": "Nodes",
		"identityProfile":   map[string]any{"kubeletidentity": map[string]any{"resourceId": kubelet}},
		"agentPoolProfiles": []any{map[string]any{"name": "sys", "mode": "System", "count": 1, "vmSize": "Standard_D2s_v5"}}}})
	hub := put(t, src, "rg", vnetType, "hub", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	src.SeedAzure(hub+"/virtualNetworkPeerings/to-aks", stable(reg, "Microsoft.Network/virtualNetworks/virtualNetworkPeerings"), map[string]any{"properties": map[string]any{
		"remoteVirtualNetwork": map[string]any{"id": nodes + "/providers/Microsoft.Network/virtualNetworks/aks-vnet"}}})
}

// Re-review of #73: with --capture-managed the kubelet identity, in the node
// group and named by the cluster, and the cluster each waited for the other,
// and both were refused with all behind them. The node group is spelled in
// another case on the cluster than in the IDs, as Azure may.
func TestACapturedNodeGroupMakesNoCycle(t *testing.T) {
	for _, managed := range []bool{false, true} {
		reg, src, _ := worlds(t)
		clusterWithNodeGroup(t, src, reg)
		snap, err := Capture(context.Background(), src, reg, Policy{CaptureManaged: managed})
		if err != nil {
			t.Fatal(err)
		}
		order, cyclic, depIdx := restoreGraph(snap.Objects)
		if len(cyclic) != 0 {
			t.Errorf("--capture-managed %v: cycle: %v", managed, cyclic)
			continue
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
			t.Errorf("--capture-managed %v: the peering to the cluster's network does not wait for the cluster", managed)
		}
	}
}

// A --values entry holding the target subscription's own ID is compared in the
// snapshot's form, or every run after reads it as changed.
func TestValuesWithTheTargetsIDsAreComparedInTheSnapshotsForm(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	snap := capture(t, src, reg)
	vals := map[string]map[string]any{groupType + "/rg": {"tags": map[string]any{"home": "/subscriptions/" + dst.sub + "/resourceGroups/rg"}}}
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{Values: vals}), "|rg"); !r.OK {
		t.Fatalf("first run: %s", r.Detail)
	}
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{Values: vals}), "|rg"); !r.OK || !strings.Contains(r.Detail, "identical") {
		t.Errorf("a resumed run reads the given ID as changed: %v %s", r.OK, r.Detail)
	}
}

// A grant refused as RoleAssignmentExists counts only when the one there can be
// read and matches in what the code does not promise (re-review of #73).
func TestAGrantAlreadyThereIsReadAndCompared(t *testing.T) {
	want := map[string]any{"properties": map[string]any{"condition": "@Resource[x] StringEquals 'a'", "conditionVersion": "2.0", "description": "d", "delegatedManagedIdentityResourceId": "/subscriptions/S/rg/x"}}
	if d := grantDiffers(want, deepCopy(want)); len(d) != 0 {
		t.Errorf("the same grant differs: %v", d)
	}
	for field, other := range map[string]any{
		"condition":                          "@Resource[x] StringEquals 'A'",
		"conditionVersion":                   "1.0",
		"description":                        "e",
		"delegatedManagedIdentityResourceId": "/subscriptions/S/rg/y",
	} {
		got := deepCopy(want)
		got["properties"].(map[string]any)[field] = other
		if d := grantDiffers(want, got); len(d) != 1 || d[0] != field {
			t.Errorf("%s differs, said: %v", field, d)
		}
	}
	got := deepCopy(want)
	got["properties"].(map[string]any)["delegatedManagedIdentityResourceId"] = "/SUBSCRIPTIONS/S/RG/X"
	if d := grantDiffers(want, got); len(d) != 0 {
		t.Errorf("an ID in other case differs: %v", d)
	}
	for msg, name := range map[string]string{
		"The ID of the existing role assignment is 3333444455554666877788889999aaaa.":     "33334444-5555-4666-8777-88889999aaaa",
		"The role assignment already exists.":                                             "",
		"The ID of the existing role assignment is 3333444455554666877788889999.":         "",
		"The ID of the existing role assignment is 3333444455554666877788889999aaaaabcd.": "",
	} {
		if got := existingAssignment(msg); got != name {
			t.Errorf("existingAssignment(%q) = %q, want %q", msg, got, name)
		}
	}

	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, src, "rg", "Microsoft.Authorization/roleAssignments", "11111111-1111-1111-1111-111111111111", map[string]any{"properties": map[string]any{
		"principalId": "22222222-2222-2222-2222-222222222222", "principalType": "ServicePrincipal",
		"roleDefinitionId": "/subscriptions/" + src.sub + "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"}})
	snap := capture(t, src, reg)
	for msg, why := range map[string]string{
		// Named, and not there to read.
		"RoleAssignmentExists: The ID of the existing role assignment is 3333444455554666877788889999aaaa.": "cannot be read",
		// Not named.
		"RoleAssignmentExists: The role assignment already exists.": "RoleAssignmentExists",
	} {
		dst.PutError = func(id string, body map[string]any) error {
			if strings.Contains(id, "/roleAssignments/") {
				return errors.New(msg)
			}
			return nil
		}
		if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{}), "roleAssignments|rg|1111"); r.OK || !strings.Contains(r.Detail, why) {
			t.Errorf("%q: %v %s", msg, r.OK, r.Detail)
		}
	}
}

// A table Azure defines is sent as AzureDiagnostics is: not its read-only
// flags, not a retention inherited from the workspace. Search results (_SRCH)
// and restored logs (_RST), like custom tables (_CL), keep their schema.
func TestTablesAzureDefinesAndOthers(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	w := put(t, src, "rg", "Microsoft.OperationalInsights/workspaces", "law", map[string]any{"location": "eastus"})
	for _, n := range []string{"ContainerLogV2", "Hunt_SRCH", "Old_RST"} {
		src.SeedAzure(w+"/tables/"+n, stable(reg, tablesType), map[string]any{"properties": map[string]any{
			"retentionInDays": 30, "retentionInDaysAsDefault": true, "totalRetentionInDays": 365, "totalRetentionInDaysAsDefault": false, "plan": "Analytics",
			"schema": map[string]any{"name": n, "columns": []any{map[string]any{"name": "Kept", "type": "string"}}}}})
	}
	snap := capture(t, src, reg)
	for _, o := range snap.Objects {
		spec := canon(o.Body["spec"])
		switch o.Name() {
		case "law/Hunt_SRCH", "law/Old_RST":
			if !strings.Contains(spec, `"Kept"`) {
				t.Errorf("%s lost its schema: %s", o.Name(), spec)
			}
		case "law/ContainerLogV2":
			if strings.Contains(spec, `"Kept"`) {
				t.Errorf("Azure's table kept its schema: %s", spec)
			}
		}
	}
	var body string
	dst.PutError = func(id string, b map[string]any) error {
		if strings.HasSuffix(id, "/tables/ContainerLogV2") {
			body = canon(b)
		}
		return nil
	}
	put(t, dst, "", groupType, "rg", map[string]any{"location": "eastus"})
	Restore(ctx, dst, reg, snapshot.Snapshot{Platform: snap.Platform, Objects: snap.Objects}, RestoreOptions{})
	if body == "" || strings.Contains(body, "AsDefault") || strings.Contains(body, `"retentionInDays"`) || !strings.Contains(body, `"totalRetentionInDays":365`) {
		t.Errorf("Azure's table sent as: %s", body)
	}
}

// A --values key that matches nothing was ignored, and the restore said
// "created" with the snapshot's value (re-review of #73).
func TestAValuesKeyThatMatchesNothingIsSaid(t *testing.T) {
	reg, src, _ := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	put(t, src, "rg", "Microsoft.Network/virtualNetworks", "net", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	snap := capture(t, src, reg)
	got := UnmatchedValues(snap, map[string]map[string]any{
		"Microsoft.Network/virtualNetworks/rg/net":  {},
		"Microsoft.Resources/resourceGroups/rg":     {},
		"microsoft.network/virtualnetworks/rg/net":  {},
		"Microsoft.Network/virtualNetworks/rg/gone": {},
	})
	want := []string{"Microsoft.Network/virtualNetworks/rg/gone", "microsoft.network/virtualnetworks/rg/net (the snapshot has Microsoft.Network/virtualNetworks/rg/net)"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("UnmatchedValues = %q, want %q", got, want)
	}
}

// Third review of #73: the cluster waits for what its identity is granted, and
// a grant to that identity (user-assigned, as the ones it waits for are)
// scoped at the node group named the node group, so it
// also waited for the cluster: a cycle. Through a capture, with the cluster's
// identity tokenized in the grant as it is in a real snapshot.
func TestAGrantToTheClustersIdentityAtItsNodeGroupMakesNoCycle(t *testing.T) {
	reg, src, _ := worlds(t)
	clusterWithNodeGroup(t, src, reg)
	cluster := id(srcSub, "rg", managedClusterType, "aks")
	nodes := "/subscriptions/" + srcSub + "/resourceGroups/nodes"
	cp := id(srcSub, "rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "cp")
	src.SeedAzure(cp, stable(reg, "Microsoft.ManagedIdentity/userAssignedIdentities"), map[string]any{"location": "eastus", "properties": map[string]any{"principalId": "33333333-3333-3333-3333-333333333333", "tenantId": "tenant"}})
	b, _ := src.Get(context.Background(), cluster, stable(reg, managedClusterType))
	b["identity"] = map[string]any{"type": "UserAssigned", "userAssignedIdentities": map[string]any{cp: map[string]any{}}}
	src.SeedAzure(cluster, stable(reg, managedClusterType), b)
	src.SeedAzure(nodes+"/providers/Microsoft.Authorization/roleAssignments/44444444-4444-4444-4444-444444444444", stable(reg, "Microsoft.Authorization/roleAssignments"), map[string]any{"properties": map[string]any{
		"principalId": "33333333-3333-3333-3333-333333333333", "principalType": "ServicePrincipal", "scope": nodes,
		"roleDefinitionId": "/subscriptions/" + srcSub + "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"}})
	snap, err := Capture(context.Background(), src, reg, Policy{CaptureManaged: true})
	if err != nil {
		t.Fatal(err)
	}
	var grant snapshot.Object
	for _, o := range snap.Objects {
		if strings.HasSuffix(o.Name(), "44444444-4444-4444-4444-444444444444") {
			grant = o
		}
	}
	if grant.Body == nil || !strings.Contains(canon(grant.Body["spec"]), "userAssignedIdentities|rg|cp|properties.principalId") {
		t.Fatalf("the grant to the cluster's identity is not captured as a ref: %v", grant.Body)
	}
	// Capture keeps a grant's scope out of its spec (it is read-only), so a
	// real capture does not name the node group here; a snapshot that holds it
	// (written by hand, or by another tool) does, as the review's did.
	grant.Body["spec"].(map[string]any)["properties"].(map[string]any)["scope"] = "/subscriptions/" + tokSub + "/resourceGroups/nodes"
	order, cyclic, depIdx := restoreGraph(snap.Objects)
	if len(cyclic) != 0 {
		t.Fatalf("cycle: %v", cyclic)
	}
	for i, o := range order {
		if o.Kind() == managedClusterType {
			waits := false
			for _, j := range depIdx[i] {
				waits = waits || strings.HasSuffix(order[j].Name(), "44444444-4444-4444-4444-444444444444")
			}
			if !waits {
				t.Error("the cluster no longer waits for its identity's grant")
			}
		}
	}
}
