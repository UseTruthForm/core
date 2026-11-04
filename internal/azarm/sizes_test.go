package azarm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// A real restore's cluster was refused with AvailabilityZoneNotSupported, the
// region's supported zones given as none: its node size was
// NotAvailableForSubscription in the target, though the source had it. Nothing
// said so before the restore had run.
func TestASizeTheTargetCannotHaveIsSaid(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(dstSub, dstTenant)
	zones := func(z ...any) []any { return []any{map[string]any{"location": "eastus", "zones": z}} }
	f.SKUs = map[string][]map[string]any{"eastus": {
		{"name": "Standard_E4s_v3", "resourceType": "virtualMachines", "locationInfo": zones("1", "2", "3"), "restrictions": []any{
			map[string]any{"type": "Location", "reasonCode": "NotAvailableForSubscription"},
			map[string]any{"type": "Zone", "reasonCode": "NotAvailableForSubscription", "restrictionInfo": map[string]any{"zones": []any{"1", "2", "3"}}}}},
		{"name": "Standard_D2s_v5", "resourceType": "virtualMachines", "locationInfo": zones("1", "2", "3"), "restrictions": []any{
			map[string]any{"type": "Zone", "reasonCode": "NotAvailableForSubscription", "restrictionInfo": map[string]any{"zones": []any{"3", "1"}}}}},
		{"name": "Standard_D4s_v5", "resourceType": "virtualMachines", "locationInfo": zones("1", "2", "3")},
		// Offered in the region, in no zone: a pool pinned to zones is refused
		// AvailabilityZoneNotSupported all the same.
		{"name": "Standard_F2s_v2", "resourceType": "virtualMachines", "locationInfo": zones()},
		// A disk size of the same name is not a VM's.
		{"name": "Standard_E4s_v3", "resourceType": "disks"},
	}}
	sub := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/"
	pool := func(size string, z ...any) map[string]any {
		return map[string]any{"location": "East US", "properties": map[string]any{"agentPoolProfiles": []any{map[string]any{"name": "sys", "vmSize": size, "availabilityZones": z}}}}
	}
	vm := func(name, size string, z ...any) snapshot.Object {
		spec := map[string]any{"location": "eastus", "properties": map[string]any{"hardwareProfile": map[string]any{"vmSize": size}}}
		if z != nil {
			spec["zones"] = z
		}
		return obj("Microsoft.Compute/virtualMachines", "rg", name, sub+"Microsoft.Compute/virtualMachines/"+name, spec)
	}
	poolKind := managedClusterType + "/agentPools"
	s := snapshot.Snapshot{Objects: []snapshot.Object{
		obj(managedClusterType, "rg", "aks", sub+managedClusterType+"/aks", pool("Standard_E4s_v3")),
		obj(managedClusterType, "rg", "zoned", sub+managedClusterType+"/zoned", pool("Standard_F2s_v2", "1", "2", "3")),
		vm("vm", "Standard_D2s_v5", "1", "2"),
		vm("free", "Standard_D2s_v5"),
		vm("gone", "Standard_Retired"),
		obj("Microsoft.Compute/virtualMachineScaleSets", "rg", "ss", sub+"Microsoft.Compute/virtualMachineScaleSets/ss", map[string]any{
			"location": "eastus", "sku": map[string]any{"name": "Standard_D4s_v5"}}),
		// A pool read on its own has no region: it is its cluster's.
		obj(poolKind, "rg", "aks/extra", sub+managedClusterType+"/aks/agentPools/extra", map[string]any{"properties": map[string]any{"vmSize": "Standard_E4s_v3"}}),
		obj(poolKind, "rg", "elsewhere/p", sub+managedClusterType+"/elsewhere/agentPools/p", map[string]any{"properties": map[string]any{"vmSize": "Standard_D4s_v5"}}),
		obj("Microsoft.ServiceFabric/managedClusters/nodeTypes", "rg", "sf/nt", sub+"Microsoft.ServiceFabric/managedClusters/sf/nodeTypes/nt", map[string]any{
			"location": "eastus", "properties": map[string]any{"vmSize": "Standard_Retired"}}),
		obj("Microsoft.Batch/batchAccounts/pools", "rg", "b/p", sub+"Microsoft.Batch/batchAccounts/b/pools/p", map[string]any{
			"properties": map[string]any{"vmSize": "standard_d2s_v3"}}),
	}}
	c := SizesRefused(context.Background(), f, s, nil)
	got := strings.Join(c.Refused, "\n")
	for _, want := range []string{
		"Microsoft.ContainerService/managedClusters/rg/aks uses Standard_E4s_v3 in eastus, where this subscription cannot have it: Azure restricts it (NotAvailableForSubscription)",
		"--values (properties.agentPoolProfiles, the whole list)",
		"Microsoft.ContainerService/managedClusters/rg/zoned uses Standard_F2s_v2 in eastus, where this subscription cannot have it: it is asked for in zones 1, 2, 3, and offered in no zone there",
		"Microsoft.Compute/virtualMachines/rg/vm uses Standard_D2s_v5 in eastus, where this subscription cannot have it: it is asked for in zones 1, and offered only in zones 2",
		"Microsoft.Compute/virtualMachines/rg/gone uses Standard_Retired in eastus, where this subscription cannot have it: it is not offered there",
		"Microsoft.ContainerService/managedClusters/agentPools/rg/aks/extra uses Standard_E4s_v3 in eastus",
		"Microsoft.ServiceFabric/managedClusters/nodeTypes/rg/sf/nt uses Standard_Retired in eastus",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Standard_D4s_v5") || strings.Contains(got, "/free ") {
		t.Errorf("a size the target has is warned of:\n%s", got)
	}
	unchecked := strings.Join(c.NotChecked, "\n")
	for _, want := range []string{
		"Microsoft.ContainerService/managedClusters/agentPools/rg/elsewhere/p uses Standard_D4s_v5, and its region is not in the snapshot",
		"Microsoft.Batch/batchAccounts/pools/rg/b/p has a VM size at properties.vmSize, which is not checked",
	} {
		if !strings.Contains(unchecked, want) {
			t.Errorf("not said as unchecked: %q in:\n%s", want, unchecked)
		}
	}
	if c.Sizes != 8 || c.Regions != 1 {
		t.Errorf("checked %d sizes in %d regions, want 8 in 1", c.Sizes, c.Regions)
	}

	// Given another size with --values, as the restore was, the cluster is fine.
	vals := map[string]map[string]any{"Microsoft.ContainerService/managedClusters/rg/aks": pool("Standard_D4s_v5")}
	if got := strings.Join(SizesRefused(context.Background(), f, s, vals).Refused, "\n"); strings.Contains(got, "/rg/aks uses") {
		t.Errorf("an overridden size is still warned of:\n%s", got)
	}

	// A list that cannot be read is said, not a failure and not silence.
	f.ListError = func(path string) error {
		if strings.Contains(path, "Microsoft.Compute/skus") {
			return errors.New("AuthorizationFailed")
		}
		return nil
	}
	c = SizesRefused(context.Background(), f, s, nil)
	if got := strings.Join(c.NotChecked, "\n"); !strings.Contains(got, "cannot read the VM sizes offered in eastus, so 8 uses there were not checked") || !strings.Contains(got, "AuthorizationFailed") || len(c.Refused) != 0 || c.Regions != 0 {
		t.Errorf("an unreadable list: %+v", c)
	}
}
