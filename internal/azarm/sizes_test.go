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
	f.SKUs = map[string][]map[string]any{"eastus": {
		{"name": "Standard_E4s_v3", "resourceType": "virtualMachines", "restrictions": []any{
			map[string]any{"type": "Location", "reasonCode": "NotAvailableForSubscription"},
			map[string]any{"type": "Zone", "reasonCode": "NotAvailableForSubscription", "restrictionInfo": map[string]any{"zones": []any{"1", "2", "3"}}}}},
		{"name": "Standard_D2s_v5", "resourceType": "virtualMachines", "restrictions": []any{
			map[string]any{"type": "Zone", "reasonCode": "NotAvailableForSubscription", "restrictionInfo": map[string]any{"zones": []any{"3", "1"}}}}},
		{"name": "Standard_D4s_v5", "resourceType": "virtualMachines"},
		// A disk size of the same name is not a VM's.
		{"name": "Standard_E4s_v3", "resourceType": "disks"},
	}}
	sub := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/"
	pool := func(size string) map[string]any {
		return map[string]any{"location": "East US", "properties": map[string]any{"agentPoolProfiles": []any{map[string]any{"name": "sys", "vmSize": size}}}}
	}
	s := snapshot.Snapshot{Objects: []snapshot.Object{
		obj(managedClusterType, "rg", "aks", sub+managedClusterType+"/aks", pool("Standard_E4s_v3")),
		obj("Microsoft.Compute/virtualMachines", "rg", "vm", sub+"Microsoft.Compute/virtualMachines/vm", map[string]any{
			"location": "eastus", "properties": map[string]any{"hardwareProfile": map[string]any{"vmSize": "Standard_D2s_v5"}}}),
		obj("Microsoft.Compute/virtualMachineScaleSets", "rg", "ss", sub+"Microsoft.Compute/virtualMachineScaleSets/ss", map[string]any{
			"location": "eastus", "sku": map[string]any{"name": "Standard_D4s_v5"}}),
		obj("Microsoft.Compute/virtualMachines", "rg", "gone", sub+"Microsoft.Compute/virtualMachines/gone", map[string]any{
			"location": "eastus", "properties": map[string]any{"hardwareProfile": map[string]any{"vmSize": "Standard_Retired"}}}),
	}}
	got := strings.Join(SizesRefused(context.Background(), f, s, nil), "\n")
	for _, want := range []string{
		"Microsoft.ContainerService/managedClusters/rg/aks uses Standard_E4s_v3 in eastus, where this subscription cannot have it: Azure restricts it (NotAvailableForSubscription)",
		"--values (properties.agentPoolProfiles, the whole list)",
		"Microsoft.Compute/virtualMachines/rg/vm uses Standard_D2s_v5 in eastus, where this subscription cannot have it: Azure restricts it in zones 1, 3",
		"Microsoft.Compute/virtualMachines/rg/gone uses Standard_Retired in eastus, where this subscription cannot have it: it is not offered there",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Standard_D4s_v5") {
		t.Errorf("a size the target has is warned of:\n%s", got)
	}

	// Given another size with --values, as the restore was, the cluster is fine.
	vals := map[string]map[string]any{"Microsoft.ContainerService/managedClusters/rg/aks": pool("Standard_D4s_v5")}
	if got := strings.Join(SizesRefused(context.Background(), f, s, vals), "\n"); strings.Contains(got, "/aks") {
		t.Errorf("an overridden size is still warned of:\n%s", got)
	}

	// A list that cannot be read is said, not a failure and not silence.
	f.ListError = func(path string) error {
		if strings.Contains(path, "Microsoft.Compute/skus") {
			return errors.New("AuthorizationFailed")
		}
		return nil
	}
	if got := strings.Join(SizesRefused(context.Background(), f, s, nil), "\n"); !strings.Contains(got, "cannot read the VM sizes offered in eastus") || !strings.Contains(got, "AuthorizationFailed") {
		t.Errorf("an unreadable list: %q", got)
	}
}
