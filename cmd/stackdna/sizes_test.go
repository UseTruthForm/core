package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/azarm"
	"github.com/stackdna/core/internal/snapshot"
)

// A real restore's cluster was refused because the target could not have its
// node size, after the rest of the restore had run. diff and restore say so
// first.
func TestDiffAndRestoreSayASizeTheTargetCannotHave(t *testing.T) {
	reg, err := azarm.LoadDefinitions(leaveDefs)
	if err != nil {
		t.Fatal(err)
	}
	w := azarm.NewWorld(reg)
	src, dst := w.Subscription(leaveSrc, "tenant"), w.Subscription(leaveDst, "tenant")
	ctx := context.Background()
	rg := "/subscriptions/" + leaveSrc + "/resourceGroups/rg"
	if _, err := src.Put(ctx, rg, reg.Versions("Microsoft.Resources/resourceGroups")[0], map[string]any{"location": "eastus"}); err != nil {
		t.Fatal(err)
	}
	vm := "Microsoft.Compute/virtualMachines"
	src.SeedAzure(rg+"/providers/"+vm+"/vm", reg.Versions(vm)[0], map[string]any{"location": "eastus", "properties": map[string]any{"hardwareProfile": map[string]any{"vmSize": "Standard_Old_v1"}}})
	s, err := (&azarm.Adapter{API: src, Registry: reg}).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "snap")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	dst.SKUs = map[string][]map[string]any{"eastus": {{"name": "Standard_Old_v1", "resourceType": "virtualMachines", "restrictions": []any{
		map[string]any{"type": "Location", "reasonCode": "NotAvailableForSubscription"}}}}}
	old := azureAPI
	azureAPI = func(sub string, readOnly bool) (azarm.ARM, error) {
		if sub != leaveDst {
			return nil, errors.New("only the fake target")
		}
		if readOnly {
			return readOnlyFake{dst}, nil
		}
		return dst, nil
	}
	defer func() { azureAPI = old }()
	target := []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir}
	want := "Microsoft.Compute/virtualMachines/rg/vm uses Standard_Old_v1 in eastus, where this subscription cannot have it"
	if _, _, errOut := output(t, func() int { return diff(ctx, target) }); !strings.Contains(errOut, "WARNING: 1 VM sizes") || !strings.Contains(errOut, want) {
		t.Errorf("diff does not say it:\n%s", errOut)
	}
	if captureOnly {
		return // restore is refused in the capture-only build
	}
	if _, _, errOut := output(t, func() int { return restore(ctx, target) }); !strings.Contains(errOut, want) {
		t.Errorf("restore does not say it:\n%s", errOut)
	}
}

// A snapshot from before a fix holds what the fix took out. The first nightly
// after one compared it with a capture that does not, and reported every
// cluster's extensionManager add-on, which Azure sets, as drift.
func TestADiffComparesAnOlderAzureSnapshotAsCapturedNow(t *testing.T) {
	cluster := func(addons map[string]any) snapshot.Snapshot {
		return snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{{Body: map[string]any{
			"apiVersion": azarm.APIVersion, "kind": "Microsoft.ContainerService/managedClusters",
			"metadata": map[string]any{"name": "aks", "namespace": "rg"},
			"spec":     map[string]any{"properties": map[string]any{"addonProfiles": addons}}}}}}
	}
	old := cluster(map[string]any{"extensionManager": map[string]any{"enabled": true}, "omsagent": map[string]any{"enabled": true}})
	now := cluster(map[string]any{"omsagent": map[string]any{"enabled": true}})
	if ch := compareTarget("azure", old, now); len(ch) != 0 {
		t.Errorf("an older snapshot differs on what Azure sets: %v", ch)
	}
	if ch := compareTarget("kubernetes", old, now); len(ch) != 1 {
		t.Errorf("only Azure snapshots are made as captured now: %v", ch)
	}
}
