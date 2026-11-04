package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/azarm"
	"github.com/stackdna/core/internal/snapshot"
)

// azureWorld is a source captured to a snapshot directory by seed, and a
// target azureAPI hands restore and diff in place of Azure.
func azureWorld(t *testing.T, seed func(reg *azarm.Registry, src *azarm.Fake, rg string), edit func(*snapshot.Snapshot)) (dir string, dst *azarm.Fake) {
	t.Helper()
	reg, err := azarm.LoadDefinitions(leaveDefs)
	if err != nil {
		t.Fatal(err)
	}
	w := azarm.NewWorld(reg)
	src := w.Subscription(leaveSrc, "tenant")
	dst = w.Subscription(leaveDst, "tenant")
	ctx := context.Background()
	rg := "/subscriptions/" + leaveSrc + "/resourceGroups/rg"
	if _, err := src.Put(ctx, rg, reg.Versions("Microsoft.Resources/resourceGroups")[0], map[string]any{"location": "eastus"}); err != nil {
		t.Fatal(err)
	}
	seed(reg, src, rg)
	s, err := (&azarm.Adapter{API: src, Registry: reg}).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(&s)
	}
	dir = filepath.Join(t.TempDir(), "snap")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
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
	t.Cleanup(func() { azureAPI = old; heldBack = nil; sizeCheck = nil })
	return dir, dst
}

// A real restore's cluster was refused because the target could not have its
// node size, after the rest of the restore had run. diff and restore say so
// first, in their documents too, and a size given with --values is the one
// checked.
func TestDiffAndRestoreSayASizeTheTargetCannotHave(t *testing.T) {
	vm := "Microsoft.Compute/virtualMachines"
	dir, dst := azureWorld(t, func(reg *azarm.Registry, src *azarm.Fake, rg string) {
		src.SeedAzure(rg+"/providers/"+vm+"/vm", reg.Versions(vm)[0], map[string]any{"location": "eastus", "properties": map[string]any{"hardwareProfile": map[string]any{"vmSize": "Standard_Old_v1"}}})
	}, nil)
	dst.SKUs = map[string][]map[string]any{"eastus": {
		{"name": "Standard_Old_v1", "resourceType": "virtualMachines", "restrictions": []any{map[string]any{"type": "Location", "reasonCode": "NotAvailableForSubscription"}}},
		{"name": "Standard_New_v2", "resourceType": "virtualMachines"},
	}}
	ctx := context.Background()
	target := []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir}
	want := "Microsoft.Compute/virtualMachines/rg/vm uses Standard_Old_v1 in eastus, where this subscription cannot have it"
	_, _, errOut := output(t, func() int { return diff(ctx, target) })
	if !strings.Contains(errOut, "WARNING: 1 VM sizes") || !strings.Contains(errOut, want) || !strings.Contains(errOut, "VM sizes: checked 1 in 1 regions") {
		t.Errorf("diff does not say it:\n%s", errOut)
	}
	d := asJSON(t, func() { diff(ctx, target) })
	if v, _ := d["vm_sizes"].(map[string]any); v == nil || len(v["refused"].([]any)) != 1 {
		t.Errorf("the diff document: %v", d["vm_sizes"])
	}
	if captureOnly {
		return // restore is refused in the capture-only build
	}
	if _, _, errOut := output(t, func() int { return restore(ctx, target) }); !strings.Contains(errOut, want) {
		t.Errorf("restore does not say it:\n%s", errOut)
	}
	vals := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(vals, []byte(vm+"/rg/vm:\n  properties:\n    hardwareProfile:\n      vmSize: Standard_New_v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, errOut := output(t, func() int { return restore(ctx, append(target, "--values", vals)) }); strings.Contains(errOut, "WARNING") || !strings.Contains(errOut, "checked 1 in 1") {
		t.Errorf("restore checks the snapshot's size, not the one given:\n%s", errOut)
	}
}

// Review of #72: NOT SENT counted as applied and towards complete, said only
// in a detail. A workspace's AzureDiagnostics table waits for Azure to make
// it, so its retention is not kept yet: the restore says so, in its document,
// and does not finish.
func TestRestoreSaysWhatItDidNotSend(t *testing.T) {
	if captureOnly {
		t.Skip("restore is refused in the capture-only build")
	}
	law := "Microsoft.OperationalInsights/workspaces"
	dir, dst := azureWorld(t, func(reg *azarm.Registry, src *azarm.Fake, rg string) {
		ws := rg + "/providers/" + law + "/law"
		if _, err := src.Put(context.Background(), ws, reg.Versions(law)[0], map[string]any{"location": "eastus"}); err != nil {
			t.Fatal(err)
		}
		src.SeedAzure(ws+"/tables/AzureDiagnostics", reg.Versions(law + "/tables")[0], map[string]any{"properties": map[string]any{
			"retentionInDays": 90, "retentionInDaysAsDefault": false, "totalRetentionInDays": 730, "totalRetentionInDaysAsDefault": false}})
		// Only the workspace's defaults: nothing to wait for.
		plain := rg + "/providers/" + law + "/plain"
		if _, err := src.Put(context.Background(), plain, reg.Versions(law)[0], map[string]any{"location": "eastus"}); err != nil {
			t.Fatal(err)
		}
		src.SeedAzure(plain+"/tables/AzureDiagnostics", reg.Versions(law + "/tables")[0], map[string]any{"properties": map[string]any{
			"retentionInDays": 30, "retentionInDaysAsDefault": true, "totalRetentionInDays": 30, "totalRetentionInDaysAsDefault": true}})
	}, nil)
	dst.PutError = func(id string, body map[string]any) error {
		if strings.HasSuffix(id, "/tables/AzureDiagnostics") && dst.Stored(id) == nil {
			return errors.New("InvalidParameter: cannot create or migrate AzureDiagnostics table")
		}
		return nil
	}
	ctx := context.Background()
	target := []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir}
	code, out, errOut := output(t, func() int { return restore(ctx, target) })
	if code != 3 || !strings.Contains(out, "NOT SENT azure.stackdna.org/v1|"+law+"/tables|rg|law/AzureDiagnostics: Azure makes AzureDiagnostics") ||
		!strings.Contains(out, "of those, 2 not sent") || !strings.Contains(out, "not finished: 1 wait for Azure") ||
		!strings.Contains(out, "law/AzureDiagnostics: Azure makes AzureDiagnostics") || !strings.Contains(out, "plain/AzureDiagnostics: Azure makes AzureDiagnostics") {
		t.Errorf("exit %d\n%s%s", code, out, errOut)
	}
	r := asJSON(t, func() { restore(ctx, target) })
	if ns, _ := r["not_sent"].([]any); r["complete"] != false || r["pending"] != float64(1) || len(ns) != 2 {
		t.Errorf("the restore document: complete %v, pending %v, not_sent %v", r["complete"], r["pending"], r["not_sent"])
	}
	// Leave the one with retention set out: the one with only defaults does
	// not keep the restore unfinished, and is still said.
	leave := filepath.Join(t.TempDir(), "leave.yaml")
	if err := os.WriteFile(leave, []byte("- "+law+"/tables/rg/law/AzureDiagnostics\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = output(t, func() int { return restore(ctx, append(target, "--leave-out", leave)) })
	if code != 0 || !strings.Contains(out, "plain/AzureDiagnostics: Azure makes AzureDiagnostics") || strings.Contains(out, "not finished") {
		t.Errorf("a table with only defaults: exit %d\n%s%s", code, out, errOut)
	}
}

// Re-review of #72: nothing failed when the capture's CHECK line or the
// report's sections for AzureDiagnostics were taken out.
func TestCaptureSaysWhatAzureMakesAndWhatWaitsForIt(t *testing.T) {
	law := "Microsoft.OperationalInsights/workspaces"
	_, dst := azureWorld(t, func(*azarm.Registry, *azarm.Fake, string) {}, nil)
	reg, _ := azarm.LoadDefinitions(leaveDefs)
	ctx := context.Background()
	rg := "/subscriptions/" + leaveDst + "/resourceGroups/rg"
	if _, err := dst.Put(ctx, rg, reg.Versions("Microsoft.Resources/resourceGroups")[0], map[string]any{"location": "eastus"}); err != nil {
		t.Fatal(err)
	}
	for name, asDefault := range map[string]bool{"law": false, "plain": true} {
		ws := rg + "/providers/" + law + "/" + name
		if _, err := dst.Put(ctx, ws, reg.Versions(law)[0], map[string]any{"location": "eastus"}); err != nil {
			t.Fatal(err)
		}
		dst.SeedAzure(ws+"/tables/AzureDiagnostics", reg.Versions(law + "/tables")[0], map[string]any{"properties": map[string]any{
			"retentionInDays": 30, "retentionInDaysAsDefault": true, "totalRetentionInDays": 90, "totalRetentionInDaysAsDefault": asDefault}})
	}
	out := filepath.Join(t.TempDir(), "snap")
	_, stdout, errOut := output(t, func() int {
		return capture(ctx, []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--out", out})
	})
	if !strings.Contains(stdout, "CHECK: 1 resources Azure makes itself are kept only once it has") {
		t.Errorf("no CHECK line:\n%s%s", stdout, errOut)
	}
	rep, _ := os.ReadFile(filepath.Join(out, "REPORT.md"))
	for _, want := range []string{"## Check before relying on a restore: 1 resources", "rg/law/AzureDiagnostics", "## Made by Azure, with nothing set on them: 1", "rg/plain/AzureDiagnostics"} {
		if !strings.Contains(string(rep), want) {
			t.Errorf("REPORT.md lacks %q:\n%s", want, rep)
		}
	}
}

// A snapshot from before a fix holds what the fix took out. The first nightly
// after one compared it with a capture that does not, and reported every
// cluster's extensionManager add-on, which Azure sets, as drift.
func TestAnEnvironmentDiffComparesAnOlderAzureSnapshotAsCapturedNow(t *testing.T) {
	cluster := "Microsoft.ContainerService/managedClusters"
	addons := map[string]any{"extensionManager": map[string]any{"enabled": true}, "omsagent": map[string]any{"enabled": true}}
	dir, dst := azureWorld(t, func(reg *azarm.Registry, src *azarm.Fake, rg string) {}, nil)
	// The target is what the snapshot was taken of; the snapshot is older,
	// and holds the add-on Azure set.
	reg, _ := azarm.LoadDefinitions(leaveDefs)
	rg := "/subscriptions/" + leaveDst + "/resourceGroups/rg"
	if _, err := dst.Put(context.Background(), rg, reg.Versions("Microsoft.Resources/resourceGroups")[0], map[string]any{"location": "eastus"}); err != nil {
		t.Fatal(err)
	}
	dst.SeedAzure(rg+"/providers/"+cluster+"/aks", reg.Versions(cluster)[0], map[string]any{"location": "eastus", "properties": map[string]any{
		"dnsPrefix": "aks", "addonProfiles": addons, "agentPoolProfiles": []any{map[string]any{"name": "sys", "mode": "System", "count": 1, "vmSize": "Standard_D2s_v5"}}}})
	s, err := (&azarm.Adapter{API: dst, Registry: reg}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range s.Objects {
		if o.Kind() == cluster {
			o.Body["spec"].(map[string]any)["properties"].(map[string]any)["addonProfiles"].(map[string]any)["extensionManager"] = map[string]any{"enabled": true}
		}
	}
	from := filepath.Dir(dir)
	if err := s.Write(filepath.Join(from, "azure")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, from, envManifest, "name: e\ntargets:\n  - {name: azure, platform: azure, status: complete}\n")
	cfg := writeFile(t, t.TempDir(), "env.yaml", "name: e\ntargets:\n  - {name: azure, platform: azure, subscription: "+leaveDst+"}\n")
	old := envAzureDefinitions
	envAzureDefinitions = leaveDefs
	defer func() { envAzureDefinitions = old }()
	if _, out, errOut := output(t, func() int { return diffEnvironment(context.Background(), cfg, from) }); !strings.Contains(out, "== azure (azure): 0 differences") {
		t.Errorf("an older snapshot differs on what Azure sets:\n%s%s", out, errOut)
	}
}

// compare reads two snapshots, either older: each Azure one is made as this
// version captures before they are compared.
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
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	if err := now.Write(a); err != nil {
		t.Fatal(err)
	}
	if err := old.Write(b); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][]string{{a, b}, {b, a}} {
		if code, out, _ := output(t, func() int { return compare(pair) }); code != 0 {
			t.Errorf("compare of a newer and an older snapshot: exit %d\n%s", code, out)
		}
	}
}

// Review of #72: a table from a snapshot that predates the *AsDefault flags
// is taken as set, and REPORT.md says why and how to clear it.
func TestReportSaysAnOlderDiagnosticsTableIsTakenAsSet(t *testing.T) {
	s := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{{Body: map[string]any{
		"apiVersion": azarm.APIVersion, "kind": "Microsoft.OperationalInsights/workspaces/tables",
		"metadata": map[string]any{"name": "law/AzureDiagnostics", "namespace": "rg"},
		"spec":     map[string]any{"properties": map[string]any{"retentionInDays": 30, "totalRetentionInDays": 30}}}}}}
	dir := t.TempDir()
	if err := writeReport(dir, s, "azure x"); err != nil {
		t.Fatal(err)
	}
	rep, _ := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	for _, want := range []string{"## Check before relying on a restore: 1 resources", "rg/law/AzureDiagnostics (this snapshot predates", "capture the source again with this version"} {
		if !strings.Contains(string(rep), want) {
			t.Errorf("REPORT.md lacks %q:\n%s", want, rep)
		}
	}
}
