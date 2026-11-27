package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/azarm"
)

// A diff did not take --values, so every value a restore was given read as
// drift (destroy-and-restore drill: the node size, the event hubs, a vault's
// soft delete). It now compares what a restore sent.
func TestADiffComparesWhatTheRestoreWasGiven(t *testing.T) {
	if captureOnly {
		t.Skip("restore is refused in the capture-only build")
	}
	dir, _, _ := leaveOutWorld(t)
	ctx := context.Background()
	vals := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(vals, []byte("Microsoft.Network/privateDnsZones/rg/corp.example:\n  tags: {env: test}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir}
	if code, out, errOut := output(t, func() int { return restore(ctx, append(target, "--values", vals)) }); code != 0 {
		t.Fatalf("restore: exit %d\n%s%s", code, out, errOut)
	}
	if code, out, _ := output(t, func() int { return diff(ctx, target) }); code != 2 || !strings.Contains(out, "corp.example") {
		t.Errorf("without --values, what it set is not a difference: exit %d\n%s", code, out)
	}
	if code, out, errOut := output(t, func() int { return diff(ctx, append(target, "--values", vals)) }); code != 0 || !strings.Contains(out, "no differences") {
		t.Errorf("with --values: exit %d\n%s%s", code, out, errOut)
	}
	// A key that matches nothing is refused, as by restore.
	if err := os.WriteFile(vals, []byte("Microsoft.Network/privateDnsZones/rg/gone:\n  tags: {env: test}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := output(t, func() int { return diff(ctx, append(target, "--values", vals)) }); code != 1 || !strings.Contains(errOut, "--values: nothing in the snapshot has") {
		t.Errorf("a key that matches nothing: exit %d\n%s", code, errOut)
	}
	if code, _, errOut := output(t, func() int {
		return diff(ctx, []string{"--platform", "aws", "--region", "us-east-1", "--from", dir, "--values", vals})
	}); code != 1 || !strings.Contains(errOut, "--values is for --platform azure") {
		t.Errorf("--values elsewhere: exit %d\n%s", code, errOut)
	}
}

// Names held by deleted resources are said before a restore sends anything,
// and in its document (destroy-and-restore drill: a run lost to them).
func TestARestoreSaysWhichNamesAreHeld(t *testing.T) {
	if captureOnly {
		t.Skip("restore is refused in the capture-only build")
	}
	dir, _, dst := leaveOutWorld(t)
	dst.Deleted = map[string][]map[string]any{}
	// The world has a private DNS zone; held names are for the types that
	// keep them, so this one is not held, and the check still runs and says so.
	ctx := context.Background()
	target := []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir}
	d := asJSON(t, func() { restore(ctx, target) })
	nh, ok := d["names_held"].(map[string]any)
	if !ok {
		t.Fatalf("no names_held in the restore document: %v", d)
	}
	if held, _ := nh["held"].([]any); len(held) != 0 {
		t.Errorf("held: %v", held)
	}
}

// kvWorld is a source subscription with a key vault, captured, and a target
// that holds the same vault as Azure answers for it there.
func kvWorld(t *testing.T, targetProps map[string]any) (dir string, dst *azarm.Fake) {
	t.Helper()
	reg, err := azarm.LoadDefinitions(leaveDefs)
	if err != nil {
		t.Fatal(err)
	}
	w := azarm.NewWorld(reg)
	src := w.Subscription(leaveSrc, "tenant")
	dst = w.Subscription(leaveDst, "tenant")
	ctx := context.Background()
	kv := "Microsoft.KeyVault/vaults"
	ver := reg.Versions(kv)[0]
	for _, side := range []struct {
		f     *azarm.Fake
		sub   string
		props map[string]any
	}{{src, leaveSrc, map[string]any{}}, {dst, leaveDst, targetProps}} {
		rg := "/subscriptions/" + side.sub + "/resourceGroups/rg"
		if _, err := side.f.Put(ctx, rg, "2024-11-01", map[string]any{"location": "eastus"}); err != nil {
			t.Fatal(err)
		}
		p := map[string]any{"tenantId": "00000000-0000-0000-0000-000000000000", "sku": map[string]any{"family": "A", "name": "standard"}, "accessPolicies": []any{}}
		for k, v := range side.props {
			p[k] = v
		}
		side.f.SeedAzure(rg+"/providers/"+kv+"/kv1", ver, map[string]any{"location": "eastus", "properties": p})
	}
	s, err := (&azarm.Adapter{API: src, Registry: reg}).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(t.TempDir(), "snap")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	old := azureAPI
	azureAPI = func(sub string, readOnly bool) (azarm.ARM, error) { return dst, nil }
	t.Cleanup(func() { azureAPI = old })
	return dir, dst
}

// A diff did not count Azure's default for what the snapshot does not set,
// through compareTarget (review of #75: only the unit was tested). A value
// other than the default is still a difference.
func TestADiffDoesNotCountAzuresDefault(t *testing.T) {
	ctx := context.Background()
	for v, want := range map[bool]int{false: 0, true: 2} {
		dir, _ := kvWorld(t, map[string]any{"enabledForDiskEncryption": v})
		code, out, errOut := output(t, func() int {
			return diff(ctx, []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir})
		})
		if code != want {
			t.Errorf("enabledForDiskEncryption %v in the target: exit %d, want %d\n%s%s", v, code, want, out, errOut)
		}
	}
}

// A diff says which names are held, and that only this subscription is seen
// (review of #75: diff's check had no test, and "none held" read as clear).
func TestADiffSaysWhichNamesAreHeld(t *testing.T) {
	ctx := context.Background()
	dir, dst := kvWorld(t, map[string]any{})
	dst.Deleted = map[string][]map[string]any{"/providers/microsoft.keyvault/deletedvaults": {{"name": "kv1"}}}
	code, out, errOut := output(t, func() int {
		return diff(ctx, []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir})
	})
	if !strings.Contains(errOut, "WARNING: 1 name is held by deleted resources") || !strings.Contains(errOut, "Microsoft.KeyVault/vaults/rg/kv1") || !strings.Contains(errOut, "only deleted resources in this subscription are seen") {
		t.Errorf("diff: exit %d\n%s%s", code, out, errOut)
	}
	d := asJSON(t, func() {
		diff(ctx, []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir})
	})
	nh, _ := d["names_held"].(map[string]any)
	if held, _ := nh["held"].([]any); len(held) != 1 || nh["only_this_subscription"] != true {
		t.Errorf("names_held: %v", d["names_held"])
	}
}
