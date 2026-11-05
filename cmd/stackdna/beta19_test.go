package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
