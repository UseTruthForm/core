package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// A person reads REPORT.md to decide whether a restore can be relied on. Both
// halves of the managed-group decision have to reach them: what may not come
// back, and what was captured on a guess that the manager did not make it.
func TestReportNamesWhatMayNotComeBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	manager := "/subscriptions/{{stackdna|subscription}}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	id := "/subscriptions/{{stackdna|subscription}}/resourceGroups/MC_x/providers/Microsoft.Storage/storageAccounts/placed"
	s := snapshot.Snapshot{Platform: "azure", Policy: "default",
		Objects: []snapshot.Object{{Body: map[string]any{
			"apiVersion": "azure.stackdna.org/v1", "kind": "Microsoft.Storage/storageAccounts",
			"metadata": map[string]any{"name": "placed", "namespace": "MC_x", "annotations": map[string]any{
				"stackdna.org/id": id, "stackdna.org/api-version": "2023-01-01", "stackdna.org/after": manager}},
			"spec": map[string]any{"location": "westus"},
		}}},
		Skips: []snapshot.Skip{
			{Resource: "Microsoft.Compute/disks", Name: "rg/data", Reason: "managed by " + manager + ", which may not recreate it"},
			{Resource: "Microsoft.Network/loadBalancers", Name: "MC_x/kubernetes", Reason: "in a resource group managed by " + manager + ", which recreates it; its children and diagnostic settings are not read"},
		}}
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(dir, s, "azure test"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	r := string(b)
	for _, want := range []string{
		"## Check before relying on a restore: 1 resources",
		"- Microsoft.Compute/disks rg/data",
		"## Captured from a managed resource group: 1 resources",
		"- Microsoft.Storage/storageAccounts MC_x/placed",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("no %q in:\n%s", want, r)
		}
	}
	if strings.Contains(r, "- Microsoft.Network/loadBalancers MC_x/kubernetes") {
		t.Errorf("what the manager recreates is listed as needing a look:\n%s", r)
	}
	if strings.Contains(r, "## Not checked") {
		t.Errorf("a current snapshot reads as old:\n%s", r)
	}

	s.Skips = []snapshot.Skip{{Resource: "Microsoft.Network/loadBalancers", Name: "MC_x/kubernetes", Reason: "in a resource group managed by /subscriptions/11111111-1111-1111-1111-111111111111/x, which recreates it"}}
	if err := writeReport(dir, s, "azure test"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "REPORT.md")); !strings.Contains(string(b), "## Not checked") {
		t.Errorf("an old snapshot reads as checked:\n%s", b)
	}
}

func TestCaptureSaysToCheck(t *testing.T) {
	skips := []snapshot.Skip{
		{Reason: "managed by /x, which may not recreate it"},
		{Reason: "managed by /y, which recreates it"},
	}
	if got := checkLine(skips, "out"); !strings.Contains(got, "CHECK: 1 skipped") {
		t.Errorf("%q", got)
	}
	if got := checkLine(skips[1:], "out"); got != "" {
		t.Errorf("%q", got)
	}
}
