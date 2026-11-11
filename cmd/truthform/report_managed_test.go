package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// A person reads REPORT.md to decide whether a restore can be relied on. Both
// halves of the managed-group decision have to reach them: what may not come
// back, and what was captured on a guess that the manager did not make it.
func TestReportNamesWhatMayNotComeBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	manager := "/subscriptions/{{truthform|subscription}}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	id := "/subscriptions/{{truthform|subscription}}/resourceGroups/MC_x/providers/Microsoft.Storage/storageAccounts/placed"
	s := snapshot.Snapshot{Platform: "azure", Policy: "default",
		Objects: []snapshot.Object{{Body: map[string]any{
			"apiVersion": "azure.truthform.org/v1", "kind": "Microsoft.Storage/storageAccounts",
			"metadata": map[string]any{"name": "placed", "namespace": "MC_x", "annotations": map[string]any{
				"truthform.org/id": id, "truthform.org/api-version": "2023-01-01", "truthform.org/after": manager}},
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

// A guess a person can check: each one named, with its evidence, and the way to
// keep it.
func TestReportNamesWhatWasTakenAsThePlatforms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Skips: []snapshot.Skip{
		{Resource: "validatingadmissionpolicies.admissionregistration.k8s.io", Name: "aks-managed-x", Reason: "taken as AKS's: applied by Eno, named aks-managed-; --capture-platform keeps it"},
		{Resource: "daemonsets.apps", Namespace: "gw", Name: "agent", Reason: "installed and upgraded by AKS itself; a new cluster provides it"},
	}}
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(dir, s, "kube test"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	r := string(b)
	for _, want := range []string{"## Taken as the platform's: 1 resources", "- validatingadmissionpolicies.admissionregistration.k8s.io aks-managed-x: taken as AKS", "`--capture-platform`"} {
		if !strings.Contains(r, strings.ReplaceAll(want, "taken as AKS", "applied by Eno")) && !strings.Contains(r, want) {
			t.Errorf("no %q in:\n%s", want, r)
		}
	}
	if strings.Contains(r, "gw/agent") && strings.Contains(r[:strings.Index(r, "## Skipped on purpose")], "gw/agent") {
		t.Errorf("a fact listed as a guess:\n%s", r)
	}
}

// A peering with a cluster's network fails on a restore beside a new cluster,
// whose network has a new name: the report says so beforehand.
func TestReportNamesPeeringsWithAClustersNetwork(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	sub := "/subscriptions/{{truthform|subscription}}/resourceGroups/"
	peer := func(ns, name, remote string) snapshot.Object {
		return snapshot.Object{Body: map[string]any{"apiVersion": "azure.truthform.org/v1", "kind": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
			"metadata": map[string]any{"name": name, "namespace": ns, "annotations": map[string]any{"truthform.org/id": sub + ns + "/providers/Microsoft.Network/virtualNetworks/" + name, "truthform.org/api-version": "2025-07-01"}},
			"spec":     map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": sub + remote}}}}}
	}
	s := snapshot.Snapshot{Platform: "azure", Policy: "default",
		Objects: []snapshot.Object{peer("rg", "core/to-aks", "MC_x/providers/Microsoft.Network/virtualNetworks/aks-vnet"), peer("rg", "core/to-hub", "rg/providers/Microsoft.Network/virtualNetworks/hub")},
		Skips:   []snapshot.Skip{{Resource: "Microsoft.Resources/resourceGroups", Name: "MC_x/MC_x", Reason: "managed by /subscriptions/{{truthform|subscription}}/x, which recreates it"}}}
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(dir, s, "azure test"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	r := string(b)
	if !strings.Contains(r, "## Peerings with a cluster's network: 1") || !strings.Contains(r, "rg/core/to-aks: to a cluster's network") || strings.Contains(r, "core/to-hub:") {
		t.Errorf("report:\n%s", r)
	}
}

// A restore beside its source was refused for a DNS zone's link to another
// subscription's network, and nothing in the report had said the snapshot
// reached outside its own subscription.
func TestReportNamesReferencesToOtherSubscriptions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	other := "33333333-3333-3333-3333-333333333333"
	s := snapshot.Snapshot{Platform: "azure", Policy: "default",
		Objects: []snapshot.Object{{Body: map[string]any{
			"apiVersion": "azure.truthform.org/v1", "kind": "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
			"metadata": map[string]any{"name": "corp.example/office", "namespace": "rg", "annotations": map[string]any{
				"truthform.org/id":          "/subscriptions/{{truthform|subscription}}/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/corp.example/virtualNetworkLinks/office",
				"truthform.org/api-version": "2024-06-01"}},
			"spec": map[string]any{"location": "global", "properties": map[string]any{"virtualNetwork": map[string]any{
				"id": "/subscriptions/" + other + "/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/office"}}},
		}}}}
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
	if r := string(b); !strings.Contains(r, "## References to other subscriptions: 1") || !strings.Contains(r, other) {
		t.Errorf("the report does not name the reference:\n%s", r)
	}
}

// --leave-out is read by Azure only; anywhere else it is refused, never
// ignored, so a restore that sent what it was told to hold back cannot say it
// held it back.
func TestLeaveOutIsRefusedOffAzure(t *testing.T) {
	f := filepath.Join(t.TempDir(), "leave.yaml")
	if err := os.WriteFile(f, []byte("- Kind/rg/name\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A snapshot that has the object, so only the platform can refuse it.
	has := snapshot.Snapshot{Platform: "aws", Objects: []snapshot.Object{{Body: map[string]any{
		"apiVersion": "v1", "kind": "Kind", "metadata": map[string]any{"name": "name", "namespace": "rg"}}}}}
	if _, err := leftOut(f, "aws", has); err == nil {
		t.Error("--leave-out was accepted for aws")
	}
	if _, err := leftOut(f, "azure", snapshot.Snapshot{Platform: "azure"}); err == nil || !strings.Contains(err.Error(), "not in the snapshot") {
		t.Errorf("an entry naming nothing: %v", err)
	}
}
