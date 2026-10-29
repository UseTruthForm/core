package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// graph reads a snapshot and nothing else: no login, no request. It is for
// Azure snapshots and says so for others.
func TestGraphCommand(t *testing.T) {
	dir := t.TempDir()
	id := "/subscriptions/{{stackdna|subscription}}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
	s := snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{{Body: map[string]any{
		"apiVersion": "azure.stackdna.org/v1", "kind": "Microsoft.Storage/storageAccounts",
		"metadata": map[string]any{"name": "acct", "namespace": "rg", "annotations": map[string]any{"stackdna.org/id": id, "stackdna.org/api-version": "2023-01-01"}},
		"spec":     map[string]any{"location": "westus", "properties": map[string]any{"publicNetworkAccess": "Disabled"}},
	}}}}
	snap := filepath.Join(dir, "snap")
	if err := s.Write(snap); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "graph.json")
	if code := graphCmd([]string{"--from", snap, "--out", out}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Format                     int
		Projection, SnapshotDigest string
		Nodes                      []map[string]any
	}
	_ = json.Unmarshal(b, &g)
	if g.Projection != "security" || !strings.HasPrefix(g.SnapshotDigest, "sha256:") || len(g.Nodes) != 1 ||
		g.Nodes[0]["properties"].(map[string]any)["properties.publicNetworkAccess"] != "Disabled" {
		t.Errorf("graph %s", b)
	}
	if !strings.Contains(string(b), "{{stackdna|subscription}}") {
		t.Error("without --subscription the graph must keep the placeholder")
	}

	s.Platform = "kubernetes"
	kube := filepath.Join(dir, "kube")
	if err := s.Write(kube); err != nil {
		t.Fatal(err)
	}
	if code := graphCmd([]string{"--from", kube}); code == 0 {
		t.Error("a kubernetes snapshot was graphed as azure")
	}
	if code := graphCmd([]string{"--from", snap, "--types", filepath.Join(dir, "missing.yaml")}); code == 0 {
		t.Error("a missing projection file was accepted")
	}
}
