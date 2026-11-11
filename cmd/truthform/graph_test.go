package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/snapshot"
)

// graph reads a snapshot and nothing else: no login, no request. It is for
// Azure snapshots and says so for others.
func TestGraphCommand(t *testing.T) {
	dir := t.TempDir()
	id := "/subscriptions/{{truthform|subscription}}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
	s := snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{{Body: map[string]any{
		"apiVersion": "azure.truthform.org/v1", "kind": "Microsoft.Storage/storageAccounts",
		"metadata": map[string]any{"name": "acct", "namespace": "rg", "annotations": map[string]any{"truthform.org/id": id, "truthform.org/api-version": "2023-01-01"}},
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
	// A live consumer held an export and nobody could say which build wrote
	// it: its counts differed from a known run, and neither the file nor the
	// consumer's logs named a version.
	if want := generator(); want == "" || !strings.Contains(string(b), `"generator": "`+want+`"`) {
		t.Errorf("the graph does not name the build that wrote it: %s", b)
	}
	if !strings.Contains(string(b), "{{truthform|subscription}}") {
		t.Error("without --subscription the graph must keep the placeholder")
	}
	// The placeholder in those IDs was renamed with the tool, so a graph
	// from an earlier build shares no ID with this one. The format says so;
	// left at 1, a consumer joining the two would see every resource
	// replaced and nothing to tell it why.
	if g.Format != 2 {
		t.Errorf("graph format %d, want 2", g.Format)
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

// A projection file's path went into the export as typed, so a graph handed to
// another system named a directory on the machine that wrote it.
func TestGraphProjectionNameHasNoPath(t *testing.T) {
	read := func(string) ([]byte, error) { return []byte("version: 1\n"), nil }
	for _, p := range []string{`C:\Users\someone\views\mine.yaml`, "/home/someone/views/mine.yaml", "views/mine.yaml", "mine.yaml"} {
		if _, name, err := azarm.LoadProjection(p, read); err != nil || name != "mine.yaml" {
			t.Errorf("%s: name %q, err %v", p, name, err)
		}
	}
	if _, name, err := azarm.LoadProjection("views/security", read); err != nil || name != "./security" {
		t.Errorf("a file named as a built-in reads as it: %q, %v", name, err)
	}
}
