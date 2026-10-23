package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// An agent's arguments can never change what a tool runs: the command is
// the tool's, unknown keys are dropped, and each value is one --name=value
// argument, so "us-east-2 --update" stays a region (the real probe failed
// on it as a host name, as it should).
func TestMCPArgvCannotBecomeRestore(t *testing.T) {
	got := mcpArgv("capture", map[string]any{
		"platform": "aws", "region": "us-east-2 --update", "out": "snap",
		"values": "secrets.yaml", "update": "true", "from": "-x",
	})
	want := []string{"capture", "--platform=aws", "--region=us-east-2 --update", "--out=snap"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, a := range got {
		if strings.Contains(a, "values") || strings.Contains(a, "update=") {
			t.Errorf("unknown key passed on: %q", a)
		}
	}
}

// Every tool but capture is read-only; capture writes local files and is
// marked so. None is destructive, and there is no restore tool.
func TestMCPToolsAreReadOnly(t *testing.T) {
	for _, tool := range mcpTools() {
		if tool.ReadOnly == (tool.Name == "capture") || tool.Destructive {
			t.Errorf("%s: readOnly=%v destructive=%v", tool.Name, tool.ReadOnly, tool.Destructive)
		}
		if strings.Contains(tool.Name, "restore") || strings.Contains(strings.ToLower(tool.Description), "restore it") {
			t.Errorf("%s looks like a restore", tool.Name)
		}
	}
}

// A region goes into a host name and a cache path: anything else is
// refused before either is built (the review's probe used
// "x@attacker.example/../../../../tmp/owned").
func TestMCPRefusesNonRegion(t *testing.T) {
	for _, r := range []string{"x@attacker.example/../../../../tmp/owned", "us-east-2 --update", "../us-east-1", ""} {
		if _, err := listTypes(context.Background(), map[string]any{"platform": "aws", "region": r + "#"}); err == nil {
			t.Errorf("region %q accepted", r)
		}
	}
	if _, err := runStackDNA(context.Background(), "capture", map[string]any{"platform": "aws", "region": "x@evil.example", "out": t.TempDir() + "/new"}, "out"); err == nil {
		t.Error("capture accepted a non-region")
	}
}

// capture never writes into a directory that holds something: the CLI
// replaces a snapshot in place, and an agent must not wipe one that way.
func TestMCPCaptureRefusesNonEmptyOut(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snapshot.yaml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tool := range mcpTools() {
		if tool.Name == "capture" {
			if _, err := tool.Call(context.Background(), map[string]any{"platform": "aws", "region": "us-east-1", "out": dir}); err == nil || !strings.Contains(err.Error(), "not empty") {
				t.Errorf("capture into a snapshot directory: %v", err)
			}
		}
	}
}
