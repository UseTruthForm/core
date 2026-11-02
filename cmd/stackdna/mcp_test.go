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

// The permissions tool is how an agent sets up someone's access: a value
// it lacks comes back as an error to ask the person about, never as a
// placeholder in a command (PowerShell read "<admin-profile>" as a
// redirection when one was pasted, 2026-10-23).
func TestMCPPermissionsAsksRatherThanPlaceholders(t *testing.T) {
	_, err := permissionsTool(context.Background(), map[string]any{"platform": "aws"})
	if err == nil || !strings.Contains(err.Error(), "--account") || !strings.Contains(err.Error(), "--principal") {
		t.Fatalf("want the missing values named: %v", err)
	}
	out, err := permissionsTool(context.Background(), map[string]any{"platform": "aws", "account": "111122223333",
		"principal": "arn:aws:iam::111122223333:role/runner", "source_profile": "runner"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"aws cloudformation deploy", "stackdna check --platform aws", "delete-stack", "----- stackdna-aws.yaml -----", "ReadOnlyAccess"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q", want)
		}
	}
	if strings.ContainsAny(out[:strings.Index(out, "-----")], "<>") {
		t.Errorf("plan text holds < or >:\n%s", out)
	}
}

func TestMCPCheckArgv(t *testing.T) {
	got := mcpArgv("check", map[string]any{"platform": "aws", "region": "us-east-1", "access": "capture", "out": "x", "update": "true"})
	want := []string{"check", "--platform=aws", "--region=us-east-1", "--access=capture"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// An agent rehearsing a restore into another subscription compares under the
// new names; without --rename every renamed resource read as missing.
func TestMCPDiffArgvCarriesRenameAndParallel(t *testing.T) {
	got := mcpArgv("diff", map[string]any{"platform": "azure", "subscription": "s", "parallel": "2", "rename": "n.yaml", "from": "d"})
	want := []string{"diff", "--platform=azure", "--subscription=s", "--parallel=2", "--rename=n.yaml", "--from=d"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := mcpArgv("capture", map[string]any{"platform": "azure", "rename": "n.yaml", "out": "d"}); !reflect.DeepEqual(got, []string{"capture", "--platform=azure", "--out=d"}) {
		t.Errorf("capture has no --rename, and an unknown flag fails it: %q", got)
	}
	if got := mcpArgv("capture", map[string]any{"platform": "azure", "parallel": "2", "out": "d"}); !reflect.DeepEqual(got, []string{"capture", "--platform=azure", "--parallel=2", "--out=d"}) {
		t.Errorf("capture: %q", got)
	}
	// Advertised in the shared schema, and dropped here without a word.
	if got := mcpArgv("check", map[string]any{"platform": "azure", "parallel": "2"}); !reflect.DeepEqual(got, []string{"check", "--platform=azure", "--parallel=2"}) {
		t.Errorf("check: %q", got)
	}
}

// An agent may send a number or a boolean for an argument, and dropped it changed
// nothing, without a word.
func TestMCPTakesWhatAnAgentMaySend(t *testing.T) {
	got := mcpArgv("diff", map[string]any{"platform": "azure", "parallel": float64(2), "new-role-assignment-ids": true, "from": "d"})
	want := []string{"diff", "--platform=azure", "--parallel=2", "--new-role-assignment-ids=true", "--from=d"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A tool's schema is all an agent sees: an argument passed on and not offered
// is one no agent will send.
func TestMCPOffersWhatItPasses(t *testing.T) {
	want := map[string][]string{"capture": {"parallel"}, "diff": {"parallel", "rename"}, "check_access": {"parallel"}}
	for _, tool := range mcpTools() {
		for _, name := range want[tool.Name] {
			props, _ := tool.Schema["properties"].(map[string]any)
			if _, ok := props[name]; !ok {
				t.Errorf("%s does not offer %s", tool.Name, name)
			}
		}
	}
}
