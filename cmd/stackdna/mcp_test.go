package main

import (
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
	want := []string{"capture", "--platform=aws", "--region=us-east-2 --update", "--out=snap", "--from=-x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, a := range got {
		if strings.Contains(a, "values") || strings.Contains(a, "update=") {
			t.Errorf("unknown key passed on: %q", a)
		}
	}
}

// Every tool is read-only, and there is no restore tool.
func TestMCPToolsAreReadOnly(t *testing.T) {
	for _, tool := range mcpTools() {
		if !tool.ReadOnly {
			t.Errorf("%s is not marked read-only", tool.Name)
		}
		if strings.Contains(tool.Name, "restore") || strings.Contains(strings.ToLower(tool.Description), "restore it") {
			t.Errorf("%s looks like a restore", tool.Name)
		}
	}
}
