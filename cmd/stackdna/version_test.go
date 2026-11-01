package main

import (
	"strings"
	"testing"
)

// One release's binaries must write the same graph, so the generator names
// the version and commit and nothing that differs between them, the build
// time included.
func TestGeneratorIsVersionAndCommitOnly(t *testing.T) {
	v, c, b := version, commit, built
	defer func() { version, commit, built = v, c, b }()
	version, commit, built = "v9.9.9", "abc123", "2026-01-01T00:00:00Z"
	_, _, _, dirty := versionInfo()
	if got, want := generator(), generatorOf("v9.9.9", "abc123", dirty); got != want {
		t.Errorf("generator() = %q, want %q", got, want)
	}
	for _, c := range []struct {
		ver, rev string
		dirty    bool
		want     string
	}{
		{"v9.9.9", "abc123", false, "stackdna v9.9.9 (abc123)"},
		{"v9.9.9", "abc123", true, "stackdna v9.9.9 (abc123, with uncommitted changes)"},
		{"dev", "", false, "stackdna dev (unknown commit)"},
	} {
		if got := generatorOf(c.ver, c.rev, c.dirty); got != c.want {
			t.Errorf("generatorOf(%q, %q, %v) = %q, want %q", c.ver, c.rev, c.dirty, got, c.want)
		}
	}
}

// The version line names the edition: a capture-only binary must say it
// cannot restore, so whoever holds it knows what it can do. CI runs this in
// both editions.
func TestVersionNamesEdition(t *testing.T) {
	v := versionString()
	want := "full"
	if captureOnly {
		want = "capture-only"
	}
	if !strings.Contains(v, want) || !strings.HasPrefix(v, "stackdna ") {
		t.Errorf("version %q does not name the %s edition", v, want)
	}
}
