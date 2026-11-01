package main

import (
	"runtime"
	"strings"
	"testing"
)

// The version line names the edition: a capture-only binary must say it
// cannot restore, so whoever holds it knows what it can do. CI runs this in
// both editions.
// Two binaries of one commit must write the same graph, so the generator
// names the version and commit and nothing else.
func TestGeneratorIsVersionAndCommitOnly(t *testing.T) {
	v, c := version, commit
	defer func() { version, commit = v, c }()
	version, commit = "v9.9.9", "abc123"
	if got := generator(); !strings.HasPrefix(got, "stackdna v9.9.9 (abc123") {
		t.Errorf("generator() = %q, want the version and commit", got)
	}
	for _, varies := range []string{runtime.GOOS, runtime.GOARCH, runtime.Version(), "capture-only", "full"} {
		if strings.Contains(generator(), varies) {
			t.Errorf("generator() = %q holds %q, which differs between binaries of one commit", generator(), varies)
		}
	}
}

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
