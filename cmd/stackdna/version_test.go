package main

import (
	"strings"
	"testing"
)

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
