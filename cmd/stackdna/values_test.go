package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// A GCP restore took --values and never read it, so it reported what it
// applied as if the secrets had gone with it.
func TestValuesRefusedWhereNothingReadsThem(t *testing.T) {
	for _, tc := range []struct {
		platform, file string
		ok             bool
	}{
		{"gcp", "v.yaml", false},
		{"kubernetes", "v.yaml", false},
		{"gcp", "", true},
		{"kubernetes", "", true},
		{"aws", "v.yaml", true},
		{"azure", "v.yaml", true},
		{"github", "v.yaml", true},
		{"cloudflare", "v.yaml", true},
	} {
		if err := valuesAccepted(tc.platform, tc.file); (err == nil) != tc.ok {
			t.Errorf("%s %q: %v", tc.platform, tc.file, err)
		}
	}
}

// Through the command itself, on a snapshot on disk: exit 1 before any platform
// is reached, where the helper alone would pass with its call removed.
func TestRestoreCommandRefusesValuesItWouldDrop(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	if err := (snapshot.Snapshot{Platform: "gcp", Policy: "default"}).Write(dir); err != nil {
		t.Fatal(err)
	}
	if code := restore(context.Background(), []string{"--platform", "gcp", "--project", "p", "--from", dir, "--values", "v.yaml"}); code != 1 {
		t.Errorf("exit %d", code)
	}
}
