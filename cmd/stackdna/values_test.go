package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// A staged --types that restored everything would have created, and billed for,
// what was held back; a flag for one platform must not read as taken on another.
func TestRestoreCommandRefusesWhatItWouldIgnore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	if err := (snapshot.Snapshot{Platform: "gcp", Policy: "default"}).Write(dir); err != nil {
		t.Fatal(err)
	}
	base := []string{"--platform", "gcp", "--project", "p", "--from", dir}
	for _, extra := range [][]string{{"--types", "x"}, {"--new-role-assignment-ids"}} {
		if code := restore(context.Background(), append(append([]string{}, base...), extra...)); code != 1 {
			t.Errorf("%v: exit %d", extra, code)
		}
	}
	if code := diff(context.Background(), append(append([]string{}, base...), "--new-role-assignment-ids")); code != 1 {
		t.Errorf("diff: exit %d", code)
	}
}

// Only the capture said what it could not read, so a restore or a diff of an
// incomplete snapshot could report full success. Through both commands, up to the
// point each needs a live target.
func TestRestoreAndDiffRepeatWhatCaptureCouldNotRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snap")
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Coverage: []snapshot.Coverage{{Resource: "x", NotCaptured: "list failed: no"}}}
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func(context.Context, []string) int{"restore": restore, "diff": diff} {
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		run(context.Background(), []string{"--context", "no-such-context", "--kubeconfig", filepath.Join(dir, "none"), "--from", dir})
		w.Close()
		os.Stdout = old
		b, _ := io.ReadAll(r)
		if !strings.Contains(string(b), "INCOMPLETE SNAPSHOT") {
			t.Errorf("%s does not say: %q", name, b)
		}
	}
}
