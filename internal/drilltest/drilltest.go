// Package drilltest is Truthform's restore drill, written once against the
// platform contract so every adapter is held to the same proof:
//
//  1. capture the source twice and require byte-identical snapshots on disk
//     (CI regenerates snapshots; unstable output would be noise forever)
//  2. require the captured objects to be exactly the expected set (more
//     means a filter failed, fewer means something was dropped)
//  3. restore into the target and require every object to report applied
//  4. capture the target and require no differences from the snapshot
//
// A backup that has never been restored is not a backup. This is what makes
// "captured" mean "recreatable" for each adapter.
package drilltest

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/platform"
	"github.com/usetruthform/core/internal/snapshot"
)

// Spec describes one drill.
type Spec struct {
	Source, Target platform.Platform
	// ExpectKeys is the exact set of snapshot.Object keys the source capture
	// must contain.
	ExpectKeys []string
}

// Run executes the drill and returns the snapshot it restored from.
func Run(t *testing.T, s Spec) snapshot.Snapshot {
	t.Helper()
	ctx := context.Background()

	first, err := s.Source.Capture(ctx)
	if err != nil {
		t.Fatalf("capture source: %v", err)
	}
	second, err := s.Source.Capture(ctx)
	if err != nil {
		t.Fatalf("capture source again: %v", err)
	}
	dirA, dirB := t.TempDir(), t.TempDir()
	if err := first.Write(dirA); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	if err := second.Write(dirB); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	da, _ := snapshot.Digest(dirA)
	db, _ := snapshot.Digest(dirB)
	if da != db {
		t.Fatalf("two captures of an unchanged source differ:\n%v", snapshot.Compare(first, second))
	}

	// Restore from what was written to disk, not the in-memory value, so the
	// file format is part of what the drill proves.
	snap, err := snapshot.Read(dirA)
	if err != nil {
		t.Fatalf("read snapshot back: %v", err)
	}
	var got []string
	for _, o := range snap.Objects {
		got = append(got, o.Key())
	}
	want := append([]string(nil), s.ExpectKeys...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("captured set differs from the expected set\ncaptured:\n  %s\nexpected:\n  %s",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}

	results := s.Target.Restore(ctx, snap)
	if len(results) != len(snap.Objects) {
		t.Fatalf("restore reported %d results for %d objects; an object went missing", len(results), len(snap.Objects))
	}
	for _, r := range results {
		if !r.OK {
			t.Errorf("not restored: %s: %s", r.Key, r.Detail)
		}
	}
	if t.Failed() {
		t.FailNow()
	}

	after, err := s.Target.Capture(ctx)
	if err != nil {
		t.Fatalf("capture target: %v", err)
	}
	if ch := snapshot.Compare(snap, after); len(ch) != 0 {
		for _, c := range ch {
			t.Errorf("%s %s %v", c.Kind, c.Key, c.Fields)
		}
		t.FailNow()
	}
	t.Logf("drill passed: %d objects captured deterministically (%s), restored and diffed clean", len(snap.Objects), da)
	return snap
}
