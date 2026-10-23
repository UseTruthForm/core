package gcp

import (
	"context"
	"testing"
	"time"

	"github.com/stackdna/core/internal/snapshot"
)

// Independent creates run at once, and the result is the one-at-a-time
// result: the same objects applied in the same order, the same target.
func TestParallelRestoreMatchesSequential(t *testing.T) {
	run := func(workers int) (time.Duration, []snapshot.Result) {
		docs := fixtures(t)
		w := NewWorld(docs)
		src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
		seedShop(t, src)
		seedNetwork(t, src)
		a := func(f *Fake) *Adapter { return &Adapter{API: f, Docs: docs} }
		snap, err := a(src).Capture(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		dst.WriteDelay = 30 * time.Millisecond
		start := time.Now()
		res := restoreWith(context.Background(), dst, docs, snap, RestoreOptions{}, workers)
		took := time.Since(start)
		got, err := a(dst).Capture(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range snapshot.Compare(snap, got) {
			t.Errorf("workers=%d: target differs: %+v", workers, c)
		}
		return took, res
	}
	slow, one := run(1)
	fast, many := run(8)
	for i := range one {
		if one[i].Key != many[i].Key || one[i].OK != many[i].OK {
			t.Errorf("result %d: %s %v vs %s %v", i, one[i].Key, one[i].OK, many[i].Key, many[i].OK)
		}
	}
	if fast*2 > slow {
		t.Errorf("at once %v, one at a time %v: creates did not overlap", fast, slow)
	}
	t.Logf("one at a time %v, eight at once %v", slow, fast)
}

// --parallel reaches the restore: one worker is one create at a time.
func TestParallelFlagReachesRestore(t *testing.T) {
	docs := fixtures(t)
	w := NewWorld(docs)
	src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
	seedShop(t, src)
	snap, err := (&Adapter{API: src, Docs: docs}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dst.WriteDelay = 30 * time.Millisecond
	a := &Adapter{API: dst, Docs: docs, Policy: Policy{Parallel: 1}}
	start := time.Now()
	res := a.Restore(context.Background(), snap)
	if took, min := time.Since(start), time.Duration(len(res))*dst.WriteDelay; took < min {
		t.Errorf("--parallel 1 restored %d objects in %v, less than one at a time (%v)", len(res), took, min)
	}
}
