package azarm

import (
	"context"
	"testing"
	"time"

	"github.com/stackdna/core/internal/snapshot"
)

// Independent PUTs run at once, and the result is the one-at-a-time result:
// the same objects applied in the same order, the same target afterwards.
func TestParallelRestoreMatchesSequential(t *testing.T) {
	run := func(workers int) (time.Duration, []snapshot.Result) {
		e := newEnv(t)
		snap, err := e.adapter(e.src).Capture(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		e.dst.PutDelay = 30 * time.Millisecond
		start := time.Now()
		res := restoreWith(context.Background(), e.dst, e.reg, snap, RestoreOptions{Values: e.vals}, workers)
		took := time.Since(start)
		got, err := e.adapter(e.dst).Capture(context.Background())
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
		t.Errorf("at once %v, one at a time %v: PUTs did not overlap", fast, slow)
	}
	t.Logf("one at a time %v, eight at once %v", slow, fast)
}
