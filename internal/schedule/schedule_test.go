package schedule

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every item runs once, never before what it depends on, never more than
// workers at once, and independent items overlap.
func TestRun(t *testing.T) {
	// 0 <- 1 <- 2 (a chain); 3, 4, 5 independent; 6 needs 2 and 5.
	deps := [][]int{nil, {0}, {1}, nil, nil, nil, {2, 5}}
	var mu sync.Mutex
	done := map[int]bool{}
	var now, peak int32
	Run(len(deps), deps, 3, func(i int) {
		c := atomic.AddInt32(&now, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if c <= p || atomic.CompareAndSwapInt32(&peak, p, c) {
				break
			}
		}
		mu.Lock()
		for _, d := range deps[i] {
			if !done[d] {
				t.Errorf("%d started before its dependency %d finished", i, d)
			}
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		if done[i] {
			t.Errorf("%d ran twice", i)
		}
		done[i] = true
		mu.Unlock()
		atomic.AddInt32(&now, -1)
	})
	if len(done) != len(deps) {
		t.Errorf("ran %d of %d", len(done), len(deps))
	}
	if peak > 3 || peak < 2 {
		t.Errorf("peak concurrency %d, want 2..3", peak)
	}
}

// One worker is the sequential order: ready items in index order.
func TestOneWorkerIsSequential(t *testing.T) {
	deps := [][]int{{2}, nil, nil, {1}}
	var got []int
	Run(len(deps), deps, 1, func(i int) { got = append(got, i) })
	want := []int{1, 2, 0, 3}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}

// A cycle the caller did not set aside is a loud failure, not a hang.
func TestCyclePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a cycle must not hang or pass silently")
		}
	}()
	Run(2, [][]int{{1}, {0}}, 2, func(int) {})
}
