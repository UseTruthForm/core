package awscc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stackdna/core/internal/snapshot"
)

// Creates that do not depend on each other run at once, and the result is
// the same as one at a time: the same objects applied, in the same order,
// with the same target afterwards.
func TestParallelRestoreMatchesSequential(t *testing.T) {
	run := func(workers int) (time.Duration, []snapshot.Result, snapshot.Snapshot) {
		e := newEnv(t)
		snap, err := e.adapter(e.src).Capture(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		e.dst.CreateDelay = 40 * time.Millisecond
		a := e.adapter(e.dst)
		a.Tuning = Tuning{Parallel: workers}
		start := time.Now()
		res := a.Restore(context.Background(), snap)
		took := time.Since(start)
		got, err := a.Capture(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range snapshot.Compare(snap, got) {
			t.Errorf("workers=%d: target differs: %+v", workers, c)
		}
		return took, res, snap
	}
	slow, one, _ := run(1)
	fast, many, _ := run(8)
	if len(one) != len(many) {
		t.Fatalf("%d results one at a time, %d at once", len(one), len(many))
	}
	for i := range one {
		if one[i].Key != many[i].Key || one[i].OK != many[i].OK {
			t.Errorf("result %d: %s %v vs %s %v", i, one[i].Key, one[i].OK, many[i].Key, many[i].OK)
		}
	}
	// The shop's longest chain is 3 creates (API, resource, child resource);
	// 12 creates one at a time take at least 12 delays.
	if fast*2 > slow {
		t.Errorf("at once %v, one at a time %v: creates did not overlap", fast, slow)
	}
	t.Logf("one at a time %v, eight at once %v", slow, fast)
}

// A write AWS accepted is never sent again: a throttled status poll is
// not a throttled submission (review of #19 sent the create twice). Only a
// submission refused before acceptance is retried.
func TestOnlyRefusedSubmissionsAreRetried(t *testing.T) {
	b := submitBackoff
	submitBackoff = time.Millisecond
	defer func() { submitBackoff = b }()
	calls := 0
	poll := errors.New("AWS::EC2::SecurityGroupIngress create: polling request tok-1: operation error CloudControl: GetResourceRequestStatus, ThrottlingException: Rate exceeded")
	err := submitted(context.Background(), func() error { calls++; return poll })
	if calls != 1 || err == nil {
		t.Errorf("an accepted create whose poll was throttled was sent %d times (err %v)", calls, err)
	}
	calls = 0
	err = submitted(context.Background(), func() error {
		calls++
		if calls == 1 {
			return notAccepted(errors.New("operation error CloudControl: CreateResource, ThrottlingException: Rate exceeded"))
		}
		return nil
	})
	if calls != 2 || err != nil {
		t.Errorf("a refused submission: %d calls, err %v; want it sent again once", calls, err)
	}
	if notAccepted(errors.New("AlreadyExists")) != nil && errors.Is(notAccepted(errors.New("AlreadyExists")), ErrNotAccepted) {
		t.Error("only throttling marks a submission as not accepted")
	}
}
