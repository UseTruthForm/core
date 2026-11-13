//go:build !windows

package sources

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// exec: runs the command for real, takes its output less the line end, and
// says nothing of what a failing command printed.
func TestResolveExec(t *testing.T) {
	r := &Resolver{AllowExec: true}
	ctx := context.Background()
	if v, err := r.Resolve(ctx, "exec:printf 'a b\\n'"); err != nil || string(v) != "a b" {
		t.Errorf("exec: %q, %v", v, err)
	}
	if v, err := r.Resolve(ctx, "exec:printf 'a\\n\\n'"); err != nil || string(v) != "a\n" {
		t.Errorf("only the last line end goes: %q, %v", v, err)
	}
	_, err := r.Resolve(ctx, "exec:echo leaked-out; echo leaked-err >&2; exit 3")
	if err == nil || strings.Contains(err.Error(), "leaked") || !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("a failing command: %v", err)
	}
	// A read that is given up on ends what the command started too: a
	// pipeline's other commands held its output open, and the wait was for
	// them.
	for _, c := range []string{"sleep 20 | cat", "sleep 20; true"} {
		start := time.Now()
		_, _, err := runFor(ctx, time.Second, "sh", "-c", c)
		if took := time.Since(start); took > 8*time.Second || !errors.Is(err, errNoAnswer) {
			t.Errorf("%q: waited %s, %v", c, took.Round(time.Second), err)
		}
	}
	// What a command left running is ended with it, not left behind.
	pidFile := filepath.Join(t.TempDir(), "pid")
	if _, _, err := runFor(ctx, time.Second, "sh", "-c", "sleep 60 & echo $! > "+pidFile+"; wait"); !errors.Is(err, errNoAnswer) {
		t.Errorf("a command that waits: %v", err)
	}
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	gone := false
	for i := 0; i < 50 && pid > 0 && !gone; i++ {
		gone = syscall.Kill(pid, 0) != nil
		time.Sleep(100 * time.Millisecond)
	}
	if !gone {
		t.Errorf("the process a given-up read started (pid %d) is still running", pid)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	if _, err := r.Resolve(ctx, "exec:true"); err == nil || !strings.Contains(err.Error(), "read, and empty") {
		t.Errorf("a command that prints nothing: %v", err)
	}
}
