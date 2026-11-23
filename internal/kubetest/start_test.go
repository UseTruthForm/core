package kubetest

import (
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStart runs start with this test binary standing for etcd and
// kube-apiserver, in the helper mode given (see TestMain).
func fakeStart(t *testing.T, mode string, timeout time.Duration) (time.Duration, error) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(helperEnv, mode)
	began := time.Now()
	s, err := start("fake", self, self, t.TempDir(), timeout)
	if s != nil {
		s.stop()
		t.Fatal("a fake API server became ready")
	}
	return time.Since(began), err
}

// A start under a full parallel run on Windows failed with "API server
// never became ready" and empty logs, after the whole minute, and said
// nothing of why. A process that exits now ends the wait at once, and the
// failure says which one, how, and what it wrote.
func TestStartFailsAtOnceWhenEtcdExits(t *testing.T) {
	took, err := fakeStart(t, "etcd-exits", time.Minute)
	if err == nil {
		t.Fatal("no error")
	}
	if took > 20*time.Second {
		t.Errorf("took %s: an exited etcd should end the wait at once, not at the deadline", took)
	}
	msg := err.Error()
	for _, want := range []string{
		"API server fake never became ready",
		"etcd exited (exit status 1) before it answered /health",
		"fake etcd: cannot open its data directory", // its own output, under its name
		"--- etcd output ---",
		"--- kube-apiserver output ---\n(none)",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	if !strings.Contains(msg, "\netcd: exited after") || !strings.Contains(msg, "\nkube-apiserver: running for") {
		t.Errorf("each process's state is not reported:\n%s", msg)
	}
}

// Started and silent, the two reach the deadline: the failure names the
// stage (etcd's /health, before kube-apiserver's /readyz) and says both
// were running and had written nothing.
func TestStartSaysWhatHungAtTheDeadline(t *testing.T) {
	_, err := fakeStart(t, "silent", 2*time.Second)
	if err == nil {
		t.Fatal("no error")
	}
	msg := err.Error()
	for _, want := range []string{
		"etcd never answered /health",
		"\netcd: running for",
		"\nkube-apiserver: running for",
		", no output",
		"--- etcd output ---\n(none)",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
}

// A process's output is locked: etcd and kube-apiserver once shared one
// unlocked buffer, written by a goroutine each at the same time. Run with
// -race.
func TestOutputTakesWritesAtOnce(t *testing.T) {
	var a proc
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			_, _ = a.out.Write([]byte("x"))
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		_, _ = a.out.Write([]byte("y"))
	}
	<-done
	if n, _ := a.out.written(); n != 2000 {
		t.Fatalf("%d bytes written, want 2000", n)
	}
}

// Ports for one server, and for servers started side by side, are all
// different: the same port given twice made etcd fail to start with
// "address already in use" on a CI run.
func TestFreePortsAreAllDifferent(t *testing.T) {
	seen := map[int]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ports, err := freePorts(3)
			if err != nil || len(ports) != 3 {
				t.Errorf("%v %v", ports, err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, p := range ports {
				if seen[p] || p == 0 {
					t.Errorf("port %d was given twice", p)
				}
				seen[p] = true
			}
		}()
	}
	wg.Wait()
	// Each is free once handed over.
	ports, err := freePorts(3)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ports {
		l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if err != nil {
			t.Errorf("port %d is not free: %v", p, err)
			continue
		}
		l.Close()
	}
}
