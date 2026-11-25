package kubetest

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// helperEnv makes the test binary one of the two processes the test
// below needs: "starter" stands for a test binary that is killed, and
// "left" for what it would leave running.
const helperEnv = "TRUTHFORM_KUBETEST_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "left":
		// Listens, so that whether it still runs can be asked from
		// anywhere, on any platform.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			os.Exit(1)
		}
		fmt.Println(l.Addr().String())
		// It ends when told to, so that the test leaves nothing itself.
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				b := make([]byte, 1)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				if n, _ := c.Read(b); n == 1 && b[0] == 'q' {
					os.Exit(0)
				}
				_ = c.Close()
			}
		}()
		time.Sleep(2 * time.Minute)
		os.Exit(0)
	case "etcd-exits":
		// Stands for both binaries of start (see start_test.go): as etcd,
		// named by its --data-dir, it says why and exits 1; as
		// kube-apiserver it waits, silent, until it is stopped.
		for _, a := range os.Args[1:] {
			if a == "--data-dir" {
				fmt.Fprintln(os.Stderr, "fake etcd: cannot open its data directory")
				os.Exit(1)
			}
		}
		time.Sleep(2 * time.Minute)
		os.Exit(0)
	case "api-exits":
		// As kube-apiserver, named by its --etcd-servers, it says why and
		// exits 1; as etcd it waits, silent, never answering /health.
		for _, a := range os.Args[1:] {
			if a == "--etcd-servers" {
				fmt.Fprintln(os.Stderr, "fake kube-apiserver: cannot read its service account key")
				os.Exit(1)
			}
		}
		time.Sleep(2 * time.Minute)
		os.Exit(0)
	case "silent":
		// Both binaries, started and never answering or writing: what a
		// start under load looked like.
		time.Sleep(2 * time.Minute)
		os.Exit(0)
	case "starter", "starter-unwatched":
		self, _ := os.Executable()
		left := exec.Command(self)
		left.Env = append(os.Environ(), helperEnv+"=left")
		out, _ := left.StdoutPipe()
		if err := left.Start(); err != nil {
			os.Exit(1)
		}
		addr, _ := bufio.NewReader(out).ReadString('\n')
		if os.Getenv(helperEnv) == "starter" {
			if _, err := watch(left.Process.Pid); err != nil {
				os.Exit(1)
			}
		}
		fmt.Print(addr)
		time.Sleep(2 * time.Minute) // until killed
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// What a test binary started is stopped when the binary is killed, which
// runs no cleanup: a run interrupted or timed out left etcd and
// kube-apiserver behind.
func TestWhatIsStartedEndsWithAKilledBinary(t *testing.T) {
	run := func(mode string) (addr string, kill func()) {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		starter := exec.Command(self)
		starter.Env = append(os.Environ(), helperEnv+"="+mode)
		out, err := starter.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := starter.Start(); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(out).ReadString('\n')
		if err != nil {
			_ = starter.Process.Kill()
			t.Fatalf("%s: no address: %v", mode, err)
		}
		return strings.TrimSpace(line), func() { _ = starter.Process.Kill(); _ = starter.Wait() }
	}
	answers := func(addr string) bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}
	gone := func(addr string) bool {
		for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
			if !answers(addr) {
				return true
			}
		}
		return false
	}

	addr, kill := run("starter")
	if !answers(addr) {
		t.Fatalf("what was started does not answer at %s", addr)
	}
	kill()
	if !gone(addr) {
		t.Errorf("what a killed binary started still answers at %s", addr)
	}
	// And without a watcher it is left: that is what this guards.
	addr, kill = run("starter-unwatched")
	kill()
	time.Sleep(500 * time.Millisecond)
	if !answers(addr) {
		t.Fatalf("with no watcher, what was started ended by itself: the test above shows nothing")
	}
	// Told to end at the address it gave: nothing else knows its process.
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_, _ = c.Write([]byte("q"))
		_ = c.Close()
	}
	if !gone(addr) {
		t.Errorf("the process left for the comparison did not end when told to: %s", addr)
	}
}
