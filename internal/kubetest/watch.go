package kubetest

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// watchEnv, set, makes this process a watcher and nothing else: it waits
// for its standard input to end, stops the processes named, and exits.
const watchEnv = "TRUTHFORM_KUBETEST_WATCH"

// A test binary that is killed (a timeout, an interrupted run) runs no
// cleanup, and etcd and kube-apiserver do not end with what started them:
// they were left running. So each Start has a watcher, this same binary
// started again, holding the read end of a pipe whose write end only the
// test binary has. However the test binary ends, the pipe closes, and the
// watcher stops the two. It is a process and a pipe, and so the same on
// every platform.
func init() {
	list := os.Getenv(watchEnv)
	if list == "" {
		return
	}
	_, _ = io.Copy(io.Discard, os.Stdin) // until what started this is gone
	for _, s := range strings.Split(list, ",") {
		if pid, err := strconv.Atoi(s); err == nil {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	}
	os.Exit(0)
}

// watch starts a watcher over the processes, and returns how to dismiss
// it once they have been stopped in the ordinary way.
func watch(pids ...int) (dismiss func(), err error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	list := make([]string, len(pids))
	for i, pid := range pids {
		list[i] = strconv.Itoa(pid)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), watchEnv+"="+strings.Join(list, ","))
	cmd.Stdin = r
	err = cmd.Start()
	_ = r.Close()
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	return func() {
		// Dismissed before the pipe closes: it has nothing left to
		// stop, and a process id may by then be another's.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = w.Close()
	}, nil
}
