//go:build !windows

package sources

import (
	"os/exec"
	"syscall"
)

const shell, shellFlag = "sh", "-c"

// wholeGroup has a command run in a process group of its own, and has a
// cancel end the group: the command and what it started.
func wholeGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
