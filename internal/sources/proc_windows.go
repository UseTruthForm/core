package sources

import (
	"os/exec"
	"syscall"
)

const shell, shellFlag = "cmd", "/C"

// wholeGroup, on Windows, gives cmd.exe the command as it was written: Go
// would otherwise escape its quotes in a way cmd.exe does not read. What a
// command started is not ended with it here; the wait is bounded all the
// same (WaitDelay).
func wholeGroup(cmd *exec.Cmd) {
	if len(cmd.Args) == 3 && cmd.Args[0] == shell && cmd.Args[1] == shellFlag {
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd /S /C "` + cmd.Args[2] + `"`}
	}
}
