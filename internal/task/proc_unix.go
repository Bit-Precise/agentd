//go:build !windows

package task

import (
	"os/exec"
	"path/filepath"
	"syscall"
)

func setProcAttr(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killTree(c *exec.Cmd) {
	if c.Process == nil {
		return
	}
	_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
	_ = c.Process.Kill()
}

func isCmdExe(shell string) bool { return filepath.Base(shell) == "cmd.exe" }
