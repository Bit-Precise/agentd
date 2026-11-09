//go:build windows

package task

import (
	"os/exec"
	"path/filepath"
	"strings"
)

func setProcAttr(c *exec.Cmd) {}

func killTree(c *exec.Cmd) {
	if c.Process != nil {
		_ = c.Process.Kill()
	}
}

func isCmdExe(shell string) bool { return strings.EqualFold(filepath.Base(shell), "cmd.exe") }
