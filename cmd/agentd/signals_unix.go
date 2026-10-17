//go:build !windows

package main

import (
	"os"
	"syscall"
)

func terminationSignals() []os.Signal { return []os.Signal{os.Interrupt, syscall.SIGTERM} }
func reloadSignal() os.Signal         { return syscall.SIGHUP }
