//go:build windows

package main

import (
	"os"
	"testing"
)

func TestWindowsConsoleSignals(t *testing.T) {
	signals := terminationSignals()
	if len(signals) != 1 || signals[0] != os.Interrupt {
		t.Fatal("Windows must handle console Ctrl+C")
	}
	if reloadSignal() != nil {
		t.Fatal("Windows must not advertise unsupported SIGHUP reload")
	}
}
