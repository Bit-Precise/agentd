//go:build windows

package main

import "os"

// Ctrl+C shuts down the console process. Windows has no SIGHUP reload signal.
func terminationSignals() []os.Signal { return []os.Signal{os.Interrupt} }
func reloadSignal() os.Signal         { return nil }
