//go:build !linux && !darwin && !windows

// Package elevator is the privileged TUN helper; TUN mode is implemented for
// macOS and Linux (design phase 2), not yet for Windows.
package elevator

import (
	"context"
	"errors"
	"log/slog"
)

// DefaultSocket is unused on this platform.
const DefaultSocket = ""

var errUnsupported = errors.New("TUN mode and the elevator are available on macOS and Linux; use the http/socks5 proxies or agentd connect here")

// Server is the elevator process.
type Server struct {
	Socket   string
	AllowUID int
	AllowSID string
	Log      *slog.Logger
}

// Run reports that TUN mode is unsupported here.
func (s *Server) Run(ctx context.Context) error { return errUnsupported }

// Install reports that TUN mode is unsupported here.
func Install(exe, allow string) error { return errUnsupported }

// Uninstall is a no-op here.
func Uninstall() error { return errUnsupported }
