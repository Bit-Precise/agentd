//go:build linux || darwin

package agent

import (
	"agentd/internal/elevator"
	"agentd/internal/tun"
)

// tunDevice wraps the descriptor the elevator passed.
func tunDevice(s *elevator.Session) tun.Device { return tun.NewFileDevice(s.File, s.MTU) }
