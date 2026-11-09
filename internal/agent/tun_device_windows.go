//go:build windows

package agent

import (
	"agentd/internal/elevator"
	"agentd/internal/tun"
)

// tunDevice is the elevator's packet relay (wintun sessions stay in the
// elevator process).
func tunDevice(s *elevator.Session) tun.Device { return s.Dev }
