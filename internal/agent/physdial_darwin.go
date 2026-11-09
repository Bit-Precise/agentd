package agent

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"

	"agentd/internal/elevator"
)

// physicalDialer pins agentd's own sockets to the physical interface
// (IP_BOUND_IF) so they bypass the TUN routes.
func physicalDialer(p elevator.Physical) *net.Dialer {
	idx := p.Index
	return &net.Dialer{KeepAlive: 30e9, Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if network == "tcp6" || network == "udp6" {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
			} else {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
}

func physicalNetwork(network string, p elevator.Physical) string { return network }

func physicalLocal(network string, p elevator.Physical) net.Addr { return nil }
