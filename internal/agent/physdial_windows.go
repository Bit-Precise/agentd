//go:build windows

package agent

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"

	"agentd/internal/elevator"
)

// Socket options that pin a socket to an interface (ws2ipdef.h).
const (
	ipUnicastIF   = 31
	ipv6UnicastIF = 31
)

// physicalDialer pins agentd's own sockets to the physical interface so they
// bypass the TUN routes. IPv4 takes the index in network byte order.
func physicalDialer(p elevator.Physical) *net.Dialer {
	idx := uint32(p.Index)
	return &net.Dialer{KeepAlive: 30e9, Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			h := windows.Handle(fd)
			if network == "tcp6" || network == "udp6" {
				serr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIF, int(idx))
			} else {
				be := idx>>24 | (idx>>8)&0xff00 | (idx<<8)&0xff0000 | idx<<24
				serr = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIF, int(be))
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
