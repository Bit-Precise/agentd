package agent

import (
	"net"

	"agentd/internal/elevator"
)

// physicalControl binds agentd's own IPv4 sockets to the physical address;
// the elevator's policy rule routes that source around the TUN.
func physicalDialer(p elevator.Physical) *net.Dialer {
	return &net.Dialer{KeepAlive: 30e9}
}

func physicalNetwork(network string, p elevator.Physical) string {
	if p.IPv4 == "" {
		return network
	}
	switch network {
	case "tcp":
		return "tcp4"
	case "udp":
		return "udp4"
	}
	return network
}

func physicalLocal(network string, p elevator.Physical) net.Addr {
	ip := net.ParseIP(p.IPv4)
	if ip == nil {
		return nil
	}
	if network == "udp" || network == "udp4" {
		return &net.UDPAddr{IP: ip}
	}
	return &net.TCPAddr{IP: ip}
}
