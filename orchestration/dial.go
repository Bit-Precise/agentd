package orchestration

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// dialTarget resolves once, checks every candidate, and dials those same IPs.
// RFC1918/ULA destinations are intentional for enterprise/campus egress;
// loopback, link-local (including metadata), multicast and unspecified are not.
func dialTarget(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return nil, errors.New("invalid target port")
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var last error = errors.New("no permitted DNS result")
	for _, ip := range addresses {
		ip = ip.Unmap()
		if forbiddenIP(ip) {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

func forbiddenIP(ip netip.Addr) bool {
	return !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || !ip.IsGlobalUnicast()
}
