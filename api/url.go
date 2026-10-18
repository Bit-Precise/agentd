package api

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/bit-precise/agentd/policy"
)

// ParseURL validates Control, Edge and serve origin URLs. plainHTTP permits an
// http origin on any host; loopbackHTTP permits http only for loopback hosts.
func ParseURL(raw, field string, rootOnly, plainHTTP, loopbackHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid URL: %w", field, err)
	}
	localHTTP := loopbackHTTP && u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback())
	if u.Scheme != "https" && !(plainHTTP && u.Scheme == "http") && !localHTTP {
		return nil, fmt.Errorf("%s: HTTPS required (serve origins also support HTTP)", field)
	}
	if u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%s: URL requires a host and must not include credentials, query or fragment", field)
	}
	if rootOnly && u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("%s: URL path must be empty or /", field)
	}
	host := u.Hostname()
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("%s: scoped IP addresses are unsupported", field)
		}
	} else if _, err := policy.CanonicalDomain(host); err != nil {
		return nil, fmt.Errorf("%s: invalid host: %w", field, err)
	}
	if port := u.Port(); port != "" {
		if _, err := StrictPort(port); err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("%s: empty port", field)
	}
	return u, nil
}

// StrictPort accepts only plain decimal ports between 1 and 65535.
func StrictPort(s string) (int, error) {
	if s == "" {
		return 0, errors.New("port must be an integer between 1 and 65535")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("port must be an integer between 1 and 65535")
		}
	}
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("port must be an integer between 1 and 65535")
	}
	return port, nil
}
