package tlsutil

import (
	"crypto/tls"
	"net"

	"agentd/internal/pki"
)

func ephemeral(names []string) (tls.Certificate, []byte, error) {
	var dns, ips []string
	for _, n := range names {
		if net.ParseIP(n) != nil {
			ips = append(ips, n)
		} else {
			dns = append(dns, n)
		}
	}
	return pki.SelfSigned(dns, ips)
}
