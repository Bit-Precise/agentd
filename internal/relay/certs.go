package relay

import (
	"context"
	"crypto/tls"
	"strings"
	"sync"
	"time"

	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// certStore keeps, in memory only, the workspace wildcard certificates and
// this relay's per-workspace relay certificates pushed by agentserver.
type certStore struct {
	mu     sync.RWMutex
	ws     map[string]*tls.Certificate            // base domain -> wildcard cert
	relay  map[string]*pb.RelayCert               // base domain -> relay cert
	lookup func(ctx context.Context, base string) // asks agentserver for a missing cert
}

func newCertStore() *certStore {
	return &certStore{ws: map[string]*tls.Certificate{}, relay: map[string]*pb.RelayCert{}}
}

func (s *certStore) putCerts(c *pb.WorkspaceCerts) {
	for _, wc := range c.Certs {
		cert, err := tls.X509KeyPair(wc.CertChainPem, wc.KeyPem)
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.ws[strings.ToLower(wc.Workspace)] = &cert
		s.mu.Unlock()
	}
}

func (s *certStore) putRelayCert(c *pb.RelayCert) {
	body, err := wire.DecodeRelayCert(c)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.relay[strings.ToLower(body.Workspace)] = c
	s.mu.Unlock()
}

func (s *certStore) relayCert(base string) *pb.RelayCert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.relay[strings.ToLower(base)]
	if c == nil {
		return nil
	}
	if b, err := wire.DecodeRelayCert(c); err != nil || time.Unix(int64(b.ExpiresAt), 0).Before(time.Now()) {
		return nil
	}
	return c
}

// baseFor maps a service name to the workspace base domain it belongs to:
// the wildcard covers exactly one label below the base domain.
func (s *certStore) baseFor(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	_, base, ok := strings.Cut(host, ".")
	if !ok {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.relay[base]; ok {
		return base
	}
	if _, ok := s.ws[base]; ok {
		return base
	}
	return ""
}

// cert returns the wildcard certificate for a service name, asking
// agentserver once when it is missing.
func (s *certStore) cert(host string) *tls.Certificate {
	base := s.baseFor(host)
	if base == "" {
		return nil
	}
	s.mu.RLock()
	c := s.ws[base]
	s.mu.RUnlock()
	if c == nil && s.lookup != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		s.lookup(ctx, base)
		cancel()
		s.mu.RLock()
		c = s.ws[base]
		s.mu.RUnlock()
	}
	return c
}
