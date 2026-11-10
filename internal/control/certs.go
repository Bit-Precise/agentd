package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"agentd/internal/pki"
	"agentd/internal/store"
)

// Issuer obtains a certificate for a set of names.
type Issuer interface {
	Issue(ctx context.Context, names []string) (chainPEM, keyPEM []byte, notBefore, notAfter time.Time, err error)
}

// RenewBefore is how long before expiry a certificate is renewed.
const RenewBefore = 30 * 24 * time.Hour

// CertManager keeps a wildcard certificate for every workspace (design 6.2).
type CertManager struct {
	st      *store.Store
	issuers map[string]Issuer
	zones   map[string]string // zone -> dns provider name
	def     string
	log     *slog.Logger
	onReady func(ctx context.Context, ws string)

	mu       sync.Mutex
	inflight map[string]bool
}

// NewCertManager creates a manager. issuers maps dns provider names to
// issuers and zones maps each zone to the provider whose account hosts it: a
// workspace's base domain selects the provider of the longest zone holding
// it, or def when no zone does.
func NewCertManager(st *store.Store, issuers map[string]Issuer, zones map[string]string, def string, log *slog.Logger) *CertManager {
	if issuers == nil {
		issuers = map[string]Issuer{}
	}
	if _, ok := issuers["selfsigned"]; !ok {
		issuers["selfsigned"] = &SelfSignedIssuer{Store: st}
	}
	if def == "" {
		def = "selfsigned"
	}
	if log == nil {
		log = slog.Default()
	}
	z := map[string]string{}
	for zone, p := range zones {
		z[strings.ToLower(strings.TrimSuffix(zone, "."))] = p
	}
	return &CertManager{st: st, issuers: issuers, zones: z, def: def, log: log, inflight: map[string]bool{}}
}

// ProviderFor names the dns provider that issues certificates under domain:
// the provider of the longest zone holding it, else the default.
func (m *CertManager) ProviderFor(domain string) string {
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for {
		if p, ok := m.zones[d]; ok {
			return p
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return m.def
		}
		d = d[i+1:]
	}
}

func (m *CertManager) issuerFor(ws store.Workspace) (Issuer, string, error) {
	name := m.ProviderFor(ws.BaseDomain)
	is, ok := m.issuers[name]
	if !ok {
		return nil, name, fmt.Errorf("unknown dns provider %q", name)
	}
	return is, name, nil
}

func (m *CertManager) needsRenewal(ctx context.Context, ws store.Workspace) bool {
	c, err := m.st.GetCert(ctx, ws.Name)
	if err != nil || c.State != "ready" || c.NotAfter == nil {
		return true
	}
	return time.Until(*c.NotAfter) < RenewBefore
}

// Ensure starts issuance in the background when needed (or always with force).
func (m *CertManager) Ensure(ctx context.Context, ws store.Workspace, force bool) {
	if !force && !m.needsRenewal(ctx, ws) {
		return
	}
	m.mu.Lock()
	if m.inflight[ws.Name] {
		m.mu.Unlock()
		return
	}
	m.inflight[ws.Name] = true
	m.mu.Unlock()
	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.inflight, ws.Name)
			m.mu.Unlock()
		}()
		if err := m.IssueNow(context.Background(), ws); err != nil {
			m.log.Error("certificate issuance failed", "workspace", ws.Name, "err", err)
		}
	}()
}

// IssueNow issues synchronously and records the result.
func (m *CertManager) IssueNow(ctx context.Context, ws store.Workspace) error {
	is, name, err := m.issuerFor(ws)
	if err != nil {
		_ = m.st.PutCert(ctx, store.Cert{Workspace: ws.Name, State: "failed", Issuer: name, LastError: err.Error()})
		return err
	}
	prev, _ := m.st.GetCert(ctx, ws.Name)
	state := "pending"
	if prev.State == "ready" {
		state = "renewing"
	}
	_ = m.st.PutCert(ctx, store.Cert{Workspace: ws.Name, State: state, Issuer: name})
	chain, key, nb, na, err := is.Issue(ctx, []string{"*." + ws.BaseDomain, ws.BaseDomain})
	if err != nil {
		st := "failed"
		if prev.State == "ready" {
			st = "ready" // keep serving the previous certificate
		}
		_ = m.st.PutCert(ctx, store.Cert{Workspace: ws.Name, State: st, Issuer: name, LastError: err.Error()})
		return err
	}
	if err := m.st.PutCert(ctx, store.Cert{Workspace: ws.Name, State: "ready", ChainPEM: chain, KeyPEM: key, NotBefore: &nb, NotAfter: &na, Issuer: name}); err != nil {
		return err
	}
	m.log.Info("certificate issued", "workspace", ws.Name, "issuer", name, "not_after", na)
	if m.onReady != nil {
		m.onReady(ctx, ws.Name)
	}
	return nil
}

// Loop checks every workspace hourly.
func (m *CertManager) Loop(ctx context.Context) {
	check := func() {
		wss, err := m.st.ListWorkspaces(ctx)
		if err != nil {
			return
		}
		for _, ws := range wss {
			m.Ensure(ctx, ws, false)
		}
	}
	check()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

// SelfSignedIssuer signs certificates with a local CA kept in the store. It is
// meant for development and tests: clients must trust the CA (CAPEM).
type SelfSignedIssuer struct {
	Store *store.Store
	mu    sync.Mutex
}

// CAPEM returns the CA certificate and key, creating them on first use.
func (s *SelfSignedIssuer) CAPEM(ctx context.Context) (certPEM, keyPEM []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	certPEM, keyPEM, err = s.Store.CA(ctx)
	if errors.Is(err, store.ErrNotFound) {
		certPEM, keyPEM, err = pki.NewCA("agentd local CA")
		if err != nil {
			return nil, nil, err
		}
		if err := s.Store.SetCA(ctx, certPEM, keyPEM); err != nil {
			return nil, nil, err
		}
		return s.Store.CA(ctx)
	}
	return certPEM, keyPEM, err
}

// Issue signs a 90-day certificate for names; the chain includes the CA.
func (s *SelfSignedIssuer) Issue(ctx context.Context, names []string) ([]byte, []byte, time.Time, time.Time, error) {
	caPEM, caKey, err := s.CAPEM(ctx)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, err
	}
	certPEM, keyPEM, nb, na, err := pki.SignLeaf(caPEM, caKey, names, nil, 90*24*time.Hour)
	if err != nil {
		return nil, nil, nb, na, err
	}
	return append(certPEM, caPEM...), keyPEM, nb, na, nil
}
