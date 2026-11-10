package control

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"agentd/internal/identity"
	"agentd/internal/pki"
	"agentd/internal/store"
	"agentd/internal/tlsutil"
)

// Server is a configured agentserver process: the relay-session listener
// (TLS) and the admin listener (API and console).
type Server struct {
	Config      *ServerConfig
	Store       *store.Store
	Coordinator *Coordinator
	Certs       *CertManager
	TLS         *tlsutil.Source

	log      *slog.Logger
	token    string
	ui       http.Handler
	relayLn  net.Listener
	adminLn  net.Listener
	ownStore bool
}

// ServerOptions adjust NewServer for embedding (tests, sim).
type ServerOptions struct {
	Logger *slog.Logger
	Store  *store.Store // use this store instead of opening Database
	UI     http.Handler // web console served at the admin root
	// Issuers replace the issuers built from dns_providers.
	Issuers map[string]Issuer
}

// NewServer opens the state, loads keys and binds both listeners.
func NewServer(ctx context.Context, cfg *ServerConfig, o ServerOptions) (*Server, error) {
	lg := o.Logger
	if lg == nil {
		lg = slog.Default()
	}
	token, err := cfg.AdminToken()
	if err != nil {
		return nil, err
	}
	s := &Server{Config: cfg, log: lg, token: token, ui: o.UI, Store: o.Store}
	if s.Store == nil {
		url, err := cfg.DatabaseURL()
		if err != nil {
			return nil, err
		}
		if s.Store, err = openWithRetry(ctx, url, cfg.StateKey(), lg); err != nil {
			return nil, err
		}
		s.ownStore = true
	}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()

	var key ed25519.PrivateKey
	if cfg.KeyFile != "" {
		var created bool
		if key, created, err = identity.LoadOrCreateKey(cfg.KeyFile); err != nil {
			return nil, err
		}
		if created {
			lg.Info("generated server key", "file", cfg.KeyFile)
		}
	} else if key, err = s.Store.ServerKey(ctx); err != nil {
		return nil, err
	}

	if c := cfg.SelfSignedCA; c.CertFile != "" {
		certPEM, err := os.ReadFile(c.CertFile)
		if err != nil {
			return nil, err
		}
		keyPEM, err := os.ReadFile(c.KeyFile)
		if err != nil {
			return nil, err
		}
		if _, _, err := pki.ParseCertKey(certPEM, keyPEM); err != nil {
			return nil, fmt.Errorf("selfsigned_ca: %w", err)
		}
		if err := s.Store.SetCA(ctx, certPEM, keyPEM); err != nil {
			return nil, err
		}
	}
	self := &SelfSignedIssuer{Store: s.Store}
	issuers := o.Issuers
	if issuers == nil {
		if issuers, err = dnsIssuers(cfg, s.Store, self); err != nil {
			return nil, err
		}
	}
	s.Certs = NewCertManager(s.Store, issuers, cfg.DNSZones(), cfg.DefaultDNSProvider, lg)
	bootstrap := ""
	if cfg.RelayJoinTokenEnv != "" {
		bootstrap = os.Getenv(cfg.RelayJoinTokenEnv)
		if bootstrap != "" && len(bootstrap) < 16 {
			return nil, fmt.Errorf("%s must be at least 16 characters", cfg.RelayJoinTokenEnv)
		}
	}
	s.Coordinator = New(Options{Store: s.Store, ServerKey: key, Certs: s.Certs, Logger: lg, RelayBootstrapToken: bootstrap, RelayCertTTL: cfg.RelayCertTTL})

	s.TLS, err = tlsutil.New(cfg.TLS, tlsutil.Options{
		Names: []string{cfg.Domain},
		Cache: autocertCache{s.Store},
		SelfSigned: func(names []string) (tls.Certificate, []byte, error) {
			caPEM, caKey, err := self.CAPEM(ctx)
			if err != nil {
				return tls.Certificate{}, nil, err
			}
			var dns, ips []string
			for _, n := range names {
				if net.ParseIP(n) != nil {
					ips = append(ips, n)
				} else {
					dns = append(dns, n)
				}
			}
			certPEM, keyPEM, _, _, err := pki.SignLeaf(caPEM, caKey, dns, ips, 365*24*time.Hour)
			if err != nil {
				return tls.Certificate{}, nil, err
			}
			c, err := tls.X509KeyPair(append(certPEM, caPEM...), keyPEM)
			return c, caPEM, err
		},
	})
	if err != nil {
		return nil, err
	}
	if s.relayLn, err = net.Listen("tcp", cfg.Listen); err != nil {
		return nil, err
	}
	if s.adminLn, err = net.Listen("tcp", cfg.AdminListen); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

// openWithRetry waits up to two minutes for the database (it may start after
// agentserver, as in Kubernetes).
func openWithRetry(ctx context.Context, url string, key []byte, lg *slog.Logger) (*store.Store, error) {
	deadline := time.Now().Add(2 * time.Minute)
	delay := time.Second
	for {
		st, err := store.Open(ctx, url, key)
		if err == nil {
			return st, nil
		}
		var ne *net.OpError
		retry := errors.As(err, &ne) || strings.Contains(err.Error(), "connect to postgres")
		if !retry || time.Now().After(deadline) {
			return nil, err
		}
		lg.Warn("waiting for the database", "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		if delay < 5*time.Second {
			delay *= 2
		}
	}
}

// RelayAddr is the bound relay-session address.
func (s *Server) RelayAddr() net.Addr { return s.relayLn.Addr() }

// AdminAddr is the bound admin address.
func (s *Server) AdminAddr() net.Addr { return s.adminLn.Addr() }

// PublicKey is agentserver's public key.
func (s *Server) PublicKey() []byte { return s.Coordinator.PublicKey() }

// Close releases listeners and the store.
func (s *Server) Close() {
	if s.relayLn != nil {
		s.relayLn.Close()
	}
	if s.adminLn != nil {
		s.adminLn.Close()
	}
	if s.ownStore && s.Store != nil {
		s.Store.Close()
	}
}

// Run serves until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	defer s.Close()
	errLog := log.New(&slogWriter{s.log}, "", 0)
	relaySrv := &http.Server{Handler: s.Coordinator.RelayHandler(s.Config.Transports), TLSConfig: s.TLS.TLSConfig(nil), ReadHeaderTimeout: 10 * time.Second, ErrorLog: errLog}
	admin := &Admin{C: s.Coordinator, Domain: s.Config.Domain}
	adminSrv := &http.Server{Handler: admin.Handler(s.token, s.ui), ReadHeaderTimeout: 10 * time.Second, ErrorLog: errLog}

	go s.Coordinator.RenewLoop(ctx)
	go s.Certs.Loop(ctx)

	errc := make(chan error, 2)
	go func() { errc <- relaySrv.ServeTLS(s.relayLn, "", "") }()
	go func() { errc <- adminSrv.Serve(s.adminLn) }()
	s.log.Info("agentserver running", "relay_listen", s.relayLn.Addr().String(), "admin_listen", s.adminLn.Addr().String(),
		"identity", identity.EncodeKey(s.PublicKey()), "domain", s.Config.Domain, "tls", s.Config.TLS.Mode)

	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relaySrv.Shutdown(sctx)
	adminSrv.Shutdown(sctx)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}

// autocertCache keeps agentserver's ACME state in Postgres.
type autocertCache struct{ st *store.Store }

func (a autocertCache) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := a.st.CacheGet(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	return b, err
}
func (a autocertCache) Put(ctx context.Context, key string, data []byte) error {
	return a.st.CachePut(ctx, key, data)
}
func (a autocertCache) Delete(ctx context.Context, key string) error {
	return a.st.CacheDelete(ctx, key)
}

// slogWriter routes net/http's error log to slog at debug level (TLS
// handshake noise from scanners would otherwise flood the log).
type slogWriter struct{ l *slog.Logger }

func (w *slogWriter) Write(p []byte) (int, error) {
	w.l.Debug(string(trimNL(p)))
	return len(p), nil
}

func trimNL(p []byte) []byte {
	for len(p) > 0 && (p[len(p)-1] == '\n' || p[len(p)-1] == '\r') {
		p = p[:len(p)-1]
	}
	return p
}

// dnsIssuers builds the workspace certificate issuers named by
// dns_providers; "selfsigned" always exists.
func dnsIssuers(cfg *ServerConfig, st *store.Store, self Issuer) (map[string]Issuer, error) {
	issuers := map[string]Issuer{"selfsigned": self}
	for name, p := range cfg.DNSProviders {
		env := func(v string) (string, error) {
			if val := os.Getenv(v); val != "" {
				return val, nil
			}
			return "", fmt.Errorf("dns provider %s: %s is empty", name, v)
		}
		var dns DNSClient
		switch p.Provider {
		case "selfsigned":
			issuers[name] = self
			continue
		case "cloudflare":
			tok, err := env(p.TokenEnv)
			if err != nil {
				return nil, err
			}
			dns = &CloudflareClient{Token: tok}
		case "dnspod":
			id, err := env(p.SecretIDEnv)
			if err != nil {
				return nil, err
			}
			key, err := env(p.SecretKeyEnv)
			if err != nil {
				return nil, err
			}
			dns = &DNSPodClient{SecretID: id, SecretKey: key}
		default:
			return nil, fmt.Errorf("dns provider %s: unknown provider %q", name, p.Provider)
		}
		is := &ACMEIssuer{Store: st, Directory: p.Directory, Email: p.Email, DNS: dns, PropagationWait: p.PropagationWait}
		if p.EABKeyIDEnv != "" {
			kid, err := env(p.EABKeyIDEnv)
			if err != nil {
				return nil, err
			}
			hmacKey, err := env(p.EABHMACKeyEnv)
			if err != nil {
				return nil, err
			}
			key, err := DecodeEABKey(hmacKey)
			if err != nil {
				return nil, fmt.Errorf("dns provider %s: %s: %w", name, p.EABHMACKeyEnv, err)
			}
			is.EAB = &acme.ExternalAccountBinding{KID: kid, Key: key}
		}
		if p.AccountKeyEnv != "" {
			pemKey, err := env(p.AccountKeyEnv)
			if err != nil {
				return nil, err
			}
			if is.AccountKey, err = ParseACMEAccountKey([]byte(pemKey)); err != nil {
				return nil, fmt.Errorf("dns provider %s: %s: %w", name, p.AccountKeyEnv, err)
			}
		}
		issuers[name] = is
	}
	return issuers, nil
}
