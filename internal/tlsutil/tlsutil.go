// Package tlsutil builds the server certificates of agentserver and
// agentrelay from the shared `tls` configuration block: ACME (TLS-ALPN-01 on
// the listener itself), certificate files reloaded on change, or a
// self-signed chain for development. There is no option to skip
// verification anywhere; clients trust extra roots explicitly instead.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Config is the `tls` block.
type Config struct {
	Mode      string   `yaml:"mode"`      // acme | file | selfsigned
	CertFile  string   `yaml:"cert_file"` // file mode: PEM chain
	KeyFile   string   `yaml:"key_file"`  // file mode: PEM key
	Email     string   `yaml:"email"`     // acme mode: account contact
	Directory string   `yaml:"directory"` // acme mode: directory URL (default Let's Encrypt)
	CacheDir  string   `yaml:"cache_dir"` // acme mode on agentrelay: certificate cache
	CAOut     string   `yaml:"ca_out"`    // selfsigned mode: write the CA certificate here
	Names     []string `yaml:"names"`     // extra DNS names or IPs for the certificate
}

// Validate checks the block.
func (c Config) Validate() error {
	switch c.Mode {
	case "acme", "selfsigned":
	case "file":
		if c.CertFile == "" || c.KeyFile == "" {
			return errors.New("tls.mode file needs cert_file and key_file")
		}
	case "":
		return errors.New("tls.mode is required (acme, file or selfsigned)")
	default:
		return fmt.Errorf("tls.mode must be acme, file or selfsigned, got %q", c.Mode)
	}
	return nil
}

// Options supply what the modes need beyond the block.
type Options struct {
	Names []string // the server's own names (domain first)
	// Cache stores ACME state; nil uses CacheDir (or memory when that is empty).
	Cache autocert.Cache
	// SelfSigned issues the development chain; nil makes an ephemeral CA.
	SelfSigned func(names []string) (cert tls.Certificate, caPEM []byte, err error)
}

// Source yields the server's own certificate.
type Source struct {
	get   func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	acme  *autocert.Manager
	CAPEM []byte // the CA in selfsigned mode
	Names []string
}

// New builds a Source.
func New(c Config, o Options) (*Source, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	names := dedupe(append(append([]string{}, o.Names...), c.Names...))
	s := &Source{Names: names}
	switch c.Mode {
	case "file":
		f := &fileCert{cert: c.CertFile, key: c.KeyFile}
		if _, err := f.load(); err != nil {
			return nil, err
		}
		s.get = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return f.load() }
	case "selfsigned":
		mk := o.SelfSigned
		if mk == nil {
			mk = ephemeral
		}
		cert, caPEM, err := mk(names)
		if err != nil {
			return nil, err
		}
		s.CAPEM = caPEM
		if c.CAOut != "" {
			if err := os.WriteFile(c.CAOut, caPEM, 0o644); err != nil {
				return nil, fmt.Errorf("write tls.ca_out: %w", err)
			}
		}
		s.get = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
	case "acme":
		var dnsNames []string
		for _, n := range names {
			if !isIP(n) {
				dnsNames = append(dnsNames, n)
			}
		}
		if len(dnsNames) == 0 {
			return nil, errors.New("tls.mode acme needs a domain name")
		}
		cache := o.Cache
		if cache == nil && c.CacheDir != "" {
			if err := os.MkdirAll(c.CacheDir, 0o700); err != nil {
				return nil, err
			}
			cache = autocert.DirCache(c.CacheDir)
		}
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(dnsNames...), Cache: cache, Email: c.Email}
		if c.Directory != "" {
			m.Client = &acme.Client{DirectoryURL: c.Directory}
		}
		s.acme = m
		s.get = m.GetCertificate
	}
	return s, nil
}

// GetCertificate returns the server certificate.
func (s *Source) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return s.get(h) }

// IsChallenge reports whether a handshake is an ACME TLS-ALPN-01 probe.
func (s *Source) IsChallenge(h *tls.ClientHelloInfo) bool {
	if s.acme == nil {
		return false
	}
	for _, p := range h.SupportedProtos {
		if p == acme.ALPNProto {
			return true
		}
	}
	return false
}

// TLSConfig returns a server config; extra, when set, is consulted first
// (agentrelay serves workspace certificates for service domains with it).
func (s *Source) TLSConfig(extra func(*tls.ClientHelloInfo) *tls.Certificate) *tls.Config {
	protos := []string{"http/1.1"}
	if s.acme != nil {
		protos = append(protos, acme.ALPNProto)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: protos,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if extra != nil && !s.IsChallenge(h) {
				if c := extra(h); c != nil {
					return c, nil
				}
			}
			return s.get(h)
		},
	}
}

// fileCert reloads a key pair when either file changes (cert-manager and
// certbot rotate files in place).
type fileCert struct {
	cert, key string
	mu        sync.Mutex
	mod       time.Time
	checked   time.Time
	c         *tls.Certificate
}

func (f *fileCert) load() (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.c != nil && time.Since(f.checked) < 10*time.Second {
		return f.c, nil
	}
	f.checked = time.Now()
	mod, err := newest(f.cert, f.key)
	if err != nil {
		if f.c != nil {
			return f.c, nil
		}
		return nil, err
	}
	if f.c != nil && mod.Equal(f.mod) {
		return f.c, nil
	}
	c, err := tls.LoadX509KeyPair(f.cert, f.key)
	if err != nil {
		if f.c != nil {
			return f.c, nil
		}
		return nil, fmt.Errorf("load tls key pair: %w", err)
	}
	f.c, f.mod = &c, mod
	return f.c, nil
}

func newest(paths ...string) (time.Time, error) {
	var t time.Time
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return t, err
		}
		if st.ModTime().After(t) {
			t = st.ModTime()
		}
	}
	return t, nil
}

func isIP(s string) bool { return net.ParseIP(s) != nil }

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// RootsWithExtra returns the system roots plus PEM files listed in an
// environment variable (comma or path-list separated). Verification stays on;
// this only adds trust anchors for private deployments.
func RootsWithExtra(env string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	v := os.Getenv(env)
	if v == "" {
		return pool, nil
	}
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == os.PathListSeparator }) {
		pem, err := os.ReadFile(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", env, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates in %s", env, p)
		}
	}
	return pool, nil
}

// AddPEMFile appends the certificates of a PEM file to a pool.
func AddPEMFile(pool *x509.CertPool, path string) error {
	if path == "" {
		return nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("no certificates in %s", path)
	}
	return nil
}
