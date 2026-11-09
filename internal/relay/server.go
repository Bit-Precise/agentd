package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"google.golang.org/protobuf/proto"

	"agentd/internal/identity"
	"agentd/internal/tlsutil"
	"agentd/internal/transport"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// Server is a configured agentrelay process.
type Server struct {
	Config  *Config
	Key     ed25519.PrivateKey
	Backend *Backend
	Hub     *Hub
	Edge    *Edge
	TLS     *tlsutil.Source

	log      *slog.Logger
	certs    *certStore
	ln       net.Listener
	httpLn   net.Listener
	stunPC   net.PacketConn
	relayLn  *chanListener
	relaySrv *http.Server
	own      map[string]bool
}

// Options adjust NewServer for embedding (tests, sim).
type Options struct {
	Logger *slog.Logger
	Key    ed25519.PrivateKey // instead of key_file
	// ControlDial overrides how agentserver is reached (tests).
	ControlDial transport.Options
}

// NewServer loads keys, prepares TLS and binds the listeners.
func NewServer(cfg *Config, o Options) (*Server, error) {
	lg := o.Logger
	if lg == nil {
		lg = slog.Default()
	}
	key := o.Key
	if key == nil && cfg.KeyEnv != "" && os.Getenv(cfg.KeyEnv) != "" {
		k, err := identity.ParseKey([]byte(os.Getenv(cfg.KeyEnv)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", cfg.KeyEnv, err)
		}
		key = k
	}
	if key == nil {
		var created bool
		var err error
		if err := os.MkdirAll(dirOf(cfg.KeyFile), 0o700); err != nil {
			return nil, err
		}
		if key, created, err = identity.LoadOrCreateKey(cfg.KeyFile); err != nil {
			return nil, err
		}
		if created {
			lg.Info("generated relay key", "file", cfg.KeyFile)
		}
	}
	src, err := tlsutil.New(cfg.TLS, tlsutil.Options{Names: []string{cfg.Domain}})
	if err != nil {
		return nil, err
	}
	dial := o.ControlDial
	if dial.RootCAs == nil {
		pool, err := tlsutil.RootsWithExtra("AGENTD_EXTRA_ROOTS")
		if err != nil {
			return nil, err
		}
		if err := tlsutil.AddPEMFile(pool, cfg.Control.CAFile); err != nil {
			return nil, err
		}
		dial.RootCAs = pool
	}
	var serverKey []byte
	if cfg.Control.PublicKey != "" {
		serverKey, _ = identity.DecodeKey(cfg.Control.PublicKey)
	}
	stun := ""
	if cfg.STUN != "" {
		_, port, _ := net.SplitHostPort(cfg.STUN)
		stun = net.JoinHostPort(cfg.Domain, port)
	}
	s := &Server{Config: cfg, Key: key, TLS: src, log: lg, certs: newCertStore(), relayLn: newChanListener(), own: map[string]bool{}}
	for _, n := range src.Names {
		s.own[n] = true
	}
	s.Backend = &Backend{Key: key, ServerURL: cfg.Control.URL, ServerKey: serverKey, Transport: transport.Kind(cfg.Control.Transport), DialOpts: dial,
		Hello: &pb.RelayRegistration{Name: cfg.Name, Url: cfg.URL, Transports: cfg.Transports, Stun: stun}, JoinToken: os.Getenv(cfg.Control.JoinTokenEnv),
		CacheTTL: cfg.Cache.TTL, Log: lg, cache: newAnswerCache(cfg.Cache.MaxEntries)}
	s.Backend.OnCerts = s.certs.putCerts
	s.Backend.OnRelayCert = s.certs.putRelayCert
	s.certs.lookup = func(ctx context.Context, base string) {
		a, err := s.Backend.Lookup(ctx, &pb.RelayLookup{Query: &pb.RelayLookup_Cert{Cert: &pb.CertLookup{Workspace: base}}}, direct)
		if err == nil && a.GetCerts() != nil {
			s.certs.putCerts(a.GetCerts())
		}
	}
	s.Hub = NewHub(key, s.Backend, lg)
	s.Edge = newEdge(s.Hub, key, s.certs, lg)

	mux := http.NewServeMux()
	if p := cfg.Transports["ws"]; p != "" {
		mux.Handle(p, transport.WSHandler(s.Hub.ServeNode))
	}
	if p := cfg.Transports["httpupgrade"]; p != "" {
		mux.Handle(p, transport.UpgradeHandler(s.Hub.ServeNode))
	}
	if p := cfg.Transports["xhttp"]; p != "" {
		mux.Handle(p+"/", transport.XHTTPHandler(p+"/", s.Hub.ServeNode))
	}
	mux.HandleFunc("/.well-known/agentd", s.wellKnown)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !s.Backend.Connected() {
			http.Error(w, "control session down", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", http.NotFound)
	s.relaySrv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	if s.ln, err = net.Listen("tcp", cfg.Listen); err != nil {
		return nil, err
	}
	if cfg.HTTPListen != "" {
		if s.httpLn, err = net.Listen("tcp", cfg.HTTPListen); err != nil {
			s.ln.Close()
			return nil, err
		}
	}
	if cfg.STUN != "" {
		if s.stunPC, err = net.ListenPacket("udp", cfg.STUN); err != nil {
			s.ln.Close()
			return nil, err
		}
	}
	return s, nil
}

func dirOf(p string) string {
	i := strings.LastIndexAny(p, `/\`)
	if i <= 0 {
		return "."
	}
	return p[:i]
}

// Addr is the bound TLS address.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// PublicKey is the relay's public key.
func (s *Server) PublicKey() []byte { return identity.Public(s.Key) }

func (s *Server) wellKnown(w http.ResponseWriter, r *http.Request) {
	ws := strings.ToLower(r.URL.Query().Get("workspace"))
	c := s.certs.relayCert(ws)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	b, _ := proto.Marshal(c)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"relay_cert": base64.RawURLEncoding.EncodeToString(b),
		"protocol":   map[string]int{"major": 1, "min": wire.MinorVersion, "max": wire.MinorVersion},
		"transports": s.Config.Transports,
	})
}

// tlsConfig dispatches by SNI: the relay's own name (or none) gets the
// relay certificate; a served workspace's service names get its wildcard
// certificate; anything else fails the handshake.
func (s *Server) tlsConfig() *tls.Config {
	own := s.TLS.TLSConfig(nil)
	edge := s.Edge.tlsConfig()
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni := strings.ToLower(h.ServerName)
			if sni == "" || s.own[sni] || s.TLS.IsChallenge(h) {
				return own, nil
			}
			if s.certs.baseFor(sni) != "" {
				return edge, nil
			}
			return nil, errors.New("unknown server name")
		},
	}
}

func (s *Server) handleConn(raw net.Conn, cfg *tls.Config) {
	c := tls.Server(raw, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := c.HandshakeContext(ctx)
	cancel()
	if err != nil {
		raw.Close()
		return
	}
	st := c.ConnectionState()
	if st.NegotiatedProtocol == acme.ALPNProto {
		c.Close()
		return
	}
	sni := strings.ToLower(st.ServerName)
	if sni == "" || s.own[sni] {
		if !s.relayLn.push(c) {
			c.Close()
		}
		return
	}
	s.Edge.ServePublic(c)
}

// Run serves until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	go s.Backend.Run(ctx)
	go s.Edge.sweep(ctx)
	errc := make(chan error, 4)
	go func() { errc <- s.relaySrv.Serve(s.relayLn) }()
	go func() { errc <- s.Edge.run() }()
	cfg := s.tlsConfig()
	go func() {
		for {
			raw, err := s.ln.Accept()
			if err != nil {
				errc <- err
				return
			}
			go s.handleConn(raw, cfg)
		}
	}()
	var redirect *http.Server
	if s.httpLn != nil {
		redirect = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+hostOnly(r.Host)+r.URL.RequestURI(), http.StatusMovedPermanently)
		})}
		go func() { errc <- redirect.Serve(s.httpLn) }()
	}
	if s.stunPC != nil {
		go serveSTUN(s.stunPC)
	}
	s.log.Info("agentrelay running", "name", s.Config.Name, "listen", s.ln.Addr().String(), "url", s.Config.URL,
		"identity", identity.EncodeKey(s.PublicKey()), "control", s.Config.Control.URL)
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	s.Hub.Shutdown()
	s.ln.Close()
	s.relayLn.Close()
	s.Edge.ln.Close()
	s.Edge.close()
	s.relaySrv.Close()
	if redirect != nil {
		redirect.Close()
	}
	if s.stunPC != nil {
		s.stunPC.Close()
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
