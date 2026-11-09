package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"agentd/internal/identity"
	"agentd/internal/session"
	"agentd/internal/stream"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// peerInfo is who is on the other end of an edge connection; id is empty
// for anonymous visitors on the public 443.
type peerInfo struct {
	id     []byte
	name   string
	ws     string // set for members: their workspace
	remote string
}

type peerKey struct{}

// Edge terminates TLS for HTTP services and reverse-proxies each request to
// the service node over a stream the relay signs (protocol 6.3).
type Edge struct {
	hub   *Hub
	key   ed25519.PrivateKey
	pub   []byte
	certs *certStore
	log   *slog.Logger

	ln    *chanListener
	srv   *http.Server
	conns sync.Map // net.Conn -> *peerInfo

	tmu        sync.Mutex
	transports map[string]*edgeTransport
}

type edgeTransport struct {
	rt   *http.Transport
	used time.Time
}

func newEdge(hub *Hub, key ed25519.PrivateKey, certs *certStore, log *slog.Logger) *Edge {
	e := &Edge{hub: hub, key: key, pub: identity.Public(key), certs: certs, log: log, ln: newChanListener(), transports: map[string]*edgeTransport{}}
	e.srv = &http.Server{
		Handler:           e,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		TLSConfig:         &tls.Config{NextProtos: []string{"h2", "http/1.1"}},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if p, ok := e.conns.Load(c); ok {
				return context.WithValue(ctx, peerKey{}, p)
			}
			return ctx
		},
		ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				e.conns.Delete(c)
			}
		},
		ErrorLog: nil,
	}
	hub.edge = e
	return e
}

// tlsConfig serves workspace wildcard certificates only.
func (e *Edge) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := e.certs.cert(h.ServerName); c != nil {
				return c, nil
			}
			return nil, errors.New("no certificate for " + h.ServerName)
		},
	}
}

func (e *Edge) run() error { return e.srv.Serve(e.ln) }

func (e *Edge) close() {
	e.srv.Close()
	e.tmu.Lock()
	for _, t := range e.transports {
		t.rt.CloseIdleConnections()
	}
	e.tmu.Unlock()
}

// ServePublic takes a TLS connection from the public listener whose
// handshake already selected a workspace certificate.
func (e *Edge) ServePublic(c *tls.Conn) {
	e.conns.Store(c, &peerInfo{remote: c.RemoteAddr().String()})
	if !e.ln.push(c) {
		c.Close()
	}
}

// ServeMember takes the first leg of a member's stream (already Acked) and
// terminates TLS on it.
func (e *Edge) ServeMember(st *session.Stream, p *peerInfo) {
	c := tls.Server(st, e.tlsConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.HandshakeContext(ctx); err != nil {
		st.Reset()
		return
	}
	p.remote = "agentd:" + p.name
	e.conns.Store(c, p)
	if !e.ln.push(c) {
		c.Close()
	}
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// ServeHTTP authorizes each request with the control plane (cached) and
// proxies it.
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(peerKey{}).(*peerInfo)
	if p == nil {
		p = &peerInfo{}
	}
	host := hostOnly(r.Host)
	base := e.certs.baseFor(host)
	if base == "" || (p.ws != "" && base != p.ws) {
		page(w, http.StatusMisdirectedRequest, "Misdirected request", "This host is not served on this connection.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), LookupTimeout+time.Second)
	a, err := e.hub.backend.Lookup(ctx, &pb.RelayLookup{Query: &pb.RelayLookup_Stream{Stream: &pb.StreamLookup{
		Workspace: base, From: p.id, Kind: pb.Kind_KIND_TCP, Proto: pb.Proto_PROTO_TLS, Domain: host, Port: 443}}}, cached)
	cancel()
	if err != nil {
		page(w, http.StatusServiceUnavailable, "Temporarily unavailable", "The control plane cannot be reached. Try again shortly.")
		return
	}
	route := a.GetRoute()
	switch {
	case a.Status == pb.Status_SERVICE_UNKNOWN:
		page(w, http.StatusNotFound, "Not found", "There is no service with this name.")
		return
	case a.Status == pb.Status_SERVICE_NOT_READY:
		page(w, http.StatusServiceUnavailable, "Not ready", "This service is not ready yet.")
		return
	case a.Status != pb.Status_OK || route == nil || route.TargetKind != pb.StreamRoute_EDGE:
		page(w, http.StatusForbidden, "Access denied", "You are not allowed to use this service.")
		return
	}
	if e.hub.session(route.Target) == nil {
		page(w, http.StatusBadGateway, "Service offline", "The node that provides this service is not connected.")
		return
	}
	rt := e.transport(base, host, route.Target, p)
	proxy := &httputil.ReverseProxy{
		Transport: rt,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = host
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Del("X-Agentd-Peer")
			pr.Out.Header.Del("X-Agentd-Peer-Key")
			pr.SetXForwarded()
			if len(p.id) > 0 {
				pr.Out.Header.Set("X-Agentd-Peer", p.name)
				pr.Out.Header.Set("X-Agentd-Peer-Key", identity.EncodeKey(p.id))
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			e.log.Debug("edge proxy error", "host", host, "err", err)
			page(w, http.StatusBadGateway, "Bad gateway", "The service did not respond.")
		},
	}
	proxy.ServeHTTP(w, r)
}

// transport returns the HTTP/1.1 connection pool for (service, target,
// peer); each pooled connection is a stream signed by the relay that names
// the peer in http_peer.
func (e *Edge) transport(base, fqdn string, target []byte, p *peerInfo) *http.Transport {
	key := fqdn + "|" + string(target) + "|" + string(p.id)
	e.tmu.Lock()
	defer e.tmu.Unlock()
	if t, ok := e.transports[key]; ok {
		t.used = time.Now()
		return t.rt
	}
	peer := *p
	rt := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return e.dialService(ctx, base, fqdn, target, &peer)
		},
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     false,
	}
	e.transports[key] = &edgeTransport{rt: rt, used: time.Now()}
	return rt
}

// sweep drops pools unused for a while.
func (e *Edge) sweep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		e.tmu.Lock()
		for k, tr := range e.transports {
			if time.Since(tr.used) > 5*time.Minute {
				tr.rt.CloseIdleConnections()
				delete(e.transports, k)
			}
		}
		e.tmu.Unlock()
	}
}

func (e *Edge) dialService(ctx context.Context, base, fqdn string, target []byte, p *peerInfo) (net.Conn, error) {
	ns := e.hub.session(target)
	if ns == nil {
		return nil, errors.New("service node offline")
	}
	st, err := ns.mux.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	body := &pb.OpenBody{Kind: pb.Kind_KIND_TCP, Workspace: base, From: e.pub, To: target, IssuedAt: uint64(time.Now().Unix()), Nonce: randomBytes(16),
		Tcp: &pb.TcpOpen{Proto: pb.Proto_PROTO_HTTP, Domain: fqdn, Port: 443}}
	if len(p.id) > 0 {
		body.Tcp.HttpPeer = &pb.HttpPeer{Identity: p.id, Name: p.name}
	}
	open, err := wire.SignOpen(e.key, body)
	if err != nil {
		st.Reset()
		return nil, err
	}
	if err := wire.WriteMsg(st, &pb.StreamOpen{Open: open, Relay: &pb.RelayInfo{TraceId: randomBytes(16), RelayedAt: uint64(time.Now().UnixMilli())}}); err != nil {
		st.Reset()
		return nil, err
	}
	ack, err := stream.ReadAck(st, AckTimeout)
	if err != nil {
		st.Reset()
		return nil, err
	}
	if ack.Status != pb.Status_OK {
		st.Reset()
		return nil, fmt.Errorf("service node refused: %s %s", ack.Status, ack.Message)
	}
	return st, nil
}

func page(w http.ResponseWriter, status int, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>%[1]s</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 1rem;color:#222}h1{font-size:1.4rem}p{color:#555}</style></head>
<body><h1>%[1]s</h1><p>%[2]s</p><p><small>%[3]d</small></p></body></html>`, html.EscapeString(title), html.EscapeString(msg), status)
}

// chanListener is a net.Listener fed by push.
type chanListener struct {
	ch     chan net.Conn
	done   chan struct{}
	closed sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn, 64), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.closed.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{} }
