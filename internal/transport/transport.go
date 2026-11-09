// Package transport provides the byte-stream transports under the session
// layer (protocol 2): WebSocket (default) and HTTP Upgrade, always over TLS
// with standard certificate verification.
package transport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Kind names a transport.
type Kind string

const (
	WebSocket   Kind = "ws"
	HTTPUpgrade Kind = "httpupgrade"
	XHTTP       Kind = "xhttp"
	AutoKind    Kind = "auto"
)

// Subprotocol is the WebSocket subprotocol (protocol 2.2).
const Subprotocol = "agentd.v1"

// DialTimeout covers TCP, TLS and the HTTP upgrade (TRANSPORT_DIAL_TIMEOUT).
const DialTimeout = 10 * time.Second

// Options configure a client dial.
type Options struct {
	// RootCAs replaces the system roots when non-nil (tests, private CAs).
	RootCAs *x509.CertPool
	// ServerName overrides the TLS server name (defaults to the URL host).
	ServerName string
	// NetDial overrides the TCP dial (tests, binding to a physical interface).
	NetDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// UserAgent is sent with the upgrade request.
	UserAgent string
}

func (o Options) tlsConfig(host string) *tls.Config {
	name := o.ServerName
	if name == "" {
		name = host
	}
	return &tls.Config{ServerName: name, RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
}

func (o Options) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if o.NetDial != nil {
		return o.NetDial(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func (o Options) dialTLS(ctx context.Context, u *url.URL) (*tls.Conn, error) {
	raw, err := o.dialTCP(ctx, hostPort(u))
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, o.tlsConfig(u.Hostname()))
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), "443")
}

// Dial opens a transport connection to rawURL (an https URL including the
// transport path) and returns a byte stream ready for the Noise handshake.
func Dial(ctx context.Context, kind Kind, rawURL string, opts Options) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("transport URL must be https, got %q", rawURL)
	}
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	switch kind {
	case WebSocket, "":
		return dialWS(ctx, u, opts)
	case HTTPUpgrade:
		return dialUpgrade(ctx, u, opts)
	case XHTTP:
		return dialXHTTP(ctx, u, opts)
	default:
		return nil, fmt.Errorf("unknown transport %q", kind)
	}
}

func dialWS(ctx context.Context, u *url.URL, opts Options) (net.Conn, error) {
	tr := &http.Transport{
		DialTLSContext:    func(ctx context.Context, _, _ string) (net.Conn, error) { return opts.dialTLS(ctx, u) },
		ForceAttemptHTTP2: false,
	}
	hdr := http.Header{}
	if opts.UserAgent != "" {
		hdr.Set("User-Agent", opts.UserAgent)
	}
	c, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		HTTPClient:   &http.Client{Transport: tr},
		Subprotocols: []string{Subprotocol},
		HTTPHeader:   hdr,
	})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("websocket upgrade: %s: %w", resp.Status, err)
		}
		return nil, err
	}
	c.SetReadLimit(4 << 20)
	return wsConn{websocket.NetConn(context.Background(), c, websocket.MessageBinary)}, nil
}

// wsConn hides deadlines from the layers above. coder/websocket's net.Conn
// cancels the connection for good when a deadline fires during a write, and
// yamux keeps a rolling write deadline on its connection, so an idle session
// died at its first keepalive. The session layer enforces the handshake
// timeout with its own timer and yamux keepalives detect dead peers.
type wsConn struct{ net.Conn }

func (wsConn) SetDeadline(time.Time) error      { return nil }
func (wsConn) SetReadDeadline(time.Time) error  { return nil }
func (wsConn) SetWriteDeadline(time.Time) error { return nil }

func dialUpgrade(ctx context.Context, u *url.URL, opts Options) (net.Conn, error) {
	tc, err := opts.dialTLS(ctx, u)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		tc.SetDeadline(dl)
	}
	var key [16]byte
	_, _ = rand.Read(key[:])
	path := u.RequestURI()
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key[:]) + "\r\nSec-WebSocket-Version: 13\r\n"
	if opts.UserAgent != "" {
		req += "User-Agent: " + opts.UserAgent + "\r\n"
	}
	req += "\r\n"
	if _, err := tc.Write([]byte(req)); err != nil {
		tc.Close()
		return nil, err
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		tc.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		tc.Close()
		return nil, fmt.Errorf("http upgrade: unexpected status %s", resp.Status)
	}
	tc.SetDeadline(time.Time{})
	return &bufConn{Conn: tc, r: br}, nil
}

// WSHandler accepts WebSocket transport connections and runs accept for each,
// blocking until accept returns.
func WSHandler(accept func(net.Conn)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		c.SetReadLimit(4 << 20)
		accept(wsConn{websocket.NetConn(context.Background(), c, websocket.MessageBinary)})
	})
}

// UpgradeHandler accepts HTTP Upgrade transport connections: WebSocket-style
// upgrade headers, then raw bytes with no framing.
func UpgradeHandler(accept func(net.Conn)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		if err == nil {
			err = rw.Flush()
		}
		if err != nil {
			conn.Close()
			return
		}
		accept(&bufConn{Conn: conn, r: rw.Reader})
	})
}

// bufConn reads through a bufio.Reader that may hold bytes read past the
// HTTP headers.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Auto implements `transport: auto` (protocol 2.5): try kinds in order; after
// `threshold` consecutive failures before a handshake completes, move on.
type Auto struct {
	mu        sync.Mutex
	kinds     []Kind
	idx       int
	fails     int
	threshold int
}

// NewAuto creates an Auto selector.
func NewAuto(kinds []Kind, threshold int) *Auto {
	if len(kinds) == 0 {
		kinds = []Kind{WebSocket, XHTTP, HTTPUpgrade}
	}
	if threshold <= 0 {
		threshold = 3
	}
	return &Auto{kinds: kinds, threshold: threshold}
}

// Current returns the kind to try next.
func (a *Auto) Current() Kind {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.kinds[a.idx]
}

// Success records a completed handshake.
func (a *Auto) Success() {
	a.mu.Lock()
	a.fails = 0
	a.mu.Unlock()
}

// Failure records a failure before the handshake completed.
func (a *Auto) Failure() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fails++
	if a.fails >= a.threshold {
		a.fails = 0
		a.idx = (a.idx + 1) % len(a.kinds)
	}
}

var errXHTTPServerOnly = errors.New("xhttp: server handler missing")
