package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func echoServer(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	echo := func(c net.Conn) {
		defer c.Close()
		io.Copy(c, c)
	}
	mux := http.NewServeMux()
	mux.Handle("/ws", WSHandler(echo))
	mux.Handle("/up", UpgradeHandler(echo))
	mux.Handle("/x/", XHTTPHandler("/x/", echo))
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, 300_000)
	rand.Read(payload)
	go c.Write(payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo mismatch")
	}
}

func TestWebSocketAndUpgradeEcho(t *testing.T) {
	srv, pool := echoServer(t)
	for _, kind := range []Kind{WebSocket, HTTPUpgrade, XHTTP} {
		t.Run(string(kind), func(t *testing.T) {
			path := map[Kind]string{WebSocket: "/ws", HTTPUpgrade: "/up", XHTTP: "/x"}[kind]
			c, err := Dial(context.Background(), kind, srv.URL+path, Options{RootCAs: pool})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			roundTrip(t, c)
		})
	}
}

func TestDialRejectsUntrustedCertificate(t *testing.T) {
	srv, _ := echoServer(t)
	if _, err := Dial(context.Background(), WebSocket, srv.URL+"/ws", Options{RootCAs: x509.NewCertPool()}); err == nil {
		t.Fatal("dial succeeded against an untrusted certificate")
	}
}

func TestDialRejectsPlainHTTP(t *testing.T) {
	if _, err := Dial(context.Background(), WebSocket, "http://127.0.0.1:1/ws", Options{}); err == nil {
		t.Fatal("plain http accepted")
	}
}

func TestAutoFallsBackToNextTransport(t *testing.T) {
	srv, pool := echoServer(t)
	paths := map[Kind]string{WebSocket: "/missing", HTTPUpgrade: "/up"}
	a := NewAuto([]Kind{WebSocket, HTTPUpgrade}, 1)
	var c net.Conn
	var err error
	for i := 0; i < 3; i++ {
		kind := a.Current()
		c, err = Dial(context.Background(), kind, srv.URL+paths[kind], Options{RootCAs: pool})
		if err == nil {
			a.Success()
			break
		}
		a.Failure()
	}
	if err != nil {
		t.Fatalf("auto never succeeded: %v", err)
	}
	if a.Current() != HTTPUpgrade {
		t.Fatalf("auto settled on %s", a.Current())
	}
	roundTrip(t, c)
}

func TestNetDialOverride(t *testing.T) {
	srv, pool := echoServer(t)
	addr := srv.Listener.Addr().String()
	opts := Options{
		RootCAs:    pool,
		ServerName: "example.com",
		NetDial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	// httptest certificates are valid for example.com.
	c, err := Dial(context.Background(), WebSocket, "https://relay.invalid/ws", opts)
	if err != nil {
		t.Fatalf("dial with override: %v", err)
	}
	roundTrip(t, c)
	_ = tls.VersionTLS13
}

// TestDeadlinesDoNotKillConnections: yamux keeps a rolling write deadline on
// its connection. On the WebSocket and XHTTP transports a deadline that fires
// while a write is in flight must not break the connection for good (plain
// TLS connections keep standard net.Conn deadline semantics).
func TestDeadlinesDoNotKillConnections(t *testing.T) {
	srv, pool := echoServer(t)
	for _, kind := range []Kind{WebSocket, XHTTP} {
		t.Run(string(kind), func(t *testing.T) {
			path := map[Kind]string{WebSocket: "/ws", XHTTP: "/x"}[kind]
			c, err := Dial(context.Background(), kind, srv.URL+path, Options{RootCAs: pool})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()
			stop := time.AfterFunc(20*time.Second, func() { c.Close() })
			defer stop.Stop()
			const n = 4 << 20
			c.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
			werr := make(chan error, 1)
			go func() { _, err := c.Write(make([]byte, n)); werr <- err }()
			time.Sleep(50 * time.Millisecond)
			c.SetWriteDeadline(time.Time{})
			if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
				t.Fatalf("echo of the large write: %v", err)
			}
			if err := <-werr; err != nil {
				t.Fatalf("large write: %v", err)
			}
			if _, err := c.Write([]byte("still alive")); err != nil {
				t.Fatalf("write after the deadline fired: %v", err)
			}
			got := make([]byte, len("still alive"))
			if _, err := io.ReadFull(c, got); err != nil || string(got) != "still alive" {
				t.Fatalf("echo after the deadline fired: %v %q", err, got)
			}
		})
	}
}
