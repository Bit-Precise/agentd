// Package integration tests the runnable agent against a deliberately small,
// in-process Edge fixture. The fixture is not a production control plane.
package integration

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/credentials"
	"github.com/bit-precise/agentd/policy"
	"github.com/bit-precise/agentd/policygate"
	"github.com/bit-precise/agentd/stream"
	"github.com/bit-precise/agentd/supervisor"
	"github.com/bit-precise/agentd/transport/xhttp"
	"github.com/rs/zerolog"
)

type edgeFixture struct {
	ctx           context.Context
	server        *httptest.Server
	mu            sync.Mutex
	provider      *connection.Session
	accessReady   chan struct{}
	providerReady chan struct{}
	port          uint16
}

func newEdge(t *testing.T, port uint16) *edgeFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	e := &edgeFixture{ctx: ctx, accessReady: make(chan struct{}, 8), providerReady: make(chan struct{}, 8), port: port}
	h, err := xhttp.NewHandler(xhttp.ServerConfig{Authorize: func(r *http.Request) (string, error) {
		switch r.Header.Get("Authorization") {
		case "Bearer provider-secret":
			return "provider", nil
		case "Bearer access-secret":
			return "access", nil
		default:
			return "", errors.New("denied")
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	e.server = ts
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := h.Accept(ctx)
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); defer c.Close(); e.accept(c) }()
		}
	}()
	t.Cleanup(func() { cancel(); _ = h.Close(); ts.Close(); wg.Wait() })
	return e
}

func (e *edgeFixture) accept(c net.Conn) {
	s, err := connection.Server(e.ctx, c, func(_ context.Context, h connection.Hello) (connection.Principal, error) {
		if h.Workspace != "workspace1" || h.AgentID != "agent-1" {
			return connection.Principal{}, errors.New("wrong identity")
		}
		p := connection.Principal{Role: h.Role, Workspace: h.Workspace, AgentID: h.AgentID, ConnectorID: h.ConnectorID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}
		switch h.Role {
		case connection.RoleProvider:
			if h.Token != "provider-secret" {
				return p, errors.New("wrong role credential")
			}
			p.Services = h.Services
			p.EgressEnabled = h.EgressEnabled
		case connection.RoleAccess:
			if h.Token != "access-secret" {
				return p, errors.New("wrong role credential")
			}
			p.UserID = "alice"
		default:
			return p, errors.New("wrong role")
		}
		return p, nil
	}, connection.Config{AuthorizeOpen: func(_ context.Context, p connection.Principal, r connection.OpenRequest) (connection.OpenClaims, error) {
		if p.Role != connection.RoleAccess || p.UserID != "alice" || r.Purpose != connection.PurposeAccess || r.Protocol != "tls" || r.Destination.Host != "example.com" || r.Destination.Port != e.port {
			return connection.OpenClaims{}, errors.New("route denied")
		}
		return connection.OpenClaims{FlowID: r.FlowID, Purpose: r.Purpose, Destination: r.Destination, Protocol: r.Protocol, Revision: r.Revision, Deadline: r.Deadline}, nil
	}})
	if err != nil {
		return
	}
	defer s.Close()
	if s.Principal().Role == connection.RoleProvider {
		e.mu.Lock()
		e.provider = s
		e.mu.Unlock()
		e.providerReady <- struct{}{}
		select {
		case <-e.ctx.Done():
		case <-s.Done():
		}
		return
	}
	e.accessReady <- struct{}{}
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		flow, err := s.Accept(e.ctx)
		if err != nil {
			return
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer flow.Close(); e.route(flow) }()
	}
}

func (e *edgeFixture) route(access *connection.Stream) {
	preface, err := policygate.Inspect(access.Context(), access, access.Claims().Destination.Host)
	if err != nil {
		return
	}
	e.mu.Lock()
	provider := e.provider
	e.mu.Unlock()
	if provider == nil {
		return
	}
	deadline := access.Claims().Deadline
	if provider.Principal().ExpiresAt.Before(deadline) {
		deadline = provider.Principal().ExpiresAt
	}
	flow, err := provider.Open(access.Context(), connection.OpenRequest{Purpose: connection.PurposeEgress, Resource: "office", Destination: access.Claims().Destination, Protocol: "tls", Revision: 7, Deadline: deadline})
	if err != nil {
		return
	}
	defer flow.Close()
	if _, err := flow.Write(preface); err != nil {
		return
	}
	stream.Pipe(access.Context(), access, flow)
}

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	_ = l.Close()
	return address
}

func wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not become ready")
	}
}

func TestAgentdThreeRolesOverModifiedXHTTP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "local")
		_, _ = io.WriteString(w, "served "+r.URL.Path)
	}))
	defer origin.Close()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "egress "+r.URL.Path) }))
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pn, _ := strconv.Atoi(targetPort)
	port := uint16(pn)
	edge := newEdge(t, port)
	state := filepath.Join(t.TempDir(), "state")
	releaseState, err := credentials.Lock(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseState(); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: edge.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	rule := policy.Rule{Domain: policy.Domain{Exact: "example.com"}, Ports: []int{int(port)}, Protocol: "tls"}
	cfg := &config.Config{Instance: "https://instance1.example.com", Workspace: "workspace1", Agent: config.AgentConfig{Name: "agentd1", StateDir: state}, Transport: config.TransportConfig{Type: "xhttp", Endpoint: edge.server.URL + "/agent", Mode: "packet-up", CAFile: caPath}, Ingress: config.IngressConfig{Enabled: true, HTTP: config.ListenerConfig{Enabled: true, Listen: freeAddress(t)}, SOCKS: config.ListenerConfig{Enabled: true, Listen: freeAddress(t)}, Routes: []policy.Rule{rule}, OnUnmatched: "reject"}, Serve: config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: origin.URL}}}, Egress: config.EgressConfig{Enabled: true, Allow: []policy.Rule{rule}}}
	creds := &credentials.Credentials{Version: 1, Workspace: "workspace1", AgentID: "agent-1", ProviderToken: "provider-secret", AccessToken: "access-secret", Approval: credentials.Approval{Revision: 7, ExpiresAt: time.Now().Add(time.Hour), Services: map[string]string{"demo": origin.URL}, Egress: []policy.Rule{rule}}}
	s, err := supervisor.New(cfg, creds, zerolog.Nop(), supervisor.WithEgressDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort("example.com", targetPort) {
			return nil, errors.New("unexpected dial")
		}
		return (&net.Dialer{}).DialContext(ctx, network, target.Listener.Addr().String())
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-result:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(8 * time.Second):
			t.Error("agent shutdown hung")
		}
	})
	wait(t, edge.providerReady)
	wait(t, edge.accessReady)
	edge.mu.Lock()
	provider := edge.provider
	edge.mu.Unlock()
	if len(provider.Principal().Services) != 1 || provider.Principal().Services[0] != "demo" {
		t.Fatal("provider did not advertise approved service")
	}
	flow, err := provider.Open(ctx, connection.OpenRequest{Purpose: connection.PurposeServe, Resource: "demo", Revision: 7, Deadline: time.Now().Add(30 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(flow, "GET /hello HTTP/1.1\r\nHost: demo.workspace1.instance1.example.com\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(flow), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = flow.Close()
	if err != nil || string(body) != "served /hello" {
		t.Fatalf("serve: %q %v", body, err)
	}
	for _, kind := range []string{"http", "socks"} {
		t.Run(kind, func(t *testing.T) {
			var c net.Conn
			var err error
			if kind == "http" {
				c, err = net.DialTimeout("tcp", cfg.Ingress.HTTP.Listen, time.Second)
				if err == nil {
					_, err = fmt.Fprintf(c, "CONNECT example.com:%d HTTP/1.1\r\nHost: example.com:%d\r\n\r\n", port, port)
				}
				if err != nil {
					t.Fatal(err)
				}
				reply, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil || reply.StatusCode != 200 {
					t.Fatalf("CONNECT: %v %v", reply, err)
				}
			} else {
				c, err = net.DialTimeout("tcp", cfg.Ingress.SOCKS.Listen, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = c.Write([]byte{5, 1, 0})
				var greeting [2]byte
				if _, err = io.ReadFull(c, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
					t.Fatal("SOCKS negotiation failed")
				}
				packet := append([]byte{5, 1, 0, 3, 11}, []byte("example.com")...)
				packet = append(packet, byte(port>>8), byte(port))
				_, _ = c.Write(packet)
				var reply [10]byte
				if _, err = io.ReadFull(c, reply[:]); err != nil || reply[1] != 0 {
					t.Fatalf("SOCKS CONNECT: %v %v", reply, err)
				}
			}
			defer c.Close()
			roots := x509.NewCertPool()
			roots.AddCert(target.Certificate())
			tlsConn := tls.Client(c, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12})
			defer tlsConn.Close()
			_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
			if err := tlsConn.Handshake(); err != nil {
				t.Fatal(err)
			}
			if !tlsConn.ConnectionState().PeerCertificates[0].Equal(target.Certificate()) {
				t.Fatal("target TLS certificate was replaced")
			}
			_, err = fmt.Fprintf(tlsConn, "GET /secure HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || string(body) != "egress /secure" {
				t.Fatalf("egress response: %q %v", body, err)
			}
		})
	}
	// Local filtering must reject before any Edge candidate flow or target dial.
	c, err := net.DialTimeout("tcp", cfg.Ingress.HTTP.Listen, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n")
	denied, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || denied.StatusCode != 403 {
		t.Fatalf("unmatched destination was not rejected: %v %v", denied, err)
	}
	_ = denied.Body.Close()
	// Withdrawing one role must not require tearing down the shared provider.
	updated := *cfg
	updated.Serve = config.ServeConfig{}
	if err := s.Reload(&updated); err != nil {
		t.Fatal(err)
	}
	_, err = provider.Open(ctx, connection.OpenRequest{Purpose: connection.PurposeServe, Resource: "demo", Revision: 7, Deadline: time.Now().Add(10 * time.Second)})
	if err == nil {
		t.Fatal("withdrawn service still admitted")
	}
	select {
	case <-provider.Done():
		t.Fatal("service withdrawal killed shared provider session")
	default:
	}
	// A new transport after failure keeps the process Connector identity and
	// advertises the current local service set, without restoring withdrawn work.
	connectorID := provider.Principal().ConnectorID
	_ = provider.Close()
	wait(t, edge.providerReady)
	edge.mu.Lock()
	reconnected := edge.provider
	edge.mu.Unlock()
	if reconnected == provider || reconnected.Principal().ConnectorID != connectorID || len(reconnected.Principal().Services) != 0 {
		t.Fatal("reconnect changed runtime identity or revived the withdrawn service")
	}
}
