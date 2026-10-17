package servertest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/edge"
	"github.com/bit-precise/agentd/policy"
	"github.com/bit-precise/agentd/supervisor"
)

func socksConnect(ctx context.Context, address, domain string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	failed := func(err error) (net.Conn, error) { _ = conn.Close(); return nil, err }
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		return failed(err)
	}
	var hello [2]byte
	if _, err = io.ReadFull(conn, hello[:]); err != nil {
		return failed(err)
	}
	if hello != [2]byte{5, 0} {
		return failed(errors.New("SOCKS auth rejected"))
	}
	request := append([]byte{5, 1, 0, 3, byte(len(domain))}, []byte(domain)...)
	request = append(request, 1, 187)
	if _, err = conn.Write(request); err != nil {
		return failed(err)
	}
	var response [10]byte
	if _, err = io.ReadFull(conn, response[:]); err != nil {
		return failed(err)
	}
	if response[0] != 5 || response[1] != 0 || response[3] != 1 {
		return failed(fmt.Errorf("SOCKS route rejected: %v", response[:4]))
	}
	return conn, nil
}

func proxyHTTPClient(t *testing.T, address string, certificate *x509.Certificate) *http.Client {
	t.Helper()
	proxyURL, _ := url.Parse("http://" + address)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func TestHTTPAndSOCKSEgressPreserveTLSAndRevokeOnlyAffectedFlow(t *testing.T) {
	testHTTPAndSOCKSEgress(t, false)
}

func TestRealSupervisorRenewsServeAndTLSFlowsAcrossPolicyLeases(t *testing.T) {
	testHTTPAndSOCKSEgress(t, true)
}

func testHTTPAndSOCKSEgress(t *testing.T, shortLeases bool) {
	h := newHarness(t)
	if shortLeases {
		// Keep the actual control app, SQL state, public API and supervisors. Only
		// compress lease duration so CI exercises multiple renewals in seconds.
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		if err := h.app.Edge.Shutdown(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		replacement, err := edge.New(h.app.State, edge.Config{AllowLoopbackHTTP: true, FlowTTL: 1200 * time.Millisecond, MaxFlowLifetime: 8 * time.Second, SessionTTL: 15 * time.Second, RecheckInterval: 100 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		h.app.Edge = replacement
		done := make(chan error, 1)
		go func() { done <- replacement.Run(t.Context()) }()
		t.Cleanup(func() {
			h.close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("short-lease Edge did not stop")
			}
		})
	}
	w, u := h.workspace("workspace", "alice")
	targetCanceled := make(chan struct{})
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			defer close(targetCanceled)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "tls-ready\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "original-tls-target")
	}))
	defer target.Close()
	certificate := target.Certificate()
	if len(certificate.DNSNames) == 0 {
		t.Fatal("TLS fixture has no DNS SAN")
	}
	domain := certificate.DNSNames[0]
	serveMessages := make(chan string, 2)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "serve-ready\n")
		w.(http.Flusher).Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case message := <-serveMessages:
				_, _ = io.WriteString(w, message+"\n")
				w.(http.Flusher).Flush()
			}
		}
	}))
	defer origin.Close()
	exitCfg := h.agentConfig(w.Name, "exit")
	exitCfg.Egress = config.EgressConfig{Enabled: true, Allow: []policy.Rule{tlsRule(domain)}}
	exitCfg.Serve = config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: origin.URL}}}
	exit, _ := h.enroll(exitCfg, w, u, []string{"serve", "egress"}, true)
	var dials atomic.Int32
	h.runAgent(exitCfg, exit, supervisor.WithEgressDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != net.JoinHostPort(domain, "443") {
			return nil, errors.New("unexpected target")
		}
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, target.Listener.Addr().String())
	}))
	clientCfg := h.agentConfig(w.Name, "client")
	clientCfg.Ingress = config.IngressConfig{Enabled: true, HTTP: config.ListenerConfig{Enabled: true, Listen: freeAddress(t)}, SOCKS: config.ListenerConfig{Enabled: true, Listen: freeAddress(t)}, Routes: []policy.Rule{tlsRule(domain)}, OnUnmatched: "reject"}
	access, _ := h.enroll(clientCfg, w, u, []string{"ingress"}, true)
	h.runAgent(clientCfg, access)
	await(t, func() bool { return h.connected(exit.Agent.ID, "provider") && h.connected(access.Agent.ID, "access") })
	proxyClient := proxyHTTPClient(t, clientCfg.Ingress.HTTP.Listen, certificate)
	if response, err := proxyClient.Get("https://" + domain + "/"); err == nil {
		_ = response.Body.Close()
		t.Fatal("TLS request succeeded without EgressRoute/Grant")
	}
	if dials.Load() != 0 {
		t.Fatal("unauthorized ingress caused provider dial")
	}
	_, grant := h.grantRoute(w, u, exit.Agent.ID, domain, "office")
	response, err := proxyClient.Get("https://" + domain + "/")
	if err != nil {
		t.Fatal(err)
	}
	if response.TLS == nil || !bytes.Equal(response.TLS.PeerCertificates[0].Raw, certificate.Raw) {
		t.Fatal("HTTP CONNECT changed the remote certificate")
	}
	if body := readResponse(t, response, 200); body != "original-tls-target" {
		t.Fatalf("wrong TLS origin body: %s", body)
	}
	conn, err := socksConnect(t.Context(), clientCfg.Ingress.SOCKS.Listen, domain)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	secure := tls.Client(conn, &tls.Config{ServerName: domain, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err = secure.HandshakeContext(t.Context()); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if !bytes.Equal(secure.ConnectionState().PeerCertificates[0].Raw, certificate.Raw) {
		t.Fatal("SOCKS changed remote certificate")
	}
	if _, err = fmt.Fprintf(secure, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", domain); err != nil {
		_ = secure.Close()
		t.Fatal(err)
	}
	response, err = http.ReadResponse(bufio.NewReader(secure), nil)
	if err != nil {
		_ = secure.Close()
		t.Fatal(err)
	}
	if body := readResponse(t, response, 200); body != "original-tls-target" {
		t.Fatal("SOCKS wrong origin body")
	}
	_ = secure.Close()
	streamResponse, err := proxyClient.Get("https://" + domain + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer streamResponse.Body.Close()
	tlsBody := bufio.NewReader(streamResponse.Body)
	if line, err := tlsBody.ReadString('\n'); err != nil || line != "tls-ready\n" {
		t.Fatalf("TLS stream preface: %q %v", line, err)
	}
	serveResponse, err := h.serveRequest(serviceHost("demo", w.Name), u.Token, "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer serveResponse.Body.Close()
	serveBody := bufio.NewReader(serveResponse.Body)
	if line, err := serveBody.ReadString('\n'); err != nil || line != "serve-ready\n" {
		t.Fatalf("Serve stream preface: %q %v", line, err)
	}
	if shortLeases {
		initial := map[string]edge.FlowStatus{}
		for _, flow := range h.app.Edge.Snapshot().Flows {
			if old, ok := initial[flow.Purpose]; !ok || flow.StartedAt.After(old.StartedAt) {
				initial[flow.Purpose] = flow
			}
		}
		if len(initial) != 2 {
			t.Fatalf("expected Serve and Egress flows, got %v", initial)
		}
		time.Sleep(3200 * time.Millisecond)
		select {
		case <-targetCanceled:
			t.Fatal("TLS origin canceled at the initial short policy lease")
		default:
		}
		current := h.app.Edge.Snapshot()
		for purpose, before := range initial {
			found := false
			for _, after := range current.Flows {
				if before.ID == after.ID {
					found = true
					if !after.ExpiresAt.After(before.ExpiresAt) {
						t.Fatalf("%s lease was not renewed", purpose)
					}
				}
			}
			if !found {
				t.Fatalf("%s stream was replaced or closed instead of renewed", purpose)
			}
		}
		serveMessages <- "after-multiple-renewals"
		if line, err := serveBody.ReadString('\n'); err != nil || line != "after-multiple-renewals\n" {
			t.Fatalf("Serve stream did not survive policy renewals: %q %v", line, err)
		}
	}
	h.api("DELETE", "/api/v1/grants/"+grant.ID, adminToken, nil, nil, 200)
	select {
	case <-targetCanceled:
	case <-time.After(4 * time.Second):
		t.Fatal("grant revocation did not close target TLS flow")
	}
	if _, err = tlsBody.ReadByte(); err == nil {
		t.Fatal("revoked TLS stream remained readable")
	}
	serveMessages <- "still-serving"
	if line, err := serveBody.ReadString('\n'); err != nil || line != "still-serving\n" {
		t.Fatalf("unrelated Serve flow was interrupted: %q %v", line, err)
	}
	if !h.connected(exit.Agent.ID, "provider") {
		t.Fatal("single Grant revoke closed shared provider session")
	}
	if response, err := proxyClient.Get("https://" + domain + "/"); err == nil {
		_ = response.Body.Close()
		t.Fatal("revoked Grant still allowed new TLS flow")
	}
}

func TestAccessProfileCannotUseAnotherWorkspacesRoute(t *testing.T) {
	h := newHarness(t)
	w1, alice := h.workspace("one", "alice")
	w2, bob := h.workspace("two", "bob")
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "private") }))
	defer target.Close()
	certificate := target.Certificate()
	domain := certificate.DNSNames[0]
	exitCfg := h.agentConfig(w1.Name, "exit")
	exitCfg.Egress = config.EgressConfig{Enabled: true, Allow: []policy.Rule{tlsRule(domain)}}
	exit, _ := h.enroll(exitCfg, w1, alice, []string{"egress"}, true)
	var dials atomic.Int32
	h.runAgent(exitCfg, exit, supervisor.WithEgressDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, target.Listener.Addr().String())
	}))
	route, _ := h.grantRoute(w1, alice, exit.Agent.ID, domain, "private")
	clientCfg := h.agentConfig(w2.Name, "client")
	clientCfg.Ingress = config.IngressConfig{Enabled: true, HTTP: config.ListenerConfig{Enabled: true, Listen: freeAddress(t)}, Routes: []policy.Rule{tlsRule(domain)}, OnUnmatched: "reject"}
	access, _ := h.enroll(clientCfg, w2, bob, []string{"ingress"}, true)
	h.runAgent(clientCfg, access)
	await(t, func() bool { return h.connected(exit.Agent.ID, "provider") && h.connected(access.Agent.ID, "access") })
	client := proxyHTTPClient(t, clientCfg.Ingress.HTTP.Listen, certificate)
	if response, err := client.Get("https://" + domain); err == nil {
		_ = response.Body.Close()
		t.Fatal("SNI selected a route in another workspace")
	}
	if dials.Load() != 0 {
		t.Fatal("cross-workspace denial still dialed private target")
	}
	h.api("POST", "/api/v1/grants", adminToken, types.Grant{WorkspaceID: w2.ID, ResourceType: "egress", ResourceID: route.ID, SubjectType: "user", SubjectID: bob.User.ID, ExpiresAt: time.Now().Add(time.Hour)}, nil, 403)
}
