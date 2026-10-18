package orchestration

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bit-precise/agentd/connection"
)

func managedSessions(t *testing.T, m *Manager) (provider, edge *connection.Session) {
	t.Helper()
	a, b := net.Pipe()
	type result struct {
		session *connection.Session
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		s, err := connection.Server(t.Context(), b, func(_ context.Context, h connection.Hello) (connection.Principal, error) {
			if h.Token != "test-secret" {
				return connection.Principal{}, errors.New("not authenticated")
			}
			return connection.Principal{Role: connection.RoleProvider, Workspace: "w1", AgentID: "agent1", ConnectorID: "connector1", Generation: 9, ExpiresAt: time.Now().Add(time.Minute)}, nil
		}, connection.Config{HandshakeTimeout: time.Second, OpenTimeout: time.Second})
		resultCh <- result{s, err}
	}()
	provider, err := connection.Client(t.Context(), a, connection.Hello{
		Version: connection.ProtocolVersion, Role: connection.RoleProvider, Workspace: "w1", AgentID: "agent1", ConnectorID: "connector1", Token: "test-secret",
	}, connection.Config{AuthorizeOpen: m.AuthorizeOpen, HandshakeTimeout: time.Second, OpenTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	r := <-resultCh
	if r.err != nil {
		_ = provider.Close()
		t.Fatal(r.err)
	}
	t.Cleanup(func() { _ = provider.Close(); _ = r.session.Close() })
	return provider, r.session
}

func openManaged(t *testing.T, m *Manager, provider, edge *connection.Session, request connection.OpenRequest) (*connection.Stream, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	peer, err := edge.Open(ctx, request)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	local, err := provider.Accept(ctx)
	if err != nil {
		_ = peer.Close()
		t.Fatalf("accept: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- m.Handle(t.Context(), local) }()
	t.Cleanup(func() { _ = peer.Close(); _ = local.Close() })
	return peer, done
}

func waitSignal(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitHandled(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("flow handler failed to finish")
		return nil
	}
}

func TestReloadCancelsPendingDial(t *testing.T) {
	m := New(testManagerConfig(), testEffective())
	started := make(chan struct{})
	canceled := make(chan struct{})
	m.SetDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	})
	provider, edge := managedSessions(t, m)
	peer, done := openManaged(t, m, provider, edge, testOpen(connection.PurposeEgress))
	waitSignal(t, started, "pending dial")
	if m.ActiveFlows() != 1 {
		t.Fatal("pending dial was absent from flow ledger")
	}
	next := testManagerConfig()
	next.Egress.Allow = nil
	m.Reload(next)
	waitSignal(t, canceled, "pending dial cancellation")
	if err := waitHandled(t, done); err == nil {
		t.Fatal("canceled dial returned success")
	}
	waitSignal(t, peer.Context().Done(), "remote flow cancellation")
	if m.ActiveFlows() != 0 {
		t.Fatal("canceled pending flow leaked from ledger")
	}
	select {
	case <-edge.Done():
		t.Fatal("local egress revocation closed shared provider session")
	default:
	}
}

func TestSuccessfulDialRacingCancellationClosesSocket(t *testing.T) {
	m := New(testManagerConfig(), testEffective())
	started := make(chan struct{})
	target, remote := net.Pipe()
	t.Cleanup(func() { _ = target.Close(); _ = remote.Close() })
	m.SetDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		// Model a dialer whose success races with cancellation.
		return target, nil
	})
	provider, edge := managedSessions(t, m)
	_, done := openManaged(t, m, provider, edge, testOpen(connection.PurposeEgress))
	waitSignal(t, started, "dial before cancellation")
	next := testManagerConfig()
	next.Egress.Enabled = false
	m.Reload(next)
	_ = waitHandled(t, done)
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := remote.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("dial completed after cancellation but target socket was not closed: %v", err)
	}
}

func TestRemovingServiceCancelsOnlyItsFlow(t *testing.T) {
	demoCanceled := make(chan struct{})
	apiCanceled := make(chan struct{})
	apiMessages := make(chan string, 1)
	origin := func(canceled chan struct{}, messages <-chan string) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(canceled)
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "ready\n")
			w.(http.Flusher).Flush()
			for {
				select {
				case <-r.Context().Done():
					return
				case message := <-messages:
					_, _ = io.WriteString(w, message+"\n")
					w.(http.Flusher).Flush()
				}
			}
		}))
		t.Cleanup(server.Close)
		return server
	}
	demoOrigin := origin(demoCanceled, nil)
	apiOrigin := origin(apiCanceled, apiMessages)
	cfg := testManagerConfig()
	cfg.Serve.Services[0].Origin, cfg.Serve.Services[1].Origin = demoOrigin.URL, apiOrigin.URL
	effective := testEffective()
	effective.Services[0].Origin, effective.Services[1].Origin = demoOrigin.URL, apiOrigin.URL
	m := New(cfg, effective)
	provider, edge := managedSessions(t, m)
	request := testOpen(connection.PurposeServe)
	request.FlowID = "demo-flow"
	demo, demoDone := openManaged(t, m, provider, edge, request)
	request.FlowID, request.Resource = "api-flow", "api"
	api, apiDone := openManaged(t, m, provider, edge, request)
	readBody := func(s *connection.Stream, name string) (*http.Response, *bufio.Reader) {
		_ = s.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprintf(s, "GET /events HTTP/1.1\r\nHost: %s.w1.instance.example\r\nConnection: close\r\n\r\n", name); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(s), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		if response.StatusCode != http.StatusOK {
			t.Fatalf("origin status %d", response.StatusCode)
		}
		body := bufio.NewReader(response.Body)
		if line, err := body.ReadString('\n'); err != nil || line != "ready\n" {
			t.Fatalf("initial response = %q, %v", line, err)
		}
		return response, body
	}
	_, _ = readBody(demo, "demo")
	apiResponse, apiBody := readBody(api, "api")
	if m.ActiveFlows() != 2 {
		t.Fatal("expected two active service flows")
	}
	next := testManagerConfig()
	next.Serve.Services = next.Serve.Services[1:]
	next.Serve.Services[0].Origin = apiOrigin.URL
	m.Reload(next)
	waitSignal(t, demoCanceled, "removed service origin cancellation")
	_ = waitHandled(t, demoDone)
	waitSignal(t, demo.Context().Done(), "removed service remote cancellation")
	select {
	case <-apiCanceled:
		t.Fatal("unrelated service origin canceled")
	default:
	}
	apiMessages <- "still-running"
	if line, err := apiBody.ReadString('\n'); err != nil || line != "still-running\n" {
		t.Fatalf("unrelated service did not survive reload: %q, %v", line, err)
	}
	select {
	case <-edge.Done():
		t.Fatal("shared provider session closed")
	default:
	}
	_ = apiResponse.Body.Close()
	_ = api.Close()
	_ = waitHandled(t, apiDone)
}

func TestServeStripsReservedIdentityAndCrossOriginCookies(t *testing.T) {
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		http.SetCookie(w, &http.Cookie{Name: "__Host-agents-session", Value: "forged", Path: "/", Secure: true})
		http.SetCookie(w, &http.Cookie{Name: "broad", Value: "forged", Domain: ".instance.example", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "app", Value: "valid", Path: "/"})
		_, _ = io.WriteString(w, "ordinary-response")
	}))
	t.Cleanup(origin.Close)
	cfg := testManagerConfig()
	cfg.Serve.Services[0].Origin = origin.URL
	effective := testEffective()
	effective.Services[0].Origin = origin.URL
	m := New(cfg, effective)
	provider, edge := managedSessions(t, m)
	peer, done := openManaged(t, m, provider, edge, testOpen(connection.PurposeServe))
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	request := "GET / HTTP/1.1\r\nHost: demo.w1.instance.example\r\nConnection: close\r\n" +
		"X-Agents-Subject: attacker\r\nX-Auth-Request-User: attacker\r\nX-Forwarded-For: attacker\r\n" +
		"X-Forwarded-User: attacker\r\nForwarded: for=attacker\r\nCookie: __Host-agents-session=secret; app=allowed\r\n\r\n"
	if _, err := io.WriteString(peer, request); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(peer), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "ordinary-response" {
		t.Fatalf("ordinary HTTP response truncated: %q, %v", body, err)
	}
	if cookies := response.Cookies(); len(cookies) != 1 || cookies[0].Name != "app" || cookies[0].Value != "valid" {
		t.Fatalf("unsafe origin cookies forwarded: %+v", cookies)
	}
	var headers http.Header
	select {
	case headers = <-seen:
	case <-time.After(time.Second):
		t.Fatal("origin was not reached")
	}
	for key, values := range headers {
		if strings.Contains(strings.Join(values, " "), "attacker") || strings.Contains(strings.Join(values, " "), "secret") {
			t.Fatalf("untrusted identity survived in %s: %v", key, values)
		}
	}
	if headers.Get("Cookie") != "app=allowed" {
		t.Fatalf("ordinary application cookie not preserved: %q", headers.Get("Cookie"))
	}
	_ = peer.Close()
	_ = waitHandled(t, done)
}
