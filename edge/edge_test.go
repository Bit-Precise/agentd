package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/credentials"
	"github.com/bit-precise/agentd/orchestration"
	"github.com/bit-precise/agentd/policy"
	"github.com/bit-precise/agentd/transport/xhttp"
)

type memoryBackend struct {
	mu             sync.RWMutex
	tokens         map[string]types.Identity
	agents         map[string]types.Agent
	serve          map[string]types.Decision
	egress         map[string]types.Decision
	events         chan struct{}
	decisionWindow time.Duration
}

func (b *memoryBackend) Identity(token string) (types.Identity, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.tokens[token]
	if !ok {
		return v, ErrDenied
	}
	return v, nil
}
func (b *memoryBackend) Agent(id string) (types.Agent, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.agents[id]
	if !ok {
		return v, ErrDenied
	}
	return v, nil
}
func (b *memoryBackend) ResolveServe(host, user string) (types.Decision, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.serve[host+"/"+user]
	if !ok {
		return v, ErrDenied
	}
	if b.decisionWindow > 0 {
		v.ExpiresAt = minExpiry(v.ExpiresAt, time.Now().Add(b.decisionWindow))
	}
	return v, nil
}
func (b *memoryBackend) ResolveEgress(workspace, user, host string, port int) (types.Decision, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.egress[fmt.Sprintf("%s/%s/%s/%d", workspace, user, host, port)]
	if !ok {
		return v, ErrDenied
	}
	if b.decisionWindow > 0 {
		v.ExpiresAt = minExpiry(v.ExpiresAt, time.Now().Add(b.decisionWindow))
	}
	return v, nil
}
func (b *memoryBackend) Subscribe() (<-chan struct{}, func()) { return b.events, func() {} }
func (b *memoryBackend) changed() {
	select {
	case b.events <- struct{}{}:
	default:
	}
}

func fixtureBackend() *memoryBackend {
	until := time.Now().Add(time.Minute)
	b := &memoryBackend{tokens: map[string]types.Identity{}, agents: map[string]types.Agent{}, serve: map[string]types.Decision{}, egress: map[string]types.Decision{}, events: make(chan struct{}, 1)}
	for _, id := range []string{"campus", "office", "client", "bob"} {
		b.agents[id] = types.Agent{ID: id, WorkspaceID: "w1", Workspace: "workspace1", UserID: "alice", Status: "active",
			Desired:  config.Config{Serve: config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: "http://127.0.0.1:8080"}, {Name: "api", Origin: "http://127.0.0.1:8081"}}}, Egress: config.EgressConfig{Enabled: true, Allow: []policy.Rule{{Domain: policy.Domain{Suffix: "example.com"}, Ports: []int{443}, Protocol: "tls"}}}},
			Approval: credentials.Approval{Revision: 1, ExpiresAt: until, Services: map[string]string{"demo": "http://127.0.0.1:8080", "api": "http://127.0.0.1:8081"}, Egress: []policy.Rule{{Domain: policy.Domain{Suffix: "example.com"}, Ports: []int{443}, Protocol: "tls"}}}}
		kind, user := "provider", "alice"
		if id == "client" || id == "bob" {
			kind = "access"
		}
		if id == "bob" {
			user = "bob"
		}
		b.tokens[id+"-token"] = types.Identity{TokenID: id + "-token-id", Kind: kind, UserID: user, AgentID: id, WorkspaceID: "w1", Workspace: "workspace1", ExpiresAt: until}
	}
	for _, route := range []struct{ host, agent string }{{"campus.example.com", "campus"}, {"office.example.com", "office"}} {
		b.egress["workspace1/alice/"+route.host+"/443"] = types.Decision{ResourceType: "egress", ResourceID: route.agent + "-route", WorkspaceID: "w1", Workspace: "workspace1", AgentID: route.agent, UserID: "alice", Destination: connection.Destination{Host: route.host, Port: 443}, Revision: 1, PolicyRevision: 1, ExpiresAt: until}
	}
	for _, name := range []string{"demo", "api"} {
		host := name + ".workspace1.instance.example"
		b.serve[host+"/alice"] = types.Decision{ResourceType: "service", ResourceID: name + "-service", WorkspaceID: "w1", Workspace: "workspace1", AgentID: "office", ServiceName: name, Hostname: host, UserID: "alice", Revision: 1, PolicyRevision: 1, ExpiresAt: until}
	}
	return b
}

type harness struct {
	e      *Edge
	b      *memoryBackend
	server *httptest.Server
	ctx    context.Context
}

func newHarness(t *testing.T) *harness {
	return newHarnessConfig(t, Config{RecheckInterval: 10 * time.Millisecond})
}
func newHarnessConfig(t *testing.T, cfg Config) *harness {
	t.Helper()
	b := fixtureBackend()
	e, err := New(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- e.Run(ctx) }()
	ts := httptest.NewUnstartedServer(e.Handler())
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(func() {
		cancel()
		shutdown, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		if err := e.Shutdown(shutdown); err != nil {
			t.Error(err)
		}
		ts.Close()
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("edge Run did not stop")
		}
	})
	return &harness{e: e, b: b, server: ts, ctx: ctx}
}
func await(t *testing.T, condition func() bool) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(until) {
			t.Fatal("condition timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func (h *harness) dial(t *testing.T, id, connector, transportToken, helloToken string, authorize connection.AuthorizeOpenFunc) (*connection.Session, error) {
	t.Helper()
	identity, _ := h.b.Identity(helloToken)
	raw, err := xhttp.Dial(h.ctx, h.server.URL+"/agent", xhttp.ClientConfig{HTTPClient: h.server.Client(), Headers: http.Header{"Authorization": {"Bearer " + transportToken}}})
	if err != nil {
		return nil, err
	}
	hello := connection.Hello{Version: connection.ProtocolVersion, Role: connection.Role(identity.Kind), Workspace: identity.Workspace, AgentID: id, Token: helloToken, Revision: 1}
	if identity.Kind == "provider" {
		hello.ConnectorID = connector
		hello.Services = []string{"demo", "api", "forged"}
		hello.EgressEnabled = true
	}
	s, err := connection.Client(h.ctx, raw, hello, connection.Config{AuthorizeOpen: authorize})
	if err != nil {
		raw.Close()
		return nil, err
	}
	t.Cleanup(func() { s.Close() })
	return s, nil
}
func permit(_ context.Context, _ connection.Principal, r connection.OpenRequest) (connection.OpenClaims, error) {
	return connection.OpenClaims{FlowID: r.FlowID, Purpose: r.Purpose, Resource: r.Resource, Destination: r.Destination, Protocol: r.Protocol, Revision: r.Revision, Deadline: r.Deadline}, nil
}
func (h *harness) provider(t *testing.T, id, connector string, authorize connection.AuthorizeOpenFunc, handler func(*connection.Stream)) *connection.Session {
	t.Helper()
	if authorize == nil {
		authorize = permit
	}
	s, err := h.dial(t, id, connector, id+"-token", id+"-token", authorize)
	if err != nil {
		t.Fatal(err)
	}
	await(t, func() bool {
		for _, c := range h.e.Snapshot().Connections {
			if c.ID == s.Principal().SessionID {
				return true
			}
		}
		return false
	})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			flow, err := s.Accept(h.ctx)
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); defer flow.Close(); handler(flow) }()
		}
	}()
	t.Cleanup(func() {
		s.Close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("provider handlers leaked")
		}
	})
	return s
}

type capture struct{ bytes.Buffer }

func (c *capture) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *capture) Close() error                     { return nil }
func (c *capture) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *capture) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *capture) SetDeadline(time.Time) error      { return nil }
func (c *capture) SetReadDeadline(time.Time) error  { return nil }
func (c *capture) SetWriteDeadline(time.Time) error { return nil }
func helloBytes(host string) []byte {
	c := new(capture)
	client := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
	_ = client.Handshake()
	return bytes.Clone(c.Bytes())
}

func TestExactAgentRoutingPreservesClientHello(t *testing.T) {
	h := newHarness(t)
	prefaces := map[string][]byte{}
	for _, agent := range []string{"campus", "office"} {
		agent := agent
		host := agent + ".example.com"
		preface := helloBytes(host)
		prefaces[host] = preface
		h.provider(t, agent, "connector-"+agent, nil, func(flow *connection.Stream) {
			if flow.Claims().Destination.Host != host {
				t.Errorf("wrong provider %s got %s", agent, flow.Claims().Destination.Host)
				return
			}
			got := make([]byte, len(preface)+4)
			if _, err := io.ReadFull(flow, got); err != nil {
				return
			}
			if !bytes.Equal(got, append(bytes.Clone(preface), []byte("ping")...)) {
				t.Error("TLS preface changed")
			}
			_, _ = flow.Write([]byte(agent))
			_ = flow.CloseWrite()
			_, _ = io.Copy(io.Discard, flow)
		})
	}
	access, err := h.dial(t, "client", "", "client-token", "client-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, agent := range []string{"campus", "office"} {
		host := agent + ".example.com"
		flow, err := access.Open(t.Context(), connection.OpenRequest{Purpose: connection.PurposeAccess, Destination: connection.Destination{Host: host, Port: 443}, Protocol: "tls", Deadline: time.Now().Add(20 * time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		flow.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = flow.Write(append(bytes.Clone(prefaces[host]), []byte("ping")...))
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(agent))
		if _, err = io.ReadFull(flow, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != agent {
			t.Fatalf("wrong exit %q", got)
		}
		flow.Close()
	}
	await(t, func() bool { return len(h.e.Snapshot().Flows) == 0 })
}

func TestTransportHelloBindingAndScope(t *testing.T) {
	h := newHarness(t)
	h.b.mu.Lock()
	alternate := h.b.tokens["office-token"]
	alternate.TokenID = "another-token-id"
	h.b.tokens["alternate"] = alternate
	h.b.mu.Unlock()
	if s, err := h.dial(t, "office", "c", "office-token", "alternate", permit); err == nil {
		s.Close()
		t.Fatal("mixed HTTP and Hello identities accepted")
	}
	bob, err := h.dial(t, "bob", "", "bob-token", "bob-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bob.Open(t.Context(), connection.OpenRequest{Purpose: connection.PurposeAccess, Destination: connection.Destination{Host: "office.example.com", Port: 443}, Protocol: "tls", Deadline: time.Now().Add(time.Second)})
	if err == nil {
		t.Fatal("another user inherited Alice's grant")
	}
	h.b.mu.Lock()
	id := h.b.tokens["client-token"]
	id.Kind = "control"
	h.b.tokens["control-token"] = id
	h.b.mu.Unlock()
	if _, err := xhttp.Dial(t.Context(), h.server.URL, xhttp.ClientConfig{HTTPClient: h.server.Client(), Headers: http.Header{"Authorization": {"Bearer control-token"}}}); err == nil {
		t.Fatal("control token admitted to public transport")
	}
}

func TestConnectorReplacementUsesCASAndRejectsClone(t *testing.T) {
	h := newHarness(t)
	handler := func(s *connection.Stream) { <-s.Context().Done() }
	first := h.provider(t, "office", "same-connector", nil, handler)
	h.e.mu.Lock()
	old := h.e.providers["office"]
	h.e.mu.Unlock()
	if s, err := h.dial(t, "office", "different-connector", "office-token", "office-token", permit); err == nil {
		s.Close()
		t.Fatal("clone replaced active Connector")
	}
	second := h.provider(t, "office", "same-connector", nil, handler)
	select {
	case <-first.Done():
	case <-time.After(time.Second):
		t.Fatal("old connection not closed")
	}
	h.e.removeProvider(old) // A delayed cleanup must not remove the newer session.
	h.e.mu.Lock()
	current := h.e.providers["office"]
	h.e.mu.Unlock()
	if current == nil || current.session.Principal().SessionID != second.Principal().SessionID {
		t.Fatal("old close removed new session")
	}
	if second.Principal().Generation <= first.Principal().Generation {
		t.Fatal("generation did not advance")
	}
	for _, service := range second.Principal().Services {
		if service == "forged" {
			t.Fatal("unapproved declaration accepted")
		}
	}
}

func TestServeOneFlowPerRequestAndBodyIntegrity(t *testing.T) {
	h := newHarness(t)
	var count atomic.Int32
	payload := strings.Repeat("response", 32768)
	h.provider(t, "office", "c", nil, func(flow *connection.Stream) {
		r, err := http.ReadRequest(bufio.NewReader(flow))
		if err != nil {
			return
		}
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Header.Get("X-Auth-Request-User") != "" || strings.Contains(r.Header.Get("Cookie"), "__Host-agents") || strings.Contains(r.Header.Get("Cookie"), "agents-dev-") {
			t.Error("platform identity leaked to origin")
		}
		count.Add(1)
		_, _ = fmt.Fprintf(flow, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nSet-Cookie: cross=x; Domain=instance.example\r\nSet-Cookie: agents-dev-service=evil\r\nConnection: close\r\n\r\n%s", len(payload), payload)
		_ = flow.CloseWrite()
		_, _ = io.Copy(io.Discard, flow)
	})
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.e.ServeHTTP(w, r, "alice") }))
	defer gw.Close()
	for i := 0; i < 2; i++ {
		r, _ := http.NewRequest(http.MethodPost, gw.URL+"/echo", strings.NewReader("request-body"))
		r.Host = "demo.workspace1.instance.example"
		r.Header.Set("X-Auth-Request-User", "forged")
		r.Header.Set("Cookie", "__Host-agents-session=secret; agents-dev-service=secret; app=ok")
		response, err := gw.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || string(got) != payload {
			t.Fatalf("response truncated/status %d len %d: %v", response.StatusCode, len(got), err)
		}
		if len(response.Cookies()) != 0 {
			t.Fatal("cross-domain cookie escaped gateway")
		}
	}
	if count.Load() != 2 {
		t.Fatalf("expected 2 independently opened flows, got %d", count.Load())
	}
	await(t, func() bool { return len(h.e.Snapshot().Flows) == 0 })
}

func TestResourceRevocationKeepsSiblingFlowAndSession(t *testing.T) {
	h := newHarness(t)
	closedDemo := make(chan struct{})
	closedAPI := make(chan struct{})
	provider := h.provider(t, "office", "c", nil, func(flow *connection.Stream) {
		r, err := http.ReadRequest(bufio.NewReader(flow))
		if err != nil {
			return
		}
		r.Body.Close()
		_, _ = io.WriteString(flow, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
		<-flow.Context().Done()
		if flow.Claims().Resource == "demo" {
			close(closedDemo)
		} else {
			close(closedAPI)
		}
	})
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.e.ServeHTTP(w, r, "alice") }))
	defer gw.Close()
	responses := map[string]*http.Response{}
	for _, name := range []string{"demo", "api"} {
		r, _ := http.NewRequest(http.MethodGet, gw.URL, nil)
		r.Host = name + ".workspace1.instance.example"
		response, err := gw.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		responses[name] = response
		t.Cleanup(func() { response.Body.Close() })
		b := make([]byte, 5)
		if _, err := io.ReadFull(response.Body, b); err != nil {
			t.Fatal(err)
		}
	}
	h.b.mu.Lock()
	delete(h.b.serve, "demo.workspace1.instance.example/alice")
	for k, d := range h.b.serve {
		d.PolicyRevision++
		h.b.serve[k] = d
	}
	h.b.mu.Unlock()
	h.b.changed()
	select {
	case <-closedDemo:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked flow stayed open")
	}
	select {
	case <-closedAPI:
		t.Fatal("sibling flow revoked")
	case <-provider.Done():
		t.Fatal("shared provider revoked")
	case <-time.After(40 * time.Millisecond):
	}
	responses["demo"].Body.Close()
	responses["api"].Body.Close()
	select {
	case <-closedAPI:
	case <-time.After(time.Second):
		t.Fatal("request cancellation did not reach provider")
	}
}

func TestRevocationCancelsPendingProviderOpen(t *testing.T) {
	h := newHarness(t)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	h.provider(t, "office", "c", func(ctx context.Context, _ connection.Principal, r connection.OpenRequest) (connection.OpenClaims, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return connection.OpenClaims{}, ctx.Err()
	}, func(*connection.Stream) { t.Error("revoked pending stream reached handler") })
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.e.ServeHTTP(w, r, "alice") }))
	defer gw.Close()
	request, _ := http.NewRequest(http.MethodGet, gw.URL, nil)
	request.Host = "demo.workspace1.instance.example"
	done := make(chan struct{})
	go func() {
		defer close(done)
		response, _ := gw.Client().Do(request)
		if response != nil {
			response.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("OPEN did not start")
	}
	h.b.mu.Lock()
	delete(h.b.serve, "demo.workspace1.instance.example/alice")
	h.b.mu.Unlock()
	h.b.changed()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("pending OPEN not canceled")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("gateway request leaked")
	}
}

func TestPendingAccessAndStaleProviderRevision(t *testing.T) {
	h := newHarness(t)
	h.b.mu.Lock()
	client := h.b.agents["client"]
	client.Status = "pending"
	h.b.agents["client"] = client
	office := h.b.agents["office"]
	office.Approval.Revision = 2
	h.b.agents["office"] = office
	h.b.mu.Unlock()
	if _, err := h.dial(t, "client", "", "client-token", "client-token", nil); err != nil {
		t.Fatalf("pending provider approval blocked valid access identity: %v", err)
	}
	if session, err := h.dial(t, "office", "c", "office-token", "office-token", permit); err == nil {
		session.Close()
		t.Fatal("stale provider configuration accepted")
	}
}

func TestUnavailableExactAgentDoesNotFallBack(t *testing.T) {
	h := newHarness(t)
	var wrongAgentCalls atomic.Int32
	h.provider(t, "campus", "c", nil, func(*connection.Stream) { wrongAgentCalls.Add(1) })
	access, err := h.dial(t, "client", "", "client-token", "client-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := access.Open(t.Context(), connection.OpenRequest{Purpose: connection.PurposeAccess,
		Destination: connection.Destination{Host: "office.example.com", Port: 443}, Protocol: "tls", Deadline: time.Now().Add(time.Second)})
	if err == nil {
		defer flow.Close()
		flow.SetDeadline(time.Now().Add(time.Second))
		_, _ = flow.Write(helloBytes("office.example.com"))
		if _, err := flow.Read(make([]byte, 1)); err == nil {
			t.Fatal("offline exit produced business bytes")
		}
	}
	if wrongAgentCalls.Load() != 0 {
		t.Fatal("used an available but unselected exit")
	}
}

type brokenBody struct{ closed atomic.Bool }

func (b *brokenBody) Read([]byte) (int, error) { return 0, errors.New("injected request-body failure") }
func (b *brokenBody) Close() error             { b.closed.Store(true); return nil }

func TestServeBodyFailureClosesPendingResources(t *testing.T) {
	h := newHarness(t)
	providerCanceled := make(chan struct{}, 1)
	h.provider(t, "office", "c", nil, func(flow *connection.Stream) {
		request, err := http.ReadRequest(bufio.NewReader(flow))
		if err == nil {
			_, _ = io.Copy(io.Discard, request.Body)
			request.Body.Close()
		}
		<-flow.Context().Done()
		providerCanceled <- struct{}{}
	})
	body := new(brokenBody)
	request := httptest.NewRequest(http.MethodPost, "http://demo.workspace1.instance.example/upload", body)
	request.ContentLength = 10
	response := httptest.NewRecorder()
	h.e.ServeHTTP(response, request, "alice")
	if response.Code != http.StatusBadGateway {
		t.Fatalf("body error returned %d", response.Code)
	}
	if !body.closed.Load() {
		t.Fatal("failed request body not closed")
	}
	select {
	case <-providerCanceled:
	case <-time.After(time.Second):
		t.Fatal("body failure leaked provider stream")
	}
	await(t, func() bool { return len(h.e.Snapshot().Flows) == 0 })
}

func TestGrantDeadlineClosesServeFlow(t *testing.T) {
	h := newHarness(t)
	h.b.mu.Lock()
	d := h.b.serve["demo.workspace1.instance.example/alice"]
	d.ExpiresAt = time.Now().Add(250 * time.Millisecond)
	h.b.serve["demo.workspace1.instance.example/alice"] = d
	h.b.mu.Unlock()
	canceled := make(chan struct{})
	h.provider(t, "office", "c", nil, func(flow *connection.Stream) {
		request, err := http.ReadRequest(bufio.NewReader(flow))
		if err != nil {
			return
		}
		request.Body.Close()
		_, _ = io.WriteString(flow, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n")
		<-flow.Context().Done()
		close(canceled)
	})
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.e.ServeHTTP(w, r, "alice") }))
	defer gw.Close()
	request, _ := http.NewRequest(http.MethodGet, gw.URL, nil)
	request.Host = "demo.workspace1.instance.example"
	response, err := gw.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadFull(response.Body, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("grant expiry did not close provider stream")
	}
	await(t, func() bool { return len(h.e.Snapshot().Flows) == 0 })
}

func TestRevocationInterruptsStalledRequestBody(t *testing.T) {
	h := newHarness(t)
	providerCanceled := make(chan struct{}, 1)
	h.provider(t, "office", "c", nil, func(flow *connection.Stream) {
		request, err := http.ReadRequest(bufio.NewReader(flow))
		if err == nil {
			_, _ = io.Copy(io.Discard, request.Body)
			request.Body.Close()
		}
		<-flow.Context().Done()
		providerCanceled <- struct{}{}
	})
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.e.ServeHTTP(w, r, "alice") }))
	defer gw.Close()
	client, err := net.Dial("tcp", gw.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = io.WriteString(client, "POST /upload HTTP/1.1\r\nHost: demo.workspace1.instance.example\r\nContent-Length: 1000000\r\n\r\nx")
	if err != nil {
		t.Fatal(err)
	}
	await(t, func() bool { return len(h.e.Snapshot().Flows) == 1 })
	h.b.mu.Lock()
	delete(h.b.serve, "demo.workspace1.instance.example/alice")
	h.b.mu.Unlock()
	h.b.changed()
	select {
	case <-providerCanceled:
	case <-time.After(time.Second):
		t.Fatal("stalled upload kept provider flow alive")
	}
	await(t, func() bool { return len(h.e.Snapshot().Flows) == 0 })
}

func TestRollingLeaseThroughRealProviderManager(t *testing.T) {
	h := newHarnessConfig(t, Config{SessionTTL: 3 * time.Second, FlowTTL: 200 * time.Millisecond, MaxFlowLifetime: 2 * time.Second, RecheckInterval: 10 * time.Millisecond})
	originCanceled := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "started\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(originCanceled)
	}))
	defer origin.Close()
	local := config.Config{Instance: "https://instance.example", Workspace: "workspace1", Serve: config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: origin.URL}}}}
	h.b.mu.Lock()
	h.b.decisionWindow = 180 * time.Millisecond
	agent := h.b.agents["office"]
	agent.Desired = local
	agent.Approval.Services = map[string]string{"demo": origin.URL}
	h.b.agents["office"] = agent
	h.b.mu.Unlock()
	manager := orchestration.New(&local, agent.Approval)
	var authorizations atomic.Int32
	provider := h.provider(t, "office", "c", func(ctx context.Context, p connection.Principal, r connection.OpenRequest) (connection.OpenClaims, error) {
		authorizations.Add(1)
		return manager.AuthorizeOpen(ctx, p, r)
	}, func(flow *connection.Stream) { _ = manager.Handle(h.ctx, flow) })
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.e.ServeHTTP(w, r, "alice") }))
	defer gw.Close()
	request, _ := http.NewRequest(http.MethodGet, gw.URL, nil)
	request.Host = "demo.workspace1.instance.example"
	response, err := gw.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadFull(response.Body, make([]byte, len("started\n"))); err != nil {
		t.Fatal(err)
	}
	initial := h.e.Snapshot().Flows[0]
	time.Sleep(750 * time.Millisecond)
	select {
	case <-originCanceled:
		t.Fatal("original decision lease ended real provider handler")
	case <-provider.Done():
		t.Fatal("renewal replaced provider session")
	default:
	}
	view := h.e.Snapshot()
	if len(view.Flows) != 1 || view.Flows[0].ID != initial.ID || !view.Flows[0].ExpiresAt.After(initial.ExpiresAt) {
		t.Fatal("flow was not renewed in place")
	}
	if authorizations.Load() < 3 || manager.ActiveFlows() != 1 {
		t.Fatalf("provider was not reauthorized across leases: calls=%d active=%d", authorizations.Load(), manager.ActiveFlows())
	}
	h.b.mu.Lock()
	delete(h.b.serve, "demo.workspace1.instance.example/alice")
	h.b.mu.Unlock()
	h.b.changed()
	select {
	case <-originCanceled:
	case <-time.After(time.Second):
		t.Fatal("grant revocation did not reach real origin after renewals")
	}
	await(t, func() bool { return manager.ActiveFlows() == 0 && len(h.e.Snapshot().Flows) == 0 })
}

func TestRollingAccessAndProviderLeasesRemainOnExactAgent(t *testing.T) {
	h := newHarnessConfig(t, Config{SessionTTL: 3 * time.Second, FlowTTL: 200 * time.Millisecond, MaxFlowLifetime: 2 * time.Second, RecheckInterval: 10 * time.Millisecond})
	h.b.mu.Lock()
	h.b.decisionWindow = 180 * time.Millisecond
	h.b.mu.Unlock()
	preface := helloBytes("office.example.com")
	var admissions atomic.Int32
	h.provider(t, "office", "c", func(ctx context.Context, p connection.Principal, r connection.OpenRequest) (connection.OpenClaims, error) {
		admissions.Add(1)
		return permit(ctx, p, r)
	}, func(flow *connection.Stream) {
		if _, err := io.ReadFull(flow, make([]byte, len(preface))); err != nil {
			return
		}
		_, _ = io.Copy(flow, flow)
	})
	access, err := h.dial(t, "client", "", "client-token", "client-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := access.Open(t.Context(), connection.OpenRequest{Purpose: connection.PurposeAccess, Destination: connection.Destination{Host: "office.example.com", Port: 443}, Protocol: "tls", Deadline: time.Now().Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	firstLease := flow.Claims().LeaseExpiresAt
	if _, err := flow.Write(preface); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	if !flow.Claims().LeaseExpiresAt.After(firstLease) || admissions.Load() < 3 {
		t.Fatal("access and provider leases were not both renewed")
	}
	flow.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = flow.Write([]byte("still same stream")) }()
	got := make([]byte, len("still same stream"))
	if _, err := io.ReadFull(flow, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "still same stream" {
		t.Fatal("renewal corrupted bytes")
	}
	// Changing the selected Agent must terminate this flow, never migrate it.
	h.b.mu.Lock()
	d := h.b.egress["workspace1/alice/office.example.com/443"]
	d.AgentID = "campus"
	h.b.egress["workspace1/alice/office.example.com/443"] = d
	h.b.mu.Unlock()
	h.b.changed()
	select {
	case <-flow.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("route change migrated/retained original flow")
	}
}

func TestRenewedFlowStillHonorsHardDeadline(t *testing.T) {
	h := newHarnessConfig(t, Config{SessionTTL: 2 * time.Second, FlowTTL: 160 * time.Millisecond, MaxFlowLifetime: 650 * time.Millisecond, RecheckInterval: 10 * time.Millisecond})
	h.b.mu.Lock()
	h.b.decisionWindow = 150 * time.Millisecond
	h.b.mu.Unlock()
	closed := make(chan struct{})
	provider := h.provider(t, "office", "c", nil, func(flow *connection.Stream) {
		request, err := http.ReadRequest(bufio.NewReader(flow))
		if err != nil {
			return
		}
		request.Body.Close()
		_, _ = io.WriteString(flow, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n")
		<-flow.Context().Done()
		close(closed)
	})
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.e.ServeHTTP(w, r, "alice") }))
	defer gw.Close()
	request, _ := http.NewRequest(http.MethodGet, gw.URL, nil)
	request.Host = "demo.workspace1.instance.example"
	response, err := gw.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.ReadFull(response.Body, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(350 * time.Millisecond)
	select {
	case <-closed:
		t.Fatal("short lease ended flow before hard limit")
	default:
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("rolling lease bypassed hard flow deadline")
	}
	select {
	case <-provider.Done():
		t.Fatal("hard flow boundary closed sibling-capable session")
	default:
	}
}

func TestDefaultLeaseAndLifetimeBounds(t *testing.T) {
	e, err := New(fixtureBackend(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown(t.Context())
	if e.cfg.FlowTTL != 55*time.Second || e.cfg.SessionTTL != 24*time.Hour || e.cfg.MaxFlowLifetime != 12*time.Hour {
		t.Fatal("default hard/soft bounds differ from contract")
	}
	if _, err := New(fixtureBackend(), Config{FlowTTL: time.Minute + time.Second}); err == nil {
		t.Fatal("unbounded policy lease accepted")
	}
}

var _ Backend = (*memoryBackend)(nil)
