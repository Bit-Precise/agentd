// Package servertest exercises the public control API and the actual agent
// supervisor over loopback HTTP; policy is persisted in a real SQLite database.
package servertest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/control"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/controlclient"
	"github.com/bit-precise/agentd/policy"
	"github.com/bit-precise/agentd/supervisor"
	"github.com/rs/zerolog"
)

const adminToken = "test-bootstrap-admin-token-with-at-least-32-bytes"

type harness struct {
	t         *testing.T
	app       *control.App
	server    *httptest.Server
	cfg       control.Config
	base      string
	client    *http.Client
	closeOnce sync.Once
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return startHarness(t, filepath.Join(t.TempDir(), "control.sqlite"), "127.0.0.1:0")
}

func startHarness(t *testing.T, databasePath, listenAddress string) *harness {
	t.Helper()
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	base := "http://localhost:" + port
	cfg := control.Config{ListenAddress: listener.Addr().String(), ServerURL: base, EdgeURL: base + "/agent", StateDir: filepath.Dir(databasePath), DevelopmentHTTP: true}
	cfg.Database.Type = "sqlite"
	cfg.Database.DSN = databasePath
	if err := cfg.Validate(); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	app, err := control.New(t.Context(), cfg, adminToken)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(app.Handler())
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil}}
	h := &harness{t: t, app: app, server: server, cfg: cfg, base: base, client: client}
	t.Cleanup(h.close)
	return h
}

func (h *harness) close() {
	h.closeOnce.Do(func() { h.client.CloseIdleConnections(); _ = h.app.Close(); h.server.Close() })
}

func (h *harness) api(method, path, token string, body, out any, want int) {
	h.t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
	}
	r, err := http.NewRequestWithContext(h.t.Context(), method, h.base+path, bytes.NewReader(encoded))
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.client.Do(r)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		h.t.Fatal(err)
	}
	if resp.StatusCode != want {
		h.t.Fatalf("%s %s returned %d, want %d: %s", method, path, resp.StatusCode, want, data)
	}
	if out != nil {
		if err = json.Unmarshal(data, out); err != nil {
			h.t.Fatalf("decode %s: %v: %s", path, err, data)
		}
	}
}

type userCredential struct {
	User  types.User `json:"user"`
	Token string     `json:"token"`
}

func (h *harness) workspace(name, userName string) (types.Workspace, userCredential) {
	h.t.Helper()
	var w types.Workspace
	var u userCredential
	h.api("POST", "/api/v1/workspaces", adminToken, map[string]string{"name": name}, &w, 201)
	h.api("POST", "/api/v1/users", adminToken, map[string]any{"name": userName, "admin": false}, &u, 201)
	h.api("POST", "/api/v1/memberships", adminToken, types.Membership{WorkspaceID: w.ID, UserID: u.User.ID, Role: "developer"}, nil, 201)
	return w, u
}

func (h *harness) enroll(cfg *config.Config, w types.Workspace, u userCredential, roles []string, auto bool) (types.EnrollResponse, *controlclient.Client) {
	h.t.Helper()
	var key struct {
		Key   types.EnrollmentKey `json:"key"`
		Token string              `json:"token"`
	}
	h.api("POST", "/api/v1/enrollment-keys", adminToken, types.EnrollmentKey{WorkspaceID: w.ID, UserID: u.User.ID, Roles: roles, MaxUses: 1, AutoApprove: auto, ExpiresAt: time.Now().Add(time.Hour)}, &key, 201)
	client, err := controlclient.New(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(client.Close)
	response, err := client.Enroll(h.t.Context(), key.Token)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := client.Enroll(h.t.Context(), key.Token); err == nil {
		h.t.Fatal("one-use enrollment key admitted a second registration")
	}
	return response, client
}

func (h *harness) agentConfig(workspace, name string) *config.Config {
	h.t.Helper()
	return &config.Config{APIVersion: "agents/v1alpha1", Kind: "AgentConfig", Instance: h.base, Workspace: workspace,
		Agent:     config.AgentConfig{Name: name, StateDir: filepath.Join(h.t.TempDir(), "agent-state")},
		Transport: config.TransportConfig{Type: "xhttp", Mode: "packet-up", Endpoint: h.base + "/agent", AllowHTTP: true},
		Ingress:   config.IngressConfig{OnUnmatched: "reject"}}
}

func (h *harness) runAgent(cfg *config.Config, enrolled types.EnrollResponse, options ...supervisor.Option) func() {
	_, stop := h.runAgentInstance(cfg, enrolled, options...)
	return stop
}

func (h *harness) runAgentInstance(cfg *config.Config, enrolled types.EnrollResponse, options ...supervisor.Option) (*supervisor.Supervisor, func()) {
	h.t.Helper()
	s, err := supervisor.New(cfg, &enrolled.Credentials, zerolog.Nop(), options...)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(h.t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					h.t.Errorf("supervisor shutdown: %v", err)
				}
			case <-time.After(12 * time.Second):
				h.t.Error("supervisor failed to stop")
			}
		})
	}
	h.t.Cleanup(stop)
	return s, stop
}

func await(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for data-plane state")
}

func (h *harness) connected(agentID, role string) bool {
	for _, c := range h.app.Edge.Snapshot().Connections {
		if c.AgentID == agentID && c.Role == role {
			return true
		}
	}
	return false
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

func tlsRule(host string) policy.Rule {
	return policy.Rule{Domain: policy.Domain{Exact: host}, Ports: []int{443}, Protocol: "tls"}
}

func (h *harness) serveRequest(host, token, path string) (*http.Response, error) {
	r, err := http.NewRequestWithContext(h.t.Context(), "GET", h.base+path, nil)
	if err != nil {
		return nil, err
	}
	r.Host = host
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return h.client.Do(r)
}

func readResponse(t *testing.T, response *http.Response, want int) string {
	t.Helper()
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("response status %d want %d: %s", response.StatusCode, want, data)
	}
	return string(data)
}

func (h *harness) grantRoute(w types.Workspace, u userCredential, agentID, domain, name string) (types.EgressRoute, types.Grant) {
	h.t.Helper()
	var r types.EgressRoute
	var g types.Grant
	h.api("POST", "/api/v1/egress-routes", adminToken, types.EgressRoute{WorkspaceID: w.ID, AgentID: agentID, Name: name, Rule: tlsRule(domain)}, &r, 201)
	h.api("POST", "/api/v1/grants", adminToken, types.Grant{WorkspaceID: w.ID, ResourceType: "egress", ResourceID: r.ID, SubjectType: "user", SubjectID: u.User.ID, ExpiresAt: time.Now().Add(time.Hour)}, &g, 201)
	return r, g
}

func serviceHost(service, workspace string) string {
	return fmt.Sprintf("%s.%s.localhost", service, workspace)
}
