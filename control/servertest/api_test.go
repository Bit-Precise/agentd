package servertest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/credentials"
	"github.com/bit-precise/agentd/edge"
	"github.com/bit-precise/agentd/policy"
)

func TestManualApprovalThroughHTTPAPIAndSupervisor(t *testing.T) {
	h := newHarness(t)
	w, u := h.workspace("workspace", "alice")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("management bearer token leaked to origin")
		}
		_, _ = io.WriteString(w, "published-origin")
	}))
	defer origin.Close()
	cfg := h.agentConfig(w.Name, "provider")
	cfg.Serve = config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: origin.URL}}}
	enrolled, client := h.enroll(cfg, w, u, []string{"serve"}, false)
	if enrolled.Agent.Status != "pending" {
		t.Fatal("manual enrollment did not remain pending")
	}
	h.runAgent(cfg, enrolled)
	response, err := h.serveRequest(serviceHost("demo", w.Name), u.Token, "/")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response, http.StatusForbidden)
	if h.connected(enrolled.Agent.ID, "provider") {
		t.Fatal("pending provider connected before approval")
	}
	h.api("POST", "/api/v1/agents/"+enrolled.Agent.ID+"/approve", adminToken, nil, nil, 200)
	await(t, func() bool { return h.connected(enrolled.Agent.ID, "provider") })
	refreshed, err := client.Refresh(t.Context(), enrolled.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.ProviderToken != enrolled.Credentials.ProviderToken || refreshed.Approval.Revision <= enrolled.Credentials.Approval.Revision {
		t.Fatal("client did not merge secret with updated approval")
	}
	response, err = h.serveRequest(serviceHost("demo", w.Name), u.Token, "/")
	if err != nil {
		t.Fatal(err)
	}
	if body := readResponse(t, response, 200); body != "published-origin" {
		t.Fatalf("wrong origin response %q", body)
	}
	response, err = h.serveRequest(serviceHost("demo", w.Name), "", "/")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response, 403)
}

func TestBrowserSessionCSRFAndDisabledUser(t *testing.T) {
	h := newHarness(t)
	_, u := h.workspace("workspace", "alice")
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	request := func(method, path, origin, csrf string, body any) (*http.Response, []byte) {
		t.Helper()
		encoded, _ := json.Marshal(body)
		r, err := http.NewRequestWithContext(t.Context(), method, h.base+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return resp, data
	}
	login, data := request("POST", "/api/v1/login", h.base, "", map[string]string{"token": adminToken})
	if login.StatusCode != 200 {
		t.Fatalf("admin login: %d %s", login.StatusCode, data)
	}
	var logged struct {
		CSRF string `json:"csrfToken"`
	}
	if err = json.Unmarshal(data, &logged); err != nil || logged.CSRF == "" {
		t.Fatal("login omitted CSRF token")
	}
	for _, cookie := range login.Cookies() {
		if cookie.Domain != "" || !cookie.HttpOnly || cookie.Path != "/" || !cookie.Expires.After(time.Now()) {
			t.Fatalf("unsafe or expired browser cookie: %+v", cookie)
		}
	}
	resp, data := request("GET", "/api/v1/me", "", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("fresh bootstrap cookie not usable: %d %s", resp.StatusCode, data)
	}
	resp, _ = request("POST", "/api/v1/workspaces", h.base, "", map[string]string{"name": "forged"})
	if resp.StatusCode < 400 {
		t.Fatal("cookie mutation without CSRF accepted")
	}
	resp, _ = request("POST", "/api/v1/workspaces", "http://evil.example", logged.CSRF, map[string]string{"name": "forged"})
	if resp.StatusCode != 403 {
		t.Fatalf("foreign Origin accepted: %d", resp.StatusCode)
	}
	resp, data = request("POST", "/api/v1/workspaces", h.base, logged.CSRF, map[string]string{"name": "legitimate"})
	if resp.StatusCode != 201 {
		t.Fatalf("valid cookie mutation failed: %d %s", resp.StatusCode, data)
	}
	resp, _ = request("POST", "/api/v1/logout", h.base, logged.CSRF, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("logout status %d", resp.StatusCode)
	}
	resp, _ = request("GET", "/api/v1/me", "", "", nil)
	if resp.StatusCode != 401 {
		t.Fatal("logged out cookie retained access")
	}
	resp, data = request("POST", "/api/v1/login", h.base, "", map[string]string{"token": u.Token})
	if resp.StatusCode != 200 {
		t.Fatalf("user login: %s", data)
	}
	h.api("DELETE", "/api/v1/users/"+u.User.ID, adminToken, nil, nil, 200)
	resp, _ = request("GET", "/api/v1/me", "", "", nil)
	if resp.StatusCode != 401 {
		t.Fatal("disabled user's existing cookie retained access")
	}
}

func TestHTTPAPIPersistsRegistrationAcrossServerRestart(t *testing.T) {
	h := newHarness(t)
	w, u := h.workspace("workspace", "alice")
	cfg := h.agentConfig(w.Name, "device")
	cfg.Ingress = config.IngressConfig{Enabled: true, HTTP: config.ListenerConfig{Enabled: true, Listen: "127.0.0.1:18888"}, Routes: []policy.Rule{tlsRule("example.com")}, OnUnmatched: "reject"}
	enrolled, _ := h.enroll(cfg, w, u, []string{"ingress"}, false)
	address := h.cfg.ListenAddress
	database := h.cfg.Database.DSN
	h.close()
	restarted := startHarness(t, database, address)
	var snapshot types.Snapshot
	restarted.api("GET", "/api/v1/state", u.Token, nil, &snapshot, 200)
	if len(snapshot.Agents) != 1 || snapshot.Agents[0].ID != enrolled.Agent.ID || len(snapshot.Workspaces) != 1 {
		t.Fatal("server restart lost scoped resource state")
	}
	var refreshed credentials.Credentials
	restarted.api("GET", "/api/v1/agent/credentials", enrolled.Credentials.ControlToken, nil, &refreshed, 200)
	if refreshed.AgentID != enrolled.Agent.ID || refreshed.ProviderToken != "" || refreshed.AccessToken != "" {
		t.Fatal("restart lost agent identity or exposed stored original secrets")
	}
}

func TestSnapshotDoesNotLeakOtherWorkspaceSessions(t *testing.T) {
	h := newHarness(t)
	w1, alice := h.workspace("one", "alice")
	w2, bob := h.workspace("two", "bob")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	enroll := func(w types.Workspace, u userCredential, name string) types.EnrollResponse {
		cfg := h.agentConfig(w.Name, name)
		cfg.Serve = config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: origin.URL}}}
		response, _ := h.enroll(cfg, w, u, []string{"serve"}, true)
		h.runAgent(cfg, response)
		return response
	}
	first := enroll(w1, alice, "alice-agent")
	second := enroll(w2, bob, "bob-agent")
	await(t, func() bool {
		return h.connected(first.Agent.ID, "provider") && h.connected(second.Agent.ID, "provider")
	})
	var view struct {
		types.Snapshot
		Connections []edge.ConnectionStatus `json:"connections"`
		Flows       []edge.FlowStatus       `json:"flows"`
	}
	h.api("GET", "/api/v1/state", alice.Token, nil, &view, 200)
	if len(view.Workspaces) != 1 || view.Workspaces[0].ID != w1.ID {
		t.Fatal("snapshot leaked another workspace")
	}
	for _, a := range view.Agents {
		if a.WorkspaceID != w1.ID {
			t.Fatal("agent leaked across workspace")
		}
	}
	for _, c := range view.Connections {
		if c.WorkspaceID != w1.ID || c.AgentID == second.Agent.ID {
			t.Fatal("Edge session metadata leaked across workspace")
		}
	}
	h.api("POST", "/api/v1/egress-routes", adminToken, types.EgressRoute{WorkspaceID: w2.ID, AgentID: first.Agent.ID, Name: "cross-tenant", Rule: tlsRule("example.com")}, nil, 403)
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), second.Credentials.ProviderToken) || strings.Contains(string(encoded), second.Agent.ID) {
		t.Fatal("foreign identity or secret escaped state filtering")
	}
}

func TestBootstrapTokenRotationSurvivesHTTPServerRestart(t *testing.T) {
	h := newHarness(t)
	var me struct {
		User types.User `json:"user"`
	}
	h.api("GET", "/api/v1/me", adminToken, nil, &me, 200)
	var rotated struct {
		Token string `json:"token"`
	}
	h.api("POST", "/api/v1/users/"+me.User.ID+"/token", adminToken, nil, &rotated, 201)
	if rotated.Token == "" || rotated.Token == adminToken {
		t.Fatal("rotation did not issue a new secret")
	}
	h.api("GET", "/api/v1/me", adminToken, nil, nil, 401)
	h.api("GET", "/api/v1/me", rotated.Token, nil, nil, 200)
	address, path := h.cfg.ListenAddress, h.cfg.Database.DSN
	h.close()
	restarted := startHarness(t, path, address)
	restarted.api("GET", "/api/v1/me", adminToken, nil, nil, 401)
	var restored struct {
		User types.User `json:"user"`
	}
	restarted.api("GET", "/api/v1/me", rotated.Token, nil, &restored, 200)
	if restored.User.ID != me.User.ID {
		t.Fatal("token rotation replaced stable administrator identity")
	}
}
