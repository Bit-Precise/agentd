package control

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/control/types"
)

func TestServiceLoginBrokerBindsHostStateAndAuthenticationExpiry(t *testing.T) {
	cfg := Config{ListenAddress: "127.0.0.1:8443", ServerURL: "https://agents.test", EdgeURL: "https://agents.test/agent"}
	cfg.TLS.CertFile = "test.crt"
	cfg.TLS.KeyFile = "test.key"
	cfg.Database.Type = "sqlite"
	cfg.Database.DSN = filepath.Join(t.TempDir(), "state.db")
	const bootstrap = "test-bootstrap-token-32-characters-minimum"
	app, err := New(t.Context(), cfg, bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	admin, err := app.State.BootstrapAdmin(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	user, token, err := app.State.CreateUser(admin.ID, "alice", false)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := app.State.CreateWorkspace(admin.ID, "work")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.State.SetMembership(admin.ID, workspace.ID, user.ID, "developer"); err != nil {
		t.Fatal(err)
	}
	_, key, err := app.State.CreateEnrollmentKey(admin.ID, types.EnrollmentKey{WorkspaceID: workspace.ID, UserID: user.ID, Roles: []string{"serve"}, MaxUses: 1, AutoApprove: true})
	if err != nil {
		t.Fatal(err)
	}
	desired := config.Config{APIVersion: "agents/v1alpha1", Kind: "AgentConfig", Instance: cfg.ServerURL, Workspace: "work", Agent: config.AgentConfig{Name: "laptop", StateDir: "./state"}, Transport: config.TransportConfig{Type: "xhttp", Mode: "packet-up", Endpoint: cfg.EdgeURL}, Serve: config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: "http://127.0.0.1:3000"}}}, Ingress: config.IngressConfig{OnUnmatched: "reject"}}
	if _, err = app.State.Enroll(types.EnrollRequest{EnrollmentKey: key, Config: desired}); err != nil {
		t.Fatal(err)
	}
	nonce := strings.Repeat("a", 64)
	target := "https://demo.work.agents.test/nested?app=ok"
	authorize := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", cfg.ServerURL+"/auth/authorize?"+url.Values{"return_to": {target}, "state": {nonce}}.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, req)
		return w
	}
	for _, bad := range []string{"https://evil.test/", "https://demo.work.agents.test:444/", "https://demo.work.agents.test@evil.test/"} {
		if response := authorize(bad); response.Code < 400 {
			t.Fatalf("unsafe target %q accepted: %d", bad, response.Code)
		}
	}
	response := authorize(target)
	if response.Code != 303 {
		t.Fatalf("authorize: %d %s", response.Code, response.Body.String())
	}
	callback, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := app.State.Identity(token)
	if err != nil {
		t.Fatal(err)
	}
	app.auth.mu.Lock()
	entry := app.auth.codes[secretHash(callback.Query().Get("code"))]
	app.auth.mu.Unlock()
	if !entry.IdentityExpiresAt.Equal(identity.ExpiresAt) {
		t.Fatal("Bearer login discarded the underlying identity expiry")
	}
	// Model a central authentication that expires sooner than the service cookie.
	identityExpiry := time.Now().Add(20 * time.Second).Truncate(time.Second)
	app.auth.mu.Lock()
	entry.IdentityExpiresAt = identityExpiry
	app.auth.codes[secretHash(callback.Query().Get("code"))] = entry
	app.auth.mu.Unlock()
	call := func(host, state string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", callback.String(), nil)
		req.Host = host
		req.AddCookie(&http.Cookie{Name: app.cookieName("state"), Value: state})
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, req)
		return w
	}
	if call("other.work.agents.test", nonce).Code != 403 {
		t.Fatal("code accepted on another service host")
	}
	if call(callback.Host, strings.Repeat("b", 64)).Code != 403 {
		t.Fatal("mismatched browser state accepted")
	}
	accepted := call(callback.Host, nonce)
	if accepted.Code != 303 || accepted.Header().Get("Location") != target {
		t.Fatalf("callback failed: %d %s", accepted.Code, accepted.Body.String())
	}
	var serviceCookie *http.Cookie
	for _, cookie := range accepted.Result().Cookies() {
		if cookie.Name == app.cookieName("service") {
			serviceCookie = cookie
		}
	}
	if serviceCookie == nil || !serviceCookie.Expires.Equal(identityExpiry) || !serviceCookie.Secure || !serviceCookie.HttpOnly || serviceCookie.Domain != "" {
		t.Fatal("service cookie not bounded to authentication and host")
	}
	if call(callback.Host, nonce).Code != 403 {
		t.Fatal("one-use login code replay accepted")
	}
	req := httptest.NewRequest("GET", target, nil)
	req.AddCookie(serviceCookie)
	session, ok := app.session(req, "service")
	if !ok || session.UserID != user.ID {
		t.Fatal("new service session unusable")
	}
	if _, _, err = app.actor(req, false); err == nil {
		t.Fatal("service cookie accepted as console identity")
	}
	req.AddCookie(serviceCookie)
	if _, ok = app.session(req, "service"); ok {
		t.Fatal("duplicate service cookies accepted")
	}
	streamCtx, stopStream := app.watchToken(t.Context(), token)
	defer stopStream()
	otherCtx, stopOther := app.watchToken(t.Context(), bootstrap)
	defer stopOther()
	if _, err := app.State.RotateUserToken(admin.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-streamCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("rotated Bearer retained an active stream identity")
	}
	if otherCtx.Err() != nil {
		t.Fatal("user token rotation canceled another identity")
	}
}

func TestOriginNormalizesDefaultPortButRejectsOtherOrigins(t *testing.T) {
	app := &App{Config: Config{ServerURL: "https://agents.test:443"}}
	for _, value := range []string{"https://agents.test", "https://AGENTS.test:443", "https://agents.test/"} {
		if !app.validOrigin(value) {
			t.Errorf("equivalent origin rejected: %s", value)
		}
	}
	for _, value := range []string{"https://evil.test", "https://agents.test:444", "https://user@agents.test", "http://agents.test", "https://agents.test/path", "https://agents.test?x=y", "null"} {
		if app.validOrigin(value) {
			t.Errorf("foreign origin accepted: %s", value)
		}
	}
}
