package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bit-precise/agentd/api"
	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/credentials"
	"github.com/bit-precise/agentd/deviceflow"
)

func loginFixture(t *testing.T, offerDeviceFlow bool) (*config.Config, *httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/instance":
			info := api.InstanceInfo{ServerURL: srv.URL}
			if offerDeviceFlow {
				info.DeviceAuthorization = &api.DeviceAuthorizationInfo{Issuer: srv.URL, ClientID: "agentd", Scope: "agents:enroll", Audience: "urn:agents:test:agent-enrollment"}
			}
			_ = json.NewEncoder(w).Encode(info)
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "device_authorization_endpoint": srv.URL + "/device", "token_endpoint": srv.URL + "/token"})
		case "/device":
			_ = json.NewEncoder(w).Encode(deviceflow.Authorization{DeviceCode: "device-code-secret", UserCode: "WXYZ-1234", VerificationURI: srv.URL + "/verify", VerificationURIComplete: srv.URL + "/verify?user_code=WXYZ-1234", ExpiresIn: 60, Interval: 1})
		case "/token":
			if polls.Add(1) == 1 {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"access-token-secret","token_type":"bearer","scope":"agents:enroll","expires_in":300}`))
		case "/v1/agent-enrollments":
			var request api.AgentEnrollment
			if r.Header.Get("Authorization") != "Bearer access-token-secret" || json.NewDecoder(r.Body).Decode(&request) != nil || request.Name != "laptop" || request.Workspace != "w1" || !request.Desired.Ingress.Enabled {
				w.WriteHeader(403)
				return
			}
			principal := api.Principal{Type: api.PrincipalUser, ID: "alice"}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(api.EnrollResponse{
				Agent: api.Agent{ID: "agent-1", Name: "laptop", Workspace: "w1", Principal: principal},
				Credentials: api.Credentials{Version: api.CredentialsVersion, Workspace: "w1", AgentID: "agent-1", Principal: &principal, ControlToken: "control-token", AccessToken: "device-access-token",
					Effective: api.EffectiveConfig{Revision: 1, ExpiresAt: time.Now().Add(time.Hour), Ingress: true}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Instance: srv.URL, Workspace: "w1", Agent: config.AgentConfig{Name: "laptop", StateDir: state},
		Transport: config.TransportConfig{Type: "xhttp", Endpoint: srv.URL + "/agent", AllowHTTP: true}, Ingress: config.IngressConfig{Enabled: true}}
	return cfg, srv, &polls
}

func TestLoginRunsDeviceFlowAndStoresOnlyDeviceCredentials(t *testing.T) {
	cfg, srv, polls := loginFixture(t, true)
	var out, prompt bytes.Buffer
	var opened []string
	flow := &deviceflow.Client{Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }}
	err := login(t.Context(), cfg, loginOptions{}, &out, &prompt, func(url string) error { opened = append(opened, url); return nil }, flow)
	if err != nil {
		t.Fatal(err)
	}
	if polls.Load() != 2 || len(opened) != 1 || opened[0] != srv.URL+"/verify?user_code=WXYZ-1234" {
		t.Fatalf("polls=%d opened=%v", polls.Load(), opened)
	}
	if !strings.Contains(prompt.String(), "WXYZ-1234") || strings.Contains(prompt.String()+out.String(), "device-code-secret") || strings.Contains(prompt.String()+out.String(), "access-token-secret") {
		t.Fatalf("prompt leaked secrets or omitted the user code:\n%s%s", prompt.String(), out.String())
	}
	if !strings.Contains(out.String(), "as user alice") {
		t.Fatalf("result did not name the principal: %s", out.String())
	}
	saved, err := credentials.Load(cfg.Agent.StateDir)
	if err != nil || saved.Principal == nil || saved.Principal.ID != "alice" || saved.ControlURL != srv.URL {
		t.Fatalf("saved credentials = %+v, %v", saved, err)
	}
	entries, _ := os.ReadDir(cfg.Agent.StateDir)
	for _, entry := range entries {
		data, _ := os.ReadFile(filepath.Join(cfg.Agent.StateDir, entry.Name()))
		if bytes.Contains(data, []byte("access-token-secret")) || bytes.Contains(data, []byte("device-code-secret")) {
			t.Fatalf("%s persisted an OAuth secret", entry.Name())
		}
	}
	if err := login(t.Context(), cfg, loginOptions{noBrowser: true}, &out, &prompt, func(string) error { t.Fatal("browser opened"); return nil }, flow); err == nil {
		t.Fatal("login replaced existing credentials without --replace")
	}
}

func TestLoginRequiresDeviceFlowSupport(t *testing.T) {
	cfg, _, _ := loginFixture(t, false)
	err := login(t.Context(), cfg, loginOptions{noBrowser: true}, &bytes.Buffer{}, &bytes.Buffer{}, nil, &deviceflow.Client{})
	if err == nil || !strings.Contains(err.Error(), "enroll --key-file") {
		t.Fatalf("missing device flow support: %v", err)
	}
}
