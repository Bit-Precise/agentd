package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type script struct {
	mu        sync.Mutex
	responses []func(http.ResponseWriter)
	polls     int
	forms     []string
}

func (s *script) server(t *testing.T) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "device_authorization_endpoint": srv.URL + "/device", "token_endpoint": srv.URL + "/token"})
		case "/device":
			_ = r.ParseForm()
			s.mu.Lock()
			s.forms = append(s.forms, r.Form.Encode())
			s.mu.Unlock()
			_ = json.NewEncoder(w).Encode(Authorization{DeviceCode: "secret-device-code", UserCode: "ABCD-EFGH", VerificationURI: srv.URL + "/verify", ExpiresIn: 600, Interval: 2})
		case "/token":
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != grantType || r.Form.Get("device_code") != "secret-device-code" || r.Form.Get("client_id") != "agentd" {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
				return
			}
			s.mu.Lock()
			next := s.responses[s.polls]
			s.polls++
			s.mu.Unlock()
			next(w)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func oauth(status int, code string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
	}
}

func TestPollHonorsIntervalSlowDownAndTransientFailures(t *testing.T) {
	s := &script{responses: []func(http.ResponseWriter){
		oauth(400, "authorization_pending"),
		oauth(400, "slow_down"),
		oauth(503, "temporarily_unavailable"),
		oauth(400, "authorization_pending"),
		func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer","scope":"agents:enroll","expires_in":300}`))
		},
	}}
	srv := s.server(t)
	var waits []time.Duration
	c := &Client{HTTP: srv.Client(), Sleep: func(ctx context.Context, d time.Duration) error { waits = append(waits, d); return ctx.Err() }}
	endpoints, err := c.Discover(t.Context(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := c.Start(t.Context(), endpoints.DeviceAuthorization, "agentd", "agents:enroll", "urn:agents:test:agent-enrollment")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.forms[0], "audience=urn%3Aagents%3Atest%3Aagent-enrollment") {
		t.Fatalf("audience was not requested explicitly: %s", s.forms[0])
	}
	token, err := c.Poll(t.Context(), endpoints.Token, "agentd", auth)
	if err != nil || token.AccessToken != "at" {
		t.Fatalf("poll = %+v, %v", token, err)
	}
	want := []time.Duration{2 * time.Second, 2 * time.Second, 7 * time.Second, 14 * time.Second, 7 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v", waits)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("wait %d = %v, want %v (all %v)", i, waits[i], want[i], waits)
		}
	}
}

func TestPollStopsOnTerminalErrors(t *testing.T) {
	for code, want := range map[string]error{"access_denied": ErrDenied, "expired_token": ErrExpired, "invalid_grant": ErrExpired} {
		t.Run(code, func(t *testing.T) {
			s := &script{responses: []func(http.ResponseWriter){oauth(400, code)}}
			srv := s.server(t)
			c := &Client{HTTP: srv.Client(), Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() }}
			auth := Authorization{DeviceCode: "secret-device-code", ExpiresIn: 60, Interval: 1}
			if _, err := c.Poll(t.Context(), srv.URL+"/token", "agentd", auth); !errors.Is(err, want) || s.polls != 1 {
				t.Fatalf("%s: err=%v polls=%d", code, err, s.polls)
			}
		})
	}
}

func TestDiscoveryRejectsForeignEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "http://" + r.Host, "device_authorization_endpoint": "https://attacker.example/device", "token_endpoint": "http://" + r.Host + "/token"})
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client()}
	if _, err := c.Discover(t.Context(), srv.URL); err == nil {
		t.Fatal("device authorization endpoint on another origin was accepted")
	}
}
