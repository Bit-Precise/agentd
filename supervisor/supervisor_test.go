package supervisor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/credentials"
	"github.com/rs/zerolog"
)

func TestControlRejectionStopsImmediately(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer server.Close()
	cfg := &config.Config{Instance: server.URL, Workspace: "work", Agent: config.AgentConfig{StateDir: filepath.Join(t.TempDir(), "state")}}
	creds := &credentials.Credentials{Version: 1, AgentID: "device", Workspace: "work", ControlToken: "control-token", ControlURL: server.URL, Approval: credentials.Approval{Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}}
	s, err := New(cfg, creds, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err = s.Run(ctx); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("identity rejection must terminate promptly with cause: %v", err)
	}
}

func TestStaticApprovalExpiryIsReported(t *testing.T) {
	cfg := &config.Config{Workspace: "work", Agent: config.AgentConfig{StateDir: filepath.Join(t.TempDir(), "state")}}
	creds := &credentials.Credentials{Workspace: "work", Approval: credentials.Approval{Revision: 1, ExpiresAt: time.Now().Add(100 * time.Millisecond)}}
	s, err := New(cfg, creds, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "approval snapshot expired") {
		t.Fatalf("silent approval expiry: %v", err)
	}
}

func TestFailedDesiredUpdateIsRetried(t *testing.T) {
	var updates atomic.Int32
	var desired atomic.Bool
	creds := &credentials.Credentials{Version: 1, AgentID: "device", Workspace: "work", ControlToken: "control-token", Approval: credentials.Approval{Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/config" {
			if updates.Add(1) == 1 {
				w.WriteHeader(503)
				return
			}
			var cfg config.Config
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				t.Error(err)
			}
			desired.Store(len(cfg.Serve.Services) == 1 && cfg.Serve.Services[0].Name == "new")
			w.WriteHeader(200)
			return
		}
		_ = json.NewEncoder(w).Encode(creds)
	}))
	defer server.Close()
	creds.ControlURL = server.URL
	cfg := &config.Config{Instance: server.URL, Workspace: "work", Agent: config.AgentConfig{StateDir: filepath.Join(t.TempDir(), "state")}}
	s, err := New(cfg, creds, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	next := *cfg
	next.Serve.Services = []config.ServiceConfig{{Name: "new", Origin: "http://localhost:3000"}}
	if err = s.Reload(&next); err == nil {
		t.Fatal("failed initial update not reported")
	}
	// Mutating the caller's config must not mutate the queued retry.
	next.Serve.Services[0].Name = "mutated"
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	done := make(chan struct{})
	go func() { defer close(done); s.pollControl(ctx, cancel) }()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !desired.Load() {
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("desired configuration was not retried intact")
		}
	}
	cancel(nil)
	<-done
}
