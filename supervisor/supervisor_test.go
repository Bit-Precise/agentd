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

	"github.com/bit-precise/agentd/api"
	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/credentials"
	"github.com/rs/zerolog"
)

func TestControlRejectionStopsImmediately(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer server.Close()
	cfg := &config.Config{Instance: server.URL, Workspace: "work", Agent: config.AgentConfig{StateDir: filepath.Join(t.TempDir(), "state")}}
	creds := &credentials.Credentials{Version: api.CredentialsVersion, AgentID: "device", Workspace: "work", ControlToken: "control-token", ControlURL: server.URL, Effective: api.EffectiveConfig{Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}}
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

func TestStaticEffectiveExpiryIsReported(t *testing.T) {
	cfg := &config.Config{Workspace: "work", Agent: config.AgentConfig{StateDir: filepath.Join(t.TempDir(), "state")}}
	creds := &credentials.Credentials{Workspace: "work", Effective: api.EffectiveConfig{Revision: 1, ExpiresAt: time.Now().Add(100 * time.Millisecond)}}
	s, err := New(cfg, creds, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "effective configuration snapshot expired") {
		t.Fatalf("silent effective configuration expiry: %v", err)
	}
}

func TestControlOutageKeepsRunningUntilEffectiveExpiry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	cfg := &config.Config{Instance: server.URL, Workspace: "work", Agent: config.AgentConfig{StateDir: filepath.Join(t.TempDir(), "state")}}
	for _, tc := range []struct {
		name    string
		expires time.Duration
		want    string
	}{{"outage outlives the snapshot", 400 * time.Millisecond, "expired without reaching control"}, {"outage within validity", time.Hour, context.DeadlineExceeded.Error()}} {
		t.Run(tc.name, func(t *testing.T) {
			creds := &credentials.Credentials{Version: api.CredentialsVersion, AgentID: "device", Workspace: "work", ControlToken: "control-token", ControlURL: server.URL, Effective: api.EffectiveConfig{Revision: 1, ExpiresAt: time.Now().Add(tc.expires)}}
			s, err := New(cfg, creds, zerolog.Nop())
			if err != nil {
				t.Fatal(err)
			}
			s.pollInterval = 20 * time.Millisecond
			ctx, cancel := context.WithTimeout(t.Context(), 800*time.Millisecond)
			defer cancel()
			started := time.Now()
			err = s.Run(ctx)
			if err == nil || !strings.Contains(err.Error(), tc.want) || time.Since(started) < 350*time.Millisecond {
				t.Fatalf("control outage handling = %v after %v", err, time.Since(started))
			}
		})
	}
}

func TestRejectedDesiredUpdateIsNotRetried(t *testing.T) {
	var updates atomic.Int32
	creds := &credentials.Credentials{Version: api.CredentialsVersion, AgentID: "device", Workspace: "work", ControlToken: "control-token", Effective: api.EffectiveConfig{Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/config" {
			updates.Add(1)
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":{"kind":"forbidden","message":"desired role exceeds enrollment permission"}}`))
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
	s.pollInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancelCause(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); s.pollControl(ctx, cancel) }()
	time.Sleep(200 * time.Millisecond)
	cancel(nil)
	<-done
	if updates.Load() != 1 || context.Cause(ctx) != context.Canceled {
		t.Fatalf("policy rejection was retried %d times or stopped the agent: %v", updates.Load(), context.Cause(ctx))
	}
}

func TestFailedDesiredUpdateIsRetried(t *testing.T) {
	var updates atomic.Int32
	var desired atomic.Bool
	creds := &credentials.Credentials{Version: api.CredentialsVersion, AgentID: "device", Workspace: "work", ControlToken: "control-token", Effective: api.EffectiveConfig{Revision: 1, ExpiresAt: time.Now().Add(time.Hour)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/config" {
			if updates.Add(1) == 1 {
				w.WriteHeader(503)
				return
			}
			var update api.ConfigUpdate
			if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
				t.Error(err)
			}
			desired.Store(len(update.Desired.Serve.Services) == 1 && update.Desired.Serve.Services[0].Name == "new")
			_, _ = w.Write([]byte("{}"))
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
