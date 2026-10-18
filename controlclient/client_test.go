package controlclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/credentials"
)

func TestInstanceMismatchDoesNotSendCredential(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(401) }))
	defer target.Close()
	cfg := &config.Config{Instance: target.URL}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	identity := credentials.Credentials{ControlToken: "private-device-token", ControlURL: "https://original.example"}
	if _, err = client.Refresh(t.Context(), identity); err == nil {
		t.Fatal("wrong-instance refresh accepted")
	}
	if _, err = client.Update(t.Context(), identity, cfg); err == nil {
		t.Fatal("wrong-instance config accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("credential was transmitted to a different control origin")
	}
}

func TestHTTPErrorKeepsBoundedControlReason(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"kind":"forbidden","message":"guests cannot provide serve\n` + strings.Repeat("x", 400) + `"}}`))
	}))
	defer target.Close()
	cfg := &config.Config{Instance: target.URL, Workspace: "w1", Agent: config.AgentConfig{Name: "agent1"}}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Update(t.Context(), credentials.Credentials{ControlToken: "token", ControlURL: target.URL}, cfg)
	var failure *HTTPError
	if !Rejected(err) || AuthenticationRejected(err) || !errors.As(err, &failure) || failure.Kind != "forbidden" || len(failure.Message) != 256 || strings.ContainsAny(failure.Message, "\n") {
		t.Fatalf("policy rejection was not classified with a bounded reason: %v", err)
	}
}
