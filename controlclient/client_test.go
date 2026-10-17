package controlclient

import (
	"net/http"
	"net/http/httptest"
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
	if err = client.Update(t.Context(), identity, cfg); err == nil {
		t.Fatal("wrong-instance config accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("credential was transmitted to a different control origin")
	}
}
