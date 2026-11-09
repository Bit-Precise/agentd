package control

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"agentd/internal/adminapi"
	"agentd/internal/identity"
	"agentd/internal/pgtest"
	"agentd/internal/pki"
	"agentd/internal/store"
)

const testAdminToken = "test-admin-token-0123456789"

// startServer runs a full agentserver on loopback with a self-signed chain.
func startServer(t *testing.T) (*Server, *adminapi.ClientWithResponses) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Setenv("AGENTSERVER_ADMIN_TOKEN", testAdminToken)
	cfg, err := ParseServerConfig([]byte(`
apiVersion: agentd/v1
kind: AgentserverConfiguration
domain: agentsrv.test
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:0
tls: { mode: selfsigned, names: ["127.0.0.1"] }
`))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, pgtest.NewDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	srv, err := NewServer(ctx, cfg, ServerOptions{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { srv.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	cl, err := adminapi.NewClientWithResponses("http://"+srv.AdminAddr().String()+"/api/v1", adminapi.WithRequestEditorFn(func(ctx context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+testAdminToken)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return srv, cl
}

func TestServerAdminAndWellKnown(t *testing.T) {
	srv, cl := startServer(t)
	ctx := context.Background()

	// Without the token the API refuses.
	resp, err := http.Get("http://" + srv.AdminAddr().String() + "/api/v1/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", resp.StatusCode)
	}

	relayKey, _ := identity.GenerateKey()
	r, err := cl.RegisterRelayWithResponse(ctx, adminapi.RelayCreate{Name: "relay-hk", PublicKey: identity.EncodeKey(identity.Public(relayKey)), Url: "https://relay-hk.agentsrv.test"})
	if err != nil || r.JSON201 == nil {
		t.Fatalf("register relay: %v %s", err, r.Body)
	}
	w, err := cl.CreateWorkspaceWithResponse(ctx, adminapi.WorkspaceCreate{Name: "home", Relay: "relay-hk"})
	if err != nil || w.JSON201 == nil {
		t.Fatalf("create workspace: %v %s", err, w.Body)
	}
	if w.JSON201.BaseDomain != "home.agentsrv.test" {
		t.Fatalf("base domain: %s", w.JSON201.BaseDomain)
	}
	name := "laptop"
	tk, err := cl.CreateTokenWithResponse(ctx, "home", adminapi.TokenCreate{Name: &name})
	if err != nil || tk.JSON201 == nil {
		t.Fatalf("create token: %v %s", err, tk.Body)
	}
	link, err := identity.ParseJoinLink(tk.JSON201.JoinLink)
	if err != nil || link.RelayURL != "https://relay-hk.agentsrv.test" || link.Name != "laptop" {
		t.Fatalf("join link %q: %v %+v", tk.JSON201.JoinLink, err, link)
	}
	if bad, _ := cl.CreateWorkspaceWithResponse(ctx, adminapi.WorkspaceCreate{Name: "Bad_Name", Relay: "relay-hk"}); bad.StatusCode() != http.StatusBadRequest {
		t.Fatalf("bad workspace name: %d %s", bad.StatusCode(), bad.Body)
	}

	// The relay-session listener serves the well-known identity over TLS
	// that verifies against the self-signed CA.
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.Pool(srv.TLS.CAPEM), ServerName: "agentsrv.test"}}}
	resp, err = hc.Get("https://" + srv.RelayAddr().String() + "/.well-known/agentserver")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var wk struct{ Identity string }
	json.NewDecoder(resp.Body).Decode(&wk)
	if wk.Identity != identity.EncodeKey(srv.PublicKey()) {
		t.Fatalf("well-known identity %q", wk.Identity)
	}
}

func TestServerConfigValidation(t *testing.T) {
	bad := []string{
		"apiVersion: agentd/v1\nkind: Wrong\ndomain: a.test\ntls: {mode: selfsigned}\n",
		"apiVersion: agentd/v1\nkind: AgentserverConfiguration\ndomain: a.test\n",
		"apiVersion: agentd/v1\nkind: AgentserverConfiguration\ndomain: a.test\ntls: {mode: selfsigned}\nunknown: 1\n",
		"apiVersion: agentd/v1\nkind: AgentserverConfiguration\ndomain: a.test\ntls: {mode: file}\n",
		"apiVersion: agentd/v1\nkind: AgentserverConfiguration\ndomain: a.test\ntls: {mode: selfsigned}\ndns_providers: {cf: {provider: cloudflare}}\n",
		"apiVersion: agentd/v1\nkind: AgentserverConfiguration\ndomain: a.test\ntls: {mode: selfsigned}\ndefault_dns_provider: nope\n",
	}
	for i, b := range bad {
		if _, err := ParseServerConfig([]byte(b)); err == nil {
			t.Errorf("config %d should be rejected", i)
		}
	}
	c, err := ParseServerConfig([]byte("apiVersion: agentd/v1\nkind: AgentserverConfiguration\ndomain: a.test\ntls: {mode: selfsigned}\nrelay_cert_ttl: 48h\n"))
	if err != nil || c.RelayCertTTL != 48*time.Hour || c.AdminListen != "127.0.0.1:7800" {
		t.Fatalf("defaults: %v %+v", err, c)
	}
}
