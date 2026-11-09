package sim

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/adminapi"
	"agentd/internal/control"
	"agentd/internal/identity"
	"agentd/internal/pgtest"
	"agentd/internal/pki"
	"agentd/internal/relay"
	"agentd/internal/store"
	"agentd/internal/transport"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

const (
	adminToken = "sim-admin-token-0123456789"
	relayToken = "sim-relay-token-0123456789"
	srvDomain  = "agentsrv.test"
	relayName  = "relay-1"
	relayHost  = "relay-1.agentsrv.test"
)

// stack is agentserver + one agentrelay on loopback, with a dialer that maps
// the test names to the listeners.
type stack struct {
	t      *testing.T
	ctx    context.Context
	srv    *control.Server
	admin  *adminapi.ClientWithResponses
	relay  *relay.Server
	roots  *x509.CertPool
	logger *slog.Logger
	extra  sync.Map // host -> address for origin servers
}

func (s *stack) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var target string
	if v, ok := s.extra.Load(host); ok {
		var d net.Dialer
		return d.DialContext(ctx, network, v.(string))
	}
	switch {
	case host == srvDomain:
		target = s.srv.RelayAddr().String()
	case host == relayHost || strings.HasSuffix(host, "."+srvDomain):
		target = s.relay.Addr().String()
	default:
		return nil, fmt.Errorf("sim: no route to %s", host)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, target)
}

func newStack(t *testing.T) *stack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	lvl := slog.LevelWarn
	if os.Getenv("SIM_DEBUG") != "" {
		lvl = slog.LevelDebug
	}
	s := &stack{t: t, ctx: ctx, logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))}
	t.Setenv("AGENTSERVER_ADMIN_TOKEN", adminToken)
	t.Setenv("SIM_RELAY_TOKEN", relayToken)
	cfg, err := control.ParseServerConfig([]byte(`
apiVersion: agentd/v1
kind: AgentserverConfiguration
domain: ` + srvDomain + `
listen: 127.0.0.1:0
admin_listen: 127.0.0.1:0
relay_join_token_env: SIM_RELAY_TOKEN
tls: { mode: selfsigned }
`))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, pgtest.NewDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if s.srv, err = control.NewServer(ctx, cfg, control.ServerOptions{Store: st, Logger: s.logger.With("c", "agentserver")}); err != nil {
		t.Fatal(err)
	}
	srvDone := make(chan struct{})
	go func() { s.srv.Run(ctx); close(srvDone) }()

	s.roots = pki.Pool(s.srv.TLS.CAPEM)
	rcfg, err := relay.ParseConfig([]byte(`
apiVersion: agentd/v1
kind: AgentrelayConfiguration
name: ` + relayName + `
domain: ` + relayHost + `
url: https://` + relayHost + `
listen: 127.0.0.1:0
control: { url: "https://` + srvDomain + `", join_token_env: SIM_RELAY_TOKEN }
tls: { mode: selfsigned }
`))
	if err != nil {
		t.Fatal(err)
	}
	relayKey, _ := identity.GenerateKey()
	if s.relay, err = relay.NewServer(rcfg, relay.Options{Logger: s.logger.With("c", "agentrelay"), Key: relayKey,
		ControlDial: transport.Options{RootCAs: s.roots, NetDial: s.dial}}); err != nil {
		t.Fatal(err)
	}
	s.roots.AppendCertsFromPEM(s.relay.TLS.CAPEM)
	relayDone := make(chan struct{})
	go func() { s.relay.Run(ctx); close(relayDone) }()
	t.Cleanup(func() { cancel(); <-relayDone; <-srvDone })

	s.admin, _ = adminapi.NewClientWithResponses("http://"+s.srv.AdminAddr().String()+"/api/v1", adminapi.WithRequestEditorFn(func(ctx context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+adminToken)
		return nil
	}))
	s.eventually("relay registers and connects", func() bool {
		ok, _ := s.srv.Coordinator.RelayConnected(relayName)
		return ok
	})
	return s
}

func (s *stack) eventually(what string, f func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.t.Fatalf("timed out waiting: %s", what)
}

// workspace creates a workspace on the relay and waits until the relay can
// vouch for it (relay certificate pushed).
func (s *stack) workspace(name string) adminapi.Workspace {
	s.t.Helper()
	r, err := s.admin.CreateWorkspaceWithResponse(s.ctx, adminapi.WorkspaceCreate{Name: name, Relay: relayName})
	if err != nil || r.JSON201 == nil {
		s.t.Fatalf("create workspace: %v %s", err, r.Body)
	}
	s.eventually("relay certificate for "+name, func() bool { _, err := s.relayCert(r.JSON201.BaseDomain); return err == nil })
	return *r.JSON201
}

func (s *stack) httpClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: s.dial, TLSClientConfig: tlsConfig(s.roots)}}
}

// relayCert fetches /.well-known/agentd for a workspace.
func (s *stack) relayCert(base string) (*pb.RelayCert, error) {
	resp, err := s.httpClient().Get("https://" + relayHost + "/.well-known/agentd?workspace=" + base)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, b)
	}
	var v struct {
		RelayCert string `json:"relay_cert"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	b, err := base64.RawURLEncoding.DecodeString(v.RelayCert)
	if err != nil {
		return nil, err
	}
	var c pb.RelayCert
	return &c, proto.Unmarshal(b, &c)
}

func (s *stack) token(ws, name string, roles ...adminapi.Role) string {
	s.t.Helper()
	tc := adminapi.TokenCreate{Name: &name}
	if len(roles) > 0 {
		tc.Roles = &roles
	}
	r, err := s.admin.CreateTokenWithResponse(s.ctx, ws, tc)
	if err != nil || r.JSON201 == nil {
		s.t.Fatalf("create token: %v %s", err, r.Body)
	}
	return r.JSON201.JoinLink
}

var _ = wire.MinorVersion
