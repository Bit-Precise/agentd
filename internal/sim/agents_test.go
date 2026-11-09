package sim

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentd/internal/adminapi"
	"agentd/internal/agent"
	"agentd/internal/identity"
	"agentd/internal/pki"
	"agentd/internal/transport"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// node is one agentd instance in the sim.
type node struct {
	name string
	dir  string
	a    *agent.Agent
	key  []byte
}

// join enrolls an instance and rewrites its roles section.
func (s *stack) join(ws, name, roles string) *node {
	s.t.Helper()
	dir := filepath.Join(s.t.TempDir(), name)
	ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
	defer cancel()
	res, err := agent.Join(ctx, dir, s.token(ws, name), agent.JoinOptions{Dial: transport.Options{RootCAs: s.roots, NetDial: s.dial}})
	if err != nil {
		s.t.Fatalf("join %s: %v", name, err)
	}
	if res.Name != name {
		s.t.Fatalf("joined as %q, want %q", res.Name, name)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	head := string(b)[:strings.Index(string(b), "roles:")]
	cfg := head + "roles:\n" + roles + "\nlog:\n  path: \"\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		s.t.Fatal(err)
	}
	a, err := agent.New(dir, agent.Options{Logger: s.logger.With("node", name), RootCAs: s.roots, NetDial: s.dial, NoLocalAPI: true})
	if err != nil {
		s.t.Fatalf("start %s: %v\n%s", name, err, cfg)
	}
	done := make(chan struct{})
	go func() { a.Run(s.ctx); close(done) }()
	s.t.Cleanup(func() { a.Stop(); <-done })
	n := &node{name: name, dir: dir, a: a, key: a.PublicKey()}
	s.eventually(name+" online", func() bool { ok, _ := s.srv.Coordinator.NodeOnline(n.key); return ok })
	return n
}

func key(n *node) string { return identity.EncodeKey(n.key) }

// socksDial opens a CONNECT through a SOCKS5 proxy.
func socksDial(t *testing.T, proxy, host string, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0})
	r := bufio.NewReader(c)
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil || b[1] != 0 {
		t.Fatalf("socks greeting: %v %v", err, b)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(r, rep); err != nil || rep[1] != 0 {
		t.Fatalf("socks connect: %v %v", err, rep)
	}
	return c
}

func httpsGet(conn net.Conn, roots *tlsConfigT, host, path string) (*http.Response, string, error) {
	tc := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots.RootCAs, NextProtos: []string{"http/1.1"}})
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		return nil, "", err
	}
	fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		return nil, "", err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body), nil
}

type tlsConfigT = tls.Config

func TestEndToEnd(t *testing.T) {
	s := newStack(t)
	ws := s.workspace("home")
	base := ws.BaseDomain

	// An origin "on the campus network" that only dorm can reach.
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "campus says hi to %s", r.Host)
	}))
	originCert, originCA, err := pki.SelfSigned([]string{"course.campus.test", "blocked.campus.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{originCert}}
	origin.StartTLS()
	defer origin.Close()
	s.extra.Store("course.campus.test", origin.Listener.Addr().String())
	s.extra.Store("blocked.campus.test", origin.Listener.Addr().String())
	originRoots := pki.Pool(originCA)

	// A plaintext app on homepc.
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "nas host=%s peer=%s fwd=%s", r.Host, r.Header.Get("X-Agentd-Peer"), r.Header.Get("X-Forwarded-Proto"))
	}))
	defer app.Close()
	appPort := app.Listener.Addr().(*net.TCPAddr).Port

	socksPort, mcpPort := freePort(t), freePort(t)
	laptop := s.join("home", "laptop", fmt.Sprintf(`
  ingress:
    enabled: true
    socks5: { enabled: true, port: %d }
    fallback: reject
  submitter:
    enabled: true
    mcp: { port: %d }
`, socksPort, mcpPort))
	workdir := t.TempDir()
	dorm := s.join("home", "dorm", fmt.Sprintf(`
  egress:
    enabled: true
    policies:
      - { public_key: %q, action: allow, proto: tls, domains: [{ kind: suffix, value: course.campus.test }] }
`, key(laptop)))
	office := s.join("home", "office", fmt.Sprintf(`
  executor:
    enabled: true
    description: test executor
    workdir: %q
    policies:
      - { public_key: %q, action: allow, argv: ["echo"] }
`, workdir, key(laptop)))
	homepc := s.join("home", "homepc", fmt.Sprintf(`
  service:
    enabled: true
    servers:
      - { name: nas, proto: http, target: { host: 127.0.0.1, port: %d } }
      - { name: grafana, proto: http, target: { host: 127.0.0.1, port: %d } }
    policies:
      - { public_key: %q, action: allow, service: nas }
      - { public_key: "*", action: allow, service: grafana }
`, appPort, appPort, key(laptop)))
	_ = dorm
	_ = homepc

	// Route campus.test through dorm.
	proto := []adminapi.Proto{"tls"}
	if r, err := s.admin.AddRouteWithResponse(s.ctx, "home", adminapi.RouteWrite{From: "workspace", Proto: &proto, Domains: []adminapi.Match{{Kind: "suffix", Value: "campus.test"}}, To: "dorm"}); err != nil || r.StatusCode() != 201 {
		t.Fatalf("add route: %v %s", err, r.Body)
	}
	proxy := fmt.Sprintf("127.0.0.1:%d", socksPort)
	s.eventually("laptop receives the route", func() bool {
		v := laptop.a.Routes()
		return len(v.Routes) == 1
	})

	t.Run("egress via dorm", func(t *testing.T) {
		c := socksDial(t, proxy, "course.campus.test", 443)
		defer c.Close()
		resp, body, err := httpsGet(c, &tls.Config{RootCAs: originRoots}, "course.campus.test", "/")
		if err != nil || resp.StatusCode != 200 || !strings.Contains(body, "campus says hi to course.campus.test") {
			t.Fatalf("egress: %v %v %q", err, resp, body)
		}
	})

	t.Run("egress denied by dorm's policy", func(t *testing.T) {
		c := socksDial(t, proxy, "blocked.campus.test", 443)
		defer c.Close()
		if _, _, err := httpsGet(c, &tls.Config{RootCAs: originRoots}, "blocked.campus.test", "/"); err == nil {
			t.Fatal("blocked.campus.test must not be reachable through dorm")
		}
	})

	t.Run("task on office", func(t *testing.T) {
		s.eventually("laptop sees office as executor", func() bool { _, _, err := laptop.a.ResolveExecutor("office"); return err == nil })
		ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
		defer cancel()
		exec, _, _ := laptop.a.ResolveExecutor("office")
		out, err := laptop.a.Submit(ctx, exec, fc("exec_command", `{"cmd":"echo hello from office"}`))
		if err != nil || out.ExitCode == nil || *out.ExitCode != 0 || !strings.Contains(out.Output, "hello from office") {
			t.Fatalf("exec: %v %v", err, out)
		}
		if _, err := laptop.a.Submit(ctx, exec, fc("exec_command", `{"cmd":"ls /"}`)); err == nil || !strings.Contains(err.Error(), "POLICY_DENIED") {
			t.Fatalf("ls must be denied by office's policy, got %v", err)
		}
		_ = office
	})

	t.Run("mcp tools", func(t *testing.T) {
		testMCP(t, s, fmt.Sprintf("http://127.0.0.1:%d/mcp", mcpPort))
	})

	t.Run("http service via edge", func(t *testing.T) {
		s.eventually("nas is ready", func() bool {
			for _, sv := range laptop.a.Routes().Services {
				if sv.FQDN == "nas."+base && sv.State == "ready" {
					return true
				}
			}
			return false
		})
		c := socksDial(t, proxy, "nas."+base, 443)
		defer c.Close()
		resp, body, err := httpsGet(c, &tls.Config{RootCAs: s.roots}, "nas."+base, "/")
		if err != nil || resp.StatusCode != 200 || !strings.Contains(body, "peer=laptop") || !strings.Contains(body, "host=nas."+base) || !strings.Contains(body, "fwd=https") {
			t.Fatalf("member access to nas: %v %v %q", err, resp, body)
		}
		// Public visitors: grafana has a "*" rule, nas does not.
		hc := s.httpClient()
		r1, err := hc.Get("https://grafana." + base + "/")
		if err != nil {
			t.Fatal(err)
		}
		b1, _ := io.ReadAll(r1.Body)
		r1.Body.Close()
		if r1.StatusCode != 200 || !strings.Contains(string(b1), "peer= ") {
			t.Fatalf("public grafana: %d %q", r1.StatusCode, b1)
		}
		r2, err := hc.Get("https://nas." + base + "/")
		if err != nil {
			t.Fatal(err)
		}
		r2.Body.Close()
		if r2.StatusCode != http.StatusForbidden {
			t.Fatalf("public nas must be forbidden, got %d", r2.StatusCode)
		}
	})
}
