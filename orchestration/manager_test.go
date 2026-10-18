package orchestration

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/bit-precise/agentd/api"
	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/policy"
)

func tlsRule(domain string) policy.Rule {
	return policy.Rule{Domain: policy.Domain{Exact: domain}, Ports: []int{443}, Protocol: "tls"}
}

func testManagerConfig() *config.Config {
	return &config.Config{
		Instance: "https://instance.example", Workspace: "w1", Agent: config.AgentConfig{Name: "agent1", StateDir: "/test/state"},
		Transport: config.TransportConfig{Type: "xhttp", Endpoint: "https://connect.instance.example/agent", Mode: "packet-up"},
		Serve: config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{
			{Name: "demo", Origin: "http://127.0.0.1:8080"}, {Name: "api", Origin: "http://127.0.0.1:3000"},
		}},
		Egress: config.EgressConfig{Enabled: true, Allow: []policy.Rule{tlsRule("oa.example"), tlsRule("local-only.example"), tlsRule("blocked.example")}},
	}
}

func testEffective() api.EffectiveConfig {
	return api.EffectiveConfig{
		Revision: 7, ExpiresAt: time.Now().Add(time.Minute),
		Services: []api.EffectiveService{{Name: "demo", Origin: "http://127.0.0.1:8080", Hostname: "demo.w1.instance.example"}, {Name: "api", Origin: "http://127.0.0.1:3000", Hostname: "api.w1.instance.example"}},
		Egress:   []policy.Rule{tlsRule("oa.example"), tlsRule("effective-only.example"), tlsRule("blocked.example")},
		Deny:     []policy.Rule{tlsRule("blocked.example")},
	}
}

func testOpen(purpose connection.Purpose) connection.OpenRequest {
	r := connection.OpenRequest{FlowID: "flow1", Purpose: purpose, Revision: 7, Deadline: time.Now().Add(30 * time.Second)}
	if purpose == connection.PurposeServe {
		r.Resource, r.Protocol = "demo", "http"
	} else {
		r.Resource, r.Protocol = "office", "tls"
		r.Destination = connection.Destination{Host: "oa.example", Port: 443}
	}
	return r
}

func authorize(m *Manager, r connection.OpenRequest) error {
	_, err := m.AuthorizeOpen(context.Background(), connection.Principal{Role: connection.RoleProvider, Workspace: "w1", AgentID: "agent1"}, r)
	return err
}

func TestEffectiveAndLocalPolicyIntersection(t *testing.T) {
	m := New(testManagerConfig(), testEffective())
	for _, tc := range []struct {
		name    string
		request connection.OpenRequest
		allowed bool
	}{
		{"effective serve", testOpen(connection.PurposeServe), true},
		{"effective egress", testOpen(connection.PurposeEgress), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := authorize(m, tc.request); (err == nil) != tc.allowed {
				t.Fatalf("authorization = %v, allowed = %v", err, tc.allowed)
			}
		})
	}
	for _, domain := range []string{"local-only.example", "effective-only.example", "blocked.example", "unlisted.example"} {
		r := testOpen(connection.PurposeEgress)
		r.Destination.Host = domain
		if err := authorize(m, r); err == nil {
			t.Errorf("domain outside effective intersection accepted: %s", domain)
		}
	}
	cfg := testManagerConfig()
	cfg.Egress.Deny = []policy.Rule{tlsRule("oa.example")}
	m = New(cfg, testEffective())
	if err := authorize(m, testOpen(connection.PurposeEgress)); err == nil {
		t.Fatal("local deny did not override effective allow")
	}
}

func TestRejectInvalidOrExpiredOpen(t *testing.T) {
	for name, change := range map[string]func(*connection.OpenRequest){
		"missing deadline":  func(r *connection.OpenRequest) { r.Deadline = time.Time{} },
		"expired":           func(r *connection.OpenRequest) { r.Deadline = time.Now().Add(-time.Second) },
		"wrong purpose":     func(r *connection.OpenRequest) { r.Purpose = connection.PurposeAccess },
		"wrong protocol":    func(r *connection.OpenRequest) { r.Protocol = "tcp" },
		"noncanonical host": func(r *connection.OpenRequest) { r.Destination.Host = "OA.EXAMPLE." },
		"IP destination":    func(r *connection.OpenRequest) { r.Destination.Host = "127.0.0.1" },
		"wrong port":        func(r *connection.OpenRequest) { r.Destination.Port = 8443 },
	} {
		t.Run(name, func(t *testing.T) {
			m := New(testManagerConfig(), testEffective())
			r := testOpen(connection.PurposeEgress)
			change(&r)
			if err := authorize(m, r); err == nil {
				t.Fatal("invalid OPEN authorized")
			}
		})
	}
	for _, port := range []uint16{443, 0} {
		r := testOpen(connection.PurposeServe)
		r.Destination = connection.Destination{Host: "unapproved.example", Port: port}
		if err := authorize(New(testManagerConfig(), testEffective()), r); err == nil {
			t.Fatal("serve OPEN accepted arbitrary target")
		}
	}
	effective := testEffective()
	effective.ExpiresAt = time.Now().Add(-time.Second)
	if err := authorize(New(testManagerConfig(), effective), testOpen(connection.PurposeServe)); err == nil {
		t.Fatal("expired effective configuration remained usable")
	}
}

func TestOpenIsAuthorizedByContentNotRevision(t *testing.T) {
	m := New(testManagerConfig(), testEffective())
	for _, revision := range []uint64{1, 7, 99} {
		r := testOpen(connection.PurposeServe)
		r.Revision = revision
		if err := authorize(m, r); err != nil {
			t.Fatalf("revision %d of the opener's decision revoked an allowed flow: %v", revision, err)
		}
	}
	r := testOpen(connection.PurposeEgress)
	r.Deadline = time.Now().Add(2 * time.Hour)
	claims, err := m.AuthorizeOpen(context.Background(), connection.Principal{}, r)
	if err != nil || claims.Deadline.After(time.Now().Add(time.Minute)) {
		t.Fatalf("hard deadline was not clamped to the effective validity: %v %v", claims.Deadline, err)
	}
	next := testEffective()
	next.Revision = 8
	next.Services = next.Services[1:]
	if err := m.UpdateEffective(next); err != nil {
		t.Fatal(err)
	}
	if err := authorize(m, testOpen(connection.PurposeServe)); err == nil {
		t.Fatal("service removed from the effective configuration stayed usable")
	}
	r = testOpen(connection.PurposeServe)
	r.Resource = "api"
	if err := authorize(m, r); err != nil {
		t.Fatalf("unrelated service lost access on an effective update: %v", err)
	}
	stale := testEffective()
	stale.Revision = 6
	if err := m.UpdateEffective(stale); err == nil {
		t.Fatal("stale effective revision replaced a newer one")
	}
}

func TestReloadLimitsAndRolesIndependently(t *testing.T) {
	m := New(testManagerConfig(), testEffective())
	next := testManagerConfig()
	next.Egress.Allow = nil
	m.Reload(next)
	if err := authorize(m, testOpen(connection.PurposeEgress)); err == nil {
		t.Fatal("empty allow continued to authorize egress")
	}
	if err := authorize(m, testOpen(connection.PurposeServe)); err != nil {
		t.Fatalf("egress shrink disabled serve: %v", err)
	}
	next = testManagerConfig()
	next.Serve.Services = next.Serve.Services[1:]
	m.Reload(next)
	if err := authorize(m, testOpen(connection.PurposeServe)); err == nil {
		t.Fatal("removed service still authorized")
	}
	r := testOpen(connection.PurposeServe)
	r.Resource = "api"
	if err := authorize(m, r); err != nil {
		t.Fatalf("removing one service disabled another: %v", err)
	}
	next = testManagerConfig()
	next.Serve.Services[0].Origin = "http://127.0.0.1:9999"
	m.Reload(next)
	if err := authorize(m, testOpen(connection.PurposeServe)); err == nil {
		t.Fatal("origin not yet in the effective configuration was applied")
	}
	if _, _, err := m.origin("demo"); err == nil {
		t.Fatal("changed origin is usable before Control accepts it")
	}
	if _, host, err := m.origin("api"); err != nil || host != "api.w1.instance.example" {
		t.Fatalf("unrelated service lost its Control-assigned hostname: %q %v", host, err)
	}
	if err := authorize(m, testOpen(connection.PurposeEgress)); err != nil {
		t.Fatalf("syncing serve origin disabled egress: %v", err)
	}
}

func TestReloadNarrowsProviderEvenWithRestartOnlyChanges(t *testing.T) {
	for name, change := range map[string]func(*config.Config){
		"workspace":       func(c *config.Config) { c.Workspace = "w2" },
		"instance":        func(c *config.Config) { c.Instance = "https://other.example" },
		"state directory": func(c *config.Config) { c.Agent.StateDir = "/other/state" },
		"transport":       func(c *config.Config) { c.Transport.Endpoint = "https://other.example/agent" },
		"ingress":         func(c *config.Config) { c.Ingress.Enabled = true },
	} {
		t.Run(name, func(t *testing.T) {
			m := New(testManagerConfig(), testEffective())
			next := testManagerConfig()
			change(next)
			next.Egress.Allow = nil
			m.Reload(next)
			if err := authorize(m, testOpen(connection.PurposeEgress)); err == nil {
				t.Fatal("egress narrowing was blocked by an unrelated restart-only change")
			}
			if _, host, err := m.origin("demo"); err != nil || host != "demo.w1.instance.example" {
				t.Fatalf("restart-only identity change was applied: %q %v", host, err)
			}
		})
	}
}

func TestEgressAddressGuards(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "ff02::1"} {
		if !forbiddenIP(netip.MustParseAddr(raw).Unmap()) {
			t.Errorf("dangerous target accepted: %s", raw)
		}
	}
	for _, raw := range []string{"10.2.3.4", "172.16.0.1", "192.168.1.1", "fd00::1", "8.8.8.8"} {
		if forbiddenIP(netip.MustParseAddr(raw)) {
			t.Errorf("ordinary enterprise or public target rejected: %s", raw)
		}
	}
}

func TestManagerOwnsImmutablePolicySnapshots(t *testing.T) {
	cfg := testManagerConfig()
	effective := testEffective()
	m := New(cfg, effective)
	cfg.Serve.Services[0].Origin = "http://127.0.0.1:9999"
	cfg.Egress.Allow[0].Ports[0] = 8443
	effective.Services[0].Origin = "http://127.0.0.1:9999"
	effective.Egress[0].Ports[0] = 8443
	effective.Deny[0].Domain.Exact = "oa.example"
	if err := authorize(m, testOpen(connection.PurposeServe)); err != nil {
		t.Fatalf("caller modified existing effective service: %v", err)
	}
	if err := authorize(m, testOpen(connection.PurposeEgress)); err != nil {
		t.Fatalf("caller modified existing effective egress: %v", err)
	}
	next := testManagerConfig()
	m.Reload(next)
	next.Egress.Enabled = false
	next.Serve.Services[0].Origin = "http://127.0.0.1:9999"
	if err := authorize(m, testOpen(connection.PurposeServe)); err != nil {
		t.Fatalf("reload retained mutable origin slice: %v", err)
	}
	if err := authorize(m, testOpen(connection.PurposeEgress)); err != nil {
		t.Fatalf("reload retained mutable config pointer: %v", err)
	}
}

func TestMalformedDenyDoesNotBecomeWildcardDuringSnapshotCopy(t *testing.T) {
	effective := testEffective()
	effective.Deny = []policy.Rule{{Domain: policy.Domain{Exact: "unrelated.example"}, Ports: []int{}, Protocol: "tls"}}
	m := New(testManagerConfig(), effective)
	if err := authorize(m, testOpen(connection.PurposeEgress)); err == nil {
		t.Fatal("malformed explicit-empty deny was normalized into a valid policy")
	}
}
