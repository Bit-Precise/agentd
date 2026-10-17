package orchestration

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/credentials"
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

func testApproval() credentials.Approval {
	return credentials.Approval{
		Revision: 7, ExpiresAt: time.Now().Add(time.Minute),
		Services: map[string]string{"demo": "http://127.0.0.1:8080", "api": "http://127.0.0.1:3000"},
		Egress:   []policy.Rule{tlsRule("oa.example"), tlsRule("approved-only.example"), tlsRule("blocked.example")},
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

func TestApprovedAndLocalPolicyIntersection(t *testing.T) {
	m := New(testManagerConfig(), testApproval())
	for _, tc := range []struct {
		name    string
		request connection.OpenRequest
		allowed bool
	}{
		{"approved serve", testOpen(connection.PurposeServe), true},
		{"approved egress", testOpen(connection.PurposeEgress), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := authorize(m, tc.request); (err == nil) != tc.allowed {
				t.Fatalf("authorization = %v, allowed = %v", err, tc.allowed)
			}
		})
	}
	for _, domain := range []string{"local-only.example", "approved-only.example", "blocked.example", "unlisted.example"} {
		r := testOpen(connection.PurposeEgress)
		r.Destination.Host = domain
		if err := authorize(m, r); err == nil {
			t.Errorf("domain outside effective intersection accepted: %s", domain)
		}
	}
	cfg := testManagerConfig()
	cfg.Egress.Deny = []policy.Rule{tlsRule("oa.example")}
	m = New(cfg, testApproval())
	if err := authorize(m, testOpen(connection.PurposeEgress)); err == nil {
		t.Fatal("local deny did not override approved allow")
	}
}

func TestRejectInvalidOrExpiredOpen(t *testing.T) {
	for name, change := range map[string]func(*connection.OpenRequest){
		"old revision":             func(r *connection.OpenRequest) { r.Revision-- },
		"future revision":          func(r *connection.OpenRequest) { r.Revision++ },
		"missing deadline":         func(r *connection.OpenRequest) { r.Deadline = time.Time{} },
		"expired":                  func(r *connection.OpenRequest) { r.Deadline = time.Now().Add(-time.Second) },
		"deadline beyond approval": func(r *connection.OpenRequest) { r.Deadline = time.Now().Add(2 * time.Minute) },
		"wrong purpose":            func(r *connection.OpenRequest) { r.Purpose = connection.PurposeAccess },
		"wrong protocol":           func(r *connection.OpenRequest) { r.Protocol = "tcp" },
		"noncanonical host":        func(r *connection.OpenRequest) { r.Destination.Host = "OA.EXAMPLE." },
		"IP destination":           func(r *connection.OpenRequest) { r.Destination.Host = "127.0.0.1" },
		"wrong port":               func(r *connection.OpenRequest) { r.Destination.Port = 8443 },
	} {
		t.Run(name, func(t *testing.T) {
			m := New(testManagerConfig(), testApproval())
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
		if err := authorize(New(testManagerConfig(), testApproval()), r); err == nil {
			t.Fatal("serve OPEN accepted arbitrary target")
		}
	}
	approval := testApproval()
	approval.ExpiresAt = time.Now().Add(-time.Second)
	m := New(testManagerConfig(), approval)
	if err := authorize(m, testOpen(connection.PurposeServe)); err == nil || len(m.Services()) != 0 {
		t.Fatal("expired approval remained usable or advertised")
	}
}

func TestReloadLimitsAndRolesIndependently(t *testing.T) {
	m := New(testManagerConfig(), testApproval())
	next := testManagerConfig()
	next.Egress.Allow = nil
	if err := m.Reload(next); err != nil {
		t.Fatal(err)
	}
	if err := authorize(m, testOpen(connection.PurposeEgress)); err == nil {
		t.Fatal("empty allow continued to authorize egress")
	}
	if err := authorize(m, testOpen(connection.PurposeServe)); err != nil {
		t.Fatalf("egress shrink disabled serve: %v", err)
	}
	next = testManagerConfig()
	next.Serve.Services = next.Serve.Services[1:]
	if err := m.Reload(next); err != nil {
		t.Fatal(err)
	}
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
	if err := m.Reload(next); err != nil {
		t.Fatal(err)
	}
	if err := authorize(m, testOpen(connection.PurposeServe)); err == nil {
		t.Fatal("unapproved origin applied")
	}
	if len(m.Services()) != 1 || m.Services()[0] != "api" {
		t.Fatal("pending origin remained advertised or removed unrelated service")
	}
	if err := authorize(m, testOpen(connection.PurposeEgress)); err != nil {
		t.Fatalf("pending serve origin disabled egress: %v", err)
	}
}

func TestRejectedReloadDoesNotChangeEffectivePolicy(t *testing.T) {
	for name, change := range map[string]func(*config.Config){
		"workspace":       func(c *config.Config) { c.Workspace = "w2" },
		"instance":        func(c *config.Config) { c.Instance = "https://other.example" },
		"state directory": func(c *config.Config) { c.Agent.StateDir = "/other/state" },
		"transport":       func(c *config.Config) { c.Transport.Endpoint = "https://other.example/agent" },
		"ingress":         func(c *config.Config) { c.Ingress.Enabled = true },
	} {
		t.Run(name, func(t *testing.T) {
			m := New(testManagerConfig(), testApproval())
			next := testManagerConfig()
			change(next)
			next.Egress.Allow = nil
			if err := m.Reload(next); err == nil {
				t.Fatal("restart-only change accepted")
			}
			if err := authorize(m, testOpen(connection.PurposeEgress)); err != nil {
				t.Fatalf("rejected reload partially applied: %v", err)
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
	approval := testApproval()
	m := New(cfg, approval)
	cfg.Serve.Services[0].Origin = "http://127.0.0.1:9999"
	cfg.Egress.Allow[0].Ports[0] = 8443
	approval.Services["demo"] = "http://127.0.0.1:9999"
	approval.Egress[0].Ports[0] = 8443
	approval.Deny[0].Domain.Exact = "oa.example"
	if err := authorize(m, testOpen(connection.PurposeServe)); err != nil {
		t.Fatalf("caller modified existing service approval: %v", err)
	}
	if err := authorize(m, testOpen(connection.PurposeEgress)); err != nil {
		t.Fatalf("caller modified existing egress approval: %v", err)
	}
	next := testManagerConfig()
	if err := m.Reload(next); err != nil {
		t.Fatal(err)
	}
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
	approval := testApproval()
	approval.Deny = []policy.Rule{{Domain: policy.Domain{Exact: "unrelated.example"}, Ports: []int{}, Protocol: "tls"}}
	m := New(testManagerConfig(), approval)
	if err := authorize(m, testOpen(connection.PurposeEgress)); err == nil {
		t.Fatal("malformed explicit-empty deny was normalized into a valid policy")
	}
}
