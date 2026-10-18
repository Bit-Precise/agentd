package api

import (
	"slices"
	"testing"
	"time"

	"github.com/bit-precise/agentd/policy"
)

func TestNormalizeCanonicalizesAndRejects(t *testing.T) {
	spec := AgentSpec{Serve: ServeSpec{Enabled: true, Services: []ServiceSpec{{Name: "Demo", Origin: "http://127.0.0.1:8080"}}},
		Egress: EgressSpec{Enabled: true, Allow: []policy.Rule{{Domain: policy.Domain{Suffix: "Example.COM."}, Ports: []int{443}, Protocol: "tls"}}}}
	if err := spec.Normalize("agent1"); err != nil {
		t.Fatal(err)
	}
	if spec.Serve.Services[0].Name != "demo" || spec.Egress.Allow[0].Domain.Suffix != "example.com" {
		t.Fatalf("spec was not canonicalized: %+v", spec)
	}
	if !slices.Equal(spec.Roles(), []string{RoleServe, RoleEgress}) {
		t.Fatalf("roles = %v", spec.Roles())
	}
	for name, change := range map[string]func(*AgentSpec){
		"empty serve":       func(s *AgentSpec) { s.Serve.Services = nil },
		"duplicate service": func(s *AgentSpec) { s.Serve.Services = append(s.Serve.Services, s.Serve.Services[0]) },
		"agent name reused": func(s *AgentSpec) { s.Serve.Services[0].Name = "agent1" },
		"origin with path":  func(s *AgentSpec) { s.Serve.Services[0].Origin = "http://127.0.0.1:8080/app" },
		"origin credential": func(s *AgentSpec) { s.Serve.Services[0].Origin = "http://user@127.0.0.1:8080" },
		"allow without port": func(s *AgentSpec) {
			s.Egress.Allow = []policy.Rule{{Domain: policy.Domain{Exact: "example.com"}, Protocol: "tls"}}
		},
		"wildcard deny": func(s *AgentSpec) {
			s.Egress.Deny = []policy.Rule{{Domain: policy.Domain{Exact: "*.example.com"}, Protocol: "tls"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := spec.Clone()
			change(&next)
			if err := next.Normalize("agent1"); err == nil {
				t.Fatal("invalid desired spec accepted")
			}
		})
	}
}

func TestEffectiveSameContentIgnoresRevisionAndValidity(t *testing.T) {
	a := EffectiveConfig{Revision: 1, ExpiresAt: time.Now(), Ingress: true, Services: []EffectiveService{{Name: "demo", Origin: "http://127.0.0.1:1", Hostname: "demo.w.example"}},
		Deny: []policy.Rule{{Domain: policy.Domain{Exact: "x.example"}, Protocol: "tls"}}}
	b := a.Clone()
	b.Revision, b.ExpiresAt = 9, time.Now().Add(time.Hour)
	if !a.SameContent(b) {
		t.Fatal("revision or validity changed content equality")
	}
	b.Deny[0].Ports = []int{}
	if a.SameContent(b) {
		t.Fatal("a nil deny port list (all ports) compared equal to an explicit empty list")
	}
	b = a.Clone()
	b.Services[0].Hostname = "other.w.example"
	if a.SameContent(b) || a.Services[0].Hostname != "demo.w.example" {
		t.Fatal("clone shared services or content difference was ignored")
	}
}
