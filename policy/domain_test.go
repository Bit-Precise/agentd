package policy

import (
	"strings"
	"testing"
)

func TestCanonicalDomain(t *testing.T) {
	for input, want := range map[string]string{
		"Example.COM.":   "example.com",
		"BÜCHER.example": "xn--bcher-kva.example",
		"example。com":    "example.com",
		"localhost":      "localhost",
	} {
		got, err := CanonicalDomain(input)
		if err != nil || got != want {
			t.Errorf("CanonicalDomain(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{
		"", " example.com", "example.com ", "example..com", ".example.com", "example.com..",
		"*.example.com", "a_b.example", "-bad.example", "bad-.example", "https://example.com",
		"example.com:443", "127.0.0.1", "127.1", "2130706433", "0x7f000001", "::1", "[::1]",
		strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 128) + "com",
	} {
		if got, err := CanonicalDomain(input); err == nil {
			t.Errorf("accepted invalid domain %q as %q", input, got)
		}
	}
}

func TestPolicyBoundaryAndDenyPrecedence(t *testing.T) {
	allow := []Rule{{Domain: Domain{Suffix: "Example.com."}, Ports: []int{443, 8443}, Protocol: "tls"}}
	deny := []Rule{{Domain: Domain{Suffix: "blocked.example.com"}, Protocol: "tls"}}
	for _, tc := range []struct {
		domain   string
		port     int
		protocol string
		want     bool
	}{
		{"example.com", 443, "tls", true},
		{"api.EXAMPLE.com.", 8443, "tls", true},
		{"evil-example.com", 443, "tls", false},
		{"example.com.evil.org", 443, "tls", false},
		{"blocked.example.com", 443, "tls", false},
		{"x.blocked.example.com", 8443, "tls", false},
		{"api.example.com", 80, "tls", false},
		{"api.example.com", 443, "tcp", false},
	} {
		if got := Allowed(allow, deny, tc.domain, tc.port, tc.protocol); got != tc.want {
			t.Errorf("Allowed(%s, %d, %s) = %v", tc.domain, tc.port, tc.protocol, got)
		}
	}
	if Allowed(nil, nil, "example.com", 443, "tls") {
		t.Fatal("empty allow granted access")
	}
	if Allowed(allow, []Rule{{Domain: Domain{Exact: "example.com"}, Ports: []int{}, Protocol: "tls"}}, "example.com", 443, "tls") {
		t.Fatal("malformed deny did not fail closed")
	}
	if Allowed([]Rule{{Domain: Domain{Exact: "example.com"}, Protocol: "tls"}}, nil, "example.com", 443, "tls") {
		t.Fatal("allow without explicit ports granted access")
	}
	if allow[0].Domain.Suffix != "Example.com." {
		t.Fatal("matching mutated caller's policy")
	}
}

func TestRuleValidation(t *testing.T) {
	for _, rule := range []Rule{
		{Domain: Domain{}, Ports: []int{443}, Protocol: "tls"},
		{Domain: Domain{Exact: "a.test", Suffix: "b.test"}, Ports: []int{443}, Protocol: "tls"},
		{Domain: Domain{Exact: "a.test"}, Ports: []int{443, 443}, Protocol: "tls"},
		{Domain: Domain{Exact: "a.test"}, Ports: []int{0}, Protocol: "tls"},
		{Domain: Domain{Exact: "a.test"}, Ports: []int{65536}, Protocol: "tls"},
		{Domain: Domain{Exact: "a.test"}, Ports: []int{443}, Protocol: "udp"},
	} {
		if err := rule.Validate(true); err == nil {
			t.Errorf("accepted invalid rule: %+v", rule)
		}
	}
}
