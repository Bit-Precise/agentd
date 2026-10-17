package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimal = `apiVersion: agents/v1alpha1
kind: AgentConfig
instance: https://instance.example.com
workspace: workspace1
agent:
  name: agent1
  stateDir: ./state
transport:
  type: xhttp
  endpoint: https://connect.instance.example.com/agent
  mode: packet-up
`

func TestLoadPathsAndDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte(minimal+"  caFile: ./certs/root.pem\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.StateDir != filepath.Join(dir, "state") || cfg.Transport.CAFile != filepath.Join(dir, "certs/root.pem") {
		t.Fatalf("paths not relative to configuration: %+v", cfg)
	}
	if cfg.Ingress.Enabled || cfg.Serve.Enabled || cfg.Egress.Enabled || cfg.Ingress.OnUnmatched != "reject" {
		t.Fatal("omitted roles or default policy enabled access")
	}
	if _, err := os.Stat(cfg.Agent.StateDir); !os.IsNotExist(err) {
		t.Fatal("loading config changed runtime state")
	}
}

func TestAllRoleCombinationsAndEmptyEgress(t *testing.T) {
	for bits := 0; bits < 8; bits++ {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			body := minimal + fmt.Sprintf(`ingress:
  enabled: %t
  http: {enabled: true, listen: "127.0.0.1:8088"}
  routes:
    - domain: {exact: "BÜCHER.example."}
      ports: [443]
      protocol: tls
serve:
  enabled: %t
  services:
    - name: demo
      origin: http://127.0.0.1:8080/
egress:
  enabled: %t
  allow: []
  deny:
    - domain: {suffix: blocked.example}
      protocol: tls
`, bits&1 != 0, bits&2 != 0, bits&4 != 0)
			cfg, err := Parse([]byte(body), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Ingress.Enabled != (bits&1 != 0) || cfg.Serve.Enabled != (bits&2 != 0) || cfg.Egress.Enabled != (bits&4 != 0) {
				t.Fatal("role combination changed")
			}
			if cfg.Ingress.Routes[0].Domain.Exact != "xn--bcher-kva.example" {
				t.Fatal("route was not canonicalized")
			}
		})
	}
}

func TestStrictYAMLAndSemantics(t *testing.T) {
	cases := map[string]string{
		"unknown":                  minimal + "credentials: secret\n",
		"nested unknown":           minimal + "egress: {enabled: false, broad: true}\n",
		"duplicate":                minimal + "workspace: other\n",
		"nested duplicate":         minimal + "egress: {enabled: true, enabled: false}\n",
		"multi document":           minimal + "---\n{}\n",
		"empty second document":    minimal + "---\n",
		"alias":                    minimal + "egress: &eg {enabled: false}\n",
		"custom tag":               minimal + "egress: !Custom {enabled: false}\n",
		"null":                     minimal + "egress: null\n",
		"boolean coercion":         minimal + "egress: {enabled: yes}\n",
		"quoted boolean":           minimal + "egress: {enabled: 'true'}\n",
		"scalar coercion":          strings.Replace(minimal, "name: agent1", "name: true", 1),
		"wrong version":            strings.Replace(minimal, "v1alpha1", "v2", 1),
		"unsupported wss":          strings.Replace(minimal, "type: xhttp", "type: wss", 1),
		"unsupported mode":         strings.Replace(minimal, "mode: packet-up", "mode: stream-up", 1),
		"insecure endpoint":        strings.Replace(minimal, "https://connect", "http://connect", 1),
		"endpoint credentials":     strings.Replace(minimal, "https://connect", "https://alice:secret@connect", 1),
		"endpoint query":           strings.Replace(minimal, "/agent\n", "/agent?token=secret\n", 1),
		"endpoint empty port":      strings.Replace(minimal, ".com/agent", ".com:/agent", 1),
		"endpoint port overflow":   strings.Replace(minimal, ".com/agent", ".com:65536/agent", 1),
		"direct fallback":          minimal + "ingress: {onUnmatched: direct}\n",
		"missing ingress listener": minimal + "ingress: {enabled: true}\n",
		"missing serve services":   minimal + "serve: {enabled: true}\n",
		"public listener":          minimal + "ingress: {http: {enabled: true, listen: '0.0.0.0:8088'}}\n",
		"zero listener port":       minimal + "ingress: {http: {enabled: true, listen: '127.0.0.1:0'}}\n",
		"duplicate listener":       minimal + "ingress: {http: {enabled: true, listen: '127.0.0.1:8088'}, socks: {enabled: true, listen: '127.0.0.1:08088'}}\n",
		"empty deny ports":         minimal + "egress: {deny: [{domain: {exact: example.com}, ports: [], protocol: tls}]}\n",
		"null deny ports":          minimal + "egress: {deny: [{domain: {exact: example.com}, ports: null, protocol: tls}]}\n",
		"missing allow ports":      minimal + "egress: {allow: [{domain: {exact: example.com}, protocol: tls}]}\n",
		"duplicate ports":          minimal + "egress: {allow: [{domain: {exact: example.com}, ports: [443, 443], protocol: tls}]}\n",
		"bad target":               minimal + "egress: {allow: [{domain: {exact: 127.0.0.1}, ports: [443], protocol: tls}]}\n",
		"duplicate service":        minimal + "serve: {services: [{name: demo, origin: 'http://localhost:80'}, {name: DEMO, origin: 'http://localhost:81'}]}\n",
		"agent name collision":     minimal + "serve: {services: [{name: agent1, origin: 'http://localhost:80'}]}\n",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data), t.TempDir()); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	for _, data := range []string{"", "[]", strings.Repeat(" ", MaxConfigBytes+1)} {
		if _, err := Parse([]byte(data), t.TempDir()); err == nil {
			t.Fatal("accepted empty, nonmapping or oversized configuration")
		}
	}
}

func TestOriginValidation(t *testing.T) {
	for _, origin := range []string{
		"http://localhost:8080/path", "http://localhost:8080/%2f", "http://user:pass@localhost:8080",
		"http://localhost?", "http://localhost?query", "http://localhost#", "ftp://localhost",
		"http://localhost:0", "http://localhost:65536", "http://localhost:", "http:///",
	} {
		body := minimal + "serve:\n  enabled: true\n  services:\n    - name: demo\n      origin: " + origin + "\n"
		if _, err := Parse([]byte(body), t.TempDir()); err == nil {
			t.Errorf("accepted origin %q", origin)
		}
	}
	for _, origin := range []string{"http://127.0.0.1:8080", "https://[::1]:8443/", "https://local.example/"} {
		body := minimal + "serve:\n  enabled: true\n  services:\n    - name: demo\n      origin: " + origin + "\n"
		if _, err := Parse([]byte(body), t.TempDir()); err != nil {
			t.Errorf("valid origin %q: %v", origin, err)
		}
	}
}

func TestTUNDeclarationParsesWithoutActivatingIt(t *testing.T) {
	body := minimal + `ingress:
  enabled: true
  tun: {enabled: true, name: agentd0, dns: {mode: fake-ip}}
  routes: [{domain: {exact: example.com}, ports: [443], protocol: tls}]
`
	if _, err := Parse([]byte(body), t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
