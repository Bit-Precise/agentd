package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentd/internal/identity"
	"agentd/internal/wire/pb"
)

func testKey(t *testing.T) string {
	k, _ := identity.GenerateKey()
	return identity.EncodeKey(identity.Public(k))
}

func TestReferenceConfigParses(t *testing.T) {
	// docs/agentd-config.yaml documents every field; with real keys and TUN
	// off it must load.
	b, err := os.ReadFile("../../docs/agentd-config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, placeholder := range []string{`"Rt7aB…"`, `"QmX9v…"`, `"hC3Qm…"`} {
		s = strings.ReplaceAll(s, placeholder, `"`+testKey(t)+`"`)
	}
	c, err := ParseConfig([]byte(s), t.TempDir())
	if err != nil {
		t.Fatalf("reference config: %v", err)
	}
	if c.Metadata.Name != "laptop" || !c.Roles.Ingress.SOCKS5.Enabled || len(c.Roles.Service.Servers) != 3 {
		t.Fatalf("parsed: %+v", c.Roles)
	}
	p := c.LocalPolicy()
	if len(p.Egress) != 3 || p.Egress[2].Action != pb.Action_ACTION_DENY || len(p.Egress[2].PublicKey) != 0 {
		t.Fatalf("egress rules: %v", p.Egress)
	}
	if len(p.Exec) != 4 || !p.Exec[1].Stdin || !p.Exec[3].Shell {
		t.Fatalf("exec rules: %v", p.Exec)
	}
}

func TestConfigRejects(t *testing.T) {
	base := "apiVersion: agentd/v1\nkind: AgentdConfiguration\nmetadata: {name: laptop}\nworkspace: {domain: home.example.com, public_key: \"" + testKey(t) + "\", relay: {url: \"https://relay.example.com\"}}\n"
	if _, err := ParseConfig([]byte(base), t.TempDir()); err != nil {
		t.Fatalf("minimal config: %v", err)
	}
	bad := map[string]string{
		"plain http relay":   strings.Replace(base, "https://relay", "http://relay", 1),
		"unknown field":      base + "peers: []\n",
		"socks no port":      base + "roles: {ingress: {enabled: true, socks5: {enabled: true}}}\n",
		"bad key":            base + "roles: {egress: {enabled: true, policies: [{public_key: nope, action: allow, domains: [{kind: suffix, value: a.com}]}]}}\n",
		"egress udp":         base + "roles: {egress: {enabled: true, policies: [{public_key: \"*\", action: allow, proto: udp, domains: [{kind: suffix, value: a.com}]}]}}\n",
		"executor no dir":    base + "roles: {executor: {enabled: true}}\n",
		"service tcp":        base + "roles: {service: {enabled: true, servers: [{name: x, proto: tcp, target: {host: 127.0.0.1, port: 1}}]}}\n",
		"allow without argv": base + "roles: {executor: {enabled: true, workdir: /tmp, policies: [{public_key: \"*\", action: allow}]}}\n",
	}
	for name, cfg := range bad {
		if _, err := ParseConfig([]byte(cfg), t.TempDir()); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
}

func TestRewriteNameKeepsOtherFields(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	if err := writeJoinedConfig(dir, "laptop", "home.example.com", key, "https://relay.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(dir); err != nil {
		t.Fatalf("joined config must load: %v", err)
	}
	if err := rewriteName(dir, "laptop2"); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(dir)
	if err != nil || c.Metadata.Name != "laptop2" || c.Workspace.PublicKey != key {
		t.Fatalf("after rename: %v %+v", err, c)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if !strings.Contains(string(b), "docs/agentd-config.yaml") {
		t.Fatal("comments should survive the rename")
	}
}

func TestHome(t *testing.T) {
	t.Setenv("AGENTD_HOME", "")
	t.Setenv("AGENTD_INSTANCE", "")
	h, _ := os.UserHomeDir()
	if d, _ := Home("", ""); d != filepath.Join(h, ".agentd") {
		t.Fatalf("default: %s", d)
	}
	if d, _ := Home("work", ""); d != filepath.Join(h, ".agentd", "instances", "work") {
		t.Fatalf("instance: %s", d)
	}
	if _, err := Home("Bad_Name", ""); err == nil {
		t.Fatal("bad instance names must be rejected")
	}
}
