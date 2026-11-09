// Package agent is the agentd daemon: one instance, one workspace, one
// session to the assigned relay (design 5, protocol 3 to 7).
package agent

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"agentd/internal/identity"
	"agentd/internal/routes"
	"agentd/internal/wire/pb"
)

// Config is AgentdConfiguration (docs/agentd-config.yaml).
type Config struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Workspace WorkspaceConfig `yaml:"workspace"`
	Roles     RolesConfig     `yaml:"roles"`
	P2P       P2PConfig       `yaml:"p2p"`
	Log       LogConfig       `yaml:"log"`

	dir string // instance directory, for relative paths
}

// WorkspaceConfig is written by `agentd join`.
type WorkspaceConfig struct {
	Domain    string      `yaml:"domain"`
	PublicKey string      `yaml:"public_key"`
	Relay     RelayConfig `yaml:"relay"`
}

// RelayConfig names the assigned relay and how to reach it.
type RelayConfig struct {
	URL       string `yaml:"url"`
	Transport struct {
		Type     string `yaml:"type"`     // ws | xhttp | httpupgrade | auto
		Sessions int    `yaml:"sessions"` // MVP: 1
	} `yaml:"transport"`
}

// Listener is { enabled, address, port }.
type Listener struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

// HostPort renders the listen address.
func (l Listener) HostPort() string { return net.JoinHostPort(l.Address, fmt.Sprint(l.Port)) }

// RolesConfig holds the five roles.
type RolesConfig struct {
	Ingress   IngressConfig   `yaml:"ingress"`
	Submitter SubmitterConfig `yaml:"submitter"`
	Egress    EgressConfig    `yaml:"egress"`
	Service   ServiceConfig   `yaml:"service"`
	Executor  ExecutorConfig  `yaml:"executor"`
}

// IngressConfig captures local traffic.
type IngressConfig struct {
	Enabled  bool     `yaml:"enabled"`
	HTTP     Listener `yaml:"http"`
	SOCKS5   Listener `yaml:"socks5"`
	Fallback string   `yaml:"fallback"` // direct | reject
	Sniffing struct {
		SkipPorts []int `yaml:"skip_ports"`
	} `yaml:"sniffing"`
	TUN struct {
		Enabled bool   `yaml:"enabled"`
		Capture string `yaml:"capture"` // all (default route) | fakeip (only the fake-IP pools)
		DNS     struct {
			OverrideSystem    *bool  `yaml:"override_system"`
			Upstream          []Addr `yaml:"upstream"`
			StripHTTPSRecords *bool  `yaml:"strip_https_records"`
			FirefoxCanary     *bool  `yaml:"firefox_canary"`
		} `yaml:"dns"`
		DoHBlock struct {
			Enabled *bool    `yaml:"enabled"`
			Domains []string `yaml:"domains"`
		} `yaml:"doh_block"`
	} `yaml:"tun"`
}

// Addr is { address, port }.
type Addr struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

// SubmitterConfig exposes executors to local agents.
type SubmitterConfig struct {
	Enabled bool `yaml:"enabled"`
	MCP     Addr `yaml:"mcp"`
}

// MatchConfig is a domain pattern object.
type MatchConfig struct {
	Kind  string `yaml:"kind"`
	Value string `yaml:"value"`
}

// EgressConfig provides exits.
type EgressConfig struct {
	Enabled      bool           `yaml:"enabled"`
	PolicySource string         `yaml:"policy_source"`
	Policies     []EgressPolicy `yaml:"policies"`
}

// EgressPolicy is (public_key, action, proto, domains[, ports]).
type EgressPolicy struct {
	PublicKey string        `yaml:"public_key"`
	Action    string        `yaml:"action"`
	Proto     string        `yaml:"proto"`
	Domains   []MatchConfig `yaml:"domains"`
	Ports     []int         `yaml:"ports"`
}

// ServiceConfig publishes local services.
type ServiceConfig struct {
	Enabled      bool            `yaml:"enabled"`
	PolicySource string          `yaml:"policy_source"`
	Servers      []ServerConfig  `yaml:"servers"`
	Policies     []ServicePolicy `yaml:"policies"`
}

// ServerConfig is one service.
type ServerConfig struct {
	Name   string `yaml:"name"`
	Proto  string `yaml:"proto"` // http | ssh
	Target struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"target"`
}

// ServicePolicy is (public_key, action, service).
type ServicePolicy struct {
	PublicKey string `yaml:"public_key"`
	Action    string `yaml:"action"`
	Service   string `yaml:"service"`
}

// ExecutorConfig runs tool calls.
type ExecutorConfig struct {
	Enabled      bool         `yaml:"enabled"`
	PolicySource string       `yaml:"policy_source"`
	Description  string       `yaml:"description"`
	Policies     []ExecPolicy `yaml:"policies"`
	Shell        struct {
		Path string `yaml:"path"`
	} `yaml:"shell"`
	Workdir string `yaml:"workdir"`
	Env     struct {
		Passthrough []string `yaml:"passthrough"`
	} `yaml:"env"`
	Limits struct {
		MaxSessions    int           `yaml:"max_sessions"`
		DefaultYieldMS int           `yaml:"default_yield_ms"`
		MaxOutputBytes int           `yaml:"max_output_bytes"`
		SessionIdle    time.Duration `yaml:"session_idle"`
	} `yaml:"limits"`
}

// ExecPolicy is (public_key, action, argv[, stdin][, shell]).
type ExecPolicy struct {
	PublicKey string   `yaml:"public_key"`
	Action    string   `yaml:"action"`
	Argv      []string `yaml:"argv"`
	Stdin     bool     `yaml:"stdin"`
	Shell     bool     `yaml:"shell"`
}

// P2PConfig is reserved (protocol 2.6).
type P2PConfig struct {
	Enabled bool `yaml:"enabled"`
	Listen  Addr `yaml:"listen"`
	STUN    []struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"stun"`
}

// LogConfig selects log files.
type LogConfig struct {
	Level    string  `yaml:"level"`
	Path     *string `yaml:"path"`
	Decision struct {
		Enabled *bool   `yaml:"enabled"`
		Path    *string `yaml:"path"`
	} `yaml:"decision"`
	Audit struct {
		Enabled *bool   `yaml:"enabled"`
		Path    *string `yaml:"path"`
	} `yaml:"audit"`
}

// LoadConfig reads <dir>/config.yaml.
func LoadConfig(dir string) (*Config, error) {
	b, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no configuration in %s; run `agentd join <link>` first", dir)
		}
		return nil, err
	}
	return ParseConfig(b, dir)
}

// ParseConfig parses YAML strictly, applies defaults and validates.
func ParseConfig(b []byte, dir string) (*Config, error) {
	c := &Config{dir: dir}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.SetDefaults()
	return c, c.Validate()
}

// Dir is the instance directory.
func (c *Config) Dir() string { return c.dir }

// Path resolves a path relative to the instance directory.
func (c *Config) Path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.dir, p)
}

// SetDefaults fills unset fields.
func (c *Config) SetDefaults() {
	t := &c.Workspace.Relay.Transport
	if t.Type == "" {
		t.Type = "ws"
	}
	if t.Sessions == 0 {
		t.Sessions = 1
	}
	in := &c.Roles.Ingress
	for _, l := range []*Listener{&in.HTTP, &in.SOCKS5} {
		if l.Address == "" {
			l.Address = "127.0.0.1"
		}
	}
	if in.Fallback == "" {
		in.Fallback = "direct"
	}
	if in.Sniffing.SkipPorts == nil {
		in.Sniffing.SkipPorts = []int{25, 110, 143, 3306}
	}
	if c.Roles.Submitter.MCP.Address == "" {
		c.Roles.Submitter.MCP.Address = "127.0.0.1"
	}
	for _, s := range []*string{&c.Roles.Egress.PolicySource, &c.Roles.Service.PolicySource, &c.Roles.Executor.PolicySource} {
		if *s == "" {
			*s = "local"
		}
	}
	for i := range c.Roles.Service.Servers {
		if c.Roles.Service.Servers[i].Proto == "" {
			c.Roles.Service.Servers[i].Proto = "http"
		}
	}
	ex := &c.Roles.Executor
	if len(ex.Env.Passthrough) == 0 {
		ex.Env.Passthrough = []string{"HOME", "PATH", "LANG", "TERM"}
	}
	if ex.Limits.DefaultYieldMS == 0 {
		ex.Limits.DefaultYieldMS = 10000
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
}

func validKey(k string) error {
	if k == "*" {
		return nil
	}
	_, err := identity.DecodeKey(k)
	return err
}

func validAction(a string) error {
	if a != "allow" && a != "deny" {
		return fmt.Errorf("action must be allow or deny, got %q", a)
	}
	return nil
}

func validSource(s string) error {
	if s != "local" && s != "server" {
		return fmt.Errorf("policy_source must be local or server, got %q", s)
	}
	return nil
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if c.APIVersion != "agentd/v1" || c.Kind != "AgentdConfiguration" {
		return fmt.Errorf("expected apiVersion agentd/v1 and kind AgentdConfiguration, got %q %q", c.APIVersion, c.Kind)
	}
	if !identity.ValidLabel(c.Metadata.Name) {
		return fmt.Errorf("metadata.name %q is not a valid instance name", c.Metadata.Name)
	}
	if !identity.ValidDomain(c.Workspace.Domain) {
		return fmt.Errorf("workspace.domain %q is not a valid domain", c.Workspace.Domain)
	}
	if _, err := identity.DecodeKey(c.Workspace.PublicKey); err != nil {
		return fmt.Errorf("workspace.public_key: %w", err)
	}
	if u, err := url.Parse(c.Workspace.Relay.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("workspace.relay.url must be an https URL, got %q", c.Workspace.Relay.URL)
	}
	switch c.Workspace.Relay.Transport.Type {
	case "ws", "xhttp", "httpupgrade", "auto":
	default:
		return fmt.Errorf("workspace.relay.transport.type must be ws, xhttp, httpupgrade or auto")
	}
	in := c.Roles.Ingress
	if in.Enabled {
		for name, l := range map[string]Listener{"http": in.HTTP, "socks5": in.SOCKS5} {
			if l.Enabled && (l.Port < 1 || l.Port > 65535) {
				return fmt.Errorf("roles.ingress.%s.port is required", name)
			}
		}
		if in.Fallback != "direct" && in.Fallback != "reject" {
			return fmt.Errorf("roles.ingress.fallback must be direct or reject")
		}
		if c := in.TUN.Capture; c != "" && c != "all" && c != "fakeip" {
			return fmt.Errorf("roles.ingress.tun.capture must be all or fakeip")
		}
	}
	if s := c.Roles.Submitter; s.Enabled && (s.MCP.Port < 1 || s.MCP.Port > 65535) {
		return errors.New("roles.submitter.mcp.port is required")
	}
	eg := c.Roles.Egress
	if err := validSource(eg.PolicySource); err != nil {
		return fmt.Errorf("roles.egress: %w", err)
	}
	for i, p := range eg.Policies {
		if err := validKey(p.PublicKey); err != nil {
			return fmt.Errorf("roles.egress.policies[%d].public_key: %w", i, err)
		}
		if err := validAction(p.Action); err != nil {
			return fmt.Errorf("roles.egress.policies[%d]: %w", i, err)
		}
		if p.Proto != "" && p.Proto != "tls" && p.Proto != "ssh" {
			return fmt.Errorf("roles.egress.policies[%d].proto must be tls or ssh", i)
		}
		if len(p.Domains) == 0 {
			return fmt.Errorf("roles.egress.policies[%d].domains is required", i)
		}
		for _, m := range p.Domains {
			if m.Kind != "domain" && m.Kind != "suffix" {
				return fmt.Errorf("roles.egress.policies[%d]: domain kind must be domain or suffix", i)
			}
			if err := routes.ValidateMatch(toMatch(m)); err != nil {
				return fmt.Errorf("roles.egress.policies[%d]: %w", i, err)
			}
		}
		for _, port := range p.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("roles.egress.policies[%d]: invalid port %d", i, port)
			}
		}
	}
	sv := c.Roles.Service
	if err := validSource(sv.PolicySource); err != nil {
		return fmt.Errorf("roles.service: %w", err)
	}
	names := map[string]bool{}
	for i, s := range sv.Servers {
		if !identity.ValidLabel(s.Name) {
			return fmt.Errorf("roles.service.servers[%d].name %q is not a valid label", i, s.Name)
		}
		if names[s.Name] {
			return fmt.Errorf("roles.service.servers: duplicate name %q", s.Name)
		}
		names[s.Name] = true
		if s.Proto != "http" && s.Proto != "ssh" {
			return fmt.Errorf("roles.service.servers[%d].proto must be http or ssh", i)
		}
		if s.Target.Host == "" || s.Target.Port < 1 || s.Target.Port > 65535 {
			return fmt.Errorf("roles.service.servers[%d].target needs host and port", i)
		}
	}
	for i, p := range sv.Policies {
		if err := validKey(p.PublicKey); err != nil {
			return fmt.Errorf("roles.service.policies[%d].public_key: %w", i, err)
		}
		if err := validAction(p.Action); err != nil {
			return fmt.Errorf("roles.service.policies[%d]: %w", i, err)
		}
		if !identity.ValidLabel(p.Service) {
			return fmt.Errorf("roles.service.policies[%d].service is required", i)
		}
	}
	ex := c.Roles.Executor
	if err := validSource(ex.PolicySource); err != nil {
		return fmt.Errorf("roles.executor: %w", err)
	}
	if ex.Enabled && ex.Workdir == "" {
		return errors.New("roles.executor.workdir is required")
	}
	if len(ex.Description) > 512 {
		return errors.New("roles.executor.description is longer than 512 bytes")
	}
	if y := ex.Limits.DefaultYieldMS; y < 250 || y > 30000 {
		return errors.New("roles.executor.limits.default_yield_ms must be between 250 and 30000")
	}
	for i, p := range ex.Policies {
		if err := validKey(p.PublicKey); err != nil {
			return fmt.Errorf("roles.executor.policies[%d].public_key: %w", i, err)
		}
		if err := validAction(p.Action); err != nil {
			return fmt.Errorf("roles.executor.policies[%d]: %w", i, err)
		}
		if p.Action == "allow" && len(p.Argv) == 0 && !p.Shell {
			return fmt.Errorf("roles.executor.policies[%d]: an allow rule needs argv (or shell: true)", i)
		}
	}
	return nil
}

func toMatch(m MatchConfig) *pb.Match {
	k := pb.Match_SUFFIX
	if m.Kind == "domain" {
		k = pb.Match_DOMAIN
	}
	return &pb.Match{Kind: k, Value: normalize(m.Value)}
}

func keyBytes(k string) []byte {
	if k == "*" {
		return nil
	}
	b, _ := identity.DecodeKey(k)
	return b
}

func action(a string) pb.Action {
	if a == "deny" {
		return pb.Action_ACTION_DENY
	}
	return pb.Action_ACTION_ALLOW
}

func source(s string) pb.PolicySource {
	if s == "server" {
		return pb.PolicySource_POLICY_SOURCE_SERVER
	}
	return pb.PolicySource_POLICY_SOURCE_LOCAL
}

// TUNSocket is the elevator socket (AGENTD_ELEVATOR_SOCKET overrides it,
// for tests and containers).
func (c *Config) TUNSocket() string {
	if v := os.Getenv("AGENTD_ELEVATOR_SOCKET"); v != "" {
		return v
	}
	return ""
}

// LocalPolicy renders the local policies of the enabled provider roles.
func (c *Config) LocalPolicy() *pb.Policy {
	p := &pb.Policy{}
	if c.Roles.Egress.Enabled {
		for _, r := range c.Roles.Egress.Policies {
			proto := pb.Proto_PROTO_TLS
			if r.Proto == "ssh" {
				proto = pb.Proto_PROTO_SSH
			}
			er := &pb.EgressRule{PublicKey: keyBytes(r.PublicKey), Action: action(r.Action), Proto: proto}
			for _, m := range r.Domains {
				er.Domains = append(er.Domains, toMatch(m))
			}
			for _, port := range r.Ports {
				er.Ports = append(er.Ports, uint32(port))
			}
			p.Egress = append(p.Egress, er)
		}
	}
	if c.Roles.Service.Enabled {
		for _, r := range c.Roles.Service.Policies {
			p.Services = append(p.Services, &pb.ServiceRule{PublicKey: keyBytes(r.PublicKey), Action: action(r.Action), Name: r.Service})
		}
	}
	if c.Roles.Executor.Enabled {
		for _, r := range c.Roles.Executor.Policies {
			p.Exec = append(p.Exec, &pb.ExecRule{PublicKey: keyBytes(r.PublicKey), Action: action(r.Action), Argv: r.Argv, Stdin: r.Stdin, Shell: r.Shell})
		}
	}
	return p
}

// Sources reports each provider role's policy source.
func (c *Config) Sources() *pb.PolicySources {
	return &pb.PolicySources{Egress: source(c.Roles.Egress.PolicySource), Service: source(c.Roles.Service.PolicySource), Executor: source(c.Roles.Executor.PolicySource)}
}

// WorkspaceKey decodes workspace.public_key.
func (c *Config) WorkspaceKey() []byte {
	k, _ := identity.DecodeKey(c.Workspace.PublicKey)
	return k
}

func normalize(d string) string {
	for len(d) > 0 && d[len(d)-1] == '.' {
		d = d[:len(d)-1]
	}
	return toLower(d)
}

func toLower(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if ch >= 'A' && ch <= 'Z' {
			b[i] = ch + 32
		}
	}
	return string(b)
}
