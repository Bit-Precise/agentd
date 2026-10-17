// Package config loads the declarative agentd configuration. Parsing never
// creates identities, opens listeners, or changes a running configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/bit-precise/agentd/policy"
	"gopkg.in/yaml.v3"
)

const MaxConfigBytes = 1 << 20

type Config struct {
	APIVersion string          `yaml:"apiVersion" json:"apiVersion"`
	Kind       string          `yaml:"kind" json:"kind"`
	Instance   string          `yaml:"instance" json:"instance"`
	Workspace  string          `yaml:"workspace" json:"workspace"`
	Agent      AgentConfig     `yaml:"agent" json:"agent"`
	Transport  TransportConfig `yaml:"transport" json:"transport"`
	Ingress    IngressConfig   `yaml:"ingress" json:"ingress"`
	Serve      ServeConfig     `yaml:"serve" json:"serve"`
	Egress     EgressConfig    `yaml:"egress" json:"egress"`
}

type AgentConfig struct {
	Name     string `yaml:"name" json:"name"`
	StateDir string `yaml:"stateDir" json:"stateDir"`
}

type TransportConfig struct {
	Type     string `yaml:"type" json:"type"`
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	Mode     string `yaml:"mode" json:"mode"`
	CAFile   string `yaml:"caFile" json:"caFile,omitempty"`
}

type ListenerConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Listen  string `yaml:"listen" json:"listen"`
}

type DNSConfig struct {
	Mode string `yaml:"mode" json:"mode"`
}

type TUNConfig struct {
	Enabled bool      `yaml:"enabled" json:"enabled"`
	Name    string    `yaml:"name" json:"name"`
	DNS     DNSConfig `yaml:"dns" json:"dns"`
}

type IngressConfig struct {
	Enabled     bool           `yaml:"enabled" json:"enabled"`
	HTTP        ListenerConfig `yaml:"http" json:"http"`
	SOCKS       ListenerConfig `yaml:"socks" json:"socks"`
	TUN         TUNConfig      `yaml:"tun" json:"tun"`
	Routes      []policy.Rule  `yaml:"routes" json:"routes"`
	OnUnmatched string         `yaml:"onUnmatched" json:"onUnmatched"`
}

type ServiceConfig struct {
	Name   string `yaml:"name" json:"name"`
	Origin string `yaml:"origin" json:"origin"`
}

type ServeConfig struct {
	Enabled  bool            `yaml:"enabled" json:"enabled"`
	Services []ServiceConfig `yaml:"services" json:"services"`
}

type EgressConfig struct {
	Enabled bool          `yaml:"enabled" json:"enabled"`
	Allow   []policy.Rule `yaml:"allow" json:"allow"`
	Deny    []policy.Rule `yaml:"deny" json:"deny"`
}

func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config path: %w", err)
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(data, filepath.Dir(abs))
}

func Parse(data []byte, baseDir string) (*Config, error) {
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("configuration exceeds %d bytes", MaxConfigBytes)
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse configuration: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("configuration must be a YAML mapping")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parse trailing configuration: %w", err)
		}
		return nil, errors.New("configuration must contain exactly one YAML document")
	}
	if err := validateYAML(&document, 0); err != nil {
		return nil, err
	}
	if err := validateTypes(document.Content[0], reflect.TypeFor[Config](), "config"); err != nil {
		return nil, err
	}
	var cfg Config
	decoder = yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode configuration: %w", err)
	}
	if err := cfg.validate(baseDir); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Explicit keys and ordinary scalar values keep declarations unambiguous.
// Aliases and merge keys are unnecessary for this small schema and are rejected
// before expansion, including recursive aliases and alias amplification.
func validateYAML(node *yaml.Node, depth int) error {
	if depth > 64 {
		return errors.New("YAML nesting exceeds 64 levels")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("line %d: YAML anchors and aliases are unsupported", node.Line)
	}
	if node.Kind != yaml.DocumentNode && !strings.HasPrefix(node.Tag, "!!") {
		return fmt.Errorf("line %d: custom YAML tags are unsupported", node.Line)
	}
	if node.Tag == "!!null" {
		return fmt.Errorf("line %d: null configuration values are not allowed; omit the field instead", node.Line)
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]bool)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" {
				return fmt.Errorf("line %d: configuration keys must be explicit strings", key.Line)
			}
			if seen[key.Value] {
				return fmt.Errorf("line %d: duplicate configuration key %q", key.Line, key.Value)
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// yaml.v3 intentionally accepts YAML 1.1 boolean spellings and coerces some
// scalar types. Configuration fields use their declared types instead.
func validateTypes(node *yaml.Node, typ reflect.Type, field string) error {
	switch typ.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return fmt.Errorf("%s must be a mapping", field)
		}
		fields := make(map[string]reflect.Type, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fields[strings.Split(f.Tag.Get("yaml"), ",")[0]] = f.Type
		}
		for i := 0; i < len(node.Content); i += 2 {
			name := node.Content[i].Value
			childType, ok := fields[name]
			if !ok {
				return fmt.Errorf("%s: unknown field %q", field, name)
			}
			if err := validateTypes(node.Content[i+1], childType, field+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if node.Kind != yaml.SequenceNode {
			return fmt.Errorf("%s must be a sequence", field)
		}
		for i, child := range node.Content {
			if err := validateTypes(child, typ.Elem(), fmt.Sprintf("%s[%d]", field, i)); err != nil {
				return err
			}
		}
	case reflect.String:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
			return fmt.Errorf("%s must be a string", field)
		}
	case reflect.Bool:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
			return fmt.Errorf("%s must be true or false", field)
		}
	case reflect.Int:
		if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
			return fmt.Errorf("%s must be an integer", field)
		}
	}
	return nil
}

func (c *Config) validate(baseDir string) error {
	if c.APIVersion != "agents/v1alpha1" || c.Kind != "AgentConfig" {
		return errors.New("apiVersion must be agents/v1alpha1 and kind must be AgentConfig")
	}
	u, err := validateURL(c.Instance, "instance", true)
	if err != nil {
		return err
	}
	c.Instance = strings.TrimSuffix(u.String(), "/")
	if c.Workspace, err = label(c.Workspace); err != nil {
		return fmt.Errorf("workspace: %w", err)
	}
	if c.Agent.Name, err = label(c.Agent.Name); err != nil {
		return fmt.Errorf("agent.name: %w", err)
	}
	if c.Agent.StateDir == "" {
		c.Agent.StateDir = "./state"
	}
	if c.Agent.StateDir, err = localPath(baseDir, c.Agent.StateDir); err != nil {
		return fmt.Errorf("agent.stateDir: %w", err)
	}
	if c.Transport.Type != "xhttp" {
		return fmt.Errorf("transport.type %q unsupported: this implementation supports only xhttp", c.Transport.Type)
	}
	if c.Transport.Mode == "" {
		c.Transport.Mode = "packet-up"
	}
	if c.Transport.Mode != "packet-up" {
		return fmt.Errorf("transport.mode %q unsupported: only packet-up is implemented", c.Transport.Mode)
	}
	u, err = validateURL(c.Transport.Endpoint, "transport.endpoint", false)
	if err != nil {
		return err
	}
	c.Transport.Endpoint = u.String()
	if c.Transport.CAFile != "" {
		if c.Transport.CAFile, err = localPath(baseDir, c.Transport.CAFile); err != nil {
			return fmt.Errorf("transport.caFile: %w", err)
		}
	}
	if c.Ingress.OnUnmatched == "" {
		c.Ingress.OnUnmatched = "reject"
	}
	if c.Ingress.OnUnmatched != "reject" {
		return errors.New("ingress.onUnmatched must be reject; direct fallback is unsupported")
	}
	for name, listener := range map[string]*ListenerConfig{"http": &c.Ingress.HTTP, "socks": &c.Ingress.SOCKS} {
		if listener.Listen != "" || listener.Enabled {
			if err := validateListener(listener); err != nil {
				return fmt.Errorf("ingress.%s: %w", name, err)
			}
		}
	}
	if c.Ingress.HTTP.Enabled && c.Ingress.SOCKS.Enabled && c.Ingress.HTTP.Listen == c.Ingress.SOCKS.Listen {
		return errors.New("ingress HTTP and SOCKS listeners must not use the same address")
	}
	if c.Ingress.TUN.Name != "" && (len(c.Ingress.TUN.Name) > 15 || strings.ContainsAny(c.Ingress.TUN.Name, "/\x00 \t\r\n")) {
		return errors.New("ingress.tun.name must be a valid interface name of at most 15 bytes")
	}
	if c.Ingress.TUN.Enabled && c.Ingress.TUN.Name == "" {
		return errors.New("ingress.tun.name is required when TUN is enabled")
	}
	if c.Ingress.TUN.DNS.Mode != "" && c.Ingress.TUN.DNS.Mode != "fake-ip" {
		return errors.New("ingress.tun.dns.mode must be fake-ip")
	}
	if c.Ingress.TUN.Enabled && c.Ingress.TUN.DNS.Mode != "fake-ip" {
		return errors.New("ingress.tun.dns.mode must be fake-ip when TUN is enabled")
	}
	if c.Ingress.Enabled && (!c.Ingress.HTTP.Enabled && !c.Ingress.SOCKS.Enabled && !c.Ingress.TUN.Enabled || len(c.Ingress.Routes) == 0) {
		return errors.New("enabled ingress requires an enabled listener and nonempty routes")
	}
	if err := validateRules(c.Ingress.Routes, true, "ingress.routes"); err != nil {
		return err
	}
	if c.Serve.Enabled && len(c.Serve.Services) == 0 {
		return errors.New("enabled serve requires nonempty services")
	}
	names := make(map[string]bool)
	for i := range c.Serve.Services {
		service := &c.Serve.Services[i]
		service.Name, err = label(service.Name)
		if err != nil {
			return fmt.Errorf("serve.services[%d].name: %w", i, err)
		}
		if names[service.Name] || service.Name == c.Agent.Name {
			return fmt.Errorf("service name %q conflicts with another service or agent name", service.Name)
		}
		names[service.Name] = true
		u, err = validateURL(service.Origin, fmt.Sprintf("serve.services[%d].origin", i), true)
		if err != nil {
			return err
		}
		service.Origin = u.String()
	}
	if err := validateRules(c.Egress.Allow, true, "egress.allow"); err != nil {
		return err
	}
	return validateRules(c.Egress.Deny, false, "egress.deny")
}

func validateRules(rules []policy.Rule, requirePorts bool, field string) error {
	for i := range rules {
		if err := rules[i].Validate(requirePorts); err != nil {
			return fmt.Errorf("%s[%d]: %w", field, i, err)
		}
	}
	return nil
}

func label(s string) (string, error) {
	// A DNS label may be entirely numeric even though a complete numeric
	// destination is disallowed by the domain routing policy.
	const suffix = ".agent-label.invalid"
	canonical, err := policy.CanonicalDomain(s + suffix)
	if err != nil {
		return "", err
	}
	canonical = strings.TrimSuffix(canonical, suffix)
	if strings.Contains(canonical, ".") {
		return "", errors.New("must be a single DNS label")
	}
	return canonical, nil
}

func localPath(baseDir, path string) (string, error) {
	if strings.ContainsRune(path, '\x00') {
		return "", errors.New("path contains NUL")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	return filepath.Abs(path)
}

func validateListener(listener *ListenerConfig) error {
	host, portText, err := net.SplitHostPort(listener.Listen)
	if err != nil {
		return fmt.Errorf("listen requires a loopback IP and port: %w", err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() || addr.Zone() != "" {
		return errors.New("listen must use a loopback IP; shared unauthenticated listeners are unsupported")
	}
	port, err := strictPort(portText)
	if err != nil {
		return err
	}
	listener.Listen = net.JoinHostPort(addr.Unmap().String(), strconv.Itoa(port))
	return nil
}

func strictPort(s string) (int, error) {
	if s == "" {
		return 0, errors.New("port must be an integer between 1 and 65535")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("port must be an integer between 1 and 65535")
		}
	}
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("port must be an integer between 1 and 65535")
	}
	return port, nil
}

func validateURL(raw, field string, rootOnly bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid URL: %w", field, err)
	}
	isOrigin := strings.HasPrefix(field, "serve.services[")
	if u.Scheme != "https" && !(isOrigin && u.Scheme == "http") {
		return nil, fmt.Errorf("%s: HTTPS required (serve origins also support HTTP)", field)
	}
	if u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%s: URL requires a host and must not include credentials, query or fragment", field)
	}
	if rootOnly && u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("%s: URL path must be empty or /", field)
	}
	host := u.Hostname()
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("%s: scoped IP addresses are unsupported", field)
		}
	} else if _, err := policy.CanonicalDomain(host); err != nil {
		return nil, fmt.Errorf("%s: invalid host: %w", field, err)
	}
	if port := u.Port(); port != "" {
		if _, err := strictPort(port); err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("%s: empty port", field)
	}
	return u, nil
}
