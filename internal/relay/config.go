// Package relay is agentrelay, the data plane (design 5.8): the only server
// nodes connect to. It terminates node sessions and their control streams,
// asks agentserver (over its own relay session) who a node is and where a
// stream goes, forwards streams between nodes, and runs the edge that
// terminates TLS for HTTP services.
package relay

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"agentd/internal/control"
	"agentd/internal/identity"
	"agentd/internal/tlsutil"
)

// Config is AgentrelayConfiguration (design 9.1).
type Config struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`

	Name       string            `yaml:"name"`        // relay name (RFC 1123 label)
	Domain     string            `yaml:"domain"`      // the relay's own name; SNI for node sessions
	URL        string            `yaml:"url"`         // https base URL nodes use; default https://<domain>
	Listen     string            `yaml:"listen"`      // TLS listener; default ":443"
	HTTPListen string            `yaml:"http_listen"` // optional plain listener that only redirects to https
	KeyFile    string            `yaml:"key_file"`    // relay Ed25519 key; created on first start
	KeyEnv     string            `yaml:"key_env"`     // environment variable holding the key (wins over key_file; Kubernetes Secrets)
	Control    ControlConfig     `yaml:"control"`
	TLS        tlsutil.Config    `yaml:"tls"`
	Transports map[string]string `yaml:"transports"`
	Cache      CacheConfig       `yaml:"cache"`
	STUN       string            `yaml:"stun"` // UDP address of the STUN responder; empty disables

	Log control.LogConfig `yaml:"log"`
}

// ControlConfig locates agentserver.
type ControlConfig struct {
	URL          string `yaml:"url"`            // https URL of agentserver's relay endpoint
	PublicKey    string `yaml:"public_key"`     // agentserver key; empty fetches /.well-known/agentserver over verified TLS
	CAFile       string `yaml:"ca_file"`        // extra trusted root for agentserver's certificate (private deployments)
	Transport    string `yaml:"transport"`      // ws (default), httpupgrade or xhttp
	JoinTokenEnv string `yaml:"join_token_env"` // registration token used while the key is unregistered; default AGENTRELAY_JOIN_TOKEN
}

// CacheConfig bounds the answer cache (protocol 5.8).
type CacheConfig struct {
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"max_entries"`
}

// LoadConfig reads a configuration file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(b)
}

// ParseConfig parses YAML strictly and validates it.
func ParseConfig(b []byte) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.SetDefaults()
	return c, c.Validate()
}

// SetDefaults fills unset fields.
func (c *Config) SetDefaults() {
	if c.Listen == "" {
		c.Listen = ":443"
	}
	if c.URL == "" && c.Domain != "" {
		c.URL = "https://" + c.Domain
		if _, port, err := net.SplitHostPort(c.Listen); err == nil && port != "443" && port != "0" {
			c.URL += ":" + port
		}
	}
	if len(c.Transports) == 0 {
		c.Transports = map[string]string{"ws": "/ws", "httpupgrade": "/up", "xhttp": "/x"}
	}
	if c.Control.Transport == "" {
		c.Control.Transport = "ws"
	}
	if c.Control.JoinTokenEnv == "" {
		c.Control.JoinTokenEnv = "AGENTRELAY_JOIN_TOKEN"
	}
	if c.Cache.TTL == 0 {
		c.Cache.TTL = 60 * time.Second
	}
	if c.Cache.MaxEntries == 0 {
		c.Cache.MaxEntries = 100000
	}
	if c.KeyFile == "" {
		c.KeyFile = "/var/lib/agentrelay/relay.key"
	}
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if c.APIVersion != "agentd/v1" || c.Kind != "AgentrelayConfiguration" {
		return fmt.Errorf("expected apiVersion agentd/v1 and kind AgentrelayConfiguration, got %q %q", c.APIVersion, c.Kind)
	}
	if !identity.ValidLabel(c.Name) {
		return fmt.Errorf("invalid relay name %q", c.Name)
	}
	if !identity.ValidDomain(c.Domain) {
		return fmt.Errorf("invalid domain %q", c.Domain)
	}
	if u, err := url.Parse(c.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("url must be an https URL, got %q", c.URL)
	}
	if u, err := url.Parse(c.Control.URL); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("control.url must be an https URL, got %q", c.Control.URL)
	}
	if c.Control.PublicKey != "" {
		if _, err := identity.DecodeKey(c.Control.PublicKey); err != nil {
			return fmt.Errorf("control.public_key: %w", err)
		}
	}
	switch c.Control.Transport {
	case "ws", "httpupgrade", "xhttp":
	default:
		return fmt.Errorf("control.transport must be ws, httpupgrade or xhttp")
	}
	if err := c.TLS.Validate(); err != nil {
		return err
	}
	for _, a := range []string{c.Listen, c.HTTPListen, c.STUN} {
		if a == "" {
			continue
		}
		if _, p, err := net.SplitHostPort(a); err != nil {
			return fmt.Errorf("invalid address %q: %w", a, err)
		} else if _, err := strconv.Atoi(p); err != nil {
			return fmt.Errorf("invalid port in %q", a)
		}
	}
	for k, p := range c.Transports {
		if k != "ws" && k != "httpupgrade" && k != "xhttp" {
			return fmt.Errorf("unknown transport %q", k)
		}
		if len(p) < 2 || p[0] != '/' {
			return fmt.Errorf("transport %s path must start with /", k)
		}
	}
	if c.Cache.MaxEntries < 0 || c.Cache.TTL < 0 {
		return errors.New("cache values must be positive")
	}
	return nil
}
