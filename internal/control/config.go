package control

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"agentd/internal/identity"
	"agentd/internal/tlsutil"
)

// ServerConfig is AgentserverConfiguration (design 9.1).
type ServerConfig struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`

	Domain     string            `yaml:"domain"`     // agentserver's own name; default parent of workspace base domains
	Listen     string            `yaml:"listen"`     // relay sessions (TLS); default ":443"
	KeyFile    string            `yaml:"key_file"`   // optional; empty keeps the key sealed in the database
	TLS        tlsutil.Config    `yaml:"tls"`        // certificate of `domain`
	Transports map[string]string `yaml:"transports"` // relay session endpoints

	AdminListen   string `yaml:"admin_listen"`    // admin API and web console (plain HTTP); default 127.0.0.1:7800
	AdminTokenEnv string `yaml:"admin_token_env"` // default AGENTSERVER_ADMIN_TOKEN

	Database          DatabaseConfig `yaml:"database"`
	StateKeyEnv       string         `yaml:"state_key_env"`        // default AGENTSERVER_STATE_KEY
	RelayJoinTokenEnv string         `yaml:"relay_join_token_env"` // long-lived relay bootstrap token; empty disables
	RelayCertTTL      time.Duration  `yaml:"relay_cert_ttl"`       // default 720h

	// SelfSignedCA seeds the development CA (used by tls.mode selfsigned and
	// the selfsigned dns provider) when the database has none yet.
	SelfSignedCA struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
	} `yaml:"selfsigned_ca"`

	DNSProviders       map[string]DNSProvider `yaml:"dns_providers"`
	DefaultDNSProvider string                 `yaml:"default_dns_provider"` // for workspaces that name none; default "selfsigned"

	Log LogConfig `yaml:"log"`
}

// DatabaseConfig locates Postgres.
type DatabaseConfig struct {
	URL    string `yaml:"url"`
	URLEnv string `yaml:"url_env"` // default AGENTSERVER_DATABASE_URL; wins over url when set
}

// DNSProvider issues workspace wildcard certificates.
type DNSProvider struct {
	Provider        string        `yaml:"provider"`  // cloudflare | selfsigned
	TokenEnv        string        `yaml:"token_env"` // cloudflare API token
	Email           string        `yaml:"email"`     // ACME account contact
	Directory       string        `yaml:"acme_directory"`
	PropagationWait time.Duration `yaml:"propagation_wait"`
}

// LogConfig selects the log format.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // text | json
}

// LoadServerConfig reads and validates a configuration file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseServerConfig(b)
}

// ParseServerConfig parses YAML strictly (unknown fields are errors).
func ParseServerConfig(b []byte) (*ServerConfig, error) {
	c := &ServerConfig{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.SetDefaults()
	return c, c.Validate()
}

// SetDefaults fills unset fields.
func (c *ServerConfig) SetDefaults() {
	if c.Listen == "" {
		c.Listen = ":443"
	}
	if c.AdminListen == "" {
		c.AdminListen = "127.0.0.1:7800"
	}
	if c.AdminTokenEnv == "" {
		c.AdminTokenEnv = "AGENTSERVER_ADMIN_TOKEN"
	}
	if c.Database.URLEnv == "" {
		c.Database.URLEnv = "AGENTSERVER_DATABASE_URL"
	}
	if c.StateKeyEnv == "" {
		c.StateKeyEnv = "AGENTSERVER_STATE_KEY"
	}
	if c.RelayCertTTL == 0 {
		c.RelayCertTTL = 720 * time.Hour
	}
	if len(c.Transports) == 0 {
		c.Transports = DefaultTransports
	}
	if c.DefaultDNSProvider == "" {
		c.DefaultDNSProvider = "selfsigned"
	}
}

// Validate checks the configuration.
func (c *ServerConfig) Validate() error {
	if c.APIVersion != "agentd/v1" || c.Kind != "AgentserverConfiguration" {
		return fmt.Errorf("expected apiVersion agentd/v1 and kind AgentserverConfiguration, got %q %q", c.APIVersion, c.Kind)
	}
	if !identity.ValidDomain(c.Domain) {
		return fmt.Errorf("invalid domain %q", c.Domain)
	}
	if err := c.TLS.Validate(); err != nil {
		return err
	}
	for _, a := range []string{c.Listen, c.AdminListen} {
		if _, _, err := net.SplitHostPort(a); err != nil {
			return fmt.Errorf("invalid listen address %q: %w", a, err)
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
	for name, p := range c.DNSProviders {
		if !identity.ValidLabel(name) {
			return fmt.Errorf("invalid dns provider name %q", name)
		}
		switch p.Provider {
		case "cloudflare":
			if p.TokenEnv == "" {
				return fmt.Errorf("dns provider %s: cloudflare needs token_env", name)
			}
		case "selfsigned":
		default:
			return fmt.Errorf("dns provider %s: provider must be cloudflare or selfsigned", name)
		}
	}
	if c.DefaultDNSProvider != "selfsigned" {
		if _, ok := c.DNSProviders[c.DefaultDNSProvider]; !ok {
			return fmt.Errorf("default_dns_provider %q is not defined", c.DefaultDNSProvider)
		}
	}
	return nil
}

// DatabaseURL resolves the database URL.
func (c *ServerConfig) DatabaseURL() (string, error) {
	if v := os.Getenv(c.Database.URLEnv); v != "" {
		return v, nil
	}
	if c.Database.URL != "" {
		return c.Database.URL, nil
	}
	return "", fmt.Errorf("no database: set %s or database.url", c.Database.URLEnv)
}

// StateKey derives the 32-byte keybox key from the secret in StateKeyEnv
// (SHA-256 of the value; empty leaves private keys unencrypted).
func (c *ServerConfig) StateKey() []byte {
	v := os.Getenv(c.StateKeyEnv)
	if v == "" {
		return nil
	}
	k := sha256.Sum256([]byte(v))
	return k[:]
}

// AdminToken reads the admin token.
func (c *ServerConfig) AdminToken() (string, error) {
	v := os.Getenv(c.AdminTokenEnv)
	if len(v) < 16 {
		return "", fmt.Errorf("set %s to an admin token of at least 16 characters", c.AdminTokenEnv)
	}
	return v, nil
}

// NewLogger builds the process logger.
func (l LogConfig) NewLogger() (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(orDefault(l.Level, "info"))); err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: level}
	switch l.Format {
	case "", "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	}
	return nil, errors.New("log.format must be text or json")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
