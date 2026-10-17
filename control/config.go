package control

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/bit-precise/agentd/control/db"
	"github.com/bit-precise/agentd/policy"
	"gopkg.in/yaml.v3"
)

// Config mirrors Headscale's separation of server configuration from agent state.
type Config struct {
	ListenAddress  string `yaml:"listenAddress"`
	ServerURL      string `yaml:"serverURL"`
	EdgeURL        string `yaml:"edgeURL"`
	StateDir       string `yaml:"stateDir"`
	AdminTokenFile string `yaml:"adminTokenFile"`
	Database       struct {
		Type string `yaml:"type"`
		DSN  string `yaml:"dsn"`
	} `yaml:"database"`
	TLS struct {
		CertFile string `yaml:"certFile"`
		KeyFile  string `yaml:"keyFile"`
	} `yaml:"tls"`
	DevelopmentHTTP bool `yaml:"developmentHTTP"`
}

func LoadConfig(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return cfg, err
	}
	if len(data) > 1<<20 {
		return cfg, errors.New("server config exceeds 1 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err = d.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("server config: %w", err)
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("server config must contain one document")
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return cfg, err
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "./state/agents"
	}
	cfg.StateDir = resolvePath(base, cfg.StateDir)
	if cfg.AdminTokenFile == "" {
		cfg.AdminTokenFile = filepath.Join(cfg.StateDir, "admin.token")
	} else {
		cfg.AdminTokenFile = resolvePath(base, cfg.AdminTokenFile)
	}
	if cfg.Database.Type == "" {
		cfg.Database.Type = "sqlite"
	}
	if cfg.Database.Type == "sqlite" {
		if cfg.Database.DSN == "" {
			cfg.Database.DSN = filepath.Join(cfg.StateDir, "agents.db")
		} else if cfg.Database.DSN != ":memory:" {
			cfg.Database.DSN = resolvePath(base, cfg.Database.DSN)
		}
	}
	if cfg.TLS.CertFile != "" {
		cfg.TLS.CertFile = resolvePath(base, cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "" {
		cfg.TLS.KeyFile = resolvePath(base, cfg.TLS.KeyFile)
	}
	return cfg, cfg.Validate()
}

func resolvePath(base, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}
func localHost(host string) bool { return host == "localhost" || net.ParseIP(host).IsLoopback() }
func (c Config) Validate() error {
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("serverURL must be an origin URL")
	}
	if _, err := policy.CanonicalDomain(u.Hostname()); err != nil {
		return errors.New("serverURL requires a DNS hostname; use localhost for development")
	}
	e, err := url.Parse(c.EdgeURL)
	if err != nil || e.Host == "" || e.User != nil || e.RawQuery != "" || e.Fragment != "" || e.Path != "/agent" {
		return errors.New("edgeURL must point to an origin's /agent endpoint")
	}
	host, _, err := net.SplitHostPort(c.ListenAddress)
	if err != nil {
		return errors.New("listenAddress must contain host and port")
	}
	if c.DevelopmentHTTP {
		if !localHost(host) || !localHost(u.Hostname()) || !localHost(e.Hostname()) || u.Scheme != "http" || e.Scheme != "http" {
			return errors.New("developmentHTTP requires loopback-only HTTP URLs and listener")
		}
	} else if u.Scheme != "https" || e.Scheme != "https" || c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
		return errors.New("HTTPS URLs and server TLS cert/key are required")
	}
	if c.Database.Type != "sqlite" && c.Database.Type != "postgres" {
		return errors.New("database.type must be sqlite or postgres")
	}
	if c.Database.DSN == "" {
		return errors.New("database.dsn required")
	}
	return nil
}
func (c Config) DBOptions() db.Options {
	return db.Options{Driver: c.Database.Type, DSN: c.Database.DSN}
}
func (c Config) BaseDomain() string {
	u, _ := url.Parse(c.ServerURL)
	return strings.ToLower(u.Hostname())
}
