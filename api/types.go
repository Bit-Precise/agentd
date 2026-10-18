// Package api defines the agentd ↔ Control wire contract: the server-relevant
// desired spec, the Control-computed effective configuration and the device
// credentials. Local-only settings such as listeners, paths and ingress routes
// never enter this contract.
package api

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bit-precise/agentd/policy"
)

const (
	RoleIngress = "ingress"
	RoleServe   = "serve"
	RoleEgress  = "egress"

	StatusActive  = "active"
	StatusRevoked = "revoked"

	// CredentialsVersion 2 replaced the manual-approval snapshot with Effective.
	CredentialsVersion = 2

	maxServices = 128
	maxRules    = 256
)

// AgentSpec is the desired configuration Control validates: which roles the
// Agent runs and what it offers. It is derived from the local config.yaml.
type AgentSpec struct {
	Ingress IngressSpec `json:"ingress"`
	Serve   ServeSpec   `json:"serve"`
	Egress  EgressSpec  `json:"egress"`
}
type IngressSpec struct {
	Enabled bool `json:"enabled"`
}
type ServeSpec struct {
	Enabled  bool          `json:"enabled"`
	Services []ServiceSpec `json:"services,omitempty"`
}
type ServiceSpec struct {
	Name   string `json:"name"`
	Origin string `json:"origin"`
}
type EgressSpec struct {
	Enabled bool          `json:"enabled"`
	Allow   []policy.Rule `json:"allow,omitempty"`
	Deny    []policy.Rule `json:"deny,omitempty"`
}

// Roles lists the enabled roles in canonical order.
func (s AgentSpec) Roles() []string {
	var roles []string
	if s.Ingress.Enabled {
		roles = append(roles, RoleIngress)
	}
	if s.Serve.Enabled {
		roles = append(roles, RoleServe)
	}
	if s.Egress.Enabled {
		roles = append(roles, RoleEgress)
	}
	return roles
}

// Normalize validates and canonicalizes the spec in place. A nonempty
// agentName must not be reused as a service name: both share one DNS namespace.
func (s *AgentSpec) Normalize(agentName string) error {
	if s.Serve.Enabled && len(s.Serve.Services) == 0 {
		return errors.New("enabled serve requires nonempty services")
	}
	if len(s.Serve.Services) > maxServices || len(s.Egress.Allow) > maxRules || len(s.Egress.Deny) > maxRules {
		return errors.New("too many services or egress rules")
	}
	names := make(map[string]bool, len(s.Serve.Services))
	for i := range s.Serve.Services {
		service := &s.Serve.Services[i]
		name, err := policy.Label(service.Name)
		if err != nil {
			return fmt.Errorf("serve.services[%d].name: %w", i, err)
		}
		if names[name] || name == agentName {
			return fmt.Errorf("service name %q conflicts with another service or agent name", name)
		}
		names[name] = true
		origin, err := ParseURL(service.Origin, fmt.Sprintf("serve.services[%d].origin", i), true, true, false)
		if err != nil {
			return err
		}
		service.Name, service.Origin = name, origin.String()
	}
	for i := range s.Egress.Allow {
		if err := s.Egress.Allow[i].Validate(true); err != nil {
			return fmt.Errorf("egress.allow[%d]: %w", i, err)
		}
	}
	for i := range s.Egress.Deny {
		if err := s.Egress.Deny[i].Validate(false); err != nil {
			return fmt.Errorf("egress.deny[%d]: %w", i, err)
		}
	}
	return nil
}

// Clone returns a copy that shares no slices with s.
func (s AgentSpec) Clone() AgentSpec {
	s.Serve.Services = slices.Clone(s.Serve.Services)
	s.Egress.Allow = CloneRules(s.Egress.Allow)
	s.Egress.Deny = CloneRules(s.Egress.Deny)
	return s
}

// EffectiveConfig is Desired ∩ role ceiling ∩ Workspace policy, computed by
// Control rather than approved by a person. Revision is per Agent and changes
// only when the content changes. ExpiresAt bounds how long agentd may keep using
// this copy without reaching Control; it is neither a grant nor an Edge lease.
type EffectiveConfig struct {
	Revision  uint64             `json:"revision"`
	Policy    string             `json:"policy,omitempty"`
	ExpiresAt time.Time          `json:"expiresAt,omitzero"`
	Ingress   bool               `json:"ingress"`
	Services  []EffectiveService `json:"services,omitempty"`
	Egress    []policy.Rule      `json:"egress,omitempty"`
	Deny      []policy.Rule      `json:"deny,omitempty"`
}

// EffectiveService carries the Control-assigned public hostname so agentd never
// derives it independently.
type EffectiveService struct {
	Name     string `json:"name"`
	Origin   string `json:"origin"`
	Hostname string `json:"hostname"`
}

func (e EffectiveConfig) Service(name string) (EffectiveService, bool) {
	for _, service := range e.Services {
		if service.Name == name {
			return service, true
		}
	}
	return EffectiveService{}, false
}

func (e EffectiveConfig) Clone() EffectiveConfig {
	e.Services = slices.Clone(e.Services)
	e.Egress = CloneRules(e.Egress)
	e.Deny = CloneRules(e.Deny)
	return e
}

// SameContent compares capabilities, ignoring Revision and ExpiresAt.
func (e EffectiveConfig) SameContent(other EffectiveConfig) bool {
	return e.Policy == other.Policy && e.Ingress == other.Ingress && slices.Equal(e.Services, other.Services) &&
		slices.EqualFunc(e.Egress, other.Egress, sameRule) && slices.EqualFunc(e.Deny, other.Deny, sameRule)
}

// Validate checks a received copy before it can authorize local flows.
func (e *EffectiveConfig) Validate() error {
	if e.Revision == 0 {
		return errors.New("effective configuration revision is missing")
	}
	for _, service := range e.Services {
		if service.Name == "" || service.Origin == "" {
			return errors.New("invalid effective service")
		}
	}
	for i := range e.Egress {
		if err := e.Egress[i].Validate(true); err != nil {
			return errors.New("invalid effective egress rule")
		}
	}
	for i := range e.Deny {
		if err := e.Deny[i].Validate(false); err != nil {
			return errors.New("invalid effective deny rule")
		}
	}
	return nil
}

func sameRule(a, b policy.Rule) bool {
	return a.Domain == b.Domain && a.Protocol == b.Protocol && slices.Equal(a.Ports, b.Ports) && (a.Ports == nil) == (b.Ports == nil)
}

// CloneRules deep-copies rules, preserving the nil/empty Ports distinction.
func CloneRules(src []policy.Rule) []policy.Rule {
	if src == nil {
		return nil
	}
	out := slices.Clone(src)
	for i := range out {
		out[i].Ports = slices.Clone(src[i].Ports)
	}
	return out
}

// ConfigRejection records the most recent desired update that Control refused.
// The previous effective configuration keeps running; nothing awaits a person.
type ConfigRejection struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
}

// Agent is the API view of a registered device. Roles is the enrollment role
// ceiling, not the currently enabled roles; see Desired and Effective for those.
type Agent struct {
	ID            string           `json:"id"`
	WorkspaceID   string           `json:"workspaceId"`
	Workspace     string           `json:"workspace"`
	UserID        string           `json:"userId"`
	Name          string           `json:"name"`
	Status        string           `json:"status"`
	Roles         []string         `json:"roles"`
	Desired       AgentSpec        `json:"desired"`
	Effective     EffectiveConfig  `json:"effective"`
	LastRejection *ConfigRejection `json:"lastRejection,omitempty"`
	CreatedAt     time.Time        `json:"createdAt"`
	RevokedAt     time.Time        `json:"revokedAt,omitzero"`
}

// Credentials is both the Control response and the private credentials.json
// document. Tokens are returned in plain text only once, at enrollment.
type Credentials struct {
	Version       int             `json:"version"`
	Workspace     string          `json:"workspace"`
	AgentID       string          `json:"agentId"`
	ProviderToken string          `json:"providerToken,omitempty"`
	AccessToken   string          `json:"accessToken,omitempty"`
	ControlToken  string          `json:"controlToken,omitempty"`
	ControlURL    string          `json:"controlUrl,omitempty"`
	Effective     EffectiveConfig `json:"effective"`
}

// EnrollRequest names the profile identity separately from its desired spec so
// local paths, listeners and routes are never uploaded.
type EnrollRequest struct {
	EnrollmentKey string    `json:"enrollmentKey"`
	Instance      string    `json:"instance"`
	Endpoint      string    `json:"endpoint"`
	Workspace     string    `json:"workspace"`
	Name          string    `json:"name"`
	Desired       AgentSpec `json:"desired"`
}
type EnrollResponse struct {
	Agent       Agent       `json:"agent"`
	Credentials Credentials `json:"credentials"`
}

// ConfigUpdate replaces the authenticated Agent's desired spec. Workspace and
// Name are checked against the registration and cannot change it.
type ConfigUpdate struct {
	Workspace string    `json:"workspace"`
	Name      string    `json:"name"`
	Desired   AgentSpec `json:"desired"`
}
