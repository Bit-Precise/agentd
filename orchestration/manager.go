// Package orchestration intersects local intent with the Control-computed
// effective configuration for every provider flow.
package orchestration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/bit-precise/agentd/api"
	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/policy"
)

type activeFlow struct {
	request connection.OpenRequest
	cancel  context.CancelFunc
	close   func() error
}

// Manager owns both opening and active flows so a local restriction can cancel
// a DNS lookup or dial just as it can cancel an established connection.
type Manager struct {
	mu        sync.Mutex
	cfg       *config.Config
	effective api.EffectiveConfig
	flows     map[string]activeFlow
	dial      func(context.Context, string, string) (net.Conn, error)
}

func New(cfg *config.Config, effective api.EffectiveConfig) *Manager {
	return &Manager{cfg: cloneConfig(cfg), effective: effective.Clone(), flows: make(map[string]activeFlow), dial: dialTarget}
}

// SetDialer supplies an embedding application's trusted resolver/dialer. Call
// before serving flows. The standalone daemon uses the checked default dialer.
func (m *Manager) SetDialer(dial func(context.Context, string, string) (net.Conn, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dial = dial
}

// AuthorizeOpen also runs for every lease renewal. The hard deadline is clamped
// to the effective snapshot's validity instead of rejecting a longer request.
func (m *Manager) AuthorizeOpen(_ context.Context, _ connection.Principal, r connection.OpenRequest) (connection.OpenClaims, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	deadline, err := m.check(r)
	if err != nil {
		return connection.OpenClaims{}, err
	}
	return connection.OpenClaims{FlowID: r.FlowID, Purpose: r.Purpose, Resource: r.Resource, Destination: r.Destination, Protocol: r.Protocol, Revision: r.Revision, Deadline: deadline}, nil
}

// check runs under mu and authorizes by content: the local config and the
// effective configuration must both permit the flow. The opener's revision is
// informational, so an unrelated effective update never revokes this flow.
func (m *Manager) check(r connection.OpenRequest) (time.Time, error) {
	now := time.Now()
	if !m.effective.ExpiresAt.After(now) || r.Deadline.IsZero() || !r.Deadline.After(now) {
		return time.Time{}, errors.New("effective configuration or flow expired")
	}
	deadline := r.Deadline
	if m.effective.ExpiresAt.Before(deadline) {
		deadline = m.effective.ExpiresAt
	}
	switch r.Purpose {
	case connection.PurposeServe:
		if !m.cfg.Serve.Enabled || (r.Protocol != "http" && r.Protocol != "") {
			return time.Time{}, errors.New("serve disabled or wrong protocol")
		}
		if r.Destination.Host != "" || r.Destination.Port != 0 {
			return time.Time{}, errors.New("serve cannot carry an arbitrary destination")
		}
		if _, _, ok := m.serviceLocked(r.Resource); ok {
			return deadline, nil
		}
		return time.Time{}, errors.New("service is not in the local and effective configuration")
	case connection.PurposeEgress:
		if !m.cfg.Egress.Enabled || r.Protocol != "tls" {
			return time.Time{}, errors.New("egress disabled or wrong protocol")
		}
		domain, err := policy.CanonicalDomain(r.Destination.Host)
		if err != nil || domain != r.Destination.Host || r.Destination.Port == 0 {
			return time.Time{}, errors.New("noncanonical egress destination")
		}
		port := int(r.Destination.Port)
		if !policy.Allowed(m.cfg.Egress.Allow, m.cfg.Egress.Deny, domain, port, "tls") || !policy.Allowed(m.effective.Egress, m.effective.Deny, domain, port, "tls") {
			return time.Time{}, errors.New("egress destination denied")
		}
		return deadline, nil
	default:
		return time.Time{}, errors.New("unsupported provider purpose")
	}
}

// serviceLocked requires the same name and origin locally and in the effective
// configuration: a changed local origin waits for Control to accept it.
func (m *Manager) serviceLocked(name string) (config.ServiceConfig, api.EffectiveService, bool) {
	for _, local := range m.cfg.Serve.Services {
		if local.Name != name {
			continue
		}
		if effective, ok := m.effective.Service(name); ok && effective.Origin == local.Origin {
			return local, effective, true
		}
	}
	return config.ServiceConfig{}, api.EffectiveService{}, false
}

func (m *Manager) begin(parent context.Context, s *connection.Stream) (context.Context, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := s.Request()
	if _, err := m.check(r); err != nil {
		return nil, nil, err
	}
	if _, exists := m.flows[r.FlowID]; exists {
		return nil, nil, errors.New("duplicate active flow")
	}
	ctx, cancel := context.WithDeadline(parent, s.Claims().Deadline)
	stop := context.AfterFunc(s.Context(), cancel)
	m.flows[r.FlowID] = activeFlow{request: r, cancel: cancel, close: s.Close}
	finish := func() {
		stop()
		cancel()
		_ = s.Close()
		m.mu.Lock()
		delete(m.flows, r.FlowID)
		m.mu.Unlock()
	}
	return ctx, finish, nil
}

// Reload applies the provider sections (serve and egress) of a validated
// config. Narrowing takes effect at once; widening still needs the effective
// configuration. Identity, transport and listener settings are not changed here.
func (m *Manager) Reload(next *config.Config) {
	m.mu.Lock()
	cfg := cloneConfig(m.cfg)
	cfg.Serve, cfg.Egress = cloneConfig(next).Serve, cloneConfig(next).Egress
	m.cfg = cfg
	revoke := m.revocableLocked()
	m.mu.Unlock()
	cancelFlows(revoke)
}

func (m *Manager) revocableLocked() []activeFlow {
	var revoke []activeFlow
	for _, flow := range m.flows {
		if _, err := m.check(flow.request); err != nil {
			revoke = append(revoke, flow)
		}
	}
	return revoke
}

func cancelFlows(flows []activeFlow) {
	for _, flow := range flows {
		flow.cancel()
		_ = flow.close()
	}
}

func cloneConfig(src *config.Config) *config.Config {
	out := *src
	out.Ingress.Routes = api.CloneRules(src.Ingress.Routes)
	out.Serve.Services = append([]config.ServiceConfig(nil), src.Serve.Services...)
	out.Egress.Allow = api.CloneRules(src.Egress.Allow)
	out.Egress.Deny = api.CloneRules(src.Egress.Deny)
	return &out
}

// Provides reports whether any provider role is enabled locally.
func (m *Manager) Provides() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Serve.Enabled || m.cfg.Egress.Enabled
}

func (m *Manager) ActiveFlows() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.flows) }

// UpdateEffective installs a newer Control-computed configuration and closes
// only the flows it no longer permits. An equal revision refreshes validity.
func (m *Manager) UpdateEffective(next api.EffectiveConfig) error {
	if err := next.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	if next.Revision < m.effective.Revision || !next.ExpiresAt.After(time.Now()) {
		m.mu.Unlock()
		return errors.New("stale or expired effective configuration")
	}
	m.effective = next.Clone()
	revoke := m.revocableLocked()
	m.mu.Unlock()
	cancelFlows(revoke)
	return nil
}

func (m *Manager) origin(name string) (*url.URL, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	local, effective, ok := m.serviceLocked(name)
	if !ok {
		return nil, "", fmt.Errorf("service %q unavailable", name)
	}
	u, err := url.Parse(local.Origin)
	if err != nil {
		return nil, "", err
	}
	host := effective.Hostname
	if host == "" {
		// Converted legacy credentials lack hostnames until the next refresh.
		instance, err := url.Parse(m.cfg.Instance)
		if err != nil {
			return nil, "", err
		}
		host = name + "." + m.cfg.Workspace + "." + instance.Hostname()
	}
	return u, host, nil
}
