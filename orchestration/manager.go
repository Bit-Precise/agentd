// Package orchestration reconciles local intent with a provisioned approval.
package orchestration

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/url"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/credentials"
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
	mu       sync.Mutex
	cfg      *config.Config
	approval credentials.Approval
	flows    map[string]activeFlow
	dial     func(context.Context, string, string) (net.Conn, error)
}

func New(cfg *config.Config, approval credentials.Approval) *Manager {
	approval.Services = maps.Clone(approval.Services)
	approval.Egress = cloneRules(approval.Egress)
	approval.Deny = cloneRules(approval.Deny)
	return &Manager{cfg: cloneConfig(cfg), approval: approval, flows: make(map[string]activeFlow), dial: dialTarget}
}

// SetDialer supplies an embedding application's trusted resolver/dialer. Call
// before serving flows. The standalone daemon uses the checked default dialer.
func (m *Manager) SetDialer(dial func(context.Context, string, string) (net.Conn, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dial = dial
}

func (m *Manager) AuthorizeOpen(_ context.Context, _ connection.Principal, r connection.OpenRequest) (connection.OpenClaims, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(r); err != nil {
		return connection.OpenClaims{}, err
	}
	return connection.OpenClaims{FlowID: r.FlowID, Purpose: r.Purpose, Resource: r.Resource, Destination: r.Destination, Protocol: r.Protocol, Revision: r.Revision, Deadline: r.Deadline}, nil
}

// check runs under mu; the approved revision and absolute deadline are enforced
// independently of the authenticated transport's lifetime.
func (m *Manager) check(r connection.OpenRequest) error {
	if r.Revision != m.approval.Revision || !m.approval.ExpiresAt.After(time.Now()) || r.Deadline.IsZero() || !r.Deadline.After(time.Now()) || r.Deadline.After(m.approval.ExpiresAt) {
		return errors.New("unapproved revision or expired flow")
	}
	switch r.Purpose {
	case connection.PurposeServe:
		if !m.cfg.Serve.Enabled || (r.Protocol != "http" && r.Protocol != "") {
			return errors.New("serve disabled or wrong protocol")
		}
		if r.Destination.Host != "" || r.Destination.Port != 0 {
			return errors.New("serve cannot carry an arbitrary destination")
		}
		for _, service := range m.cfg.Serve.Services {
			if service.Name == r.Resource && m.approval.Services[service.Name] == service.Origin {
				return nil
			}
		}
		return errors.New("service unavailable or pending approval")
	case connection.PurposeEgress:
		if !m.cfg.Egress.Enabled || r.Protocol != "tls" {
			return errors.New("egress disabled or wrong protocol")
		}
		domain, err := policy.CanonicalDomain(r.Destination.Host)
		if err != nil || domain != r.Destination.Host || r.Destination.Port == 0 {
			return errors.New("noncanonical egress destination")
		}
		port := int(r.Destination.Port)
		if !policy.Allowed(m.cfg.Egress.Allow, m.cfg.Egress.Deny, domain, port, "tls") || !policy.Allowed(m.approval.Egress, m.approval.Deny, domain, port, "tls") {
			return errors.New("egress destination denied")
		}
		return nil
	default:
		return errors.New("unsupported provider purpose")
	}
}

func (m *Manager) begin(parent context.Context, s *connection.Stream) (context.Context, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := s.Request()
	if err := m.check(r); err != nil {
		return nil, nil, err
	}
	if _, exists := m.flows[r.FlowID]; exists {
		return nil, nil, errors.New("duplicate active flow")
	}
	ctx, cancel := context.WithDeadline(parent, r.Deadline)
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

// Reload changes local limits and origin declarations only. Listener, identity,
// and transport changes require a restart in this first implementation.
func (m *Manager) Reload(next *config.Config) error {
	m.mu.Lock()
	if next.Instance != m.cfg.Instance || next.Workspace != m.cfg.Workspace || next.Agent != m.cfg.Agent || next.Transport != m.cfg.Transport || !reflect.DeepEqual(next.Ingress, m.cfg.Ingress) {
		m.mu.Unlock()
		return errors.New("identity, transport and ingress changes require restart")
	}
	m.cfg = cloneConfig(next)
	var revoke []activeFlow
	for _, flow := range m.flows {
		if m.check(flow.request) != nil {
			revoke = append(revoke, flow)
		}
	}
	m.mu.Unlock()
	for _, flow := range revoke {
		flow.cancel()
		_ = flow.close()
	}
	return nil
}

func cloneRules(src []policy.Rule) []policy.Rule {
	if src == nil {
		return nil
	}
	out := slices.Clone(src)
	for i := range out {
		out[i].Ports = slices.Clone(src[i].Ports)
	}
	return out
}
func cloneConfig(src *config.Config) *config.Config {
	out := *src
	out.Ingress.Routes = cloneRules(src.Ingress.Routes)
	out.Serve.Services = append([]config.ServiceConfig(nil), src.Serve.Services...)
	out.Egress.Allow = cloneRules(src.Egress.Allow)
	out.Egress.Deny = cloneRules(src.Egress.Deny)
	return &out
}

func (m *Manager) Services() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []string
	if m.cfg.Serve.Enabled && m.approval.ExpiresAt.After(time.Now()) {
		for _, s := range m.cfg.Serve.Services {
			if m.approval.Services[s.Name] == s.Origin {
				result = append(result, s.Name)
			}
		}
	}
	return result
}

func (m *Manager) ActiveFlows() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.flows) }

// UpdateApproval replaces a control-approved snapshot without changing local
// intent. Equal revisions may still narrow capabilities after local withdrawal.
func (m *Manager) UpdateApproval(next credentials.Approval) error {
	m.mu.Lock()
	if next.Revision < m.approval.Revision || !next.ExpiresAt.After(time.Now()) {
		m.mu.Unlock()
		return errors.New("stale or expired approval")
	}
	next.Services = maps.Clone(next.Services)
	next.Egress = cloneRules(next.Egress)
	next.Deny = cloneRules(next.Deny)
	m.approval = next
	var revoked []activeFlow
	for _, f := range m.flows {
		if m.check(f.request) != nil {
			revoked = append(revoked, f)
		}
	}
	m.mu.Unlock()
	for _, f := range revoked {
		f.cancel()
		_ = f.close()
	}
	return nil
}

func (m *Manager) EgressEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Egress.Enabled && len(m.cfg.Egress.Allow) > 0 && len(m.approval.Egress) > 0 && m.approval.ExpiresAt.After(time.Now())
}

func (m *Manager) origin(name string) (*url.URL, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.cfg.Serve.Services {
		if s.Name == name && m.approval.Services[name] == s.Origin {
			u, err := url.Parse(s.Origin)
			if err != nil {
				return nil, "", err
			}
			instance, err := url.Parse(m.cfg.Instance)
			if err != nil {
				return nil, "", err
			}
			return u, name + "." + m.cfg.Workspace + "." + instance.Hostname(), nil
		}
	}
	return nil, "", fmt.Errorf("service %q unavailable", name)
}
