package edge

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/policy"
	"github.com/bit-precise/agentd/transport/xhttp"
)

func bearer(r *http.Request) string {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return ""
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 4096 {
		return ""
	}
	return parts[1]
}

func (e *Edge) authorizeHTTP(r *http.Request) (string, error) {
	token := bearer(r)
	if token == "" {
		return "", ErrDenied
	}
	id, err := e.backend.Identity(token)
	if err != nil || !validIdentity(id) {
		return "", ErrDenied
	}
	return id.TokenID, nil
}

func validIdentity(id types.Identity) bool {
	return (id.Kind == "provider" || id.Kind == "access") && id.TokenID != "" && id.AgentID != "" && id.WorkspaceID != "" && id.Workspace != "" && id.ExpiresAt.After(time.Now()) && (id.Kind != "access" || id.UserID != "")
}

func minExpiry(values ...time.Time) time.Time {
	var result time.Time
	for _, value := range values {
		if !value.IsZero() && (result.IsZero() || value.Before(result)) {
			result = value
		}
	}
	return result
}

func approvedServices(agent types.Agent, declared []string) map[string]bool {
	allowed := make(map[string]bool)
	if !agent.Desired.Serve.Enabled {
		return allowed
	}
	local := make(map[string]string)
	for _, service := range agent.Desired.Serve.Services {
		local[service.Name] = service.Origin
	}
	for _, name := range declared {
		if origin, ok := agent.Approval.Services[name]; ok && origin != "" && local[name] == origin {
			allowed[name] = true
		}
	}
	return allowed
}

func (e *Edge) authenticate(p *provider, hello connection.Hello) (connection.Principal, error) {
	transportID, ok := xhttp.AuthenticatedPrincipal(p.raw)
	if !ok {
		return connection.Principal{}, ErrDenied
	}
	id, err := e.backend.Identity(hello.Token)
	if err != nil || !validIdentity(id) || id.TokenID != transportID || string(hello.Role) != id.Kind || hello.Workspace != id.Workspace || hello.AgentID != id.AgentID {
		return connection.Principal{}, ErrDenied
	}
	agent, err := e.backend.Agent(id.AgentID)
	if err != nil || agent.ID != id.AgentID || agent.WorkspaceID != id.WorkspaceID || agent.Workspace != id.Workspace || agent.Status == "revoked" {
		return connection.Principal{}, ErrDenied
	}
	expires := minExpiry(id.ExpiresAt, time.Now().Add(e.cfg.SessionTTL))
	services := map[string]bool{}
	egress := false
	if hello.Role == connection.RoleProvider {
		if agent.Status != "active" || agent.Approval.Revision == 0 || hello.Revision != agent.Approval.Revision || !agent.Approval.ExpiresAt.After(time.Now()) {
			return connection.Principal{}, ErrDenied
		}
		expires = minExpiry(expires, agent.Approval.ExpiresAt)
		services = approvedServices(agent, hello.Services)
		egress = hello.EgressEnabled && agent.Desired.Egress.Enabled && len(agent.Desired.Egress.Allow) > 0 && len(agent.Approval.Egress) > 0
	} else if agent.Status != "pending" && agent.Status != "active" {
		return connection.Principal{}, ErrDenied
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return connection.Principal{}, ErrClosed
	}
	var old *provider
	if hello.Role == connection.RoleProvider {
		old = e.providers[id.AgentID]
		if old != nil && old.connector != hello.ConnectorID {
			e.mu.Unlock()
			return connection.Principal{}, ErrDenied
		}
	}
	key := id.AgentID + "/" + id.Kind
	e.generation[key]++
	p.identity = id
	p.token = hello.Token
	p.connector = hello.ConnectorID
	p.generation = e.generation[key]
	p.revision = agent.Approval.Revision
	p.services = services
	p.egress = egress
	if hello.Role == connection.RoleProvider {
		e.providers[id.AgentID] = p
	}
	principal := connection.Principal{Role: hello.Role, Workspace: id.Workspace, AgentID: id.AgentID, UserID: id.UserID, ConnectorID: hello.ConnectorID,
		Generation: p.generation, Revision: p.revision, ExpiresAt: expires, EgressEnabled: egress}
	for name := range services {
		principal.Services = append(principal.Services, name)
	}
	e.mu.Unlock()
	if old != nil {
		e.closeProvider(old)
	}
	return principal, nil
}

func (e *Edge) accept(p *provider) {
	defer func() { e.closeProvider(p); e.removeProvider(p) }()
	s, err := connection.Server(e.ctx, p.raw, func(_ context.Context, h connection.Hello) (connection.Principal, error) { return e.authenticate(p, h) },
		connection.Config{SessionTTL: e.cfg.SessionTTL, AuthorizeOpen: func(ctx context.Context, principal connection.Principal, r connection.OpenRequest) (connection.OpenClaims, error) {
			return e.authorizeCandidate(ctx, p, principal, r)
		}})
	if err != nil {
		return
	}
	e.mu.Lock()
	p.session = s
	current := !e.closed && (p.identity.Kind != "provider" || e.providers[p.identity.AgentID] == p)
	e.mu.Unlock()
	if !current || !e.currentIdentity(p) {
		return
	}
	if p.identity.Kind == "provider" {
		<-s.Done()
		return
	}
	for {
		incoming, err := s.Accept(e.ctx)
		if err != nil {
			return
		}
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			incoming.Close()
			return
		}
		e.wg.Add(1)
		e.mu.Unlock()
		go func() { defer e.wg.Done(); defer incoming.Close(); e.handleAccess(p, incoming) }()
	}
}

func (e *Edge) currentIdentity(p *provider) bool {
	id, err := e.backend.Identity(p.token)
	if err != nil || !validIdentity(id) || id.TokenID != p.identity.TokenID || id.Kind != p.identity.Kind || id.AgentID != p.identity.AgentID || id.UserID != p.identity.UserID || id.WorkspaceID != p.identity.WorkspaceID || id.Workspace != p.identity.Workspace {
		return false
	}
	agent, err := e.backend.Agent(id.AgentID)
	if err != nil || agent.WorkspaceID != id.WorkspaceID || agent.Status == "revoked" {
		return false
	}
	if id.Kind == "provider" {
		if agent.Status != "active" || agent.Approval.Revision != p.revision || !agent.Approval.ExpiresAt.After(time.Now()) {
			return false
		}
	}
	return true
}

func (e *Edge) authorizeCandidate(ctx context.Context, p *provider, principal connection.Principal, r connection.OpenRequest) (connection.OpenClaims, error) {
	if ctx.Err() != nil || principal.Role != connection.RoleAccess || r.Purpose != connection.PurposeAccess || r.Protocol != "tls" || r.Resource != "" || !e.currentIdentity(p) {
		return connection.OpenClaims{}, ErrDenied
	}
	host, err := policy.CanonicalDomain(r.Destination.Host)
	if err != nil || host != r.Destination.Host || r.Destination.Port == 0 {
		return connection.OpenClaims{}, ErrDenied
	}
	d, err := e.backend.ResolveEgress(principal.Workspace, principal.UserID, host, int(r.Destination.Port))
	if err != nil || !validDecision(d, connection.PurposeEgress) || d.WorkspaceID != p.identity.WorkspaceID || d.UserID != principal.UserID || d.Destination != r.Destination {
		return connection.OpenClaims{}, ErrDenied
	}
	deadline := minExpiry(r.Deadline, principal.ExpiresAt, time.Now().Add(e.cfg.MaxFlowLifetime))
	lease := minExpiry(deadline, d.ExpiresAt, time.Now().Add(e.cfg.FlowTTL))
	return connection.OpenClaims{FlowID: r.FlowID, Purpose: r.Purpose, Resource: d.ResourceID, Destination: d.Destination, Protocol: "tls", Revision: d.Revision, Deadline: deadline, LeaseExpiresAt: lease}, nil
}
