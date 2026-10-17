package state

import (
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/policy"
)

func service(snap *types.Snapshot, id string) *types.Service {
	for i := range snap.Services {
		if snap.Services[i].ID == id {
			return &snap.Services[i]
		}
	}
	return nil
}
func route(snap *types.Snapshot, id string) *types.EgressRoute {
	for i := range snap.EgressRoutes {
		if snap.EgressRoutes[i].ID == id {
			return &snap.EgressRoutes[i]
		}
	}
	return nil
}
func canManageService(snap *types.Snapshot, actorID string, v *types.Service) error {
	if err := requireManager(snap, actorID, v.WorkspaceID); err == nil {
		return nil
	}
	u, err := requireUser(snap, actorID)
	if err != nil {
		return err
	}
	m := member(snap, v.WorkspaceID, actorID)
	a := agent(snap, v.AgentID)
	if !u.Disabled && m != nil && m.Role == "developer" && a != nil && a.UserID == actorID {
		return nil
	}
	return problem(types.KindForbidden, "service management is not permitted")
}

func (s *State) CreateEgressRoute(actorID string, value types.EgressRoute) (types.EgressRoute, error) {
	var err error
	value.Name, err = label(value.Name)
	if err != nil {
		return value, err
	}
	if err = value.Rule.Validate(true); err != nil {
		return value, problem(types.KindInvalid, err.Error())
	}
	err = s.mutate(func(snap *types.Snapshot) error {
		w := workspace(snap, value.WorkspaceID)
		if w == nil {
			return problem(types.KindNotFound, "workspace not found")
		}
		if err := requireManager(snap, actorID, w.ID); err != nil {
			return err
		}
		a := agent(snap, value.AgentID)
		if a == nil || a.WorkspaceID != w.ID {
			return problem(types.KindForbidden, "exit agent must belong to this workspace")
		}
		if a.Status == "revoked" || !slices.Contains(a.Roles, "egress") {
			return problem(types.KindForbidden, "agent cannot provide egress")
		}
		for _, r := range snap.EgressRoutes {
			if r.WorkspaceID != w.ID {
				continue
			}
			if r.Name == value.Name {
				return problem(types.KindConflict, "route name already exists")
			}
			if r.Enabled && r.Priority == value.Priority && r.Rule.Domain == value.Rule.Domain {
				for _, port := range value.Rule.Ports {
					if slices.Contains(r.Rule.Ports, port) {
						return problem(types.KindConflict, "ambiguous egress rule at the same priority")
					}
				}
			}
		}
		value.ID = randomID()
		value.WorkspaceID = w.ID
		value.Enabled = true
		snap.EgressRoutes = append(snap.EgressRoutes, value)
		audit(snap, actorID, "egress_route.create", value.ID)
		return nil
	})
	return value, err
}

func (s *State) CreateGrant(actorID string, value types.Grant) (types.Grant, error) {
	err := s.mutate(func(snap *types.Snapshot) error {
		w := workspace(snap, value.WorkspaceID)
		if w == nil {
			return problem(types.KindNotFound, "workspace not found")
		}
		switch value.ResourceType {
		case "service":
			v := service(snap, value.ResourceID)
			if v == nil || v.WorkspaceID != w.ID {
				return problem(types.KindForbidden, "service does not belong to this workspace")
			}
			if err := canManageService(snap, actorID, v); err != nil {
				return err
			}
		case "egress":
			v := route(snap, value.ResourceID)
			if v == nil || v.WorkspaceID != w.ID {
				return problem(types.KindForbidden, "egress route does not belong to this workspace")
			}
			if err := requireManager(snap, actorID, w.ID); err != nil {
				return err
			}
		default:
			return problem(types.KindInvalid, "resourceType must be service or egress")
		}
		external := false
		switch value.SubjectType {
		case "anonymous":
			if value.ResourceType != "service" || value.SubjectID != "" {
				return problem(types.KindInvalid, "anonymous grants only apply to services without a subject ID")
			}
			external = true
		case "user":
			if _, err := requireUser(snap, value.SubjectID); err != nil {
				return err
			}
			external = member(snap, w.ID, value.SubjectID) == nil
		case "workspace":
			subject := workspace(snap, value.SubjectID)
			if subject == nil {
				return problem(types.KindNotFound, "subject workspace not found")
			}
			value.SubjectID = subject.ID
			external = subject.ID != w.ID
		default:
			return problem(types.KindInvalid, "invalid grant subject type")
		}
		if value.ResourceType == "egress" && external {
			return problem(types.KindForbidden, "egress cannot be shared outside its workspace")
		}
		if external {
			if err := requireManager(snap, actorID, w.ID); err != nil {
				return problem(types.KindForbidden, "external or anonymous sharing requires a workspace manager")
			}
		}
		now := time.Now()
		if value.StartsAt.IsZero() {
			value.StartsAt = now.UTC()
		}
		if value.ExpiresAt.IsZero() || !value.StartsAt.Before(value.ExpiresAt) || !value.ExpiresAt.After(now) || value.ExpiresAt.Sub(value.StartsAt) > TokenTTL {
			return problem(types.KindInvalid, "grant needs an ordered, finite window of at most 30 days")
		}
		value.ID = randomID()
		value.WorkspaceID = w.ID
		value.Revoked = false
		snap.Grants = append(snap.Grants, value)
		audit(snap, actorID, "grant.create", value.ID)
		return nil
	})
	return value, err
}

func (s *State) RevokeGrant(actorID, id string) error {
	return s.mutate(func(snap *types.Snapshot) error {
		for i := range snap.Grants {
			g := &snap.Grants[i]
			if g.ID != id {
				continue
			}
			if g.ResourceType == "service" {
				v := service(snap, g.ResourceID)
				if v == nil {
					return problem(types.KindNotFound, "service not found")
				}
				if err := canManageService(snap, actorID, v); err != nil {
					return err
				}
			} else if err := requireManager(snap, actorID, g.WorkspaceID); err != nil {
				return err
			}
			g.Revoked = true
			audit(snap, actorID, "grant.revoke", id)
			return nil
		}
		return problem(types.KindNotFound, "grant not found")
	})
}
func (s *State) RevokeAgent(actorID, id string) error {
	return s.mutate(func(snap *types.Snapshot) error {
		a := agent(snap, id)
		if a == nil {
			return problem(types.KindNotFound, "agent not found")
		}
		if a.UserID != actorID {
			if err := requireManager(snap, actorID, a.WorkspaceID); err != nil {
				return err
			}
		} else if _, err := requireUser(snap, actorID); err != nil {
			return err
		}
		a.Status = "revoked"
		for i := range snap.Tokens {
			if snap.Tokens[i].AgentID == id {
				snap.Tokens[i].Revoked = true
			}
		}
		audit(snap, actorID, "agent.revoke", id)
		return nil
	})
}
func (s *State) RevokeEnrollmentKey(actorID, id string) error {
	return s.mutate(func(snap *types.Snapshot) error {
		for i := range snap.EnrollmentKeys {
			k := &snap.EnrollmentKeys[i]
			if k.ID != id {
				continue
			}
			if k.UserID != actorID {
				if err := requireManager(snap, actorID, k.WorkspaceID); err != nil {
					return err
				}
			} else if _, err := requireUser(snap, actorID); err != nil {
				return err
			}
			k.Revoked = true
			for j := range snap.Tokens {
				if snap.Tokens[j].Kind == "enrollment" && snap.Tokens[j].ID == id {
					snap.Tokens[j].Revoked = true
				}
			}
			audit(snap, actorID, "enrollment_key.revoke", id)
			return nil
		}
		return problem(types.KindNotFound, "enrollment key not found")
	})
}
func (s *State) SetServiceEnabled(actorID, id string, enabled bool) (types.Service, error) {
	var out types.Service
	err := s.mutate(func(snap *types.Snapshot) error {
		v := service(snap, id)
		if v == nil {
			return problem(types.KindNotFound, "service not found")
		}
		if err := canManageService(snap, actorID, v); err != nil {
			return err
		}
		v.Enabled = enabled
		out = *v
		audit(snap, actorID, "service.enabled", id)
		return nil
	})
	return out, err
}
func (s *State) SetEgressRouteEnabled(actorID, id string, enabled bool) (types.EgressRoute, error) {
	var out types.EgressRoute
	err := s.mutate(func(snap *types.Snapshot) error {
		v := route(snap, id)
		if v == nil {
			return problem(types.KindNotFound, "egress route not found")
		}
		if err := requireManager(snap, actorID, v.WorkspaceID); err != nil {
			return err
		}
		if enabled {
			for _, other := range snap.EgressRoutes {
				if other.ID != v.ID && other.Enabled && other.WorkspaceID == v.WorkspaceID && other.Priority == v.Priority && other.Rule.Domain == v.Rule.Domain {
					for _, port := range other.Rule.Ports {
						if slices.Contains(v.Rule.Ports, port) {
							return problem(types.KindConflict, "ambiguous egress route")
						}
					}
				}
			}
		}
		v.Enabled = enabled
		out = *v
		audit(snap, actorID, "egress_route.enabled", id)
		return nil
	})
	return out, err
}

func grantDeadline(snap *types.Snapshot, resourceType, resourceID, userID string, now time.Time) time.Time {
	var until time.Time
	u := user(snap, userID)
	for _, g := range snap.Grants {
		if g.ResourceType != resourceType || g.ResourceID != resourceID || g.Revoked || now.Before(g.StartsAt) || !now.Before(g.ExpiresAt) {
			continue
		}
		match := g.SubjectType == "anonymous" && resourceType == "service"
		if u != nil && !u.Disabled {
			match = match || g.SubjectType == "user" && g.SubjectID == userID || g.SubjectType == "workspace" && member(snap, g.SubjectID, userID) != nil
		}
		if match && g.ExpiresAt.After(until) {
			until = g.ExpiresAt
		}
	}
	return until
}
func cappedDeadline(until time.Time) time.Time {
	limit := time.Now().Add(time.Minute)
	if until.Before(limit) {
		return until
	}
	return limit
}
func canonicalHost(host string) (string, error) {
	if strings.Contains(host, ":") {
		h, p, err := net.SplitHostPort(host)
		if err != nil {
			return "", problem(types.KindInvalid, "invalid request authority")
		}
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", problem(types.KindInvalid, "invalid request authority port")
		}
		host = h
	}
	d, err := policy.CanonicalDomain(host)
	if err != nil {
		return "", problem(types.KindInvalid, "invalid request domain")
	}
	return d, nil
}

func (s *State) ResolveServe(host, userID string) (types.Decision, error) {
	domain, err := canonicalHost(host)
	if err != nil {
		return types.Decision{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := &s.snapshot
	if userID != "" {
		if _, err := requireUser(snap, userID); err != nil {
			return types.Decision{}, err
		}
	}
	var found *types.Service
	for i := range snap.Services {
		if snap.Services[i].Hostname == domain {
			found = &snap.Services[i]
			break
		}
	}
	if found == nil {
		return types.Decision{}, problem(types.KindNotFound, "unknown service")
	}
	if !found.Enabled {
		return types.Decision{}, problem(types.KindUnavailable, "service disabled")
	}
	until := grantDeadline(snap, "service", found.ID, userID, time.Now())
	if until.IsZero() {
		return types.Decision{}, problem(types.KindForbidden, "service access is not granted")
	}
	a := agent(snap, found.AgentID)
	if a == nil {
		return types.Decision{}, problem(types.KindUnavailable, "service provider unavailable")
	}
	view := agentView(snap, *a)
	if view.Status != "active" || view.Approval.Services[found.Name] == "" {
		return types.Decision{}, problem(types.KindUnavailable, "service provider is pending or locally withdrawn")
	}
	return types.Decision{ResourceType: "service", ResourceID: found.ID, WorkspaceID: found.WorkspaceID, Workspace: a.Workspace, AgentID: a.ID, ServiceName: found.Name, Hostname: domain, UserID: userID, Revision: a.Approval.Revision, PolicyRevision: snap.Revision, ExpiresAt: cappedDeadline(until)}, nil
}

func (s *State) ResolveEgress(workspaceSlug, userID, host string, port int) (types.Decision, error) {
	domain, err := policy.CanonicalDomain(host)
	if err != nil || port < 1 || port > 65535 {
		return types.Decision{}, problem(types.KindInvalid, "invalid egress destination")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := &s.snapshot
	if _, err := requireUser(snap, userID); err != nil {
		return types.Decision{}, err
	}
	w := workspace(snap, workspaceSlug)
	if w == nil {
		return types.Decision{}, problem(types.KindNotFound, "workspace not found")
	}
	if member(snap, w.ID, userID) == nil {
		return types.Decision{}, problem(types.KindForbidden, "egress requires current workspace membership")
	}
	var candidates []types.EgressRoute
	for _, r := range snap.EgressRoutes {
		if r.WorkspaceID == w.ID && r.Enabled && policy.Match(r.Rule, domain, port, "tls") {
			candidates = append(candidates, r)
		}
	}
	if len(candidates) == 0 {
		return types.Decision{}, problem(types.KindForbidden, "no egress route matches")
	}
	slices.SortFunc(candidates, func(a, b types.EgressRoute) int {
		if a.Priority != b.Priority {
			if a.Priority < b.Priority {
				return -1
			}
			return 1
		}
		if (a.Rule.Domain.Exact != "") != (b.Rule.Domain.Exact != "") {
			if a.Rule.Domain.Exact != "" {
				return -1
			}
			return 1
		}
		return len(b.Rule.Domain.Suffix) - len(a.Rule.Domain.Suffix)
	})
	r := candidates[0]
	until := grantDeadline(snap, "egress", r.ID, userID, time.Now())
	if until.IsZero() {
		return types.Decision{}, problem(types.KindForbidden, "selected egress route is not granted")
	}
	a := agent(snap, r.AgentID)
	if a == nil {
		return types.Decision{}, problem(types.KindUnavailable, "exit agent unavailable")
	}
	view := agentView(snap, *a)
	if view.Status != "active" {
		return types.Decision{}, problem(types.KindUnavailable, "exit agent is inactive")
	}
	if !policy.Allowed(view.Approval.Egress, view.Approval.Deny, domain, port, "tls") {
		return types.Decision{}, problem(types.KindForbidden, "exit agent does not permit this destination")
	}
	return types.Decision{ResourceType: "egress", ResourceID: r.ID, WorkspaceID: w.ID, Workspace: w.Name, AgentID: a.ID, UserID: userID, Destination: connection.Destination{Host: domain, Port: uint16(port)}, Revision: a.Approval.Revision, PolicyRevision: snap.Revision, ExpiresAt: cappedDeadline(until)}, nil
}
