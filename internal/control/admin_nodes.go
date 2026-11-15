package control

import (
	"context"
	"errors"
	"time"

	"agentd/internal/adminapi"
	"agentd/internal/identity"
	"agentd/internal/store"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

func apiNode(ctx context.Context, a *Admin, ws store.Workspace, n store.Node, svcs []store.Service) adminapi.Node {
	online, relay := a.C.NodeOnline(n.PublicKey)
	out := adminapi.Node{Id: idFor("node", ws.Name+"/"+n.Name), Name: n.Name, PublicKey: identity.EncodeKey(n.PublicKey), RoleCaps: apiRoles(n.RoleCaps), Online: online, JoinedAt: n.JoinedAt, LastSeen: n.LastSeen, Status: adminapi.NodeStatus("active")}
	if online {
		rid := idFor("relay", relay)
		out.RelayId = &rid
	}
	if len(n.PolicySources) > 0 {
		ps := &struct {
			Egress   *adminapi.PolicySource `json:"egress,omitempty"`
			Executor *adminapi.PolicySource `json:"executor,omitempty"`
			Service  *adminapi.PolicySource `json:"service,omitempty"`
		}{}
		if v, ok := n.PolicySources["egress"]; ok {
			x := adminapi.PolicySource(v)
			ps.Egress = &x
		}
		if v, ok := n.PolicySources["executor"]; ok {
			x := adminapi.PolicySource(v)
			ps.Executor = &x
		}
		if v, ok := n.PolicySources["service"]; ok {
			x := adminapi.PolicySource(v)
			ps.Service = &x
		}
		out.PolicySources = ps
	}
	var names []string
	for _, s := range svcs {
		if s.Node == n.Name {
			names = append(names, s.Name)
		}
	}
	if len(names) > 0 {
		out.Services = &names
	}
	if n.Executor != nil {
		ex := &struct {
			Description *string   `json:"description,omitempty"`
			Tools       *[]string `json:"tools,omitempty"`
		}{Description: &n.Executor.Description}
		var tools []string
		for _, t := range n.Executor.Tools {
			tools = append(tools, t.Name)
		}
		ex.Tools = &tools
		out.Executor = ex
	}
	if n.PolicyApplied > 0 {
		v := int(n.PolicyApplied)
		out.PolicyVersionApplied = &v
	}
	return out
}
func (a *Admin) resolveNode(ctx context.Context, ws store.Workspace, id string) (store.Node, error) {
	if n, err := a.C.st.GetNode(ctx, ws.Name, id); err == nil {
		return n, nil
	}
	ns, err := a.C.st.ListNodes(ctx, ws.Name)
	if err != nil {
		return store.Node{}, err
	}
	for _, n := range ns {
		if idFor("node", ws.Name+"/"+n.Name) == id {
			return n, nil
		}
	}
	return store.Node{}, store.ErrNotFound
}
func (a *Admin) ListNodes(ctx context.Context, req adminapi.ListNodesRequestObject) (adminapi.ListNodesResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.ListNodes200JSONResponse{}, nil
	}
	ns, err := a.C.st.ListNodes(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	svcs, _ := a.C.st.ListServices(ctx, ws.Name)
	out := adminapi.ListNodes200JSONResponse{}
	for _, n := range ns {
		v := apiNode(ctx, a, ws, n, svcs)
		if req.Params.Online != nil && v.Online != *req.Params.Online {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}
func (a *Admin) GetNode(ctx context.Context, req adminapi.GetNodeRequestObject) (adminapi.GetNodeResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.GetNode404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	n, err := a.resolveNode(ctx, ws, req.NodeId)
	if err != nil {
		return adminapi.GetNode404JSONResponse{NotFoundJSONResponse: notFoundErr("node")}, nil
	}
	svcs, _ := a.C.st.ListServices(ctx, ws.Name)
	return adminapi.GetNode200JSONResponse(apiNode(ctx, a, ws, n, svcs)), nil
}
func (a *Admin) UpdateNode(ctx context.Context, req adminapi.UpdateNodeRequestObject) (adminapi.UpdateNodeResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.UpdateNode404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	n, err := a.resolveNode(ctx, ws, req.NodeId)
	if err != nil {
		return adminapi.UpdateNode404JSONResponse{NotFoundJSONResponse: notFoundErr("node")}, nil
	}
	if req.Body == nil {
		return adminapi.UpdateNode400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	b := req.Body
	if b.RoleCaps != nil {
		roles := roleNames(*b.RoleCaps)
		for _, r := range roles {
			if _, ok := roleByName[r]; !ok {
				return adminapi.UpdateNode400JSONResponse{BadRequestJSONResponse: badRequest("unknown role " + r)}, nil
			}
		}
		if err := a.C.st.SetRoleCaps(ctx, ws.Name, n.Name, roles); err != nil {
			return nil, err
		}
		a.C.notify(ws, n.PublicKey, &pb.Notice{Kind: pb.Notice_ROLES_CHANGED, RoleCaps: pbRoles(roles)})
	}
	if b.Name != nil && *b.Name != n.Name {
		if err := a.C.st.RenameNode(ctx, ws.Name, n.Name, *b.Name); err != nil {
			code, c := classify(err)
			if code == 409 {
				return adminapi.UpdateNode409JSONResponse(apiErr(c, err.Error())), nil
			}
			return adminapi.UpdateNode400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
		}
		a.C.notify(ws, n.PublicKey, &pb.Notice{Kind: pb.Notice_RENAMED, NewName: *b.Name})
		n.Name = *b.Name
	}
	a.C.Changed(ctx, ws.Name)
	n, _ = a.C.st.GetNode(ctx, ws.Name, n.Name)
	svcs, _ := a.C.st.ListServices(ctx, ws.Name)
	return adminapi.UpdateNode200JSONResponse(apiNode(ctx, a, ws, n, svcs)), nil
}
func (a *Admin) RemoveNode(ctx context.Context, req adminapi.RemoveNodeRequestObject) (adminapi.RemoveNodeResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.RemoveNode404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	n, err := a.resolveNode(ctx, ws, req.NodeId)
	if err != nil {
		return adminapi.RemoveNode404JSONResponse{NotFoundJSONResponse: notFoundErr("node")}, nil
	}
	a.C.notify(ws, n.PublicKey, &pb.Notice{Kind: pb.Notice_REMOVED, Message: "removed by the administrator"})
	until := time.Now().Add(wire.MembershipTTL)
	_ = a.C.st.AddRevocation(ctx, ws.Name, n.PublicKey, ws.PublicKey, until)
	groups, _ := a.C.st.ListGroups(ctx, ws.Name)
	for _, g := range groups {
		for _, m := range g.Members {
			if m == n.Name {
				_ = a.C.st.AddRevocation(ctx, ws.Name, n.PublicKey, g.PublicKey, until)
			}
		}
	}
	if err := a.C.st.DeleteNode(ctx, ws.Name, n.Name); err != nil {
		return nil, err
	}
	a.C.invalidate(ws, n.PublicKey)
	a.C.broadcastRevocations(ctx, ws)
	a.C.Changed(ctx, ws.Name)
	return adminapi.RemoveNode204Response{}, nil
}

func apiGroup(ws store.Workspace, g store.Group) adminapi.Group {
	members := g.Members
	if members == nil {
		members = []string{}
	}
	return adminapi.Group{Id: idFor("group", ws.Name+"/"+g.Name), Name: g.Name, PublicKey: identity.EncodeKey(g.PublicKey), Members: members, Status: adminapi.GroupStatus("active"), Uri: ptr("agentd://" + ws.BaseDomain + "/group/" + g.Name)}
}
func (a *Admin) ListGroups(ctx context.Context, req adminapi.ListGroupsRequestObject) (adminapi.ListGroupsResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.ListGroups200JSONResponse{}, nil
	}
	gs, err := a.C.st.ListGroups(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListGroups200JSONResponse{}
	for _, g := range gs {
		out = append(out, apiGroup(ws, g))
	}
	return out, nil
}
func (a *Admin) CreateGroup(ctx context.Context, req adminapi.CreateGroupRequestObject) (adminapi.CreateGroupResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.CreateGroup400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
	}
	if req.Body == nil || !identity.ValidLabel(req.Body.Name) {
		return adminapi.CreateGroup400JSONResponse{BadRequestJSONResponse: badRequest("group name must be an RFC 1123 label")}, nil
	}
	key, err := identity.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := a.C.st.CreateGroup(ctx, store.Group{Workspace: ws.Name, Name: req.Body.Name, PrivateKey: key}); err != nil {
		code, c := classify(err)
		if code == 409 {
			if c == "CONFLICT" {
				c = "NAME_TAKEN"
			}
			return adminapi.CreateGroup409JSONResponse(apiErr(c, err.Error())), nil
		}
		return nil, err
	}
	if req.Body.Members != nil {
		for _, m := range *req.Body.Members {
			if err := a.C.st.AddGroupMember(ctx, ws.Name, req.Body.Name, m); err != nil {
				return adminapi.CreateGroup400JSONResponse{BadRequestJSONResponse: badRequest("unknown member " + m)}, nil
			}
		}
	}
	a.C.Changed(ctx, ws.Name)
	g, _ := a.C.st.GetGroup(ctx, ws.Name, req.Body.Name)
	return adminapi.CreateGroup201JSONResponse(apiGroup(ws, g)), nil
}
func (a *Admin) resolveGroup(ctx context.Context, ws store.Workspace, id string) (store.Group, error) {
	if g, err := a.C.st.GetGroup(ctx, ws.Name, id); err == nil {
		return g, nil
	}
	gs, err := a.C.st.ListGroups(ctx, ws.Name)
	if err != nil {
		return store.Group{}, err
	}
	for _, g := range gs {
		if idFor("group", ws.Name+"/"+g.Name) == id {
			return g, nil
		}
	}
	return store.Group{}, store.ErrNotFound
}
func (a *Admin) GetGroup(ctx context.Context, req adminapi.GetGroupRequestObject) (adminapi.GetGroupResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.GetGroup404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	g, err := a.resolveGroup(ctx, ws, req.GroupId)
	if err != nil {
		return adminapi.GetGroup404JSONResponse{NotFoundJSONResponse: notFoundErr("group")}, nil
	}
	return adminapi.GetGroup200JSONResponse(apiGroup(ws, g)), nil
}
func (a *Admin) DeleteGroup(ctx context.Context, req adminapi.DeleteGroupRequestObject) (adminapi.DeleteGroupResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.DeleteGroup404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	g, err := a.resolveGroup(ctx, ws, req.GroupId)
	if err != nil {
		return adminapi.DeleteGroup404JSONResponse{NotFoundJSONResponse: notFoundErr("group")}, nil
	}
	_ = a.C.st.AddRevocation(ctx, ws.Name, nil, g.PublicKey, time.Now().Add(wire.MembershipTTL))
	if err := a.C.st.DeleteGroup(ctx, ws.Name, g.Name); err != nil {
		return nil, err
	}
	a.C.broadcastRevocations(ctx, ws)
	a.C.Changed(ctx, ws.Name)
	return adminapi.DeleteGroup204Response{}, nil
}
func (a *Admin) AddGroupNode(ctx context.Context, req adminapi.AddGroupNodeRequestObject) (adminapi.AddGroupNodeResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.AddGroupNode404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	g, err := a.resolveGroup(ctx, ws, req.GroupId)
	if err != nil {
		return adminapi.AddGroupNode404JSONResponse{NotFoundJSONResponse: notFoundErr("group")}, nil
	}
	n, err := a.resolveNode(ctx, ws, req.NodeId)
	if err != nil {
		return adminapi.AddGroupNode404JSONResponse{NotFoundJSONResponse: notFoundErr("node")}, nil
	}
	if err := a.C.st.AddGroupMember(ctx, ws.Name, g.Name, n.Name); err != nil {
		return nil, err
	}
	a.C.Changed(ctx, ws.Name)
	return adminapi.AddGroupNode204Response{}, nil
}
func (a *Admin) RemoveGroupNode(ctx context.Context, req adminapi.RemoveGroupNodeRequestObject) (adminapi.RemoveGroupNodeResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.RemoveGroupNode404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	g, err := a.resolveGroup(ctx, ws, req.GroupId)
	if err != nil {
		return adminapi.RemoveGroupNode404JSONResponse{NotFoundJSONResponse: notFoundErr("group")}, nil
	}
	n, err := a.resolveNode(ctx, ws, req.NodeId)
	if err != nil {
		return adminapi.RemoveGroupNode404JSONResponse{NotFoundJSONResponse: notFoundErr("node")}, nil
	}
	if err := a.C.st.RemoveGroupMember(ctx, ws.Name, g.Name, n.Name); err != nil {
		return adminapi.RemoveGroupNode404JSONResponse{NotFoundJSONResponse: notFoundErr("membership")}, nil
	}
	_ = a.C.st.AddRevocation(ctx, ws.Name, n.PublicKey, g.PublicKey, time.Now().Add(wire.MembershipTTL))
	a.C.broadcastRevocations(ctx, ws)
	a.C.Changed(ctx, ws.Name)
	return adminapi.RemoveGroupNode204Response{}, nil
}

func apiWorkspaceMember(m store.WorkspaceMember) adminapi.WorkspaceMember {
	return adminapi.WorkspaceMember{Id: idFor("membership", m.Workspace+"/"+m.Subject), UserId: idFor("user", m.Subject), Subject: m.Subject, Role: adminapi.WorkspaceRole(m.Role), Status: ptr(adminapi.WorkspaceMemberStatus("active")), CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}
}
func (a *Admin) ListWorkspaceMembers(ctx context.Context, req adminapi.ListWorkspaceMembersRequestObject) (adminapi.ListWorkspaceMembersResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.ListWorkspaceMembers404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	ms, err := a.C.st.ListWorkspaceMembers(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListWorkspaceMembers200JSONResponse{}
	for _, m := range ms {
		out = append(out, apiWorkspaceMember(m))
	}
	return out, nil
}
func (a *Admin) UpsertWorkspaceMember(ctx context.Context, req adminapi.UpsertWorkspaceMemberRequestObject) (adminapi.UpsertWorkspaceMemberResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.UpsertWorkspaceMember404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	if req.Body == nil {
		return adminapi.UpsertWorkspaceMember404JSONResponse{NotFoundJSONResponse: notFoundErr("user")}, nil
	}
	subject := string(req.Body.UserId)
	if req.Body.Subject != "" {
		subject = req.Body.Subject
	}
	if u, e := a.resolveUser(ctx, req.Body.UserId); e == nil {
		subject = u.Subject
	}
	role := store.WorkspaceRole(req.Body.Role)
	if role != store.WorkspaceOwner && role != store.WorkspaceMaintainer && role != store.WorkspaceRoleMember {
		return adminapi.UpsertWorkspaceMember409JSONResponse(apiErr("CONFLICT", "invalid role")), nil
	}
	if err := a.C.st.UpsertWorkspaceMember(ctx, store.WorkspaceMember{Workspace: ws.Name, Subject: subject, Role: role}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return adminapi.UpsertWorkspaceMember409JSONResponse(apiErr("CONFLICT", err.Error())), nil
		}
		return nil, err
	}
	m, _ := a.C.st.GetWorkspaceMember(ctx, ws.Name, subject)
	return adminapi.UpsertWorkspaceMember200JSONResponse(apiWorkspaceMember(m)), nil
}
func (a *Admin) resolveMember(ctx context.Context, ws store.Workspace, id string) (store.WorkspaceMember, error) {
	ms, err := a.C.st.ListWorkspaceMembers(ctx, ws.Name)
	if err != nil {
		return store.WorkspaceMember{}, err
	}
	for _, m := range ms {
		if m.Subject == id || idFor("membership", ws.Name+"/"+m.Subject) == id {
			return m, nil
		}
	}
	return store.WorkspaceMember{}, store.ErrNotFound
}
func (a *Admin) RemoveWorkspaceMember(ctx context.Context, req adminapi.RemoveWorkspaceMemberRequestObject) (adminapi.RemoveWorkspaceMemberResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.RemoveWorkspaceMember404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	m, err := a.resolveMember(ctx, ws, req.MemberId)
	if err != nil {
		return adminapi.RemoveWorkspaceMember404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace member")}, nil
	}
	if err := a.C.st.DeleteWorkspaceMember(ctx, ws.Name, m.Subject); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return adminapi.RemoveWorkspaceMember409JSONResponse(apiErr("CONFLICT", err.Error())), nil
		}
		return nil, err
	}
	return adminapi.RemoveWorkspaceMember204Response{}, nil
}
