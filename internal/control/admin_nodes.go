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

func (a *Admin) apiNode(ctx context.Context, ws store.Workspace, n store.Node, svcs []store.Service) adminapi.Node {
	online, relay := a.C.NodeOnline(n.PublicKey)
	out := adminapi.Node{
		Name: n.Name, PublicKey: identity.EncodeKey(n.PublicKey), RoleCaps: apiRoles(n.RoleCaps), Online: online, JoinedAt: n.JoinedAt, LastSeen: n.LastSeen,
		UriKey: ptr("agentd://" + identity.EncodeKey(n.PublicKey)), UriName: ptr("agentd://" + ws.BaseDomain + "/" + n.Name),
	}
	if online {
		out.Relay = ptr(relay)
	}
	if len(n.PolicySources) > 0 {
		ps := &struct {
			Egress   *adminapi.PolicySource `json:"egress,omitempty"`
			Executor *adminapi.PolicySource `json:"executor,omitempty"`
			Service  *adminapi.PolicySource `json:"service,omitempty"`
		}{}
		src := func(r string) *adminapi.PolicySource { v := adminapi.PolicySource(n.PolicySources[r]); return &v }
		ps.Egress, ps.Executor, ps.Service = src("egress"), src("executor"), src("service")
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
		}{Description: ptr(n.Executor.Description)}
		var tools []string
		for _, t := range n.Executor.Tools {
			tools = append(tools, t.Name)
		}
		ex.Tools = &tools
		out.Executor = ex
	}
	if n.PolicyApplied > 0 {
		out.PolicyVersionApplied = ptr(int(n.PolicyApplied))
	}
	return out
}

func (a *Admin) ListNodes(ctx context.Context, req adminapi.ListNodesRequestObject) (adminapi.ListNodesResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.ListNodes200JSONResponse{}, nil
	}
	nodes, err := a.C.st.ListNodes(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	svcs, _ := a.C.st.ListServices(ctx, ws.Name)
	out := adminapi.ListNodes200JSONResponse{}
	for _, n := range nodes {
		an := a.apiNode(ctx, ws, n, svcs)
		if req.Params.Online != nil && an.Online != *req.Params.Online {
			continue
		}
		out = append(out, an)
	}
	return out, nil
}

func (a *Admin) GetNode(ctx context.Context, req adminapi.GetNodeRequestObject) (adminapi.GetNodeResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.GetNode404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	n, err := a.C.st.GetNode(ctx, ws.Name, req.Node)
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.GetNode404JSONResponse{NotFoundJSONResponse: notFoundErr("node")}, nil
	}
	if err != nil {
		return nil, err
	}
	svcs, _ := a.C.st.ListServices(ctx, ws.Name)
	return adminapi.GetNode200JSONResponse(a.apiNode(ctx, ws, n, svcs)), nil
}

func (a *Admin) UpdateNode(ctx context.Context, req adminapi.UpdateNodeRequestObject) (adminapi.UpdateNodeResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.UpdateNode404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	n, err := a.C.st.GetNode(ctx, ws.Name, req.Node)
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.UpdateNode404JSONResponse{NotFoundJSONResponse: notFoundErr("node")}, nil
	}
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return adminapi.UpdateNode400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
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
			if code == 400 {
				return adminapi.UpdateNode400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
			}
			return nil, err
		}
		a.C.notify(ws, n.PublicKey, &pb.Notice{Kind: pb.Notice_RENAMED, NewName: *b.Name})
		n.Name = *b.Name
	}
	a.C.Changed(ctx, ws.Name)
	n, _ = a.C.st.GetNode(ctx, ws.Name, n.Name)
	svcs, _ := a.C.st.ListServices(ctx, ws.Name)
	return adminapi.UpdateNode200JSONResponse(a.apiNode(ctx, ws, n, svcs)), nil
}

func (a *Admin) RemoveNode(ctx context.Context, req adminapi.RemoveNodeRequestObject) (adminapi.RemoveNodeResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.RemoveNode404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	n, err := a.C.st.GetNode(ctx, ws.Name, req.Node)
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.RemoveNode404JSONResponse{NotFoundJSONResponse: notFoundErr("node")}, nil
	}
	if err != nil {
		return nil, err
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

// ---------------------------------------------------------------- groups

func (a *Admin) apiGroup(ws store.Workspace, g store.Group) adminapi.Group {
	members := g.Members
	if members == nil {
		members = []string{}
	}
	return adminapi.Group{Name: g.Name, PublicKey: identity.EncodeKey(g.PublicKey), Uri: ptr("agentd://" + ws.BaseDomain + "/group/" + g.Name), Members: members}
}

func (a *Admin) ListGroups(ctx context.Context, req adminapi.ListGroupsRequestObject) (adminapi.ListGroupsResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.ListGroups200JSONResponse{}, nil
	}
	gs, err := a.C.st.ListGroups(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListGroups200JSONResponse{}
	for _, g := range gs {
		out = append(out, a.apiGroup(ws, g))
	}
	return out, nil
}

func (a *Admin) CreateGroup(ctx context.Context, req adminapi.CreateGroupRequestObject) (adminapi.CreateGroupResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
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
		if code, c := classify(err); code == 409 {
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
	g, err := a.C.st.GetGroup(ctx, ws.Name, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return adminapi.CreateGroup201JSONResponse(a.apiGroup(ws, g)), nil
}

func (a *Admin) GetGroup(ctx context.Context, req adminapi.GetGroupRequestObject) (adminapi.GetGroupResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.GetGroup404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	g, err := a.C.st.GetGroup(ctx, ws.Name, req.Group)
	if err != nil {
		return adminapi.GetGroup404JSONResponse{NotFoundJSONResponse: notFoundErr("group")}, nil
	}
	return adminapi.GetGroup200JSONResponse(a.apiGroup(ws, g)), nil
}

func (a *Admin) DeleteGroup(ctx context.Context, req adminapi.DeleteGroupRequestObject) (adminapi.DeleteGroupResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.DeleteGroup404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	g, err := a.C.st.GetGroup(ctx, ws.Name, req.Group)
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

func (a *Admin) AddGroupMember(ctx context.Context, req adminapi.AddGroupMemberRequestObject) (adminapi.AddGroupMemberResponseObject, error) {
	if err := a.C.st.AddGroupMember(ctx, req.Ws, req.Group, req.Node); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.AddGroupMember404JSONResponse{NotFoundJSONResponse: notFoundErr("group or node")}, nil
		}
		return nil, err
	}
	a.C.Changed(ctx, req.Ws)
	return adminapi.AddGroupMember204Response{}, nil
}

func (a *Admin) RemoveGroupMember(ctx context.Context, req adminapi.RemoveGroupMemberRequestObject) (adminapi.RemoveGroupMemberResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.RemoveGroupMember404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	g, err1 := a.C.st.GetGroup(ctx, ws.Name, req.Group)
	n, err2 := a.C.st.GetNode(ctx, ws.Name, req.Node)
	if err1 != nil || err2 != nil {
		return adminapi.RemoveGroupMember404JSONResponse{NotFoundJSONResponse: notFoundErr("group or node")}, nil
	}
	if err := a.C.st.RemoveGroupMember(ctx, ws.Name, g.Name, n.Name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.RemoveGroupMember404JSONResponse{NotFoundJSONResponse: notFoundErr("membership")}, nil
		}
		return nil, err
	}
	_ = a.C.st.AddRevocation(ctx, ws.Name, n.PublicKey, g.PublicKey, time.Now().Add(wire.MembershipTTL))
	a.C.broadcastRevocations(ctx, ws)
	a.C.Changed(ctx, ws.Name)
	return adminapi.RemoveGroupMember204Response{}, nil
}
