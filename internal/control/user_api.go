package control

import (
	"context"
	"errors"

	"agentd/internal/adminapi"
	"agentd/internal/store"
	"agentd/internal/userapi"
)

var _ userapi.StrictServerInterface = (*Admin)(nil)

func userWorkspace(ctx context.Context, a *Admin, id string, allowed ...store.WorkspaceRole) (store.Workspace, bool) {
	ws, err := a.resolveWorkspace(ctx, id)
	if err != nil {
		return store.Workspace{}, false
	}
	role, ok := userRole(ctx, a, ws.Name)
	if !ok {
		return store.Workspace{}, false
	}
	for _, want := range allowed {
		if role == want {
			return ws, true
		}
	}
	return store.Workspace{}, false
}

func userWorkspaceNotFound() adminapi.NotFoundJSONResponse {
	return notFoundErr("workspace")
}

func (a *Admin) ListMyWorkspaces(ctx context.Context, _ userapi.ListMyWorkspacesRequestObject) (userapi.ListMyWorkspacesResponseObject, error) {
	wss, err := a.C.st.ListWorkspaces(ctx)
	if err != nil {
		return nil, err
	}
	out := userapi.ListMyWorkspaces200JSONResponse{}
	for _, ws := range wss {
		if _, ok := userRole(ctx, a, ws.Name); ok {
			out = append(out, a.apiWorkspace(ctx, ws))
		}
	}
	return out, nil
}

func (a *Admin) GetMyWorkspace(ctx context.Context, req userapi.GetMyWorkspaceRequestObject) (userapi.GetMyWorkspaceResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner, store.WorkspaceMaintainer, store.WorkspaceRoleMember)
	if !ok {
		return userapi.GetMyWorkspace404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	return userapi.GetMyWorkspace200JSONResponse(a.apiWorkspace(ctx, ws)), nil
}

func (a *Admin) ListMyWorkspaceMembers(ctx context.Context, req userapi.ListMyWorkspaceMembersRequestObject) (userapi.ListMyWorkspaceMembersResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner, store.WorkspaceMaintainer, store.WorkspaceRoleMember)
	if !ok {
		return userapi.ListMyWorkspaceMembers404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	items, err := a.C.st.ListWorkspaceMembers(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	out := userapi.ListMyWorkspaceMembers200JSONResponse{}
	for _, item := range items {
		out = append(out, apiWorkspaceMember(item))
	}
	return out, nil
}

func (a *Admin) UpsertMyWorkspaceMember(ctx context.Context, req userapi.UpsertMyWorkspaceMemberRequestObject) (userapi.UpsertMyWorkspaceMemberResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner)
	if !ok {
		return userapi.UpsertMyWorkspaceMember404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	v, err := a.UpsertWorkspaceMember(ctx, adminapi.UpsertWorkspaceMemberRequestObject{WorkspaceId: idFor("workspace", ws.Name), Body: req.Body})
	if err != nil {
		return nil, err
	}
	switch response := v.(type) {
	case adminapi.UpsertWorkspaceMember200JSONResponse:
		return userapi.UpsertMyWorkspaceMember200JSONResponse(response), nil
	case adminapi.UpsertWorkspaceMember404JSONResponse:
		return userapi.UpsertMyWorkspaceMember404JSONResponse{NotFoundJSONResponse: response.NotFoundJSONResponse}, nil
	case adminapi.UpsertWorkspaceMember409JSONResponse:
		return userapi.UpsertMyWorkspaceMember409JSONResponse{ConflictJSONResponse: adminapi.ConflictJSONResponse(response)}, nil
	default:
		return nil, errors.New("unexpected workspace-member response")
	}
}

func (a *Admin) RemoveMyWorkspaceMember(ctx context.Context, req userapi.RemoveMyWorkspaceMemberRequestObject) (userapi.RemoveMyWorkspaceMemberResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner)
	if !ok {
		return userapi.RemoveMyWorkspaceMember404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	v, err := a.RemoveWorkspaceMember(ctx, adminapi.RemoveWorkspaceMemberRequestObject{WorkspaceId: idFor("workspace", ws.Name), MemberId: req.MemberId})
	if err != nil {
		return nil, err
	}
	switch response := v.(type) {
	case adminapi.RemoveWorkspaceMember204Response:
		return userapi.RemoveMyWorkspaceMember204Response{}, nil
	case adminapi.RemoveWorkspaceMember404JSONResponse:
		return userapi.RemoveMyWorkspaceMember404JSONResponse{NotFoundJSONResponse: response.NotFoundJSONResponse}, nil
	case adminapi.RemoveWorkspaceMember409JSONResponse:
		return userapi.RemoveMyWorkspaceMember409JSONResponse{ConflictJSONResponse: adminapi.ConflictJSONResponse(response)}, nil
	default:
		return nil, errors.New("unexpected workspace-member response")
	}
}

func (a *Admin) ListMyWorkspaceNodes(ctx context.Context, req userapi.ListMyWorkspaceNodesRequestObject) (userapi.ListMyWorkspaceNodesResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner, store.WorkspaceMaintainer, store.WorkspaceRoleMember)
	if !ok {
		return userapi.ListMyWorkspaceNodes404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	nodes, err := a.C.st.ListNodes(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	services, _ := a.C.st.ListServices(ctx, ws.Name)
	out := userapi.ListMyWorkspaceNodes200JSONResponse{}
	for _, node := range nodes {
		out = append(out, apiNode(ctx, a, ws, node, services))
	}
	return out, nil
}

func (a *Admin) ListMyPolicies(ctx context.Context, req userapi.ListMyPoliciesRequestObject) (userapi.ListMyPoliciesResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner, store.WorkspaceMaintainer, store.WorkspaceRoleMember)
	if !ok {
		return userapi.ListMyPolicies404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	items, err := a.C.st.ListPolicies(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	out := userapi.ListMyPolicies200JSONResponse{}
	for _, item := range items {
		out = append(out, apiStatement(item))
	}
	return out, nil
}

func (a *Admin) ReplaceMyPolicies(ctx context.Context, req userapi.ReplaceMyPoliciesRequestObject) (userapi.ReplaceMyPoliciesResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner, store.WorkspaceMaintainer)
	if !ok {
		return userapi.ReplaceMyPolicies404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	v, err := a.ReplacePolicies(ctx, adminapi.ReplacePoliciesRequestObject{WorkspaceId: idFor("workspace", ws.Name), Body: req.Body})
	if err != nil {
		return nil, err
	}
	switch response := v.(type) {
	case adminapi.ReplacePolicies200JSONResponse:
		return userapi.ReplaceMyPolicies200JSONResponse(response), nil
	case adminapi.ReplacePolicies400JSONResponse:
		return userapi.ReplaceMyPolicies400JSONResponse{BadRequestJSONResponse: response.BadRequestJSONResponse}, nil
	default:
		return nil, errors.New("unexpected policy response")
	}
}

func (a *Admin) GetMyRouteTable(ctx context.Context, req userapi.GetMyRouteTableRequestObject) (userapi.GetMyRouteTableResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner, store.WorkspaceMaintainer, store.WorkspaceRoleMember)
	if !ok {
		return userapi.GetMyRouteTable404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	table, err := a.C.st.GetRouteTable(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	return userapi.GetMyRouteTable200JSONResponse(apiTable(ws.Name, table)), nil
}

func (a *Admin) ReplaceMyRouteTable(ctx context.Context, req userapi.ReplaceMyRouteTableRequestObject) (userapi.ReplaceMyRouteTableResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner, store.WorkspaceMaintainer)
	if !ok {
		return userapi.ReplaceMyRouteTable404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	v, err := a.ReplaceRouteTable(ctx, adminapi.ReplaceRouteTableRequestObject{WorkspaceId: idFor("workspace", ws.Name), Body: req.Body})
	if err != nil {
		return nil, err
	}
	switch response := v.(type) {
	case adminapi.ReplaceRouteTable200JSONResponse:
		return userapi.ReplaceMyRouteTable200JSONResponse(response), nil
	case adminapi.ReplaceRouteTable400JSONResponse:
		return userapi.ReplaceMyRouteTable400JSONResponse{BadRequestJSONResponse: response.BadRequestJSONResponse}, nil
	default:
		return nil, errors.New("unexpected route-table response")
	}
}

func (a *Admin) ListMyServices(ctx context.Context, req userapi.ListMyServicesRequestObject) (userapi.ListMyServicesResponseObject, error) {
	ws, ok := userWorkspace(ctx, a, req.WorkspaceId, store.WorkspaceOwner, store.WorkspaceMaintainer, store.WorkspaceRoleMember)
	if !ok {
		return userapi.ListMyServices404JSONResponse{NotFoundJSONResponse: userWorkspaceNotFound()}, nil
	}
	v, err := a.ListServices(ctx, adminapi.ListServicesRequestObject{WorkspaceId: idFor("workspace", ws.Name)})
	if err != nil {
		return nil, err
	}
	items, ok := v.(adminapi.ListServices200JSONResponse)
	if !ok {
		return nil, errors.New("unexpected service response")
	}
	return userapi.ListMyServices200JSONResponse(items), nil
}
