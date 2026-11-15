package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"agentd/internal/adminapi"
	"agentd/internal/store"
)

// userHandler implements the deliberately smaller user OpenAPI surface.  OIDC
// validation is deployment-specific; until an auth provider is configured the
// bearer is accepted as a user id/subject, while the bootstrap admin token has
// break-glass access to every workspace.
func (a *Admin) userHandler(adminToken string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") || strings.HasPrefix(r.URL.Path, "/api/v1/join/") {
			http.NotFound(w, r)
			return
		}
		bearer := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if bearer == "" {
			writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "user bearer required")
			return
		}
		if adminToken != "" && bearer == adminToken {
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "use the instance admin API for the bootstrap administrator")
			return
		}
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/"), "/")
		if len(parts) == 1 && parts[0] == "workspaces" && r.Method == http.MethodGet {
			a.userListWorkspaces(w, r, bearer)
			return
		}
		if len(parts) < 2 || parts[0] != "workspaces" {
			http.NotFound(w, r)
			return
		}
		ws, err := a.resolveWorkspace(r.Context(), parts[1])
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "workspace not found")
			return
		}
		role := store.WorkspaceRole("")
		role = a.userRole(r.Context(), ws.Name, bearer)
		if role == "" {
			writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "workspace not found")
			return
		}
		if len(parts) == 2 && r.Method == http.MethodGet {
			a.userJSON(w, http.StatusOK, a.apiWorkspace(r.Context(), ws))
			return
		}
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		switch parts[2] {
		case "members":
			a.userMembers(w, r, ws, role, false, parts[3:])
		case "nodes":
			a.userNodes(w, r, ws, parts[3:])
		case "routes":
			a.userRoutes(w, r, ws, role, parts[3:])
		case "policies":
			a.userPolicies(w, r, ws, role, parts[3:])
		case "services":
			if r.Method == http.MethodGet {
				v, _ := a.ListServices(r.Context(), adminapi.ListServicesRequestObject{WorkspaceId: idFor("workspace", ws.Name)})
				a.userJSON(w, http.StatusOK, v)
			} else {
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

func (a *Admin) userJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (a *Admin) userRole(ctx context.Context, ws, bearer string) store.WorkspaceRole {
	if m, err := a.C.st.GetWorkspaceMember(ctx, ws, bearer); err == nil {
		return m.Role
	}
	if users, err := a.C.st.ListUsers(ctx); err == nil {
		for _, u := range users {
			if u.ID == bearer || u.Email == bearer || u.Subject == bearer {
				if m, e := a.C.st.GetWorkspaceMember(ctx, ws, u.Subject); e == nil {
					return m.Role
				}
			}
		}
	}
	return ""
}
func (a *Admin) userListWorkspaces(w http.ResponseWriter, r *http.Request, bearer string) {
	wss, _ := a.C.st.ListWorkspaces(r.Context())
	out := adminapi.ListWorkspaces200JSONResponse{}
	for _, ws := range wss {
		if a.userRole(r.Context(), ws.Name, bearer) != "" {
			out = append(out, a.apiWorkspace(r.Context(), ws))
		}
	}
	a.userJSON(w, http.StatusOK, out)
}

func (a *Admin) userMembers(w http.ResponseWriter, r *http.Request, ws store.Workspace, role store.WorkspaceRole, admin bool, tail []string) {
	if len(tail) == 0 && r.Method == http.MethodGet {
		v, _ := a.ListWorkspaceMembers(r.Context(), adminapi.ListWorkspaceMembersRequestObject{WorkspaceId: idFor("workspace", ws.Name)})
		a.userJSON(w, 200, v)
		return
	}
	if len(tail) == 0 && r.Method == http.MethodPost {
		if role != store.WorkspaceOwner && !admin {
			writeJSONError(w, 404, "NOT_FOUND", "workspace not found")
			return
		}
		var b adminapi.UpsertWorkspaceMemberJSONRequestBody
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSONError(w, 400, "BAD_REQUEST", "invalid JSON")
			return
		}
		v, e := a.UpsertWorkspaceMember(r.Context(), adminapi.UpsertWorkspaceMemberRequestObject{WorkspaceId: idFor("workspace", ws.Name), Body: &b})
		if e != nil {
			writeJSONError(w, 500, "INTERNAL", e.Error())
			return
		}
		a.userJSON(w, 200, v)
		return
	}
	if len(tail) == 1 && r.Method == http.MethodDelete {
		if role != store.WorkspaceOwner && !admin {
			writeJSONError(w, 404, "NOT_FOUND", "workspace not found")
			return
		}
		v, e := a.RemoveWorkspaceMember(r.Context(), adminapi.RemoveWorkspaceMemberRequestObject{WorkspaceId: idFor("workspace", ws.Name), MemberId: tail[0]})
		if e != nil {
			writeJSONError(w, 500, "INTERNAL", e.Error())
			return
		}
		a.userJSON(w, 204, v)
		return
	}
	http.NotFound(w, r)
}
func (a *Admin) userNodes(w http.ResponseWriter, r *http.Request, ws store.Workspace, tail []string) {
	if r.Method != http.MethodGet || len(tail) > 0 {
		http.NotFound(w, r)
		return
	}
	v, _ := a.ListNodes(r.Context(), adminapi.ListNodesRequestObject{WorkspaceId: idFor("workspace", ws.Name)})
	a.userJSON(w, 200, v)
}
func (a *Admin) userRoutes(w http.ResponseWriter, r *http.Request, ws store.Workspace, role store.WorkspaceRole, tail []string) {
	id := idFor("workspace", ws.Name)
	if len(tail) == 0 && r.Method == http.MethodGet {
		v, e := a.GetRouteTable(r.Context(), adminapi.GetRouteTableRequestObject{WorkspaceId: id})
		if e != nil {
			writeJSONError(w, 500, "INTERNAL", e.Error())
			return
		}
		a.userJSON(w, 200, v)
		return
	}
	if len(tail) == 0 && r.Method == http.MethodPut {
		if role == store.WorkspaceRoleMember {
			writeJSONError(w, 404, "NOT_FOUND", "workspace not found")
			return
		}
		var b adminapi.ReplaceRouteTableJSONRequestBody
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSONError(w, 400, "BAD_REQUEST", "invalid JSON")
			return
		}
		v, e := a.ReplaceRouteTable(r.Context(), adminapi.ReplaceRouteTableRequestObject{WorkspaceId: id, Body: &b})
		if e != nil {
			writeJSONError(w, 500, "INTERNAL", e.Error())
			return
		}
		a.userJSON(w, 200, v)
		return
	}
	http.NotFound(w, r)
}
func (a *Admin) userPolicies(w http.ResponseWriter, r *http.Request, ws store.Workspace, role store.WorkspaceRole, tail []string) {
	id := idFor("workspace", ws.Name)
	if len(tail) == 0 && r.Method == http.MethodGet {
		v, e := a.ListPolicies(r.Context(), adminapi.ListPoliciesRequestObject{WorkspaceId: id})
		if e != nil {
			writeJSONError(w, 500, "INTERNAL", e.Error())
			return
		}
		a.userJSON(w, 200, v)
		return
	}
	if len(tail) == 0 && r.Method == http.MethodPut {
		if role == store.WorkspaceRoleMember {
			writeJSONError(w, 404, "NOT_FOUND", "workspace not found")
			return
		}
		var b adminapi.ReplacePoliciesJSONBody
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			writeJSONError(w, 400, "BAD_REQUEST", "invalid JSON")
			return
		}
		v, e := a.ReplacePolicies(r.Context(), adminapi.ReplacePoliciesRequestObject{WorkspaceId: id, Body: &b})
		if e != nil {
			writeJSONError(w, 500, "INTERNAL", e.Error())
			return
		}
		a.userJSON(w, 200, v)
		return
	}
	http.NotFound(w, r)
}
