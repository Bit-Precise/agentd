package control

import (
	"context"
	"net/http"
	"strings"

	"agentd/internal/store"
	"agentd/internal/userapi"
)

// userPrincipal is attached to requests after authentication and is consumed
// by the generated user-surface handlers. Keeping authentication outside the
// generated router lets the OpenAPI handler remain responsible for paths,
// methods, parameter binding, request decoding, and response status codes.
type userPrincipal struct {
	subject       string
	instanceAdmin bool
}

type userPrincipalKey struct{}

func withUserPrincipal(ctx context.Context, p userPrincipal) context.Context {
	return context.WithValue(ctx, userPrincipalKey{}, p)
}

func currentUserPrincipal(ctx context.Context) (userPrincipal, bool) {
	p, ok := ctx.Value(userPrincipalKey{}).(userPrincipal)
	return p, ok
}

// userHandler mounts the generated user OpenAPI surface. Authentication is a
// middleware around that surface; the route table itself comes only from
// docs/agentserver-user-openapi.yaml via oapi-codegen.
func (a *Admin) userHandler(adminToken string, oidc *OIDCAuth) http.Handler {
	api := userapi.HandlerWithOptions(
		userapi.NewStrictHandlerWithOptions(a, nil, userapi.StrictHTTPServerOptions{
			RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			},
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeJSONError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			},
		}),
		userapi.StdHTTPServerOptions{
			BaseURL: "/api/v1",
			ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
				writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			},
		},
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") || strings.HasPrefix(r.URL.Path, "/api/v1/join/") {
			http.NotFound(w, r)
			return
		}
		p, ok := a.authenticateUser(r, adminToken, oidc)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "user bearer required")
			return
		}
		if p.instanceAdmin {
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "use the instance admin API for the bootstrap administrator")
			return
		}
		r = r.WithContext(withUserPrincipal(r.Context(), p))
		api.ServeHTTP(w, r)
	})
}

func (a *Admin) authenticateUser(r *http.Request, adminToken string, oidc *OIDCAuth) (userPrincipal, bool) {
	if oidc != nil {
		if session, ok := oidc.Session(r); ok {
			return userPrincipal{subject: session.UserSubject, instanceAdmin: session.InstanceAdmin}, true
		}
		// When OIDC is configured, a raw bearer is not a validated user
		// principal. Browser requests must use the OIDC session above.
		return userPrincipal{}, false
	}
	bearer := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if bearer == "" {
		return userPrincipal{}, false
	}
	if adminToken != "" && bearer == adminToken {
		return userPrincipal{instanceAdmin: true}, true
	}
	return userPrincipal{subject: bearer}, true
}

func userRole(ctx context.Context, a *Admin, workspace string) (store.WorkspaceRole, bool) {
	p, ok := currentUserPrincipal(ctx)
	if !ok || p.subject == "" {
		return "", false
	}
	role := a.userRole(ctx, workspace, p.subject)
	return role, role != ""
}

func (a *Admin) userRole(ctx context.Context, workspace, bearer string) store.WorkspaceRole {
	if m, err := a.C.st.GetWorkspaceMember(ctx, workspace, bearer); err == nil {
		return m.Role
	}
	if users, err := a.C.st.ListUsers(ctx); err == nil {
		for _, u := range users {
			if u.ID == bearer || u.Email == bearer || u.Subject == bearer {
				if m, err := a.C.st.GetWorkspaceMember(ctx, workspace, u.Subject); err == nil {
					return m.Role
				}
			}
		}
	}
	return ""
}
