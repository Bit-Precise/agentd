package control

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	clientconfig "github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/edge"
)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func apiError(w http.ResponseWriter, status int, kind, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"kind": kind, "message": message}})
}
func respond(w http.ResponseWriter, value any, err error, status int) {
	if err == nil {
		writeJSON(w, status, value)
		return
	}
	var e *types.Error
	if errors.As(err, &e) {
		codes := map[types.ErrorKind]int{types.KindInvalid: 400, types.KindUnauthorized: 401, types.KindForbidden: 403, types.KindNotFound: 404, types.KindConflict: 409, types.KindExpired: 401, types.KindUnavailable: 503}
		code := codes[e.Kind]
		if code == 0 {
			code = 500
		}
		apiError(w, code, string(e.Kind), e.Message)
		return
	}
	apiError(w, 500, "internal", "request could not be completed")
}
func decode(w http.ResponseWriter, r *http.Request, target any) (complete bool) {
	// Only bounded control JSON bodies have this read timeout. A server-wide
	// ReadTimeout would terminate legitimate XHTTP downloads and service streams.
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() {
		// Leave the bound in place if net/http must drain an unread/invalid body.
		if complete {
			_ = controller.SetReadDeadline(time.Time{})
		}
	}()
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		apiError(w, 415, "invalid", "application/json required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		apiError(w, 400, "invalid", "invalid request JSON")
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		apiError(w, 400, "invalid", "one JSON document required")
		return false
	}
	return true
}
func (a *App) manage(fn func(http.ResponseWriter, *http.Request, types.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && !a.validOrigin(o) {
			apiError(w, 403, "forbidden", "origin rejected")
			return
		}
		user, _, err := a.actor(r, r.Method != "GET" && r.Method != "HEAD")
		if err != nil {
			apiError(w, 401, "unauthorized", "authentication or CSRF required")
			return
		}
		fn(w, r, user)
	}
}

func (a *App) routes() {
	m := a.router
	m.HandleFunc("POST /api/v1/login", a.login)
	m.HandleFunc("POST /api/v1/logout", a.logout)
	m.HandleFunc("GET /auth/authorize", a.authorizeService)
	m.HandleFunc("GET /api/v1/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"serverURL": a.Config.ServerURL, "edgeURL": a.Config.EdgeURL, "developmentHTTP": a.Config.DevelopmentHTTP})
	})
	m.HandleFunc("GET /api/v1/me", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		_, s, _ := a.actor(r, false)
		writeJSON(w, 200, map[string]any{"user": u, "csrfToken": s.CSRF})
	}))
	m.HandleFunc("GET /api/v1/state", a.manage(a.snapshot))
	m.HandleFunc("POST /api/v1/enroll", a.enroll)
	m.HandleFunc("GET /api/v1/agent/credentials", a.agentCredentials)
	m.HandleFunc("POST /api/v1/agent/config", a.agentConfig)
	m.HandleFunc("POST /api/v1/users", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		var b struct {
			Name  string `json:"name"`
			Admin bool   `json:"admin"`
		}
		if !decode(w, r, &b) {
			return
		}
		user, token, err := a.State.CreateUser(u.ID, b.Name, b.Admin)
		respond(w, map[string]any{"user": user, "token": token}, err, 201)
	}))
	m.HandleFunc("DELETE /api/v1/users/{id}", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		err := a.State.DisableUser(u.ID, r.PathValue("id"))
		respond(w, map[string]bool{"ok": true}, err, 200)
	}))
	m.HandleFunc("POST /api/v1/users/{id}/token", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		token, err := a.State.RotateUserToken(u.ID, r.PathValue("id"))
		respond(w, map[string]string{"token": token}, err, 201)
	}))
	m.HandleFunc("POST /api/v1/workspaces", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		var b struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &b) {
			return
		}
		v, err := a.State.CreateWorkspace(u.ID, b.Name)
		respond(w, v, err, 201)
	}))
	m.HandleFunc("POST /api/v1/memberships", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		var b types.Membership
		if !decode(w, r, &b) {
			return
		}
		v, err := a.State.SetMembership(u.ID, b.WorkspaceID, b.UserID, b.Role)
		respond(w, v, err, 201)
	}))
	m.HandleFunc("DELETE /api/v1/memberships/{workspace}/{user}", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		err := a.State.RemoveMembership(u.ID, r.PathValue("workspace"), r.PathValue("user"))
		respond(w, map[string]bool{"ok": true}, err, 200)
	}))
	m.HandleFunc("POST /api/v1/enrollment-keys", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		var b types.EnrollmentKey
		if !decode(w, r, &b) {
			return
		}
		key, token, err := a.State.CreateEnrollmentKey(u.ID, b)
		respond(w, map[string]any{"key": key, "token": token}, err, 201)
	}))
	m.HandleFunc("DELETE /api/v1/enrollment-keys/{id}", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		err := a.State.RevokeEnrollmentKey(u.ID, r.PathValue("id"))
		respond(w, map[string]bool{"ok": true}, err, 200)
	}))
	m.HandleFunc("POST /api/v1/agents/{id}/approve", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		v, err := a.State.ApproveAgent(u.ID, r.PathValue("id"))
		respond(w, v, err, 200)
	}))
	m.HandleFunc("POST /api/v1/agents/{id}/revoke", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		err := a.State.RevokeAgent(u.ID, r.PathValue("id"))
		respond(w, map[string]bool{"ok": true}, err, 200)
	}))
	m.HandleFunc("POST /api/v1/egress-routes", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		var b types.EgressRoute
		if !decode(w, r, &b) {
			return
		}
		v, err := a.State.CreateEgressRoute(u.ID, b)
		respond(w, v, err, 201)
	}))
	m.HandleFunc("DELETE /api/v1/egress-routes/{id}", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		v, err := a.State.SetEgressRouteEnabled(u.ID, r.PathValue("id"), false)
		respond(w, v, err, 200)
	}))
	m.HandleFunc("POST /api/v1/egress-routes/{id}/enable", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		v, err := a.State.SetEgressRouteEnabled(u.ID, r.PathValue("id"), true)
		respond(w, v, err, 200)
	}))
	m.HandleFunc("DELETE /api/v1/services/{id}", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		v, err := a.State.SetServiceEnabled(u.ID, r.PathValue("id"), false)
		respond(w, v, err, 200)
	}))
	m.HandleFunc("POST /api/v1/services/{id}/enable", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		v, err := a.State.SetServiceEnabled(u.ID, r.PathValue("id"), true)
		respond(w, v, err, 200)
	}))
	m.HandleFunc("POST /api/v1/grants", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		var b types.Grant
		if !decode(w, r, &b) {
			return
		}
		v, err := a.State.CreateGrant(u.ID, b)
		respond(w, v, err, 201)
	}))
	m.HandleFunc("DELETE /api/v1/grants/{id}", a.manage(func(w http.ResponseWriter, r *http.Request, u types.User) {
		err := a.State.RevokeGrant(u.ID, r.PathValue("id"))
		respond(w, map[string]bool{"ok": true}, err, 200)
	}))
}

func (a *App) enroll(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && !a.validOrigin(o) {
		apiError(w, 403, "forbidden", "origin rejected")
		return
	}
	var b types.EnrollRequest
	if !decode(w, r, &b) {
		return
	}
	if strings.TrimSuffix(b.Config.Instance, "/") != strings.TrimSuffix(a.Config.ServerURL, "/") || b.Config.Transport.Endpoint != a.Config.EdgeURL {
		apiError(w, 400, "invalid", "agent instance and edge endpoint must match this server")
		return
	}
	v, err := a.State.Enroll(b)
	v.Credentials.ControlURL = strings.TrimSuffix(a.Config.ServerURL, "/")
	respond(w, v, err, 201)
}
func controlToken(r *http.Request) string {
	token, _ := bearerToken(r)
	return token
}
func (a *App) agentCredentials(w http.ResponseWriter, r *http.Request) {
	v, err := a.State.GetAgentCredentials(controlToken(r))
	v.ControlURL = strings.TrimSuffix(a.Config.ServerURL, "/")
	respond(w, v, err, 200)
}
func (a *App) agentConfig(w http.ResponseWriter, r *http.Request) {
	var c clientconfig.Config
	if !decode(w, r, &c) {
		return
	}
	if strings.TrimSuffix(c.Instance, "/") != strings.TrimSuffix(a.Config.ServerURL, "/") || c.Transport.Endpoint != a.Config.EdgeURL {
		apiError(w, 400, "invalid", "agent instance and edge endpoint must match this server")
		return
	}
	v, err := a.State.UpdateAgent(controlToken(r), c)
	respond(w, v, err, 200)
}
func (a *App) snapshot(w http.ResponseWriter, r *http.Request, u types.User) {
	snapshot, err := a.State.SnapshotForUser(u.ID)
	if err != nil {
		respond(w, nil, err, 200)
		return
	}
	// Edge's public snapshot is narrowed again to the caller's visible agents.
	view := a.Edge.Snapshot()
	if !u.Admin {
		managed := map[string]bool{}
		own := map[string]bool{}
		for _, m := range snapshot.Memberships {
			if m.UserID == u.ID && (m.Role == "owner" || m.Role == "maintainer") {
				managed[m.WorkspaceID] = true
			}
		}
		for _, agent := range snapshot.Agents {
			if agent.UserID == u.ID {
				own[agent.ID] = true
			}
		}
		view.Connections = slices.DeleteFunc(view.Connections, func(c edge.ConnectionStatus) bool { return !managed[c.WorkspaceID] && !own[c.AgentID] })
		view.Flows = slices.DeleteFunc(view.Flows, func(f edge.FlowStatus) bool { return !managed[f.WorkspaceID] && f.UserID != u.ID })
	}
	writeJSON(w, 200, struct {
		types.Snapshot
		User        types.User `json:"user"`
		ServerURL   string     `json:"serverURL"`
		Connections any        `json:"connections"`
		Flows       any        `json:"flows"`
	}{Snapshot: snapshot, User: u, ServerURL: a.Config.ServerURL, Connections: view.Connections, Flows: view.Flows})
}
