package control

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"agentd/internal/adminapi"
	"agentd/internal/identity"
	"agentd/internal/routes"
	"agentd/internal/store"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// Version is the agentserver build version (set with -ldflags).
var Version = "dev"

// Admin implements the generated admin API on top of the Coordinator.
type Admin struct {
	C      *Coordinator
	Domain string // agentserver domain: default parent of workspace base domains
}

var _ adminapi.StrictServerInterface = (*Admin)(nil)

// Handler returns the admin API under /api/v1 with bearer-token auth, and
// the web console (ui, optional) at the root.
func (a *Admin) Handler(token string, ui http.Handler) http.Handler {
	api := adminapi.HandlerWithOptions(adminapi.NewStrictHandlerWithOptions(a, nil, adminapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		},
	}), adminapi.StdHTTPServerOptions{BaseURL: "/api/v1", ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
	}})
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.Handle("/api/v1/", requireToken(token, api))
	mux.HandleFunc("/api/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		sw, err := adminapi.GetSwagger()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sw)
	})
	if ui != nil {
		mux.Handle("/", ui)
	}
	return mux
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func requireToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"missing or wrong admin token"}}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func apiErr(code, msg string) adminapi.Error {
	var e adminapi.Error
	e.Error.Code, e.Error.Message = code, msg
	return e
}

func badRequest(msg string) adminapi.BadRequestJSONResponse {
	return adminapi.BadRequestJSONResponse(apiErr("BAD_REQUEST", msg))
}

func notFoundErr(what string) adminapi.NotFoundJSONResponse {
	return adminapi.NotFoundJSONResponse(apiErr("NOT_FOUND", what+" not found"))
}

// classify maps store errors to (status, code).
func classify(err error) (int, string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return 404, "NOT_FOUND"
	case errors.Is(err, store.ErrConflict):
		return 409, "CONFLICT"
	}
	var we *wire.Error
	if errors.As(err, &we) {
		switch we.Status {
		case pb.Status_NAME_TAKEN, pb.Status_IDENTITY_IN_USE:
			return 409, we.Status.String()
		case pb.Status_BAD_NAME:
			return 400, we.Status.String()
		}
		return 400, we.Status.String()
	}
	return 500, "INTERNAL"
}

func randomToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func ptr[T any](v T) *T { return &v }

func parseTTL(s *string, def time.Duration) (time.Duration, error) {
	if s == nil || *s == "" {
		return def, nil
	}
	return time.ParseDuration(*s)
}

// ---------------------------------------------------------------- server

func (a *Admin) GetServer(ctx context.Context, _ adminapi.GetServerRequestObject) (adminapi.GetServerResponseObject, error) {
	info := adminapi.ServerInfo{PublicKey: identity.EncodeKey(a.C.PublicKey()), Version: Version, Domain: ptr(a.Domain)}
	info.Protocol.Major, info.Protocol.Min, info.Protocol.Max = ptr(1), ptr(wire.MinorVersion), ptr(wire.MinorVersion)
	return adminapi.GetServer200JSONResponse(info), nil
}

func (a *Admin) GetStatus(ctx context.Context, _ adminapi.GetStatusRequestObject) (adminapi.GetStatusResponseObject, error) {
	relays, online, up := a.C.Stats()
	st := adminapi.Status{RelaysConnected: ptr(relays), NodesOnline: ptr(online), UptimeSeconds: ptr(int(up.Seconds()))}
	wss, err := a.C.st.ListWorkspaces(ctx)
	if err != nil {
		return nil, err
	}
	rs, _ := a.C.st.ListRelays(ctx)
	total, pending := 0, 0
	for _, ws := range wss {
		ns, _ := a.C.st.ListNodes(ctx, ws.Name)
		total += len(ns)
		if c, err := a.C.st.GetCert(ctx, ws.Name); err != nil || c.State != "ready" {
			pending++
		}
	}
	st.Workspaces, st.RelaysRegistered, st.NodesTotal, st.CertsPending = ptr(len(wss)), ptr(len(rs)), ptr(total), ptr(pending)
	return adminapi.GetStatus200JSONResponse(st), nil
}

// ---------------------------------------------------------------- workspaces

func (a *Admin) apiCert(ctx context.Context, ws store.Workspace) adminapi.Cert {
	out := adminapi.Cert{Workspace: ws.Name, Domain: "*." + ws.BaseDomain, State: adminapi.CertState("pending")}
	if c, err := a.C.st.GetCert(ctx, ws.Name); err == nil {
		out.State = adminapi.CertState(c.State)
		out.NotBefore, out.NotAfter = c.NotBefore, c.NotAfter
		if c.Issuer != "" {
			out.Issuer = ptr(c.Issuer)
		}
		if c.LastError != "" {
			out.LastError = ptr(c.LastError)
		}
		if c.State == "ready" {
			if ok, _ := a.C.RelayConnected(ws.Relay); ok {
				out.Relays = &[]string{ws.Relay}
			}
		}
	}
	return out
}

func (a *Admin) apiWorkspace(ctx context.Context, ws store.Workspace) adminapi.Workspace {
	nodes, _ := a.C.st.ListNodes(ctx, ws.Name)
	cert := a.apiCert(ctx, ws)
	return adminapi.Workspace{
		Name: ws.Name, BaseDomain: ws.BaseDomain, PublicKey: identity.EncodeKey(ws.PublicKey), Uri: ptr("agentd://" + ws.BaseDomain + "/"),
		Relay: ws.Relay, DnsProvider: ptr(ws.DNSProvider), PublishDns: ptr(ws.PublishDNS), Cert: &cert,
		Members: ptr(len(nodes)), MembersOnline: ptr(a.C.OnlineCount(ws.Name)),
		RoutesVersion: ptr(int(ws.RoutesVersion)), DirectoryVersion: ptr(int(ws.DirectoryVersion)), CreatedAt: ws.CreatedAt,
	}
}

func (a *Admin) ListWorkspaces(ctx context.Context, _ adminapi.ListWorkspacesRequestObject) (adminapi.ListWorkspacesResponseObject, error) {
	wss, err := a.C.st.ListWorkspaces(ctx)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListWorkspaces200JSONResponse{}
	for _, ws := range wss {
		out = append(out, a.apiWorkspace(ctx, ws))
	}
	return out, nil
}

func (a *Admin) CreateWorkspace(ctx context.Context, req adminapi.CreateWorkspaceRequestObject) (adminapi.CreateWorkspaceResponseObject, error) {
	b := req.Body
	if b == nil || !identity.ValidLabel(b.Name) {
		return adminapi.CreateWorkspace400JSONResponse{BadRequestJSONResponse: badRequest("workspace name must be an RFC 1123 label")}, nil
	}
	base := b.Name + "." + a.Domain
	if b.BaseDomain != nil && *b.BaseDomain != "" {
		base = strings.ToLower(strings.TrimSuffix(*b.BaseDomain, "."))
	}
	if !identity.ValidDomain(base) {
		return adminapi.CreateWorkspace400JSONResponse{BadRequestJSONResponse: badRequest("invalid base domain " + base)}, nil
	}
	provider := ""
	if b.DnsProvider != nil {
		provider = *b.DnsProvider
	}
	if a.C.certs != nil && !a.C.certs.HasIssuer(provider) {
		return adminapi.CreateWorkspace400JSONResponse{BadRequestJSONResponse: badRequest("unknown dns provider " + provider)}, nil
	}
	if _, err := a.C.st.GetRelay(ctx, b.Relay); err != nil {
		return adminapi.CreateWorkspace400JSONResponse{BadRequestJSONResponse: badRequest("unknown relay " + b.Relay)}, nil
	}
	key, err := identity.GenerateKey()
	if err != nil {
		return nil, err
	}
	ws := store.Workspace{Name: b.Name, BaseDomain: base, PrivateKey: key, Relay: b.Relay, DNSProvider: provider, PublishDNS: b.PublishDns != nil && *b.PublishDns}
	if err := a.C.st.CreateWorkspace(ctx, ws); err != nil {
		if code, c := classify(err); code == 409 {
			return adminapi.CreateWorkspace409JSONResponse(apiErr(c, err.Error())), nil
		}
		return nil, err
	}
	ws, err = a.C.st.GetWorkspace(ctx, b.Name)
	if err != nil {
		return nil, err
	}
	if a.C.certs != nil {
		a.C.certs.Ensure(context.Background(), ws, true)
	}
	a.C.pushRelayState(ctx, ws.Relay)
	return adminapi.CreateWorkspace201JSONResponse(a.apiWorkspace(ctx, ws)), nil
}

func (a *Admin) GetWorkspace(ctx context.Context, req adminapi.GetWorkspaceRequestObject) (adminapi.GetWorkspaceResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.GetWorkspace404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	if err != nil {
		return nil, err
	}
	return adminapi.GetWorkspace200JSONResponse(a.apiWorkspace(ctx, ws)), nil
}

func (a *Admin) memberKeys(ctx context.Context, ws string) [][]byte {
	nodes, _ := a.C.st.ListNodes(ctx, ws)
	var keys [][]byte
	for _, n := range nodes {
		keys = append(keys, n.PublicKey)
	}
	return keys
}

func (a *Admin) UpdateWorkspace(ctx context.Context, req adminapi.UpdateWorkspaceRequestObject) (adminapi.UpdateWorkspaceResponseObject, error) {
	old, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.UpdateWorkspace404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return adminapi.UpdateWorkspace400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	if b.DnsProvider != nil && a.C.certs != nil && !a.C.certs.HasIssuer(*b.DnsProvider) {
		return adminapi.UpdateWorkspace400JSONResponse{BadRequestJSONResponse: badRequest("unknown dns provider " + *b.DnsProvider)}, nil
	}
	if err := a.C.st.UpdateWorkspace(ctx, req.Ws, b.Relay, b.PublishDns, b.DnsProvider); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.UpdateWorkspace400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
		}
		return nil, err
	}
	ws, _ := a.C.st.GetWorkspace(ctx, req.Ws)
	if b.Relay != nil && *b.Relay != old.Relay {
		a.C.pushRelayState(ctx, ws.Relay)
		a.C.invalidate(old, a.memberKeys(ctx, ws.Name)...) // old relay closes the members' sessions
	}
	if b.DnsProvider != nil && a.C.certs != nil {
		a.C.certs.Ensure(context.Background(), ws, true)
	}
	a.C.Changed(ctx, ws.Name)
	return adminapi.UpdateWorkspace200JSONResponse(a.apiWorkspace(ctx, ws)), nil
}

func (a *Admin) DeleteWorkspace(ctx context.Context, req adminapi.DeleteWorkspaceRequestObject) (adminapi.DeleteWorkspaceResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.DeleteWorkspace404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	if err != nil {
		return nil, err
	}
	keys := a.memberKeys(ctx, ws.Name)
	if len(keys) > 0 && (req.Params.Force == nil || !*req.Params.Force) {
		return adminapi.DeleteWorkspace409JSONResponse(apiErr("WORKSPACE_NOT_EMPTY", "workspace still has members; pass force=true")), nil
	}
	for _, k := range keys {
		a.C.notify(ws, k, &pb.Notice{Kind: pb.Notice_REMOVED, Message: "workspace deleted"})
	}
	a.C.invalidate(ws, keys...)
	if err := a.C.st.DeleteWorkspace(ctx, ws.Name); err != nil {
		return nil, err
	}
	return adminapi.DeleteWorkspace204Response{}, nil
}

// ---------------------------------------------------------------- join tokens

func roleNames(rs []adminapi.Role) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, string(r))
	}
	return out
}

func apiRoles(names []string) []adminapi.Role {
	if len(names) == 0 {
		names = AllRoles
	}
	out := []adminapi.Role{}
	for _, n := range names {
		out = append(out, adminapi.Role(n))
	}
	return out
}

func (a *Admin) ListTokens(ctx context.Context, req adminapi.ListTokensRequestObject) (adminapi.ListTokensResponseObject, error) {
	ts, err := a.C.st.ListJoinTokens(ctx, req.Ws)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListTokens200JSONResponse{}
	for _, t := range ts {
		tok := adminapi.Token{Id: t.ID, Roles: apiRoles(t.Roles), ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt}
		if t.Name != "" {
			tok.Name = ptr(t.Name)
		}
		out = append(out, tok)
	}
	return out, nil
}

func (a *Admin) CreateToken(ctx context.Context, req adminapi.CreateTokenRequestObject) (adminapi.CreateTokenResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.CreateToken400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace " + req.Ws)}, nil
	}
	relay, err := a.C.st.GetRelay(ctx, ws.Relay)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		b = &adminapi.TokenCreate{}
	}
	name := ""
	if b.Name != nil {
		name = *b.Name
		if !identity.ValidLabel(name) || store.ReservedNames[name] {
			return adminapi.CreateToken400JSONResponse{BadRequestJSONResponse: badRequest("invalid instance name " + name)}, nil
		}
	}
	var roles []string
	if b.Roles != nil {
		roles = roleNames(*b.Roles)
		for _, r := range roles {
			if _, ok := roleByName[r]; !ok {
				return adminapi.CreateToken400JSONResponse{BadRequestJSONResponse: badRequest("unknown role " + r)}, nil
			}
		}
	}
	ttl, err := parseTTL(b.Ttl, 24*time.Hour)
	if err != nil || ttl <= 0 {
		return adminapi.CreateToken400JSONResponse{BadRequestJSONResponse: badRequest("invalid ttl")}, nil
	}
	token := randomToken()
	t := store.JoinToken{ID: wire.RandomID(), Workspace: ws.Name, Hash: store.HashToken(token), Name: name, Roles: roles, ExpiresAt: time.Now().Add(ttl)}
	if err := a.C.st.CreateJoinToken(ctx, t); err != nil {
		if code, c := classify(err); code == 409 {
			return adminapi.CreateToken409JSONResponse(apiErr(c, err.Error())), nil
		}
		return nil, err
	}
	link := identity.JoinLink{Workspace: ws.BaseDomain, Name: name, RelayURL: relay.URL, Key: ws.PublicKey, Token: token}
	out := adminapi.CreateToken201JSONResponse{Id: t.ID, Roles: apiRoles(roles), ExpiresAt: t.ExpiresAt, CreatedAt: time.Now(), JoinLink: link.String()}
	if name != "" {
		out.Name = ptr(name)
	}
	return out, nil
}

func (a *Admin) RevokeToken(ctx context.Context, req adminapi.RevokeTokenRequestObject) (adminapi.RevokeTokenResponseObject, error) {
	if err := a.C.st.DeleteJoinToken(ctx, req.Ws, req.TokenId); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.RevokeToken404JSONResponse{NotFoundJSONResponse: notFoundErr("token")}, nil
		}
		return nil, err
	}
	return adminapi.RevokeToken204Response{}, nil
}

var _ = json.Marshal
var _ = routes.Direct
