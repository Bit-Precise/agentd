package control

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"agentd/internal/adminapi"
	"agentd/internal/identity"
	"agentd/internal/store"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// Version is the agentserver build version (set with -ldflags).
var Version = "dev"

// Admin implements the instance-admin API generated from the current OpenAPI
// document.  The store still uses the protocol's human-readable names for its
// internal joins; API resources expose stable UUIDs through idFor/resolve*.
type Admin struct {
	C      *Coordinator
	Config *ServerConfig
	Domain string
	OIDC   *OIDCAuth
}

var _ adminapi.StrictServerInterface = (*Admin)(nil)

func idFor(kind, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("agentd/"+kind+"/"+key)).String()
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
func conflictErr(code, msg string) adminapi.ConflictJSONResponse {
	return adminapi.ConflictJSONResponse(apiErr(code, msg))
}

func classify(err error) (int, string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "NOT_FOUND"
	case errors.Is(err, store.ErrConflict):
		return http.StatusConflict, "CONFLICT"
	}
	var we *wire.Error
	if errors.As(err, &we) {
		switch we.Status {
		case pb.Status_NAME_TAKEN, pb.Status_IDENTITY_IN_USE:
			return http.StatusConflict, we.Status.String()
		case pb.Status_BAD_NAME:
			return http.StatusBadRequest, we.Status.String()
		}
		return http.StatusBadRequest, we.Status.String()
	}
	return http.StatusInternalServerError, "INTERNAL"
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

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func requireToken(token string, oidc *OIDCAuth, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		allowed := oidc == nil || !oidc.Enabled()
		allowed = allowed && token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
		if !allowed && oidc != nil {
			if s, ok := oidc.Session(r); ok && s.InstanceAdmin {
				allowed = true
			}
		}
		if !allowed {
			writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or wrong admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Handler mounts the generated admin surface, the machine join discovery
// endpoint, and the user surface.  The user surface is intentionally mounted
// separately so an admin operation can never be reached with a user bearer.
func (a *Admin) Handler(token string, ui http.Handler) http.Handler {
	api := adminapi.HandlerWithOptions(adminapi.NewStrictHandlerWithOptions(a, nil, adminapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		},
	}), adminapi.StdHTTPServerOptions{BaseURL: "/api/v1/admin", ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
	}})
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.Handle("/api/v1/admin/", a.auditWrites(requireToken(token, a.OIDC, api)))
	// Compatibility aggregate used by older clients; it is not in the current
	// OpenAPI document and is read-only.
	mux.Handle("/api/v1/admin/instance", requireToken(token, a.OIDC, http.HandlerFunc(a.compatInstance)))
	mux.Handle("/api/v1/admin/audit/events", requireToken(token, a.OIDC, http.HandlerFunc(a.auditEventsHTTP)))
	mux.Handle("/api/v1/admin/audit/events/", requireToken(token, a.OIDC, http.HandlerFunc(a.auditEventHTTP)))
	mux.HandleFunc("/api/v1/join/candidates", a.joinCandidates)
	mux.Handle("/api/v1/", a.auditUserWrites(a.userHandler(token, a.OIDC)))
	if a.OIDC != nil {
		mux.HandleFunc("/auth/login", a.oidcLogin)
		mux.HandleFunc("/auth/callback", a.oidcCallback)
		mux.HandleFunc("/auth/logout", a.oidcLogout)
		mux.HandleFunc("/auth/me", a.oidcMe)
	}
	mux.HandleFunc("/auth/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"oidc_enabled": a.OIDC != nil && a.OIDC.Enabled()})
	})
	mux.HandleFunc("/api/admin/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		sw, err := adminapi.GetSwagger()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sw)
	})
	if ui != nil {
		mux.Handle("/", ui)
	}
	return mux
}

// compatInstance preserves the old aggregate read endpoint for the checked-in
// simulation.  New clients use /domains, /dns-providers, and so on.
func (a *Admin) compatInstance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	d, dns, issuers, auth := a.instanceCollections(r.Context())
	_ = json.NewEncoder(w).Encode(adminapi.Instance{Domains: d, DnsProviders: dns, CertificateIssuers: issuers, AuthProviders: auth, Rbac: &adminapi.InstanceRBAC{
		Audiences:      []adminapi.Audience{adminapi.AudienceWebUser, adminapi.AudienceAgentd, adminapi.AudienceRelay},
		InstanceRoles:  []adminapi.InstanceRole{adminapi.InstanceRole("instance_admin")},
		WorkspaceRoles: []adminapi.WorkspaceRole{adminapi.WorkspaceRole("owner"), adminapi.WorkspaceRole("maintainer"), adminapi.WorkspaceRole("member")},
	}})
}

func (a *Admin) joinCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tok == "" {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "join token required")
		return
	}
	t, err := a.C.st.ProbeJoinToken(r.Context(), store.HashToken(tok))
	if err != nil {
		st := wire.StatusOf(err)
		status := http.StatusGone
		if st == pb.Status_TOKEN_INVALID {
			status = http.StatusUnauthorized
		}
		writeJSONError(w, status, st.String(), err.Error())
		return
	}
	ws, err := a.C.st.GetWorkspace(r.Context(), t.Workspace)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "workspace not found")
		return
	}
	relays, err := a.C.st.ListRelays(r.Context())
	if err != nil || len(relays) == 0 {
		writeJSONError(w, http.StatusServiceUnavailable, "NO_RELAY", "no relay candidates available")
		return
	}
	type candidate struct {
		RelayID    string `json:"relay_id"`
		URL        string `json:"url"`
		Status     string `json:"status"`
		Connected  bool   `json:"connected"`
		Preference int    `json:"preference"`
	}
	out := make([]candidate, 0, len(relays))
	for i, relay := range relays {
		connected, _ := a.C.RelayConnected(relay.Name)
		out = append(out, candidate{RelayID: idFor("relay", relay.Name), URL: relay.URL, Status: "active", Connected: connected, Preference: i})
	}
	resp := map[string]any{
		"workspace_id": idFor("workspace", ws.Name), "workspace_domain": ws.BaseDomain,
		"workspace_public_key": identity.EncodeKey(ws.PublicKey), "candidates": out, "expires_at": t.ExpiresAt,
		"roles": apiRoles(t.Roles),
	}
	if t.Name != "" {
		resp["name"] = t.Name
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Admin) auditEventView(e store.AuditEvent) adminapi.AuditEvent {
	actorKind := adminapi.AuditActorKind(e.ActorKind)
	if !actorKind.Valid() {
		actorKind = adminapi.AuditActorKindSystem
	}
	actor := adminapi.AuditActor{Kind: actorKind, Id: e.ActorID}
	var rid, wid *string
	if e.ResourceID != "" {
		rid = &e.ResourceID
	}
	if e.WorkspaceID != "" {
		wid = &e.WorkspaceID
	}
	out := adminapi.AuditEvent{Id: e.ID, OccurredAt: e.OccurredAt, Actor: actor, Action: e.Action, ResourceType: e.ResourceType, RequestId: e.RequestID, Outcome: adminapi.AuditOutcome(e.Outcome), ResourceId: rid, WorkspaceId: wid}
	if e.ErrorCode != "" {
		out.ErrorCode = &e.ErrorCode
	}
	if e.Metadata != nil {
		out.Metadata = &e.Metadata
	}
	return out
}

func (a *Admin) ListAuditEvents(ctx context.Context, req adminapi.ListAuditEventsRequestObject) (adminapi.ListAuditEventsResponseObject, error) {
	f := store.AuditFilter{}
	p := req.Params
	if p.ActorId != nil {
		f.ActorID = *p.ActorId
	}
	if p.ResourceType != nil {
		f.ResourceType = *p.ResourceType
	}
	if p.ResourceId != nil {
		f.ResourceID = *p.ResourceId
	}
	if p.WorkspaceId != nil {
		f.WorkspaceID = *p.WorkspaceId
	}
	if p.Action != nil {
		f.Action = *p.Action
	}
	if p.Outcome != nil {
		f.Outcome = string(*p.Outcome)
	}
	if p.Limit != nil {
		f.Limit = *p.Limit
	}
	events, err := a.C.st.ListAuditEvents(ctx, f)
	if err != nil {
		return nil, err
	}
	page := adminapi.AuditEventPage{Items: make([]adminapi.AuditEvent, 0, len(events))}
	for _, e := range events {
		page.Items = append(page.Items, a.auditEventView(e))
	}
	return adminapi.ListAuditEvents200JSONResponse(page), nil
}

func (a *Admin) GetAuditEvent(ctx context.Context, req adminapi.GetAuditEventRequestObject) (adminapi.GetAuditEventResponseObject, error) {
	e, err := a.C.st.GetAuditEvent(ctx, req.EventId)
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.GetAuditEvent404JSONResponse{NotFoundJSONResponse: notFoundErr("audit event")}, nil
	}
	if err != nil {
		return nil, err
	}
	return adminapi.GetAuditEvent200JSONResponse(a.auditEventView(e)), nil
}

func (a *Admin) auditEventsHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	f := store.AuditFilter{ActorID: q.Get("actor_id"), ResourceType: q.Get("resource_type"), ResourceID: q.Get("resource_id"), WorkspaceID: q.Get("workspace_id"), Action: q.Get("action"), Outcome: q.Get("outcome"), Limit: limit}
	events, err := a.C.st.ListAuditEvents(r.Context(), f)
	if err != nil {
		writeJSONError(w, 500, "INTERNAL", err.Error())
		return
	}
	items := make([]adminapi.AuditEvent, 0, len(events))
	for _, e := range events {
		items = append(items, a.auditEventView(e))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(adminapi.AuditEventPage{Items: items})
}
func (a *Admin) auditEventHTTP(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/audit/events/")
	e, err := a.C.st.GetAuditEvent(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSONError(w, 404, "NOT_FOUND", "audit event not found")
		return
	}
	if err != nil {
		writeJSONError(w, 500, "INTERNAL", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.auditEventView(e))
}

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(s int) { w.status = s; w.ResponseWriter.WriteHeader(s) }
func (w *auditResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (a *Admin) auditWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", requestID)
		aw := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(aw, r)
		status := aw.status
		if status == 0 {
			status = 200
		}
		resourceType := "admin"
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		for i, p := range parts {
			if p == "admin" && i+1 < len(parts) {
				resourceType = parts[i+1]
				break
			}
		}
		outcome := "success"
		if status >= 400 {
			outcome = "failure"
		}
		_ = a.C.st.RecordAudit(r.Context(), store.AuditEvent{ActorKind: "instance_admin", ActorID: "admin-token", Action: strings.ToLower(r.Method), ResourceType: resourceType, RequestID: requestID, Outcome: outcome, Metadata: map[string]any{"path": r.URL.Path, "status": status}})
	})
}

func (a *Admin) auditUserWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		aw := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(aw, r)
		status := aw.status
		if status == 0 {
			status = http.StatusOK
		}
		outcome := "success"
		if status >= 400 {
			outcome = "failure"
		}
		actor := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if actor == "" {
			actor = "unknown"
		}
		_ = a.C.st.RecordAudit(r.Context(), store.AuditEvent{ActorKind: "user", ActorID: actor, Action: strings.ToLower(r.Method), ResourceType: "workspace", RequestID: r.Header.Get("X-Request-ID"), Outcome: outcome, Metadata: map[string]any{"path": r.URL.Path, "status": status}})
	})
}

// ---------------------------------------------------------------- server and certificates

func (a *Admin) GetServer(ctx context.Context, _ adminapi.GetServerRequestObject) (adminapi.GetServerResponseObject, error) {
	domains, _, _, _ := a.instanceCollections(ctx)
	info := adminapi.ServerInfo{PublicKey: identity.EncodeKey(a.C.PublicKey()), Version: Version, Domain: ptr(a.Domain), Domains: &domains}
	info.Protocol.Major, info.Protocol.Min, info.Protocol.Max = ptr(1), ptr(wire.MinorVersion), ptr(wire.MinorVersion)
	return adminapi.GetServer200JSONResponse(info), nil
}
func (a *Admin) GetStatus(ctx context.Context, _ adminapi.GetStatusRequestObject) (adminapi.GetStatusResponseObject, error) {
	relays, online, up := a.C.Stats()
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
	return adminapi.GetStatus200JSONResponse(adminapi.Status{RelaysConnected: ptr(relays), NodesOnline: ptr(online), UptimeSeconds: ptr(int(up.Seconds())), Workspaces: ptr(len(wss)), RelaysRegistered: ptr(len(rs)), NodesTotal: ptr(total), CertsPending: ptr(pending)}), nil
}

func certificateWorkspaceID(id string) string {
	if strings.HasPrefix(id, "workspace:") {
		return strings.TrimPrefix(id, "workspace:")
	}
	return id
}

func (a *Admin) resolveCertificateWorkspace(ctx context.Context, id string) (store.Workspace, error) {
	if ws, err := a.resolveWorkspace(ctx, certificateWorkspaceID(id)); err == nil {
		return ws, nil
	}
	wss, err := a.C.st.ListWorkspaces(ctx)
	if err != nil {
		return store.Workspace{}, err
	}
	for _, ws := range wss {
		if idFor("certificate", "workspace/"+ws.Name) == id {
			return ws, nil
		}
	}
	return store.Workspace{}, store.ErrNotFound
}
func (a *Admin) certificateView(ctx context.Context, ws store.Workspace) adminapi.Certificate {
	c := store.Cert{State: "pending"}
	if got, err := a.C.st.GetCert(ctx, ws.Name); err == nil {
		c = got
	}
	state := adminapi.CertificateState(c.State)
	if state == "" {
		state = adminapi.CertificateStatePending
	}
	out := adminapi.Certificate{Id: idFor("certificate", "workspace/"+ws.Name), Kind: adminapi.CertificateKindWorkspaceWildcard, Issuer: idFor("issuer", c.Issuer), State: state, Subject: ptr("*." + ws.BaseDomain), WorkspaceId: ptr(idFor("workspace", ws.Name)), NotBefore: c.NotBefore, NotAfter: c.NotAfter, UpdatedAt: ptr(time.Now())}
	if c.Issuer == "" {
		out.Issuer = idFor("issuer", "selfsigned")
	}
	if c.LastError != "" {
		out.LastError = &c.LastError
	}
	return out
}
func (a *Admin) ListCertificates(ctx context.Context, req adminapi.ListCertificatesRequestObject) (adminapi.ListCertificatesResponseObject, error) {
	wss, err := a.C.st.ListWorkspaces(ctx)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListCertificates200JSONResponse{}
	for _, ws := range wss {
		if req.Params.Workspace != nil && *req.Params.Workspace != ws.Name {
			continue
		}
		c := a.certificateView(ctx, ws)
		if req.Params.Kind != nil && *req.Params.Kind != c.Kind {
			continue
		}
		if req.Params.State != nil && *req.Params.State != c.State {
			continue
		}
		out = append(out, c)
	}
	if relays, e := a.C.st.ListRelays(ctx); e == nil {
		for _, relay := range relays {
			for _, ws := range wss {
				if req.Params.Workspace != nil && *req.Params.Workspace != ws.Name {
					continue
				}
				cert, e := a.C.relayCert(ws, relay)
				if e != nil {
					continue
				}
				body, e := wire.DecodeRelayCert(cert)
				if e != nil {
					continue
				}
				c := adminapi.Certificate{Id: idFor("certificate", "relay/"+relay.Name+"/"+ws.Name), Kind: adminapi.CertificateKindRelay, Issuer: idFor("workspace", ws.Name), State: adminapi.CertificateStateReady, RelayId: ptr(idFor("relay", relay.Name)), WorkspaceId: ptr(idFor("workspace", ws.Name)), Subject: ptr(relay.Name), NotBefore: ptr(time.Unix(int64(body.IssuedAt), 0)), NotAfter: ptr(time.Unix(int64(body.ExpiresAt), 0))}
				if req.Params.Kind != nil && *req.Params.Kind != c.Kind {
					continue
				}
				if req.Params.State != nil && *req.Params.State != c.State {
					continue
				}
				out = append(out, c)
			}
		}
	}
	return out, nil
}
func (a *Admin) IssueCertificate(ctx context.Context, req adminapi.IssueCertificateRequestObject) (adminapi.IssueCertificateResponseObject, error) {
	if req.Body == nil || req.Body.Kind != adminapi.CertificateKindWorkspaceWildcard {
		return adminapi.IssueCertificate400JSONResponse{BadRequestJSONResponse: badRequest("only workspace_wildcard certificates are supported")}, nil
	}
	ws, err := a.resolveWorkspace(ctx, req.Body.WorkspaceId)
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.IssueCertificate404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	if err != nil {
		return nil, err
	}
	if c, err := a.C.st.GetCert(ctx, ws.Name); err == nil && c.State == "ready" {
		return adminapi.IssueCertificate409JSONResponse{ConflictJSONResponse: adminapi.ConflictJSONResponse(apiErr("CONFLICT", "certificate is already ready; use renew"))}, nil
	}
	if a.C.certs != nil {
		a.C.certs.Ensure(context.Background(), ws, true)
	}
	return adminapi.IssueCertificate202JSONResponse(a.certificateView(ctx, ws)), nil
}
func (a *Admin) GetCertificate(ctx context.Context, req adminapi.GetCertificateRequestObject) (adminapi.GetCertificateResponseObject, error) {
	ws, err := a.resolveCertificateWorkspace(ctx, req.CertificateId)
	if err != nil {
		return adminapi.GetCertificate404JSONResponse{NotFoundJSONResponse: notFoundErr("certificate")}, nil
	}
	return adminapi.GetCertificate200JSONResponse(a.certificateView(ctx, ws)), nil
}
func (a *Admin) RenewCertificate(ctx context.Context, req adminapi.RenewCertificateRequestObject) (adminapi.RenewCertificateResponseObject, error) {
	ws, err := a.resolveCertificateWorkspace(ctx, req.CertificateId)
	if err != nil {
		return adminapi.RenewCertificate404JSONResponse{NotFoundJSONResponse: notFoundErr("certificate")}, nil
	}
	if c, err := a.C.st.GetCert(ctx, ws.Name); err == nil && c.State == "revoked" {
		return adminapi.RenewCertificate409JSONResponse{ConflictJSONResponse: adminapi.ConflictJSONResponse(apiErr("CONFLICT", "revoked certificate needs a new issue operation"))}, nil
	}
	if a.C.certs != nil {
		a.C.certs.Ensure(context.Background(), ws, true)
	}
	return adminapi.RenewCertificate202JSONResponse(a.certificateView(ctx, ws)), nil
}
func (a *Admin) RevokeCertificate(ctx context.Context, req adminapi.RevokeCertificateRequestObject) (adminapi.RevokeCertificateResponseObject, error) {
	ws, err := a.resolveCertificateWorkspace(ctx, req.CertificateId)
	if err != nil {
		return adminapi.RevokeCertificate404JSONResponse{NotFoundJSONResponse: notFoundErr("certificate")}, nil
	}
	reason := "revoked by instance admin"
	if req.Body != nil && req.Body.Reason != nil && strings.TrimSpace(*req.Body.Reason) != "" {
		reason = strings.TrimSpace(*req.Body.Reason)
	}
	if err := a.C.st.RevokeCert(ctx, ws.Name, reason); err != nil {
		return adminapi.RevokeCertificate404JSONResponse{NotFoundJSONResponse: notFoundErr("certificate")}, nil
	}
	a.C.Changed(ctx, ws.Name)
	return adminapi.RevokeCertificate200JSONResponse(a.certificateView(ctx, ws)), nil
}

// ---------------------------------------------------------------- workspaces and tokens

func (a *Admin) resolveWorkspace(ctx context.Context, id string) (store.Workspace, error) {
	if ws, err := a.C.st.GetWorkspace(ctx, id); err == nil {
		return ws, nil
	}
	for _, ws := range mustWorkspaces(a.C.st.ListWorkspaces(ctx)) {
		if idFor("workspace", ws.Name) == id {
			return ws, nil
		}
	}
	return store.Workspace{}, store.ErrNotFound
}
func mustWorkspaces(w []store.Workspace, err error) []store.Workspace {
	if err != nil {
		return nil
	}
	return w
}
func (a *Admin) apiWorkspace(ctx context.Context, ws store.Workspace) adminapi.Workspace {
	nodes, _ := a.C.st.ListNodes(ctx, ws.Name)
	members, _ := a.C.st.ListWorkspaceMembers(ctx, ws.Name)
	base := ws.BaseDomain
	out := adminapi.Workspace{Id: idFor("workspace", ws.Name), Name: ws.Name, DomainId: idFor("domain", strings.TrimSuffix(strings.TrimPrefix(base, ws.Name+"."), ".")), BaseDomain: base, PublicKey: identity.EncodeKey(ws.PublicKey), Status: adminapi.WorkspaceStatus("active"), Members: ptr(len(members)), Nodes: ptr(len(nodes)), NodesOnline: ptr(a.C.OnlineCount(ws.Name)), RoutesVersion: ptr(int(ws.RoutesVersion)), DirectoryVersion: ptr(int(ws.DirectoryVersion)), CreatedAt: ws.CreatedAt}
	out.BaseDomain = ws.BaseDomain
	out.Relay = ws.Relay
	cert := a.compatCert(ctx, ws)
	out.Cert = &cert
	return out
}

func (a *Admin) compatCert(ctx context.Context, ws store.Workspace) adminapi.Cert {
	c := adminapi.Cert{Workspace: ws.Name, Domain: "*." + ws.BaseDomain, State: adminapi.CertStatePending}
	if v, err := a.C.st.GetCert(ctx, ws.Name); err == nil {
		c.State = adminapi.CertState(v.State)
		c.NotBefore, c.NotAfter = v.NotBefore, v.NotAfter
		if v.Issuer != "" {
			c.Issuer = &v.Issuer
		}
		if v.LastError != "" {
			c.LastError = &v.LastError
		}
	}
	return c
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
	if req.Body == nil || !identity.ValidLabel(req.Body.Name) {
		return adminapi.CreateWorkspace400JSONResponse{BadRequestJSONResponse: badRequest("workspace name must be an RFC 1123 label")}, nil
	}
	domain := a.Domain
	if domains, _, _, _ := a.instanceCollections(ctx); len(domains) > 0 {
		for _, d := range domains {
			if d.Default {
				domain = d.Domain
				break
			}
		}
	}
	if req.Body.DomainId != nil {
		if d, ok := a.domainByID(ctx, *req.Body.DomainId); ok {
			domain = d.Domain
		} else {
			return adminapi.CreateWorkspace400JSONResponse{BadRequestJSONResponse: badRequest("unknown domain")}, nil
		}
	}
	base := req.Body.Name + "." + domain
	if req.Body.BaseDomain != nil && strings.TrimSpace(*req.Body.BaseDomain) != "" {
		base = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*req.Body.BaseDomain), "."))
	}
	key, err := identity.GenerateKey()
	if err != nil {
		return nil, err
	}
	ws := store.Workspace{Name: req.Body.Name, BaseDomain: base, PrivateKey: key}
	if err := a.C.st.CreateWorkspace(ctx, ws); err != nil {
		code, c := classify(err)
		if code == 409 {
			if c == "CONFLICT" {
				c = "NAME_TAKEN"
			}
			return adminapi.CreateWorkspace409JSONResponse(apiErr(c, err.Error())), nil
		}
		return nil, err
	}
	ws, _ = a.C.st.GetWorkspace(ctx, ws.Name)
	if a.C.certs != nil {
		a.C.certs.Ensure(context.Background(), ws, true)
	}
	if relays, e := a.C.st.ListRelays(ctx); e == nil {
		for _, relay := range relays {
			a.C.pushRelayState(ctx, relay.Name)
		}
	}
	a.C.pushCertsForWorkspace(ctx, ws.Name)
	return adminapi.CreateWorkspace201JSONResponse(a.apiWorkspace(ctx, ws)), nil
}
func (a *Admin) GetWorkspace(ctx context.Context, req adminapi.GetWorkspaceRequestObject) (adminapi.GetWorkspaceResponseObject, error) {
	ws, err := a.resolveWorkspace(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.GetWorkspace404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	return adminapi.GetWorkspace200JSONResponse(a.apiWorkspace(ctx, ws)), nil
}
func (a *Admin) DeleteWorkspace(ctx context.Context, req adminapi.DeleteWorkspaceRequestObject) (adminapi.DeleteWorkspaceResponseObject, error) {
	ws, err := a.resolveWorkspace(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.DeleteWorkspace404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	keys := memberKeys(ctx, a.C.st, ws.Name)
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

func memberKeys(ctx context.Context, st *store.Store, ws string) [][]byte {
	ns, _ := st.ListNodes(ctx, ws)
	out := make([][]byte, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.PublicKey)
	}
	return out
}
func roleNames(rs []adminapi.Role) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, string(r))
	}
	return out
}
func apiRoles(names []string) []adminapi.Role {
	out := make([]adminapi.Role, 0, len(names))
	for _, n := range names {
		out = append(out, adminapi.Role(n))
	}
	return out
}
func (a *Admin) ListTokens(ctx context.Context, req adminapi.ListTokensRequestObject) (adminapi.ListTokensResponseObject, error) {
	ws, err := a.resolveWorkspace(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.ListTokens200JSONResponse{}, nil
	}
	ts, err := a.C.st.ListJoinTokens(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListTokens200JSONResponse{}
	for _, t := range ts {
		id := idFor("token", ws.Name+"/"+t.ID)
		tok := adminapi.Token{Id: id, Roles: apiRoles(t.Roles), Status: joinStatus(t), ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt}
		if t.Name != "" {
			tok.Name = &t.Name
		}
		out = append(out, tok)
	}
	return out, nil
}
func joinStatus(t store.JoinToken) adminapi.JoinTokenStatus {
	if !t.ExpiresAt.After(time.Now()) {
		return adminapi.JoinTokenStatus("expired")
	}
	return adminapi.JoinTokenStatus("active")
}
func (a *Admin) CreateToken(ctx context.Context, req adminapi.CreateTokenRequestObject) (adminapi.CreateTokenResponseObject, error) {
	ws, err := a.resolveWorkspace(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.CreateToken400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
	}
	b := req.Body
	if b == nil {
		b = &adminapi.CreateTokenJSONRequestBody{}
	}
	name := ""
	if b.Name != nil {
		name = *b.Name
		if !identity.ValidLabel(name) || store.ReservedNames[name] {
			return adminapi.CreateToken400JSONResponse{BadRequestJSONResponse: badRequest("invalid instance name")}, nil
		}
	}
	roles := []string{}
	if b.Roles != nil {
		roles = roleNames(*b.Roles)
	}
	ttl, err := parseTTL(b.Ttl, 24*time.Hour)
	if err != nil || ttl <= 0 {
		return adminapi.CreateToken400JSONResponse{BadRequestJSONResponse: badRequest("invalid ttl")}, nil
	}
	tok := randomToken()
	t := store.JoinToken{ID: uuid.NewString(), Workspace: ws.Name, Hash: store.HashToken(tok), Name: name, Roles: roles, ExpiresAt: time.Now().Add(ttl)}
	if err := a.C.st.CreateJoinToken(ctx, t); err != nil {
		return nil, err
	}
	link := identity.JoinLink{Workspace: ws.BaseDomain, Name: name, Key: ws.PublicKey, Token: tok}
	// The deprecated join_link keeps a bootstrap relay for older agentd
	// clients. The token itself remains unbound; current clients use join_token
	// with /api/v1/join/candidates and choose from the full pool.
	if relays, e := a.C.st.ListRelays(ctx); e == nil && len(relays) > 0 {
		link.RelayURL = relays[0].URL
	}
	out := adminapi.TokenCreated{Id: idFor("token", ws.Name+"/"+t.ID), Roles: apiRoles(roles), Status: adminapi.JoinTokenStatus("active"), ExpiresAt: t.ExpiresAt, CreatedAt: time.Now(), JoinToken: tok}
	linkString := link.String()
	out.JoinLink = linkString
	if name != "" {
		out.Name = &name
	}
	return adminapi.CreateToken201JSONResponse(out), nil
}
func (a *Admin) RevokeToken(ctx context.Context, req adminapi.RevokeTokenRequestObject) (adminapi.RevokeTokenResponseObject, error) {
	ws, err := a.resolveWorkspace(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.RevokeToken404JSONResponse{NotFoundJSONResponse: notFoundErr("token")}, nil
	}
	raw := req.TokenId
	ts, _ := a.C.st.ListJoinTokens(ctx, ws.Name)
	for _, t := range ts {
		if t.ID == raw || idFor("token", ws.Name+"/"+t.ID) == raw {
			if err := a.C.st.DeleteJoinToken(ctx, ws.Name, t.ID); err != nil {
				return nil, err
			}
			return adminapi.RevokeToken204Response{}, nil
		}
	}
	return adminapi.RevokeToken404JSONResponse{NotFoundJSONResponse: notFoundErr("token")}, nil
}

// ---------------------------------------------------------------- user directory

func apiUser(u store.User) adminapi.User {
	out := adminapi.User{Id: idFor("user", u.Subject), Email: openapi_types.Email(u.Email), Status: adminapi.UserStatus(u.Status), CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
	admin := u.InstanceAdmin
	out.InstanceAdmin = &admin
	if u.Name != "" {
		out.Name = &u.Name
	}
	if u.Picture != "" {
		out.Picture = &u.Picture
	}
	return out
}
func (a *Admin) resolveUser(ctx context.Context, id string) (store.User, error) {
	if u, err := a.C.st.GetUser(ctx, id); err == nil {
		return u, nil
	}
	users, err := a.C.st.ListUsers(ctx)
	if err != nil {
		return store.User{}, err
	}
	for _, u := range users {
		if idFor("user", u.Subject) == id {
			return u, nil
		}
	}
	return store.User{}, store.ErrNotFound
}
func (a *Admin) ListUsers(ctx context.Context, _ adminapi.ListUsersRequestObject) (adminapi.ListUsersResponseObject, error) {
	us, err := a.C.st.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListUsers200JSONResponse{}
	for _, u := range us {
		out = append(out, apiUser(u))
	}
	return out, nil
}
func (a *Admin) UpsertUser(ctx context.Context, req adminapi.UpsertUserRequestObject) (adminapi.UpsertUserResponseObject, error) {
	if req.Body == nil || strings.TrimSpace(string(req.Body.Email)) == "" {
		return adminapi.UpsertUser400JSONResponse{BadRequestJSONResponse: badRequest("email is required")}, nil
	}
	status := "active"
	if req.Body.Status != nil {
		status = string(*req.Body.Status)
	}
	subject := strings.ToLower(strings.TrimSpace(string(req.Body.Email)))
	u := store.User{Subject: subject, Provider: "manual", Email: subject, Status: status}
	if err := a.C.st.UpsertUser(ctx, u); err != nil {
		return nil, err
	}
	got, err := a.C.st.GetUser(ctx, subject)
	if err != nil {
		return nil, err
	}
	return adminapi.UpsertUser200JSONResponse(apiUser(got)), nil
}
func (a *Admin) GetUser(ctx context.Context, req adminapi.GetUserRequestObject) (adminapi.GetUserResponseObject, error) {
	u, err := a.resolveUser(ctx, req.UserId)
	if err != nil {
		return adminapi.GetUser404JSONResponse{NotFoundJSONResponse: notFoundErr("user")}, nil
	}
	return adminapi.GetUser200JSONResponse(apiUser(u)), nil
}
func (a *Admin) DeleteUser(ctx context.Context, req adminapi.DeleteUserRequestObject) (adminapi.DeleteUserResponseObject, error) {
	u, err := a.resolveUser(ctx, req.UserId)
	if err != nil {
		return adminapi.DeleteUser404JSONResponse{NotFoundJSONResponse: notFoundErr("user")}, nil
	}
	if err := a.C.st.DeleteUser(ctx, u.Subject); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return adminapi.DeleteUser409JSONResponse(apiErr("CONFLICT", err.Error())), nil
		}
		return nil, err
	}
	return adminapi.DeleteUser204Response{}, nil
}

// ---------------------------------------------------------------- instance configuration collections

func (a *Admin) instanceCollections(ctx context.Context) ([]adminapi.InstanceDomain, []adminapi.DNSProvider, []adminapi.CertificateIssuer, []adminapi.AuthProvider) {
	defaultDomain := adminapi.InstanceDomain{Id: ptr(idFor("domain", a.Domain)), Domain: a.Domain, Name: a.Domain, Default: true, Status: ptr(adminapi.DomainStatusActive)}
	domains := []adminapi.InstanceDomain{defaultDomain}
	dns := []adminapi.DNSProvider{}
	issuers := []adminapi.CertificateIssuer{}
	auth := []adminapi.AuthProvider{}
	if a.Config != nil {
		for name, p := range a.Config.DNSProviders {
			k := adminapi.DNSProviderKind(p.Provider)
			if !k.Valid() {
				continue
			}
			dns = append(dns, adminapi.DNSProvider{Id: ptr(idFor("dns-provider", name)), Name: name, Kind: k, Zones: append([]string(nil), p.Zones...), Status: ptr(adminapi.DNSProviderStatusActive)})
			kind := adminapi.CertificateIssuerKindLetsEncrypt
			directory := p.Directory
			if directory == "" {
				directory = "https://acme-v02.api.letsencrypt.org/directory"
			}
			if strings.Contains(directory, "pki.goog") {
				kind = adminapi.CertificateIssuerKindGoogleTrustServices
			}
			issuers = append(issuers, adminapi.CertificateIssuer{Id: ptr(idFor("issuer", name)), Name: name, Kind: kind, Directory: directory, Status: ptr(adminapi.CertificateIssuerStatusActive), AccountStatus: ptr(adminapi.IssuerAccountStatus("not_created"))})
		}
		if a.Config.OIDC.Enabled {
			name := "oidc"
			auth = append(auth, adminapi.AuthProvider{Id: ptr(idFor("auth-provider", a.Config.OIDC.Issuer)), Name: name, Kind: adminapi.AuthProviderKindOidc, Issuer: a.Config.OIDC.Issuer, ClientId: a.Config.OIDC.ClientID, Scopes: ptr(append([]string(nil), a.Config.OIDC.Scopes...)), Status: ptr(adminapi.AuthProviderStatusActive)})
		}
	}
	if s, err := a.C.st.GetInstanceSettings(ctx); err == nil {
		domains = decodeDomains(s.DomainsJSON, domains)
		dns = decodeDNSProviders(s.DNSProvidersJSON, dns)
		issuers = decodeIssuers(s.CertificateIssuersJSON, issuers)
	}
	for i := range dns {
		dns[i].Credentials = nil
	}
	for i := range issuers {
		issuers[i].EabKeyId, issuers[i].EabHmacKey = nil, nil
	}
	for i := range auth {
		auth[i].ClientSecret = nil
	}
	return domains, dns, issuers, auth
}
func decodeDomains(b []byte, def []adminapi.InstanceDomain) []adminapi.InstanceDomain {
	var v []adminapi.InstanceDomain
	if len(b) > 0 && json.Unmarshal(b, &v) == nil && len(v) > 0 {
		return v
	}
	return def
}
func decodeDNSProviders(b []byte, def []adminapi.DNSProvider) []adminapi.DNSProvider {
	var v []adminapi.DNSProvider
	if len(b) > 0 && json.Unmarshal(b, &v) == nil {
		return v
	}
	return def
}
func decodeIssuers(b []byte, def []adminapi.CertificateIssuer) []adminapi.CertificateIssuer {
	var v []adminapi.CertificateIssuer
	if len(b) > 0 && json.Unmarshal(b, &v) == nil {
		return v
	}
	return def
}
func (a *Admin) saveCollections(ctx context.Context, d []adminapi.InstanceDomain, dns []adminapi.DNSProvider, issuers []adminapi.CertificateIssuer, _ ...[]adminapi.AuthProvider) error {
	db, _ := json.Marshal(d)
	dp, _ := json.Marshal(dns)
	ci, _ := json.Marshal(issuers)
	return a.C.st.SetInstanceSettings(ctx, store.InstanceSettings{Domain: a.Domain, DomainsJSON: db, DNSProvidersJSON: dp, CertificateIssuersJSON: ci})
}
func (a *Admin) domainByID(ctx context.Context, id string) (adminapi.InstanceDomain, bool) {
	d, _, _, _ := a.instanceCollections(ctx)
	for _, v := range d {
		if v.Id != nil && *v.Id == id || v.Domain == id {
			return v, true
		}
	}
	return adminapi.InstanceDomain{}, false
}
func findDomain(ds []adminapi.InstanceDomain, id string) (int, bool) {
	for i, d := range ds {
		if (d.Id != nil && *d.Id == id) || d.Domain == id {
			return i, true
		}
	}
	return -1, false
}
func findNamed[T any](items []T, id string, get func(T) (string, string)) (int, bool) {
	for i, v := range items {
		name, rid := get(v)
		if name == id || rid == id {
			return i, true
		}
	}
	return -1, false
}

func (a *Admin) ListInstanceDomains(ctx context.Context, _ adminapi.ListInstanceDomainsRequestObject) (adminapi.ListInstanceDomainsResponseObject, error) {
	d, _, _, _ := a.instanceCollections(ctx)
	return adminapi.ListInstanceDomains200JSONResponse(d), nil
}
func (a *Admin) CreateInstanceDomain(ctx context.Context, req adminapi.CreateInstanceDomainRequestObject) (adminapi.CreateInstanceDomainResponseObject, error) {
	if req.Body == nil || !identity.ValidDomain(req.Body.Domain) {
		return adminapi.CreateInstanceDomain400JSONResponse{BadRequestJSONResponse: badRequest("invalid domain")}, nil
	}
	d, dns, ci, _ := a.instanceCollections(ctx)
	if req.Body.DnsProviderId != nil {
		found := false
		for _, p := range dns {
			if p.Id != nil && *p.Id == *req.Body.DnsProviderId {
				found = true
				break
			}
		}
		if !found {
			return adminapi.CreateInstanceDomain400JSONResponse{BadRequestJSONResponse: badRequest("unknown DNS provider")}, nil
		}
	}
	if req.Body.CertificateIssuerId != nil {
		found := false
		for _, p := range ci {
			if p.Id != nil && *p.Id == *req.Body.CertificateIssuerId {
				found = true
				break
			}
		}
		if !found {
			return adminapi.CreateInstanceDomain400JSONResponse{BadRequestJSONResponse: badRequest("unknown certificate issuer")}, nil
		}
	}
	for _, v := range d {
		if v.Domain == strings.ToLower(strings.TrimSuffix(req.Body.Domain, ".")) {
			return adminapi.CreateInstanceDomain409JSONResponse{ConflictJSONResponse: conflictErr("CONFLICT", "domain already exists")}, nil
		}
	}
	v := adminapi.InstanceDomain{Id: ptr(uuid.NewString()), Domain: strings.ToLower(strings.TrimSuffix(req.Body.Domain, ".")), Name: strings.ToLower(strings.TrimSuffix(req.Body.Domain, ".")), Default: req.Body.Default, Status: ptr(adminapi.DomainStatusPending), DnsProviderId: req.Body.DnsProviderId, CertificateIssuerId: req.Body.CertificateIssuerId}
	if v.Default {
		for i := range d {
			d[i].Default = false
		}
	}
	d = append(d, v)
	if err := a.saveCollections(ctx, d, dns, ci); err != nil {
		return nil, err
	}
	return adminapi.CreateInstanceDomain201JSONResponse(v), nil
}
func (a *Admin) GetInstanceDomain(ctx context.Context, req adminapi.GetInstanceDomainRequestObject) (adminapi.GetInstanceDomainResponseObject, error) {
	d, ok := a.domainByID(ctx, req.DomainId)
	if !ok {
		return adminapi.GetInstanceDomain404JSONResponse{NotFoundJSONResponse: notFoundErr("domain")}, nil
	}
	return adminapi.GetInstanceDomain200JSONResponse(d), nil
}
func (a *Admin) UpdateInstanceDomain(ctx context.Context, req adminapi.UpdateInstanceDomainRequestObject) (adminapi.UpdateInstanceDomainResponseObject, error) {
	if req.Body == nil || !identity.ValidDomain(req.Body.Domain) {
		return adminapi.UpdateInstanceDomain400JSONResponse{BadRequestJSONResponse: badRequest("invalid domain")}, nil
	}
	d, dns, ci, _ := a.instanceCollections(ctx)
	i, ok := findDomain(d, req.DomainId)
	if !ok {
		return adminapi.UpdateInstanceDomain404JSONResponse{NotFoundJSONResponse: notFoundErr("domain")}, nil
	}
	if req.Body.DnsProviderId != nil {
		found := false
		for _, p := range dns {
			if p.Id != nil && *p.Id == *req.Body.DnsProviderId {
				found = true
				break
			}
		}
		if !found {
			return adminapi.UpdateInstanceDomain400JSONResponse{BadRequestJSONResponse: badRequest("unknown DNS provider")}, nil
		}
	}
	if req.Body.CertificateIssuerId != nil {
		found := false
		for _, p := range ci {
			if p.Id != nil && *p.Id == *req.Body.CertificateIssuerId {
				found = true
				break
			}
		}
		if !found {
			return adminapi.UpdateInstanceDomain400JSONResponse{BadRequestJSONResponse: badRequest("unknown certificate issuer")}, nil
		}
	}
	d[i].Domain = strings.ToLower(strings.TrimSuffix(req.Body.Domain, "."))
	d[i].Name = d[i].Domain
	d[i].Default = req.Body.Default
	d[i].DnsProviderId = req.Body.DnsProviderId
	d[i].CertificateIssuerId = req.Body.CertificateIssuerId
	if d[i].Default {
		for j := range d {
			if j != i {
				d[j].Default = false
			}
		}
	}
	if err := a.saveCollections(ctx, d, dns, ci); err != nil {
		return nil, err
	}
	return adminapi.UpdateInstanceDomain200JSONResponse(d[i]), nil
}
func (a *Admin) DeleteInstanceDomain(ctx context.Context, req adminapi.DeleteInstanceDomainRequestObject) (adminapi.DeleteInstanceDomainResponseObject, error) {
	d, dns, ci, _ := a.instanceCollections(ctx)
	i, ok := findDomain(d, req.DomainId)
	if !ok {
		return adminapi.DeleteInstanceDomain404JSONResponse{NotFoundJSONResponse: notFoundErr("domain")}, nil
	}
	if d[i].Default {
		return adminapi.DeleteInstanceDomain409JSONResponse{ConflictJSONResponse: conflictErr("CONFLICT", "default domain cannot be deleted")}, nil
	}
	d = append(d[:i], d[i+1:]...)
	if err := a.saveCollections(ctx, d, dns, ci); err != nil {
		return nil, err
	}
	return adminapi.DeleteInstanceDomain204Response{}, nil
}

func (a *Admin) ListDNSProviders(ctx context.Context, _ adminapi.ListDNSProvidersRequestObject) (adminapi.ListDNSProvidersResponseObject, error) {
	_, d, _, _ := a.instanceCollections(ctx)
	return adminapi.ListDNSProviders200JSONResponse(d), nil
}
func (a *Admin) CreateDNSProvider(ctx context.Context, req adminapi.CreateDNSProviderRequestObject) (adminapi.CreateDNSProviderResponseObject, error) {
	if req.Body == nil || !identity.ValidLabel(req.Body.Name) || !req.Body.Kind.Valid() || len(req.Body.Zones) == 0 {
		return adminapi.CreateDNSProvider400JSONResponse{BadRequestJSONResponse: badRequest("invalid DNS provider")}, nil
	}
	domains, d, ci, _ := a.instanceCollections(ctx)
	for _, v := range d {
		if v.Name == req.Body.Name {
			return adminapi.CreateDNSProvider409JSONResponse{ConflictJSONResponse: conflictErr("CONFLICT", "provider already exists")}, nil
		}
	}
	v := adminapi.DNSProvider{Id: ptr(uuid.NewString()), Name: req.Body.Name, Kind: adminapi.DNSProviderKind(req.Body.Kind), Zones: req.Body.Zones, Status: ptr(adminapi.DNSProviderStatusActive), Credentials: req.Body.Credentials}
	d = append(d, v)
	if err := a.saveCollections(ctx, domains, d, ci); err != nil {
		return nil, err
	}
	v.Credentials = nil
	return adminapi.CreateDNSProvider200JSONResponse(v), nil
}
func (a *Admin) dnsProvider(ctx context.Context, id string) ([]adminapi.InstanceDomain, []adminapi.DNSProvider, []adminapi.CertificateIssuer, []adminapi.AuthProvider, int, bool) {
	d, dp, ci, au := a.instanceCollections(ctx)
	i, ok := findNamed(dp, id, func(v adminapi.DNSProvider) (string, string) {
		if v.Id == nil {
			return v.Name, ""
		}
		return v.Name, *v.Id
	})
	return d, dp, ci, au, i, ok
}
func (a *Admin) ListDNSProviderByID(ctx context.Context, id string) (adminapi.DNSProvider, bool) {
	_, d, _, _, i, ok := a.dnsProvider(ctx, id)
	if !ok {
		return adminapi.DNSProvider{}, false
	}
	return d[i], true
}
func (a *Admin) GetDNSProvider(ctx context.Context, req adminapi.GetDNSProviderRequestObject) (adminapi.GetDNSProviderResponseObject, error) {
	v, ok := a.ListDNSProviderByID(ctx, req.ProviderId)
	if !ok {
		return adminapi.GetDNSProvider404JSONResponse{NotFoundJSONResponse: notFoundErr("DNS provider")}, nil
	}
	v.Credentials = nil
	return adminapi.GetDNSProvider200JSONResponse(v), nil
}
func (a *Admin) UpdateDNSProvider(ctx context.Context, req adminapi.UpdateDNSProviderRequestObject) (adminapi.UpdateDNSProviderResponseObject, error) {
	if req.Body == nil {
		return adminapi.UpdateDNSProvider400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	domains, dp, ci, _, i, ok := a.dnsProvider(ctx, req.ProviderId)
	if !ok {
		return adminapi.UpdateDNSProvider404JSONResponse{NotFoundJSONResponse: notFoundErr("DNS provider")}, nil
	}
	dp[i] = adminapi.DNSProvider{Id: dp[i].Id, Name: req.Body.Name, Kind: adminapi.DNSProviderKind(req.Body.Kind), Zones: req.Body.Zones, Status: ptr(adminapi.DNSProviderStatusActive), Credentials: req.Body.Credentials}
	if err := a.saveCollections(ctx, domains, dp, ci); err != nil {
		return nil, err
	}
	dp[i].Credentials = nil
	return adminapi.UpdateDNSProvider200JSONResponse(dp[i]), nil
}
func (a *Admin) DeleteDNSProvider(ctx context.Context, req adminapi.DeleteDNSProviderRequestObject) (adminapi.DeleteDNSProviderResponseObject, error) {
	domains, dp, ci, _, i, ok := a.dnsProvider(ctx, req.ProviderId)
	if !ok {
		return adminapi.DeleteDNSProvider404JSONResponse{NotFoundJSONResponse: notFoundErr("DNS provider")}, nil
	}
	dp = append(dp[:i], dp[i+1:]...)
	if err := a.saveCollections(ctx, domains, dp, ci); err != nil {
		return nil, err
	}
	return adminapi.DeleteDNSProvider204Response{}, nil
}

func (a *Admin) ListCertificateIssuers(ctx context.Context, _ adminapi.ListCertificateIssuersRequestObject) (adminapi.ListCertificateIssuersResponseObject, error) {
	_, _, v, _ := a.instanceCollections(ctx)
	return adminapi.ListCertificateIssuers200JSONResponse(v), nil
}
func (a *Admin) CreateCertificateIssuer(ctx context.Context, req adminapi.CreateCertificateIssuerRequestObject) (adminapi.CreateCertificateIssuerResponseObject, error) {
	if req.Body == nil || !identity.ValidLabel(req.Body.Name) || !req.Body.Kind.Valid() {
		return adminapi.CreateCertificateIssuer400JSONResponse{BadRequestJSONResponse: badRequest("invalid certificate issuer")}, nil
	}
	d, dp, ci, _ := a.instanceCollections(ctx)
	for _, v := range ci {
		if v.Name == req.Body.Name {
			return adminapi.CreateCertificateIssuer409JSONResponse{ConflictJSONResponse: conflictErr("CONFLICT", "issuer already exists")}, nil
		}
	}
	v := adminapi.CertificateIssuer{Id: ptr(uuid.NewString()), Name: req.Body.Name, Kind: adminapi.CertificateIssuerKind(req.Body.Kind), Directory: req.Body.Directory, Email: req.Body.Email, Status: ptr(adminapi.CertificateIssuerStatusActive), AccountStatus: ptr(adminapi.IssuerAccountStatus("not_created")), EabKeyId: req.Body.EabKeyId, EabHmacKey: req.Body.EabHmacKey}
	ci = append(ci, v)
	if err := a.saveCollections(ctx, d, dp, ci); err != nil {
		return nil, err
	}
	v.EabKeyId = nil
	v.EabHmacKey = nil
	return adminapi.CreateCertificateIssuer200JSONResponse(v), nil
}
func (a *Admin) issuer(ctx context.Context, id string) ([]adminapi.InstanceDomain, []adminapi.DNSProvider, []adminapi.CertificateIssuer, []adminapi.AuthProvider, int, bool) {
	d, dp, ci, au := a.instanceCollections(ctx)
	i, ok := findNamed(ci, id, func(v adminapi.CertificateIssuer) (string, string) {
		if v.Id == nil {
			return v.Name, ""
		}
		return v.Name, *v.Id
	})
	return d, dp, ci, au, i, ok
}
func (a *Admin) ListCertificateIssuerByID(ctx context.Context, id string) (adminapi.CertificateIssuer, bool) {
	_, _, v, _, i, ok := a.issuer(ctx, id)
	if !ok {
		return adminapi.CertificateIssuer{}, false
	}
	return v[i], true
}
func (a *Admin) GetCertificateIssuer(ctx context.Context, req adminapi.GetCertificateIssuerRequestObject) (adminapi.GetCertificateIssuerResponseObject, error) {
	v, ok := a.ListCertificateIssuerByID(ctx, req.IssuerId)
	if !ok {
		return adminapi.GetCertificateIssuer404JSONResponse{NotFoundJSONResponse: notFoundErr("certificate issuer")}, nil
	}
	v.EabKeyId = nil
	v.EabHmacKey = nil
	return adminapi.GetCertificateIssuer200JSONResponse(v), nil
}
func (a *Admin) UpdateCertificateIssuer(ctx context.Context, req adminapi.UpdateCertificateIssuerRequestObject) (adminapi.UpdateCertificateIssuerResponseObject, error) {
	if req.Body == nil {
		return adminapi.UpdateCertificateIssuer400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	d, dp, ci, _, i, ok := a.issuer(ctx, req.IssuerId)
	if !ok {
		return adminapi.UpdateCertificateIssuer404JSONResponse{NotFoundJSONResponse: notFoundErr("certificate issuer")}, nil
	}
	ci[i] = adminapi.CertificateIssuer{Id: ci[i].Id, Name: req.Body.Name, Kind: adminapi.CertificateIssuerKind(req.Body.Kind), Directory: req.Body.Directory, Email: req.Body.Email, Status: ptr(adminapi.CertificateIssuerStatusActive), AccountStatus: ci[i].AccountStatus, EabKeyId: req.Body.EabKeyId, EabHmacKey: req.Body.EabHmacKey}
	if err := a.saveCollections(ctx, d, dp, ci); err != nil {
		return nil, err
	}
	ci[i].EabKeyId = nil
	ci[i].EabHmacKey = nil
	return adminapi.UpdateCertificateIssuer200JSONResponse(ci[i]), nil
}
func (a *Admin) DeleteCertificateIssuer(ctx context.Context, req adminapi.DeleteCertificateIssuerRequestObject) (adminapi.DeleteCertificateIssuerResponseObject, error) {
	d, dp, ci, _, i, ok := a.issuer(ctx, req.IssuerId)
	if !ok {
		return adminapi.DeleteCertificateIssuer404JSONResponse{NotFoundJSONResponse: notFoundErr("certificate issuer")}, nil
	}
	ci = append(ci[:i], ci[i+1:]...)
	if err := a.saveCollections(ctx, d, dp, ci); err != nil {
		return nil, err
	}
	return adminapi.DeleteCertificateIssuer204Response{}, nil
}

func (a *Admin) ListAuthProviders(ctx context.Context, _ adminapi.ListAuthProvidersRequestObject) (adminapi.ListAuthProvidersResponseObject, error) {
	_, _, _, v := a.instanceCollections(ctx)
	return adminapi.ListAuthProviders200JSONResponse(v), nil
}

func (a *Admin) GetAuthProvider(ctx context.Context, req adminapi.GetAuthProviderRequestObject) (adminapi.GetAuthProviderResponseObject, error) {
	_, _, _, providers := a.instanceCollections(ctx)
	for _, provider := range providers {
		if provider.Id != nil && *provider.Id == req.ProviderId || provider.Name == req.ProviderId {
			provider.ClientSecret = nil
			return adminapi.GetAuthProvider200JSONResponse(provider), nil
		}
	}
	return adminapi.GetAuthProvider404JSONResponse{NotFoundJSONResponse: notFoundErr("auth provider")}, nil
}

// The remaining resource handlers live in admin_config.go and admin_nodes.go.
