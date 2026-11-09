package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/adminapi"
	"agentd/internal/identity"
	"agentd/internal/routes"
	"agentd/internal/store"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// ---------------------------------------------------------------- routes

func apiMatches(ms []*pb.Match) []adminapi.Match {
	out := []adminapi.Match{}
	for _, m := range ms {
		j := FromMatch(m)
		out = append(out, adminapi.Match{Kind: adminapi.MatchKind(j.Kind), Value: j.Value})
	}
	return out
}

func apiRoute(r routes.Route) adminapi.Route {
	protos := []adminapi.Proto{}
	for _, p := range r.Protos {
		if p == pb.Proto_PROTO_SSH {
			protos = append(protos, adminapi.ProtoSsh)
		} else {
			protos = append(protos, adminapi.ProtoTls)
		}
	}
	return adminapi.Route{Id: r.ID, From: r.From, Proto: protos, Domains: apiMatches(r.Domains), To: r.To}
}

func routeFromAPI(w adminapi.RouteWrite) (routes.Route, error) {
	r := routes.Route{From: w.From, To: w.To}
	if w.Proto != nil {
		for _, p := range *w.Proto {
			pp, err := ProtoFromName(string(p))
			if err != nil {
				return r, err
			}
			r.Protos = append(r.Protos, pp)
		}
	}
	for _, m := range w.Domains {
		r.Domains = append(r.Domains, MatchJSON{Kind: string(m.Kind), Value: m.Value}.ToMatch())
	}
	return r, r.Validate()
}

func apiTable(t routes.Table) adminapi.RouteTable {
	out := adminapi.RouteTable{Version: int(t.Version), Default: adminapi.RouteTableDefault(t.Default), Routes: []adminapi.Route{}}
	for _, r := range t.Routes {
		out.Routes = append(out.Routes, apiRoute(r))
	}
	return out
}

func (a *Admin) GetRouteTable(ctx context.Context, req adminapi.GetRouteTableRequestObject) (adminapi.GetRouteTableResponseObject, error) {
	t, err := a.C.st.GetRouteTable(ctx, req.Ws)
	if err != nil {
		return nil, err
	}
	return adminapi.GetRouteTable200JSONResponse(apiTable(t)), nil
}

func (a *Admin) ReplaceRouteTable(ctx context.Context, req adminapi.ReplaceRouteTableRequestObject) (adminapi.ReplaceRouteTableResponseObject, error) {
	if req.Body == nil {
		return adminapi.ReplaceRouteTable400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	var rs []routes.Route
	for _, w := range req.Body.Routes {
		r, err := routeFromAPI(w)
		if err != nil {
			return adminapi.ReplaceRouteTable400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
		}
		rs = append(rs, r)
	}
	def := "direct"
	if req.Body.Default != nil {
		def = string(*req.Body.Default)
	}
	if def != routes.Direct && def != routes.Reject {
		return adminapi.ReplaceRouteTable400JSONResponse{BadRequestJSONResponse: badRequest("default must be direct or reject")}, nil
	}
	if err := a.C.st.ReplaceRoutes(ctx, req.Ws, rs, def); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.ReplaceRouteTable400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
		}
		return nil, err
	}
	a.C.Changed(ctx, req.Ws)
	t, _ := a.C.st.GetRouteTable(ctx, req.Ws)
	return adminapi.ReplaceRouteTable200JSONResponse(apiTable(t)), nil
}

func (a *Admin) AddRoute(ctx context.Context, req adminapi.AddRouteRequestObject) (adminapi.AddRouteResponseObject, error) {
	if req.Body == nil {
		return adminapi.AddRoute400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	r, err := routeFromAPI(*req.Body)
	if err != nil {
		return adminapi.AddRoute400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
	}
	id, err := a.C.st.AddRoute(ctx, req.Ws, r)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.AddRoute400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
		}
		return nil, err
	}
	r.ID = id
	a.C.Changed(ctx, req.Ws)
	return adminapi.AddRoute201JSONResponse(apiRoute(r)), nil
}

func (a *Admin) DeleteRoute(ctx context.Context, req adminapi.DeleteRouteRequestObject) (adminapi.DeleteRouteResponseObject, error) {
	if err := a.C.st.DeleteRoute(ctx, req.Ws, req.RouteId); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.DeleteRoute404JSONResponse{NotFoundJSONResponse: notFoundErr("route")}, nil
		}
		return nil, err
	}
	a.C.Changed(ctx, req.Ws)
	return adminapi.DeleteRoute204Response{}, nil
}

// ---------------------------------------------------------------- policies

func statementFromAPI(w adminapi.PolicyStatementWrite) (json.RawMessage, error) {
	b, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	var st Statement
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(st)
}

func apiStatement(r store.PolicyRecord) adminapi.PolicyStatement {
	var out adminapi.PolicyStatement
	_ = json.Unmarshal(r.Statement, &out)
	out.Id = r.ID
	if out.Subjects == nil {
		out.Subjects = []string{}
	}
	return out
}

func (a *Admin) ListPolicies(ctx context.Context, req adminapi.ListPoliciesRequestObject) (adminapi.ListPoliciesResponseObject, error) {
	recs, err := a.C.st.ListPolicies(ctx, req.Ws)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListPolicies200JSONResponse{}
	for _, r := range recs {
		out = append(out, apiStatement(r))
	}
	return out, nil
}

func (a *Admin) AddPolicy(ctx context.Context, req adminapi.AddPolicyRequestObject) (adminapi.AddPolicyResponseObject, error) {
	if req.Body == nil {
		return adminapi.AddPolicy400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	raw, err := statementFromAPI(*req.Body)
	if err != nil {
		return adminapi.AddPolicy400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
	}
	id, err := a.C.st.AddPolicy(ctx, req.Ws, raw)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.AddPolicy400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
		}
		return nil, err
	}
	a.C.Changed(ctx, req.Ws)
	return adminapi.AddPolicy201JSONResponse(apiStatement(store.PolicyRecord{ID: id, Statement: raw})), nil
}

func (a *Admin) ReplacePolicies(ctx context.Context, req adminapi.ReplacePoliciesRequestObject) (adminapi.ReplacePoliciesResponseObject, error) {
	if req.Body == nil {
		return adminapi.ReplacePolicies400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	var raws []json.RawMessage
	for _, w := range *req.Body {
		raw, err := statementFromAPI(w)
		if err != nil {
			return adminapi.ReplacePolicies400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
		}
		raws = append(raws, raw)
	}
	ids, err := a.C.st.ReplacePolicies(ctx, req.Ws, raws)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.ReplacePolicies400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
		}
		return nil, err
	}
	a.C.Changed(ctx, req.Ws)
	out := adminapi.ReplacePolicies200JSONResponse{}
	for i, id := range ids {
		out = append(out, apiStatement(store.PolicyRecord{ID: id, Statement: raws[i]}))
	}
	return out, nil
}

func (a *Admin) DeletePolicy(ctx context.Context, req adminapi.DeletePolicyRequestObject) (adminapi.DeletePolicyResponseObject, error) {
	if err := a.C.st.DeletePolicy(ctx, req.Ws, req.PolicyId); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.DeletePolicy404JSONResponse{NotFoundJSONResponse: notFoundErr("policy")}, nil
		}
		return nil, err
	}
	a.C.Changed(ctx, req.Ws)
	return adminapi.DeletePolicy204Response{}, nil
}

// ---------------------------------------------------------------- services & certs

func (a *Admin) ListServices(ctx context.Context, req adminapi.ListServicesRequestObject) (adminapi.ListServicesResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.ListServices200JSONResponse{}, nil
	}
	svcs, err := a.C.st.ListServices(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	ready := a.C.certReady(ctx, ws)
	out := adminapi.ListServices200JSONResponse{}
	for _, sv := range svcs {
		n, _ := a.C.st.GetNode(ctx, ws.Name, sv.Node)
		online, _ := a.C.NodeOnline(n.PublicKey)
		s := adminapi.Service{Name: sv.Name, Fqdn: sv.Name + "." + ws.BaseDomain, Proto: adminapi.ServiceProto(sv.Proto), Node: sv.Node, NodeOnline: ptr(online), State: adminapi.ServiceState("ready")}
		if sv.Proto == "http" {
			s.Port = ptr(443)
			if !ready {
				s.State = adminapi.ServiceState("cert_pending")
			}
			if pol, err := a.C.effectivePolicy(ctx, ws, n, "service"); err == nil {
				pub := false
				for _, r := range pol.Services {
					if r.Name == sv.Name && r.Action == pb.Action_ACTION_ALLOW && len(r.PublicKey) == 0 {
						pub = true
					}
				}
				s.Public = ptr(pub)
			}
		} else {
			s.Port = ptr(22)
		}
		out = append(out, s)
	}
	return out, nil
}

func (a *Admin) ListCerts(ctx context.Context, req adminapi.ListCertsRequestObject) (adminapi.ListCertsResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.ListCerts200JSONResponse{}, nil
	}
	return adminapi.ListCerts200JSONResponse{a.apiCert(ctx, ws)}, nil
}

func (a *Admin) RenewCert(ctx context.Context, req adminapi.RenewCertRequestObject) (adminapi.RenewCertResponseObject, error) {
	ws, err := a.C.st.GetWorkspace(ctx, req.Ws)
	if err != nil {
		return adminapi.RenewCert404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	if a.C.certs != nil {
		a.C.certs.Ensure(context.Background(), ws, true)
	}
	return adminapi.RenewCert202JSONResponse(a.apiCert(ctx, ws)), nil
}

// ---------------------------------------------------------------- relays

func (a *Admin) apiRelay(ctx context.Context, r store.Relay) adminapi.Relay {
	connected, since := a.C.RelayConnected(r.Name)
	out := adminapi.Relay{Name: r.Name, PublicKey: identity.EncodeKey(r.PublicKey), Url: r.URL, Connected: connected}
	if len(r.Transports) > 0 {
		tr := r.Transports
		out.Transports = &tr
	}
	if r.STUN != "" {
		out.Stun = ptr(r.STUN)
	}
	if connected {
		out.ConnectedSince = &since
	}
	wss, _ := a.C.st.WorkspacesOfRelay(ctx, r.Name)
	names := []string{}
	online := 0
	for _, ws := range wss {
		names = append(names, ws.Name)
		online += a.C.OnlineCount(ws.Name)
	}
	out.Workspaces, out.NodesOnline = &names, ptr(online)
	return out
}

func (a *Admin) ListRelays(ctx context.Context, _ adminapi.ListRelaysRequestObject) (adminapi.ListRelaysResponseObject, error) {
	rs, err := a.C.st.ListRelays(ctx)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListRelays200JSONResponse{}
	for _, r := range rs {
		out = append(out, a.apiRelay(ctx, r))
	}
	return out, nil
}

func (a *Admin) RegisterRelay(ctx context.Context, req adminapi.RegisterRelayRequestObject) (adminapi.RegisterRelayResponseObject, error) {
	b := req.Body
	if b == nil || !identity.ValidLabel(b.Name) {
		return adminapi.RegisterRelay400JSONResponse{BadRequestJSONResponse: badRequest("relay name must be an RFC 1123 label")}, nil
	}
	key, err := identity.DecodeKey(b.PublicKey)
	if err != nil {
		return adminapi.RegisterRelay400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
	}
	if u, err := url.Parse(b.Url); err != nil || u.Scheme != "https" || u.Host == "" {
		return adminapi.RegisterRelay400JSONResponse{BadRequestJSONResponse: badRequest("url must be https")}, nil
	}
	r := store.Relay{Name: b.Name, PublicKey: key, URL: b.Url, Transports: DefaultTransports}
	if b.Transports != nil {
		r.Transports = *b.Transports
	}
	if b.Stun != nil {
		r.STUN = *b.Stun
	}
	if err := a.C.st.CreateRelay(ctx, r); err != nil {
		if code, c := classify(err); code == 409 {
			return adminapi.RegisterRelay409JSONResponse(apiErr(c, err.Error())), nil
		}
		return nil, err
	}
	r, _ = a.C.st.GetRelay(ctx, b.Name)
	return adminapi.RegisterRelay201JSONResponse(a.apiRelay(ctx, r)), nil
}

func (a *Admin) GetRelay(ctx context.Context, req adminapi.GetRelayRequestObject) (adminapi.GetRelayResponseObject, error) {
	r, err := a.C.st.GetRelay(ctx, req.Relay)
	if err != nil {
		return adminapi.GetRelay404JSONResponse{NotFoundJSONResponse: notFoundErr("relay")}, nil
	}
	return adminapi.GetRelay200JSONResponse(a.apiRelay(ctx, r)), nil
}

func (a *Admin) RemoveRelay(ctx context.Context, req adminapi.RemoveRelayRequestObject) (adminapi.RemoveRelayResponseObject, error) {
	if err := a.C.st.DeleteRelay(ctx, req.Relay); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.RemoveRelay404JSONResponse{NotFoundJSONResponse: notFoundErr("relay")}, nil
		}
		if errors.Is(err, store.ErrConflict) {
			return adminapi.RemoveRelay409JSONResponse(apiErr("RELAY_IN_USE", err.Error())), nil
		}
		return nil, err
	}
	return adminapi.RemoveRelay204Response{}, nil
}

func (a *Admin) ListRelayCerts(ctx context.Context, req adminapi.ListRelayCertsRequestObject) (adminapi.ListRelayCertsResponseObject, error) {
	r, err := a.C.st.GetRelay(ctx, req.Relay)
	if err != nil {
		return adminapi.ListRelayCerts404JSONResponse{NotFoundJSONResponse: notFoundErr("relay")}, nil
	}
	wss, _ := a.C.st.WorkspacesOfRelay(ctx, r.Name)
	out := adminapi.ListRelayCerts200JSONResponse{}
	for _, ws := range wss {
		c, err := a.C.relayCert(ws, r)
		if err != nil {
			continue
		}
		b, _ := wire.DecodeRelayCert(c)
		raw, _ := proto.Marshal(c)
		out = append(out, adminapi.RelayCert{Workspace: ws.Name, Relay: r.Name, IssuedAt: time.Unix(int64(b.IssuedAt), 0), ExpiresAt: time.Unix(int64(b.ExpiresAt), 0), Cert: base64.RawURLEncoding.EncodeToString(raw)})
	}
	return out, nil
}

func (a *Admin) ListRelayTokens(ctx context.Context, _ adminapi.ListRelayTokensRequestObject) (adminapi.ListRelayTokensResponseObject, error) {
	ts, err := a.C.st.ListRelayTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := adminapi.ListRelayTokens200JSONResponse{}
	for _, t := range ts {
		out = append(out, adminapi.RelayToken{Id: t.ID, ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt})
	}
	return out, nil
}

func (a *Admin) CreateRelayToken(ctx context.Context, req adminapi.CreateRelayTokenRequestObject) (adminapi.CreateRelayTokenResponseObject, error) {
	var ttlStr *string
	if req.Body != nil {
		ttlStr = req.Body.Ttl
	}
	ttl, err := parseTTL(ttlStr, 24*time.Hour)
	if err != nil || ttl <= 0 {
		ttl = 24 * time.Hour
	}
	token := randomToken()
	t := store.RelayToken{ID: wire.RandomID(), Hash: store.HashToken(token), ExpiresAt: time.Now().Add(ttl)}
	if err := a.C.st.CreateRelayToken(ctx, t); err != nil {
		return nil, err
	}
	return adminapi.CreateRelayToken201JSONResponse{Id: t.ID, ExpiresAt: t.ExpiresAt, CreatedAt: time.Now(), Token: token}, nil
}

func (a *Admin) RevokeRelayToken(ctx context.Context, req adminapi.RevokeRelayTokenRequestObject) (adminapi.RevokeRelayTokenResponseObject, error) {
	if err := a.C.st.DeleteRelayToken(ctx, req.TokenId); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.RevokeRelayToken404JSONResponse{NotFoundJSONResponse: notFoundErr("token")}, nil
		}
		return nil, err
	}
	return adminapi.RevokeRelayToken204Response{}, nil
}
