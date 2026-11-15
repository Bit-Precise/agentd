package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"agentd/internal/adminapi"
	"agentd/internal/identity"
	"agentd/internal/routes"
	"agentd/internal/store"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

func apiMatches(ms []*pb.Match) []adminapi.Match {
	out := make([]adminapi.Match, 0, len(ms))
	for _, m := range ms {
		kind := "domain"
		if m.Kind == pb.Match_SUFFIX {
			kind = "suffix"
		}
		out = append(out, adminapi.Match{Kind: adminapi.MatchKind(kind), Value: m.Value})
	}
	return out
}
func apiRoute(ws string, r routes.Route) adminapi.Route {
	protos := make([]adminapi.Proto, 0, len(r.Protos))
	for _, p := range r.Protos {
		if p == pb.Proto_PROTO_SSH {
			protos = append(protos, adminapi.ProtoSsh)
		} else {
			protos = append(protos, adminapi.ProtoTls)
		}
	}
	return adminapi.Route{Id: idFor("route", ws+"/"+r.ID), From: r.From, Proto: protos, Domains: apiMatches(r.Domains), To: r.To, Status: adminapi.RouteStatus("active")}
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
		kind := pb.Match_DOMAIN
		if m.Kind == adminapi.Suffix {
			kind = pb.Match_SUFFIX
		}
		r.Domains = append(r.Domains, &pb.Match{Kind: kind, Value: strings.ToLower(strings.TrimSuffix(m.Value, "."))})
	}
	return r, r.Validate()
}
func apiTable(ws string, t routes.Table) adminapi.RouteTable {
	out := adminapi.RouteTable{Version: int(t.Version), Default: adminapi.RouteTableDefault(t.Default), Routes: []adminapi.Route{}}
	for _, r := range t.Routes {
		out.Routes = append(out.Routes, apiRoute(ws, r))
	}
	return out
}

func (a *Admin) workspaceFor(ctx context.Context, id string) (store.Workspace, error) {
	return a.resolveWorkspace(ctx, id)
}
func (a *Admin) GetRouteTable(ctx context.Context, req adminapi.GetRouteTableRequestObject) (adminapi.GetRouteTableResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return nil, err
	}
	t, err := a.C.st.GetRouteTable(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	return adminapi.GetRouteTable200JSONResponse(apiTable(ws.Name, t)), nil
}
func (a *Admin) ReplaceRouteTable(ctx context.Context, req adminapi.ReplaceRouteTableRequestObject) (adminapi.ReplaceRouteTableResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.ReplaceRouteTable400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
	}
	if req.Body == nil {
		return adminapi.ReplaceRouteTable400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	rs := make([]routes.Route, 0, len(req.Body.Routes))
	for _, r := range req.Body.Routes {
		rr, err := routeFromAPI(r)
		if err != nil {
			return adminapi.ReplaceRouteTable400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
		}
		rs = append(rs, rr)
	}
	def := "direct"
	if req.Body.Default != nil {
		def = string(*req.Body.Default)
	}
	if def != routes.Direct && def != routes.Reject {
		return adminapi.ReplaceRouteTable400JSONResponse{BadRequestJSONResponse: badRequest("default must be direct or reject")}, nil
	}
	if err := a.C.st.ReplaceRoutes(ctx, ws.Name, rs, def); err != nil {
		return nil, err
	}
	a.C.Changed(ctx, ws.Name)
	t, _ := a.C.st.GetRouteTable(ctx, ws.Name)
	return adminapi.ReplaceRouteTable200JSONResponse(apiTable(ws.Name, t)), nil
}
func (a *Admin) AddRoute(ctx context.Context, req adminapi.AddRouteRequestObject) (adminapi.AddRouteResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.AddRoute400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
	}
	if req.Body == nil {
		return adminapi.AddRoute400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	r, err := routeFromAPI(*req.Body)
	if err != nil {
		return adminapi.AddRoute400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
	}
	id, err := a.C.st.AddRoute(ctx, ws.Name, r)
	if err != nil {
		return nil, err
	}
	a.C.Changed(ctx, ws.Name)
	r.ID = id
	return adminapi.AddRoute201JSONResponse(apiRoute(ws.Name, r)), nil
}
func (a *Admin) DeleteRoute(ctx context.Context, req adminapi.DeleteRouteRequestObject) (adminapi.DeleteRouteResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.DeleteRoute404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	raw := req.RouteId
	rs, _ := a.C.st.GetRouteTable(ctx, ws.Name)
	for _, r := range rs.Routes {
		if r.ID == raw || idFor("route", ws.Name+"/"+r.ID) == raw {
			if err := a.C.st.DeleteRoute(ctx, ws.Name, r.ID); err != nil {
				return nil, err
			}
			a.C.Changed(ctx, ws.Name)
			return adminapi.DeleteRoute204Response{}, nil
		}
	}
	return adminapi.DeleteRoute404JSONResponse{NotFoundJSONResponse: notFoundErr("route")}, nil
}

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
	out.Id = idFor("policy", r.ID)
	out.Status = adminapi.PolicyStatus("active")
	if out.Subjects == nil {
		out.Subjects = []string{}
	}
	return out
}
func (a *Admin) ListPolicies(ctx context.Context, req adminapi.ListPoliciesRequestObject) (adminapi.ListPoliciesResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return nil, err
	}
	recs, err := a.C.st.ListPolicies(ctx, ws.Name)
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
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.AddPolicy400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
	}
	if req.Body == nil {
		return adminapi.AddPolicy400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	raw, err := statementFromAPI(*req.Body)
	if err != nil {
		return adminapi.AddPolicy400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
	}
	id, err := a.C.st.AddPolicy(ctx, ws.Name, raw)
	if err != nil {
		return nil, err
	}
	a.C.Changed(ctx, ws.Name)
	return adminapi.AddPolicy201JSONResponse(apiStatement(store.PolicyRecord{ID: id, Statement: raw})), nil
}
func (a *Admin) ReplacePolicies(ctx context.Context, req adminapi.ReplacePoliciesRequestObject) (adminapi.ReplacePoliciesResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.ReplacePolicies400JSONResponse{BadRequestJSONResponse: badRequest("unknown workspace")}, nil
	}
	if req.Body == nil {
		return adminapi.ReplacePolicies400JSONResponse{BadRequestJSONResponse: badRequest("empty body")}, nil
	}
	raws := make([]json.RawMessage, 0, len(*req.Body))
	for _, st := range *req.Body {
		raw, err := statementFromAPI(st)
		if err != nil {
			return adminapi.ReplacePolicies400JSONResponse{BadRequestJSONResponse: badRequest(err.Error())}, nil
		}
		raws = append(raws, raw)
	}
	ids, err := a.C.st.ReplacePolicies(ctx, ws.Name, raws)
	if err != nil {
		return nil, err
	}
	a.C.Changed(ctx, ws.Name)
	out := adminapi.ReplacePolicies200JSONResponse{}
	for i, id := range ids {
		out = append(out, apiStatement(store.PolicyRecord{ID: id, Statement: raws[i]}))
	}
	return out, nil
}
func (a *Admin) DeletePolicy(ctx context.Context, req adminapi.DeletePolicyRequestObject) (adminapi.DeletePolicyResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
	if err != nil {
		return adminapi.DeletePolicy404JSONResponse{NotFoundJSONResponse: notFoundErr("workspace")}, nil
	}
	recs, _ := a.C.st.ListPolicies(ctx, ws.Name)
	for _, r := range recs {
		if r.ID == req.PolicyId || idFor("policy", r.ID) == req.PolicyId {
			if err := a.C.st.DeletePolicy(ctx, ws.Name, r.ID); err != nil {
				return nil, err
			}
			a.C.Changed(ctx, ws.Name)
			return adminapi.DeletePolicy204Response{}, nil
		}
	}
	return adminapi.DeletePolicy404JSONResponse{NotFoundJSONResponse: notFoundErr("policy")}, nil
}

func (a *Admin) ListServices(ctx context.Context, req adminapi.ListServicesRequestObject) (adminapi.ListServicesResponseObject, error) {
	ws, err := a.workspaceFor(ctx, req.WorkspaceId)
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
		n, nerr := a.C.st.GetNode(ctx, ws.Name, sv.Node)
		online := false
		if nerr == nil {
			online, _ = a.C.NodeOnline(n.PublicKey)
		}
		protoName := adminapi.ServiceProto(sv.Proto)
		state := adminapi.ServiceState("ready")
		if sv.Proto == "http" && !ready {
			state = adminapi.ServiceState("cert_pending")
		}
		s := adminapi.Service{Name: sv.Name, Id: idFor("service", ws.Name+"/"+sv.Name), Fqdn: sv.Name + "." + ws.BaseDomain, Proto: protoName, NodeOnline: &online, State: state, Status: adminapi.ServiceStatus("ready")}
		if nerr == nil {
			nid := idFor("node", ws.Name+"/"+n.Name)
			s.NodeId = &nid
		}
		if sv.Proto == "http" {
			p := 443
			s.Port = &p
			pub := false
			if nerr == nil {
				if pol, e := a.C.effectivePolicy(ctx, ws, n, "service"); e == nil {
					for _, r := range pol.Services {
						if r.Name == sv.Name && r.Action == pb.Action_ACTION_ALLOW && len(r.PublicKey) == 0 {
							pub = true
						}
					}
				}
			}
			s.Public = &pub
		} else {
			p := 22
			s.Port = &p
		}
		out = append(out, s)
	}
	return out, nil
}

// ---------------------------------------------------------------- relay resources

func (a *Admin) apiRelay(ctx context.Context, r store.Relay) adminapi.Relay {
	connected, since := a.C.RelayConnected(r.Name)
	status := adminapi.RelayStatus("active")
	if !connected {
		status = adminapi.RelayStatus("failed")
	}
	out := adminapi.Relay{Id: idFor("relay", r.Name), Name: r.Name, PublicKey: wireKey(r.PublicKey), Url: r.URL, Connected: connected, Status: status}
	if len(r.Transports) > 0 {
		tr := r.Transports
		out.Transports = &tr
	}
	if r.STUN != "" {
		out.Stun = &r.STUN
	}
	if connected {
		out.ConnectedSince = &since
	}
	wss, _ := a.C.st.WorkspacesOfRelay(ctx, r.Name)
	online := 0
	for _, ws := range wss {
		online += a.C.OnlineCount(ws.Name)
	}
	out.NodesOnline = &online
	return out
}
func wireKey(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
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
	u, err := url.Parse(b.Url)
	if err != nil || u.Scheme != "https" || u.Host == "" {
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
		code, c := classify(err)
		if code == 409 {
			if c == "CONFLICT" {
				c = "NAME_TAKEN"
			}
			return adminapi.RegisterRelay409JSONResponse(apiErr(c, err.Error())), nil
		}
		return nil, err
	}
	r, _ = a.C.st.GetRelay(ctx, b.Name)
	return adminapi.RegisterRelay201JSONResponse(a.apiRelay(ctx, r)), nil
}
func (a *Admin) resolveRelay(ctx context.Context, id string) (store.Relay, error) {
	if r, err := a.C.st.GetRelay(ctx, id); err == nil {
		return r, nil
	}
	rs, err := a.C.st.ListRelays(ctx)
	if err != nil {
		return store.Relay{}, err
	}
	for _, r := range rs {
		if idFor("relay", r.Name) == id {
			return r, nil
		}
	}
	return store.Relay{}, store.ErrNotFound
}
func (a *Admin) GetRelay(ctx context.Context, req adminapi.GetRelayRequestObject) (adminapi.GetRelayResponseObject, error) {
	r, err := a.resolveRelay(ctx, req.RelayId)
	if err != nil {
		return adminapi.GetRelay404JSONResponse{NotFoundJSONResponse: notFoundErr("relay")}, nil
	}
	return adminapi.GetRelay200JSONResponse(a.apiRelay(ctx, r)), nil
}
func (a *Admin) RemoveRelay(ctx context.Context, req adminapi.RemoveRelayRequestObject) (adminapi.RemoveRelayResponseObject, error) {
	r, err := a.resolveRelay(ctx, req.RelayId)
	if err != nil {
		return adminapi.RemoveRelay404JSONResponse{NotFoundJSONResponse: notFoundErr("relay")}, nil
	}
	if connected, _ := a.C.RelayConnected(r.Name); connected {
		return adminapi.RemoveRelay409JSONResponse(apiErr("RELAY_IN_USE", "relay is still connected")), nil
	}
	if err := a.C.st.DeleteRelay(ctx, r.Name); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return adminapi.RemoveRelay409JSONResponse(apiErr("RELAY_IN_USE", err.Error())), nil
		}
		return nil, err
	}
	return adminapi.RemoveRelay204Response{}, nil
}
func (a *Admin) ListRelayCerts(ctx context.Context, req adminapi.ListRelayCertsRequestObject) (adminapi.ListRelayCertsResponseObject, error) {
	r, err := a.resolveRelay(ctx, req.RelayId)
	if err != nil {
		return adminapi.ListRelayCerts404JSONResponse{NotFoundJSONResponse: notFoundErr("relay")}, nil
	}
	wss, _ := a.C.st.ListWorkspaces(ctx)
	out := adminapi.ListRelayCerts200JSONResponse{}
	for _, ws := range wss {
		c, err := a.C.relayCert(ws, r)
		if err != nil {
			continue
		}
		rb, _ := wire.DecodeRelayCert(c)
		raw, _ := proto.Marshal(c)
		out = append(out, adminapi.RelayCert{Id: idFor("relay-cert", r.Name+"/"+ws.Name), RelayId: idFor("relay", r.Name), WorkspaceId: idFor("workspace", ws.Name), IssuedAt: time.Unix(int64(rb.IssuedAt), 0), ExpiresAt: time.Unix(int64(rb.ExpiresAt), 0), State: adminapi.CertificateStateReady, Cert: base64.RawURLEncoding.EncodeToString(raw)})
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
		out = append(out, adminapi.RelayToken{Id: idFor("relay-token", t.ID), ExpiresAt: t.ExpiresAt, CreatedAt: t.CreatedAt, Status: adminapi.RelayTokenStatus("active")})
	}
	return out, nil
}
func (a *Admin) CreateRelayToken(ctx context.Context, req adminapi.CreateRelayTokenRequestObject) (adminapi.CreateRelayTokenResponseObject, error) {
	var p *string
	if req.Body != nil {
		p = req.Body.Ttl
	}
	ttl, err := parseTTL(p, 24*time.Hour)
	if err != nil || ttl <= 0 {
		return nil, err
	}
	plain := randomToken()
	t := store.RelayToken{ID: uuid.NewString(), Hash: store.HashToken(plain), ExpiresAt: time.Now().Add(ttl)}
	if err := a.C.st.CreateRelayToken(ctx, t); err != nil {
		return nil, err
	}
	return adminapi.CreateRelayToken201JSONResponse{Id: idFor("relay-token", t.ID), ExpiresAt: t.ExpiresAt, CreatedAt: time.Now(), Status: adminapi.RelayTokenStatus("active"), Token: plain}, nil
}
func (a *Admin) RevokeRelayToken(ctx context.Context, req adminapi.RevokeRelayTokenRequestObject) (adminapi.RevokeRelayTokenResponseObject, error) {
	ts, _ := a.C.st.ListRelayTokens(ctx)
	for _, t := range ts {
		if t.ID == req.TokenId || idFor("relay-token", t.ID) == req.TokenId {
			if err := a.C.st.DeleteRelayToken(ctx, t.ID); err != nil {
				return nil, err
			}
			return adminapi.RevokeRelayToken204Response{}, nil
		}
	}
	return adminapi.RevokeRelayToken404JSONResponse{NotFoundJSONResponse: notFoundErr("relay token")}, nil
}
