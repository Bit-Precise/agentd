package control

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"agentd/internal/policy"
	"agentd/internal/routes"
	"agentd/internal/store"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

func answerErr(st pb.Status, msg string) *pb.RelayAnswer {
	return &pb.RelayAnswer{Status: st, Message: msg, TtlSeconds: ttlError}
}

// Lookup answers one RelayLookup from relay.
func (c *Coordinator) Lookup(ctx context.Context, relay string, q *pb.RelayLookup) *pb.RelayAnswer {
	var a *pb.RelayAnswer
	switch x := q.Query.(type) {
	case *pb.RelayLookup_Node:
		a = c.lookupNode(ctx, relay, x.Node)
	case *pb.RelayLookup_Join:
		a = c.join(ctx, relay, x.Join)
	case *pb.RelayLookup_Stream:
		a = c.lookupStream(ctx, relay, x.Stream)
	case *pb.RelayLookup_Cert:
		a = c.lookupCert(ctx, relay, x.Cert)
	default:
		a = answerErr(pb.Status_BAD_REQUEST, "unknown lookup")
	}
	a.RequestId = q.RequestId
	return a
}

func (c *Coordinator) wrongRelay(ctx context.Context, ws store.Workspace) *pb.RelayAnswer {
	a := answerErr(pb.Status_WRONG_RELAY, "workspace is assigned to relay "+ws.Relay)
	if r, err := c.st.GetRelay(ctx, ws.Relay); err == nil {
		if cert, err := c.relayCert(ws, r); err == nil {
			a.Result = &pb.RelayAnswer_AssignedRelay{AssignedRelay: cert}
		}
	}
	return a
}

func (c *Coordinator) nodeAnswer(ctx context.Context, ws store.Workspace, n store.Node, ttl uint32) *pb.RelayAnswer {
	welcome, err := c.signedWelcome(ctx, ws, n)
	if err != nil {
		c.log.Error("welcome", "node", n.Name, "err", err)
		return answerErr(pb.Status_SERVER_BUSY, "cannot build welcome")
	}
	return &pb.RelayAnswer{Status: pb.Status_OK, TtlSeconds: ttl, Result: &pb.RelayAnswer_Node{Node: &pb.NodeInfo{
		Identity: n.PublicKey, Workspace: ws.BaseDomain, Name: n.Name, RoleCaps: pbRoles(n.RoleCaps), Welcome: welcome}}}
}

func (c *Coordinator) lookupNode(ctx context.Context, relay string, q *pb.NodeLookup) *pb.RelayAnswer {
	n, ws, err := c.st.GetNodeByKey(ctx, q.Identity)
	if errors.Is(err, store.ErrNotFound) {
		return answerErr(pb.Status_NOT_A_MEMBER, "this key is not a member of any workspace")
	}
	if err != nil {
		return answerErr(pb.Status_SERVER_BUSY, err.Error())
	}
	if ws.Relay != relay {
		return c.wrongRelay(ctx, ws)
	}
	return c.nodeAnswer(ctx, ws, n, ttlOK)
}

func (c *Coordinator) join(ctx context.Context, relay string, q *pb.JoinLookup) *pb.RelayAnswer {
	ws, err := c.st.GetWorkspaceByDomain(ctx, q.Workspace)
	if errors.Is(err, store.ErrNotFound) {
		return &pb.RelayAnswer{Status: pb.Status_TOKEN_INVALID, Message: "unknown workspace"}
	}
	if err != nil {
		return &pb.RelayAnswer{Status: pb.Status_SERVER_BUSY, Message: err.Error()}
	}
	if ws.Relay != relay {
		a := c.wrongRelay(ctx, ws)
		a.TtlSeconds = 0
		return a
	}
	n, err := c.st.Join(ctx, store.JoinRequest{TokenHash: store.HashToken(q.Token), WorkspaceDomain: q.Workspace, Identity: q.Identity, ProposedName: q.ProposedName, Timestamp: q.Timestamp})
	if err != nil {
		return &pb.RelayAnswer{Status: wire.StatusOf(err), Message: err.Error()}
	}
	c.log.Info("node joined", "workspace", ws.Name, "node", n.Name)
	ws, _ = c.st.GetWorkspace(ctx, ws.Name)
	c.Changed(ctx, ws.Name)
	return c.nodeAnswer(ctx, ws, n, 0)
}

func (c *Coordinator) lookupCert(ctx context.Context, relay string, q *pb.CertLookup) *pb.RelayAnswer {
	ws, err := c.st.GetWorkspaceByDomain(ctx, q.Workspace)
	if err != nil || ws.Relay != relay {
		return answerErr(pb.Status_BAD_REQUEST, "workspace not assigned to this relay")
	}
	wc := c.workspaceCert(ctx, ws)
	if wc == nil {
		return answerErr(pb.Status_SERVICE_NOT_READY, "certificate not issued yet")
	}
	return &pb.RelayAnswer{Status: pb.Status_OK, TtlSeconds: ttlOK, Result: &pb.RelayAnswer_Certs{Certs: &pb.WorkspaceCerts{Certs: []*pb.WorkspaceCert{wc}}}}
}

// identities returns the requester's identity set: its key, its groups' keys
// and the workspace key (design 6.6).
func (c *Coordinator) identities(ctx context.Context, ws store.Workspace, n store.Node) ([][]byte, []string, error) {
	groups, err := c.st.ListGroups(ctx, ws.Name)
	if err != nil {
		return nil, nil, err
	}
	ids := [][]byte{n.PublicKey}
	names := groupsOf(groups, n.Name)
	for _, g := range groups {
		for _, m := range g.Members {
			if m == n.Name {
				ids = append(ids, g.PublicKey)
			}
		}
	}
	return append(ids, ws.PublicKey), names, nil
}

func serviceName(domain, base string) (string, bool) {
	name, ok := strings.CutSuffix(domain, "."+base)
	if !ok || strings.Contains(name, ".") || name == "" {
		return "", false
	}
	return name, true
}

func (c *Coordinator) lookupStream(ctx context.Context, relay string, q *pb.StreamLookup) *pb.RelayAnswer {
	ws, err := c.st.GetWorkspaceByDomain(ctx, q.Workspace)
	if err != nil {
		return answerErr(pb.Status_BAD_REQUEST, "unknown workspace")
	}
	if ws.Relay != relay {
		return answerErr(pb.Status_WRONG_RELAY, "workspace is not assigned to this relay")
	}
	var from *store.Node
	var ids [][]byte
	var groupNames []string
	if len(q.From) > 0 {
		n, w2, err := c.st.GetNodeByKey(ctx, q.From)
		if err != nil {
			return answerErr(pb.Status_NOT_A_MEMBER, "requester is not a member")
		}
		if w2.Name != ws.Name {
			return answerErr(pb.Status_WORKSPACE_MISMATCH, "requester belongs to another workspace")
		}
		from = &n
		if ids, groupNames, err = c.identities(ctx, ws, n); err != nil {
			return answerErr(pb.Status_SERVER_BUSY, err.Error())
		}
	}
	switch q.Kind {
	case pb.Kind_KIND_TCP:
		return c.lookupTCP(ctx, ws, from, ids, groupNames, q)
	case pb.Kind_KIND_TASK:
		return c.lookupTask(ctx, ws, from, ids, q)
	}
	return answerErr(pb.Status_BAD_REQUEST, "unknown stream kind")
}

func (c *Coordinator) lookupTCP(ctx context.Context, ws store.Workspace, from *store.Node, ids [][]byte, groupNames []string, q *pb.StreamLookup) *pb.RelayAnswer {
	domain := policy.NormalizeDomain(q.Domain)
	if name, ok := serviceName(domain, ws.BaseDomain); ok {
		return c.lookupService(ctx, ws, from, ids, name, q)
	}
	if from == nil {
		return answerErr(pb.Status_BAD_REQUEST, "anonymous access only reaches HTTP services")
	}
	if !from.HasRole("ingress") {
		return answerErr(pb.Status_ROLE_NOT_ALLOWED, "requester has no ingress role")
	}
	table, err := c.st.GetRouteTable(ctx, ws.Name)
	if err != nil {
		return answerErr(pb.Status_SERVER_BUSY, err.Error())
	}
	route := &pb.StreamRoute{RulesVersion: table.Version}
	to := table.Select(routes.Requester{Name: from.Name, Groups: groupNames, Key: from.PublicKey}, q.Proto, domain)
	if to == routes.Direct || to == routes.Reject {
		return &pb.RelayAnswer{Status: pb.Status_NO_RULE, Message: "no egress for " + domain, TtlSeconds: ttlOK, Result: &pb.RelayAnswer_Route{Route: route}}
	}
	target, err := c.st.GetNode(ctx, ws.Name, to)
	if err != nil {
		return &pb.RelayAnswer{Status: pb.Status_NO_RULE, Message: "egress node " + to + " does not exist", TtlSeconds: ttlError, Result: &pb.RelayAnswer_Route{Route: route}}
	}
	if !target.HasRole("egress") {
		return answerErr(pb.Status_ROLE_NOT_ALLOWED, "egress node "+to+" has no egress role")
	}
	pol, err := c.effectivePolicy(ctx, ws, target, "egress")
	if err != nil {
		return answerErr(pb.Status_SERVER_BUSY, err.Error())
	}
	port := q.Port
	if port == 0 {
		port = policy.DefaultPort(q.Proto)
	}
	if d := policy.Egress(pol.Egress, ids, q.Proto, domain, port); d.Status != pb.Status_OK {
		return answerErr(pb.Status_ACL_DENIED, to+": "+d.Reason)
	}
	route.TargetKind, route.Target, route.TargetName = pb.StreamRoute_EGRESS, target.PublicKey, target.Name
	return &pb.RelayAnswer{Status: pb.Status_OK, TtlSeconds: ttlOK, Result: &pb.RelayAnswer_Route{Route: route}}
}

func (c *Coordinator) lookupService(ctx context.Context, ws store.Workspace, from *store.Node, ids [][]byte, name string, q *pb.StreamLookup) *pb.RelayAnswer {
	svcs, err := c.st.ListServices(ctx, ws.Name)
	if err != nil {
		return answerErr(pb.Status_SERVER_BUSY, err.Error())
	}
	var sv *store.Service
	for i := range svcs {
		if svcs[i].Name == name {
			sv = &svcs[i]
		}
	}
	if sv == nil {
		return answerErr(pb.Status_SERVICE_UNKNOWN, "no service "+name)
	}
	target, err := c.st.GetNode(ctx, ws.Name, sv.Node)
	if err != nil {
		return answerErr(pb.Status_SERVICE_UNKNOWN, "service node missing")
	}
	if from != nil && !from.HasRole("ingress") {
		return answerErr(pb.Status_ROLE_NOT_ALLOWED, "requester has no ingress role")
	}
	if !target.HasRole("service") {
		return answerErr(pb.Status_ROLE_NOT_ALLOWED, "service node has no service role")
	}
	ready := c.certReady(ctx, ws)
	route := &pb.StreamRoute{Target: target.PublicKey, TargetName: target.Name, Service: c.pbService(ctx, ws, *sv, target.PublicKey, ready)}
	if sv.Proto == "ssh" {
		if from == nil {
			return answerErr(pb.Status_BAD_REQUEST, "ssh services are reachable only through member ingress")
		}
		if q.Proto != pb.Proto_PROTO_SSH || (q.Port != 0 && q.Port != 22) {
			return answerErr(pb.Status_BAD_REQUEST, "service "+name+" is ssh on port 22")
		}
		route.TargetKind = pb.StreamRoute_SERVICE_NODE
	} else {
		if q.Proto != pb.Proto_PROTO_TLS || (q.Port != 0 && q.Port != 443) {
			return answerErr(pb.Status_BAD_REQUEST, "service "+name+" is https on port 443")
		}
		if !ready {
			return answerErr(pb.Status_SERVICE_NOT_READY, "certificate for "+ws.BaseDomain+" is not issued yet")
		}
		route.TargetKind = pb.StreamRoute_EDGE
	}
	pol, err := c.effectivePolicy(ctx, ws, target, "service")
	if err != nil {
		return answerErr(pb.Status_SERVER_BUSY, err.Error())
	}
	if d := policy.Service(pol.Services, ids, name); d.Status != pb.Status_OK {
		return answerErr(pb.Status_ACL_DENIED, name+": "+d.Reason)
	}
	return &pb.RelayAnswer{Status: pb.Status_OK, TtlSeconds: ttlOK, Result: &pb.RelayAnswer_Route{Route: route}}
}

func (c *Coordinator) lookupTask(ctx context.Context, ws store.Workspace, from *store.Node, ids [][]byte, q *pb.StreamLookup) *pb.RelayAnswer {
	if from == nil {
		return answerErr(pb.Status_BAD_REQUEST, "tasks need a member requester")
	}
	target, w2, err := c.st.GetNodeByKey(ctx, q.Executor)
	if err != nil || w2.Name != ws.Name {
		return answerErr(pb.Status_BAD_REQUEST, "executor is not a member of this workspace")
	}
	if !from.HasRole("submitter") {
		return answerErr(pb.Status_ROLE_NOT_ALLOWED, "requester has no submitter role")
	}
	if !target.HasRole("executor") {
		return answerErr(pb.Status_ROLE_NOT_ALLOWED, target.Name+" has no executor role")
	}
	pol, err := c.effectivePolicy(ctx, ws, target, "executor")
	if err != nil {
		return answerErr(pb.Status_SERVER_BUSY, err.Error())
	}
	if d := policy.PrecheckExec(pol.Exec, ids); d.Status != pb.Status_OK {
		return answerErr(pb.Status_ACL_DENIED, target.Name+": "+d.Reason)
	}
	return &pb.RelayAnswer{Status: pb.Status_OK, TtlSeconds: ttlOK, Result: &pb.RelayAnswer_Route{Route: &pb.StreamRoute{TargetKind: pb.StreamRoute_EXECUTOR, Target: target.PublicKey, TargetName: target.Name}}}
}

// ---------------------------------------------------------------- node messages

// HandleNodeMessage processes a message a node sent on its control stream.
func (c *Coordinator) HandleNodeMessage(ctx context.Context, relay string, nm *pb.NodeMessage) {
	n, ws, err := c.st.GetNodeByKey(ctx, nm.Identity)
	if err != nil || ws.Relay != relay {
		return
	}
	switch m := nm.Msg.GetMsg().(type) {
	case *pb.ControlMessage_Advertise:
		res := c.advertise(ctx, ws, n, m.Advertise)
		c.deliver(ws, n.PublicKey, &pb.ControlMessage{Msg: &pb.ControlMessage_AdvertiseResult{AdvertiseResult: res}})
		c.Changed(ctx, ws.Name)
	case *pb.ControlMessage_PolicyApplied:
		if m.PolicyApplied.Applied {
			_ = c.st.SetPolicyApplied(ctx, n.PublicKey, m.PolicyApplied.Version)
		}
	case *pb.ControlMessage_Pull:
		if w, err := c.buildWelcome(ctx, ws, n); err == nil {
			c.deliver(ws, n.PublicKey, &pb.ControlMessage{Msg: &pb.ControlMessage_Welcome{Welcome: w}})
		}
	case *pb.ControlMessage_RelayReport:
		c.log.Warn("node reports relay problem", "workspace", ws.Name, "node", n.Name, "status", m.RelayReport.Status, "message", m.RelayReport.Message)
	}
}

func sourceName(s pb.PolicySource) string {
	if s == pb.PolicySource_POLICY_SOURCE_SERVER {
		return "server"
	}
	return "local"
}

func (c *Coordinator) advertise(ctx context.Context, ws store.Workspace, n store.Node, a *pb.Advertise) *pb.AdvertiseResult {
	if len(a.Services) > 0 && !n.HasRole("service") {
		return &pb.AdvertiseResult{Status: pb.Status_ROLE_NOT_ALLOWED, Message: "this node may not publish services"}
	}
	if a.Executor != nil && !n.HasRole("executor") {
		return &pb.AdvertiseResult{Status: pb.Status_ROLE_NOT_ALLOWED, Message: "this node may not act as an executor"}
	}
	var svcs []store.Service
	for _, d := range a.Services {
		proto := "http"
		if d.Proto == pb.Proto_PROTO_SSH {
			proto = "ssh"
		}
		svcs = append(svcs, store.Service{Name: d.Name, Proto: proto})
	}
	accepted, rejected, err := c.st.ReplaceNodeServices(ctx, ws.Name, n.Name, svcs)
	if err != nil {
		return &pb.AdvertiseResult{Status: pb.Status_BAD_REQUEST, Message: err.Error()}
	}
	sources := map[string]string{
		"egress":   sourceName(a.GetPolicySources().GetEgress()),
		"service":  sourceName(a.GetPolicySources().GetService()),
		"executor": sourceName(a.GetPolicySources().GetExecutor()),
	}
	ex := a.Executor
	if ex != nil && len(ex.Description) > 512 {
		ex.Description = ex.Description[:512]
	}
	if err := c.st.SaveAdvert(ctx, ws.Name, n.Name, sources, a.Policy, ex, a.P2PEnabled); err != nil {
		return &pb.AdvertiseResult{Status: pb.Status_BAD_REQUEST, Message: err.Error()}
	}
	ready := c.certReady(ctx, ws)
	res := &pb.AdvertiseResult{Status: pb.Status_OK, RejectedServices: rejected}
	for _, sv := range accepted {
		res.Services = append(res.Services, c.pbService(ctx, ws, sv, n.PublicKey, ready))
	}
	return res
}

// isRelayKey reports whether key belongs to the relay of the node's workspace.
func isRelayKey(relays []*pb.RelayCert, key []byte) bool {
	for _, rc := range relays {
		if b, err := wire.DecodeRelayCert(rc); err == nil && bytes.Equal(b.Identity, key) {
			return true
		}
	}
	return false
}
