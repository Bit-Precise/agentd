package relay

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/session"
	"agentd/internal/stream"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// AckTimeout is ACK_TIMEOUT.
const AckTimeout = 15 * time.Second

// forward handles a data stream a node opened (checklist A, protocol 4.1):
// local checks, then the control plane's route and precheck, then the
// target's presence, then the second leg.
func (h *Hub) forward(ns *nodeSession, st *session.Stream) {
	trace := randomBytes(16)
	st.SetReadDeadline(time.Now().Add(AckTimeout))
	var so pb.StreamOpen
	if err := wire.ReadMsg(st, &so, wire.OpenMax); err != nil {
		stream.Fail(st, pb.Status_BAD_REQUEST, "unreadable StreamOpen", trace)
		return
	}
	st.SetReadDeadline(time.Time{})
	if len(so.Certs) > wire.OpenMaxCerts {
		stream.Fail(st, pb.Status_BAD_REQUEST, "too many membership certificates", trace)
		return
	}
	var body pb.OpenBody
	if so.Open == nil || proto.Unmarshal(so.Open.Body, &body) != nil {
		stream.Fail(st, pb.Status_BAD_REQUEST, "undecodable open", trace)
		return
	}
	// Steps 2 to 5 before the signature, then 6 (signature), 7 and 8.
	if status, msg := h.checkOpenPre(ns, &body); status != pb.Status_OK {
		stream.Fail(st, status, msg, trace)
		return
	}
	if !wire.Verify(body.From, wire.CtxOpen, so.Open.Body, so.Open.Sig) {
		stream.Fail(st, pb.Status_BAD_SIGNATURE, "open signature does not verify", trace)
		return
	}
	if !wire.WithinWindow(body.IssuedAt, time.Now()) {
		stream.Fail(st, pb.Status_TIMESTAMP_OUT_OF_WINDOW, "issued_at outside the time window", trace)
		return
	}
	if !h.nonces.Check(body.From, body.Nonce, time.Now()) {
		stream.Fail(st, pb.Status_REPLAY, "nonce already seen", trace)
		return
	}

	q := &pb.StreamLookup{Workspace: body.Workspace, From: body.From, Kind: body.Kind}
	if t := body.Tcp; t != nil {
		q.Proto, q.Domain, q.Port = t.Proto, t.Domain, t.Port
	}
	if t := body.Task; t != nil {
		q.Executor = t.Executor
	}
	ctx, cancel := context.WithTimeout(context.Background(), LookupTimeout+time.Second)
	a, err := h.backend.Lookup(ctx, &pb.RelayLookup{Query: &pb.RelayLookup_Stream{Stream: q}}, cached)
	cancel()
	if err != nil {
		stream.Fail(st, pb.Status_CONTROL_NOT_READY, "control plane unreachable", trace)
		return
	}
	route := a.GetRoute()
	if a.Status != pb.Status_OK || route == nil {
		status := a.Status
		if status == pb.Status_OK {
			status = pb.Status_BAD_REQUEST
		}
		stream.Reject(st, &pb.Ack{Status: status, Message: a.Message, RulesVersion: route.GetRulesVersion(), TraceId: trace})
		return
	}
	if route.TargetKind == pb.StreamRoute_EDGE {
		if h.edge == nil {
			stream.Fail(st, pb.Status_SERVICE_NOT_READY, "edge disabled", trace)
			return
		}
		if err := wire.WriteMsg(st, &pb.Ack{Status: pb.Status_OK, RulesVersion: route.RulesVersion, TraceId: trace}); err != nil {
			st.Reset()
			return
		}
		h.edge.ServeMember(st, &peerInfo{id: ns.id, name: ns.name, ws: ns.ws})
		return
	}
	target := h.session(route.Target)
	if target == nil {
		stream.Reject(st, &pb.Ack{Status: pb.Status_TARGET_OFFLINE, Message: route.TargetName + " is not connected to this relay", RulesVersion: route.RulesVersion, TraceId: trace})
		return
	}
	octx, ocancel := context.WithTimeout(context.Background(), AckTimeout)
	out, err := target.mux.OpenStream(octx)
	ocancel()
	if err != nil {
		stream.Fail(st, pb.Status_TARGET_OFFLINE, "cannot open a stream to "+route.TargetName, trace)
		return
	}
	so.Relay = &pb.RelayInfo{FromName: ns.name, RulesVersion: route.RulesVersion, TraceId: trace, RelayedAt: uint64(time.Now().UnixMilli())}
	if err := wire.WriteMsg(out, &so); err != nil {
		out.Reset()
		stream.Fail(st, pb.Status_TARGET_OFFLINE, "target stream failed", trace)
		return
	}
	// Early data flows upstream before the Ack (protocol 6.1).
	up := make(chan struct{})
	go func() {
		defer close(up)
		if _, err := copyHalf(out, st); err != nil {
			out.Reset()
			st.Reset()
		}
	}()
	ack, err := stream.ReadAck(out, AckTimeout)
	if err != nil {
		out.Reset()
		stream.Fail(st, pb.Status_TIMEOUT, "no Ack from "+route.TargetName, trace)
		return
	}
	if len(ack.TraceId) == 0 {
		ack.TraceId = trace
	}
	if ack.Status != pb.Status_OK {
		out.Reset()
		stream.Reject(st, ack)
		return
	}
	if err := wire.WriteMsg(st, ack); err != nil {
		out.Reset()
		st.Reset()
		return
	}
	if _, err := copyHalf(st, out); err != nil {
		out.Reset()
		st.Reset()
	}
	<-up
	st.Close()
	out.Close()
}

// copyHalf copies src to dst and half-closes dst at EOF.
func copyHalf(dst, src *session.Stream) (int64, error) {
	n, err := copyBuf(dst, src)
	if err == nil {
		dst.CloseWrite()
	}
	return n, err
}

// checkOpenPre runs checklist A steps 2 to 5.
func (h *Hub) checkOpenPre(ns *nodeSession, body *pb.OpenBody) (pb.Status, string) {
	switch {
	case body.Kind == pb.Kind_KIND_CONTROL:
		return pb.Status_BAD_REQUEST, "only stream 1 may be a control stream"
	case body.Kind != pb.Kind_KIND_TCP && body.Kind != pb.Kind_KIND_TASK:
		return pb.Status_BAD_REQUEST, "unknown stream kind"
	case body.Kind == pb.Kind_KIND_TCP && body.Tcp == nil, body.Kind == pb.Kind_KIND_TASK && body.Task == nil:
		return pb.Status_BAD_REQUEST, "stream parameters missing"
	case body.Workspace != ns.ws:
		return pb.Status_WORKSPACE_MISMATCH, "workspace does not match the session"
	case string(body.From) != string(ns.id):
		return pb.Status_FROM_MISMATCH, "from does not match the session identity"
	case string(body.To) != string(h.pub):
		return pb.Status_BAD_REQUEST, "to is not this relay"
	}
	return pb.Status_OK, ""
}

func copyBuf(dst, src *session.Stream) (int64, error) { return stream.Copy(dst, src) }
