package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"net"
	"sync"
	"time"

	"agentd/internal/identity"
	"agentd/internal/session"
	"agentd/internal/stream"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// ControlOpenTimeout bounds the time from handshake to the control stream.
const ControlOpenTimeout = 10 * time.Second

// Hub terminates node sessions (protocol 3, 5.1).
type Hub struct {
	key     ed25519.PrivateKey
	pub     []byte
	backend *Backend
	edge    *Edge
	log     *slog.Logger
	nonces  *wire.NonceCache

	mu       sync.Mutex
	sessions map[string]*nodeSession
	stamps   map[string][]byte
}

type nodeSession struct {
	id      []byte
	ws      string
	name    string
	mux     *session.Mux
	since   time.Time
	welcome *pb.Signed

	cmu     sync.Mutex
	ctrl    *session.Stream
	queue   []*pb.ControlMessage
	closing bool
}

// NewHub creates a hub.
func NewHub(key ed25519.PrivateKey, backend *Backend, log *slog.Logger) *Hub {
	if log == nil {
		log = slog.Default()
	}
	h := &Hub{key: key, pub: identity.Public(key), backend: backend, log: log, nonces: wire.NewNonceCache(wire.NonceCacheTTL, 200000),
		sessions: map[string]*nodeSession{}, stamps: map[string][]byte{}}
	backend.OnDeliver = h.deliver
	backend.OnInvalidate = h.invalidate
	backend.Online = h.online
	return h
}

func (h *Hub) session(id []byte) *nodeSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[string(id)]
}

func (h *Hub) online() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([][]byte, 0, len(h.sessions))
	for _, s := range h.sessions {
		out = append(out, s.id)
	}
	return out
}

// Count is the number of node sessions.
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sessions)
}

func (h *Hub) stampOK(id, ts []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	last := h.stamps[string(id)]
	return last == nil || bytes.Compare(ts, last) > 0
}

func (h *Hub) commitStamp(id, ts []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stamps[string(id)] = append([]byte(nil), ts...)
}

// decide answers a node's ClientHello (protocol 3.2) by asking agentserver.
func (h *Hub) decide(ch *pb.ClientHello, id ed25519.PublicKey, info **pb.NodeInfo) *pb.ServerHello {
	if ch.SessionKind != pb.SessionKind_SESSION_NODE {
		return &pb.ServerHello{Status: pb.Status_BAD_REQUEST, Message: "this endpoint serves node sessions only"}
	}
	if !h.stampOK(id, ch.Timestamp) {
		return &pb.ServerHello{Status: pb.Status_TIMESTAMP_OLD, Message: "handshake timestamp is not newer than the last one; check the clock"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), session.HandshakeTimeout-time.Second)
	defer cancel()
	var a *pb.RelayAnswer
	var err error
	if ch.JoinToken != "" {
		a, err = h.backend.Lookup(ctx, &pb.RelayLookup{Query: &pb.RelayLookup_Join{Join: &pb.JoinLookup{
			Identity: id, Token: ch.JoinToken, ProposedName: ch.ProposedName, Workspace: ch.Workspace, Timestamp: ch.Timestamp}}}, direct)
		if err == nil && a.Status == pb.Status_OK {
			h.backend.Forget(id)
		}
	} else {
		a, err = h.backend.Lookup(ctx, &pb.RelayLookup{Query: &pb.RelayLookup_Node{Node: &pb.NodeLookup{Identity: id}}}, fresh)
	}
	if err != nil {
		return &pb.ServerHello{Status: pb.Status_CONTROL_NOT_READY, Message: "control plane unreachable", RetryAfterSeconds: 5}
	}
	if a.Status != pb.Status_OK {
		return &pb.ServerHello{Status: a.Status, Message: a.Message, AssignedRelay: a.GetAssignedRelay()}
	}
	n := a.GetNode()
	if n == nil {
		return &pb.ServerHello{Status: pb.Status_SERVER_BUSY, Message: "incomplete answer"}
	}
	*info = n
	h.commitStamp(id, ch.Timestamp)
	return &pb.ServerHello{Status: pb.Status_OK, Workspace: n.Workspace, Name: n.Name, RoleCaps: n.RoleCaps}
}

// ServeNode runs one node session over an accepted transport connection.
func (h *Hub) ServeNode(raw net.Conn) {
	var info *pb.NodeInfo
	conn, hello, err := session.Server(raw, session.ResponderConfig{Local: h.key, Decide: func(ch *pb.ClientHello, id ed25519.PublicKey) *pb.ServerHello {
		return h.decide(ch, id, &info)
	}})
	if err != nil {
		if hello != nil {
			h.log.Info("node session rejected", "node", identity.EncodeKey(hello.Identity), "err", err)
		}
		return
	}
	mux, err := session.NewMux(conn, false)
	if err != nil {
		conn.Close()
		return
	}
	ns := &nodeSession{id: info.Identity, ws: info.Workspace, name: info.Name, mux: mux, since: time.Now(), welcome: info.Welcome}
	h.register(ns)
	defer h.unregister(ns)
	h.log.Info("node connected", "workspace", ns.ws, "node", ns.name, "addr", raw.RemoteAddr())

	timer := time.AfterFunc(ControlOpenTimeout, func() {
		ns.cmu.Lock()
		missing := ns.ctrl == nil
		ns.cmu.Unlock()
		if missing {
			h.log.Info("node did not open its control stream", "node", ns.name)
			mux.Close()
		}
	})
	defer timer.Stop()
	for {
		st, err := mux.AcceptStream()
		if err != nil {
			return
		}
		if st.StreamID() == 1 {
			go h.serveControl(ns, st)
		} else {
			go h.forward(ns, st)
		}
	}
}

func (h *Hub) register(ns *nodeSession) {
	h.mu.Lock()
	old := h.sessions[string(ns.id)]
	h.sessions[string(ns.id)] = ns
	h.mu.Unlock()
	if old != nil {
		h.log.Info("node session replaced", "node", ns.name)
		old.close()
	}
	h.backend.Presence([][]byte{ns.id}, nil)
}

func (h *Hub) unregister(ns *nodeSession) {
	ns.close()
	h.mu.Lock()
	cur := h.sessions[string(ns.id)] == ns
	if cur {
		delete(h.sessions, string(ns.id))
	}
	h.mu.Unlock()
	if cur {
		h.backend.Presence(nil, [][]byte{ns.id})
		h.log.Info("node disconnected", "workspace", ns.ws, "node", ns.name)
	}
}

func (ns *nodeSession) close() {
	ns.cmu.Lock()
	ns.closing = true
	ns.cmu.Unlock()
	ns.mux.Close()
}

// send writes a control message to the node, queueing until the control
// stream is open.
func (ns *nodeSession) send(m *pb.ControlMessage) error {
	ns.cmu.Lock()
	defer ns.cmu.Unlock()
	if ns.closing {
		return net.ErrClosed
	}
	if ns.ctrl == nil {
		if len(ns.queue) < 64 {
			ns.queue = append(ns.queue, m)
		}
		return nil
	}
	ns.ctrl.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return wire.WriteMsg(ns.ctrl, m)
}

func (h *Hub) serveControl(ns *nodeSession, st *session.Stream) {
	defer ns.close() // the control stream ending ends the session (protocol 5.1)
	st.SetReadDeadline(time.Now().Add(ControlOpenTimeout))
	var so pb.StreamOpen
	if err := wire.ReadMsg(st, &so, wire.OpenMax); err != nil {
		stream.Fail(st, pb.Status_BAD_REQUEST, err.Error(), nil)
		return
	}
	st.SetReadDeadline(time.Time{})
	body, err := wire.DecodeOpen(so.Open)
	if err != nil {
		stream.Fail(st, wire.StatusOf(err), err.Error(), nil)
		return
	}
	if status, msg := h.checkOpen(ns, body, true); status != pb.Status_OK {
		stream.Fail(st, status, msg, nil)
		return
	}
	if err := wire.WriteMsg(st, &pb.Ack{Status: pb.Status_OK}); err != nil {
		return
	}
	ns.cmu.Lock()
	ns.ctrl = st
	queue := ns.queue
	ns.queue = nil
	welcome := ns.welcome
	ns.welcome = nil
	ns.cmu.Unlock()
	if welcome != nil {
		_ = ns.send(&pb.ControlMessage{Msg: &pb.ControlMessage_Signed{Signed: welcome}})
	}
	for _, m := range queue {
		_ = ns.send(m)
	}
	for {
		var m pb.ControlMessage
		if err := wire.ReadMsg(st, &m, wire.ControlMsgMax); err != nil {
			return
		}
		switch m.Msg.(type) {
		case *pb.ControlMessage_Advertise, *pb.ControlMessage_PolicyApplied, *pb.ControlMessage_Pull, *pb.ControlMessage_RelayReport:
			ctx, cancel := context.WithTimeout(context.Background(), LookupTimeout+time.Second)
			if err := h.backend.Send(ctx, &pb.ControlMessage{Msg: &pb.ControlMessage_NodeMessage{NodeMessage: &pb.NodeMessage{Identity: ns.id, Msg: &m}}}); err != nil {
				h.log.Warn("dropped node message", "node", ns.name, "err", err)
			}
			cancel()
		default:
			h.log.Debug("ignored control message from node", "node", ns.name)
		}
	}
}

// checkOpen runs checklist A steps 2 to 8 (protocol 4.1).
func (h *Hub) checkOpen(ns *nodeSession, body *pb.OpenBody, control bool) (pb.Status, string) {
	switch {
	case control && body.Kind != pb.Kind_KIND_CONTROL:
		return pb.Status_BAD_REQUEST, "stream 1 must be the control stream"
	case !control && body.Kind == pb.Kind_KIND_CONTROL:
		return pb.Status_BAD_REQUEST, "only stream 1 may be a control stream"
	case body.Kind != pb.Kind_KIND_CONTROL && body.Kind != pb.Kind_KIND_TCP && body.Kind != pb.Kind_KIND_TASK:
		return pb.Status_BAD_REQUEST, "unknown stream kind"
	case body.Workspace != ns.ws:
		return pb.Status_WORKSPACE_MISMATCH, "workspace does not match the session"
	case !bytes.Equal(body.From, ns.id):
		return pb.Status_FROM_MISMATCH, "from does not match the session identity"
	case !bytes.Equal(body.To, h.pub):
		return pb.Status_BAD_REQUEST, "to is not this relay"
	case !wire.WithinWindow(body.IssuedAt, time.Now()):
		return pb.Status_TIMESTAMP_OUT_OF_WINDOW, "issued_at outside the time window"
	case !h.nonces.Check(body.From, body.Nonce, time.Now()):
		return pb.Status_REPLAY, "nonce already seen"
	}
	return pb.Status_OK, ""
}

// deliver writes an agentserver message into a node's control stream.
func (h *Hub) deliver(node []byte, s *pb.Signed) {
	if ns := h.session(node); ns != nil {
		_ = ns.send(&pb.ControlMessage{Msg: &pb.ControlMessage_Signed{Signed: s}})
	}
}

// invalidate closes the sessions of removed nodes.
func (h *Hub) invalidate(ws string, removed [][]byte) {
	for _, id := range removed {
		if ns := h.session(id); ns != nil {
			h.log.Info("closing session of removed node", "node", ns.name)
			ns.close()
		}
	}
}

// Shutdown tells every node to reconnect elsewhere and closes the sessions
// (protocol 3.6; the relay's own Notice is not signed).
func (h *Hub) Shutdown() {
	h.mu.Lock()
	all := make([]*nodeSession, 0, len(h.sessions))
	for _, s := range h.sessions {
		all = append(all, s)
	}
	h.mu.Unlock()
	for _, s := range all {
		_ = s.send(&pb.ControlMessage{Msg: &pb.ControlMessage_Notice{Notice: &pb.Notice{Kind: pb.Notice_SHUTDOWN, Message: "relay shutting down", RetryAfterSeconds: 1}}})
	}
	time.Sleep(200 * time.Millisecond)
	for _, s := range all {
		s.close()
	}
}
