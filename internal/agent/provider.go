package agent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/identity"
	"agentd/internal/policy"
	"agentd/internal/session"
	"agentd/internal/sniff"
	"agentd/internal/stream"
	"agentd/internal/task"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// Provider timing (protocol 0.5).
const (
	EgressDialTimeout = 10 * time.Second
	recheckTimeout    = 5 * time.Second
	EarlyDataMax      = 16 << 10
)

func taskTools() []*pb.ToolInfo { return task.Tools() }

func (a *Agent) acceptStreams(ctx context.Context, as *activeSession) {
	for {
		st, err := as.mux.AcceptStream()
		if err != nil {
			return
		}
		go a.serveStream(ctx, as, st)
	}
}

// incoming is a stream that passed checklist B steps 1 to 6.
type incoming struct {
	st    *session.Stream
	so    *pb.StreamOpen
	body  *pb.OpenBody
	trace []byte
	start time.Time
}

func (in *incoming) fail(status pb.Status, msg string) {
	stream.Reject(in.st, &pb.Ack{Status: status, Message: msg, TraceId: in.trace})
}

// serveStream runs checklist B (protocol 4.1) and dispatches by kind.
func (a *Agent) serveStream(ctx context.Context, as *activeSession, st *session.Stream) {
	cfg := a.config()
	st.SetReadDeadline(time.Now().Add(AckTimeout))
	var so pb.StreamOpen
	if err := wire.ReadMsg(st, &so, wire.OpenMax); err != nil {
		stream.Fail(st, pb.Status_BAD_REQUEST, "unreadable StreamOpen", nil)
		return
	}
	st.SetReadDeadline(time.Time{})
	in := &incoming{st: st, so: &so, start: time.Now()}
	if so.Relay != nil {
		in.trace = so.Relay.TraceId
	}
	var body pb.OpenBody
	if so.Open == nil || proto.Unmarshal(so.Open.Body, &body) != nil || (body.Kind != pb.Kind_KIND_TCP && body.Kind != pb.Kind_KIND_TASK) {
		in.fail(pb.Status_BAD_REQUEST, "undecodable or unsupported stream")
		return
	}
	in.body = &body
	if body.Workspace != cfg.Workspace.Domain {
		in.fail(pb.Status_WORKSPACE_MISMATCH, "wrong workspace")
		return
	}
	// Step 3: to is the next hop. Streams relayed for a node name the relay;
	// streams the relay's edge opens itself (from = relay) name this node.
	edge := bytes.Equal(body.From, as.relayKey) || a.state.isRelayKey(body.From)
	if !(bytes.Equal(body.To, as.relayKey) && !edge) && !(edge && bytes.Equal(body.To, a.pub)) {
		in.fail(pb.Status_BAD_REQUEST, "to is not the next hop of this stream")
		return
	}
	if !wire.Verify(body.From, wire.CtxOpen, so.Open.Body, so.Open.Sig) {
		in.fail(pb.Status_BAD_SIGNATURE, "open signature does not verify")
		return
	}
	if !wire.WithinWindow(body.IssuedAt, time.Now()) {
		in.fail(pb.Status_TIMESTAMP_OUT_OF_WINDOW, "issued_at outside the time window")
		return
	}
	if !a.nonces.Check(body.From, body.Nonce, time.Now()) {
		in.fail(pb.Status_REPLAY, "nonce already seen")
		return
	}
	switch {
	case body.Kind == pb.Kind_KIND_TASK:
		a.serveTask(in, cfg)
	case body.Tcp == nil:
		in.fail(pb.Status_BAD_REQUEST, "tcp parameters missing")
	case a.localService(cfg, body.Tcp.Domain) != nil:
		a.serveService(ctx, in, cfg, a.localService(cfg, body.Tcp.Domain))
	default:
		a.serveEgress(ctx, in, cfg)
	}
}

// identities runs step 7 for a role's effective policy.
func (a *Agent) identities(in *incoming, eff *pb.Policy) ([][]byte, pb.Status) {
	keys := policy.Keys(eff)
	ids := a.state.identitySet(in.body.From, in.so.Certs, keys, in.body.Workspace)
	if keys.Any {
		return ids, pb.Status_OK
	}
	for _, id := range ids {
		if keys.Has(id) {
			return ids, pb.Status_OK
		}
	}
	return nil, pb.Status_UNKNOWN_PEER
}

func (a *Agent) peerName(in *incoming) string {
	if n := a.state.memberName(in.body.From); n != "" {
		return n
	}
	if in.so.Relay != nil && in.so.Relay.FromName != "" {
		return in.so.Relay.FromName + "?"
	}
	return identity.EncodeKey(in.body.From)[:8]
}

// ------------------------------------------------------------------ egress

func (a *Agent) serveEgress(ctx context.Context, in *incoming, cfg *Config) {
	t := in.body.Tcp
	log := func(status pb.Status, msg string) {
		a.decision("egress", "from", a.peerName(in), "proto", t.Proto.String(), "domain", t.Domain, "port", t.Port, "status", status.String(), "message", msg,
			"ms", time.Since(in.start).Milliseconds())
	}
	if !cfg.Roles.Egress.Enabled {
		in.fail(pb.Status_BAD_REQUEST, "this node does not provide egress")
		log(pb.Status_BAD_REQUEST, "egress disabled")
		return
	}
	proto := t.Proto
	if proto == pb.Proto_PROTO_UNSPECIFIED {
		proto = pb.Proto_PROTO_TLS
	}
	if proto != pb.Proto_PROTO_TLS && proto != pb.Proto_PROTO_SSH {
		in.fail(pb.Status_BAD_REQUEST, "egress carries tls or ssh only")
		return
	}
	domain := policy.NormalizeDomain(t.Domain)
	port := t.Port
	if port == 0 {
		port = policy.DefaultPort(proto)
	}
	eff := a.effective(pb.Role_ROLE_EGRESS)
	ids, st := a.identities(in, eff)
	if st != pb.Status_OK {
		in.fail(st, "no rule names this peer")
		log(st, "")
		return
	}
	d := policy.Egress(eff.Egress, ids, proto, domain, port)
	if d.Status != pb.Status_OK {
		in.fail(d.Status, d.Reason)
		log(d.Status, d.Reason)
		return
	}
	if !validHost(domain) {
		in.fail(pb.Status_BAD_REQUEST, "domain is not a host name")
		return
	}
	a.dialAndSplice(ctx, in, proto, domain, net.JoinHostPort(domain, strconv.Itoa(int(port))), log)
}

func validHost(d string) bool { return identity.ValidDomain(d) && net.ParseIP(d) == nil }

// dialAndSplice dials the origin while the first client bytes arrive,
// rechecks the protocol (protocol 6.4), acks and splices.
func (a *Agent) dialAndSplice(ctx context.Context, in *incoming, proto pb.Proto, domain, addr string, log func(pb.Status, string)) {
	type dialRes struct {
		c   net.Conn
		err error
	}
	dc := make(chan dialRes, 1)
	go func() {
		dctx, cancel := context.WithTimeout(ctx, EgressDialTimeout)
		defer cancel()
		c, err := a.dialDirect(dctx, addr)
		dc <- dialRes{c, err}
	}()
	var first []byte
	if proto == pb.Proto_PROTO_TLS {
		// The ClientHello arrives as early data; verify it before the Ack.
		in.st.SetReadDeadline(time.Now().Add(recheckTimeout))
		res := sniff.Sniff(in.st, EarlyDataMax)
		in.st.SetReadDeadline(time.Time{})
		first = res.Data
		if res.Kind != sniff.TLS || !equalFold(res.SNI, domain) {
			msg := fmt.Sprintf("expected a TLS ClientHello for %s, got %s %q", domain, res.Kind, res.SNI)
			if r := <-dc; r.c != nil {
				r.c.Close()
			}
			in.fail(pb.Status_PROTOCOL_MISMATCH, msg)
			log(pb.Status_PROTOCOL_MISMATCH, msg)
			return
		}
	}
	r := <-dc
	if r.err != nil {
		st, msg := dialStatus(r.err)
		in.fail(st, msg)
		log(st, msg)
		return
	}
	origin := r.c
	if err := wire.WriteMsg(in.st, &pb.Ack{Status: pb.Status_OK, TraceId: in.trace, Responder: a.pub}); err != nil {
		origin.Close()
		in.st.Reset()
		return
	}
	log(pb.Status_OK, "")
	var client io.ReadWriteCloser = in.st
	if proto == pb.Proto_PROTO_SSH {
		// Origin bytes may flow first; client bytes wait for "SSH-".
		client = &gatedSSH{Stream: in.st}
	} else if len(first) > 0 {
		if _, err := origin.Write(first); err != nil {
			origin.Close()
			in.st.Reset()
			return
		}
	}
	stream.Splice(client, origin)
}

func equalFold(a, b string) bool { return len(a) == len(b) && toLower(a) == toLower(b) }

func dialStatus(err error) (pb.Status, string) {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return pb.Status_RESOLVE_FAILED, err.Error()
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return pb.Status_TIMEOUT, err.Error()
	case errors.Is(err, syscall.ECONNREFUSED):
		return pb.Status_DIAL_FAILED, err.Error()
	}
	return pb.Status_DIAL_FAILED, err.Error()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// dialDirect dials from this host (egress, services, direct ingress).
func (a *Agent) dialDirect(ctx context.Context, addr string) (net.Conn, error) {
	if d := a.netDial(); d != nil {
		return d(ctx, "tcp", addr)
	}
	d := net.Dialer{KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

// gatedSSH holds client bytes until the first line starts with "SSH-".
type gatedSSH struct {
	*session.Stream
	checked bool
	buf     *bufio.Reader
}

func (g *gatedSSH) Read(p []byte) (int, error) {
	if !g.checked {
		g.buf = bufio.NewReaderSize(g.Stream, 512)
		g.Stream.SetReadDeadline(time.Now().Add(30 * time.Second))
		head, err := g.buf.Peek(4)
		g.Stream.SetReadDeadline(time.Time{})
		if err != nil || !sniff.IsSSH(head) {
			return 0, errors.New("protocol mismatch: client did not start with SSH-")
		}
		g.checked = true
	}
	return g.buf.Read(p)
}

func (g *gatedSSH) CloseWrite() error { return g.Stream.CloseWrite() }
func (g *gatedSSH) Reset() error      { return g.Stream.Reset() }

// ------------------------------------------------------------------ service

func (a *Agent) localService(cfg *Config, domain string) *ServerConfig {
	if !cfg.Roles.Service.Enabled {
		return nil
	}
	domain = policy.NormalizeDomain(domain)
	for i, s := range cfg.Roles.Service.Servers {
		if s.Name+"."+cfg.Workspace.Domain == domain {
			return &cfg.Roles.Service.Servers[i]
		}
	}
	return nil
}

func (a *Agent) serveService(ctx context.Context, in *incoming, cfg *Config, sv *ServerConfig) {
	t := in.body.Tcp
	log := func(status pb.Status, msg string) {
		a.decision("service", "from", a.peerName(in), "service", sv.Name, "proto", t.Proto.String(), "status", status.String(), "message", msg)
	}
	eff := a.effective(pb.Role_ROLE_SERVICE)
	target := net.JoinHostPort(sv.Target.Host, strconv.Itoa(sv.Target.Port))
	switch {
	case sv.Proto == "http" && t.Proto == pb.Proto_PROTO_HTTP:
		// Edge streams: from must be a relay of this workspace; the edge
		// already authorized the visitor with the control plane. Local
		// deny rules naming the visitor (or *) still apply.
		if !a.state.isRelayKey(in.body.From) {
			in.fail(pb.Status_BAD_REQUEST, "http service streams must come from a relay edge")
			log(pb.Status_BAD_REQUEST, "not from a relay")
			return
		}
		var visitor [][]byte
		if p := t.HttpPeer; p != nil && len(p.Identity) > 0 {
			visitor = [][]byte{p.Identity}
		}
		if deniedExplicitly(eff.Services, visitor, sv.Name) {
			in.fail(pb.Status_POLICY_DENIED, "denied by a local rule")
			log(pb.Status_POLICY_DENIED, "local deny")
			return
		}
		if err := wire.WriteMsg(in.st, &pb.Ack{Status: pb.Status_OK, TraceId: in.trace, Responder: a.pub}); err != nil {
			in.st.Reset()
			return
		}
		log(pb.Status_OK, "")
		a.httpProxy(sv, target).serve(in.st, t.HttpPeer)
	case sv.Proto == "ssh" && t.Proto == pb.Proto_PROTO_SSH:
		ids, st := a.identities(in, eff)
		if st != pb.Status_OK {
			in.fail(st, "no rule names this peer")
			log(st, "")
			return
		}
		if d := policy.Service(eff.Services, ids, sv.Name); d.Status != pb.Status_OK {
			in.fail(d.Status, d.Reason)
			log(d.Status, d.Reason)
			return
		}
		a.dialAndSplice(ctx, in, pb.Proto_PROTO_SSH, sv.Name, target, log)
	default:
		in.fail(pb.Status_BAD_REQUEST, "protocol does not match the service")
		log(pb.Status_BAD_REQUEST, "protocol mismatch")
	}
}

// deniedExplicitly reports whether a deny rule for the service names one of
// ids or "*".
func deniedExplicitly(rules []*pb.ServiceRule, ids [][]byte, name string) bool {
	for _, r := range rules {
		if r.Action != pb.Action_ACTION_DENY || r.Name != name {
			continue
		}
		if len(r.PublicKey) == 0 {
			return true
		}
		for _, id := range ids {
			if bytes.Equal(id, r.PublicKey) {
				return true
			}
		}
	}
	return false
}

// ------------------------------------------------------------------ executor

func (a *Agent) serveTask(in *incoming, cfg *Config) {
	t := in.body.Task
	fc := t.GetCall()
	log := func(status pb.Status, msg string) {
		a.decision("task", "from", a.peerName(in), "tool", fc.GetName(), "call_id", fc.GetCallId(), "status", status.String(), "message", msg,
			"ms", time.Since(in.start).Milliseconds())
	}
	if !cfg.Roles.Executor.Enabled || a.tasks == nil {
		in.fail(pb.Status_BAD_REQUEST, "this node is not an executor")
		return
	}
	if t == nil || fc == nil || !bytes.Equal(t.Executor, a.pub) {
		in.fail(pb.Status_BAD_REQUEST, "task is not addressed to this executor")
		log(pb.Status_BAD_REQUEST, "wrong executor")
		return
	}
	eff := a.effective(pb.Role_ROLE_EXECUTOR)
	ids, st := a.identities(in, eff)
	if st != pb.Status_OK {
		in.fail(st, "no rule names this peer")
		log(st, "")
		return
	}
	prep, status, msg := a.tasks.Prepare(in.body.From, ids, fc)
	if status != pb.Status_OK {
		in.fail(status, msg)
		log(status, msg)
		return
	}
	if err := wire.WriteMsg(in.st, &pb.Ack{Status: pb.Status_OK, TraceId: in.trace, Responder: a.pub}); err != nil {
		in.st.Reset()
		return
	}
	out := prep.Run()
	res, err := wire.SignTaskResult(a.key, &pb.TaskResultBody{CallId: fc.CallId, From: a.pub, To: in.body.From, IssuedAt: uint64(time.Now().Unix()), Output: out, Final: true})
	if err != nil {
		in.st.Reset()
		return
	}
	log(pb.Status_OK, "")
	in.st.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err := wire.WriteMsg(in.st, res); err != nil {
		in.st.Reset()
		return
	}
	in.st.CloseWrite()
	go func() {
		in.st.SetReadDeadline(time.Now().Add(5 * time.Second))
		io.Copy(io.Discard, in.st)
		in.st.Close()
	}()
}
