package control

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"agentd/internal/identity"
	"agentd/internal/session"
	"agentd/internal/store"
	"agentd/internal/transport"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// RelayControlTimeout bounds the time from a relay's handshake to its control
// stream; a variable so tests can shorten it.
var RelayControlTimeout = 10 * time.Second

// DefaultTransports are the transport paths used when none are configured.
var DefaultTransports = map[string]string{"ws": "/ws", "httpupgrade": "/up", "xhttp": "/x"}

// RelayHandler serves relay sessions on the transports and the well-known
// endpoint relays use to learn agentserver's key over TLS.
func (c *Coordinator) RelayHandler(paths map[string]string) http.Handler {
	if len(paths) == 0 {
		paths = DefaultTransports
	}
	mux := http.NewServeMux()
	if p := paths["ws"]; p != "" {
		mux.Handle(p, transport.WSHandler(c.serveRelay))
	}
	if p := paths["httpupgrade"]; p != "" {
		mux.Handle(p, transport.UpgradeHandler(c.serveRelay))
	}
	if p := paths["xhttp"]; p != "" {
		mux.Handle(p+"/", transport.XHTTPHandler(p+"/", func(conn net.Conn) { c.serveRelay(conn) }))
	}
	mux.HandleFunc("/.well-known/agentserver", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"identity":   identity.EncodeKey(c.PublicKey()),
			"protocol":   map[string]int{"major": 1, "min": wire.MinorVersion, "max": wire.MinorVersion},
			"transports": paths,
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return mux
}

// decideRelay authenticates a relay session, registering the relay when it
// presents a registration token.
func (c *Coordinator) decideRelay(ctx context.Context, h *pb.ClientHello, id ed25519.PublicKey) (*pb.ServerHello, string) {
	if h.SessionKind != pb.SessionKind_SESSION_RELAY {
		return &pb.ServerHello{Status: pb.Status_BAD_REQUEST, Message: "this endpoint serves relay sessions only"}, ""
	}
	reg := h.GetRelay()
	if r, err := c.st.GetRelayByKey(ctx, id); err == nil {
		if reg != nil && reg.Url != "" {
			_ = c.st.UpsertRelayByKey(ctx, store.Relay{Name: r.Name, PublicKey: id, URL: reg.Url, Transports: reg.Transports, STUN: reg.Stun})
		}
		return &pb.ServerHello{Status: pb.Status_OK, Name: r.Name}, r.Name
	}
	if h.JoinToken == "" {
		return &pb.ServerHello{Status: pb.Status_NOT_A_MEMBER, Message: "relay key is not registered; register it or connect with a relay token"}, ""
	}
	ok := c.bootstrap != "" && subtle.ConstantTimeCompare([]byte(h.JoinToken), []byte(c.bootstrap)) == 1
	if !ok && c.st.ConsumeRelayToken(ctx, store.HashToken(h.JoinToken)) != nil {
		return &pb.ServerHello{Status: pb.Status_TOKEN_INVALID, Message: "relay registration token invalid, used or expired"}, ""
	}
	if reg == nil || !identity.ValidLabel(reg.Name) {
		return &pb.ServerHello{Status: pb.Status_BAD_NAME, Message: "relay registration needs a valid name"}, ""
	}
	if u, err := url.Parse(reg.Url); err != nil || u.Scheme != "https" || u.Host == "" {
		return &pb.ServerHello{Status: pb.Status_BAD_REQUEST, Message: "relay registration needs an https url"}, ""
	}
	if err := c.st.CreateRelay(ctx, store.Relay{Name: reg.Name, PublicKey: id, URL: reg.Url, Transports: reg.Transports, STUN: reg.Stun}); err != nil {
		return &pb.ServerHello{Status: pb.Status_NAME_TAKEN, Message: err.Error()}, ""
	}
	c.log.Info("relay registered", "relay", reg.Name)
	return &pb.ServerHello{Status: pb.Status_OK, Name: reg.Name}, reg.Name
}

func (c *Coordinator) serveRelay(raw net.Conn) {
	ctx := context.Background()
	var name string
	conn, hello, err := session.Server(raw, session.ResponderConfig{Local: c.key, Decide: func(h *pb.ClientHello, id ed25519.PublicKey) *pb.ServerHello {
		sh, n := c.decideRelay(ctx, h, id)
		name = n
		return sh
	}})
	if err != nil {
		if hello != nil {
			c.log.Info("relay session rejected", "err", err)
		}
		return
	}
	mux, err := session.NewMux(conn, false)
	if err != nil {
		conn.Close()
		return
	}
	defer mux.Close()
	st, ok := acceptRelayControl(mux)
	if !ok {
		c.log.Info("relay did not open its control stream", "relay", name)
		return
	}
	var wmu sync.Mutex
	rc := &relayConn{name: name, key: conn.RemoteIdentity(), since: time.Now(), send: func(m *pb.ControlMessage) error {
		wmu.Lock()
		defer wmu.Unlock()
		st.SetWriteDeadline(time.Now().Add(30 * time.Second))
		return wire.WriteMsg(st, m)
	}}
	c.log.Info("relay connected", "relay", name, "addr", raw.RemoteAddr())
	c.registerRelay(rc)
	defer func() {
		c.unregisterRelay(rc)
		c.log.Info("relay disconnected", "relay", name)
	}()
	for {
		var m pb.ControlMessage
		if err := wire.ReadMsg(st, &m, wire.ControlMsgMax); err != nil {
			return
		}
		switch x := m.Msg.(type) {
		case *pb.ControlMessage_RelayLookup:
			go func(q *pb.RelayLookup) {
				lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				a := c.Lookup(lctx, name, q)
				_ = rc.send(&pb.ControlMessage{Msg: &pb.ControlMessage_RelayAnswer{RelayAnswer: a}})
			}(x.RelayLookup)
		case *pb.ControlMessage_NodeMessage:
			go c.HandleNodeMessage(ctx, name, x.NodeMessage)
		case *pb.ControlMessage_RelayPresence:
			c.handlePresence(ctx, name, x.RelayPresence)
		}
	}
}

// acceptRelayControl takes the relay's control stream, which must be the first
// stream and arrive within RelayControlTimeout; otherwise the session closes.
func acceptRelayControl(mux *session.Mux) (*session.Stream, bool) {
	timer := time.AfterFunc(RelayControlTimeout, func() { mux.Close() })
	defer timer.Stop()
	st, err := mux.AcceptStream()
	if err != nil {
		return nil, false
	}
	var open pb.StreamOpen
	if err := wire.ReadMsg(st, &open, wire.OpenMax); err != nil {
		return nil, false
	}
	body, err := wire.DecodeOpen(open.Open)
	if err != nil || body.Kind != pb.Kind_KIND_CONTROL {
		wire.WriteMsg(st, &pb.Ack{Status: pb.Status_BAD_REQUEST, Message: "first stream must be the control stream"})
		return nil, false
	}
	if err := wire.WriteMsg(st, &pb.Ack{Status: pb.Status_OK}); err != nil {
		return nil, false
	}
	return st, true
}
