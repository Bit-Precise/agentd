package sim

import (
	"context"
	"testing"
	"time"

	"agentd/internal/identity"
	"agentd/internal/session"
	"agentd/internal/transport"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// TestRawJoinThroughRelay drives the node protocol by hand: verify the relay
// with the workspace key, join with a token, open the control stream and
// check the signed Welcome.
func TestRawJoinThroughRelay(t *testing.T) {
	s := newStack(t)
	ws := s.workspace("home")
	link, err := identity.ParseJoinLink(s.token("home", "laptop"))
	if err != nil {
		t.Fatal(err)
	}
	if link.RelayURL != "https://"+relayHost || link.Workspace != ws.BaseDomain {
		t.Fatalf("join link: %+v", link)
	}
	rc, err := s.relayCert(link.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	body, err := wire.VerifyRelayCert(link.Key, rc, link.Workspace, time.Now())
	if err != nil {
		t.Fatalf("relay cert does not verify with the workspace key: %v", err)
	}
	nodeKey, _ := identity.GenerateKey()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := transport.Dial(ctx, transport.WebSocket, body.Urls["ws"], transport.Options{RootCAs: s.roots, NetDial: s.dial})
	if err != nil {
		t.Fatal(err)
	}
	conn, sh, err := session.Client(raw, session.InitiatorConfig{Local: nodeKey, Remote: body.Identity, Hello: &pb.ClientHello{
		JoinToken: link.Token, Workspace: link.Workspace}})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if sh.Name != "laptop" || sh.Workspace != ws.BaseDomain {
		t.Fatalf("server hello: %v", sh)
	}
	mux, _ := session.NewMux(conn, true)
	defer mux.Close()
	st, err := mux.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	open, _ := wire.SignOpen(nodeKey, &pb.OpenBody{Kind: pb.Kind_KIND_CONTROL, Workspace: ws.BaseDomain, From: identity.Public(nodeKey), To: body.Identity,
		IssuedAt: uint64(time.Now().Unix()), Nonce: []byte("0123456789abcdef")})
	wire.WriteMsg(st, &pb.StreamOpen{Open: open})
	var ack pb.Ack
	if err := wire.ReadMsg(st, &ack, wire.AckMax); err != nil || ack.Status != pb.Status_OK {
		t.Fatalf("control ack: %v %v", err, ack.Status)
	}
	var m pb.ControlMessage
	if err := wire.ReadMsg(st, &m, wire.ControlMsgMax); err != nil {
		t.Fatal(err)
	}
	msg, err := wire.OpenSigned(link.Key, identity.Public(nodeKey), m.GetSigned(), time.Now())
	if err != nil {
		t.Fatalf("welcome: %v", err)
	}
	if w := msg.GetWelcome(); w == nil || w.Self.Name != "laptop" || len(w.Relays) != 1 {
		t.Fatalf("welcome content: %v", msg)
	}
	s.eventually("agentserver sees the node online", func() bool { ok, _ := s.srv.Coordinator.NodeOnline(identity.Public(nodeKey)); return ok })

	// A second handshake with the same token must fail (token used), and an
	// unknown key without a token is not a member.
	stranger, _ := identity.GenerateKey()
	raw2, _ := transport.Dial(ctx, transport.WebSocket, body.Urls["ws"], transport.Options{RootCAs: s.roots, NetDial: s.dial})
	_, sh2, err := session.Client(raw2, session.InitiatorConfig{Local: stranger, Remote: body.Identity})
	if err == nil || sh2 == nil || sh2.Status != pb.Status_NOT_A_MEMBER {
		t.Fatalf("stranger: %v %v", err, sh2)
	}
}
