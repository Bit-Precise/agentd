package sim

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agentd/internal/adminapi"
	"agentd/internal/identity"
	"agentd/internal/pki"
	"agentd/internal/session"
	"agentd/internal/transport"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// TestServerManagedPolicy: dorm takes its egress policy from agentserver; a
// central statement grants laptop, and dorm reports it applied.
func TestServerManagedPolicy(t *testing.T) {
	s := newStack(t)
	s.workspace("home")
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok from origin") }))
	cert, ca, _ := pki.SelfSigned([]string{"wiki.corp.test"}, nil)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	origin.StartTLS()
	defer origin.Close()
	s.extra.Store("wiki.corp.test", origin.Listener.Addr().String())

	socks := freePort(t)
	laptop := s.join("home", "laptop", fmt.Sprintf("  ingress:\n    enabled: true\n    socks5: { enabled: true, port: %d }\n    fallback: reject\n", socks))
	s.join("home", "dorm", "  egress:\n    enabled: true\n    policy_source: server\n")
	proto := []adminapi.Proto{"tls"}
	s.admin.AddRouteWithResponse(s.ctx, "home", adminapi.RouteWrite{From: "node:laptop", Proto: &proto, Domains: []adminapi.Match{{Kind: "suffix", Value: "corp.test"}}, To: "dorm"})
	s.eventually("route reaches laptop", func() bool { return len(laptop.a.Routes().Routes) == 1 })

	get := func() error {
		c := socksDial(t, fmt.Sprintf("127.0.0.1:%d", socks), "wiki.corp.test", 443)
		defer c.Close()
		resp, body, err := httpsGet(c, &tls.Config{RootCAs: pki.Pool(ca)}, "wiki.corp.test", "/")
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 || body != "ok from origin" {
			return fmt.Errorf("got %d %q", resp.StatusCode, body)
		}
		return nil
	}
	if err := get(); err == nil {
		t.Fatal("before any central statement dorm must refuse")
	}
	egress, tlsProto := "dorm", adminapi.Proto("tls")
	domains := []adminapi.Match{{Kind: "suffix", Value: "corp.test"}}
	allow := []adminapi.PolicyTarget{{Egress: &egress, Proto: &tlsProto, Domains: &domains}}
	if r, err := s.admin.AddPolicyWithResponse(s.ctx, "home", adminapi.PolicyStatementWrite{Subjects: []string{"node:laptop"}, Allow: &allow}); err != nil || r.StatusCode() != 201 {
		t.Fatalf("add policy: %v %s", err, r.Body)
	}
	s.eventually("dorm applies the rendered policy", func() bool {
		r, err := s.admin.GetNodeWithResponse(s.ctx, "home", "dorm")
		// Version 1 is the empty policy dorm got when it came online.
		return err == nil && r.JSON200 != nil && r.JSON200.PolicyVersionApplied != nil && *r.JSON200.PolicyVersionApplied >= 2
	})
	if err := get(); err != nil {
		t.Fatalf("after the central statement: %v", err)
	}
}

// TestRemovedNodeStops: removing a node notifies it and closes its session.
func TestRemovedNodeStops(t *testing.T) {
	s := newStack(t)
	s.workspace("home")
	n := s.join("home", "gone", "")
	if r, err := s.admin.RemoveNodeWithResponse(s.ctx, "home", "gone"); err != nil || r.StatusCode() != 204 {
		t.Fatalf("remove: %v %s", err, r.Body)
	}
	s.eventually("the node learns it was removed", func() bool { return n.a.Status()["removed"] == true })
	s.eventually("agentserver sees it offline", func() bool { ok, _ := s.srv.Coordinator.NodeOnline(n.key); return !ok })
}

// TestRelayRejectsReplayedOpen: the same signed StreamOpen twice gets REPLAY.
func TestRelayRejectsReplayedOpen(t *testing.T) {
	s := newStack(t)
	ws := s.workspace("home")
	link, _ := identity.ParseJoinLink(s.token("home", "laptop", "ingress"))
	rc, _ := s.relayCert(link.Workspace)
	body, _ := wire.VerifyRelayCert(link.Key, rc, link.Workspace, time.Now())
	key, _ := identity.GenerateKey()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := transport.Dial(ctx, transport.WebSocket, body.Urls["ws"], transport.Options{RootCAs: s.roots, NetDial: s.dial})
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := session.Client(raw, session.InitiatorConfig{Local: key, Remote: body.Identity, Hello: &pb.ClientHello{JoinToken: link.Token, Workspace: link.Workspace}})
	if err != nil {
		t.Fatal(err)
	}
	mux, _ := session.NewMux(conn, true)
	defer mux.Close()
	ctrl, _ := mux.OpenStream(ctx)
	copen, _ := wire.SignOpen(key, &pb.OpenBody{Kind: pb.Kind_KIND_CONTROL, Workspace: ws.BaseDomain, From: identity.Public(key), To: body.Identity, IssuedAt: uint64(time.Now().Unix()), Nonce: []byte("control-nonce-01")})
	wire.WriteMsg(ctrl, &pb.StreamOpen{Open: copen})
	var ack pb.Ack
	if err := wire.ReadMsg(ctrl, &ack, wire.AckMax); err != nil || ack.Status != pb.Status_OK {
		t.Fatalf("control: %v %v", err, ack.Status)
	}
	open, _ := wire.SignOpen(key, &pb.OpenBody{Kind: pb.Kind_KIND_TCP, Workspace: ws.BaseDomain, From: identity.Public(key), To: body.Identity,
		IssuedAt: uint64(time.Now().Unix()), Nonce: []byte("same-nonce-00001"), Tcp: &pb.TcpOpen{Proto: pb.Proto_PROTO_TLS, Domain: "nowhere.test", Port: 443}})
	statuses := []pb.Status{}
	for i := 0; i < 2; i++ {
		st, err := mux.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wire.WriteMsg(st, &pb.StreamOpen{Open: open})
		var a pb.Ack
		if err := wire.ReadMsg(st, &a, wire.AckMax); err != nil {
			t.Fatalf("ack %d: %v", i, err)
		}
		statuses = append(statuses, a.Status)
		st.Reset()
	}
	if statuses[0] == pb.Status_REPLAY || statuses[1] != pb.Status_REPLAY {
		t.Fatalf("statuses: %v", statuses)
	}
	if !strings.Contains(statuses[0].String(), "NO_RULE") {
		t.Logf("first open answered %v (no route configured)", statuses[0])
	}
}
