package control

import (
	"context"
	"net"
	"testing"
	"time"

	"agentd/internal/identity"
	"agentd/internal/pgtest"
	"agentd/internal/session"
	"agentd/internal/store"
	"agentd/internal/wire/pb"
)

// A registered relay that completes the handshake but never opens its control
// stream must not hold a session on agentserver.
func TestRelayMustOpenControlStream(t *testing.T) {
	old := RelayControlTimeout
	RelayControlTimeout = 200 * time.Millisecond
	t.Cleanup(func() { RelayControlTimeout = old })

	ctx := context.Background()
	st, err := store.Open(ctx, pgtest.NewDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	srvKey, _ := identity.GenerateKey()
	c := New(Options{Store: st, ServerKey: srvKey, Certs: NewCertManager(st, nil, "", nil)})
	relayKey, _ := identity.GenerateKey()
	if err := st.CreateRelay(ctx, store.Relay{Name: "relay-hk", PublicKey: identity.Public(relayKey), URL: "https://relay.example.com"}); err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { c.serveRelay(server); close(done) }()
	conn, sh, err := session.Client(client, session.InitiatorConfig{Local: relayKey, Remote: identity.Public(srvKey),
		Hello: &pb.ClientHello{SessionKind: pb.SessionKind_SESSION_RELAY}})
	if err != nil || sh.Status != pb.Status_OK {
		t.Fatalf("relay handshake: %v %v", err, sh)
	}
	mux, err := session.NewMux(conn, true)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agentserver kept a relay session that never opened its control stream")
	}
	select {
	case <-mux.CloseChan():
	case <-time.After(5 * time.Second):
		t.Fatal("relay side of the session is still open")
	}
}
