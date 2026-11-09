package session

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"agentd/internal/wire/pb"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

type result struct {
	conn  *Conn
	hello *pb.ClientHello
	err   error
}

func handshake(t *testing.T, clientPriv ed25519.PrivateKey, serverPub ed25519.PublicKey, serverPriv ed25519.PrivateKey, decide DecideFunc, hello *pb.ClientHello) (*Conn, *pb.ServerHello, error, result) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan result, 1)
	go func() {
		c, h, err := Server(b, ResponderConfig{Local: serverPriv, Decide: decide})
		done <- result{c, h, err}
	}()
	c, sh, err := Client(a, InitiatorConfig{Local: clientPriv, Remote: serverPub, Hello: hello})
	if err != nil {
		a.Close()
	}
	r := <-done
	return c, sh, err, r
}

func okDecide(_ *pb.ClientHello, _ ed25519.PublicKey) *pb.ServerHello {
	return &pb.ServerHello{Status: pb.Status_OK, Workspace: "home.example.com", Name: "laptop"}
}

func TestHandshakeAndDataTransfer(t *testing.T) {
	cpub, cpriv := keys(t)
	spub, spriv := keys(t)
	var gotIdentity ed25519.PublicKey
	decide := func(h *pb.ClientHello, id ed25519.PublicKey) *pb.ServerHello {
		gotIdentity = id
		return okDecide(h, id)
	}
	c, sh, err, r := handshake(t, cpriv, spub, spriv, decide, &pb.ClientHello{SessionKind: pb.SessionKind_SESSION_NODE})
	if err != nil || r.err != nil {
		t.Fatalf("handshake: client=%v server=%v", err, r.err)
	}
	defer c.Close()
	defer r.conn.Close()
	if !bytes.Equal(gotIdentity, cpub) || !bytes.Equal(r.conn.RemoteIdentity(), cpub) || !bytes.Equal(c.RemoteIdentity(), spub) {
		t.Fatal("identities not propagated")
	}
	if sh.Name != "laptop" || !bytes.Equal(sh.ServerIdentity, spub) || len(sh.SessionId) != 16 || sh.Version != 1 {
		t.Fatalf("server hello: %v", sh)
	}
	payload := make([]byte, 1<<20+123)
	rand.Read(payload)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := c.Write(payload); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r.conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatal("payload corrupted")
	}
}

func TestWrongResponderKeyFails(t *testing.T) {
	_, cpriv := keys(t)
	_, spriv := keys(t)
	otherPub, _ := keys(t)
	_, _, err, r := handshake(t, cpriv, otherPub, spriv, okDecide, &pb.ClientHello{})
	if err == nil {
		t.Fatal("client accepted a responder with the wrong static key")
	}
	if r.err == nil {
		t.Fatal("server should fail to decrypt message 1")
	}
}

func TestRejectionIsDeliveredToClient(t *testing.T) {
	_, cpriv := keys(t)
	spub, spriv := keys(t)
	decide := func(*pb.ClientHello, ed25519.PublicKey) *pb.ServerHello {
		return &pb.ServerHello{Status: pb.Status_NOT_A_MEMBER, Message: "removed"}
	}
	_, sh, err, r := handshake(t, cpriv, spub, spriv, decide, &pb.ClientHello{})
	var he *HelloError
	if !errors.As(err, &he) || he.Hello.Status != pb.Status_NOT_A_MEMBER || sh.GetMessage() != "removed" {
		t.Fatalf("client: %v %v", err, sh)
	}
	if r.err == nil || r.conn != nil {
		t.Fatal("server should report the rejection and return no conn")
	}
}

func TestIdentityMismatchRejected(t *testing.T) {
	_, cpriv := keys(t)
	spub, spriv := keys(t)
	otherPub, _ := keys(t)
	called := false
	decide := func(*pb.ClientHello, ed25519.PublicKey) *pb.ServerHello { called = true; return &pb.ServerHello{} }
	_, _, err, _ := handshake(t, cpriv, spub, spriv, decide, &pb.ClientHello{Identity: otherPub})
	var he *HelloError
	if !errors.As(err, &he) || he.Hello.Status != pb.Status_IDENTITY_MISMATCH || called {
		t.Fatalf("expected IDENTITY_MISMATCH before Decide, got %v (decide called %v)", err, called)
	}
}

func TestVersionMismatchRejected(t *testing.T) {
	_, cpriv := keys(t)
	spub, spriv := keys(t)
	_, _, err, _ := handshake(t, cpriv, spub, spriv, okDecide, &pb.ClientHello{MinVersion: 5, MaxVersion: 9})
	var he *HelloError
	if !errors.As(err, &he) || he.Hello.Status != pb.Status_VERSION_MISMATCH {
		t.Fatalf("expected VERSION_MISMATCH, got %v", err)
	}
}

func TestRekeyKeepsBothSidesInSync(t *testing.T) {
	old := rekeyInterval
	rekeyInterval = 3
	defer func() { rekeyInterval = old }()
	_, cpriv := keys(t)
	spub, spriv := keys(t)
	c, _, err, r := handshake(t, cpriv, spub, spriv, okDecide, &pb.ClientHello{})
	if err != nil || r.err != nil {
		t.Fatal(err, r.err)
	}
	defer c.Close()
	defer r.conn.Close()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for i := 0; i < 50; i++ {
			c.Write([]byte{byte(i)})
		}
	}()
	buf := make([]byte, 1)
	for i := 0; i < 50; i++ {
		if _, err := io.ReadFull(r.conn, buf); err != nil || buf[0] != byte(i) {
			t.Fatalf("message %d: %v %v", i, buf, err)
		}
	}
	<-writerDone
}

func TestMuxOverSession(t *testing.T) {
	_, cpriv := keys(t)
	spub, spriv := keys(t)
	c, _, err, r := handshake(t, cpriv, spub, spriv, okDecide, &pb.ClientHello{})
	if err != nil || r.err != nil {
		t.Fatal(err, r.err)
	}
	cm, err := NewMux(c, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cm.Close()
	sm, err := NewMux(r.conn, false)
	if err != nil {
		t.Fatal(err)
	}
	defer sm.Close()
	errc := make(chan error, 1)
	go func() {
		s, err := sm.AcceptStream()
		if err != nil {
			errc <- err
			return
		}
		data, err := io.ReadAll(s)
		if err != nil {
			errc <- err
			return
		}
		s.Write(append([]byte("echo:"), data...))
		s.CloseWrite()
		errc <- nil
	}()
	s, err := cm.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("hello"))
	s.CloseWrite()
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(s)
	if err != nil || string(got) != "echo:hello" {
		t.Fatalf("got %q %v", got, err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if s.StreamID()%2 != 1 {
		t.Fatalf("client stream id %d should be odd", s.StreamID())
	}
}
