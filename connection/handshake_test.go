package connection

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandshakeRejectsUnauthenticatedOrConflictingIdentity(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		callback AuthenticateFunc
	}{
		{"bad credential", func(context.Context, Hello) (Principal, error) {
			return Principal{}, errors.New("secret should not appear in peer errors")
		}},
		{"missing authenticator", nil},
		{"principal mismatch", func(context.Context, Hello) (Principal, error) {
			return Principal{Role: RoleAccess, Workspace: "other", AgentID: "agent1", Generation: 1}, nil
		}},
		{"expired credential", func(context.Context, Hello) (Principal, error) {
			return Principal{Role: RoleAccess, Workspace: "workspace1", AgentID: "agent1", Generation: 1, ExpiresAt: time.Now().Add(-time.Second)}, nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			a, b := net.Pipe()
			defer func() { _ = a.Close(); _ = b.Close() }()
			done := make(chan error, 1)
			go func() { _, err := Server(t.Context(), b, test.callback, Config{}); done <- err }()
			_, err := Client(t.Context(), a, Hello{Version: ProtocolVersion, Role: RoleAccess, Workspace: "workspace1", AgentID: "agent1", Token: "token"}, Config{})
			if err == nil {
				t.Fatal("handshake unexpectedly succeeded")
			}
			if strings.Contains(err.Error(), "secret should") {
				t.Fatal("authentication details leaked")
			}
			if err := <-done; err == nil {
				t.Fatal("server accepted handshake")
			}
		})
	}
}

func TestNoMultiplexedStreamBeforeAuthentication(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		send func(net.Conn)
	}{
		{"oversized frame", func(c net.Conn) { var h [4]byte; binary.BigEndian.PutUint32(h[:], 1<<30); _, _ = c.Write(h[:]) }},
		{"version", func(c net.Conn) {
			_ = writeFrame(c, Hello{Version: 99, Role: RoleAccess, Workspace: "w", AgentID: "a", Token: "t"}, 16384)
			var r handshakeReply
			_ = readFrame(c, &r, 16384)
		}},
		{"role", func(c net.Conn) {
			_ = writeFrame(c, Hello{Version: 1, Role: "admin", Workspace: "w", AgentID: "a", Token: "t"}, 16384)
			var r handshakeReply
			_ = readFrame(c, &r, 16384)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			a, b := net.Pipe()
			defer func() { _ = a.Close(); _ = b.Close() }()
			var calls atomic.Int32
			done := make(chan error, 1)
			go func() {
				_, err := Server(t.Context(), b, func(context.Context, Hello) (Principal, error) { calls.Add(1); return Principal{}, nil }, Config{HandshakeTimeout: time.Second})
				done <- err
			}()
			test.send(a)
			if err := <-done; err == nil {
				t.Fatal("invalid pre-auth bytes accepted")
			}
			if calls.Load() != 0 {
				t.Fatal("authentication invoked for invalid protocol")
			}
		})
	}
}

func TestHandshakeTimeoutAndContextCancel(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	start := time.Now()
	_, err := Server(t.Context(), b, nil, Config{HandshakeTimeout: 30 * time.Millisecond})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("handshake timeout not enforced: %v", err)
	}
	c, d := net.Pipe()
	defer func() { _ = c.Close(); _ = d.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = Client(ctx, c, Hello{Version: 1, Role: RoleAccess, Workspace: "w", AgentID: "a", Token: "t"}, Config{})
	if err == nil {
		t.Fatal("cancelled handshake succeeded")
	}
}

func TestClientRejectsWelcomeIdentityConfusion(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() {
		var h Hello
		if err := readFrame(b, &h, 16384); err != nil {
			return
		}
		_ = writeFrame(b, handshakeReply{Welcome: &Welcome{Version: 1, Principal: Principal{Role: RoleProvider, Workspace: "w", AgentID: "a", ConnectorID: "c", Generation: 1, SessionID: "s", ExpiresAt: time.Now().Add(time.Minute)}}}, 16384)
	}()
	_, err := Client(t.Context(), a, Hello{Version: 1, Role: RoleAccess, Workspace: "w", AgentID: "a", Token: "t"}, Config{})
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("welcome identity confusion: %v", err)
	}
}
