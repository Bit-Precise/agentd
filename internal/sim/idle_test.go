package sim

import (
	"testing"
	"time"

	"agentd/internal/session"
)

// TestSessionsSurviveIdleKeepalives: with short yamux timers, idle node and
// relay sessions must stay up across many keepalives (a WebSocket deadline
// bug used to drop them at the first keepalive after the write timeout).
func TestSessionsSurviveIdleKeepalives(t *testing.T) {
	ka, wt := session.KeepAliveInterval, session.WriteTimeout
	// Equal values as in production (30 s each): each keepalive lands on the
	// rolling write deadline.
	session.KeepAliveInterval, session.WriteTimeout = 300*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { session.KeepAliveInterval, session.WriteTimeout = ka, wt })
	s := newStack(t)
	s.workspace("home")
	n := s.join("home", "idle", "")
	time.Sleep(4 * time.Second) // about thirteen keepalives
	st := n.a.Status()["session"]
	b, _ := jsonMarshal(st)
	if !contains(b, `"state":"ready"`) || !contains(b, `"reconnects":0`) {
		t.Fatalf("node session did not stay up: %s", b)
	}
	if ok, _ := s.srv.Coordinator.RelayConnected(relayName); !ok {
		t.Fatal("relay session dropped")
	}
}
