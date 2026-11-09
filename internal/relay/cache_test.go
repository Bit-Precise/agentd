package relay

import (
	"testing"
	"time"

	"agentd/internal/wire/pb"
)

func TestAnswerCacheTTLLRUAndInvalidate(t *testing.T) {
	c := newAnswerCache(2)
	now := time.Now()
	a := &pb.RelayAnswer{Status: pb.Status_OK}
	c.put("k1", "home.test", a, time.Minute, now)
	c.put("k2", "work.test", a, time.Minute, now)
	if _, ok := c.get("k1", now, true); !ok {
		t.Fatal("k1 should be cached")
	}
	c.put("k3", "home.test", a, time.Minute, now) // evicts k2 (k1 was used)
	if _, ok := c.get("k2", now, true); ok {
		t.Fatal("k2 should be evicted")
	}
	later := now.Add(2 * time.Minute)
	if _, ok := c.get("k1", later, true); ok {
		t.Fatal("expired entry served as fresh")
	}
	if _, ok := c.get("k1", later, false); !ok {
		t.Fatal("expired entry must still serve while the backend is down")
	}
	c.invalidate("home.test")
	if c.len() != 0 {
		t.Fatalf("invalidate left %d entries", c.len())
	}
}

func TestCacheKeyAndWelcomeStripping(t *testing.T) {
	k1, ws := cacheKey(&pb.RelayLookup{Query: &pb.RelayLookup_Stream{Stream: &pb.StreamLookup{Workspace: "home.test", From: []byte{1}, Domain: "a.com", Port: 443}}})
	k2, _ := cacheKey(&pb.RelayLookup{Query: &pb.RelayLookup_Stream{Stream: &pb.StreamLookup{Workspace: "home.test", From: []byte{1}, Domain: "b.com", Port: 443}}})
	if k1 == k2 || ws != "home.test" {
		t.Fatalf("keys %q %q ws %q", k1, k2, ws)
	}
	if k, _ := cacheKey(&pb.RelayLookup{Query: &pb.RelayLookup_Join{Join: &pb.JoinLookup{}}}); k != "" {
		t.Fatal("join answers must not be cached")
	}
	a := &pb.RelayAnswer{Result: &pb.RelayAnswer_Node{Node: &pb.NodeInfo{Name: "laptop", Welcome: &pb.Signed{Body: []byte("x")}}}}
	if c := cacheable(a); c.GetNode().Welcome != nil || a.GetNode().Welcome == nil || c.GetNode().Name != "laptop" {
		t.Fatal("welcome must be stripped from the cached copy only")
	}
}
