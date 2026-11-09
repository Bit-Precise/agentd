package relay

import (
	"container/list"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/wire/pb"
)

// answerCache holds control-plane answers by query (protocol 5.8): bounded
// LRU, per-answer TTL, invalidated per workspace. Expired entries are kept so
// they can still serve while agentserver is unreachable.
type answerCache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List
	items map[string]*list.Element
}

type cacheEntry struct {
	key     string
	ws      string
	answer  *pb.RelayAnswer
	expires time.Time
}

func newAnswerCache(max int) *answerCache {
	return &answerCache{max: max, ll: list.New(), items: map[string]*list.Element{}}
}

// get returns an answer; fresh=false also accepts expired entries.
func (c *answerCache) get(key string, now time.Time, fresh bool) (*pb.RelayAnswer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if fresh && now.After(e.expires) {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return e.answer, true
}

func (c *answerCache) put(key, ws string, a *pb.RelayAnswer, ttl time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*cacheEntry)
		e.ws, e.answer, e.expires = ws, a, now.Add(ttl)
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(&cacheEntry{key: key, ws: ws, answer: a, expires: now.Add(ttl)})
	for c.max > 0 && c.ll.Len() > c.max {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.items, old.Value.(*cacheEntry).key)
	}
}

func (c *answerCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.Remove(el)
		delete(c.items, key)
	}
}

// invalidate drops a workspace's entries ("" drops everything). Entries
// whose workspace is unknown (errors for unknown keys) go too.
func (c *answerCache) invalidate(ws string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, el := range c.items {
		e := el.Value.(*cacheEntry)
		if ws == "" || e.ws == ws || e.ws == "" {
			c.ll.Remove(el)
			delete(c.items, key)
		}
	}
}

func (c *answerCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// cacheKey returns the key of a cacheable query and the workspace it belongs
// to; "" means the query is never cached (join, cert).
func cacheKey(q *pb.RelayLookup) (key, ws string) {
	switch x := q.Query.(type) {
	case *pb.RelayLookup_Node:
		return "node|" + hex.EncodeToString(x.Node.Identity), ""
	case *pb.RelayLookup_Stream:
		s := x.Stream
		return fmt.Sprintf("stream|%s|%x|%d|%d|%s|%d|%x", s.Workspace, s.From, s.Kind, s.Proto, s.Domain, s.Port, s.Executor), s.Workspace
	}
	return "", ""
}

// cacheable strips what must not be cached (the Welcome).
func cacheable(a *pb.RelayAnswer) *pb.RelayAnswer {
	if n := a.GetNode(); n != nil && n.Welcome != nil {
		c := proto.Clone(a).(*pb.RelayAnswer)
		c.GetNode().Welcome = nil
		return c
	}
	return a
}
