package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"agentd/internal/identity"
	"agentd/internal/session"
	"agentd/internal/transport"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// LookupTimeout is RELAY_LOOKUP_TIMEOUT.
const LookupTimeout = 5 * time.Second

// errNotReady means agentserver is unreachable and nothing is cached.
var errNotReady = wire.Errorf(pb.Status_CONTROL_NOT_READY, "control plane unreachable")

// lookupMode selects how a query uses the cache.
type lookupMode int

const (
	cached lookupMode = iota // fresh cache entries answer; misses ask agentserver
	fresh                    // always ask when connected; fall back to the cache when not (node lookups at handshake)
	direct                   // never cached (join, cert)
)

// Backend is the relay session to agentserver (protocol 5.8).
type Backend struct {
	Key       ed25519.PrivateKey
	ServerURL string
	ServerKey []byte // learned from /.well-known/agentserver when empty
	Transport transport.Kind
	DialOpts  transport.Options
	Hello     *pb.RelayRegistration
	JoinToken string
	CacheTTL  time.Duration
	Log       *slog.Logger

	// Hooks into the hub and the edge.
	OnDeliver    func(node []byte, s *pb.Signed)
	OnInvalidate func(ws string, removed [][]byte)
	OnCerts      func(*pb.WorkspaceCerts)
	OnRelayCert  func(*pb.RelayCert)
	Online       func() [][]byte

	cache *answerCache

	mu        sync.Mutex
	send      func(*pb.ControlMessage) error
	readyCh   chan struct{}
	pending   map[string]chan *pb.RelayAnswer
	flights   map[string]*flight
	paths     map[string]string
	connected time.Time
}

type flight struct {
	done chan struct{}
	a    *pb.RelayAnswer
	err  error
}

func (b *Backend) init() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending == nil {
		b.pending = map[string]chan *pb.RelayAnswer{}
		b.flights = map[string]*flight{}
		b.readyCh = make(chan struct{})
		if b.cache == nil {
			b.cache = newAnswerCache(100000)
		}
		if b.CacheTTL == 0 {
			b.CacheTTL = 60 * time.Second
		}
		if b.Log == nil {
			b.Log = slog.Default()
		}
	}
}

// Connected reports whether the relay session is up.
func (b *Backend) Connected() bool {
	b.init()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.send != nil
}

// Run keeps the session up until ctx ends, with RECONNECT_BACKOFF.
func (b *Backend) Run(ctx context.Context) {
	b.init()
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := b.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		var he *session.HelloError
		if errors.As(err, &he) && (he.Hello.Status == pb.Status_TOKEN_INVALID || he.Hello.Status == pb.Status_NOT_A_MEMBER) {
			b.Log.Error("agentserver rejected this relay; register its key (agentserver relay add) or set a relay join token", "status", he.Hello.Status, "message", he.Hello.Message)
		} else {
			b.Log.Warn("control session down", "err", err)
		}
		if time.Since(start) > 60*time.Second {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(backoff)):
		}
		if backoff *= 2; backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

func jitter(d time.Duration) time.Duration {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(d/5)+1))
	return d - d/10 + time.Duration(n.Int64())
}

// FetchServerInfo reads /.well-known/agentserver over verified TLS.
func FetchServerInfo(ctx context.Context, base string, opts transport.Options) (key []byte, paths map[string]string, err error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: opts.RootCAs, ServerName: opts.ServerName, MinVersion: tls.VersionTLS12}}
	if opts.NetDial != nil {
		tr.DialContext = opts.NetDial
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/.well-known/agentserver", nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("well-known: HTTP %d", resp.StatusCode)
	}
	var v struct {
		Identity   string            `json:"identity"`
		Transports map[string]string `json:"transports"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, nil, err
	}
	key, err = identity.DecodeKey(v.Identity)
	return key, v.Transports, err
}

func (b *Backend) runOnce(ctx context.Context) error {
	dctx, cancel := context.WithTimeout(ctx, transport.DialTimeout+session.HandshakeTimeout)
	defer cancel()
	if len(b.ServerKey) == 0 || b.paths == nil {
		key, paths, err := FetchServerInfo(dctx, b.ServerURL, b.DialOpts)
		if err != nil {
			if len(b.ServerKey) == 0 {
				return fmt.Errorf("learn agentserver key: %w", err)
			}
		} else {
			if len(b.ServerKey) == 0 {
				b.ServerKey = key
				b.Log.Info("learned agentserver key from well-known", "key", identity.EncodeKey(key))
			} else if string(key) != string(b.ServerKey) {
				return fmt.Errorf("agentserver key %s does not match control.public_key", identity.EncodeKey(key))
			}
			b.paths = paths
		}
	}
	path := b.paths[string(b.Transport)]
	if path == "" {
		path = map[transport.Kind]string{transport.WebSocket: "/ws", transport.HTTPUpgrade: "/up", transport.XHTTP: "/x"}[b.Transport]
	}
	raw, err := transport.Dial(dctx, b.Transport, strings.TrimSuffix(b.ServerURL, "/")+path, b.DialOpts)
	if err != nil {
		return err
	}
	conn, _, err := session.Client(raw, session.InitiatorConfig{Local: b.Key, Remote: b.ServerKey, Hello: &pb.ClientHello{
		SessionKind: pb.SessionKind_SESSION_RELAY, JoinToken: b.JoinToken, Relay: b.Hello, ClientVersion: "agentrelay " + Version}})
	if err != nil {
		raw.Close()
		return err
	}
	mux, err := session.NewMux(conn, true)
	if err != nil {
		conn.Close()
		return err
	}
	defer mux.Close()
	st, err := mux.OpenStream(dctx)
	if err != nil {
		return err
	}
	open, err := wire.SignOpen(b.Key, &pb.OpenBody{Kind: pb.Kind_KIND_CONTROL, From: identity.Public(b.Key), To: b.ServerKey,
		IssuedAt: uint64(time.Now().Unix()), Nonce: randomBytes(16)})
	if err != nil {
		return err
	}
	if err := wire.WriteMsg(st, &pb.StreamOpen{Open: open}); err != nil {
		return err
	}
	var ack pb.Ack
	st.SetReadDeadline(time.Now().Add(session.HandshakeTimeout))
	if err := wire.ReadMsg(st, &ack, wire.AckMax); err != nil {
		return err
	}
	st.SetReadDeadline(time.Time{})
	if ack.Status != pb.Status_OK {
		return fmt.Errorf("control stream refused: %s %s", ack.Status, ack.Message)
	}
	var wmu sync.Mutex
	send := func(m *pb.ControlMessage) error {
		wmu.Lock()
		defer wmu.Unlock()
		st.SetWriteDeadline(time.Now().Add(30 * time.Second))
		return wire.WriteMsg(st, m)
	}
	b.setSend(send)
	defer b.setSend(nil)
	b.Log.Info("control session ready", "agentserver", b.ServerURL)
	if b.Online != nil {
		if on := b.Online(); len(on) > 0 {
			_ = send(&pb.ControlMessage{Msg: &pb.ControlMessage_RelayPresence{RelayPresence: &pb.RelayPresence{Online: on}}})
		}
	}
	go func() { <-ctx.Done(); mux.Close() }()
	for {
		var m pb.ControlMessage
		if err := wire.ReadMsg(st, &m, wire.ControlMsgMax); err != nil {
			return err
		}
		b.handle(&m)
	}
}

func (b *Backend) handle(m *pb.ControlMessage) {
	switch x := m.Msg.(type) {
	case *pb.ControlMessage_RelayAnswer:
		b.mu.Lock()
		ch := b.pending[string(x.RelayAnswer.RequestId)]
		delete(b.pending, string(x.RelayAnswer.RequestId))
		b.mu.Unlock()
		if ch != nil {
			ch <- x.RelayAnswer
		}
	case *pb.ControlMessage_Deliver:
		if b.OnDeliver != nil {
			b.OnDeliver(x.Deliver.Identity, x.Deliver.Signed)
		}
	case *pb.ControlMessage_RelayInvalidate:
		b.cache.invalidate(x.RelayInvalidate.Workspace)
		if b.OnInvalidate != nil {
			b.OnInvalidate(x.RelayInvalidate.Workspace, x.RelayInvalidate.Removed)
		}
	case *pb.ControlMessage_WorkspaceCerts:
		if b.OnCerts != nil {
			b.OnCerts(x.WorkspaceCerts)
		}
	case *pb.ControlMessage_RelayCert:
		if b.OnRelayCert != nil {
			b.OnRelayCert(x.RelayCert)
		}
	case *pb.ControlMessage_Notice:
		b.Log.Info("notice from agentserver", "kind", x.Notice.Kind, "message", x.Notice.Message)
	}
}

func (b *Backend) setSend(send func(*pb.ControlMessage) error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if send != nil {
		b.cache.invalidate("") // invalidations may have been missed while disconnected
		b.send = send
		b.connected = time.Now()
		close(b.readyCh)
		return
	}
	b.send = nil
	b.readyCh = make(chan struct{})
	for id, ch := range b.pending {
		close(ch)
		delete(b.pending, id)
	}
}

// Send writes a message to agentserver, waiting up to LookupTimeout for the
// session (node messages are dropped after that, protocol 5.1).
func (b *Backend) Send(ctx context.Context, m *pb.ControlMessage) error {
	b.init()
	b.mu.Lock()
	send, ready := b.send, b.readyCh
	b.mu.Unlock()
	if send == nil {
		t := time.NewTimer(LookupTimeout)
		defer t.Stop()
		select {
		case <-ready:
		case <-t.C:
			return errNotReady
		case <-ctx.Done():
			return ctx.Err()
		}
		b.mu.Lock()
		send = b.send
		b.mu.Unlock()
		if send == nil {
			return errNotReady
		}
	}
	return send(m)
}

// Presence reports nodes going online or offline.
func (b *Backend) Presence(online, offline [][]byte) {
	b.mu.Lock()
	send := b.send
	b.mu.Unlock()
	if send != nil {
		_ = send(&pb.ControlMessage{Msg: &pb.ControlMessage_RelayPresence{RelayPresence: &pb.RelayPresence{Online: online, Offline: offline}}})
	}
}

// Lookup answers a query from the cache or agentserver.
func (b *Backend) Lookup(ctx context.Context, q *pb.RelayLookup, mode lookupMode) (*pb.RelayAnswer, error) {
	b.init()
	key, ws := cacheKey(q)
	if mode == direct {
		key = ""
	}
	now := time.Now()
	if key != "" && mode == cached {
		if a, ok := b.cache.get(key, now, true); ok {
			return a, nil
		}
	}
	if !b.Connected() {
		if key != "" {
			if a, ok := b.cache.get(key, now, false); ok {
				return a, nil
			}
		}
		return nil, errNotReady
	}
	if key == "" || mode == fresh {
		return b.ask(ctx, q, key, ws)
	}
	b.mu.Lock()
	if f, ok := b.flights[key]; ok {
		b.mu.Unlock()
		select {
		case <-f.done:
			return f.a, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	b.flights[key] = f
	b.mu.Unlock()
	f.a, f.err = b.ask(ctx, q, key, ws)
	b.mu.Lock()
	delete(b.flights, key)
	b.mu.Unlock()
	close(f.done)
	return f.a, f.err
}

func (b *Backend) ask(ctx context.Context, q *pb.RelayLookup, key, ws string) (*pb.RelayAnswer, error) {
	q.RequestId = randomBytes(16)
	ch := make(chan *pb.RelayAnswer, 1)
	b.mu.Lock()
	send := b.send
	if send == nil {
		b.mu.Unlock()
		return nil, errNotReady
	}
	b.pending[string(q.RequestId)] = ch
	b.mu.Unlock()
	drop := func() {
		b.mu.Lock()
		delete(b.pending, string(q.RequestId))
		b.mu.Unlock()
	}
	if err := send(&pb.ControlMessage{Msg: &pb.ControlMessage_RelayLookup{RelayLookup: q}}); err != nil {
		drop()
		return nil, errNotReady
	}
	t := time.NewTimer(LookupTimeout)
	defer t.Stop()
	select {
	case a, ok := <-ch:
		if !ok {
			return nil, errNotReady
		}
		if key != "" && a.TtlSeconds > 0 {
			if n := a.GetNode(); n != nil && ws == "" {
				ws = n.Workspace
			}
			b.cache.put(key, ws, cacheable(a), time.Duration(a.TtlSeconds)*time.Second, time.Now())
		}
		return a, nil
	case <-t.C:
		drop()
		return nil, errNotReady
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
}

// Forget drops the cached answer for a node (after it joins).
func (b *Backend) Forget(node []byte) {
	b.init()
	b.cache.delete("node|" + hex.EncodeToString(node))
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// Version is the agentrelay build version (set with -ldflags).
var Version = "dev"
