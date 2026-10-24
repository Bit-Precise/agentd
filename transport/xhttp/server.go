// SPDX-License-Identifier: MPL-2.0
package xhttp

import (
	"container/heap"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	VersionHeader = "X-Agents-XHTTP-Version"
	// Version 2 clients follow Xray's packet-up upload: many POSTs may be in
	// flight at once. Servers still accept version 1, whose clients upload one
	// packet at a time and are therefore a special case of version 2.
	Version       = "2"
	legacyVersion = "1"
	SessionQuery  = "session"
	SequenceQuery = "seq"
	// downloadChunk bounds one download read or response write. Upload sizes
	// are governed by MaxEachPostBytes instead.
	downloadChunk = 32 << 10
	// Xray-core splithttp defaults: scMaxEachPostBytes, scMinPostsIntervalMs
	// and scMaxBufferedPosts.
	defaultMaxEachPostBytes = 1000000
	defaultMinPostsInterval = 30 * time.Millisecond
	defaultMaxBufferedPosts = 30
)

// ServerConfig bounds allocations before handing connections to the caller.
// Authorize is mandatory and runs for EVERY GET and POST. Its nonempty result
// must identify the full authenticated transport principal, not a display name.
type ServerConfig struct {
	Authorize               func(*http.Request) (string, error)
	AllowHTTP               bool // explicit loopback-only development exception
	TLSOffload              bool // trusted TLS ingress terminates HTTPS before this listener
	MaxSessions             int
	MaxSessionsPerPrincipal int
	// MaxEachPostBytes is Xray's scMaxEachPostBytes: the largest upload body.
	// Clients must not be configured with a larger value.
	MaxEachPostBytes int
	// MaxBufferedPosts is Xray's scMaxBufferedPosts. It sizes the queue of
	// received packets; a session whose out-of-order backlog exceeds it is
	// closed instead of buffering without bound.
	MaxBufferedPosts int
	// MaxQueuedPackets bounds download packets waiting for the GET response.
	MaxQueuedPackets int
	// MaxConcurrentPosts bounds POST bodies being read across all sessions and
	// MaxPostsPerSession the POSTs one session may have inside the handler.
	// Excess POSTs wait (up to PostTimeout) instead of being rejected.
	MaxConcurrentPosts int
	MaxPostsPerSession int
	SessionIdleTimeout time.Duration
	PostTimeout        time.Duration
	WriteTimeout       time.Duration
}

type Handler struct {
	cfg        ServerConfig
	mu         sync.Mutex
	sessions   map[string]*serverSession
	principals map[string]int
	pending    []*serverSession
	notify     chan struct{}
	closed     chan struct{}
	once       sync.Once
	postSlots  chan struct{}
}

type serverSession struct {
	c         *conn
	id        string
	principal string
	path      string
	out       chan *outPacket
	activity  chan struct{}
	posts     chan struct{}
	// pushed is Xray's uploadQueue.pushedPackets: a full queue blocks POST
	// handlers, which is the upload backpressure.
	pushed chan uploadPacket
}

type uploadPacket struct {
	seq     uint64
	payload []byte
}

type outPacket struct {
	data   []byte
	result chan error
}

func NewHandler(cfg ServerConfig) (*Handler, error) {
	if cfg.Authorize == nil {
		return nil, errors.New("xhttp: Authorize is required")
	}
	if cfg.MaxPostsPerSession == 0 {
		cfg.MaxPostsPerSession = max(cfg.MaxBufferedPosts, 0)
	}
	defaults := []struct {
		p          *int
		value, max int
	}{
		{&cfg.MaxSessions, 64, 65536}, {&cfg.MaxEachPostBytes, defaultMaxEachPostBytes, 16 << 20},
		{&cfg.MaxBufferedPosts, defaultMaxBufferedPosts, 1024}, {&cfg.MaxQueuedPackets, 8, 1024},
		{&cfg.MaxConcurrentPosts, 256, 65536}, {&cfg.MaxPostsPerSession, defaultMaxBufferedPosts, 1024},
	}
	for _, d := range defaults {
		if *d.p == 0 {
			*d.p = d.value
		}
		if *d.p < 1 || *d.p > d.max {
			return nil, errors.New("xhttp: invalid server limit")
		}
	}
	if cfg.MaxSessionsPerPrincipal == 0 {
		cfg.MaxSessionsPerPrincipal = min(8, cfg.MaxSessions)
	}
	if cfg.MaxSessionsPerPrincipal < 1 || cfg.MaxSessionsPerPrincipal > cfg.MaxSessions {
		return nil, errors.New("xhttp: invalid principal session limit")
	}
	for _, d := range []struct {
		p     *time.Duration
		value time.Duration
	}{
		{&cfg.SessionIdleTimeout, 2 * time.Minute}, {&cfg.PostTimeout, 15 * time.Second}, {&cfg.WriteTimeout, 30 * time.Second},
	} {
		if *d.p == 0 {
			*d.p = d.value
		}
		if *d.p < 0 {
			return nil, errors.New("xhttp: negative timeout")
		}
	}
	return &Handler{cfg: cfg, sessions: make(map[string]*serverSession), principals: make(map[string]int),
		notify: make(chan struct{}, 1), closed: make(chan struct{}), postSlots: make(chan struct{}, cfg.MaxConcurrentPosts)}, nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16
}

func singleQuery(r *http.Request, name string) (string, bool) {
	// ParseQuery's errors must not be silently discarded by URL.Query.
	v, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", false
	}
	values := v[name]
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-transform")
	version := r.Header.Get(VersionHeader)
	supported := version == Version || version == legacyVersion
	if supported {
		w.Header().Set(VersionHeader, version)
	} else {
		w.Header().Set(VersionHeader, Version)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil && !h.cfg.TLSOffload {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if !h.cfg.AllowHTTP || err != nil || !loopbackHost(host) {
			http.Error(w, "HTTPS required", http.StatusForbidden)
			return
		}
	}
	principal, err := h.cfg.Authorize(r)
	if err != nil || principal == "" || len(principal) > 512 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !supported {
		http.Error(w, "unsupported transport version", http.StatusBadRequest)
		return
	}
	id, ok := singleQuery(r, SessionQuery)
	if !ok || !validSessionID(id) {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	select {
	case <-h.closed:
		http.Error(w, "closed", http.StatusServiceUnavailable)
		return
	default:
	}
	if r.Method == http.MethodGet {
		h.serveDown(w, r, id, principal)
		return
	}
	h.serveUp(w, r, id, principal)
}

func (h *Handler) serveDown(w http.ResponseWriter, r *http.Request, id, principal string) {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.URL.Query().Has(SequenceQuery) {
		http.Error(w, "GET must not contain an upload", http.StatusBadRequest)
		return
	}
	rc := http.NewResponseController(w)
	// The uploaded byte queue is the reorder queue; the conn holds at most one
	// delivered packet that its reader has not consumed yet.
	c := newConn(r.Context(), 1, downloadChunk)
	c.principal = principal
	// A response write deadline also runs while an HTTP/2 stream is idle. Keep
	// it scoped to Write/Flush and serialize resets against Close's forced
	// deadline, otherwise a successful write can accidentally undo cancellation.
	var writeDeadlineMu sync.Mutex
	setWriteDeadline := func(at time.Time) error {
		writeDeadlineMu.Lock()
		defer writeDeadlineMu.Unlock()
		select {
		case <-c.done:
			return c.closedError()
		default:
			return rc.SetWriteDeadline(at)
		}
	}
	c.remote = address(r.RemoteAddr)
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		c.local = a
	}
	s := &serverSession{c: c, id: id, principal: principal, path: r.URL.EscapedPath(),
		out: make(chan *outPacket, h.cfg.MaxQueuedPackets), activity: make(chan struct{}, 1),
		posts: make(chan struct{}, h.cfg.MaxPostsPerSession), pushed: make(chan uploadPacket, h.cfg.MaxBufferedPosts)}
	c.writePacket = func(p []byte) error {
		if err := s.send(p); err != nil {
			return err
		}
		s.touch()
		return nil
	}
	h.mu.Lock()
	select {
	case <-h.closed:
		h.mu.Unlock()
		c.Close()
		http.Error(w, "closed", http.StatusServiceUnavailable)
		return
	default:
	}
	if _, exists := h.sessions[id]; exists {
		h.mu.Unlock()
		c.Close()
		http.Error(w, "session already exists", http.StatusConflict)
		return
	}
	if len(h.sessions) >= h.cfg.MaxSessions || h.principals[principal] >= h.cfg.MaxSessionsPerPrincipal {
		h.mu.Unlock()
		c.Close()
		http.Error(w, "session limit", http.StatusTooManyRequests)
		return
	}
	h.sessions[id] = s
	h.principals[principal]++
	c.onClose = func() {
		h.remove(s)
		// Interrupt a blocked response write, including an HTTP/2 stream write.
		writeDeadlineMu.Lock()
		_ = rc.SetWriteDeadline(time.Now())
		writeDeadlineMu.Unlock()
	}
	h.mu.Unlock()
	c.startContextWatch()
	defer c.closeWithError(io.EOF)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	if err := setWriteDeadline(time.Now().Add(h.cfg.WriteTimeout)); err != nil {
		c.closeWithError(err)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		c.closeWithError(err)
		return
	}
	if err := setWriteDeadline(time.Time{}); err != nil {
		c.closeWithError(err)
		return
	}
	h.mu.Lock()
	select {
	case <-c.done:
	default:
		h.pending = append(h.pending, s)
		h.wake()
	}
	h.mu.Unlock()
	go s.reorder(h.cfg.MaxBufferedPosts)
	go s.watchIdle(h.cfg.SessionIdleTimeout)
	for {
		select {
		case packet := <-s.out:
			if err := setWriteDeadline(time.Now().Add(h.cfg.WriteTimeout)); err != nil {
				c.closeWithError(err)
				return
			}
			select {
			case <-c.done:
				return
			default:
			}
			if _, err := w.Write(packet.data); err != nil {
				packet.result <- err
				c.closeWithError(err)
				return
			}
			if err := rc.Flush(); err != nil {
				packet.result <- err
				c.closeWithError(err)
				return
			}
			if err := setWriteDeadline(time.Time{}); err != nil {
				packet.result <- err
				c.closeWithError(err)
				return
			}
			packet.result <- nil
			s.touch()
		case <-c.done:
			return
		}
	}
}

func (s *serverSession) send(data []byte) error {
	p := &outPacket{data: append([]byte(nil), data...), result: make(chan error, 1)}
	out := s.out
	sent := false
	for {
		at, changed := s.c.wd.watch()
		if !at.IsZero() && !time.Now().Before(at) {
			err := &timeoutError{"write"}
			if sent {
				s.c.closeWithError(err)
			}
			return err
		}
		tick, stop := timerFor(at)
		select {
		case out <- p:
			out = nil
			sent = true
		case err := <-p.result:
			stop()
			return err
		case <-changed:
		case <-tick:
			stop()
			err := &timeoutError{"write"}
			if sent {
				s.c.closeWithError(err)
			}
			return err
		case <-s.c.done:
			stop()
			return s.c.closedError()
		}
		stop()
	}
}

func (h *Handler) serveUp(w http.ResponseWriter, r *http.Request, id, principal string) {
	h.mu.Lock()
	s := h.sessions[id]
	h.mu.Unlock()
	if s == nil || s.principal != principal || s.path != r.URL.EscapedPath() {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	select {
	case <-s.c.done:
		http.Error(w, "session closed", http.StatusGone)
		return
	default:
	}
	seqText, ok := singleQuery(r, SequenceQuery)
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if !ok || err != nil || strconv.FormatUint(seq, 10) != seqText || seq == math.MaxUint64 {
		http.Error(w, "invalid sequence", http.StatusBadRequest)
		return
	}
	if r.ContentLength > int64(h.cfg.MaxEachPostBytes) {
		http.Error(w, "packet too large", http.StatusRequestEntityTooLarge)
		return
	}
	postCtx, cancel := context.WithTimeout(r.Context(), h.cfg.PostTimeout)
	defer cancel()
	// Excess POSTs wait for a slot instead of failing: a pipelined client treats
	// any failed POST as a lost byte range and closes the whole connection. The
	// session slot comes first so a stalled session cannot hold global slots.
	if status := s.acquire(postCtx, s.posts, h.closed); status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer func() { <-s.posts }()
	if status := s.acquire(postCtx, h.postSlots, h.closed); status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	holdingGlobal := true
	releaseGlobal := func() {
		if holdingGlobal {
			holdingGlobal = false
			<-h.postSlots
		}
	}
	defer releaseGlobal()
	rc := http.NewResponseController(w)
	deadline, _ := postCtx.Deadline()
	if err := rc.SetReadDeadline(deadline); err != nil {
		http.Error(w, "read deadline unavailable", http.StatusInternalServerError)
		return
	}
	readCancelled := make(chan struct{})
	stopReadCancel := context.AfterFunc(s.c.ctx, func() {
		_ = rc.SetReadDeadline(time.Now())
		close(readCancelled)
	})
	defer func() {
		if !stopReadCancel() {
			<-readCancelled
		}
		_ = rc.SetReadDeadline(time.Time{})
	}()
	select {
	case <-s.c.done:
		http.Error(w, "session closed", http.StatusGone)
		return
	default:
	}
	packet, err := io.ReadAll(io.LimitReader(r.Body, int64(h.cfg.MaxEachPostBytes)+1))
	if err != nil {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}
	if len(packet) == 0 {
		http.Error(w, "empty packet", http.StatusBadRequest)
		return
	}
	if len(packet) > h.cfg.MaxEachPostBytes {
		http.Error(w, "packet too large", http.StatusRequestEntityTooLarge)
		return
	}
	// The global slot bounds concurrent body reads. Waiting for this session's
	// queue below must not starve other sessions.
	releaseGlobal()
	select {
	case s.pushed <- uploadPacket{seq: seq, payload: packet}:
	case <-postCtx.Done():
		http.Error(w, "upload queue timeout", http.StatusRequestTimeout)
		return
	case <-s.c.done:
		http.Error(w, "session closed", http.StatusGone)
		return
	}
	s.touch()
	w.WriteHeader(http.StatusNoContent)
}

func (s *serverSession) acquire(ctx context.Context, slots chan struct{}, closed <-chan struct{}) int {
	select {
	case slots <- struct{}{}:
		return 0
	case <-ctx.Done():
		return http.StatusRequestTimeout
	case <-s.c.done:
		return http.StatusGone
	case <-closed:
		return http.StatusServiceUnavailable
	}
}

// reorder is Xray's uploadQueue.Read run as a pump. It delivers packets in
// sequence order and drops packets older than the next sequence, so duplicate
// POSTs are idempotent. More than maxPackets out-of-order packets close the
// session instead of buffering without bound. Delivery blocks until the reader
// consumes, which fills pushed and holds new POSTs: that is the backpressure.
func (s *serverSession) reorder(maxPackets int) {
	var waiting uploadHeap
	var next uint64
	for {
		for waiting.Len() > 0 {
			p := heap.Pop(&waiting).(uploadPacket)
			if p.seq < next {
				continue
			}
			if p.seq == next {
				select {
				case s.c.in <- p.payload:
				case <-s.c.done:
					return
				}
				next++
				continue
			}
			if waiting.Len() > maxPackets {
				s.c.closeWithError(errors.New("xhttp: packet queue is too large"))
				return
			}
			heap.Push(&waiting, p)
			break
		}
		select {
		case p := <-s.pushed:
			heap.Push(&waiting, p)
		case <-s.c.done:
			return
		}
	}
}

type uploadHeap []uploadPacket

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].seq < h[j].seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *uploadHeap) Push(x any)        { *h = append(*h, x.(uploadPacket)) }
func (h *uploadHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

func (s *serverSession) touch() {
	select {
	case s.activity <- struct{}{}:
	default:
	}
}
func (s *serverSession) watchIdle(timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		select {
		case <-s.activity:
			t.Reset(timeout)
		case <-t.C:
			s.c.closeWithError(&timeoutError{"idle"})
			return
		case <-s.c.done:
			return
		}
	}
}

func (h *Handler) wake() {
	select {
	case h.notify <- struct{}{}:
	default:
	}
}
func (h *Handler) remove(s *serverSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessions[s.id] != s {
		return
	}
	delete(h.sessions, s.id)
	h.principals[s.principal]--
	if h.principals[s.principal] == 0 {
		delete(h.principals, s.principal)
	}
	for i, pending := range h.pending {
		if pending == s {
			copy(h.pending[i:], h.pending[i+1:])
			h.pending[len(h.pending)-1] = nil
			h.pending = h.pending[:len(h.pending)-1]
			break
		}
	}
}

func (h *Handler) Accept(ctx context.Context) (net.Conn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h.mu.Lock()
		select {
		case <-h.closed:
			h.mu.Unlock()
			return nil, net.ErrClosed
		default:
		}
		for len(h.pending) > 0 {
			s := h.pending[0]
			h.pending[0] = nil
			h.pending = h.pending[1:]
			select {
			case <-s.c.done:
				continue
			default:
			}
			if len(h.pending) > 0 {
				h.wake()
			}
			h.mu.Unlock()
			return s.c, nil
		}
		h.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-h.closed:
			return nil, net.ErrClosed
		case <-h.notify:
		}
	}
}

func (h *Handler) ActiveSessions() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.sessions) }
func (h *Handler) Close() error {
	h.once.Do(func() {
		h.mu.Lock()
		close(h.closed)
		all := make([]*serverSession, 0, len(h.sessions))
		for _, s := range h.sessions {
			all = append(all, s)
		}
		h.mu.Unlock()
		for _, s := range all {
			s.c.closeWithError(net.ErrClosed)
		}
	})
	return nil
}

func (h *Handler) String() string {
	return fmt.Sprintf("xhttp packet-up (%d active sessions)", h.ActiveSessions())
}
