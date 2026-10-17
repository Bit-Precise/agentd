// SPDX-License-Identifier: MPL-2.0
package xhttp

import (
	"context"
	"crypto/sha256"
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
	Version       = "1"
	SessionQuery  = "session"
	SequenceQuery = "seq"
	defaultPacket = 32 << 10
)

// ServerConfig bounds allocations before handing connections to the caller.
// Authorize is mandatory and runs for EVERY GET and POST. Its nonempty result
// must identify the full authenticated transport principal, not a display name.
type ServerConfig struct {
	Authorize               func(*http.Request) (string, error)
	AllowHTTP               bool // explicit loopback-only development exception
	MaxSessions             int
	MaxSessionsPerPrincipal int
	MaxPacketBytes          int
	MaxQueuedPackets        int
	MaxReorderPackets       int
	MaxConcurrentPosts      int
	MaxPostsPerSession      int
	SessionIdleTimeout      time.Duration
	PostTimeout             time.Duration
	WriteTimeout            time.Duration
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
	c            *conn
	id           string
	principal    string
	path         string
	out          chan *outPacket
	activity     chan struct{}
	posts        chan struct{}
	mu           sync.Mutex
	next         uint64
	acceptedNext uint64
	packets      map[uint64][]byte
	recent       map[uint64][32]byte
	history      []uint64
	ready        chan struct{}
	capacity     chan struct{}
}

type outPacket struct {
	data   []byte
	result chan error
}

func NewHandler(cfg ServerConfig) (*Handler, error) {
	if cfg.Authorize == nil {
		return nil, errors.New("xhttp: Authorize is required")
	}
	defaults := []struct {
		p          *int
		value, max int
	}{
		{&cfg.MaxSessions, 64, 65536}, {&cfg.MaxPacketBytes, defaultPacket, 4 << 20},
		{&cfg.MaxQueuedPackets, 8, 1024}, {&cfg.MaxReorderPackets, 8, 1024},
		{&cfg.MaxConcurrentPosts, 64, 4096}, {&cfg.MaxPostsPerSession, 4, 128},
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
	w.Header().Set(VersionHeader, Version)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil {
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
	if r.Header.Get(VersionHeader) != Version {
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
	c := newConn(r.Context(), h.cfg.MaxQueuedPackets, h.cfg.MaxPacketBytes)
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
		posts: make(chan struct{}, h.cfg.MaxPostsPerSession), packets: make(map[uint64][]byte),
		recent: make(map[uint64][32]byte), ready: make(chan struct{}, 1), capacity: make(chan struct{}, 1)}
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
	go s.pump(h.cfg.MaxQueuedPackets + h.cfg.MaxReorderPackets + 1)
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
	if r.ContentLength > int64(h.cfg.MaxPacketBytes) {
		http.Error(w, "packet too large", http.StatusRequestEntityTooLarge)
		return
	}
	select {
	case h.postSlots <- struct{}{}:
		defer func() { <-h.postSlots }()
	default:
		http.Error(w, "upload limit", http.StatusTooManyRequests)
		return
	}
	select {
	case s.posts <- struct{}{}:
		defer func() { <-s.posts }()
	default:
		http.Error(w, "session upload limit", http.StatusTooManyRequests)
		return
	}
	rc := http.NewResponseController(w)
	postCtx, cancel := context.WithTimeout(r.Context(), h.cfg.PostTimeout)
	defer cancel()
	if err := rc.SetReadDeadline(time.Now().Add(h.cfg.PostTimeout)); err != nil {
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
	packet, err := io.ReadAll(io.LimitReader(r.Body, int64(h.cfg.MaxPacketBytes)+1))
	if err != nil {
		http.Error(w, "invalid upload", http.StatusBadRequest)
		return
	}
	if len(packet) == 0 {
		http.Error(w, "empty packet", http.StatusBadRequest)
		return
	}
	if len(packet) > h.cfg.MaxPacketBytes {
		http.Error(w, "packet too large", http.StatusRequestEntityTooLarge)
		return
	}
	status := s.receiveWait(postCtx, seq, packet, h.cfg.MaxReorderPackets)
	if status != http.StatusNoContent {
		http.Error(w, http.StatusText(status), status)
		return
	}
	s.touch()
	w.WriteHeader(http.StatusNoContent)
}

func (s *serverSession) receiveWait(ctx context.Context, seq uint64, packet []byte, window int) int {
	for {
		status := s.receive(seq, packet, window)
		if status != http.StatusTooManyRequests {
			return status
		}
		select {
		case <-s.capacity:
		case <-ctx.Done():
			return http.StatusRequestTimeout
		case <-s.c.done:
			return http.StatusGone
		}
	}
}

func (s *serverSession) receive(seq uint64, packet []byte, window int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.c.done:
		return http.StatusGone
	default:
	}
	digest := sha256.Sum256(packet)
	if seq < s.next {
		if old, ok := s.recent[seq]; ok && old == digest {
			return http.StatusNoContent
		}
		return http.StatusConflict
	}
	if old, ok := s.packets[seq]; ok {
		if sha256.Sum256(old) == digest {
			return http.StatusNoContent
		}
		return http.StatusConflict
	}
	if seq-s.next > uint64(window) {
		if seq == s.acceptedNext {
			return http.StatusTooManyRequests
		}
		return http.StatusConflict
	}
	if len(s.packets) >= window+1 {
		return http.StatusTooManyRequests
	}
	s.packets[seq] = packet
	for {
		_, pending := s.packets[s.acceptedNext]
		_, delivered := s.recent[s.acceptedNext]
		if !pending && !delivered {
			break
		}
		s.acceptedNext++
	}
	select {
	case s.ready <- struct{}{}:
	default:
	}
	return http.StatusNoContent
}

func (s *serverSession) pump(historyLimit int) {
	for {
		s.mu.Lock()
		packet, ok := s.packets[s.next]
		if ok {
			delete(s.packets, s.next)
			s.recent[s.next] = sha256.Sum256(packet)
			s.history = append(s.history, s.next)
			if len(s.history) > historyLimit {
				delete(s.recent, s.history[0])
				s.history = s.history[1:]
			}
			s.next++
			select {
			case s.capacity <- struct{}{}:
			default:
			}
		}
		s.mu.Unlock()
		if ok {
			select {
			case s.c.in <- packet:
			case <-s.c.done:
				return
			}
			continue
		}
		select {
		case <-s.ready:
		case <-s.c.done:
			return
		}
	}
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
