package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// XHTTP packet-up parameters (protocol 0.5, 2.4).
const (
	XHTTPMaxPost         = 1_000_000
	XHTTPMinPostInterval = 30 * time.Millisecond
	XHTTPReorderBuffer   = 30
	XHTTPSessionGC       = 30 * time.Second
)

// ---------------------------------------------------------------- client

func dialXHTTP(ctx context.Context, u *url.URL, opts Options) (net.Conn, error) {
	tr := &http.Transport{
		DialTLSContext:      func(ctx context.Context, _, _ string) (net.Conn, error) { return opts.dialTLS(ctx, u) },
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Transport: tr}
	var sidb [16]byte
	_, _ = rand.Read(sidb[:])
	sid := base64.RawURLEncoding.EncodeToString(sidb[:])
	base := strings.TrimSuffix(u.String(), "/") + "/" + sid

	getCtx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(getCtx, http.MethodGet, base, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}
	type getResult struct {
		resp *http.Response
		err  error
	}
	gr := make(chan getResult, 1)
	go func() {
		resp, err := client.Do(req)
		gr <- getResult{resp, err}
	}()
	var resp *http.Response
	select {
	case r := <-gr:
		if r.err != nil {
			cancel()
			return nil, r.err
		}
		resp = r.resp
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("xhttp: GET returned %s", resp.Status)
	}
	c := &xClient{
		client: client, base: base, ua: opts.UserAgent, down: resp.Body, cancel: cancel,
		kick: make(chan struct{}, 1), done: make(chan struct{}),
	}
	go c.sender()
	return c, nil
}

type xClient struct {
	client *http.Client
	base   string
	ua     string
	down   io.ReadCloser
	cancel context.CancelFunc

	mu      sync.Mutex
	pending bytes.Buffer
	err     error
	closed  bool
	kick    chan struct{}
	done    chan struct{}
	seq     uint64
}

func (c *xClient) Read(p []byte) (int, error) { return c.down.Read(p) }

func (c *xClient) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return 0, err
	}
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.pending.Write(p)
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return len(p), nil
}

// sender coalesces writes into POSTs no more often than XHTTPMinPostInterval.
func (c *xClient) sender() {
	last := time.Time{}
	for {
		select {
		case <-c.kick:
		case <-c.done:
			return
		}
		if wait := XHTTPMinPostInterval - time.Since(last); wait > 0 {
			select {
			case <-time.After(wait):
			case <-c.done:
				return
			}
		}
		for {
			c.mu.Lock()
			n := c.pending.Len()
			if n == 0 {
				c.mu.Unlock()
				break
			}
			if n > XHTTPMaxPost {
				n = XHTTPMaxPost
			}
			body := make([]byte, n)
			c.pending.Read(body)
			seq := c.seq
			c.seq++
			c.mu.Unlock()
			if err := c.post(seq, body); err != nil {
				c.mu.Lock()
				c.err = err
				c.mu.Unlock()
				c.Close()
				return
			}
			last = time.Now()
		}
	}
}

func (c *xClient) post(seq uint64, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, c.base+"/"+strconv.FormatUint(seq, 10), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.ua != "" {
		req.Header.Set("User-Agent", c.ua)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xhttp: POST returned %s", resp.Status)
	}
	return nil
}

func (c *xClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	close(c.done)
	c.cancel()
	return c.down.Close()
}

func (c *xClient) LocalAddr() net.Addr                { return xaddr("xhttp-client") }
func (c *xClient) RemoteAddr() net.Addr               { return xaddr(c.base) }
func (c *xClient) SetDeadline(t time.Time) error      { return nil }
func (c *xClient) SetReadDeadline(t time.Time) error  { return nil }
func (c *xClient) SetWriteDeadline(t time.Time) error { return nil }

type xaddr string

func (a xaddr) Network() string { return "xhttp" }
func (a xaddr) String() string  { return string(a) }

// ---------------------------------------------------------------- server

// XHTTPHandler serves packet-up sessions under a path prefix such as "/x/".
// accept is called in its own goroutine once per new session.
func XHTTPHandler(prefix string, accept func(net.Conn)) http.Handler {
	h := &xServer{prefix: prefix, accept: accept, sessions: map[string]*xSession{}}
	return h
}

type xServer struct {
	prefix   string
	accept   func(net.Conn)
	mu       sync.Mutex
	sessions map[string]*xSession
}

type xSession struct {
	srv     *xServer
	sid     string
	upR     *io.PipeReader
	upW     *io.PipeWriter
	downR   *io.PipeReader
	downW   *io.PipeWriter
	mu      sync.Mutex
	next    uint64
	pending map[uint64][]byte
	gotGet  bool
	gotPost bool
	closed  bool
	remote  string
}

func (s *xServer) session(sid, remote string, create bool) *xSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x := s.sessions[sid]; x != nil {
		return x
	}
	if !create {
		return nil
	}
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()
	x := &xSession{srv: s, sid: sid, upR: upR, upW: upW, downR: downR, downW: downW, pending: map[uint64][]byte{}, remote: remote}
	s.sessions[sid] = x
	time.AfterFunc(XHTTPSessionGC, func() {
		x.mu.Lock()
		half := !(x.gotGet && x.gotPost)
		x.mu.Unlock()
		if half {
			x.Close()
		}
	})
	go s.accept(&xServerConn{x: x})
	return x
}

func (s *xServer) remove(sid string) {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
}

func (s *xServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, s.prefix)
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || len(parts[0]) != 22 {
		http.NotFound(w, r)
		return
	}
	sid := parts[0]
	switch {
	case r.Method == http.MethodGet && len(parts) == 1:
		s.serveDown(w, r, sid)
	case r.Method == http.MethodPost && len(parts) == 2:
		seq, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			http.Error(w, "bad seq", http.StatusBadRequest)
			return
		}
		s.serveUp(w, r, sid, seq)
	default:
		http.NotFound(w, r)
	}
}

func (s *xServer) serveDown(w http.ResponseWriter, r *http.Request, sid string) {
	x := s.session(sid, r.RemoteAddr, true)
	x.mu.Lock()
	if x.gotGet {
		x.mu.Unlock()
		http.Error(w, "duplicate GET", http.StatusConflict)
		return
	}
	x.gotGet = true
	x.mu.Unlock()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	if fl != nil {
		fl.Flush()
	}
	buf := make([]byte, 32<<10)
	go func() {
		<-r.Context().Done()
		x.Close()
	}()
	for {
		n, err := x.downR.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				x.Close()
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *xServer) serveUp(w http.ResponseWriter, r *http.Request, sid string, seq uint64) {
	x := s.session(sid, r.RemoteAddr, true)
	body, err := io.ReadAll(io.LimitReader(r.Body, XHTTPMaxPost+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(body) > XHTTPMaxPost {
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return
	}
	x.mu.Lock()
	x.gotPost = true
	if x.closed {
		x.mu.Unlock()
		http.Error(w, "closed", http.StatusNotFound)
		return
	}
	if _, dup := x.pending[seq]; dup || seq < x.next {
		x.mu.Unlock()
		http.Error(w, "duplicate seq", http.StatusConflict)
		return
	}
	x.pending[seq] = body
	if len(x.pending) > XHTTPReorderBuffer {
		x.mu.Unlock()
		x.Close()
		http.Error(w, "reorder buffer exceeded", http.StatusConflict)
		return
	}
	var ready [][]byte
	for {
		b, ok := x.pending[x.next]
		if !ok {
			break
		}
		delete(x.pending, x.next)
		x.next++
		ready = append(ready, b)
	}
	x.mu.Unlock()
	for _, b := range ready {
		if _, err := x.upW.Write(b); err != nil {
			http.Error(w, "closed", http.StatusNotFound)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (x *xSession) Close() error {
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return nil
	}
	x.closed = true
	x.mu.Unlock()
	x.srv.remove(x.sid)
	x.upW.CloseWithError(io.EOF)
	x.upR.Close()
	x.downW.Close()
	return nil
}

type xServerConn struct{ x *xSession }

func (c *xServerConn) Read(p []byte) (int, error) { return c.x.upR.Read(p) }
func (c *xServerConn) Write(p []byte) (int, error) {
	n, err := c.x.downW.Write(p)
	if errors.Is(err, io.ErrClosedPipe) {
		err = net.ErrClosed
	}
	return n, err
}
func (c *xServerConn) Close() error                       { return c.x.Close() }
func (c *xServerConn) LocalAddr() net.Addr                { return xaddr("xhttp-server") }
func (c *xServerConn) RemoteAddr() net.Addr               { return xaddr(c.x.remote) }
func (c *xServerConn) SetDeadline(t time.Time) error      { return nil }
func (c *xServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xServerConn) SetWriteDeadline(t time.Time) error { return nil }
