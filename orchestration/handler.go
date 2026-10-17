package orchestration

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/stream"
)

// Handle registers a pending flow before any DNS lookup or origin connection.
func (m *Manager) Handle(parent context.Context, s *connection.Stream) error {
	ctx, finish, err := m.begin(parent, s)
	if err != nil {
		_ = s.Close()
		return err
	}
	defer finish()
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	r := s.Request()
	if r.Purpose == connection.PurposeServe {
		return m.serve(ctx, s, r.Resource)
	}
	m.mu.Lock()
	dial := m.dial
	m.mu.Unlock()
	upstream, err := dial(ctx, "tcp", net.JoinHostPort(r.Destination.Host, strconv.Itoa(int(r.Destination.Port))))
	if err != nil {
		return err
	}
	// The cancellation may have raced with a dialer completing successfully.
	if ctx.Err() != nil {
		_ = upstream.Close()
		return ctx.Err()
	}
	stream.Pipe(ctx, s, upstream)
	return nil
}

func (m *Manager) serve(ctx context.Context, s *connection.Stream, name string) error {
	origin, host, err := m.origin(name)
	if err != nil {
		return err
	}
	proxy := httputil.NewSingleHostReverseProxy(origin)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil              // local origins never use environment HTTP proxies
	transport.DisableKeepAlives = true // one approved HTTP request per logical flow
	transport.ResponseHeaderTimeout = 30 * time.Second
	defer transport.CloseIdleConnections()
	proxy.Transport = transport
	proxy.ModifyResponse = func(resp *http.Response) error {
		cookies := resp.Cookies()
		resp.Header.Del("Set-Cookie")
		for _, cookie := range cookies {
			if cookie.Domain == "" && !strings.HasPrefix(cookie.Name, "__Host-agents") {
				resp.Header.Add("Set-Cookie", cookie.String())
			}
		}
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "origin unavailable", http.StatusBadGateway)
	}
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	server.SetKeepAlivesEnabled(false)
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != host {
			http.Error(w, "service authority mismatch", http.StatusForbidden)
			return
		}
		for k := range r.Header {
			lower := strings.ToLower(k)
			if strings.HasPrefix(lower, "x-agents-") || strings.HasPrefix(lower, "x-auth-request-") || strings.HasPrefix(lower, "x-forwarded-") || lower == "forwarded" {
				r.Header.Del(k)
			}
		}
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, cookie := range cookies {
			if !strings.HasPrefix(cookie.Name, "__Host-agents") {
				r.AddCookie(cookie)
			}
		}
		proxy.ServeHTTP(w, r)
	})
	l := newSingleListener(s)
	stop := context.AfterFunc(ctx, func() { _ = server.Close(); _ = l.Close() })
	defer stop()
	err = server.Serve(l)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		// FIN lets the requester drain the response. Immediate CANCEL here could
		// discard response bytes already buffered by the peer's multiplexer.
		_ = s.CloseWrite()
		_, _ = io.Copy(io.Discard, s)
		return nil
	}
	return err
}

type singleListener struct {
	conn     net.Conn
	mu       sync.Mutex
	accepted bool
	done     chan struct{}
	once     sync.Once
}
type trackedConn struct {
	net.Conn
	closeOnce sync.Once
	onClose   func()
}

func (c *trackedConn) Close() error {
	var err error
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		err = half.CloseWrite()
	} else {
		err = c.Conn.Close()
	}
	c.closeOnce.Do(c.onClose)
	return err
}
func newSingleListener(c net.Conn) *singleListener {
	l := &singleListener{done: make(chan struct{})}
	l.conn = &trackedConn{Conn: c, onClose: func() { l.once.Do(func() { close(l.done) }) }}
	return l
}
func (l *singleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleListener) Close() error   { l.once.Do(func() { close(l.done) }); return l.conn.Close() }
func (l *singleListener) Addr() net.Addr { return l.conn.LocalAddr() }
