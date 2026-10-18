// Package ingress implements local, domain-restricted application proxy inputs.
package ingress

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bit-precise/agentd/policy"
	"github.com/bit-precise/agentd/stream"
)

type OpenFunc func(context.Context, string, uint16) (net.Conn, error)

// Proxy only selects which local connections enter agents. Its routes can be
// replaced at runtime: Edge still authorizes every destination it receives.
type Proxy struct {
	routes atomic.Pointer[[]policy.Rule]
	Open   OpenFunc
}

func NewProxy(routes []policy.Rule, open OpenFunc) *Proxy {
	p := &Proxy{Open: open}
	p.SetRoutes(routes)
	return p
}

// SetRoutes takes effect for every subsequent CONNECT or SOCKS request.
func (p *Proxy) SetRoutes(routes []policy.Rule) {
	routes = slices.Clone(routes)
	for i := range routes {
		routes[i].Ports = slices.Clone(routes[i].Ports)
	}
	p.routes.Store(&routes)
}

func (p *Proxy) target(host string, port uint16) (string, error) {
	domain, err := policy.CanonicalDomain(host)
	if err != nil || port == 0 {
		return "", errors.New("a canonical domain and nonzero port are required")
	}
	var routes []policy.Rule
	if current := p.routes.Load(); current != nil {
		routes = *current
	}
	if !policy.Allowed(routes, nil, domain, int(port), "tls") {
		return "", errors.New("destination outside local ingress routes")
	}
	return domain, nil
}

// HTTPHandler accepts CONNECT only. A 200 response means the candidate stream
// exists; TLS inspection and final destination authorization belong to Edge.
func (p *Proxy) HTTPHandler(ctx context.Context) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		host, portString, err := net.SplitHostPort(r.RequestURI)
		if err != nil {
			http.Error(w, "invalid authority", http.StatusBadRequest)
			return
		}
		port, err := strconv.ParseUint(portString, 10, 16)
		if err != nil {
			http.Error(w, "invalid port", http.StatusBadRequest)
			return
		}
		domain, err := p.target(host, uint16(port))
		if err != nil {
			http.Error(w, "destination denied", http.StatusForbidden)
			return
		}
		openCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		upstream, err := p.Open(openCtx, domain, uint16(port))
		cancel()
		if err != nil {
			http.Error(w, "edge unavailable or destination denied", http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			_ = upstream.Close()
			http.Error(w, "CONNECT requires HTTP/1.1", http.StatusHTTPVersionNotSupported)
			return
		}
		client, buffer, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
		if err := buffer.Flush(); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
		buffered := &bufferedConn{Conn: client, reader: buffer.Reader}
		stream.Pipe(ctx, buffered, upstream)
	})
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *bufferedConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return c.Conn.Close()
}

// ServeSOCKS supports SOCKS5 CONNECT with a domain target. It deliberately has no
// UDP or IP-target fallback and is bound to loopback by the config validator.
func (p *Proxy) ServeSOCKS(ctx context.Context, l net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	limit := make(chan struct{}, 128)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case limit <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-limit; _ = c.Close() }()
			stop := context.AfterFunc(ctx, func() { _ = c.Close() })
			defer stop()
			_ = p.socks(ctx, c)
		}()
	}
}

func (p *Proxy) socks(ctx context.Context, c net.Conn) error {
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 5 || greeting[1] == 0 {
		return errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, err := c.Write([]byte{5, 255})
		return err
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[1] != 1 || header[2] != 0 || header[3] != 3 {
		_ = socksReply(c, 7)
		return errors.New("only domain CONNECT is supported")
	}
	var length [1]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return err
	}
	if length[0] == 0 {
		return errors.New("empty SOCKS domain")
	}
	name := make([]byte, int(length[0]))
	if _, err := io.ReadFull(c, name); err != nil {
		return err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(c, portBytes[:]); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	domain, err := p.target(string(name), port)
	if err != nil {
		_ = socksReply(c, 2)
		return err
	}
	openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	upstream, err := p.Open(openCtx, domain, port)
	cancel()
	if err != nil {
		_ = socksReply(c, 1)
		return fmt.Errorf("open candidate stream: %w", err)
	}
	if err := socksReply(c, 0); err != nil {
		_ = upstream.Close()
		return err
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		_ = upstream.Close()
		return err
	}
	stream.Pipe(ctx, c, upstream)
	return nil
}
func socksReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
