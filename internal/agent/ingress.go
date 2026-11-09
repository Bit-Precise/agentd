package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"agentd/internal/policy"
	"agentd/internal/routes"
	"agentd/internal/sniff"
	"agentd/internal/stream"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// sniffTimeout bounds waiting for the client's first bytes.
const sniffTimeout = 3 * time.Second

func (a *Agent) startIngress(ctx context.Context, cfg *Config) error {
	in := cfg.Roles.Ingress
	if !in.Enabled {
		return nil
	}
	if in.HTTP.Enabled {
		ln, err := net.Listen("tcp", in.HTTP.HostPort())
		if err != nil {
			return fmt.Errorf("ingress http: %w", err)
		}
		a.ingressLn = append(a.ingressLn, ln)
		srv := &http.Server{Handler: http.HandlerFunc(a.serveHTTPProxy), ReadHeaderTimeout: 10 * time.Second}
		go srv.Serve(ln)
		a.log.Info("http proxy listening", "addr", ln.Addr().String())
	}
	if in.SOCKS5.Enabled {
		ln, err := net.Listen("tcp", in.SOCKS5.HostPort())
		if err != nil {
			return fmt.Errorf("ingress socks5: %w", err)
		}
		a.ingressLn = append(a.ingressLn, ln)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go a.serveSOCKS5(ctx, c)
			}
		}()
		a.log.Info("socks5 proxy listening", "addr", ln.Addr().String())
	}
	return nil
}

// IngressAddrs reports the bound proxy addresses (tests).
func (a *Agent) IngressAddrs() []string {
	var out []string
	for _, l := range a.ingressLn {
		out = append(out, l.Addr().String())
	}
	return out
}

func (a *Agent) serveHTTPProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "agentd only proxies CONNECT (TLS and SSH); plaintext HTTP forwarding is not supported", http.StatusMethodNotAllowed)
		return
	}
	host, portStr, err := net.SplitHostPort(r.Host)
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil || port < 1 || port > 65535 {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		conn.Close()
		return
	}
	var c net.Conn = conn
	if buf != nil && buf.Reader.Buffered() > 0 {
		c = &prefixConn{Conn: conn, r: io.MultiReader(buf.Reader, conn)}
	}
	a.handleConn(r.Context(), c, "http", host, port)
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *prefixConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Conn.Close()
}

// serveSOCKS5 handles CONNECT with no authentication (RFC 1928).
func (a *Agent) serveSOCKS5(ctx context.Context, c net.Conn) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 5 {
		c.Close()
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		c.Close()
		return
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		c.Write([]byte{5, 0xff})
		c.Close()
		return
	}
	c.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 5 {
		c.Close()
		return
	}
	reply := func(code byte) { c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if req[1] != 1 {
		reply(7) // command not supported (no BIND, no UDP ASSOCIATE)
		c.Close()
		return
	}
	var host string
	switch req[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			c.Close()
			return
		}
		host = net.IP(ip).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil {
			c.Close()
			return
		}
		name := make([]byte, l)
		if _, err := io.ReadFull(br, name); err != nil {
			c.Close()
			return
		}
		host = string(name)
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			c.Close()
			return
		}
		host = net.IP(ip).String()
	default:
		reply(8)
		c.Close()
		return
	}
	pb2 := make([]byte, 2)
	if _, err := io.ReadFull(br, pb2); err != nil {
		c.Close()
		return
	}
	port := int(binary.BigEndian.Uint16(pb2))
	reply(0)
	c.SetDeadline(time.Time{})
	var conn net.Conn = c
	if br.Buffered() > 0 {
		conn = &prefixConn{Conn: c, r: io.MultiReader(br, c)}
	}
	a.handleConn(ctx, conn, "socks5", host, port)
}

// handleConn is the ingress dispatcher (design 7.7): sniff, decide, then
// connect directly or through the relay.
func (a *Agent) handleConn(ctx context.Context, c net.Conn, entry, host string, port int) {
	cfg := a.config()
	start := time.Now()
	host = policy.NormalizeDomain(host)
	rec := []any{"entry", entry, "target", net.JoinHostPort(host, strconv.Itoa(port))}
	logd := func(action string, extra ...any) {
		a.decision("connection", append(append(rec, "action", action, "ms", time.Since(start).Milliseconds()), extra...)...)
	}
	for _, p := range cfg.Roles.Ingress.Sniffing.SkipPorts {
		if p == port {
			logd("direct", "reason", "skip_ports")
			a.direct(ctx, c, host, port, nil)
			return
		}
	}
	c.SetReadDeadline(time.Now().Add(sniffTimeout))
	res := sniff.Sniff(c, EarlyDataMax)
	c.SetReadDeadline(time.Time{})
	domain, source := host, "proxy"
	if net.ParseIP(host) != nil && res.SNI != "" {
		domain, source = policy.NormalizeDomain(res.SNI), "sni"
	}
	var proto pb.Proto
	switch {
	case res.Kind == sniff.TLS:
		proto = pb.Proto_PROTO_TLS
	case res.Kind == sniff.SSH, len(res.Data) == 0 && port == 22:
		proto = pb.Proto_PROTO_SSH // server-speaks-first clients send nothing yet
	}
	rec = append(rec, "domain", domain, "domain_source", source, "proto", res.Kind.String())
	svc := a.state.service(domain)
	if proto == pb.Proto_PROTO_UNSPECIFIED || net.ParseIP(domain) != nil {
		if svc != nil {
			logd("reject", "reason", "service domains carry TLS or SSH only")
			c.Close()
			return
		}
		logd("direct", "reason", "not TLS or SSH")
		a.direct(ctx, c, host, port, res.Data)
		return
	}
	act := pb.RouteAction_ROUTE_DIRECT
	if svc != nil {
		act = pb.RouteAction_ROUTE_VIA
	} else if ir := a.state.ingressRoutes(); ir != nil {
		act = routes.EvalIngress(ir, proto, domain)
	}
	switch act {
	case pb.RouteAction_ROUTE_REJECT:
		logd("reject", "reason", "route")
		stream.Abort(c)
		return
	case pb.RouteAction_ROUTE_DIRECT:
		logd("direct", "reason", "route")
		a.direct(ctx, c, host, port, res.Data)
		return
	}
	for attempt := 0; attempt < 2; attempt++ {
		st, ack, err := a.openTCP(ctx, proto, domain, uint32(port), res.Data)
		if err == nil {
			logd("via", "responder", a.state.memberName(ack.Responder), "trace", fmt.Sprintf("%x", ack.TraceId))
			stream.Splice(c, st)
			return
		}
		status := wire.StatusOf(err)
		if ack != nil {
			status = ack.Status
		}
		if status == pb.Status_NO_RULE && ack != nil && attempt == 0 {
			if ir := a.state.ingressRoutes(); ir == nil || ack.RulesVersion > ir.Version {
				a.pull()
				time.Sleep(300 * time.Millisecond)
				if ir2 := a.state.ingressRoutes(); ir2 != nil && routes.EvalIngress(ir2, proto, domain) != pb.RouteAction_ROUTE_VIA {
					logd("direct", "reason", "routes refreshed")
					a.direct(ctx, c, host, port, res.Data)
					return
				}
				continue
			}
		}
		fallback := status == pb.Status_TARGET_OFFLINE || status == pb.Status_CONTROL_NOT_READY || status == pb.Status_NO_RULE
		if fallback && svc == nil && cfg.Roles.Ingress.Fallback == "direct" {
			logd("direct", "reason", "fallback", "status", status.String())
			a.direct(ctx, c, host, port, res.Data)
			return
		}
		logd("failed", "status", status.String(), "err", err.Error())
		stream.Abort(c)
		return
	}
}

// direct connects from this host and replays the sniffed bytes.
func (a *Agent) direct(ctx context.Context, c net.Conn, host string, port int, first []byte) {
	dctx, cancel := context.WithTimeout(ctx, EgressDialTimeout)
	o, err := a.dialDirect(dctx, net.JoinHostPort(host, strconv.Itoa(port)))
	cancel()
	if err != nil {
		stream.Abort(c)
		return
	}
	if len(first) > 0 {
		if _, err := o.Write(first); err != nil {
			o.Close()
			c.Close()
			return
		}
	}
	stream.Splice(c, o)
}

// openTCP opens a tcp stream through the relay and waits for the Ack. The
// first bytes go right after the StreamOpen (protocol 6.1).
func (a *Agent) openTCP(ctx context.Context, proto pb.Proto, domain string, port uint32, early []byte) (net.Conn, *pb.Ack, error) {
	as := a.waitSession(ctx, 2*time.Second)
	if as == nil {
		return nil, nil, wire.Errorf(pb.Status_CONTROL_NOT_READY, "no session to the relay")
	}
	cfg := a.config()
	octx, cancel := context.WithTimeout(ctx, AckTimeout)
	defer cancel()
	st, err := as.mux.OpenStream(octx)
	if err != nil {
		return nil, nil, wire.Errorf(pb.Status_CONTROL_NOT_READY, "open stream: %v", err)
	}
	open, err := wire.SignOpen(a.key, &pb.OpenBody{Kind: pb.Kind_KIND_TCP, Workspace: cfg.Workspace.Domain, From: a.pub, To: as.relayKey,
		IssuedAt: uint64(time.Now().Unix()), Nonce: randomBytes(16), Tcp: &pb.TcpOpen{Proto: proto, Domain: domain, Port: port}})
	if err != nil {
		st.Reset()
		return nil, nil, err
	}
	if err := wire.WriteMsg(st, &pb.StreamOpen{Open: open, Certs: a.state.certsToAttach()}); err != nil {
		st.Reset()
		return nil, nil, err
	}
	if len(early) > 0 {
		if _, err := st.Write(early); err != nil {
			st.Reset()
			return nil, nil, err
		}
	}
	ack, err := stream.ReadAck(st, AckTimeout)
	if err != nil {
		st.Reset()
		return nil, nil, wire.Errorf(pb.Status_TIMEOUT, "no Ack: %v", err)
	}
	if ack.Status != pb.Status_OK {
		st.Reset()
		return nil, ack, wire.Errorf(ack.Status, "%s", ack.Message)
	}
	return st, ack, nil
}

var errNoSession = errors.New("no session")

func hostPortSplit(s string) (string, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	return strings.ToLower(h), n, err
}
