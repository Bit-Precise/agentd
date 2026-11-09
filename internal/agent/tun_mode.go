//go:build linux || darwin || windows

package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"agentd/internal/elevator"
	"agentd/internal/policy"
	"agentd/internal/routes"
	"agentd/internal/sniff"
	"agentd/internal/stream"
	"agentd/internal/tun"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// TUN timing (design 5.2).
const (
	tunSniffBudget = 200 * time.Millisecond
	udpIdle        = 60 * time.Second
	dnsIdle        = 15 * time.Second
)

var defaultDoH = []string{"dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com"}

type tunState struct {
	a     *Agent
	sess  *elevator.Session
	st    *tun.Stack
	dns   *tun.DNS
	pool  *tun.FakeIP
	phys  atomic.Pointer[elevator.Physical]
	doh   map[string]bool
	fixed bool // upstreams come from the configuration
}

func (t *tunState) physical() elevator.Physical { return *t.phys.Load() }

func withPort53(ips []string) []string {
	var out []string
	for _, ip := range ips {
		if _, _, err := net.SplitHostPort(ip); err == nil {
			out = append(out, ip)
		} else {
			out = append(out, net.JoinHostPort(ip, "53"))
		}
	}
	return out
}

// dial connects over the physical interface, resolving names through the
// upstream resolvers (never through the built-in DNS, which would answer fake
// addresses for routed domains).
func (t *tunState) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	p := t.physical()
	d := physicalDialer(p)
	d.LocalAddr = physicalLocal(network, p)
	d.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return t.dialUpstream(ctx)
	}}
	return d.DialContext(ctx, physicalNetwork(network, p), addr)
}

func (t *tunState) dialUpstream(ctx context.Context) (net.Conn, error) {
	ups := t.dns.UpstreamList()
	if len(ups) == 0 {
		return nil, errors.New("no upstream DNS")
	}
	var last error
	for _, up := range ups {
		c, err := t.rawDial(ctx, "udp", up)
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// rawDial dials an address literal over the physical interface.
func (t *tunState) rawDial(ctx context.Context, network, addr string) (net.Conn, error) {
	p := t.physical()
	d := physicalDialer(p)
	d.LocalAddr = physicalLocal(network, p)
	return d.DialContext(ctx, physicalNetwork(network, p), addr)
}

// fake reports whether the built-in DNS answers a fake address for a name:
// workspace service domains and domains the split table sends to the relay.
func (a *Agent) fakeDomain(name string) bool {
	if a.state.service(name) != nil {
		return true
	}
	ir := a.state.ingressRoutes()
	if ir == nil {
		return false
	}
	return routes.EvalIngress(ir, pb.Proto_PROTO_TLS, name) == pb.RouteAction_ROUTE_VIA || routes.EvalIngress(ir, pb.Proto_PROTO_SSH, name) == pb.RouteAction_ROUTE_VIA
}

func (a *Agent) startTUN(ctx context.Context, cfg *Config) error {
	tc := cfg.Roles.Ingress.TUN
	override := tc.DNS.OverrideSystem == nil || *tc.DNS.OverrideSystem
	sess, err := elevator.Open(ctx, cfg.TUNSocket(), cfg.Metadata.Name, 1500, override, tc.Capture == "fakeip")
	if err != nil {
		return err
	}
	t := &tunState{a: a, sess: sess, pool: tun.NewFakeIP(), doh: map[string]bool{}}
	p := sess.Physical
	t.phys.Store(&p)
	if tc.DoHBlock.Enabled == nil || *tc.DoHBlock.Enabled {
		list := tc.DoHBlock.Domains
		if len(list) == 0 {
			list = defaultDoH
		}
		for _, d := range list {
			t.doh[normalize(d)] = true
		}
	}
	ups := withPort53(sess.DNS)
	if len(tc.DNS.Upstream) > 0 {
		ups = nil
		for _, u := range tc.DNS.Upstream {
			port := u.Port
			if port == 0 {
				port = 53
			}
			ups = append(ups, net.JoinHostPort(u.Address, strconv.Itoa(port)))
		}
		t.fixed = true
	}
	t.dns = &tun.DNS{Pool: t.pool, Fake: a.fakeDomain, Upstreams: ups, Dial: t.rawDial, Log: a.log,
		StripHTTPS: tc.DNS.StripHTTPSRecords == nil || *tc.DNS.StripHTTPSRecords, FirefoxCanary: tc.DNS.FirefoxCanary == nil || *tc.DNS.FirefoxCanary}
	dev := tunDevice(sess)
	t.st, err = tun.NewStack(dev, tun.Handlers{TCP: t.handleTCP, UDP: t.handleUDP})
	if err != nil {
		sess.Close()
		return err
	}
	dial := dialFunc(t.dial)
	if a.opts.NetDial != nil {
		dial = a.opts.NetDial // embedding (tests) maps names itself
	}
	a.tunDial.Store(&dial)
	a.publishTUN(t)
	a.log.Info("tun mode on", "device", sess.Name, "physical", p.Interface, "upstream_dns", ups)
	go func() {
		for ev := range sess.Events {
			if ev.Event == "network" {
				np := ev.Physical
				t.phys.Store(&np)
				if !t.fixed && len(ev.DNS) > 0 {
					t.dns.SetUpstreams(withPort53(ev.DNS))
				}
				a.log.Info("network changed", "physical", np.Interface, "ipv4", np.IPv4)
				a.publishTUN(t)
				if s := a.current(); s != nil {
					s.mux.Close() // reconnect over the new path
				}
			}
		}
		// The elevator went away: it has restored routes and DNS.
		a.tunDial.Store(nil)
		t.st.Close()
		sess.Close()
		if ctx.Err() == nil {
			a.log.Error("lost the elevator; TUN mode stopped (proxy entry points keep working)")
		}
	}()
	go func() {
		<-ctx.Done()
		t.st.Close()
		sess.Close()
	}()
	return nil
}

func (a *Agent) publishTUN(t *tunState) {
	info := func() map[string]any {
		p := t.physical()
		return map[string]any{"device": t.sess.Name, "physical": p.Interface, "physical_ipv4": p.IPv4, "upstream_dns": t.dns.UpstreamList(),
			"dns_fake_answers": t.dns.FakeAnswers.Load(), "dns_forwarded": t.dns.Forwarded.Load(), "dns_stripped": t.dns.Stripped.Load(), "dns_failures": t.dns.Failures.Load()}
	}
	a.tunInfo.Store(&info)
}

func (t *tunState) handleTCP(c net.Conn, src, dst netip.AddrPort) {
	ctx := context.Background()
	a := t.a
	if dst.Port() == 53 {
		t.dns.ServeTCP(ctx, c)
		return
	}
	if tun.Contains(dst.Addr()) {
		domain, ok := t.pool.Lookup(dst.Addr())
		if !ok || dst.Addr() == tun.DNSAddr4 || dst.Addr() == tun.GatewayAddr4 {
			stream.Abort(c)
			return
		}
		if dst.Port() == 80 {
			redirectHTTPS(c, domain)
			return
		}
		t.tunConn(ctx, c, domain, dst)
		return
	}
	for _, p := range a.config().Roles.Ingress.Sniffing.SkipPorts {
		if int(dst.Port()) == p {
			t.direct(ctx, c, dst, nil, "skip_ports")
			return
		}
	}
	t.tunConn(ctx, c, "", dst)
}

// redirectHTTPS answers plain HTTP to a fake address with a 301 to https.
func redirectHTTPS(c net.Conn, domain string) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(c))
	path := "/"
	if err == nil {
		path = req.URL.RequestURI()
	}
	fmt.Fprintf(c, "HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", domain, path)
}

func (t *tunState) direct(ctx context.Context, c net.Conn, dst netip.AddrPort, first []byte, reason string) {
	t.a.decision("connection", "entry", "tun", "target", dst.String(), "action", "direct", "reason", reason)
	dctx, cancel := context.WithTimeout(ctx, EgressDialTimeout)
	o, err := t.rawDial(dctx, "tcp", dst.String())
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

// tunConn sniffs a TUN connection and routes it (design 5.2). fakeDomain is
// set when the destination came from the fake-IP pool.
func (t *tunState) tunConn(ctx context.Context, c net.Conn, fakeDomain string, dst netip.AddrPort) {
	a := t.a
	cfg := a.config()
	start := time.Now()
	fake := fakeDomain != ""
	c.SetReadDeadline(time.Now().Add(tunSniffBudget))
	res := sniff.Sniff(c, EarlyDataMax)
	c.SetReadDeadline(time.Time{})
	port := uint32(dst.Port())
	domain := fakeDomain
	var proto pb.Proto
	switch {
	case res.Kind == sniff.TLS:
		proto = pb.Proto_PROTO_TLS
		sni := policy.NormalizeDomain(res.SNI)
		if fake && sni != "" && sni != fakeDomain {
			a.decision("connection", "entry", "tun", "target", dst.String(), "domain", fakeDomain, "sni", sni, "action", "reject", "reason", "SNI differs from the fake-IP mapping")
			stream.Abort(c)
			return
		}
		if !fake {
			domain = sni
		}
	case res.Kind == sniff.SSH, fake && port == 22 && len(res.Data) == 0:
		proto = pb.Proto_PROTO_SSH
	}
	logd := func(action string, extra ...any) {
		a.decision("connection", append([]any{"entry", "tun", "target", dst.String(), "domain", domain, "proto", res.Kind.String(), "fake_ip", fake,
			"action", action, "ms", time.Since(start).Milliseconds()}, extra...)...)
	}
	if proto == pb.Proto_PROTO_UNSPECIFIED || domain == "" {
		if fake {
			logd("reject", "reason", "fake-IP destinations carry TLS or SSH only")
			stream.Abort(c)
			return
		}
		t.direct(ctx, c, dst, res.Data, "no domain")
		return
	}
	if proto == pb.Proto_PROTO_TLS && t.doh[domain] {
		logd("reject", "reason", "doh_block")
		stream.Abort(c)
		return
	}
	act := pb.RouteAction_ROUTE_DIRECT
	if a.state.service(domain) != nil {
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
		if fake {
			// The table changed since the DNS answer: dial the real name.
			logd("direct", "reason", "route (resolved again)")
			dctx, cancel := context.WithTimeout(ctx, EgressDialTimeout)
			o, err := t.dial(dctx, "tcp", net.JoinHostPort(domain, strconv.Itoa(int(port))))
			cancel()
			if err != nil {
				stream.Abort(c)
				return
			}
			if len(res.Data) > 0 {
				o.Write(res.Data)
			}
			stream.Splice(c, o)
			return
		}
		logd("direct", "reason", "route")
		t.direct(ctx, c, dst, res.Data, "route")
		return
	}
	st, ack, err := a.openTCP(ctx, proto, domain, port, res.Data)
	if err == nil {
		logd("via", "responder", a.state.memberName(ack.Responder))
		stream.Splice(c, st)
		return
	}
	status := pb.Status_TIMEOUT
	if ack != nil {
		status = ack.Status
	}
	if ack == nil {
		status = statusOf(err)
	}
	fallback := status == pb.Status_TARGET_OFFLINE || status == pb.Status_CONTROL_NOT_READY || status == pb.Status_NO_RULE
	if fallback && !fake && cfg.Roles.Ingress.Fallback == "direct" {
		logd("direct", "reason", "fallback", "status", status.String())
		t.direct(ctx, c, dst, res.Data, "fallback")
		return
	}
	logd("failed", "status", status.String(), "err", err.Error())
	stream.Abort(c)
}

func (t *tunState) handleUDP(c *gonet.UDPConn, src, dst netip.AddrPort) bool {
	if dst.Port() == 53 {
		go t.serveDNS(c)
		return true
	}
	if tun.Contains(dst.Addr()) {
		// QUIC and anything else to a routed or service name: drop, so
		// browsers fall back to TCP, which the relay carries.
		return false
	}
	var first [][]byte
	if dst.Port() == 443 {
		var qs sniff.QUICSniffer
		deadline := time.Now().Add(300 * time.Millisecond)
		for len(first) < 4 {
			c.SetReadDeadline(deadline)
			buf := make([]byte, 65535)
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			first = append(first, buf[:n])
			sni, done := qs.Add(buf[:n])
			if done {
				if sni != "" && (t.a.fakeDomain(policy.NormalizeDomain(sni)) || t.doh[policy.NormalizeDomain(sni)]) {
					t.a.decision("udp", "entry", "tun", "target", dst.String(), "sni", sni, "action", "drop", "reason", "QUIC to a routed domain")
					return false
				}
				break
			}
		}
		c.SetReadDeadline(time.Time{})
	}
	go t.relayUDP(c, dst, first)
	return true
}

func (t *tunState) serveDNS(c *gonet.UDPConn) {
	defer c.Close()
	buf := make([]byte, 65535)
	for {
		c.SetReadDeadline(time.Now().Add(dnsIdle))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out := t.dns.Answer(ctx, buf[:n])
		cancel()
		if out != nil {
			c.Write(out)
		}
	}
}

// relayUDP passes a flow through to its real destination over the physical
// interface (NTP, VoIP, games, other VPNs keep working).
func (t *tunState) relayUDP(c *gonet.UDPConn, dst netip.AddrPort, first [][]byte) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	o, err := t.rawDial(ctx, "udp", dst.String())
	cancel()
	if err != nil {
		return
	}
	defer o.Close()
	for _, b := range first {
		o.Write(b)
	}
	var once sync.Once
	done := make(chan struct{})
	stop := func() { once.Do(func() { close(done) }) }
	pump := func(dstc, srcc net.Conn) {
		defer stop()
		buf := make([]byte, 65535)
		for {
			srcc.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := srcc.Read(buf)
			if err != nil {
				return
			}
			if _, err := dstc.Write(buf[:n]); err != nil && !errors.Is(err, io.ErrShortWrite) {
				return
			}
		}
	}
	go pump(o, c)
	go pump(c, o)
	<-done
}

func statusOf(err error) pb.Status { return wire.StatusOf(err) }
