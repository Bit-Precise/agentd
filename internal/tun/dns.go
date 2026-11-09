package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// FirefoxCanary is the domain Firefox probes before enabling DoH.
const FirefoxCanary = "use-application-dns.net"

// DNS is the built-in resolver (design 6.4). It answers fake addresses for
// workspace service domains and domains the split-routing table sends to the
// relay, and forwards everything else to the upstream resolvers over the
// physical interface, stripping HTTPS and SVCB records so browsers do not get
// ECH configurations.
type DNS struct {
	Pool          *FakeIP
	Fake          func(domain string) bool // service domain or via route
	Upstreams     []string                 // host:port, queried in order
	Dial          func(ctx context.Context, network, addr string) (net.Conn, error)
	StripHTTPS    bool
	FirefoxCanary bool
	Log           *slog.Logger

	mu sync.RWMutex

	FakeAnswers atomic.Int64
	Forwarded   atomic.Int64
	Stripped    atomic.Int64
	Failures    atomic.Int64
}

func (d *DNS) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.Dial != nil {
		return d.Dial(ctx, network, addr)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

// Answer handles one DNS message and returns the reply (nil to drop).
func (d *DNS) Answer(ctx context.Context, raw []byte) []byte {
	var q dns.Msg
	if err := q.Unpack(raw); err != nil || len(q.Question) != 1 || q.Response {
		return nil
	}
	resp := d.answer(ctx, &q)
	if resp == nil {
		return nil
	}
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}

func (d *DNS) answer(ctx context.Context, q *dns.Msg) *dns.Msg {
	qs := q.Question[0]
	name := normalizeName(qs.Name)
	reply := func(rcode int, rrs ...dns.RR) *dns.Msg {
		m := new(dns.Msg)
		m.SetRcode(q, rcode)
		m.RecursionAvailable = true
		m.Answer = rrs
		return m
	}
	if d.FirefoxCanary && name == FirefoxCanary {
		return reply(dns.RcodeNameError)
	}
	if qs.Qclass == dns.ClassINET && d.Fake != nil && d.Fake(name) {
		d.FakeAnswers.Add(1)
		v4, v6 := d.Pool.Assign(name)
		hdr := dns.RR_Header{Name: qs.Name, Class: dns.ClassINET, Ttl: 1}
		switch qs.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			return reply(dns.RcodeSuccess, &dns.A{Hdr: hdr, A: v4.AsSlice()})
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			return reply(dns.RcodeSuccess, &dns.AAAA{Hdr: hdr, AAAA: v6.AsSlice()})
		}
		return reply(dns.RcodeSuccess)
	}
	if d.StripHTTPS && (qs.Qtype == dns.TypeHTTPS || qs.Qtype == dns.TypeSVCB) {
		d.Stripped.Add(1)
		return reply(dns.RcodeSuccess)
	}
	resp, err := d.forward(ctx, q)
	if err != nil {
		d.Failures.Add(1)
		if d.Log != nil {
			d.Log.Debug("dns upstream failed", "name", name, "err", err)
		}
		return reply(dns.RcodeServerFailure)
	}
	d.Forwarded.Add(1)
	if d.StripHTTPS {
		resp.Answer = d.strip(resp.Answer)
		resp.Extra = d.strip(resp.Extra)
	}
	resp.Id = q.Id
	return resp
}

func (d *DNS) strip(rrs []dns.RR) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		if t := rr.Header().Rrtype; t == dns.TypeHTTPS || t == dns.TypeSVCB {
			d.Stripped.Add(1)
			continue
		}
		out = append(out, rr)
	}
	return out
}

// SetUpstreams replaces the upstream resolvers (network changes).
func (d *DNS) SetUpstreams(ups []string) {
	d.mu.Lock()
	d.Upstreams = ups
	d.mu.Unlock()
}

// UpstreamList returns the current upstream resolvers.
func (d *DNS) UpstreamList() []string { return d.upstreams() }

func (d *DNS) upstreams() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.Upstreams
}

func (d *DNS) forward(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	ups := d.upstreams()
	if len(ups) == 0 {
		return nil, errors.New("no upstream resolvers")
	}
	var last error
	for _, up := range ups {
		ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
		resp, err := d.exchange(ctx2, "udp", up, q)
		if err == nil && resp.Truncated {
			resp, err = d.exchange(ctx2, "tcp", up, q)
		}
		cancel()
		if err == nil {
			return resp, nil
		}
		last = err
	}
	return nil, last
}

func (d *DNS) exchange(ctx context.Context, network, addr string, q *dns.Msg) (*dns.Msg, error) {
	c, err := d.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	co := &dns.Conn{Conn: c}
	if network == "udp" {
		co.UDPSize = dns.DefaultMsgSize
	}
	if err := co.WriteMsg(q); err != nil {
		return nil, err
	}
	for {
		resp, err := co.ReadMsg()
		if err != nil {
			return nil, err
		}
		if resp.Id == q.Id {
			return resp, nil
		}
	}
}

// ServeTCP answers length-prefixed DNS messages on a stream (TCP port 53).
func (d *DNS) ServeTCP(ctx context.Context, c net.Conn) {
	defer c.Close()
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		out := d.Answer(ctx, msg)
		if out == nil {
			return
		}
		binary.BigEndian.PutUint16(l[:], uint16(len(out)))
		if _, err := c.Write(append(l[:], out...)); err != nil {
			return
		}
	}
}
