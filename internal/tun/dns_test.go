package tun

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// upstream answers A 93.184.216.34 plus an HTTPS record for every name.
func upstream(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		a, _ := dns.NewRR(q.Name + " 300 IN A 93.184.216.34")
		h, _ := dns.NewRR(q.Name + ` 300 IN HTTPS 1 . alpn="h2"`)
		m.Answer = []dns.RR{a, h}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func ask(t *testing.T, d *DNS, name string, qtype uint16) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	raw, _ := q.Pack()
	out := d.Answer(context.Background(), raw)
	var m dns.Msg
	if err := m.Unpack(out); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if m.Id != q.Id {
		t.Fatalf("id mismatch")
	}
	return &m
}

func TestDNS(t *testing.T) {
	d := &DNS{Pool: NewFakeIP(), Upstreams: []string{upstream(t)}, StripHTTPS: true, FirefoxCanary: true,
		Fake: func(n string) bool { return n == "nas.home.example.com" || n == "course.ucas.edu.cn" }}
	m := ask(t, d, "course.ucas.edu.cn", dns.TypeA)
	want, want6 := d.Pool.Assign("course.ucas.edu.cn")
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != want.String() || m.Answer[0].Header().Ttl != 1 {
		t.Fatalf("fake A: %v", m.Answer)
	}
	if m := ask(t, d, "NAS.home.example.com.", dns.TypeAAAA); len(m.Answer) != 1 || m.Answer[0].(*dns.AAAA).AAAA.String() == want6.String() {
		t.Fatalf("fake AAAA for another domain: %v", m.Answer)
	}
	if m := ask(t, d, "course.ucas.edu.cn", dns.TypeHTTPS); len(m.Answer) != 0 || m.Rcode != dns.RcodeSuccess {
		t.Fatalf("fake HTTPS must be empty: %v", m)
	}
	m = ask(t, d, "www.example.org", dns.TypeA)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "93.184.216.34" {
		t.Fatalf("forwarded A (HTTPS stripped): %v", m.Answer)
	}
	if m := ask(t, d, "www.example.org", dns.TypeHTTPS); len(m.Answer) != 0 {
		t.Fatalf("HTTPS queries are answered empty: %v", m.Answer)
	}
	if m := ask(t, d, FirefoxCanary, dns.TypeA); m.Rcode != dns.RcodeNameError {
		t.Fatalf("canary: %v", m.Rcode)
	}
	d.Upstreams = []string{"127.0.0.1:1"}
	if m := ask(t, d, "down.example.org", dns.TypeA); m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("upstream down: %v", m.Rcode)
	}
}
