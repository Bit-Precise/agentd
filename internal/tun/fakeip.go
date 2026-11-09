// Package tun is agentd's TUN ingress (design 5.2, 6.4): a deterministic
// fake-IP pool, the built-in DNS server and a gVisor netstack that turns IP
// packets from the TUN device back into connections for the dispatcher.
package tun

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
)

// Fake-IP pools (design 6.4): RFC 2544 and RFC 5180 benchmarking ranges.
var (
	Pool4 = netip.MustParsePrefix("198.18.0.0/15")
	Pool6 = netip.MustParsePrefix("2001:2::/48")
	// DNSAddr4 is the address the system resolver points at; queries to any
	// address on port 53 that reach the TUN are answered as well.
	DNSAddr4 = netip.MustParseAddr("198.18.0.2")
	// GatewayAddr4 is the TUN interface's own address.
	GatewayAddr4 = netip.MustParseAddr("198.18.0.1")
)

// FakeIP maps domains to addresses in the pools. Allocation hashes the
// domain so the same name gets the same address across restarts (Chrome
// caches system answers for 60 s regardless of TTL); collisions probe on.
type FakeIP struct {
	mu     sync.RWMutex
	byName map[string][2]netip.Addr
	byAddr map[netip.Addr]string
}

// NewFakeIP creates an empty pool.
func NewFakeIP() *FakeIP {
	return &FakeIP{byName: map[string][2]netip.Addr{}, byAddr: map[netip.Addr]string{}}
}

func normalizeName(d string) string { return strings.TrimSuffix(strings.ToLower(d), ".") }

// reserved addresses inside the IPv4 pool.
func reserved4(a netip.Addr) bool {
	b := a.As4()
	return b[2] == 0 && b[3] < 16 || b[3] == 0 || b[3] == 255
}

// Lookup returns the domain behind a fake address.
func (f *FakeIP) Lookup(a netip.Addr) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	d, ok := f.byAddr[a.Unmap()]
	return d, ok
}

// Contains reports whether a is inside one of the pools.
func Contains(a netip.Addr) bool {
	a = a.Unmap()
	return Pool4.Contains(a) || Pool6.Contains(a)
}

// Assign returns the IPv4 and IPv6 fake addresses of a domain.
func (f *FakeIP) Assign(domain string) (v4, v6 netip.Addr) {
	domain = normalizeName(domain)
	f.mu.RLock()
	if a, ok := f.byName[domain]; ok {
		f.mu.RUnlock()
		return a[0], a[1]
	}
	f.mu.RUnlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.byName[domain]; ok {
		return a[0], a[1]
	}
	sum := sha256.Sum256([]byte(domain))
	h := binary.BigEndian.Uint64(sum[:8])
	size4 := uint64(1) << (32 - Pool4.Bits())
	base4 := binary.BigEndian.Uint32(Pool4.Addr().AsSlice())
	for i := uint64(0); ; i++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base4+uint32((h+i)%size4))
		a := netip.AddrFrom4(b)
		if reserved4(a) {
			continue
		}
		if _, used := f.byAddr[a]; !used {
			v4 = a
			break
		}
	}
	p6 := Pool6.Addr().As16()
	h6 := binary.BigEndian.Uint64(sum[8:16])
	for i := uint64(0); ; i++ {
		b := p6
		binary.BigEndian.PutUint64(b[8:], h6+i)
		binary.BigEndian.PutUint16(b[6:8], uint16(sum[16])<<8|uint16(sum[17]))
		a := netip.AddrFrom16(b)
		if _, used := f.byAddr[a]; !used && Pool6.Contains(a) {
			v6 = a
			break
		}
	}
	f.byName[domain] = [2]netip.Addr{v4, v6}
	f.byAddr[v4] = domain
	f.byAddr[v6] = domain
	return v4, v6
}
