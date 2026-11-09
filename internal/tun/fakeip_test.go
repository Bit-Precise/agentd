package tun

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestFakeIPDeterministicAndUnique(t *testing.T) {
	a, b := NewFakeIP(), NewFakeIP()
	v4, v6 := a.Assign("Course.UCAS.edu.cn.")
	w4, w6 := b.Assign("course.ucas.edu.cn")
	if v4 != w4 || v6 != w6 {
		t.Fatalf("not deterministic: %v %v vs %v %v", v4, v6, w4, w6)
	}
	if !Pool4.Contains(v4) || !Pool6.Contains(v6) || reserved4(v4) {
		t.Fatalf("outside the pools: %v %v", v4, v6)
	}
	if d, ok := a.Lookup(v4); !ok || d != "course.ucas.edu.cn" {
		t.Fatalf("reverse: %q %v", d, ok)
	}
	if d, ok := a.Lookup(netip.AddrFrom16(v4.As16())); !ok || d != "course.ucas.edu.cn" {
		t.Fatalf("4-in-6 reverse: %q %v", d, ok)
	}
	seen := map[netip.Addr]bool{}
	for i := 0; i < 20000; i++ {
		x4, x6 := a.Assign(fmt.Sprintf("host%d.example.com", i))
		if seen[x4] || seen[x6] {
			t.Fatalf("duplicate address at %d", i)
		}
		seen[x4], seen[x6] = true, true
	}
	if Contains(netip.MustParseAddr("8.8.8.8")) || !Contains(netip.MustParseAddr("198.19.1.2")) {
		t.Fatal("Contains")
	}
}
