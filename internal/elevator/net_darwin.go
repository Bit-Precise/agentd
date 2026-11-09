package elevator

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// darwinPhysical finds the default route that is not ours.
func darwinPhysical(skip string) (Physical, error) {
	out, err := run("netstat", "-rn", "-f", "inet")
	if err != nil {
		return Physical{}, err
	}
	var p Physical
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "default" {
			continue
		}
		netif := f[3]
		if netif == skip || strings.HasPrefix(netif, "utun") && skip == "" {
			continue
		}
		p.Interface, p.Gateway = netif, f[1]
		break
	}
	if p.Interface == "" {
		return p, errors.New("no IPv4 default route")
	}
	if net.ParseIP(p.Gateway) == nil {
		p.Gateway = ""
	}
	ifi, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return p, err
	}
	p.Index = ifi.Index
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipn.IP.To4() != nil && p.IPv4 == "" {
			p.IPv4 = ipn.IP.String()
		} else if ipn.IP.To4() == nil && p.IPv6 == "" {
			p.IPv6 = ipn.IP.String()
		}
	}
	return p, nil
}

func scutilShow(key string) string {
	out, _ := runIn("open\nshow "+key+"\nquit\n", "scutil")
	return out
}

func scutilScalar(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " : "); ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func scutilArray(out, key string) []string {
	var vals []string
	in := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, key+" : <array>") {
			in = true
			continue
		}
		if in {
			if t == "}" {
				break
			}
			if _, v, ok := strings.Cut(t, " : "); ok {
				vals = append(vals, strings.TrimSpace(v))
			}
		}
	}
	return vals
}

type darwinDNS struct {
	service string
	servers []string
	search  []string
	domain  string
}

func readDNS() (darwinDNS, error) {
	svc := scutilScalar(scutilShow("State:/Network/Global/IPv4"), "PrimaryService")
	if svc == "" {
		return darwinDNS{}, errors.New("no primary network service")
	}
	out := scutilShow("State:/Network/Service/" + svc + "/DNS")
	return darwinDNS{service: svc, servers: scutilArray(out, "ServerAddresses"), search: scutilArray(out, "SearchDomains"), domain: scutilScalar(out, "DomainName")}, nil
}

func writeDNS(d darwinDNS, servers []string) error {
	key := "State:/Network/Service/" + d.service + "/DNS"
	if len(servers) == 0 {
		_, err := runIn("open\nremove "+key+"\nquit\n", "scutil")
		return err
	}
	script := "open\nd.init\nd.add ServerAddresses * " + strings.Join(servers, " ") + "\n"
	if len(d.search) > 0 {
		script += "d.add SearchDomains * " + strings.Join(d.search, " ") + "\n"
	}
	if d.domain != "" {
		script += "d.add DomainName " + d.domain + "\n"
	}
	script += "set " + key + "\nquit\n"
	_, err := runIn(script, "scutil")
	_, _ = run("dscacheutil", "-flushcache")
	_, _ = run("killall", "-HUP", "mDNSResponder")
	return err
}

func setup(mtu int, overrideDNS, fakeOnly bool, log *slog.Logger) (*session, error) {
	phys, err := darwinPhysical("")
	if err != nil {
		return nil, err
	}
	saved, err := readDNS()
	if err != nil {
		return nil, err
	}
	upstream := saved.servers
	if len(upstream) == 0 && phys.Gateway != "" {
		upstream = []string{phys.Gateway}
	}
	dev, err := wgtun.CreateTUN("utun", mtu)
	if err != nil {
		return nil, fmt.Errorf("create utun: %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	fd, err := unix.Dup(int(dev.File().Fd()))
	dev.Close() // the duplicate keeps the interface alive
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var undo []func()
	cleanup := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	if _, err := run("ifconfig", name, "inet", "198.18.0.1", "198.18.0.1", "netmask", "255.254.0.0", "mtu", fmt.Sprint(mtu), "up"); err != nil {
		f.Close()
		return nil, err
	}
	_, _ = run("ifconfig", name, "inet6", "2001:2::1", "prefixlen", "48")
	routes4 := []string{"198.18.0.0/15", "0.0.0.0/1", "128.0.0.0/1"}
	if fakeOnly {
		routes4 = routes4[:1]
	}
	for _, r := range routes4 {
		if _, err := run("route", "-q", "-n", "add", "-inet", r, "-interface", name); err != nil {
			cleanup()
			f.Close()
			return nil, err
		}
		r := r
		undo = append(undo, func() { _, _ = run("route", "-q", "-n", "delete", "-inet", r, "-interface", name) })
	}
	_, _ = run("route", "-q", "-n", "add", "-inet6", "2001:2::/48", "-interface", name)
	if phys.IPv6 != "" && !fakeOnly {
		for _, r := range []string{"::/1", "8000::/1"} {
			if _, err := run("route", "-q", "-n", "add", "-inet6", r, "-interface", name); err == nil {
				r := r
				undo = append(undo, func() { _, _ = run("route", "-q", "-n", "delete", "-inet6", r, "-interface", name) })
			}
		}
	}
	dnsState := saved
	if overrideDNS {
		if err := writeDNS(saved, []string{"198.18.0.2"}); err != nil {
			log.Warn("override system DNS", "err", err)
		}
		undo = append(undo, func() { _ = writeDNS(dnsState, dnsState.servers) })
	}
	cur := phys
	return &session{file: f, name: name, physical: phys, dns: upstream, cleanup: cleanup,
		refresh: func() (Physical, []string, bool) {
			p, err := darwinPhysical(name)
			if err != nil || p == cur {
				return cur, upstream, false
			}
			// A new primary service: give the old one its DNS back and take over the new one.
			if overrideDNS {
				_ = writeDNS(dnsState, dnsState.servers)
			}
			if d, err := readDNS(); err == nil {
				dnsState = d
				if len(d.servers) > 0 && d.servers[0] != "198.18.0.2" {
					upstream = d.servers
				}
				if overrideDNS {
					_ = writeDNS(d, []string{"198.18.0.2"})
				}
			}
			cur = p
			return p, upstream, true
		}}, nil
}
