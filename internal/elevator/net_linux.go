package elevator

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	linuxDevice = "agentd0"
	linuxTable  = "5200"
	linuxPref   = "5200"
)

// linuxPhysical reads the main table's IPv4 default route.
func linuxPhysical() (Physical, error) {
	out, err := run("ip", "-4", "route", "show", "default")
	if err != nil {
		return Physical{}, err
	}
	var p Physical
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				p.Gateway = f[i+1]
			case "dev":
				p.Interface = f[i+1]
			case "src":
				p.IPv4 = f[i+1]
			}
		}
		if p.Interface == linuxDevice {
			p = Physical{}
			continue
		}
		break
	}
	if p.Interface == "" {
		return p, errors.New("no IPv4 default route")
	}
	ifi, err := net.InterfaceByName(p.Interface)
	if err != nil {
		return p, err
	}
	p.Index = ifi.Index
	if addrs, err := ifi.Addrs(); err == nil {
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
	}
	if p.IPv4 == "" {
		return p, fmt.Errorf("no IPv4 address on %s", p.Interface)
	}
	return p, nil
}

// linuxUpstreamDNS returns the real resolvers: systemd-resolved's upstream
// list, or the non-loopback servers in /etc/resolv.conf.
func linuxUpstreamDNS(fallback string) []string {
	for _, path := range []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		var out []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) >= 2 && fs[0] == "nameserver" {
				if ip := net.ParseIP(fs[1]); ip != nil && !ip.IsLoopback() && fs[1] != "198.18.0.2" {
					out = append(out, fs[1])
				}
			}
		}
		f.Close()
		if len(out) > 0 {
			return out
		}
	}
	if fallback != "" {
		return []string{fallback}
	}
	return nil
}

// openTun creates the device with plain IP framing (no packet info, no
// virtio header) so the unprivileged side can use it without ioctls.
func openTun(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		unix.Close(fd)
		return nil, errno
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

func resolvedActive() bool {
	if _, err := os.Stat("/run/systemd/resolve/stub-resolv.conf"); err != nil {
		return false
	}
	_, err := run("resolvectl", "status")
	return err == nil
}

func setup(mtu int, overrideDNS, fakeOnly bool, log *slog.Logger) (*session, error) {
	phys, err := linuxPhysical()
	if err != nil {
		return nil, err
	}
	dns := linuxUpstreamDNS(phys.Gateway)
	f, err := openTun(linuxDevice)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", linuxDevice, err)
	}
	var undo []func()
	cleanup := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	must := func(args ...string) error {
		_, err := run("ip", args...)
		return err
	}
	steps := [][]string{
		{"link", "set", "dev", linuxDevice, "mtu", strconv.Itoa(mtu)},
		{"addr", "add", "198.18.0.1/15", "dev", linuxDevice},
		{"link", "set", "dev", linuxDevice, "up"},
	}
	for _, s := range steps {
		if err := must(s...); err != nil {
			f.Close()
			return nil, err
		}
	}
	_ = must("-6", "addr", "add", "2001:2::1/48", "dev", linuxDevice)
	// The device's own traffic (bound to the physical address) keeps using
	// the original default route; everything else goes to the TUN.
	applyRule := func(p Physical) error {
		def := []string{"route", "replace", "default", "dev", p.Interface, "table", linuxTable}
		if p.Gateway != "" {
			def = []string{"route", "replace", "default", "via", p.Gateway, "dev", p.Interface, "table", linuxTable}
		}
		if err := must(def...); err != nil {
			return err
		}
		_ = must("rule", "del", "pref", linuxPref)
		return must("rule", "add", "pref", linuxPref, "from", p.IPv4, "lookup", linuxTable)
	}
	if err := applyRule(phys); err != nil {
		f.Close()
		return nil, err
	}
	undo = append(undo, func() {
		_ = must("rule", "del", "pref", linuxPref)
		_ = must("route", "flush", "table", linuxTable)
	})
	takeover := []string{"0.0.0.0/1", "128.0.0.0/1"}
	if fakeOnly {
		takeover = nil // the connected 198.18.0.0/15 route is enough
	}
	for _, r := range takeover {
		if err := must("route", "add", r, "dev", linuxDevice); err != nil {
			cleanup()
			f.Close()
			return nil, err
		}
		r := r
		undo = append(undo, func() { _ = must("route", "del", r, "dev", linuxDevice) })
	}
	if !overrideDNS {
		log.Info("keeping the system DNS (override_system: false)")
	} else if resolvedActive() {
		for _, args := range [][]string{{"dns", linuxDevice, "198.18.0.2"}, {"domain", linuxDevice, "~."}, {"default-route", linuxDevice, "yes"}} {
			if _, err := run("resolvectl", args...); err != nil {
				log.Warn("resolvectl", "err", err)
			}
		}
		undo = append(undo, func() { _, _ = run("resolvectl", "revert", linuxDevice) })
	} else if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if err := os.WriteFile("/etc/resolv.conf", []byte("# written by agentd elevator; restored when TUN mode stops\nnameserver 198.18.0.2\n"), 0o644); err == nil {
			undo = append(undo, func() { _ = os.WriteFile("/etc/resolv.conf", b, 0o644) })
		}
	}
	cur := phys
	return &session{file: f, name: linuxDevice, physical: phys, dns: dns, cleanup: cleanup,
		refresh: func() (Physical, []string, bool) {
			p, err := linuxPhysical()
			if err != nil || p == cur {
				return cur, dns, false
			}
			if err := applyRule(p); err != nil {
				log.Warn("update routing", "err", err)
				return cur, dns, false
			}
			cur = p
			dns = linuxUpstreamDNS(p.Gateway)
			return p, dns, true
		}}, nil
}
