//go:build windows

package elevator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// DefaultSocket is where the elevator listens (AF_UNIX works on Windows 10+).
var DefaultSocket = filepath.Join(os.Getenv("ProgramData"), "agentd", "elevator.sock")

const adapterName = "agentd"

// Server is the elevator process. On Windows it owns the wintun adapter and
// relays packets to agentd over the socket (wintun sessions cannot be passed
// to another process).
type Server struct {
	Socket   string
	AllowUID int
	AllowSID string
	Log      *slog.Logger
}

func netsh(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Run serves until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Socket == "" {
		s.Socket = DefaultSocket
	}
	if s.AllowSID == "" {
		return errors.New("the elevator needs --allow-sid")
	}
	if err := os.MkdirAll(filepath.Dir(s.Socket), 0o755); err != nil {
		return err
	}
	os.Remove(s.Socket)
	ln, err := net.Listen("unix", s.Socket)
	if err != nil {
		return err
	}
	defer os.Remove(s.Socket)
	// Only SYSTEM, administrators and the allowed user may connect.
	if out, err := exec.Command("icacls", s.Socket, "/inheritance:r", "/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F", "*"+s.AllowSID+":RW").CombinedOutput(); err != nil {
		ln.Close()
		return fmt.Errorf("restrict %s: %v: %s", s.Socket, err, out)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	s.Log.Info("elevator listening", "socket", s.Socket, "sid", s.AllowSID)
	busy := make(chan struct{}, 1)
	var wg sync.WaitGroup
	defer wg.Wait() // sessions remove the adapter when they end
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, c, busy)
		}()
	}
}

func sendLine(c net.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = c.Write(append(b, '\n'))
	return err
}

func (s *Server) handle(ctx context.Context, c net.Conn, busy chan struct{}) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := br.ReadBytes('\n')
	var req Request
	if err != nil || json.Unmarshal(line, &req) != nil || req.Op != "open" {
		sendLine(c, Response{Error: "expected an open request"})
		return
	}
	c.SetReadDeadline(time.Time{})
	select {
	case busy <- struct{}{}:
	default:
		sendLine(c, Response{Error: "the TUN device is already held by another agentd instance"})
		return
	}
	defer func() { <-busy }()
	if req.MTU < 1280 || req.MTU > 9000 {
		req.MTU = 1500
	}
	phys, err := winPhysical()
	if err != nil {
		sendLine(c, Response{Error: err.Error()})
		return
	}
	dns := winDNS(phys.Index)
	dev, err := wgtun.CreateTUN(adapterName, req.MTU)
	if err != nil {
		sendLine(c, Response{Error: fmt.Sprintf("create the wintun adapter (is wintun.dll next to agentd.exe?): %v", err)})
		return
	}
	defer dev.Close() // removing the adapter removes its routes and DNS
	steps := [][]string{
		{"interface", "ipv4", "set", "address", "name=" + adapterName, "source=static", "address=198.18.0.1", "mask=255.254.0.0"},
		{"interface", "ipv4", "set", "subinterface", adapterName, "mtu=" + strconv.Itoa(req.MTU), "store=active"},
		{"interface", "ipv4", "set", "interface", adapterName, "metric=1"},
	}
	if !req.FakeOnly {
		steps = append(steps,
			[]string{"interface", "ipv4", "add", "route", "prefix=0.0.0.0/1", "interface=" + adapterName, "nexthop=0.0.0.0", "metric=1", "store=active"},
			[]string{"interface", "ipv4", "add", "route", "prefix=128.0.0.0/1", "interface=" + adapterName, "nexthop=0.0.0.0", "metric=1", "store=active"})
	}
	if !req.KeepDNS {
		steps = append(steps, []string{"interface", "ipv4", "set", "dnsservers", "name=" + adapterName, "source=static", "address=198.18.0.2", "register=none", "validate=no"})
	}
	for _, st := range steps {
		if err := netsh(st...); err != nil {
			sendLine(c, Response{Error: err.Error()})
			return
		}
	}
	_ = netsh("interface", "ipv6", "add", "address", adapterName, "2001:2::1/48", "store=active")
	if err := sendLine(c, Response{OK: true, Name: adapterName, MTU: req.MTU, Physical: phys, DNS: dns}); err != nil {
		return
	}
	s.Log.Info("tun handed to agentd", "device", adapterName, "instance", req.Instance, "physical", phys.Interface)
	var wmu sync.Mutex
	write := func(typ byte, p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return writeFrame(c, typ, p)
	}
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }
	go func() { // adapter -> agentd
		defer stop()
		batch := dev.BatchSize()
		bufs := make([][]byte, batch)
		for i := range bufs {
			bufs[i] = make([]byte, 16+65535)
		}
		sizes := make([]int, batch)
		for {
			n, err := dev.Read(bufs, sizes, 16)
			for i := 0; i < n; i++ {
				if werr := write(framePacket, bufs[i][16:16+sizes[i]]); werr != nil {
					return
				}
			}
			if err != nil && !errors.Is(err, wgtun.ErrTooManySegments) {
				return
			}
		}
	}()
	go func() { // agentd -> adapter
		defer stop()
		for {
			typ, p, err := readFrame(br)
			if err != nil {
				return
			}
			if typ != framePacket {
				continue
			}
			buf := make([]byte, 16+len(p))
			copy(buf[16:], p)
			if _, err := dev.Write([][]byte{buf}, 16); err != nil {
				return
			}
		}
	}()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	cur := phys
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			s.Log.Info("tun released", "device", adapterName, "instance", req.Instance)
			return
		case <-t.C:
			p, err := winPhysical()
			if err != nil || p == cur {
				continue
			}
			cur = p
			b, _ := json.Marshal(Response{OK: true, Event: "network", Physical: p, DNS: winDNS(p.Index)})
			if write(frameJSON, b) != nil {
				return
			}
		}
	}
}

// winPhysical finds the lowest-metric IPv4 default route that is not ours.
func winPhysical() (Physical, error) {
	out, err := exec.Command("route", "print", "-4").CombinedOutput()
	if err != nil {
		return Physical{}, err
	}
	best, bestMetric := Physical{}, 1<<30
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 5 || f[0] != "0.0.0.0" || f[1] != "0.0.0.0" || f[3] == "198.18.0.1" {
			continue
		}
		m, err := strconv.Atoi(f[4])
		if err != nil || m >= bestMetric {
			continue
		}
		bestMetric = m
		best = Physical{IPv4: f[3], Gateway: f[2]}
	}
	if best.IPv4 == "" {
		return best, errors.New("no IPv4 default route")
	}
	ifs, _ := net.Interfaces()
	for _, ifi := range ifs {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.String() == best.IPv4 {
				best.Interface, best.Index = ifi.Name, ifi.Index
			}
		}
	}
	if best.Index == 0 {
		return best, fmt.Errorf("no interface has %s", best.IPv4)
	}
	if net.ParseIP(best.Gateway) == nil {
		best.Gateway = ""
	}
	return best, nil
}

// winDNS lists the DNS servers configured on an interface.
func winDNS(index int) []string {
	size := uint32(15000)
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var out []string
		for a := aa; a != nil; a = a.Next {
			if int(a.IfIndex) != index {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				if ip := d.Address.IP(); ip != nil && ip.To4() != nil {
					out = append(out, ip.String())
				}
			}
		}
		return out
	}
	return nil
}
