package sim

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"agentd/internal/adminapi"
	"agentd/internal/pki"
)

// TestTUNEndToEnd drives a real TUN device: the elevator runs as a separate
// privileged process (sudo on macOS and Linux, an elevated runner on
// Windows), a TUN-mode node joins the in-process stack, and the test itself
// resolves and connects like any application: kernel, TUN, netstack, relay,
// egress node, origin. It needs root/admin on a disposable machine, so it
// only runs with AGENTD_TUN_E2E=1 (CI sets it). AGENTD_TUN_CAPTURE picks
// the capture mode (default fakeip, which leaves the runner's own traffic
// alone).
func TestTUNEndToEnd(t *testing.T) {
	if os.Getenv("AGENTD_TUN_E2E") != "1" {
		t.Skip("needs root/admin on a disposable machine; set AGENTD_TUN_E2E=1")
	}
	capture := os.Getenv("AGENTD_TUN_CAPTURE")
	if capture == "" {
		capture = "fakeip"
	}
	s := newStack(t)
	s.workspace("home")

	cert, ca, err := pki.SelfSigned([]string{"web.campus.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello through the tun")
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	origin.StartTLS()
	defer origin.Close()
	s.extra.Store("web.campus.test", origin.Listener.Addr().String())

	s.join("home", "dorm", `
  egress:
    enabled: true
    policies:
      - { public_key: "*", action: allow, proto: tls, domains: [{ kind: domain, value: web.campus.test }] }
`)
	proto := []adminapi.Proto{"tls"}
	if r, err := s.admin.AddRouteWithResponse(s.ctx, "home", adminapi.RouteWrite{From: "workspace", Proto: &proto, Domains: []adminapi.Match{{Kind: "domain", Value: "web.campus.test"}}, To: "dorm"}); err != nil || r.StatusCode() != 201 {
		t.Fatalf("add route: %v %s", err, r.Body)
	}

	exe := buildAgentd(t)
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("agentd-e2e-%d.sock", os.Getpid()))
	startElevator(t, exe, sock)
	t.Setenv("AGENTD_ELEVATOR_SOCKET", sock)
	laptop := s.join("home", "laptop", `
  ingress:
    enabled: true
    fallback: reject
    tun:
      enabled: true
      capture: `+capture+`
      dns:
        override_system: false
`)
	s.eventually("tun mode on", func() bool { _, ok := laptop.a.Status()["tun"]; return ok })
	s.eventually("the route reaches the laptop", func() bool { return len(laptop.a.Routes().Routes) == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "198.18.0.2:53")
	}}
	var fake netip.Addr
	s.eventually("the built-in DNS answers a fake address", func() bool {
		addrs, err := res.LookupNetIP(ctx, "ip4", "web.campus.test")
		if err != nil || len(addrs) == 0 {
			return false
		}
		fake = addrs[0].Unmap()
		return netip.MustParsePrefix("198.18.0.0/15").Contains(fake)
	})
	c, err := net.DialTimeout("tcp", netip.AddrPortFrom(fake, 443).String(), 10*time.Second)
	if err != nil {
		t.Fatalf("connect to the fake address: %v", err)
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: "web.campus.test", RootCAs: pki.Pool(ca)})
	tc.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: web.campus.test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("https through the tun: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "hello through the tun" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	info := laptop.a.Status()["tun"].(map[string]any)
	if n, _ := info["dns_fake_answers"].(int64); n < 1 {
		t.Fatalf("tun status: %v", info)
	}
	t.Logf("tun %v: fake %v served by dorm via the relay", info["device"], fake)
}

func buildAgentd(t *testing.T) string {
	t.Helper()
	if exe := os.Getenv("AGENTD_E2E_BINARY"); exe != "" {
		return exe // prebuilt (VMs without a Go toolchain)
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "agentd")
	if runtime.GOOS == "windows" {
		exe += ".exe"
		dll := os.Getenv("AGENTD_WINTUN_DLL")
		if dll == "" {
			t.Fatal("set AGENTD_WINTUN_DLL to wintun.dll")
		}
		b, err := os.ReadFile(dll)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "wintun.dll"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command("go", "build", "-o", exe, "agentd/cmd/agentd").CombinedOutput()
	if err != nil {
		t.Fatalf("build agentd: %v\n%s", err, out)
	}
	return exe
}

func windowsSID(t *testing.T) string {
	out, err := exec.Command("whoami", "/user", "/fo", "csv", "/nh").Output()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := csv.NewReader(strings.NewReader(strings.TrimSpace(string(out)))).Read()
	if err != nil || len(rec) < 2 {
		t.Fatalf("whoami: %q", out)
	}
	return rec[1]
}

// startElevator runs the privileged helper and waits for its socket.
func startElevator(t *testing.T, exe, sock string) {
	t.Helper()
	logf, _ := os.Create(filepath.Join(t.TempDir(), "elevator.log"))
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command(exe, "elevator", "run", "--allow-sid", windowsSID(t), "--socket", sock)
	} else {
		cmd = exec.Command("sudo", "-n", exe, "elevator", "run", "--allow-uid", strconv.Itoa(os.Getuid()), "--socket", sock)
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the elevator: %v", err)
	}
	t.Cleanup(func() {
		if runtime.GOOS == "windows" {
			cmd.Process.Kill()
		} else {
			exec.Command("sudo", "-n", "kill", "-TERM", strconv.Itoa(cmd.Process.Pid)).Run()
		}
		cmd.Wait()
		logf.Seek(0, 0)
		b, _ := io.ReadAll(logf)
		t.Logf("elevator log:\n%s", b)
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	logf.Seek(0, 0)
	b, _ := io.ReadAll(logf)
	t.Fatalf("the elevator did not come up:\n%s", b)
}
