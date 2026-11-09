//go:build linux || darwin

package elevator

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestDescriptorPassing: a response carries a file descriptor that the
// receiver can use, and messages split or coalesced on the stream still
// frame correctly.
func TestDescriptorPassing(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "e.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		sc := &conn{c: c}
		var req Request
		sc.recv(&req)
		sc.send(Response{OK: true, Name: req.Instance + "-tun", MTU: req.MTU, DNS: []string{"10.0.0.53"}}, w)
		w.Close() // the receiver holds its own copy now, as with the TUN device
		sc.send(Response{OK: true, Event: "network", Physical: Physical{Interface: "wlan0"}}, nil)
		c.Close()
	}()
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	cc := &conn{c: uc}
	cc.send(Request{Op: "open", MTU: 1400, Instance: "laptop"}, nil)
	var resp Response
	f, err := cc.recv(&resp)
	if err != nil || f == nil || resp.Name != "laptop-tun" || resp.MTU != 1400 {
		t.Fatalf("response: %v %v %+v", err, f, resp)
	}
	// The passed descriptor is the pipe's write end.
	go func() { f.Write([]byte("through the passed fd")); f.Close() }()
	got, _ := io.ReadAll(r)
	if string(got) != "through the passed fd" {
		t.Fatalf("passed fd: %q", got)
	}
	var ev Response
	if _, err := cc.recv(&ev); err != nil || ev.Event != "network" || ev.Physical.Interface != "wlan0" {
		t.Fatalf("event: %v %+v", err, ev)
	}
}
