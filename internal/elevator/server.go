//go:build linux || darwin

package elevator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

// Server is the elevator process.
type Server struct {
	Socket   string
	AllowUID int    // the user whose agentd may use the TUN (macOS, Linux)
	AllowSID string // the same on Windows
	Log      *slog.Logger
}

// session is one configured TUN (platform code fills it).
type session struct {
	file     *os.File
	name     string
	physical Physical
	dns      []string
	cleanup  func()
	refresh  func() (Physical, []string, bool) // re-applies routing after network changes
}

// Run serves until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if s.Socket == "" {
		s.Socket = DefaultSocket
	}
	os.Remove(s.Socket)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer os.Remove(s.Socket)
	if err := os.Chown(s.Socket, s.AllowUID, -1); err != nil {
		return err
	}
	if err := os.Chmod(s.Socket, 0o600); err != nil {
		return err
	}
	go func() { <-ctx.Done(); ln.Close() }()
	s.Log.Info("elevator listening", "socket", s.Socket, "uid", s.AllowUID)
	busy := make(chan struct{}, 1)
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, c, busy)
	}
}

func (s *Server) handle(ctx context.Context, uc *net.UnixConn, busy chan struct{}) {
	defer uc.Close()
	c := &conn{c: uc}
	fail := func(msg string) { _ = c.send(Response{Error: msg}, nil) }
	uid, err := peerUID(uc)
	if err != nil || (uid != s.AllowUID && uid != 0) {
		fail("this user may not use the TUN device")
		s.Log.Warn("rejected elevator client", "uid", uid, "err", err)
		return
	}
	uc.SetReadDeadline(time.Now().Add(10 * time.Second))
	var req Request
	if _, err := c.recv(&req); err != nil || req.Op != "open" {
		fail("expected an open request")
		return
	}
	uc.SetReadDeadline(time.Time{})
	select {
	case busy <- struct{}{}:
	default:
		fail("the TUN device is already held by another agentd instance")
		return
	}
	defer func() { <-busy }()
	if req.MTU < 1280 || req.MTU > 9000 {
		req.MTU = 1500
	}
	sess, err := setup(req.MTU, !req.KeepDNS, req.FakeOnly, s.Log)
	if err != nil {
		fail(fmt.Sprintf("set up the TUN device: %v", err))
		s.Log.Error("tun setup failed", "err", err)
		return
	}
	defer func() {
		sess.cleanup()
		s.Log.Info("tun released", "device", sess.name, "instance", req.Instance)
	}()
	err = c.send(Response{OK: true, Name: sess.name, MTU: req.MTU, Physical: sess.physical, DNS: sess.dns}, sess.file)
	sess.file.Close() // agentd holds the device now; it vanishes when agentd exits
	if err != nil {
		return
	}
	s.Log.Info("tun handed to agentd", "device", sess.name, "instance", req.Instance, "physical", sess.physical.Interface)
	gone := make(chan struct{})
	go func() {
		b := make([]byte, 64)
		for {
			if _, err := uc.Read(b); err != nil {
				close(gone)
				return
			}
		}
	}()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-gone:
			return
		case <-t.C:
			if p, dns, changed := sess.refresh(); changed {
				s.Log.Info("network changed", "physical", p.Interface, "ipv4", p.IPv4)
				if err := c.send(Response{OK: true, Event: "network", Physical: p, DNS: dns}, nil); err != nil {
					return
				}
			}
		}
	}
}

// Session is agentd's side: the device and the network to bypass it with.
type Session struct {
	File     *os.File
	Name     string
	MTU      int
	Physical Physical
	DNS      []string
	Events   <-chan Response
	conn     *net.UnixConn
}

// Close releases the device (the elevator restores routes and DNS).
func (s *Session) Close() error {
	if s.File != nil {
		s.File.Close()
	}
	return s.conn.Close()
}

// Open asks the elevator for the TUN device; overrideDNS points the system
// resolver at the built-in DNS.
func Open(ctx context.Context, socket, instance string, mtu int, overrideDNS, fakeOnly bool) (*Session, error) {
	if socket == "" {
		socket = DefaultSocket
	}
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("the elevator is not running (install it with `sudo agentd elevator install`): %w", err)
	}
	uc := nc.(*net.UnixConn)
	c := &conn{c: uc}
	if err := c.send(Request{Op: "open", MTU: mtu, Instance: instance, KeepDNS: !overrideDNS, FakeOnly: fakeOnly}, nil); err != nil {
		uc.Close()
		return nil, err
	}
	uc.SetReadDeadline(time.Now().Add(30 * time.Second))
	var resp Response
	f, err := c.recv(&resp)
	if err != nil {
		uc.Close()
		return nil, err
	}
	uc.SetReadDeadline(time.Time{})
	if !resp.OK || f == nil {
		uc.Close()
		if f != nil {
			f.Close()
		}
		if resp.Error == "" {
			resp.Error = "no TUN device received"
		}
		return nil, errors.New(resp.Error)
	}
	events := make(chan Response, 4)
	go func() {
		defer close(events)
		for {
			var ev Response
			if _, err := c.recv(&ev); err != nil {
				return
			}
			select {
			case events <- ev:
			default:
			}
		}
	}()
	return &Session{File: f, Name: resp.Name, MTU: resp.MTU, Physical: resp.Physical, DNS: resp.DNS, Events: events, conn: uc}, nil
}
