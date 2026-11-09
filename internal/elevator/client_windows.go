//go:build windows

package elevator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Session is agentd's side of the TUN on Windows: packets come and go as
// frames on the elevator connection.
type Session struct {
	Name     string
	MTU      int
	Physical Physical
	DNS      []string
	Events   <-chan Response
	Dev      *FrameDevice
	conn     net.Conn
}

// Close releases the adapter (the elevator removes it).
func (s *Session) Close() error { return s.conn.Close() }

// FrameDevice is a TUN device backed by the elevator's packet relay.
type FrameDevice struct {
	c      net.Conn
	br     *bufio.Reader
	mtu    int
	wmu    sync.Mutex
	events chan Response
}

func (d *FrameDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		typ, p, err := readFrame(d.br)
		if err != nil {
			close(d.events)
			return 0, net.ErrClosed
		}
		switch typ {
		case framePacket:
			sizes[0] = copy(bufs[0][offset:], p)
			return 1, nil
		case frameJSON:
			var ev Response
			if json.Unmarshal(p, &ev) == nil {
				select {
				case d.events <- ev:
				default:
				}
			}
		}
	}
}

func (d *FrameDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	for i, b := range bufs {
		if err := writeFrame(d.c, framePacket, b[offset:]); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (d *FrameDevice) BatchSize() int    { return 1 }
func (d *FrameDevice) MTU() (int, error) { return d.mtu, nil }
func (d *FrameDevice) Close() error      { return d.c.Close() }

// Open asks the elevator for the TUN device.
func Open(ctx context.Context, socket, instance string, mtu int, overrideDNS, fakeOnly bool) (*Session, error) {
	if socket == "" {
		socket = DefaultSocket
	}
	var dl net.Dialer
	c, err := dl.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("the elevator is not running (install it from an administrator shell with `agentd elevator install`): %w", err)
	}
	if err := sendLine(c, Request{Op: "open", MTU: mtu, Instance: instance, KeepDNS: !overrideDNS, FakeOnly: fakeOnly}); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	line, err := br.ReadBytes('\n')
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetReadDeadline(time.Time{})
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		c.Close()
		return nil, err
	}
	if !resp.OK {
		c.Close()
		if resp.Error == "" {
			resp.Error = "the elevator refused"
		}
		return nil, errors.New(resp.Error)
	}
	events := make(chan Response, 4)
	dev := &FrameDevice{c: c, br: br, mtu: resp.MTU, events: events}
	return &Session{Name: resp.Name, MTU: resp.MTU, Physical: resp.Physical, DNS: resp.DNS, Events: events, Dev: dev, conn: c}, nil
}
