// SPDX-License-Identifier: MPL-2.0
package xhttp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var ErrClosed = net.ErrClosed

type timeoutError struct{ op string }

func (e *timeoutError) Error() string   { return "xhttp: " + e.op + " deadline exceeded" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

type address string

func (a address) Network() string { return "xhttp" }
func (a address) String() string  { return string(a) }

type deadline struct {
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func newDeadline() *deadline { return &deadline{changed: make(chan struct{})} }
func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	d.at = t
	close(d.changed)
	d.changed = make(chan struct{})
	d.mu.Unlock()
}
func (d *deadline) watch() (time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.at, d.changed
}

// timerFor avoids allocating a timer when no deadline is set.
func timerFor(at time.Time) (<-chan time.Time, func()) {
	if at.IsZero() {
		return nil, func() {}
	}
	t := time.NewTimer(time.Until(at))
	return t.C, func() { t.Stop() }
}

type conn struct {
	ctx           context.Context
	cancel        context.CancelFunc
	done          chan struct{}
	once          sync.Once
	errMu         sync.Mutex
	err           error
	onClose       func()
	in            chan []byte
	readMu        sync.Mutex
	remaining     []byte
	writeLock     chan struct{}
	rd, wd        *deadline
	packetSize    int
	writePacket   func([]byte) error
	local, remote net.Addr
}

func newConn(ctx context.Context, packets, packetSize int) *conn {
	ctx, cancel := context.WithCancel(ctx)
	c := &conn{ctx: ctx, cancel: cancel, done: make(chan struct{}), in: make(chan []byte, packets),
		writeLock: make(chan struct{}, 1), rd: newDeadline(), wd: newDeadline(), packetSize: packetSize,
		local: address("local"), remote: address("remote")}
	c.writeLock <- struct{}{}
	return c
}

func (c *conn) startContextWatch() {
	go func() {
		select {
		case <-c.ctx.Done():
			c.closeWithError(c.ctx.Err())
		case <-c.done:
		}
	}()
}

func (c *conn) closedError() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.err != nil {
		return c.err
	}
	return net.ErrClosed
}

func (c *conn) closeWithError(err error) {
	c.once.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		c.errMu.Lock()
		c.err = err
		c.errMu.Unlock()
		close(c.done)
		c.cancel()
		if c.onClose != nil {
			c.onClose()
		}
	})
}

func (c *conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		select {
		case <-c.done:
			// Local close, cancellation and failed transport operations abort
			// buffered delivery. Only a clean peer EOF drains received bytes.
			if err := c.closedError(); !errors.Is(err, io.EOF) {
				return 0, err
			}
		default:
		}
		at, changed := c.rd.watch()
		if !at.IsZero() && !time.Now().Before(at) {
			return 0, &timeoutError{"read"}
		}
		if len(c.remaining) > 0 {
			n := copy(p, c.remaining)
			c.remaining = c.remaining[n:]
			return n, nil
		}
		// Deliver already received bytes before reporting a peer EOF.
		select {
		case c.remaining = <-c.in:
			continue
		default:
		}
		tick, stop := timerFor(at)
		select {
		case c.remaining = <-c.in:
		case <-changed:
		case <-tick:
			stop()
			return 0, &timeoutError{"read"}
		case <-c.done:
			stop()
			err := c.closedError()
			if errors.Is(err, io.EOF) {
				// A producer can enqueue its final packet between the fast-path
				// queue check and this select, then signal EOF. Both cases may be
				// ready, so recheck the queue instead of returning EOF early.
				select {
				case c.remaining = <-c.in:
					continue
				default:
				}
			}
			return 0, err
		}
		stop()
	}
}

func (c *conn) lockWrite() error {
	for {
		at, changed := c.wd.watch()
		if !at.IsZero() && !time.Now().Before(at) {
			return &timeoutError{"write"}
		}
		tick, stop := timerFor(at)
		select {
		case <-c.writeLock:
			stop()
			select {
			case <-c.done:
				c.writeLock <- struct{}{}
				return c.closedError()
			default:
				return nil
			}
		case <-changed:
		case <-tick:
			stop()
			return &timeoutError{"write"}
		case <-c.done:
			stop()
			return c.closedError()
		}
		stop()
	}
}

func (c *conn) Write(p []byte) (int, error) {
	if err := c.lockWrite(); err != nil {
		return 0, err
	}
	defer func() { c.writeLock <- struct{}{} }()
	n := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), c.packetSize)]
		if err := c.writePacket(chunk); err != nil {
			return n, err
		}
		n += len(chunk)
		p = p[len(chunk):]
	}
	return n, nil
}

func (c *conn) Close() error                       { c.closeWithError(net.ErrClosed); return nil }
func (c *conn) LocalAddr() net.Addr                { return c.local }
func (c *conn) RemoteAddr() net.Addr               { return c.remote }
func (c *conn) SetReadDeadline(t time.Time) error  { c.rd.set(t); return nil }
func (c *conn) SetWriteDeadline(t time.Time) error { c.wd.set(t); return nil }
func (c *conn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return nil
}

func normalizeReadError(err error) error {
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	return err
}
