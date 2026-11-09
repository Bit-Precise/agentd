// Package stream holds the stream plumbing shared by agentd and agentrelay:
// rejecting a stream with an Ack, and splicing two byte streams with
// half-close and reset propagation (protocol 4.4).
package stream

import (
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

type closeWriter interface{ CloseWrite() error }
type resetter interface{ Reset() error }

// CloseWrite half-closes c (FIN), or closes it when half-close is unsupported.
func CloseWrite(c io.Closer) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// Abort resets c: RST on yamux streams, linger-0 close on TCP.
func Abort(c io.Closer) {
	switch x := c.(type) {
	case resetter:
		_ = x.Reset()
	case *net.TCPConn:
		_ = x.SetLinger(0)
		_ = x.Close()
	default:
		_ = c.Close()
	}
}

// Reject writes a failure Ack and resets the stream once the peer has had a
// chance to read it (a yamux RST discards unread data, so the RST is sent
// only after the peer closes or a short grace period).
func Reject(st net.Conn, ack *pb.Ack) {
	_ = st.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = wire.WriteMsg(st, ack)
	CloseWrite(st)
	go func() {
		_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(io.Discard, st)
		Abort(st)
	}()
}

// Fail is Reject with a status and message.
func Fail(st net.Conn, status pb.Status, msg string, trace []byte) {
	Reject(st, &pb.Ack{Status: status, Message: msg, TraceId: trace})
}

// Splice copies both directions until both are done. EOF on one side
// half-closes the other; an error resets both.
func Splice(a, b io.ReadWriteCloser) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src io.ReadWriteCloser, n *int64) {
		defer wg.Done()
		var err error
		*n, err = io.CopyBuffer(dst, src, make([]byte, 32<<10))
		if err == nil {
			CloseWrite(dst)
			return
		}
		Abort(dst)
		Abort(src)
	}
	go cp(b, a, &aToB)
	go cp(a, b, &bToA)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
	return
}

// ReadAck reads the first reply of a stream within timeout.
func ReadAck(st net.Conn, timeout time.Duration) (*pb.Ack, error) {
	_ = st.SetReadDeadline(time.Now().Add(timeout))
	defer st.SetReadDeadline(time.Time{})
	var ack pb.Ack
	if err := wire.ReadMsg(st, &ack, wire.AckMax); err != nil {
		return nil, err
	}
	return &ack, nil
}

// Clone copies a message (helper for callers that annotate forwarded opens).
func Clone[T proto.Message](m T) T { return proto.Clone(m).(T) }

// Copy copies with a 32 KiB buffer (backpressure follows the windows).
func Copy(dst io.Writer, src io.Reader) (int64, error) {
	return io.CopyBuffer(dst, src, make([]byte, 32<<10))
}

// Listener is a net.Listener fed by Push (serving streams with net/http).
type Listener struct {
	ch     chan net.Conn
	done   chan struct{}
	closed sync.Once
}

// NewListener creates a Listener.
func NewListener() *Listener {
	return &Listener{ch: make(chan net.Conn, 64), done: make(chan struct{})}
}

// Push hands a connection to Accept; false after Close.
func (l *Listener) Push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

// Accept implements net.Listener.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close implements net.Listener.
func (l *Listener) Close() error {
	l.closed.Do(func() { close(l.done) })
	return nil
}

// Addr implements net.Listener.
func (l *Listener) Addr() net.Addr { return &net.TCPAddr{} }
