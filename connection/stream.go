package connection

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Stream is an admitted flow. Close cancels both peers; CloseWrite only sends FIN
// and leaves the read half available for the peer's final response.
type Stream struct {
	raw            *yamux.Stream
	session        *Session
	request        OpenRequest
	claims         OpenClaims
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	closed         bool
	writeClosed    bool
	readEOF        bool
	timer          *time.Timer
	leaseEpoch     uint64
	leaseExpired   bool
	leaseSequence  uint64
	remoteRenewing bool
	renewGate      chan struct{}
	readDeadline   time.Time
	writeDeadline  time.Time
}

func newStream(session *Session, raw *yamux.Stream, request OpenRequest) *Stream {
	ctx, cancel := context.WithCancel(session.ctx)
	s := &Stream{raw: raw, session: session, request: request, ctx: ctx, cancel: cancel, renewGate: make(chan struct{}, 1)}
	s.renewGate <- struct{}{}
	return s
}

func (s *Stream) Request() OpenRequest     { return s.request }
func (s *Stream) Claims() OpenClaims       { s.mu.Lock(); defer s.mu.Unlock(); return s.claims }
func (s *Stream) Context() context.Context { return s.ctx }
func (s *Stream) LocalAddr() net.Addr      { return s.raw.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr     { return s.raw.RemoteAddr() }

func (s *Stream) activate(claims OpenClaims) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return ErrClosed
	}
	s.claims = claims
	if err := s.resetLeaseLocked(); err != nil {
		return err
	}
	return nil
}

func (s *Stream) resetLeaseLocked() error {
	deadline := s.leaseDeadline()
	if !deadline.After(time.Now()) {
		return ErrExpired
	}
	if err := s.raw.SetReadDeadline(earlier(s.readDeadline, deadline)); err != nil {
		return err
	}
	if err := s.raw.SetWriteDeadline(earlier(s.writeDeadline, deadline)); err != nil {
		return err
	}
	s.leaseEpoch++
	epoch := s.leaseEpoch
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(time.Until(deadline), func() {
		s.mu.Lock()
		if s.closed || epoch != s.leaseEpoch || time.Now().Before(s.leaseDeadline()) {
			s.mu.Unlock()
			return
		}
		s.leaseExpired = true
		s.mu.Unlock()
		_ = s.Close()
	})
	return nil
}

func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	n, err := s.raw.Read(p)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	if err == io.EOF {
		s.readEOF = true
	}
	finished := s.readEOF && s.writeClosed
	s.mu.Unlock()
	if finished {
		_ = s.close(false)
	}
	return n, err
}

func (s *Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	closed := s.closed || s.writeClosed
	s.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	return s.raw.Write(p)
}

func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	if s.closed || s.writeClosed {
		s.mu.Unlock()
		return nil
	}
	s.writeClosed = true
	finished := s.readEOF
	s.mu.Unlock()
	err := s.raw.Close() // yamux Close is documented in code as write-half FIN.
	if finished {
		_ = s.close(false)
	}
	return err
}

func (s *Stream) Close() error { return s.close(true) }

func (s *Stream) close(notify bool) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	s.cancel()
	// This unblocks local IO immediately. The control CANCEL makes the remote
	// peer cancel its flow context and close the real target socket as well.
	_ = s.raw.SetDeadline(time.Now())
	s.mu.Unlock()
	if notify {
		s.session.sendCancel(s.request.FlowID)
	}
	err := s.raw.Close()
	s.session.release(s)
	return err
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.readDeadline = t
	s.writeDeadline = t
	return s.raw.SetDeadline(earlier(t, s.leaseDeadline()))
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.readDeadline = t
	return s.raw.SetReadDeadline(earlier(t, s.leaseDeadline()))
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.writeDeadline = t
	return s.raw.SetWriteDeadline(earlier(t, s.leaseDeadline()))
}

func (s *Stream) leaseDeadline() time.Time {
	return earlier(earlier(s.request.Deadline, s.claims.Deadline), s.claims.LeaseExpiresAt)
}

var _ net.Conn = (*Stream)(nil)
