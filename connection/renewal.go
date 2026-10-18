package connection

import (
	"context"
	"math"
	"time"
)

type pendingRenewal struct {
	sequence uint64
	reply    chan controlMessage
}

func validLease(expiry, hard time.Time, maximum time.Duration) bool {
	if expiry.IsZero() {
		return true
	}
	now := time.Now()
	return expiry.After(now) && !expiry.After(hard) && !expiry.After(now.Add(maximum))
}

// peerLeaseCeiling bounds a lease stamped by the peer's clock. A lease this side
// issues itself is always checked against the strict MaxLeaseDuration.
func (c Config) peerLeaseCeiling() time.Duration { return c.MaxLeaseDuration + c.MaxClockSkew }

// RenewLease is an Edge/server-only operation. It extends only the short lease
// of an existing stream, never its immutable hard Deadline or routing scope.
// An ACK must arrive before the old lease expires. Any failure closes this flow;
// the peer may hold only the bounded lease it last acknowledged/received.
func (s *Stream) RenewLease(ctx context.Context, expiry time.Time) error {
	if !s.session.server {
		return ErrRole
	}
	select {
	case <-s.renewGate:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return ErrClosed
	}
	defer func() { s.renewGate <- struct{}{} }()
	s.mu.Lock()
	current := s.leaseDeadline()
	hard := earlier(s.request.Deadline, s.claims.Deadline)
	if s.closed || s.leaseExpired || s.claims.LeaseExpiresAt.IsZero() || !current.After(time.Now()) || s.leaseSequence == math.MaxUint64 {
		s.mu.Unlock()
		return ErrExpired
	}
	if !expiry.After(current) || !validLease(expiry, hard, s.session.config.MaxLeaseDuration) {
		s.mu.Unlock()
		return ErrUnauthorized
	}
	sequence := s.leaseSequence + 1
	s.mu.Unlock()
	ctx, cancel := context.WithDeadline(ctx, earlier(current, time.Now().Add(s.session.config.OpenTimeout)))
	defer cancel()
	pending := &pendingRenewal{sequence: sequence, reply: make(chan controlMessage, 1)}
	s.session.mu.Lock()
	if s.session.streams[s.request.FlowID] != s {
		s.session.mu.Unlock()
		return ErrClosed
	}
	s.session.renewals[s.request.FlowID] = pending
	s.session.mu.Unlock()
	defer func() {
		s.session.mu.Lock()
		if s.session.renewals[s.request.FlowID] == pending {
			delete(s.session.renewals, s.request.FlowID)
		}
		s.session.mu.Unlock()
	}()
	fail := func(err error) error { _ = s.Close(); return err }
	msg := controlMessage{Type: "renew", FlowID: s.request.FlowID, Sequence: sequence, LeaseExpiresAt: expiry}
	select {
	case s.session.controls <- msg:
	case <-ctx.Done():
		return fail(ctx.Err())
	case <-s.ctx.Done():
		return ErrClosed
	case <-s.session.done:
		return ErrClosed
	}
	select {
	case ack := <-pending.reply:
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		if ack.Error != "" || ack.LeaseExpiresAt.After(expiry) || !validLease(ack.LeaseExpiresAt, hard, s.session.config.MaxLeaseDuration) || ack.LeaseExpiresAt.IsZero() {
			return fail(ErrUnauthorized)
		}
		if err := s.applyRenewal(sequence, ack.LeaseExpiresAt); err != nil {
			return fail(err)
		}
		return nil
	case <-ctx.Done():
		return fail(ctx.Err())
	case <-s.ctx.Done():
		return ErrClosed
	case <-s.session.done:
		return ErrClosed
	}
}

func (s *Stream) applyRenewal(sequence uint64, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.leaseDeadline()
	if s.closed || s.leaseExpired || !current.After(time.Now()) {
		return ErrExpired
	}
	if s.claims.LeaseExpiresAt.IsZero() || sequence != s.leaseSequence+1 || !expiry.After(current) || !validLease(expiry, earlier(s.request.Deadline, s.claims.Deadline), s.session.config.peerLeaseCeiling()) {
		return ErrUnauthorized
	}
	s.claims.LeaseExpiresAt = expiry
	s.leaseSequence = sequence
	return s.resetLeaseLocked()
}

func (s *Session) renewalReply(msg controlMessage) {
	select {
	case s.controls <- msg:
	case <-s.done:
	default:
		go func() { _ = s.Close() }()
	}
}

func (s *Session) receiveRenewal(msg controlMessage) {
	s.mu.Lock()
	stream := s.streams[msg.FlowID]
	s.mu.Unlock()
	deny := func() {
		s.renewalReply(controlMessage{Type: "renew_ack", FlowID: msg.FlowID, Sequence: msg.Sequence, Error: "denied"})
	}
	if stream == nil {
		deny()
		return
	}
	stream.mu.Lock()
	if stream.closed || stream.leaseExpired || stream.remoteRenewing || msg.Sequence != stream.leaseSequence+1 ||
		stream.claims.LeaseExpiresAt.IsZero() || !stream.leaseDeadline().After(time.Now()) || !msg.LeaseExpiresAt.After(stream.leaseDeadline()) ||
		!validLease(msg.LeaseExpiresAt, earlier(stream.request.Deadline, stream.claims.Deadline), s.config.peerLeaseCeiling()) {
		stream.mu.Unlock()
		deny()
		_ = stream.close(false)
		return
	}
	stream.remoteRenewing = true
	previous := stream.claims
	request := stream.request
	request.Deadline = previous.Deadline
	request.LeaseExpiresAt = msg.LeaseExpiresAt
	deadline := earlier(stream.leaseDeadline(), time.Now().Add(s.config.OpenTimeout))
	stream.mu.Unlock()
	// Keep control CANCEL processing independent of a local policy callback.
	// At most one renewal worker exists per admitted stream.
	go func() {
		ownsMarker := true
		defer func() {
			if ownsMarker {
				stream.mu.Lock()
				stream.remoteRenewing = false
				stream.mu.Unlock()
			}
		}()
		ctx, cancel := context.WithDeadline(stream.ctx, deadline)
		defer cancel()
		claims := previous
		claims.LeaseExpiresAt = msg.LeaseExpiresAt
		var err error
		if s.principal.Role == RoleProvider {
			if s.config.AuthorizeOpen == nil {
				err = ErrUnauthorized
			} else {
				claims, err = s.config.AuthorizeOpen(ctx, s.Principal(), request)
				if claims.FlowID == "" {
					claims.FlowID = request.FlowID
				}
				if claims.LeaseExpiresAt.IsZero() {
					claims.LeaseExpiresAt = request.LeaseExpiresAt
				}
			}
		}
		unchanged := claims.FlowID == previous.FlowID && claims.Purpose == previous.Purpose && claims.Resource == previous.Resource &&
			claims.Destination == previous.Destination && claims.Protocol == previous.Protocol && claims.Revision == previous.Revision && claims.Deadline.Equal(previous.Deadline)
		if err != nil || ctx.Err() != nil || !unchanged || claims.LeaseExpiresAt.After(msg.LeaseExpiresAt) ||
			!validLease(claims.LeaseExpiresAt, claims.Deadline, s.config.peerLeaseCeiling()) || claims.LeaseExpiresAt.IsZero() {
			deny()
			_ = stream.close(false)
			return
		}
		if err := stream.applyRenewal(msg.Sequence, claims.LeaseExpiresAt); err != nil {
			deny()
			_ = stream.close(false)
			return
		}
		// Once ACK is visible, the sender may issue the next sequence. A late
		// defer must not clear that next worker's ownership marker.
		stream.mu.Lock()
		stream.remoteRenewing = false
		stream.mu.Unlock()
		ownsMarker = false
		s.renewalReply(controlMessage{Type: "renew_ack", FlowID: msg.FlowID, Sequence: msg.Sequence, LeaseExpiresAt: claims.LeaseExpiresAt})
	}()
}
