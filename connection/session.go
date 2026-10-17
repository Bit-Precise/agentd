package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

type controlMessage struct {
	Type   string `json:"type"`
	FlowID string `json:"flow_id,omitempty"`
}

type openReply struct {
	Claims *OpenClaims `json:"claims,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// Session owns a yamux session, one reserved control stream, and admitted flows.
// Control cancellation is separate from yamux FIN so half-close stays usable.
type Session struct {
	mux       *yamux.Session
	principal Principal
	config    Config
	server    bool
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	control   *yamux.Stream
	controls  chan controlMessage
	ready     chan *Stream
	slots     chan struct{}
	mu        sync.Mutex
	streams   map[string]*Stream
	used      map[string]struct{}
}

func newSession(ctx context.Context, conn net.Conn, principal Principal, cfg Config, server bool) (*Session, error) {
	ycfg := yamux.DefaultConfig()
	ycfg.AcceptBacklog = cfg.MaxStreams + 1
	ycfg.StreamOpenTimeout = cfg.OpenTimeout
	// yamux Close sends FIN. A slow response after the request half closes
	// must retain its full lease, not inherit the short OPEN handshake timeout.
	ycfg.StreamCloseTimeout = cfg.SessionTTL
	ycfg.ConnectionWriteTimeout = cfg.OpenTimeout
	ycfg.LogOutput = io.Discard // The caller owns structured, credential-safe logs.
	var mux *yamux.Session
	var err error
	if server {
		mux, err = yamux.Server(conn, ycfg)
	} else {
		mux, err = yamux.Client(conn, ycfg)
	}
	if err != nil {
		return nil, fmt.Errorf("start multiplexer: %w", err)
	}
	sctx, cancel := context.WithCancel(ctx)
	s := &Session{mux: mux, principal: principal, config: cfg, server: server,
		ctx: sctx, cancel: cancel, done: make(chan struct{}), controls: make(chan controlMessage, cfg.MaxStreams),
		ready: make(chan *Stream, cfg.MaxStreams), slots: make(chan struct{}, cfg.MaxStreams),
		streams: make(map[string]*Stream), used: make(map[string]struct{})}
	// Only the dialer creates this reserved stream, before either API returns.
	if server {
		s.control, err = mux.AcceptStreamWithContext(sctx)
	} else {
		s.control, err = mux.OpenStream()
	}
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("open control stream: %w", err)
	}
	deadline := earlier(time.Now().Add(cfg.OpenTimeout), principal.ExpiresAt)
	if err = s.control.SetDeadline(deadline); err != nil {
		_ = s.Close()
		return nil, err
	}
	if server {
		var msg controlMessage
		err = readFrame(s.control, &msg, cfg.MaxMetadataBytes)
		if err == nil && (msg.Type != "control" || msg.FlowID != "") {
			err = ErrProtocol
		}
		if err == nil {
			err = writeFrame(s.control, controlMessage{Type: "ready"}, cfg.MaxMetadataBytes)
		}
	} else {
		err = writeFrame(s.control, controlMessage{Type: "control"}, cfg.MaxMetadataBytes)
		var msg controlMessage
		if err == nil {
			err = readFrame(s.control, &msg, cfg.MaxMetadataBytes)
		}
		if err == nil && (msg.Type != "ready" || msg.FlowID != "") {
			err = ErrProtocol
		}
	}
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("control handshake: %w", err)
	}
	if err = s.control.SetDeadline(time.Time{}); err != nil {
		_ = s.Close()
		return nil, err
	}
	go s.watch()
	go s.readControls()
	go s.writeControls()
	go s.acceptStreams()
	return s, nil
}

func (s *Session) Principal() Principal  { return clonePrincipal(s.principal) }
func (s *Session) Done() <-chan struct{} { return s.done }

// Close terminates the transport and every logical stream, including blocked IO.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.cancel()
		_ = s.mux.Close()
		s.mu.Lock()
		streams := make([]*Stream, 0, len(s.streams))
		for _, stream := range s.streams {
			streams = append(streams, stream)
		}
		s.mu.Unlock()
		for _, stream := range streams {
			_ = stream.close(false)
		}
	})
	return nil
}

func (s *Session) watch() {
	timer := time.NewTimer(time.Until(s.principal.ExpiresAt))
	defer timer.Stop()
	select {
	case <-s.ctx.Done():
	case <-s.mux.CloseChan():
	case <-timer.C:
	}
	_ = s.Close()
}

func (s *Session) readControls() {
	defer func() { _ = s.Close() }()
	for {
		var msg controlMessage
		if err := readFrame(s.control, &msg, s.config.MaxMetadataBytes); err != nil {
			return
		}
		if msg.Type != "cancel" || !boundedName(msg.FlowID) {
			return
		}
		s.mu.Lock()
		stream := s.streams[msg.FlowID]
		// A cancel can race an OPEN on a different mux stream. Remember it so
		// the delayed OPEN cannot resurrect a flow the sender has cancelled.
		_, seen := s.used[msg.FlowID]
		if !seen && len(s.used) >= s.config.MaxFlows {
			s.mu.Unlock()
			return
		}
		s.used[msg.FlowID] = struct{}{}
		s.mu.Unlock()
		if stream != nil {
			_ = stream.close(false)
		}
	}
}

func (s *Session) writeControls() {
	for {
		select {
		case <-s.done:
			return
		case msg := <-s.controls:
			if err := s.control.SetWriteDeadline(time.Now().Add(s.config.OpenTimeout)); err != nil {
				_ = s.Close()
				return
			}
			if err := writeFrame(s.control, msg, s.config.MaxMetadataBytes); err != nil {
				_ = s.Close()
				return
			}
		}
	}
}

func (s *Session) sendCancel(flowID string) {
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.controls <- controlMessage{Type: "cancel", FlowID: flowID}:
	case <-s.done:
	default:
		// Losing cancellation under overload would violate the expiry bound.
		go func() { _ = s.Close() }()
	}
}

func (s *Session) allowedPurpose(purpose Purpose, outgoing bool) bool {
	if s.principal.Role == RoleAccess {
		return outgoing != s.server && purpose == PurposeAccess
	}
	return outgoing == s.server && (purpose == PurposeServe || purpose == PurposeEgress)
}

func (s *Session) takeSlot() error {
	select {
	case <-s.done:
		return ErrClosed
	default:
	}
	// Include half-closed yamux streams until their FIN handshake completes.
	if s.mux.NumStreams() >= s.config.MaxStreams+1 {
		return ErrStreamLimit
	}
	select {
	case s.slots <- struct{}{}:
		return nil
	default:
		return ErrStreamLimit
	}
}

func (s *Session) register(stream *Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return ErrClosed
	default:
	}
	if _, exists := s.used[stream.request.FlowID]; exists {
		return ErrDuplicateFlow
	}
	if len(s.used) >= s.config.MaxFlows {
		return ErrStreamLimit
	}
	s.used[stream.request.FlowID] = struct{}{}
	s.streams[stream.request.FlowID] = stream
	return nil
}

func (s *Session) release(stream *Stream) {
	s.mu.Lock()
	if s.streams[stream.request.FlowID] == stream {
		delete(s.streams, stream.request.FlowID)
	}
	s.mu.Unlock()
	<-s.slots
}

// Open waits for receiver authorization. OPEN_OK means logical admission only;
// the application still owns target dialing and any protocol-specific response.
// ctx only governs opening, like net.Dialer. After success, Request.Deadline,
// session expiry, Close, or a peer CANCEL owns the stream's lifetime.
func (s *Session) Open(ctx context.Context, request OpenRequest) (*Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.allowedPurpose(request.Purpose, true) {
		return nil, ErrRole
	}
	if request.FlowID == "" {
		id, err := randomID()
		if err != nil {
			return nil, err
		}
		request.FlowID = id
	}
	request.Deadline = earlier(request.Deadline, s.principal.ExpiresAt)
	if request.Protocol == "" {
		if request.Purpose == PurposeServe {
			request.Protocol = "http"
		} else {
			request.Protocol = "tls"
		}
	}
	if err := validateOpen(request); err != nil {
		return nil, err
	}
	if err := s.takeSlot(); err != nil {
		return nil, err
	}
	// yamux OpenStream has no context API. A bounded helper lets callers cancel
	// without closing sibling flows. The mux write/open timeout bounds cleanup.
	type result struct {
		raw *yamux.Stream
		err error
	}
	resultCh := make(chan result)
	go func() {
		raw, err := s.mux.OpenStream()
		select {
		case resultCh <- result{raw, err}:
		case <-ctx.Done():
			if raw != nil {
				_ = raw.Close()
			}
			<-s.slots
		case <-s.done:
			if raw != nil {
				_ = raw.Close()
			}
			<-s.slots
		}
	}()
	var raw *yamux.Stream
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, ErrClosed
	case result := <-resultCh:
		if result.err != nil {
			<-s.slots
			return nil, fmt.Errorf("open mux stream: %w", result.err)
		}
		raw = result.raw
	}
	stream := newStream(s, raw, request)
	if err := s.register(stream); err != nil {
		_ = stream.close(false)
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stop()
	deadline := earlier(time.Now().Add(s.config.OpenTimeout), request.Deadline)
	if ctxDeadline, ok := ctx.Deadline(); ok {
		deadline = earlier(deadline, ctxDeadline)
	}
	if err := raw.SetDeadline(deadline); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if err := writeFrame(raw, request, s.config.MaxMetadataBytes); err != nil {
		_ = stream.Close()
		return nil, err
	}
	var reply openReply
	if err := readFrame(raw, &reply, s.config.MaxMetadataBytes); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if reply.Error != "" || reply.Claims == nil {
		_ = stream.Close()
		return nil, ErrUnauthorized
	}
	if err := validateClaims(request, *reply.Claims, s.principal.ExpiresAt); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if err := stream.activate(*reply.Claims); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

// Accept only returns streams approved by AuthorizeOpen. Malformed or denied
// OPENs are rejected to the peer and never reach application handlers.
func (s *Session) Accept(ctx context.Context) (*Stream, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, ErrClosed
		case stream := <-s.ready:
			if stream.ctx.Err() == nil {
				return stream, nil
			}
		}
	}
}

func (s *Session) acceptStreams() {
	for {
		raw, err := s.mux.AcceptStreamWithContext(s.ctx)
		if err != nil {
			_ = s.Close()
			return
		}
		if s.mux.NumStreams() > s.config.MaxStreams+1 {
			_ = raw.Close()
			_ = s.Close()
			return
		}
		// raw is already present in NumStreams. Reserve the local admission
		// slot separately so exactly MaxStreams business streams are allowed.
		select {
		case s.slots <- struct{}{}:
			go s.admit(raw)
		default:
			_ = raw.Close()
		}
	}
}

func (s *Session) admit(raw *yamux.Stream) {
	if err := raw.SetDeadline(earlier(time.Now().Add(s.config.OpenTimeout), s.principal.ExpiresAt)); err != nil {
		_ = raw.Close()
		<-s.slots
		return
	}
	var request OpenRequest
	if err := readFrame(raw, &request, s.config.MaxMetadataBytes); err != nil {
		_ = raw.Close()
		<-s.slots
		return
	}
	if err := validateOpen(request); err != nil || !s.allowedPurpose(request.Purpose, false) || s.config.AuthorizeOpen == nil {
		_ = writeFrame(raw, openReply{Error: "denied"}, s.config.MaxMetadataBytes)
		_ = raw.Close()
		<-s.slots
		return
	}
	stream := newStream(s, raw, request)
	if err := s.register(stream); err != nil {
		_ = writeFrame(raw, openReply{Error: "denied"}, s.config.MaxMetadataBytes)
		_ = stream.close(false)
		return
	}
	ctx, cancel := context.WithDeadline(stream.ctx, earlier(time.Now().Add(s.config.OpenTimeout), request.Deadline))
	defer cancel()
	claims, err := s.config.AuthorizeOpen(ctx, s.Principal(), request)
	if claims.FlowID == "" {
		claims.FlowID = request.FlowID
	}
	if claims.Deadline.IsZero() {
		claims.Deadline = request.Deadline
	}
	claims.Deadline = earlier(claims.Deadline, s.principal.ExpiresAt)
	if err != nil || ctx.Err() != nil || validateClaims(request, claims, s.principal.ExpiresAt) != nil {
		_ = writeFrame(raw, openReply{Error: "denied"}, s.config.MaxMetadataBytes)
		_ = stream.close(false)
		return
	}
	if err = writeFrame(raw, openReply{Claims: &claims}, s.config.MaxMetadataBytes); err != nil {
		_ = stream.Close()
		return
	}
	if err = stream.activate(claims); err != nil {
		_ = stream.Close()
		return
	}
	select {
	case s.ready <- stream:
	case <-stream.ctx.Done():
		_ = stream.Close()
	}
}

func validateOpen(r OpenRequest) error {
	if !boundedName(r.FlowID) || r.Deadline.IsZero() {
		return ErrProtocol
	}
	if !r.Deadline.After(time.Now()) {
		return ErrExpired
	}
	switch r.Purpose {
	case PurposeServe:
		if !boundedName(r.Resource) || r.Destination.Host != "" || r.Destination.Port != 0 || r.Protocol != "http" {
			return ErrProtocol
		}
	case PurposeAccess, PurposeEgress:
		if !boundedName(r.Destination.Host) || r.Destination.Port == 0 || r.Protocol != "tls" {
			return ErrProtocol
		}
		if r.Purpose == PurposeEgress && !boundedName(r.Resource) {
			return ErrProtocol
		}
	default:
		return ErrRole
	}
	return nil
}

func validateClaims(r OpenRequest, c OpenClaims, sessionExpiry time.Time) error {
	if c.FlowID != r.FlowID || c.Purpose != r.Purpose || c.Protocol != r.Protocol {
		return ErrUnauthorized
	}
	if c.Deadline.IsZero() || c.Deadline.After(r.Deadline) || c.Deadline.After(sessionExpiry) {
		return ErrUnauthorized
	}
	if !c.Deadline.After(time.Now()) {
		return ErrExpired
	}
	if r.Purpose != PurposeAccess && (c.Resource != r.Resource || c.Revision != r.Revision) {
		return ErrUnauthorized
	}
	approved := OpenRequest{FlowID: c.FlowID, Purpose: c.Purpose, Resource: c.Resource, Destination: c.Destination, Protocol: c.Protocol, Revision: c.Revision, Deadline: c.Deadline}
	if err := validateOpen(approved); err != nil {
		return errors.Join(ErrUnauthorized, err)
	}
	return nil
}
