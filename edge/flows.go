package edge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
	"time"

	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/policygate"
	"github.com/bit-precise/agentd/stream"
)

type flow struct {
	id             string
	purpose        connection.Purpose
	decision       types.Decision
	provider       *provider
	userID         string
	host           string
	state          string // guarded by Edge.mu
	started        time.Time
	deadline       time.Time
	hardDeadline   time.Time
	renewAt        time.Time
	leaseEpoch     uint64
	leaseExpired   bool
	leaseTimer     *time.Timer
	renewing       bool
	upstream       *connection.Stream
	accessStream   *connection.Stream
	accessIdentity *provider
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	closers        []io.Closer
	closed         bool
	resourcesDone  chan struct{}
}

func validDecision(d types.Decision, purpose connection.Purpose) bool {
	if d.ResourceID == "" || d.WorkspaceID == "" || d.Workspace == "" || d.AgentID == "" || d.Revision == 0 || !d.ExpiresAt.After(time.Now()) {
		return false
	}
	if purpose == connection.PurposeServe {
		return d.ResourceType == "service" && d.ServiceName != "" && d.Hostname != ""
	}
	return d.ResourceType == "egress" && d.Destination.Host != "" && d.Destination.Port != 0
}

func (f *flow) attach(c io.Closer) bool {
	if c == nil {
		return true
	}
	f.mu.Lock()
	if f.closed || f.ctx.Err() != nil {
		f.mu.Unlock()
		c.Close()
		return false
	}
	f.closers = append(f.closers, c)
	f.mu.Unlock()
	return true
}
func (f *flow) closeResources() {
	f.mu.Lock()
	if f.closed {
		done := f.resourcesDone
		f.mu.Unlock()
		<-done
		return
	}
	f.closed = true
	all := f.closers
	f.closers = nil
	f.mu.Unlock()
	for _, c := range all {
		_ = c.Close()
	}
	close(f.resourcesDone)
}

func (e *Edge) beginFlow(parent context.Context, d types.Decision, purpose connection.Purpose, userID, host string, source io.Closer, access *provider) (*flow, func(), error) {
	if !validDecision(d, purpose) {
		return nil, nil, ErrDenied
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, nil, err
	}
	e.mu.Lock()
	p := e.providers[d.AgentID]
	if e.closed || len(e.flows) >= e.cfg.MaxFlows {
		e.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	if p == nil || p.session == nil || p.identity.WorkspaceID != d.WorkspaceID || p.revision != d.Revision ||
		(purpose == connection.PurposeServe && !p.services[d.ServiceName]) || (purpose == connection.PurposeEgress && !p.egress) {
		e.mu.Unlock()
		return nil, nil, ErrUnavailable
	}
	select {
	case <-p.session.Done():
		e.mu.Unlock()
		return nil, nil, ErrUnavailable
	default:
	}
	hard := minExpiry(p.session.Principal().ExpiresAt, time.Now().Add(e.cfg.MaxFlowLifetime))
	if parentDeadline, ok := parent.Deadline(); ok {
		hard = minExpiry(hard, parentDeadline)
	}
	accessStream, _ := source.(*connection.Stream)
	lease := minExpiry(hard, d.ExpiresAt, time.Now().Add(e.cfg.FlowTTL))
	if accessStream != nil {
		claims := accessStream.Claims()
		hard = minExpiry(hard, claims.Deadline)
		lease = minExpiry(lease, hard, claims.LeaseExpiresAt)
	}
	ctx, cancel := context.WithDeadline(parent, hard)
	f := &flow{id: hex.EncodeToString(id[:]), purpose: purpose, decision: d, provider: p, userID: userID, host: host, state: "pending", started: time.Now(), hardDeadline: hard, ctx: ctx, cancel: cancel, resourcesDone: make(chan struct{}), accessStream: accessStream, accessIdentity: access}
	e.flows[f.id] = f
	e.armLeaseLocked(f, lease)
	e.wg.Add(1)
	e.mu.Unlock()
	f.attach(source)
	stopClose := context.AfterFunc(ctx, f.closeResources)
	stopEdge := context.AfterFunc(e.ctx, cancel)
	// A broken provider transport must also interrupt a downstream HTTP write;
	// normal per-request HTTP transport closure must not truncate buffered bytes.
	go func() {
		select {
		case <-p.session.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	var once sync.Once
	finish := func() {
		once.Do(func() {
			cancel()
			stopEdge()
			stopClose()
			f.closeResources()
			e.mu.Lock()
			delete(e.flows, f.id)
			if f.leaseTimer != nil {
				f.leaseTimer.Stop()
			}
			e.mu.Unlock()
			e.wg.Done()
		})
	}
	// Registration precedes the second control-plane check. An event racing the
	// first decision either sees this pending flow, or this check sees its change.
	if !e.recheckFlow(f) {
		finish()
		return nil, nil, ErrDenied
	}
	return f, finish, nil
}

// armLeaseLocked keeps the Edge watchdog independent of subscription/polling
// workers. Late timer callbacks cannot expire a successfully renewed lease.
func (e *Edge) armLeaseLocked(f *flow, expiry time.Time) {
	f.deadline = expiry
	f.renewAt = time.Now().Add(time.Until(expiry) / 2)
	f.leaseEpoch++
	epoch := f.leaseEpoch
	if f.leaseTimer != nil {
		f.leaseTimer.Stop()
	}
	f.leaseTimer = time.AfterFunc(time.Until(expiry), func() {
		e.mu.Lock()
		if e.flows[f.id] != f || f.leaseEpoch != epoch || time.Now().Before(f.deadline) {
			e.mu.Unlock()
			return
		}
		f.leaseExpired = true
		e.mu.Unlock()
		f.cancel()
	})
}

func sameDecision(old, next types.Decision, deadline time.Time) bool {
	return old.ResourceType == next.ResourceType && old.ResourceID == next.ResourceID && old.WorkspaceID == next.WorkspaceID && old.Workspace == next.Workspace &&
		old.AgentID == next.AgentID && old.ServiceName == next.ServiceName && old.Hostname == next.Hostname && old.UserID == next.UserID &&
		old.Destination == next.Destination && old.Revision == next.Revision && !next.ExpiresAt.Before(deadline)
}

func (e *Edge) authorizedFlow(f *flow) (types.Decision, bool) {
	if f.ctx.Err() != nil {
		return types.Decision{}, false
	}
	var d types.Decision
	var err error
	if f.purpose == connection.PurposeServe {
		d, err = e.backend.ResolveServe(f.host, f.userID)
	} else {
		d, err = e.backend.ResolveEgress(f.decision.Workspace, f.userID, f.decision.Destination.Host, int(f.decision.Destination.Port))
	}
	if err != nil || !validDecision(d, f.purpose) || !e.currentIdentity(f.provider) || (f.accessIdentity != nil && !e.currentIdentity(f.accessIdentity)) {
		return types.Decision{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return d, !e.closed && !f.leaseExpired && f.ctx.Err() == nil && f.deadline.After(time.Now()) && sameDecision(f.decision, d, f.deadline) && e.providers[f.decision.AgentID] == f.provider && f.provider.revision == d.Revision &&
		(f.purpose != connection.PurposeServe || f.provider.services[d.ServiceName]) && (f.purpose != connection.PurposeEgress || f.provider.egress)
}

func (e *Edge) recheckFlow(f *flow) bool { _, ok := e.authorizedFlow(f); return ok }

func (e *Edge) openProvider(f *flow) (*connection.Stream, error) {
	if !e.recheckFlow(f) {
		return nil, ErrDenied
	}
	e.mu.Lock()
	r := connection.OpenRequest{FlowID: f.id, Purpose: f.purpose, Revision: f.decision.Revision, Deadline: f.hardDeadline, LeaseExpiresAt: f.deadline}
	e.mu.Unlock()
	if f.purpose == connection.PurposeServe {
		r.Resource = f.decision.ServiceName
		r.Protocol = "http"
	} else {
		r.Resource = f.decision.ResourceID
		r.Protocol = "tls"
		r.Destination = f.decision.Destination
	}
	s, err := f.provider.session.Open(f.ctx, r)
	if err != nil {
		return nil, err
	}
	if !f.attach(s) || !e.recheckFlow(f) {
		s.Close()
		return nil, ErrDenied
	}
	e.mu.Lock()
	f.upstream = s
	f.hardDeadline = minExpiry(f.hardDeadline, s.Claims().Deadline)
	actual := minExpiry(f.deadline, s.Claims().LeaseExpiresAt, f.hardDeadline)
	if actual.Before(f.deadline) {
		e.armLeaseLocked(f, actual)
	}
	f.state = "active"
	e.mu.Unlock()
	return s, nil
}

func (e *Edge) handleAccess(access *provider, incoming *connection.Stream) {
	claims := incoming.Claims()
	d, err := e.backend.ResolveEgress(access.identity.Workspace, access.identity.UserID, claims.Destination.Host, int(claims.Destination.Port))
	if err != nil || d.ResourceID != claims.Resource || d.Revision != claims.Revision || d.Destination != claims.Destination || !e.currentIdentity(access) {
		return
	}
	d.ExpiresAt = minExpiry(d.ExpiresAt, claims.Deadline)
	f, finish, err := e.beginFlow(incoming.Context(), d, connection.PurposeEgress, access.identity.UserID, "", incoming, access)
	if err != nil {
		return
	}
	defer finish()
	preface, err := policygate.Inspect(f.ctx, incoming, claims.Destination.Host)
	if err != nil {
		return
	}
	out, err := e.openProvider(f)
	if err != nil {
		return
	}
	if _, err = out.Write(preface); err != nil {
		return
	}
	stream.Pipe(f.ctx, incoming, out)
}

func (e *Edge) reconcile() {
	e.mu.Lock()
	connections := make([]*provider, 0, len(e.connections))
	for p := range e.connections {
		if p.token != "" {
			connections = append(connections, p)
		}
	}
	flows := make([]*flow, 0, len(e.flows))
	for _, f := range e.flows {
		flows = append(flows, f)
	}
	e.mu.Unlock()
	for _, p := range connections {
		if !e.currentIdentity(p) {
			e.closeProvider(p)
		}
	}
	for _, f := range flows {
		d, ok := e.authorizedFlow(f)
		if !ok {
			f.cancel()
			continue
		}
		e.mu.Lock()
		expiry := minExpiry(d.ExpiresAt, f.hardDeadline, time.Now().Add(e.cfg.FlowTTL))
		if !e.closed && e.flows[f.id] == f && !f.renewing && f.state == "active" && f.upstream != nil && !time.Now().Before(f.renewAt) && expiry.After(f.deadline) {
			f.renewing = true
			e.wg.Add(1)
			e.mu.Unlock()
			go func() { defer e.wg.Done(); e.renewFlow(f) }()
		} else {
			e.mu.Unlock()
		}
	}
}

func (e *Edge) renewFlow(f *flow) {
	defer func() { e.mu.Lock(); f.renewing = false; e.mu.Unlock() }()
	d, ok := e.authorizedFlow(f)
	if !ok {
		f.cancel()
		return
	}
	e.mu.Lock()
	out, in := f.upstream, f.accessStream
	expiry := minExpiry(d.ExpiresAt, f.hardDeadline, time.Now().Add(e.cfg.FlowTTL), out.Claims().Deadline)
	if in != nil {
		expiry = minExpiry(expiry, in.Claims().Deadline)
	}
	old := f.deadline
	e.mu.Unlock()
	if !expiry.After(old) {
		return
	}
	ctx, cancel := context.WithDeadline(f.ctx, old)
	defer cancel()
	if err := out.RenewLease(ctx, expiry); err != nil {
		f.cancel()
		return
	}
	expiry = minExpiry(expiry, out.Claims().LeaseExpiresAt)
	if in != nil {
		if err := in.RenewLease(ctx, expiry); err != nil {
			f.cancel()
			return
		}
		expiry = minExpiry(expiry, in.Claims().LeaseExpiresAt)
	}
	// Never commit after a racing revocation, expiry, new provider generation,
	// or route change, even when both transport ACKs happened to arrive.
	d, ok = e.authorizedFlow(f)
	if !ok || d.ExpiresAt.Before(expiry) {
		f.cancel()
		return
	}
	e.mu.Lock()
	if e.closed || e.flows[f.id] != f || f.ctx.Err() != nil || f.leaseExpired || !f.deadline.After(time.Now()) {
		e.mu.Unlock()
		f.cancel()
		return
	}
	e.armLeaseLocked(f, expiry)
	e.mu.Unlock()
}
