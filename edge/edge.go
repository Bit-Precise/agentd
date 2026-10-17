// Package edge owns authenticated agent sessions and per-resource business
// flows. The control Backend remains authoritative for all identity and policy.
package edge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/transport/xhttp"
)

type Backend interface {
	Identity(token string) (types.Identity, error)
	Agent(agentID string) (types.Agent, error)
	ResolveServe(host, userID string) (types.Decision, error)
	ResolveEgress(workspace, userID, host string, port int) (types.Decision, error)
	Subscribe() (<-chan struct{}, func())
}

type Config struct {
	SessionTTL time.Duration
	FlowTTL    time.Duration
	// MaxFlowLifetime is the immutable hard deadline, independent of short
	// policy leases. SessionTTL is also a hard maximum, not a policy cache TTL.
	MaxFlowLifetime   time.Duration
	MaxFlows          int
	AllowLoopbackHTTP bool
	// RecheckInterval bounds expiry/revocation when notifications are coalesced.
	RecheckInterval time.Duration
}

var (
	ErrDenied      = errors.New("edge authorization denied")
	ErrUnavailable = errors.New("approved provider unavailable")
	ErrClosed      = errors.New("edge closed")
)

type provider struct {
	raw        net.Conn
	session    *connection.Session
	identity   types.Identity
	token      string
	connector  string
	generation uint64
	revision   uint64
	services   map[string]bool
	egress     bool
	created    time.Time
}

type Edge struct {
	backend     Backend
	cfg         Config
	transport   *xhttp.Handler
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	started     bool
	closed      bool
	providers   map[string]*provider
	connections map[*provider]struct{}
	generation  map[string]uint64
	flows       map[string]*flow
	wg          sync.WaitGroup
	closeOnce   sync.Once
}

func New(backend Backend, cfg Config) (*Edge, error) {
	if backend == nil {
		return nil, errors.New("edge requires a control backend")
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 24 * time.Hour
	}
	if cfg.FlowTTL == 0 {
		cfg.FlowTTL = 55 * time.Second
	}
	if cfg.MaxFlowLifetime == 0 {
		cfg.MaxFlowLifetime = 12 * time.Hour
	}
	if cfg.MaxFlows == 0 {
		cfg.MaxFlows = 1024
	}
	if cfg.RecheckInterval == 0 {
		cfg.RecheckInterval = time.Second
	}
	if cfg.SessionTTL < 0 || cfg.SessionTTL > 24*time.Hour || cfg.FlowTTL < 10*time.Millisecond || cfg.FlowTTL > time.Minute ||
		cfg.MaxFlowLifetime <= 0 || cfg.MaxFlowLifetime > 24*time.Hour || cfg.MaxFlows < 1 || cfg.MaxFlows > 65536 || cfg.RecheckInterval < 0 {
		return nil, errors.New("invalid edge limits")
	}
	if cfg.RecheckInterval > cfg.FlowTTL/4 {
		cfg.RecheckInterval = cfg.FlowTTL / 4
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Edge{backend: backend, cfg: cfg, ctx: ctx, cancel: cancel,
		providers: make(map[string]*provider), connections: make(map[*provider]struct{}),
		generation: make(map[string]uint64), flows: make(map[string]*flow)}
	h, err := xhttp.NewHandler(xhttp.ServerConfig{Authorize: e.authorizeHTTP, AllowHTTP: cfg.AllowLoopbackHTTP})
	if err != nil {
		cancel()
		return nil, err
	}
	e.transport = h
	return e, nil
}

// Handler is only the authenticated XHTTP endpoint, never a browser login route.
func (e *Edge) Handler() http.Handler { return e.transport }

// Run must be called once. Parent cancellation closes sessions and all flows.
func (e *Edge) Run(ctx context.Context) error {
	e.mu.Lock()
	if e.started || e.closed {
		e.mu.Unlock()
		return ErrClosed
	}
	e.started = true
	e.wg.Add(1)
	e.mu.Unlock()
	events, unsubscribe := e.backend.Subscribe()
	defer unsubscribe()
	acceptError := make(chan error, 1)
	go func() { defer e.wg.Done(); acceptError <- e.acceptLoop() }()
	ticker := time.NewTicker(e.cfg.RecheckInterval)
	defer ticker.Stop()
	var result error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-e.ctx.Done():
			break loop
		case err := <-acceptError:
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrClosed) {
				result = err
			}
			break loop
		case _, ok := <-events:
			if !ok {
				events = nil
			} else {
				e.reconcile()
			}
		case <-ticker.C:
			e.reconcile()
		}
	}
	e.close()
	e.wg.Wait()
	return result
}

func (e *Edge) acceptLoop() error {
	for {
		raw, err := e.transport.Accept(e.ctx)
		if err != nil {
			return err
		}
		p := &provider{raw: raw, created: time.Now()}
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			raw.Close()
			return ErrClosed
		}
		e.connections[p] = struct{}{}
		e.wg.Add(1)
		e.mu.Unlock()
		go func() { defer e.wg.Done(); e.accept(p) }()
	}
}

func (e *Edge) closeProvider(p *provider) {
	e.mu.Lock()
	session := p.session
	e.mu.Unlock()
	if session != nil {
		_ = session.Close()
	}
	_ = p.raw.Close()
}

func (e *Edge) removeProvider(p *provider) {
	e.mu.Lock()
	delete(e.connections, p)
	if e.providers[p.identity.AgentID] == p {
		delete(e.providers, p.identity.AgentID)
	}
	e.mu.Unlock()
}

func (e *Edge) close() {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		all := make([]*provider, 0, len(e.connections))
		for p := range e.connections {
			all = append(all, p)
		}
		flows := make([]*flow, 0, len(e.flows))
		for _, f := range e.flows {
			flows = append(flows, f)
		}
		e.mu.Unlock()
		e.cancel()
		_ = e.transport.Close()
		for _, f := range flows {
			f.cancel()
		}
		for _, p := range all {
			e.closeProvider(p)
		}
	})
}

func (e *Edge) Shutdown(ctx context.Context) error {
	e.close()
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type ConnectionStatus struct {
	ID            string    `json:"id"`
	WorkspaceID   string    `json:"workspaceId"`
	AgentID       string    `json:"agentId"`
	Workspace     string    `json:"workspace"`
	Role          string    `json:"role"`
	ConnectorID   string    `json:"connectorId,omitempty"`
	SessionID     string    `json:"sessionId"`
	Generation    uint64    `json:"generation"`
	Revision      uint64    `json:"revision"`
	Services      []string  `json:"services,omitempty"`
	EgressEnabled bool      `json:"egressEnabled"`
	ConnectedAt   time.Time `json:"connectedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
}
type FlowStatus struct {
	ID           string                 `json:"id"`
	Purpose      string                 `json:"purpose"`
	ResourceID   string                 `json:"resourceId"`
	WorkspaceID  string                 `json:"workspaceId"`
	Workspace    string                 `json:"workspace"`
	UserID       string                 `json:"userId,omitempty"`
	AgentID      string                 `json:"agentId"`
	State        string                 `json:"state"`
	Deadline     time.Time              `json:"deadline"`
	Destination  connection.Destination `json:"destination"`
	StartedAt    time.Time              `json:"startedAt"`
	ExpiresAt    time.Time              `json:"expiresAt"`
	HardDeadline time.Time              `json:"hardDeadline"`
}
type Snapshot struct {
	Connections []ConnectionStatus `json:"connections"`
	Flows       []FlowStatus       `json:"flows"`
}

func (e *Edge) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := Snapshot{Connections: []ConnectionStatus{}, Flows: []FlowStatus{}}
	for p := range e.connections {
		if p.session == nil {
			continue
		}
		v := p.session.Principal()
		services := make([]string, 0, len(p.services))
		for name := range p.services {
			services = append(services, name)
		}
		sort.Strings(services)
		out.Connections = append(out.Connections, ConnectionStatus{ID: v.SessionID, WorkspaceID: p.identity.WorkspaceID, AgentID: v.AgentID, Workspace: v.Workspace, Role: string(v.Role), ConnectorID: v.ConnectorID,
			SessionID: v.SessionID, Generation: v.Generation, Revision: p.revision, Services: services, EgressEnabled: p.egress, ConnectedAt: p.created, ExpiresAt: v.ExpiresAt})
	}
	for _, f := range e.flows {
		out.Flows = append(out.Flows, FlowStatus{ID: f.id, Purpose: string(f.purpose), ResourceID: f.decision.ResourceID,
			WorkspaceID: f.decision.WorkspaceID, Workspace: f.decision.Workspace, UserID: f.userID, AgentID: f.decision.AgentID, State: f.state, Deadline: f.deadline,
			Destination: f.decision.Destination, StartedAt: f.started, ExpiresAt: f.deadline, HardDeadline: f.hardDeadline})
	}
	sort.Slice(out.Connections, func(i, j int) bool { return out.Connections[i].SessionID < out.Connections[j].SessionID })
	sort.Slice(out.Flows, func(i, j int) bool { return out.Flows[i].ID < out.Flows[j].ID })
	return out
}
