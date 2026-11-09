package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"agentd/internal/identity"
	"agentd/internal/session"
	"agentd/internal/task"
	"agentd/internal/tlsutil"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// Version is the agentd build version (set with -ldflags).
var Version = "dev"

// Options adjust an Agent for embedding (tests, sim).
type Options struct {
	Logger  *slog.Logger
	RootCAs *x509.CertPool                                                    // instead of system roots + AGENTD_EXTRA_ROOTS
	NetDial func(ctx context.Context, network, addr string) (net.Conn, error) // relay and direct dials
	// NoLocalAPI skips the unix socket (tests that run several agents).
	NoLocalAPI bool
}

// Agent is a running agentd instance.
type Agent struct {
	cfg   atomic.Pointer[Config]
	dir   string
	key   ed25519.PrivateKey
	pub   []byte
	wsKey []byte
	opts  Options
	log   *slog.Logger
	dlog  *slog.Logger // decision log
	files []io.Closer

	state  *State
	nonces *wire.NonceCache
	tasks  *task.Handler

	smu      sync.Mutex
	sess     *activeSession
	sessCond chan struct{} // closed and replaced whenever sess changes
	status   sessionStatus

	stopped  atomic.Bool // removed from the workspace
	stopOnce sync.Once
	stopCh   chan struct{}
	cancel   context.CancelFunc

	ingressLn []net.Listener
	mcpLn     net.Listener
	apiLn     net.Listener
	mcp       *mcpServer
	proxies   map[string]*serviceProxy

	// tunDial replaces the dialer while TUN mode is on: agentd's own sockets
	// must bypass the TUN.
	tunDial atomic.Pointer[dialFunc]
	tunInfo atomic.Pointer[func() map[string]any]
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// netDial is the dialer for relay transports and direct connections.
func (a *Agent) netDial() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if d := a.tunDial.Load(); d != nil {
		return *d
	}
	return a.opts.NetDial
}

type sessionStatus struct {
	State      string    `json:"state"`
	Relay      string    `json:"relay"`
	RelayURL   string    `json:"relay_url"`
	Since      time.Time `json:"since"`
	LastError  string    `json:"last_error,omitempty"`
	Transport  string    `json:"transport"`
	ClockSkew  string    `json:"clock_skew,omitempty"`
	Reconnects int       `json:"reconnects"`
}

// activeSession is one Ready session to a relay.
type activeSession struct {
	mux      *session.Mux
	relayKey []byte
	name     string
	ws       string
	send     func(*pb.ControlMessage) error
	done     chan struct{}
}

// New loads an instance (config, key) without starting it.
func New(dir string, opts Options) (*Agent, error) {
	cfg, err := LoadConfig(dir)
	if err != nil {
		return nil, err
	}
	key, _, err := identity.LoadOrCreateKey(KeyPath(dir))
	if err != nil {
		return nil, err
	}
	if opts.RootCAs == nil {
		if opts.RootCAs, err = tlsutil.RootsWithExtra("AGENTD_EXTRA_ROOTS"); err != nil {
			return nil, err
		}
	}
	a := &Agent{dir: dir, key: key, pub: identity.Public(key), wsKey: cfg.WorkspaceKey(), opts: opts, state: newState(),
		nonces: wire.NewNonceCache(wire.NonceCacheTTL, 200000), sessCond: make(chan struct{}), stopCh: make(chan struct{})}
	a.cfg.Store(cfg)
	if err := a.setupLogs(cfg); err != nil {
		return nil, err
	}
	a.state.load(StatePath(dir), a.wsKey, cfg.Workspace.Domain)
	if cfg.Roles.Executor.Enabled {
		a.tasks = a.newTaskHandler(cfg)
	}
	return a, nil
}

func (a *Agent) config() *Config { return a.cfg.Load() }

// PublicKey is the node's public key.
func (a *Agent) PublicKey() []byte { return a.pub }

func (a *Agent) setupLogs(cfg *Config) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.Log.Level)); err != nil {
		return err
	}
	if a.opts.Logger != nil {
		a.log = a.opts.Logger
	} else {
		var w io.Writer = os.Stderr
		path := "logs/agentd.log"
		if cfg.Log.Path != nil {
			path = *cfg.Log.Path
		}
		if path != "" {
			f, err := openLog(cfg.Path(path))
			if err != nil {
				return err
			}
			a.files = append(a.files, f)
			w = io.MultiWriter(os.Stderr, f)
		}
		a.log = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
	}
	a.dlog = slog.New(slog.NewJSONHandler(io.Discard, nil))
	if cfg.Log.Decision.Enabled == nil || *cfg.Log.Decision.Enabled {
		path := "decision.log"
		if cfg.Log.Decision.Path != nil {
			path = *cfg.Log.Decision.Path
		}
		if path == "" || a.opts.Logger != nil {
			a.dlog = a.log.With("log", "decision")
		} else {
			f, err := openLog(cfg.Path(path))
			if err != nil {
				return err
			}
			a.files = append(a.files, f)
			a.dlog = slog.New(slog.NewJSONHandler(f, nil))
		}
	}
	return nil
}

func openLog(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

func (a *Agent) auditPath(cfg *Config) string {
	if cfg.Log.Audit.Enabled != nil && !*cfg.Log.Audit.Enabled {
		return ""
	}
	p := "audit.log"
	if cfg.Log.Audit.Path != nil {
		p = *cfg.Log.Audit.Path
	}
	return cfg.Path(p)
}

func (a *Agent) newTaskHandler(cfg *Config) *task.Handler {
	ex := cfg.Roles.Executor
	h := task.NewHandler(task.Config{
		Workdir: cfg.Path(ex.Workdir), Shell: ex.Shell.Path, EnvPassthrough: ex.Env.Passthrough, MaxSessions: ex.Limits.MaxSessions,
		DefaultYield: time.Duration(ex.Limits.DefaultYieldMS) * time.Millisecond, MaxOutputBytes: ex.Limits.MaxOutputBytes,
		SessionIdle: ex.Limits.SessionIdle, AuditLog: a.auditPath(cfg),
	})
	h.SetRules(func() []*pb.ExecRule { return a.effective(pb.Role_ROLE_EXECUTOR).GetExec() })
	return h
}

// Run starts every enabled role and keeps the session up until ctx ends or
// the node is removed from the workspace.
func (a *Agent) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	defer cancel()
	defer a.closeAll()
	cfg := a.config()
	if cfg.Roles.Ingress.Enabled && cfg.Roles.Ingress.TUN.Enabled {
		// Before the relay session: its transport must be bound to the
		// physical interface once the TUN takes the default route.
		if err := a.startTUN(ctx, cfg); err != nil {
			return fmt.Errorf("tun: %w", err)
		}
	}
	if err := a.startIngress(ctx, cfg); err != nil {
		return err
	}
	if cfg.Roles.Submitter.Enabled {
		if err := a.startMCP(ctx, cfg); err != nil {
			return err
		}
	}
	if !a.opts.NoLocalAPI {
		if err := a.startLocalAPI(ctx); err != nil {
			return err
		}
	}
	if cfg.P2P.Enabled {
		a.log.Warn("p2p is reserved in protocol v1 and not implemented; all streams go through the relay")
	}
	a.log.Info("agentd starting", "instance", cfg.Metadata.Name, "workspace", cfg.Workspace.Domain, "key", identity.EncodeKey(a.pub), "version", Version)
	a.runSessions(ctx)
	if a.stopped.Load() {
		return errors.New("this node was removed from the workspace; run `agentd join` with a new link")
	}
	return nil
}

func (a *Agent) closeAll() {
	for _, l := range a.ingressLn {
		l.Close()
	}
	if a.mcpLn != nil {
		a.mcpLn.Close()
	}
	if a.apiLn != nil {
		a.apiLn.Close()
		os.Remove(SocketPath(a.dir))
	}
	if a.tasks != nil {
		a.tasks.Close()
	}
	if s := a.current(); s != nil {
		s.mux.Close()
	}
	for _, f := range a.files {
		f.Close()
	}
}

// Stop ends Run.
func (a *Agent) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
}

func (a *Agent) current() *activeSession {
	a.smu.Lock()
	defer a.smu.Unlock()
	return a.sess
}

// waitSession returns the Ready session, waiting up to d for one.
func (a *Agent) waitSession(ctx context.Context, d time.Duration) *activeSession {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	for {
		a.smu.Lock()
		s, ch := a.sess, a.sessCond
		a.smu.Unlock()
		if s != nil || d == 0 {
			return s
		}
		select {
		case <-ch:
		case <-deadline.C:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

func (a *Agent) setSession(s *activeSession) {
	a.smu.Lock()
	a.sess = s
	close(a.sessCond)
	a.sessCond = make(chan struct{})
	a.smu.Unlock()
}

func (a *Agent) setStatus(f func(*sessionStatus)) {
	a.smu.Lock()
	defer a.smu.Unlock()
	f(&a.status)
}

// Status is the daemon's view for `agentd status`.
func (a *Agent) Status() map[string]any {
	cfg := a.config()
	a.smu.Lock()
	st := a.status
	a.smu.Unlock()
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	var roles []string
	if a.state.self != nil {
		for _, r := range a.state.self.RoleCaps {
			roles = append(roles, roleName(r))
		}
	}
	online := 0
	for _, m := range a.state.members {
		if m.Online {
			online++
		}
	}
	out := map[string]any{
		"instance": cfg.Metadata.Name, "workspace": cfg.Workspace.Domain, "key": identity.EncodeKey(a.pub),
		"uri_key": "agentd://" + identity.EncodeKey(a.pub), "uri_name": "agentd://" + cfg.Workspace.Domain + "/" + cfg.Metadata.Name,
		"session": st, "role_caps": roles, "enabled_roles": enabledRoles(cfg), "members": len(a.state.members), "members_online": online,
		"directory_version": a.state.dirVersion, "policy_version": a.state.policyVersion, "removed": a.stopped.Load(),
		"version": Version, "platform": runtime.GOOS + "/" + runtime.GOARCH,
	}
	if a.state.routes != nil {
		out["routes_version"] = a.state.routes.Version
	}
	if t := a.tunInfo.Load(); t != nil && a.tunDial.Load() != nil {
		out["tun"] = (*t)()
	}
	return out
}

func enabledRoles(c *Config) []string {
	var out []string
	r := c.Roles
	for name, on := range map[string]bool{"ingress": r.Ingress.Enabled, "submitter": r.Submitter.Enabled, "egress": r.Egress.Enabled, "service": r.Service.Enabled, "executor": r.Executor.Enabled} {
		if on {
			out = append(out, name)
		}
	}
	sortStrings(out)
	return out
}

func roleName(r pb.Role) string {
	switch r {
	case pb.Role_ROLE_INGRESS:
		return "ingress"
	case pb.Role_ROLE_EGRESS:
		return "egress"
	case pb.Role_ROLE_SERVICE:
		return "service"
	case pb.Role_ROLE_SUBMITTER:
		return "submitter"
	case pb.Role_ROLE_EXECUTOR:
		return "executor"
	}
	return "unknown"
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// decision writes one structured decision-log record.
func (a *Agent) decision(kind string, attrs ...any) {
	a.dlog.Info(kind, attrs...)
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
