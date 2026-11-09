package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/identity"
	"agentd/internal/policy"
	"agentd/internal/session"
	"agentd/internal/transport"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// Session timing (protocol 0.5).
const (
	ControlOpenTimeout = 5 * time.Second
	AckTimeout         = 15 * time.Second
	sessionSoftAge     = 24 * time.Hour
	sessionHardAge     = 25 * time.Hour
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func jitter(d time.Duration) time.Duration {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(d/5)+1))
	return d - d/10 + time.Duration(n.Int64())
}

// FetchRelayCert reads /.well-known/agentd from a relay and verifies the
// certificate with the workspace key (first contact, protocol 1).
func FetchRelayCert(ctx context.Context, relayURL, workspace string, wsKey []byte, opts transport.Options) (*pb.RelayCert, *pb.RelayCertBody, error) {
	u, err := url.Parse(relayURL)
	if err != nil || u.Scheme != "https" {
		return nil, nil, fmt.Errorf("relay URL must be https: %q", relayURL)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: opts.RootCAs, MinVersion: tls.VersionTLS12}}
	if opts.NetDial != nil {
		tr.DialContext = opts.NetDial
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(relayURL, "/")+"/.well-known/agentd?workspace="+url.QueryEscape(workspace), nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := (&http.Client{Transport: tr, Timeout: transport.DialTimeout}).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("relay does not serve workspace %s (HTTP %d)", workspace, resp.StatusCode)
	}
	var v struct {
		RelayCert string `json:"relay_cert"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(v.RelayCert)
	if err != nil {
		return nil, nil, err
	}
	var c pb.RelayCert
	if err := proto.Unmarshal(raw, &c); err != nil {
		return nil, nil, err
	}
	body, err := wire.VerifyRelayCert(wsKey, &c, workspace, time.Now())
	if err != nil {
		return nil, nil, fmt.Errorf("relay certificate does not verify with the workspace key: %w", err)
	}
	return &c, body, nil
}

func (a *Agent) dialOpts() transport.Options {
	return transport.Options{RootCAs: a.opts.RootCAs, NetDial: a.netDial(), UserAgent: "agentd/" + Version}
}

// runSessions is the session state machine (protocol 3.5, 12.2).
func (a *Agent) runSessions(ctx context.Context) {
	backoff := time.Second
	failures := map[string]int{}
	var lastFailed []byte
	auto := transport.NewAuto([]transport.Kind{transport.WebSocket, transport.HTTPUpgrade, transport.XHTTP}, 3)
	for ctx.Err() == nil && !a.stopped.Load() {
		cfg := a.config()
		cert, body, err := a.pickRelay(ctx, cfg, failures)
		if err != nil {
			a.setStatus(func(s *sessionStatus) { s.State = "backoff"; s.LastError = err.Error() })
			a.log.Warn("no relay to connect to", "err", err)
		} else {
			kind := transport.Kind(cfg.Workspace.Relay.Transport.Type)
			if kind == transport.AutoKind {
				kind = auto.Current()
			}
			start := time.Now()
			err = a.connectOnce(ctx, cfg, cert, body, kind, lastFailed)
			if errors.Is(err, errReassigned) {
				backoff = time.Second
				continue
			}
			if ctx.Err() != nil || a.stopped.Load() {
				return
			}
			if time.Since(start) > 60*time.Second {
				backoff = time.Second
				failures = map[string]int{}
				lastFailed = nil
				auto.Success()
			} else {
				failures[string(body.Identity)]++
				if failures[string(body.Identity)] >= 3 {
					lastFailed = body.Identity
				}
				if transport.Kind(cfg.Workspace.Relay.Transport.Type) == transport.AutoKind {
					auto.Failure()
				}
			}
			var he *session.HelloError
			if errors.As(err, &he) && he.Hello.RetryAfterSeconds > 0 {
				backoff = time.Duration(he.Hello.RetryAfterSeconds) * time.Second
			}
			a.setStatus(func(s *sessionStatus) {
				s.State = "backoff"
				if err != nil {
					s.LastError = err.Error()
				}
				s.Reconnects++
			})
			if err != nil {
				a.log.Warn("session ended", "relay", body.Name, "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(backoff)):
		}
		if backoff *= 2; backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

var errReassigned = errors.New("relay reassigned")

// pickRelay chooses the assigned relay, moving to the next one after three
// consecutive failures; without cached certificates it asks the configured
// relay URL.
func (a *Agent) pickRelay(ctx context.Context, cfg *Config, failures map[string]int) (*pb.RelayCert, *pb.RelayCertBody, error) {
	for _, c := range a.state.relayChoice() {
		b, err := wire.DecodeRelayCert(c)
		if err != nil {
			continue
		}
		if failures[string(b.Identity)] >= 3 {
			continue
		}
		return c, b, nil
	}
	for k := range failures {
		delete(failures, k)
	}
	fctx, cancel := context.WithTimeout(ctx, transport.DialTimeout)
	defer cancel()
	c, b, err := FetchRelayCert(fctx, cfg.Workspace.Relay.URL, cfg.Workspace.Domain, a.wsKey, a.dialOpts())
	if err != nil {
		return nil, nil, err
	}
	a.state.setAssigned(c, a.wsKey, cfg.Workspace.Domain)
	_ = a.state.save(StatePath(a.dir))
	return c, b, nil
}

// dialSession dials a relay and runs the handshake.
func dialSession(ctx context.Context, key []byte, priv []byte, body *pb.RelayCertBody, kind transport.Kind, opts transport.Options, hello *pb.ClientHello) (*session.Conn, *pb.ServerHello, error) {
	u := body.Urls[string(kind)]
	if u == "" {
		return nil, nil, fmt.Errorf("relay %s has no %s endpoint", body.Name, kind)
	}
	dctx, cancel := context.WithTimeout(ctx, transport.DialTimeout)
	defer cancel()
	raw, err := transport.Dial(dctx, kind, u, opts)
	if err != nil {
		return nil, nil, err
	}
	if hello.ClientVersion == "" {
		hello.ClientVersion = fmt.Sprintf("agentd %s %s/%s", Version, runtime.GOOS, runtime.GOARCH)
	}
	conn, sh, err := session.Client(raw, session.InitiatorConfig{Local: priv, Remote: body.Identity, Hello: hello})
	if err != nil {
		raw.Close()
		return nil, sh, err
	}
	return conn, sh, nil
}

// openControl opens stream 1 and waits for its Ack.
func openControl(ctx context.Context, mux *session.Mux, priv []byte, pub, relayKey []byte, workspace string) (*session.Stream, error) {
	cctx, cancel := context.WithTimeout(ctx, ControlOpenTimeout)
	defer cancel()
	st, err := mux.OpenStream(cctx)
	if err != nil {
		return nil, err
	}
	open, err := wire.SignOpen(priv, &pb.OpenBody{Kind: pb.Kind_KIND_CONTROL, Workspace: workspace, From: pub, To: relayKey,
		IssuedAt: uint64(time.Now().Unix()), Nonce: randomBytes(16)})
	if err != nil {
		return nil, err
	}
	if err := wire.WriteMsg(st, &pb.StreamOpen{Open: open}); err != nil {
		return nil, err
	}
	st.SetReadDeadline(time.Now().Add(ControlOpenTimeout))
	var ack pb.Ack
	if err := wire.ReadMsg(st, &ack, wire.AckMax); err != nil {
		return nil, fmt.Errorf("control stream: %w", err)
	}
	st.SetReadDeadline(time.Time{})
	if ack.Status != pb.Status_OK {
		return nil, fmt.Errorf("control stream refused: %s %s", ack.Status, ack.Message)
	}
	return st, nil
}

func (a *Agent) connectOnce(ctx context.Context, cfg *Config, cert *pb.RelayCert, body *pb.RelayCertBody, kind transport.Kind, lastFailed []byte) error {
	a.setStatus(func(s *sessionStatus) {
		s.State = "connecting"
		s.Relay = body.Name
		s.RelayURL = body.Urls[string(kind)]
		s.Transport = string(kind)
	})
	conn, sh, err := dialSession(ctx, a.pub, a.key, body, kind, a.dialOpts(), &pb.ClientHello{})
	if err != nil {
		var he *session.HelloError
		if errors.As(err, &he) {
			switch he.Hello.Status {
			case pb.Status_NOT_A_MEMBER:
				a.log.Error("agentserver says this node is not a member; stopping", "message", he.Hello.Message)
				a.stopped.Store(true)
			case pb.Status_WRONG_RELAY:
				if c := he.Hello.AssignedRelay; c != nil && a.state.setAssigned(c, a.wsKey, cfg.Workspace.Domain) {
					a.log.Info("workspace moved to another relay; reconnecting")
					_ = a.state.save(StatePath(a.dir))
					return errReassigned
				}
			}
		}
		return err
	}
	if skew := time.Since(time.Unix(int64(sh.ServerTime), 0)); skew > time.Minute || skew < -time.Minute {
		a.log.Warn("clock differs from the relay", "skew", skew.Round(time.Second))
		a.setStatus(func(s *sessionStatus) { s.ClockSkew = skew.Round(time.Second).String() })
	}
	mux, err := session.NewMux(conn, true)
	if err != nil {
		conn.Close()
		return err
	}
	defer mux.Close()
	ctrl, err := openControl(ctx, mux, a.key, a.pub, body.Identity, cfg.Workspace.Domain)
	if err != nil {
		return err
	}
	var wmu sync.Mutex
	as := &activeSession{mux: mux, relayKey: body.Identity, name: body.Name, ws: cfg.Workspace.Domain, done: make(chan struct{}),
		send: func(m *pb.ControlMessage) error {
			wmu.Lock()
			defer wmu.Unlock()
			ctrl.SetWriteDeadline(time.Now().Add(30 * time.Second))
			return wire.WriteMsg(ctrl, m)
		}}
	a.setSession(as)
	defer func() {
		a.setSession(nil)
		close(as.done)
	}()
	a.setStatus(func(s *sessionStatus) { s.State = "ready"; s.Since = time.Now(); s.LastError = "" })
	a.log.Info("session ready", "relay", body.Name, "name", sh.Name, "transport", kind)
	if sh.Name != "" && sh.Name != cfg.Metadata.Name {
		a.rename(sh.Name)
	}
	if err := a.advertise(as); err != nil {
		return err
	}
	if len(lastFailed) > 0 {
		_ = as.send(&pb.ControlMessage{Msg: &pb.ControlMessage_RelayReport{RelayReport: &pb.RelayReport{Relay: lastFailed, Status: pb.Status_TIMEOUT, Message: "unreachable"}}})
	}
	go a.acceptStreams(ctx, as)
	// Session age limits (protocol 3.3).
	hard := time.AfterFunc(sessionHardAge, func() { mux.Close() })
	defer hard.Stop()
	go func() {
		select {
		case <-ctx.Done():
			mux.Close()
		case <-as.done:
		}
	}()
	for {
		var m pb.ControlMessage
		if err := wire.ReadMsg(ctrl, &m, wire.ControlMsgMax); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("control stream: %w", err)
		}
		if err := a.handleControl(as, &m); err != nil {
			return err
		}
	}
}

// handleControl verifies and applies one message from the control stream.
func (a *Agent) handleControl(as *activeSession, m *pb.ControlMessage) error {
	cfg := a.config()
	switch x := m.Msg.(type) {
	case *pb.ControlMessage_Notice:
		// The relay's own notices are unsigned; only SHUTDOWN is honored.
		if x.Notice.Kind == pb.Notice_SHUTDOWN {
			return fmt.Errorf("relay is shutting down: %s", x.Notice.Message)
		}
		return nil
	case *pb.ControlMessage_Signed:
		msg, err := wire.OpenSigned(a.wsKey, a.pub, x.Signed, time.Now())
		if err != nil {
			a.log.Warn("dropped a control message that failed verification", "err", err)
			return nil
		}
		return a.handleSigned(as, cfg, msg)
	}
	return nil
}

func (a *Agent) handleSigned(as *activeSession, cfg *Config, msg *pb.ControlMessage) error {
	switch x := msg.Msg.(type) {
	case *pb.ControlMessage_Welcome:
		pu := a.state.applyWelcome(x.Welcome, a.wsKey, cfg.Workspace.Domain)
		_ = a.state.save(StatePath(a.dir))
		if pu != nil {
			a.applyPolicy(as, pu)
		}
		a.onDirectoryChange()
		if w := x.Welcome; len(w.AssignedRelay) > 0 && string(w.AssignedRelay) != string(as.relayKey) {
			return errReassigned
		}
	case *pb.ControlMessage_Update:
		if a.state.applyUpdate(x.Update, a.wsKey, cfg.Workspace.Domain) {
			_ = a.state.save(StatePath(a.dir))
			a.log.Info("relay reassigned by agentserver")
			return errReassigned
		}
		if len(x.Update.Relays) > 0 {
			_ = a.state.save(StatePath(a.dir))
		}
		a.onDirectoryChange()
	case *pb.ControlMessage_PolicyUpdate:
		a.applyPolicy(as, x.PolicyUpdate)
	case *pb.ControlMessage_AdvertiseResult:
		r := x.AdvertiseResult
		a.state.mu.Lock()
		a.state.advertised = r
		a.state.mu.Unlock()
		if r.Status != pb.Status_OK || len(r.RejectedServices) > 0 {
			a.log.Warn("advertise result", "status", r.Status, "message", r.Message, "rejected_services", r.RejectedServices)
		}
	case *pb.ControlMessage_Notice:
		n := x.Notice
		switch n.Kind {
		case pb.Notice_REMOVED:
			a.log.Error("this node was removed from the workspace", "message", n.Message)
			a.stopped.Store(true)
			as.mux.Close()
		case pb.Notice_RENAMED:
			a.rename(n.NewName)
		case pb.Notice_ROLES_CHANGED:
			a.state.mu.Lock()
			if a.state.self != nil {
				a.state.self.RoleCaps = n.RoleCaps
			}
			a.state.mu.Unlock()
			a.log.Info("role caps changed", "roles", n.RoleCaps)
			_ = a.advertise(as)
		case pb.Notice_SHUTDOWN:
			return fmt.Errorf("agentserver asked to reconnect: %s", n.Message)
		default:
			a.log.Info("notice", "message", n.Message)
		}
	}
	return nil
}

// applyPolicy stores a rendered policy and reports it (protocol 5.6).
func (a *Agent) applyPolicy(as *activeSession, pu *pb.PolicyUpdate) {
	if !a.state.setServerPolicy(pu) {
		return
	}
	cfg := a.config()
	s := cfg.Sources()
	applied := (cfg.Roles.Egress.Enabled && s.Egress == pb.PolicySource_POLICY_SOURCE_SERVER) ||
		(cfg.Roles.Service.Enabled && s.Service == pb.PolicySource_POLICY_SOURCE_SERVER) ||
		(cfg.Roles.Executor.Enabled && s.Executor == pb.PolicySource_POLICY_SOURCE_SERVER)
	msg := "applied"
	if !applied {
		msg = "all provider roles use local policies"
	}
	a.log.Info("policy update", "version", pu.Version, "applied", applied)
	_ = as.send(&pb.ControlMessage{Msg: &pb.ControlMessage_PolicyApplied{PolicyApplied: &pb.PolicyApplied{Version: pu.Version, Applied: applied, Message: msg}}})
}

// effective returns the policy a provider role enforces now.
func (a *Agent) effective(role pb.Role) *pb.Policy {
	cfg := a.config()
	local := cfg.LocalPolicy()
	server, _ := a.state.server()
	s := cfg.Sources()
	switch role {
	case pb.Role_ROLE_EGRESS:
		e := policy.Effective(s.Egress, local, server)
		return &pb.Policy{Egress: e.GetEgress()}
	case pb.Role_ROLE_SERVICE:
		e := policy.Effective(s.Service, local, server)
		return &pb.Policy{Services: e.GetServices()}
	case pb.Role_ROLE_EXECUTOR:
		e := policy.Effective(s.Executor, local, server)
		return &pb.Policy{Exec: e.GetExec()}
	}
	return &pb.Policy{}
}

// advertise declares the provider capabilities and the local policies of
// roles in local mode (protocol 5.3).
func (a *Agent) advertise(as *activeSession) error {
	cfg := a.config()
	adv := &pb.Advertise{PolicySources: cfg.Sources()}
	local := cfg.LocalPolicy()
	pol := &pb.Policy{}
	s := cfg.Sources()
	if cfg.Roles.Egress.Enabled && s.Egress == pb.PolicySource_POLICY_SOURCE_LOCAL {
		pol.Egress = local.Egress
	}
	if cfg.Roles.Service.Enabled {
		for _, sv := range cfg.Roles.Service.Servers {
			p := pb.Proto_PROTO_HTTP
			if sv.Proto == "ssh" {
				p = pb.Proto_PROTO_SSH
			}
			adv.Services = append(adv.Services, &pb.ServiceDecl{Name: sv.Name, Proto: p})
		}
		if s.Service == pb.PolicySource_POLICY_SOURCE_LOCAL {
			pol.Services = local.Services
		}
	}
	if cfg.Roles.Executor.Enabled {
		adv.Executor = &pb.ExecutorDecl{Description: cfg.Roles.Executor.Description, Tools: taskTools()}
		if s.Executor == pb.PolicySource_POLICY_SOURCE_LOCAL {
			pol.Exec = local.Exec
		}
	}
	adv.Policy = pol
	return as.send(&pb.ControlMessage{Msg: &pb.ControlMessage_Advertise{Advertise: adv}})
}

// Pull asks for a full Welcome (routes or directory look stale).
func (a *Agent) pull() {
	if as := a.current(); as != nil {
		a.state.mu.RLock()
		p := &pb.Pull{HaveDirectoryVersion: a.state.dirVersion}
		if a.state.routes != nil {
			p.HaveRoutesVersion = a.state.routes.Version
		}
		a.state.mu.RUnlock()
		_ = as.send(&pb.ControlMessage{Msg: &pb.ControlMessage_Pull{Pull: p}})
	}
}

// rename rewrites metadata.name after agentserver renamed this node.
func (a *Agent) rename(name string) {
	if !identity.ValidLabel(name) {
		return
	}
	cfg := a.config()
	if cfg.Metadata.Name == name {
		return
	}
	a.log.Info("instance renamed", "from", cfg.Metadata.Name, "to", name)
	if err := rewriteName(cfg.Dir(), name); err != nil {
		a.log.Warn("could not update metadata.name in config.yaml", "err", err)
	}
	c2 := *cfg
	c2.Metadata.Name = name
	a.cfg.Store(&c2)
}
