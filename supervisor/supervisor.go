// Package supervisor owns agent role lifetimes, edge connections and reconnects.
// Its separation from config and orchestration follows cloudflared's structure.
package supervisor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/connection"
	"github.com/bit-precise/agentd/controlclient"
	"github.com/bit-precise/agentd/credentials"
	"github.com/bit-precise/agentd/ingress"
	"github.com/bit-precise/agentd/orchestration"
	"github.com/bit-precise/agentd/transport/xhttp"
	"github.com/rs/zerolog"
)

type Supervisor struct {
	// cfg is the startup configuration: identity, transport and listeners only
	// change on restart. applied tracks reloaded intent submitted to Control.
	cfg          *config.Config
	applied      *config.Config
	creds        *credentials.Credentials
	manager      *orchestration.Manager
	proxy        *ingress.Proxy
	client       *http.Client
	log          zerolog.Logger
	mu           sync.Mutex
	reloadMu     sync.Mutex
	pending      *config.Config
	access       *connection.Session
	provider     *connection.Session
	providerWake chan struct{}
	accessWake   chan struct{}
	connectorID  string
	pollInterval time.Duration
}

// Option supplies trusted embedding hooks; the standalone CLI uses none.
type Option func(*Supervisor)

func WithEgressDialer(dial func(context.Context, string, string) (net.Conn, error)) Option {
	return func(s *Supervisor) { s.manager.SetDialer(dial) }
}

func New(cfg *config.Config, c *credentials.Credentials, log zerolog.Logger, options ...Option) (*Supervisor, error) {
	if c.ControlToken != "" && strings.TrimSuffix(c.ControlURL, "/") != strings.TrimSuffix(cfg.Instance, "/") {
		return nil, errors.New("stored control credential belongs to a different instance")
	}
	cfg, err := detach(cfg)
	if err != nil {
		return nil, err
	}
	if c.Workspace != cfg.Workspace {
		return nil, errors.New("credentials belong to a different workspace")
	}
	if cfg.Ingress.Enabled && c.AccessToken == "" {
		return nil, errors.New("ingress requires an access session token")
	}
	if (cfg.Serve.Enabled || cfg.Egress.Enabled) && c.ProviderToken == "" {
		return nil, errors.New("serve/egress require a provider session token")
	}
	if cfg.Ingress.Enabled && cfg.Ingress.TUN.Enabled {
		return nil, errors.New("TUN is not implemented in this milestone; disable ingress.tun before running")
	}
	client, err := httpClient(cfg.Transport.CAFile)
	if err != nil {
		return nil, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	s := &Supervisor{cfg: cfg, applied: cfg, creds: c, manager: orchestration.New(cfg, c.Effective), client: client, log: log,
		providerWake: make(chan struct{}, 1), accessWake: make(chan struct{}, 1), connectorID: hex.EncodeToString(id[:]), pollInterval: 2 * time.Second}
	s.proxy = ingress.NewProxy(cfg.Ingress.Routes, s.openAccess)
	if c.ControlToken != "" {
		s.pending = cfg
	}
	for _, option := range options {
		option(s)
	}
	return s, nil
}

// detach copies a config so later caller mutations cannot reach running state.
func detach(cfg *config.Config) (*config.Config, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var detached config.Config
	if err := json.Unmarshal(data, &detached); err != nil {
		return nil, err
	}
	return &detached, nil
}

func httpClient(caFile string) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read transport CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("transport CA file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 60 * time.Second, MaxIdleConns: 16, MaxIdleConnsPerHost: 8}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("transport redirects are forbidden") }}, nil
}

// Run blocks until canceled, the device credential is rejected, the effective
// configuration expires without reaching Control, or all configured roles fail.
func (s *Supervisor) Run(ctx context.Context) error {
	unlock, err := credentials.Lock(s.cfg.Agent.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	start := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }
	if s.creds.ControlToken != "" {
		start(func() { s.pollControl(ctx, cancel) })
	} else {
		start(func() {
			timer := time.NewTimer(time.Until(s.creds.Effective.ExpiresAt))
			defer timer.Stop()
			select {
			case <-ctx.Done():
			case <-timer.C:
				cancel(errors.New("effective configuration snapshot expired; provision fresh credentials before restarting"))
			}
		})
	}
	if s.creds.ProviderToken != "" {
		start(func() { s.connectLoop(ctx, connection.RoleProvider) })
	}
	if s.cfg.Ingress.Enabled {
		start(func() { s.connectLoop(ctx, connection.RoleAccess) })
	}
	listeners := 0
	if s.cfg.Ingress.Enabled && s.cfg.Ingress.HTTP.Enabled {
		l, err := net.Listen("tcp", s.cfg.Ingress.HTTP.Listen)
		if err != nil {
			s.log.Error().Err(err).Str("role", "ingress.http").Msg("listener failed")
		} else {
			listeners++
			server := &http.Server{Handler: s.proxy.HTTPHandler(ctx), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
			start(func() {
				stop := context.AfterFunc(ctx, func() { _ = server.Close() })
				defer stop()
				if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
					s.log.Error().Err(err).Msg("HTTP ingress stopped")
				}
			})
			s.log.Info().Str("listen", l.Addr().String()).Msg("HTTP CONNECT ingress ready")
		}
	}
	if s.cfg.Ingress.Enabled && s.cfg.Ingress.SOCKS.Enabled {
		l, err := net.Listen("tcp", s.cfg.Ingress.SOCKS.Listen)
		if err != nil {
			s.log.Error().Err(err).Str("role", "ingress.socks").Msg("listener failed")
		} else {
			listeners++
			start(func() {
				if err := s.proxy.ServeSOCKS(ctx, l); err != nil {
					s.log.Error().Err(err).Msg("SOCKS ingress stopped")
				}
			})
			s.log.Info().Str("listen", l.Addr().String()).Msg("SOCKS5 ingress ready")
		}
	}
	if s.cfg.Ingress.Enabled && listeners == 0 && !s.cfg.Serve.Enabled && !s.cfg.Egress.Enabled {
		cancel(nil)
		wg.Wait()
		return errors.New("all ingress listeners failed")
	}
	<-ctx.Done()
	wg.Wait()
	s.client.CloseIdleConnections()
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return nil
}

// wanted reports whether a session role has anything to carry: local intent,
// a credential and a nonempty effective configuration for that role.
func (s *Supervisor) wanted(role connection.Role) bool {
	creds := s.credentials()
	if role == connection.RoleAccess {
		return s.cfg.Ingress.Enabled && creds.AccessToken != "" && creds.Effective.Ingress
	}
	return creds.ProviderToken != "" && s.manager.Provides() && (len(creds.Effective.Services) > 0 || len(creds.Effective.Egress) > 0)
}

// reconcileSessions closes sessions that lost their purpose and wakes loops
// that gained one. Individual flows are revoked by Manager, not by this.
func (s *Supervisor) reconcileSessions() {
	for _, role := range []connection.Role{connection.RoleProvider, connection.RoleAccess} {
		wake := s.providerWake
		s.mu.Lock()
		session := s.provider
		if role == connection.RoleAccess {
			session, wake = s.access, s.accessWake
		}
		s.mu.Unlock()
		if !s.wanted(role) {
			if session != nil {
				_ = session.Close()
			}
			continue
		}
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (s *Supervisor) connectLoop(ctx context.Context, role connection.Role) {
	wake := s.providerWake
	if role == connection.RoleAccess {
		wake = s.accessWake
	}
	backoff := time.Second
	idle := false
	for ctx.Err() == nil {
		if !s.wanted(role) {
			if !idle {
				s.log.Info().Str("role", string(role)).Msg("session idle: role disabled locally or absent from the effective configuration")
				idle = true
			}
			select {
			case <-ctx.Done():
				return
			case <-wake:
				continue
			}
		}
		idle = false
		started := time.Now()
		err := s.connect(ctx, role)
		if ctx.Err() != nil {
			return
		}
		s.log.Warn().Err(err).Str("role", string(role)).Msg("edge session ended; reconnecting")
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		}
		var noise [1]byte
		_, _ = rand.Read(noise[:])
		delay := backoff/2 + time.Duration(noise[0])*backoff/256
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (s *Supervisor) connect(ctx context.Context, role connection.Role) error {
	creds := s.credentials()
	token := creds.ProviderToken
	if role == connection.RoleAccess {
		token = creds.AccessToken
	}
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	c, err := xhttp.Dial(ctx, s.cfg.Transport.Endpoint, xhttp.ClientConfig{HTTPClient: s.client, Headers: headers, AllowHTTP: s.cfg.Transport.AllowHTTP})
	if err != nil {
		return fmt.Errorf("XHTTP connect: %w", err)
	}
	hello := connection.Hello{Version: connection.ProtocolVersion, Role: role, Workspace: s.cfg.Workspace, AgentID: creds.AgentID, Token: token}
	cc := connection.Config{SessionTTL: time.Until(creds.Effective.ExpiresAt)}
	if role == connection.RoleProvider {
		hello.ConnectorID = s.connectorID
		cc.AuthorizeOpen = s.manager.AuthorizeOpen
	}
	session, err := connection.Client(ctx, c, hello, cc)
	if err != nil {
		_ = c.Close()
		return fmt.Errorf("agents handshake: %w", err)
	}
	defer func() { _ = session.Close() }()
	s.log.Info().Str("role", string(role)).Str("session", session.Principal().SessionID).Msg("agents session ready")
	if role == connection.RoleAccess {
		s.mu.Lock()
		s.access = session
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			if s.access == session {
				s.access = nil
			}
			s.mu.Unlock()
		}()
		select {
		case <-ctx.Done():
		case <-session.Done():
		}
		return errors.New("access session closed")
	}
	s.mu.Lock()
	s.provider = session
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.provider == session {
			s.provider = nil
		}
		s.mu.Unlock()
	}()
	var flows sync.WaitGroup
	defer func() { _ = session.Close(); flows.Wait() }()
	for {
		flow, err := session.Accept(ctx)
		if err != nil {
			return err
		}
		flows.Add(1)
		go func() {
			defer flows.Done()
			if err := s.manager.Handle(ctx, flow); err != nil {
				s.log.Debug().Err(err).Str("flow", flow.Request().FlowID).Msg("provider flow ended")
			}
		}()
	}
}

func (s *Supervisor) openAccess(ctx context.Context, domain string, port uint16) (net.Conn, error) {
	s.mu.Lock()
	session := s.access
	s.mu.Unlock()
	if session == nil {
		return nil, errors.New("access session is offline")
	}
	creds := s.credentials()
	return session.Open(ctx, connection.OpenRequest{Purpose: connection.PurposeAccess, Destination: connection.Destination{Host: domain, Port: port}, Protocol: "tls", Revision: creds.Effective.Revision, Deadline: minTime(session.Principal().ExpiresAt, creds.Effective.ExpiresAt)})
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Reload applies what can change at runtime: serve and egress (narrowing at
// once, widening once Control accepts it) and the local ingress routes. Other
// changes are reported as needing a restart and never block those updates.
func (s *Supervisor) Reload(next *config.Config) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	desired, err := detach(next)
	if err != nil {
		return err
	}
	var problems []error
	if desired.Instance != s.cfg.Instance || desired.Workspace != s.cfg.Workspace || desired.Agent != s.cfg.Agent || desired.Transport != s.cfg.Transport {
		problems = append(problems, errors.New("instance, workspace, agent and transport changes require a restart and were not applied"))
	}
	listeners, routes := desired.Ingress, s.cfg.Ingress
	listeners.Routes, routes.Routes = nil, nil
	if !reflect.DeepEqual(listeners, routes) {
		problems = append(problems, errors.New("ingress enablement and listener changes require a restart and were not applied"))
	}
	creds := s.credentials()
	if (desired.Serve.Enabled || desired.Egress.Enabled) && creds.ProviderToken == "" {
		problems = append(problems, errors.New("serve/egress need a provider credential; enroll again with a key that permits them"))
	}
	applied := *s.applied
	applied.Serve, applied.Egress, applied.Ingress.Routes = desired.Serve, desired.Egress, desired.Ingress.Routes
	s.manager.Reload(&applied)
	s.proxy.SetRoutes(applied.Ingress.Routes)
	s.mu.Lock()
	s.applied = &applied
	s.mu.Unlock()
	s.reconcileSessions()
	if creds.ControlToken != "" {
		s.pending = &applied
		client, err := controlclient.New(s.cfg)
		if err != nil {
			return errors.Join(append(problems, err)...)
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = client.Update(ctx, creds, &applied)
		switch {
		case err == nil:
			s.pending = nil
		case controlclient.Rejected(err):
			s.pending = nil
			problems = append(problems, fmt.Errorf("control rejected the desired configuration; the previous effective configuration keeps running: %w", err))
		default:
			problems = append(problems, fmt.Errorf("local restrictions applied; control update queued for retry: %w", err))
		}
	}
	return errors.Join(problems...)
}

func (s *Supervisor) credentials() credentials.Credentials {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.creds
}
func (s *Supervisor) pollControl(ctx context.Context, stop context.CancelCauseFunc) {
	client, err := controlclient.New(s.cfg)
	if err != nil {
		stop(err)
		return
	}
	defer client.Close()
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	var lastSaved time.Time
	unreachable, retrying := false, false
	for {
		previous := s.credentials()
		// Keep reload and retries ordered, so an old POST cannot supersede new intent.
		s.reloadMu.Lock()
		if s.pending != nil {
			requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, updateErr := client.Update(requestCtx, previous, s.pending)
			cancel()
			switch {
			case updateErr == nil:
				s.pending, retrying = nil, false
			case controlclient.Rejected(updateErr):
				// Content errors are final; only a new local edit is resubmitted.
				s.pending, retrying = nil, false
				s.log.Error().Err(updateErr).Msg("control rejected the desired configuration; the previous effective configuration keeps running")
			case !retrying && !controlclient.AuthenticationRejected(updateErr):
				retrying = true
				s.log.Warn().Err(updateErr).Msg("desired configuration update failed; retrying")
			}
		}
		s.reloadMu.Unlock()
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		next, err := client.Refresh(requestCtx, previous)
		cancel()
		if err == nil {
			err = s.manager.UpdateEffective(next.Effective)
		}
		switch {
		case err == nil:
			if unreachable {
				s.log.Info().Msg("control reachable again")
				unreachable = false
			}
			// A rolling expiry alone is saved at most once per minute. Capability
			// changes are durable immediately.
			changed := previous.Effective.Revision != next.Effective.Revision || !previous.Effective.SameContent(next.Effective)
			s.mu.Lock()
			s.creds = &next
			s.mu.Unlock()
			s.reconcileSessions()
			if changed || time.Since(lastSaved) >= time.Minute {
				if err := credentials.Save(s.cfg.Agent.StateDir, &next); err != nil {
					s.log.Error().Err(err).Msg("could not persist the effective configuration")
				} else {
					lastSaved = time.Now()
				}
			}
		case controlclient.AuthenticationRejected(err):
			if ctx.Err() != nil {
				return
			}
			s.log.Error().Err(err).Msg("control rejected this device credential; stopping roles")
			stop(fmt.Errorf("device credential revoked or expired; run agentd enroll --replace to register again: %w", err))
			return
		default:
			if ctx.Err() != nil {
				return
			}
			if !previous.Effective.ExpiresAt.After(time.Now()) {
				s.log.Error().Err(err).Msg("effective configuration expired while control was unreachable; stopping roles")
				stop(fmt.Errorf("effective configuration expired without reaching control: %w", err))
				return
			}
			if !unreachable {
				s.log.Warn().Err(err).Time("effectiveUntil", previous.Effective.ExpiresAt).Msg("control unreachable; keeping the current effective configuration")
				unreachable = true
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
