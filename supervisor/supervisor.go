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
	"slices"
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
	cfg         *config.Config
	creds       *credentials.Credentials
	manager     *orchestration.Manager
	client      *http.Client
	log         zerolog.Logger
	mu          sync.Mutex
	reloadMu    sync.Mutex
	pending     *config.Config
	access      *connection.Session
	provider    *connection.Session
	connectorID string
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
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var detached config.Config
	if err := json.Unmarshal(data, &detached); err != nil {
		return nil, err
	}
	cfg = &detached
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
	s := &Supervisor{cfg: cfg, creds: c, manager: orchestration.New(cfg, c.Approval), client: client, log: log, connectorID: hex.EncodeToString(id[:])}
	if c.ControlToken != "" {
		s.pending = cfg
	}
	for _, option := range options {
		option(s)
	}
	return s, nil
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

// Run blocks until canceled, the approval expires, or all configured roles fail.
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
			timer := time.NewTimer(time.Until(s.creds.Approval.ExpiresAt))
			defer timer.Stop()
			select {
			case <-ctx.Done():
			case <-timer.C:
				cancel(errors.New("approval snapshot expired; obtain a new approval before restarting"))
			}
		})
	}
	if s.cfg.Serve.Enabled || s.cfg.Egress.Enabled {
		start(func() { s.connectLoop(ctx, connection.RoleProvider) })
	}
	if s.cfg.Ingress.Enabled {
		start(func() { s.connectLoop(ctx, connection.RoleAccess) })
	}
	proxy := &ingress.Proxy{Routes: s.cfg.Ingress.Routes, Open: s.openAccess}
	listeners := 0
	if s.cfg.Ingress.Enabled && s.cfg.Ingress.HTTP.Enabled {
		l, err := net.Listen("tcp", s.cfg.Ingress.HTTP.Listen)
		if err != nil {
			s.log.Error().Err(err).Str("role", "ingress.http").Msg("listener failed")
		} else {
			listeners++
			server := &http.Server{Handler: proxy.HTTPHandler(ctx), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
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
				if err := proxy.ServeSOCKS(ctx, l); err != nil {
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

func (s *Supervisor) connectLoop(ctx context.Context, role connection.Role) {
	backoff := time.Second
	for ctx.Err() == nil {
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
	hello := connection.Hello{Version: connection.ProtocolVersion, Role: role, Workspace: s.cfg.Workspace, AgentID: creds.AgentID, Token: token, Revision: creds.Approval.Revision}
	cc := connection.Config{SessionTTL: time.Until(creds.Approval.ExpiresAt)}
	if role == connection.RoleProvider {
		hello.ConnectorID = s.connectorID
		hello.Services = s.manager.Services()
		hello.EgressEnabled = s.manager.EgressEnabled()
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
	s.reconcileProvider()
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
	return session.Open(ctx, connection.OpenRequest{Purpose: connection.PurposeAccess, Destination: connection.Destination{Host: domain, Port: port}, Protocol: "tls", Revision: creds.Approval.Revision, Deadline: minTime(session.Principal().ExpiresAt, creds.Approval.ExpiresAt)})
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Reload applies provider-side restrictions without renewing approval. Listener,
// profile and transport settings currently require a process restart.
func (s *Supervisor) Reload(next *config.Config) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if !s.cfg.Serve.Enabled && !s.cfg.Egress.Enabled && (next.Serve.Enabled || next.Egress.Enabled) {
		return errors.New("starting a provider role requires a restart")
	}
	// Detach the pending desired config from the caller's mutable slices.
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	var desired config.Config
	if err = json.Unmarshal(data, &desired); err != nil {
		return err
	}
	if err := s.manager.Reload(&desired); err != nil {
		return err
	}
	s.reconcileProvider()
	creds := s.credentials()
	if creds.ControlToken == "" {
		return nil
	}
	s.pending = &desired
	client, err := controlclient.New(s.cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Update(ctx, creds, &desired); err != nil {
		return fmt.Errorf("local restrictions applied; control update queued for retry: %w", err)
	}
	s.pending = nil
	return nil
}

// New capabilities need fresh admission even at the same approval revision.
// Withdrawal is enforced per flow by Manager and control, without disrupting
// unrelated streams sharing the provider connection.
func (s *Supervisor) reconcileProvider() {
	services, egress := s.manager.Services(), s.manager.EgressEnabled()
	s.mu.Lock()
	p, revision := s.provider, s.creds.Approval.Revision
	s.mu.Unlock()
	if p == nil {
		return
	}
	principal := p.Principal()
	expanded := egress && !principal.EgressEnabled
	for _, service := range services {
		if !slices.Contains(principal.Services, service) {
			expanded = true
		}
	}
	if revision != principal.Revision || expanded {
		_ = p.Close()
	}
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
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	lastSuccess, lastSaved := time.Now(), time.Time{}
	for {
		previous := s.credentials()
		// Keep reload and retries ordered, so an old POST cannot supersede new intent.
		s.reloadMu.Lock()
		if s.pending != nil {
			requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			updateErr := client.Update(requestCtx, previous, s.pending)
			cancel()
			if updateErr == nil {
				s.pending = nil
			}
		}
		s.reloadMu.Unlock()
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		next, err := client.Refresh(requestCtx, previous)
		cancel()
		if err == nil {
			err = s.manager.UpdateApproval(next.Approval)
		}
		if err == nil {
			lastSuccess = time.Now()
			// A rolling expiry alone is saved at most once per minute. Capability
			// changes are durable immediately, including narrowing at one revision.
			oldApproval, newApproval := previous.Approval, next.Approval
			oldApproval.ExpiresAt, newApproval.ExpiresAt = time.Time{}, time.Time{}
			changed := !reflect.DeepEqual(oldApproval, newApproval)
			s.mu.Lock()
			s.creds = &next
			s.mu.Unlock()
			s.reconcileProvider()
			if changed || time.Since(lastSaved) >= time.Minute {
				if err := credentials.Save(s.cfg.Agent.StateDir, &next); err != nil {
					s.log.Error().Err(err).Msg("could not persist refreshed approval")
				} else {
					lastSaved = time.Now()
				}
			}
		} else if controlclient.AuthenticationRejected(err) || time.Since(lastSuccess) > 30*time.Second || !previous.Approval.ExpiresAt.After(time.Now()) {
			if ctx.Err() != nil {
				return
			}
			s.log.Error().Err(err).Msg("control rejected identity, is unavailable, or approval expired; stopping roles")
			stop(fmt.Errorf("control supervision stopped: %w", err))
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
