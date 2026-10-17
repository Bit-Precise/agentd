package connection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type handshakeReply struct {
	Welcome *Welcome `json:"welcome,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func normalizedConfig(cfg Config) (Config, error) {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 5 * time.Minute
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.OpenTimeout == 0 {
		cfg.OpenTimeout = 10 * time.Second
	}
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = 128
	}
	if cfg.MaxMetadataBytes == 0 {
		cfg.MaxMetadataBytes = 16 * 1024
	}
	if cfg.MaxFlows == 0 {
		cfg.MaxFlows = 65536
	}
	if cfg.SessionTTL < 0 || cfg.HandshakeTimeout < 0 || cfg.OpenTimeout < 0 ||
		cfg.MaxStreams < 1 || cfg.MaxStreams > 4096 || cfg.MaxMetadataBytes < 256 ||
		cfg.MaxMetadataBytes > 1024*1024 || cfg.MaxFlows < cfg.MaxStreams || cfg.MaxFlows > 1048576 {
		return Config{}, fmt.Errorf("invalid connection configuration")
	}
	return cfg, nil
}

func randomID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("create identifier: %w", err)
	}
	return hex.EncodeToString(id[:]), nil
}

func boundedName(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func validateHello(h Hello) error {
	if h.Version != ProtocolVersion {
		return ErrProtocol
	}
	if h.Role != RoleAccess && h.Role != RoleProvider {
		return ErrRole
	}
	if !boundedName(h.Workspace) || !boundedName(h.AgentID) || h.Token == "" {
		return ErrProtocol
	}
	if h.Role == RoleProvider && !boundedName(h.ConnectorID) {
		return ErrProtocol
	}
	if h.Role == RoleAccess && (h.ConnectorID != "" || len(h.Services) != 0 || h.EgressEnabled) {
		return ErrRole
	}
	if len(h.Services) > 128 {
		return ErrMetadataLimit
	}
	seen := make(map[string]struct{}, len(h.Services))
	for _, service := range h.Services {
		if !boundedName(service) {
			return ErrProtocol
		}
		if _, ok := seen[service]; ok {
			return ErrProtocol
		}
		seen[service] = struct{}{}
	}
	return nil
}

func identityMatches(h Hello, p Principal) bool {
	return h.Role == p.Role && h.Workspace == p.Workspace && h.AgentID == p.AgentID && h.ConnectorID == p.ConnectorID && p.Generation != 0
}

func clonePrincipal(p Principal) Principal {
	p.Services = append([]string(nil), p.Services...)
	return p
}

func earlier(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// Server authenticates the transport before constructing a multiplexer. The
// callback must derive Principal from its trusted registration/session store.
// The supplied context owns the resulting session as well as the handshake.
func Server(ctx context.Context, conn net.Conn, authenticate AuthenticateFunc, cfg Config) (_ *Session, err error) {
	if conn == nil {
		return nil, fmt.Errorf("nil connection")
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	cfg, err = normalizedConfig(cfg)
	if err != nil {
		return nil, err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(handshakeCtx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := handshakeCtx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}
	var hello Hello
	if err = readFrame(conn, &hello, cfg.MaxMetadataBytes); err != nil {
		return nil, err
	}
	if err = validateHello(hello); err != nil {
		_ = writeFrame(conn, handshakeReply{Error: "protocol"}, cfg.MaxMetadataBytes)
		return nil, err
	}
	if authenticate == nil {
		return nil, ErrAuthentication
	}
	principal, authErr := authenticate(handshakeCtx, hello)
	// Do not expose callback errors: they may contain registration secrets.
	if authErr != nil || !identityMatches(hello, principal) {
		_ = writeFrame(conn, handshakeReply{Error: "authentication"}, cfg.MaxMetadataBytes)
		return nil, ErrAuthentication
	}
	principal = clonePrincipal(principal)
	principal.ExpiresAt = earlier(principal.ExpiresAt, time.Now().Add(cfg.SessionTTL))
	if !principal.ExpiresAt.After(time.Now()) {
		return nil, ErrExpired
	}
	principal.SessionID, err = randomID()
	if err != nil {
		return nil, err
	}
	if err = writeFrame(conn, handshakeReply{Welcome: &Welcome{Version: ProtocolVersion, Principal: principal}}, cfg.MaxMetadataBytes); err != nil {
		return nil, err
	}
	if handshakeCtx.Err() != nil {
		return nil, handshakeCtx.Err()
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return newSession(ctx, conn, principal, cfg, true)
}

// Client verifies the server's welcome against the requested identity. The
// transport must already authenticate the trusted Edge/CDN endpoint. Generation
// is assigned by the server, so a zero Hello generation requests a fresh one.
func Client(ctx context.Context, conn net.Conn, hello Hello, cfg Config) (_ *Session, err error) {
	if conn == nil {
		return nil, fmt.Errorf("nil connection")
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	cfg, err = normalizedConfig(cfg)
	if err != nil {
		return nil, err
	}
	if err = validateHello(hello); err != nil {
		return nil, err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(handshakeCtx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := handshakeCtx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err = writeFrame(conn, hello, cfg.MaxMetadataBytes); err != nil {
		return nil, err
	}
	var reply handshakeReply
	if err = readFrame(conn, &reply, cfg.MaxMetadataBytes); err != nil {
		return nil, err
	}
	if reply.Error != "" {
		if reply.Error == "authentication" {
			return nil, ErrAuthentication
		}
		return nil, ErrProtocol
	}
	if reply.Welcome == nil || reply.Welcome.Version != ProtocolVersion {
		return nil, ErrProtocol
	}
	principal := clonePrincipal(reply.Welcome.Principal)
	if !identityMatches(hello, principal) || !boundedName(principal.SessionID) {
		return nil, ErrAuthentication
	}
	if principal.ExpiresAt.IsZero() {
		return nil, ErrProtocol
	}
	principal.ExpiresAt = earlier(principal.ExpiresAt, time.Now().Add(cfg.SessionTTL))
	if !principal.ExpiresAt.After(time.Now()) {
		return nil, ErrExpired
	}
	if handshakeCtx.Err() != nil {
		return nil, handshakeCtx.Err()
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return newSession(ctx, conn, principal, cfg, false)
}
