package connection

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func approve(_ context.Context, _ Principal, r OpenRequest) (OpenClaims, error) {
	return OpenClaims{FlowID: r.FlowID, Purpose: r.Purpose, Resource: r.Resource,
		Destination: r.Destination, Protocol: r.Protocol, Revision: r.Revision, Deadline: r.Deadline}, nil
}

func pair(t *testing.T, role Role, clientCfg, serverCfg Config) (*Session, *Session) {
	t.Helper()
	a, b := net.Pipe()
	hello := Hello{Version: ProtocolVersion, Role: role, Workspace: "workspace1", AgentID: "agent1", Token: "test-secret"}
	if role == RoleProvider {
		hello.ConnectorID = "connector1"
	}
	type result struct {
		session *Session
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := Server(t.Context(), b, func(_ context.Context, h Hello) (Principal, error) {
			if h.Token != "test-secret" {
				return Principal{}, errors.New("wrong token")
			}
			return Principal{Role: role, Workspace: "workspace1", AgentID: "agent1", ConnectorID: hello.ConnectorID, Generation: 7, ExpiresAt: time.Now().Add(time.Minute)}, nil
		}, serverCfg)
		ch <- result{s, err}
	}()
	client, err := Client(t.Context(), a, hello, clientCfg)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	r := <-ch
	if r.err != nil {
		_ = client.Close()
		t.Fatalf("server: %v", r.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = r.session.Close() })
	if client.Principal().Generation != 7 {
		t.Fatal("server-assigned generation not retained")
	}
	return client, r.session
}

func serveRequest() OpenRequest {
	return OpenRequest{Purpose: PurposeServe, Resource: "demo", Protocol: "http", Revision: 1}
}

func exchange(t *testing.T, sender, receiver *Session, r OpenRequest) (*Stream, *Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	a, err := sender.Open(ctx, r)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	b, err := receiver.Accept(ctx)
	if err != nil {
		_ = a.Close()
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestServeAndEgressConcurrentFlows(t *testing.T) {
	t.Parallel()
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		r := serveRequest()
		if i%2 == 1 {
			r = OpenRequest{Purpose: PurposeEgress, Resource: "office", Protocol: "tls", Destination: Destination{Host: "oa.example", Port: 443}, Revision: 1}
		}
		a, b := exchange(t, edge, provider, r)
		if a.Claims().FlowID == "" || a.Claims().FlowID != b.Claims().FlowID {
			t.Fatal("flow identity not bound")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := strings.Repeat("flow payload", 65536)
			writeDone := make(chan error, 1)
			go func() {
				_, err := io.WriteString(a, payload)
				if err == nil {
					err = a.CloseWrite()
				}
				writeDone <- err
			}()
			got, err := io.ReadAll(b)
			if err != nil || string(got) != payload {
				t.Errorf("payload mismatch: bytes=%d error=%v", len(got), err)
			}
			if err := <-writeDone; err != nil {
				t.Errorf("writer: %v", err)
			}
			_ = b.CloseWrite()
		}()
	}
	wg.Wait()
}

func TestRoleDirectionAndMissingAuthorization(t *testing.T) {
	t.Parallel()
	client, edge := pair(t, RoleAccess, Config{}, Config{AuthorizeOpen: approve})
	request := OpenRequest{Purpose: PurposeAccess, Destination: Destination{Host: "oa.example", Port: 443}}
	a, b := exchange(t, client, edge, request)
	if a.Claims().Protocol != "tls" || b.Request().Purpose != PurposeAccess {
		t.Fatal("access is not a typed candidate")
	}
	if _, err := client.Open(t.Context(), serveRequest()); !errors.Is(err, ErrRole) {
		t.Fatalf("access opened serve: %v", err)
	}
	if _, err := edge.Open(t.Context(), request); !errors.Is(err, ErrRole) {
		t.Fatalf("edge opened access in wrong direction: %v", err)
	}
	provider, providerEdge := pair(t, RoleProvider, Config{}, Config{})
	if _, err := provider.Open(t.Context(), serveRequest()); !errors.Is(err, ErrRole) {
		t.Fatalf("provider opened serve: %v", err)
	}
	if _, err := providerEdge.Open(t.Context(), serveRequest()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("missing authorization accepted: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := provider.Accept(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unauthorized stream surfaced: %v", err)
	}
}

func TestPeerCannotBypassPurposeCheckWithRawMux(t *testing.T) {
	t.Parallel()
	client, edge := pair(t, RoleAccess, Config{}, Config{AuthorizeOpen: approve})
	raw, err := client.mux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if err = raw.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	r := serveRequest()
	r.FlowID = "forged-serve"
	r.Deadline = time.Now().Add(time.Minute)
	if err = writeFrame(raw, r, 16384); err != nil {
		t.Fatal(err)
	}
	var reply openReply
	if err = readFrame(raw, &reply, 16384); err != nil {
		t.Fatal(err)
	}
	if reply.Error == "" || reply.Claims != nil {
		t.Fatal("forged serve OPEN accepted on access session")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err = edge.Accept(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("forged stream delivered to handler: %v", err)
	}
}

func TestAuthorizerCannotExtendRequestedLease(t *testing.T) {
	t.Parallel()
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: func(ctx context.Context, p Principal, r OpenRequest) (OpenClaims, error) {
		claims, err := approve(ctx, p, r)
		claims.Deadline = r.Deadline.Add(time.Hour)
		return claims, err
	}}, Config{})
	r := serveRequest()
	r.Deadline = time.Now().Add(2 * time.Second)
	if _, err := edge.Open(t.Context(), r); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("authorizer extended lease: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := provider.Accept(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("invalid approval delivered: %v", err)
	}
}

func TestCancelDuringAuthorization(t *testing.T) {
	t.Parallel()
	callbackStarted := make(chan struct{})
	callbackStopped := make(chan struct{})
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: func(ctx context.Context, _ Principal, _ OpenRequest) (OpenClaims, error) {
		close(callbackStarted)
		<-ctx.Done()
		close(callbackStopped)
		return OpenClaims{}, ctx.Err()
	}}, Config{})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, err := edge.Open(ctx, serveRequest()); result <- err }()
	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("authorization did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled OPEN succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("OPEN ignored cancellation")
	}
	select {
	case <-callbackStopped:
	case <-time.After(time.Second):
		t.Fatal("remote authorizer ignored flow cancellation")
	}
	select {
	case <-provider.Done():
		t.Fatal("cancelled OPEN killed provider session")
	default:
	}
}

func TestHalfClosePreservesResponse(t *testing.T) {
	t.Parallel()
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	a, b := exchange(t, edge, provider, serveRequest())
	if _, err := io.WriteString(a, "request"); err != nil {
		t.Fatal(err)
	}
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(b)
	if err != nil || string(got) != "request" {
		t.Fatalf("request after FIN: %q %v", got, err)
	}
	if _, err := io.WriteString(b, "response after FIN"); err != nil {
		t.Fatal(err)
	}
	if err := b.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(a)
	if err != nil || string(got) != "response after FIN" {
		t.Fatalf("response after FIN: %q %v", got, err)
	}
}

func TestHalfCloseMayOutliveOpeningTimeout(t *testing.T) {
	t.Parallel()
	cfg := Config{AuthorizeOpen: approve, OpenTimeout: 40 * time.Millisecond}
	provider, edge := pair(t, RoleProvider, cfg, cfg)
	a, b := exchange(t, edge, provider, serveRequest())
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(b); err != nil {
		t.Fatal(err)
	}
	// OPEN is complete. Its timeout must not truncate a later slow response.
	time.Sleep(100 * time.Millisecond)
	if _, err := b.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := io.ReadFull(a, buf[:]); err != nil {
		t.Fatal(err)
	}
}

func TestCancelClosesPeerFlowButNotSibling(t *testing.T) {
	t.Parallel()
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	a, b := exchange(t, edge, provider, serveRequest())
	c, d := exchange(t, edge, provider, serveRequest())
	blocked := make(chan error, 1)
	go func() { var buf [1]byte; _, err := a.Read(buf[:]); blocked <- err }()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("remote flow context not cancelled")
	}
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("blocked read did not fail")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not unblock read")
	}
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("sibling write: %v", err)
	}
	var buf [1]byte
	if _, err := io.ReadFull(d, buf[:]); err != nil || buf[0] != 'x' {
		t.Fatalf("sibling read: %v", err)
	}
	select {
	case <-edge.Done():
		t.Fatal("flow cancellation closed session")
	default:
	}
}

func TestOpenContextOnlyBoundsOpening(t *testing.T) {
	t.Parallel()
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	a, err := edge.Open(ctx, serveRequest())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	b, err := provider.Accept(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close(); _ = b.Close() }()
	if a.Claims().Deadline.Before(time.Now().Add(time.Second)) {
		t.Fatal("opening timeout leaked into flow lease")
	}
	if _, err := a.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := io.ReadFull(b, buf[:]); err != nil {
		t.Fatal(err)
	}
}

func TestSessionAndFlowExpiry(t *testing.T) {
	t.Parallel()
	t.Run("session closes active IO", func(t *testing.T) {
		provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{SessionTTL: 100 * time.Millisecond})
		a, b := exchange(t, edge, provider, serveRequest())
		if err := a.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-edge.Done():
		case <-time.After(time.Second):
			t.Fatal("session lease not enforced")
		}
		select {
		case <-b.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("peer stream survived expiry")
		}
		if _, err := a.Write([]byte("expired")); err == nil {
			t.Fatal("expired session allowed data")
		}
	})
	t.Run("flow expiry leaves session alive", func(t *testing.T) {
		provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
		r := serveRequest()
		r.Deadline = time.Now().Add(100 * time.Millisecond)
		a, b := exchange(t, edge, provider, r)
		if err := a.SetDeadline(time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-b.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("expired peer flow not cancelled")
		}
		select {
		case <-edge.Done():
			t.Fatal("flow expiry closed session")
		default:
		}
		exchange(t, edge, provider, serveRequest())
	})
}

func TestStreamLimitMetadataLimitAndReplay(t *testing.T) {
	t.Parallel()
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve, MaxStreams: 1}, Config{MaxStreams: 1})
	r := serveRequest()
	r.FlowID = "once"
	a, b := exchange(t, edge, provider, r)
	if _, err := edge.Open(t.Context(), serveRequest()); !errors.Is(err, ErrStreamLimit) {
		t.Fatalf("limit not enforced: %v", err)
	}
	_ = a.Close()
	select {
	case <-b.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("flow did not cancel")
	}
	deadline := time.Now().Add(time.Second)
	for edge.mux.NumStreams() > 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, err := edge.Open(t.Context(), r); !errors.Is(err, ErrDuplicateFlow) {
		t.Fatalf("replayed flow accepted: %v", err)
	}
	provider2, edge2 := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	oversized := serveRequest()
	oversized.Capability = strings.Repeat("x", 32*1024)
	if _, err := edge2.Open(t.Context(), oversized); !errors.Is(err, ErrMetadataLimit) {
		t.Fatalf("oversized metadata: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := provider2.Accept(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("oversized request delivered: %v", err)
	}
}

func TestFlowTombstonesExpireSoLongSessionsKeepAdmitting(t *testing.T) {
	t.Parallel()
	cfg := Config{OpenTimeout: 50 * time.Millisecond, MaxLeaseDuration: 100 * time.Millisecond, FlowTombstoneTTL: 300 * time.Millisecond, MaxStreams: 1, MaxFlows: 1}
	providerCfg := cfg
	providerCfg.AuthorizeOpen = approve
	provider, edge := pair(t, RoleProvider, providerCfg, cfg)
	first := serveRequest()
	first.FlowID = "first"
	a, b := exchange(t, edge, provider, first)
	_ = a.Close()
	<-b.Context().Done()
	second := serveRequest()
	second.FlowID = "second"
	if _, err := edge.Open(t.Context(), second); !errors.Is(err, ErrStreamLimit) && !errors.Is(err, ErrDuplicateFlow) {
		t.Fatalf("full replay ledger admitted a flow: %v", err)
	}
	if _, err := edge.Open(t.Context(), first); !errors.Is(err, ErrDuplicateFlow) && !errors.Is(err, ErrStreamLimit) {
		t.Fatalf("recent flow ID was reused: %v", err)
	}
	time.Sleep(350 * time.Millisecond)
	for edge.mux.NumStreams() > 1 {
		time.Sleep(time.Millisecond)
	}
	exchange(t, edge, provider, second)
}

func TestPeerLeaseToleratesBoundedClockSkew(t *testing.T) {
	t.Parallel()
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve, MaxLeaseDuration: 20 * time.Second, MaxClockSkew: 10 * time.Second}, Config{})
	r := serveRequest()
	r.Deadline = time.Now().Add(time.Hour)
	r.LeaseExpiresAt = time.Now().Add(25 * time.Second)
	exchange(t, edge, provider, r)
	r.FlowID, r.LeaseExpiresAt = "", time.Now().Add(40*time.Second)
	if _, err := edge.Open(t.Context(), r); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("lease beyond the skew allowance was accepted: %v", err)
	}
}

func TestSessionCloseAndAcceptCancellation(t *testing.T) {
	t.Parallel()
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := provider.Accept(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("accept cancellation: %v", err)
	}
	a, b := exchange(t, edge, provider, serveRequest())
	_ = edge.Close()
	for _, stream := range []*Stream{a, b} {
		select {
		case <-stream.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("stream survived session close")
		}
	}
	if _, err := provider.Accept(t.Context()); !errors.Is(err, ErrClosed) {
		t.Fatalf("accept after session close: %v", err)
	}
}
