package connection

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func leasedRequest(lease, hard time.Duration) OpenRequest {
	r := serveRequest()
	r.Deadline = time.Now().Add(hard)
	r.LeaseExpiresAt = time.Now().Add(lease)
	return r
}

func TestRenewLeaseSurvivesOriginalTimerAndKeepsHardScope(t *testing.T) {
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	r := leasedRequest(180*time.Millisecond, 800*time.Millisecond)
	a, b := exchange(t, edge, provider, r)
	deadline := time.Now().Add(500 * time.Millisecond)
	if err := a.RenewLease(t.Context(), deadline); err != nil {
		t.Fatal(err)
	}
	if !a.Claims().LeaseExpiresAt.Equal(b.Claims().LeaseExpiresAt) || !a.Claims().Deadline.Equal(r.Deadline) {
		t.Fatal("lease ACK or immutable deadline mismatch")
	}
	time.Sleep(240 * time.Millisecond)
	select {
	case <-a.Context().Done():
		t.Fatal("stale original timer canceled renewed stream")
	case <-b.Context().Done():
		t.Fatal("peer original timer canceled renewed stream")
	default:
	}
	written := make(chan error, 1)
	go func() { _, err := b.Write([]byte("live")); written <- err }()
	data := make([]byte, 4)
	if _, err := io.ReadFull(a, data); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if string(data) != "live" {
		t.Fatal("renewed stream lost bytes")
	}
	if err := a.RenewLease(t.Context(), r.Deadline.Add(time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("extended hard deadline: %v", err)
	}
	if err := b.RenewLease(t.Context(), deadline.Add(time.Millisecond)); !errors.Is(err, ErrRole) {
		t.Fatalf("client granted its own lease: %v", err)
	}
}

func TestRenewLeaseRechecksProviderAndPreservesSibling(t *testing.T) {
	var deny atomic.Bool
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: func(ctx context.Context, p Principal, r OpenRequest) (OpenClaims, error) {
		if deny.Load() && r.Resource == "demo" {
			return OpenClaims{}, ErrUnauthorized
		}
		return approve(ctx, p, r)
	}}, Config{})
	a, b := exchange(t, edge, provider, leasedRequest(300*time.Millisecond, time.Second))
	siblingRequest := leasedRequest(300*time.Millisecond, time.Second)
	siblingRequest.Resource = "api"
	sibling, _ := exchange(t, edge, provider, siblingRequest)
	deny.Store(true)
	if err := a.RenewLease(t.Context(), time.Now().Add(600*time.Millisecond)); err == nil {
		t.Fatal("renewal ignored local policy withdrawal")
	}
	select {
	case <-b.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("denied receiver lease stayed live")
	}
	if err := sibling.RenewLease(t.Context(), time.Now().Add(600*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-edge.Done():
		t.Fatal("single flow denial closed shared session")
	case <-sibling.Context().Done():
		t.Fatal("single flow denial canceled sibling")
	default:
	}
}

func TestRenewalCannotChangeAuthorizedScope(t *testing.T) {
	var calls atomic.Int32
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: func(ctx context.Context, p Principal, r OpenRequest) (OpenClaims, error) {
		c, err := approve(ctx, p, r)
		if calls.Add(1) > 1 {
			c.Resource = "other-service"
		}
		return c, err
	}}, Config{})
	a, _ := exchange(t, edge, provider, leasedRequest(300*time.Millisecond, time.Second))
	if err := a.RenewLease(t.Context(), time.Now().Add(600*time.Millisecond)); err == nil {
		t.Fatal("renewal changed original resource")
	}
}

func TestAccessLeaseRenewedOnlyByEdge(t *testing.T) {
	client, edge := pair(t, RoleAccess, Config{}, Config{AuthorizeOpen: func(ctx context.Context, p Principal, r OpenRequest) (OpenClaims, error) {
		c, err := approve(ctx, p, r)
		c.LeaseExpiresAt = time.Now().Add(180 * time.Millisecond)
		return c, err
	}})
	r := OpenRequest{Purpose: PurposeAccess, Destination: Destination{Host: "oa.example", Port: 443}, Protocol: "tls", Deadline: time.Now().Add(time.Second)}
	a, b := exchange(t, client, edge, r)
	if err := b.RenewLease(t.Context(), time.Now().Add(500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(230 * time.Millisecond)
	select {
	case <-a.Context().Done():
		t.Fatal("access peer was not renewed")
	default:
	}
	if !a.Claims().LeaseExpiresAt.Equal(b.Claims().LeaseExpiresAt) {
		t.Fatal("access lease differs across peers")
	}
}

func TestRenewalPreservesExplicitIODeadline(t *testing.T) {
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	a, b := exchange(t, edge, provider, leasedRequest(300*time.Millisecond, time.Second))
	a.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if err := a.RenewLease(t.Context(), time.Now().Add(600*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := a.Read(make([]byte, 1))
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		t.Fatalf("renewal cleared caller deadline: %v", err)
	}
	select {
	case <-a.Context().Done():
		t.Fatal("IO deadline canceled authorization lease")
	default:
	}
	a.SetReadDeadline(time.Time{})
	go func() { _, _ = b.Write([]byte("x")) }()
	if _, err := io.ReadFull(a, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestLostRenewalAckCannotExtendSenderOrResurrectPeer(t *testing.T) {
	entered := make(chan struct{})
	allow := make(chan struct{})
	var calls atomic.Int32
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: func(ctx context.Context, p Principal, r OpenRequest) (OpenClaims, error) {
		if calls.Add(1) > 1 {
			close(entered)
			select {
			case <-allow:
			case <-ctx.Done():
				return OpenClaims{}, ctx.Err()
			}
		}
		return approve(ctx, p, r)
	}}, Config{})
	a, b := exchange(t, edge, provider, leasedRequest(300*time.Millisecond, 2*time.Second))
	newExpiry := time.Now().Add(550 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- a.RenewLease(ctx, newExpiry) }()
	<-entered
	// Block ACK dispatch and peer CANCEL handling, but not either lease timer.
	// This models a lost control response without optimistic local extension.
	edge.mu.Lock()
	provider.mu.Lock()
	locked := true
	defer func() {
		if locked {
			provider.mu.Unlock()
			edge.mu.Unlock()
		}
	}()
	close(allow)
	until := time.Now().Add(150 * time.Millisecond)
	for !b.Claims().LeaseExpiresAt.Equal(newExpiry) {
		if time.Now().After(until) {
			t.Fatal("receiver did not apply proposed lease")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-a.Context().Done():
	case <-time.After(250 * time.Millisecond):
		t.Fatal("sender continued without timely ACK")
	}
	select {
	case <-b.Context().Done():
		t.Fatal("receiver lost valid bounded lease before timer")
	default:
	}
	select {
	case <-b.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("unacknowledged peer lease did not expire")
	}
	if err := b.applyRenewal(2, time.Now().Add(time.Second)); err == nil {
		t.Fatal("expired stream resurrected")
	}
	provider.mu.Unlock()
	edge.mu.Unlock()
	locked = false
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing ACK did not fail closed: %v", err)
	}
}

func TestRenewalSequenceReplayClosesOnlyAffectedStream(t *testing.T) {
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	a, b := exchange(t, edge, provider, leasedRequest(200*time.Millisecond, time.Second))
	expiry := time.Now().Add(500 * time.Millisecond)
	if err := a.RenewLease(t.Context(), expiry); err != nil {
		t.Fatal(err)
	}
	edge.controls <- controlMessage{Type: "renew", FlowID: a.Request().FlowID, Sequence: 1, LeaseExpiresAt: expiry}
	select {
	case <-b.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("replayed sequence accepted")
	}
	if err := b.applyRenewal(2, time.Now().Add(600*time.Millisecond)); err == nil {
		t.Fatal("closed stream revived")
	}
	select {
	case <-provider.Done():
		t.Fatal("replay on one flow closed session")
	default:
	}
}

func TestImmediatelyConsecutiveRenewals(t *testing.T) {
	provider, edge := pair(t, RoleProvider, Config{AuthorizeOpen: approve}, Config{})
	a, b := exchange(t, edge, provider, leasedRequest(200*time.Millisecond, 3*time.Second))
	for i := 0; i < 30; i++ {
		expiry := time.Now().Add(time.Second + time.Duration(i)*time.Millisecond)
		if err := a.RenewLease(t.Context(), expiry); err != nil {
			t.Fatalf("renewal %d: %v", i, err)
		}
		if !a.Claims().LeaseExpiresAt.Equal(b.Claims().LeaseExpiresAt) {
			t.Fatal("ACK did not identify applied lease")
		}
	}
}
