package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

type failedRead struct{ net.Conn }

func (c failedRead) Read([]byte) (int, error) { return 0, errors.New("remote flow canceled") }

type scopedFIN struct {
	net.Conn
	ctx context.Context
}

func (c scopedFIN) Context() context.Context { return c.ctx }
func (c scopedFIN) Read([]byte) (int, error) { return 0, io.EOF }

func TestPipeExpiryAfterFINReleasesSilentClient(t *testing.T) {
	t.Parallel()
	_, proxy := tcpPair(t)
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { Pipe(context.Background(), proxy, scopedFIN{Conn: a, ctx: ctx}); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("flow expiry after FIN left local reader blocked")
	}
}

func TestPipeErrorReleasesSilentClient(t *testing.T) {
	t.Parallel()
	client, proxy := tcpPair(t)
	_ = client
	a, b := net.Pipe()
	defer b.Close()
	done := make(chan struct{})
	go func() { Pipe(context.Background(), proxy, failedRead{a}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("error left the reverse direction blocked on a silent client")
	}
}

func TestPipePreservesHalfClosedResponse(t *testing.T) {
	t.Parallel()
	client, left := tcpPair(t)
	right, origin := tcpPair(t)
	done := make(chan struct{})
	go func() { Pipe(context.Background(), left, right); close(done) }()
	_, _ = io.WriteString(client, "request")
	_ = client.CloseWrite()
	request, err := io.ReadAll(origin)
	if err != nil || string(request) != "request" {
		t.Fatalf("request %q: %v", request, err)
	}
	_, _ = io.WriteString(origin, "response after request FIN")
	_ = origin.CloseWrite()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "response after request FIN" {
		t.Fatalf("response %q: %v", response, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("completed pipe did not exit")
	}
}
