// SPDX-License-Identifier: MPL-2.0
package xhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testAuth(r *http.Request) (string, error) {
	switch r.Header.Get("Authorization") {
	case "Bearer alice":
		return "alice", nil
	case "Bearer bob":
		return "bob", nil
	default:
		return "", errors.New("invalid credentials")
	}
}

func setup(t *testing.T, h2 bool, cfg ServerConfig) (*Handler, *httptest.Server, ClientConfig) {
	t.Helper()
	if cfg.Authorize == nil {
		cfg.Authorize = testAuth
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = h2
	ts.StartTLS()
	t.Cleanup(func() { h.Close(); ts.Close(); ts.Client().CloseIdleConnections() })
	return h, ts, ClientConfig{HTTPClient: ts.Client(), Headers: http.Header{"Authorization": {"Bearer alice"}}}
}

func mustDial(t *testing.T, endpoint string, cfg ClientConfig) net.Conn {
	t.Helper()
	c, err := Dial(context.Background(), endpoint, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func mustAccept(t *testing.T, h *Handler) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := h.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for !f() {
		if time.Now().After(until) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRoundTripConcurrentHTTPVersions(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			var observed atomic.Int32
			h, ts, cfg := setup(t, h2, ServerConfig{MaxSessionsPerPrincipal: 32, Authorize: func(r *http.Request) (string, error) {
				observed.Store(int32(r.ProtoMajor))
				return testAuth(r)
			}})
			cfg.PacketSize = 4096
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var echo sync.WaitGroup
			go func() {
				for {
					c, err := h.Accept(ctx)
					if err != nil {
						return
					}
					echo.Add(1)
					go func() { defer echo.Done(); defer c.Close(); io.Copy(c, c) }()
				}
			}()
			var clients sync.WaitGroup
			errs := make(chan error, 8)
			for i := 0; i < 8; i++ {
				clients.Add(1)
				go func(i int) {
					defer clients.Done()
					c, err := Dial(ctx, ts.URL+"/agent", cfg)
					if err != nil {
						errs <- err
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte(fmt.Sprintf("client-%d-", i)), 16384)
					written := make(chan error, 1)
					go func() { _, err := c.Write(payload); written <- err }()
					got := make([]byte, len(payload))
					_, err = io.ReadFull(c, got)
					if err != nil {
						errs <- err
						return
					}
					if err = <-written; err != nil {
						errs <- err
						return
					}
					if !bytes.Equal(payload, got) {
						errs <- errors.New("mixed or corrupted connection bytes")
					}
				}(i)
			}
			clients.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			eventually(t, func() bool { return h.ActiveSessions() == 0 })
			h.Close()
			cancel()
			echo.Wait()
			want := int32(1)
			if h2 {
				want = 2
			}
			if observed.Load() != want {
				t.Fatalf("HTTP version %d, want %d", observed.Load(), want)
			}
		})
	}
}

func rawGET(t *testing.T, client *http.Client, endpoint, id, token string) (*http.Response, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?session="+id, nil)
	r.Header.Set(VersionHeader, Version)
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(r)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); resp.Body.Close() })
	return resp, cancel
}

func rawPOST(t *testing.T, client *http.Client, endpoint, id, seq, token string, body []byte) int {
	t.Helper()
	r, _ := http.NewRequest(http.MethodPost, endpoint+"?session="+id+"&seq="+seq, bytes.NewReader(body))
	r.Header.Set(VersionHeader, Version)
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestOrderingDuplicatesAndPrincipalIsolation(t *testing.T) {
	var authCalls atomic.Int32
	h, ts, _ := setup(t, true, ServerConfig{MaxReorderPackets: 2, Authorize: func(r *http.Request) (string, error) {
		authCalls.Add(1)
		return testAuth(r)
	}})
	id := strings.Repeat("a", 32)
	resp, _ := rawGET(t, ts.Client(), ts.URL+"/agent", id, "alice")
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	c := mustAccept(t, h)
	c.SetReadDeadline(time.Now().Add(time.Second))
	checks := []struct {
		path, seq, token, data string
		status                 int
	}{
		{"/agent", "0", "bob", "wrong", 404},
		{"/different", "0", "alice", "wrong", 404},
		{"/agent", "1", "alice", "world", 204},
		{"/agent", "1", "alice", "world", 204},
		{"/agent", "1", "alice", "changed", 409},
		{"/agent", "0", "alice", "hello", 204},
		{"/agent", "0", "alice", "hello", 204},
		{"/agent", "1000", "alice", "too-far", 409},
		{"/agent", "02", "alice", "invalid", 400},
	}
	for _, v := range checks {
		if got := rawPOST(t, ts.Client(), ts.URL+v.path, id, v.seq, v.token, []byte(v.data)); got != v.status {
			t.Fatalf("POST %s/%s/%s status=%d want=%d", v.path, v.seq, v.token, got, v.status)
		}
	}
	got := make([]byte, 10)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "helloworld" {
		t.Fatalf("got %q", got)
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	assertTimeout(t, err)
	if authCalls.Load() != int32(len(checks)+1) {
		t.Fatal("not every request was authorized")
	}
}

func TestLimitsAndAuthorization(t *testing.T) {
	h, ts, cfg := setup(t, false, ServerConfig{MaxSessions: 1, MaxPacketBytes: 4})
	if _, err := NewHandler(ServerConfig{}); err == nil {
		t.Fatal("missing authorizer accepted")
	}
	bad := cfg
	bad.Headers = nil
	if _, err := Dial(context.Background(), ts.URL, bad); err == nil {
		t.Fatal("unauthorized GET accepted")
	}
	id := strings.Repeat("b", 32)
	resp, cancel := rawGET(t, ts.Client(), ts.URL, id, "alice")
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	if _, err := Dial(context.Background(), ts.URL, cfg); err == nil {
		t.Fatal("session limit not enforced")
	}
	if got := rawPOST(t, ts.Client(), ts.URL, id, "0", "alice", []byte("large")); got != 413 {
		t.Fatal(got)
	}
	if got := rawPOST(t, ts.Client(), ts.URL, id, "0", "alice", nil); got != 400 {
		t.Fatal(got)
	}
	if got := rawPOST(t, ts.Client(), ts.URL, id, "0", "unknown", []byte("x")); got != 401 {
		t.Fatal(got)
	}
	cancel()
	resp.Body.Close()
	eventually(t, func() bool { return h.ActiveSessions() == 0 })
}

func assertTimeout(t *testing.T, err error) {
	t.Helper()
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func TestReadDeadlineResetAndUpdate(t *testing.T) {
	h, ts, cfg := setup(t, true, ServerConfig{})
	c := mustDial(t, ts.URL, cfg)
	peer := mustAccept(t, h)
	for _, pair := range [][2]net.Conn{{c, peer}, {peer, c}} {
		reader, writer := pair[0], pair[1]
		reader.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		_, err := reader.Read(make([]byte, 1))
		assertTimeout(t, err)
		reader.SetReadDeadline(time.Time{})
		wrote := make(chan error, 1)
		go func() { _, err := writer.Write([]byte("x")); wrote <- err }()
		b := make([]byte, 1)
		if _, err := io.ReadFull(reader, b); err != nil {
			t.Fatal(err)
		}
		if err := <-wrote; err != nil {
			t.Fatal(err)
		}
		reader.SetReadDeadline(time.Now().Add(time.Hour))
		read := make(chan error, 1)
		go func() { _, err := reader.Read(b); read <- err }()
		reader.SetReadDeadline(time.Now().Add(-time.Second))
		select {
		case err := <-read:
			assertTimeout(t, err)
		case <-time.After(time.Second):
			t.Fatal("deadline update did not wake Read")
		}
		reader.SetReadDeadline(time.Time{})
	}
}

func TestWriteDeadlineCancelsPOST(t *testing.T) {
	h, err := NewHandler(ServerConfig{Authorize: testAuth})
	if err != nil {
		t.Fatal(err)
	}
	postCancelled := make(chan struct{}, 1)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			postCancelled <- struct{}{}
			return
		}
		h.ServeHTTP(w, r)
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(func() { h.Close(); ts.Close() })
	c := mustDial(t, ts.URL, ClientConfig{HTTPClient: ts.Client(), Headers: http.Header{"Authorization": {"Bearer alice"}}})
	mustAccept(t, h)
	c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = c.Write([]byte("blocked"))
	assertTimeout(t, err)
	select {
	case <-postCancelled:
	case <-time.After(time.Second):
		t.Fatal("POST context not cancelled")
	}
	eventually(t, func() bool { return h.ActiveSessions() == 0 })
}

func TestServerWriteDeadlineBoundsUnconsumedQueue(t *testing.T) {
	c := newConn(context.Background(), 1, 1024)
	s := &serverSession{c: c, out: make(chan *outPacket, 1)}
	c.writePacket = s.send
	c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	_, err := c.Write([]byte("never consumed"))
	assertTimeout(t, err)
	select {
	case <-c.done:
	default:
		t.Fatal("uncertain timed-out write did not close connection")
	}
}

func TestContextCancellationAndHandlerClose(t *testing.T) {
	h, ts, cfg := setup(t, true, ServerConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	c, err := Dial(ctx, ts.URL, cfg)
	if err != nil {
		t.Fatal(err)
	}
	peer := mustAccept(t, h)
	read := make(chan error, 1)
	go func() { _, err := peer.Read(make([]byte, 1)); read <- err }()
	cancel()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("cancelled read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not reach server")
	}
	c.Close()
	eventually(t, func() bool { return h.ActiveSessions() == 0 })
	conns := []net.Conn{}
	for i := 0; i < 4; i++ {
		conns = append(conns, mustDial(t, ts.URL, cfg))
		mustAccept(t, h)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if h.ActiveSessions() != 0 {
		t.Fatal("sessions leaked after Close")
	}
	if _, err := h.Accept(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, err := c.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("closed handler left a connection alive")
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("Close did not unblock client Read")
		}
	}
}

func TestHTTPSAndRedirectDefaults(t *testing.T) {
	for _, endpoint := range []string{"http://127.0.0.1:1", "http://example.com", "https://user:pass@example.com", "https://example.com?session=x"} {
		if _, err := Dial(context.Background(), endpoint, ClientConfig{}); err == nil {
			t.Fatalf("accepted %s", endpoint)
		}
	}
	if _, err := Dial(context.Background(), "http://example.com", ClientConfig{AllowHTTP: true}); err == nil {
		t.Fatal("non-loopback HTTP accepted")
	}
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client := redirect.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	if _, err := Dial(context.Background(), redirect.URL, ClientConfig{HTTPClient: client}); err == nil {
		t.Fatal("redirect accepted")
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect target received credentials")
	}
}

func TestHTTPExplicitLoopbackAndIdleCleanup(t *testing.T) {
	h, err := NewHandler(ServerConfig{Authorize: testAuth, AllowHTTP: true, SessionIdleTimeout: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()
	defer h.Close()
	c := mustDial(t, ts.URL, ClientConfig{AllowHTTP: true, Headers: http.Header{"Authorization": {"Bearer alice"}}})
	mustAccept(t, h)
	c.SetReadDeadline(time.Now().Add(time.Second))
	_, err = c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("idle session stayed open")
	}
	eventually(t, func() bool { return h.ActiveSessions() == 0 })
}

func TestReorderMemoryIsBounded(t *testing.T) {
	c := newConn(context.Background(), 1, 8)
	defer c.Close()
	s := &serverSession{c: c, packets: make(map[uint64][]byte), recent: make(map[uint64][32]byte), ready: make(chan struct{}, 1)}
	for i := uint64(1); i < 100; i++ {
		status := s.receive(i, []byte(strconv.FormatUint(i, 10)), 2)
		if i <= 2 && status != 204 {
			t.Fatal(status)
		}
		if i > 2 && status != 409 {
			t.Fatal(status)
		}
	}
	if len(s.packets) != 2 {
		t.Fatal("reorder window is not bounded")
	}
}

func TestSequentialUploadBackpressure(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			h, ts, cfg := setup(t, h2, ServerConfig{MaxPacketBytes: 4, MaxQueuedPackets: 1, MaxReorderPackets: 1})
			cfg.PacketSize = 4
			c := mustDial(t, ts.URL, cfg)
			peer := mustAccept(t, h)
			payload := bytes.Repeat([]byte("abcd"), 32)
			written := make(chan error, 1)
			go func() { _, err := c.Write(payload); written <- err }()
			select {
			case err := <-written:
				t.Fatalf("upload did not apply backpressure: %v", err)
			case <-time.After(75 * time.Millisecond):
			}
			peer.SetReadDeadline(time.Now().Add(2 * time.Second))
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(peer, got); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("bytes lost after backpressure")
			}
		})
	}
}

func TestHandshakeTimeout(t *testing.T) {
	ended := make(chan struct{}, 1)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		ended <- struct{}{}
	}))
	defer ts.Close()
	_, err := Dial(context.Background(), ts.URL, ClientConfig{HTTPClient: ts.Client(), HandshakeTimeout: 40 * time.Millisecond})
	assertTimeout(t, err)
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("handshake request leaked")
	}
}

func TestCloseInterruptsSlowPOSTBody(t *testing.T) {
	h, ts, _ := setup(t, true, ServerConfig{PostTimeout: time.Minute})
	id := strings.Repeat("c", 32)
	resp, _ := rawGET(t, ts.Client(), ts.URL, id, "alice")
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	mustAccept(t, h)
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"?session="+id+"&seq=0", reader)
	r.Header.Set(VersionHeader, Version)
	r.Header.Set("Authorization", "Bearer alice")
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		res, _ := ts.Client().Do(r)
		if res != nil {
			res.Body.Close()
		}
	}()
	eventually(t, func() bool { return len(h.postSlots) == 1 })
	h.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("Close left POST body blocked")
	}
}

func TestCloseDiscardsQueuedBytesButEOFDrains(t *testing.T) {
	for _, terminal := range []error{net.ErrClosed, io.EOF} {
		c := newConn(context.Background(), 1, 8)
		c.in <- []byte("x")
		c.closeWithError(terminal)
		b := make([]byte, 1)
		n, err := c.Read(b)
		if errors.Is(terminal, io.EOF) {
			if n != 1 || err != nil || b[0] != 'x' {
				t.Fatalf("EOF lost queued byte: n=%d err=%v", n, err)
			}
			if _, err := c.Read(b); !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
		} else if n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Close delivered data: n=%d err=%v", n, err)
		}
	}
}

func TestHTTP2WriteDeadlineDoesNotExpireIdleSession(t *testing.T) {
	h, ts, cfg := setup(t, true, ServerConfig{WriteTimeout: 40 * time.Millisecond, SessionIdleTimeout: 2 * time.Second})
	c := mustDial(t, ts.URL, cfg)
	peer := mustAccept(t, h)
	writeAndRead := func(writer, reader net.Conn, data string) {
		t.Helper()
		wrote := make(chan error, 1)
		go func() { _, err := writer.Write([]byte(data)); wrote <- err }()
		reader.SetReadDeadline(time.Now().Add(time.Second))
		got := make([]byte, len(data))
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatal(err)
		}
		if err := <-wrote; err != nil {
			t.Fatal(err)
		}
		if string(got) != data {
			t.Fatalf("got %q", got)
		}
		reader.SetReadDeadline(time.Time{})
	}
	time.Sleep(150 * time.Millisecond)
	if h.ActiveSessions() != 1 {
		t.Fatal("HTTP/2 header write deadline expired an idle session")
	}
	writeAndRead(peer, c, "first")
	time.Sleep(150 * time.Millisecond)
	if h.ActiveSessions() != 1 {
		t.Fatal("HTTP/2 write deadline expired an idle session")
	}
	writeAndRead(peer, c, "second")
	writeAndRead(c, peer, "upload still works")
}

func TestConcurrentReadPreservesFinalPacketBeforeEOF(t *testing.T) {
	for i := 0; i < 2000; i++ {
		c := newConn(context.Background(), 1, 8)
		result := make(chan error, 1)
		go func() {
			data := make([]byte, 4)
			_, err := io.ReadFull(c, data)
			if err == nil && string(data) != "tail" {
				err = fmt.Errorf("corrupt tail %q", data)
			}
			result <- err
		}()
		runtime.Gosched()
		c.in <- []byte("tail")
		c.closeWithError(io.EOF)
		if err := <-result; err != nil {
			t.Fatalf("iteration %d: lost tail packet: %v", i, err)
		}
	}
}

func TestAcceptedPrincipalMetadata(t *testing.T) {
	h, ts, cfg := setup(t, true, ServerConfig{})
	client := mustDial(t, ts.URL, cfg)
	accepted := mustAccept(t, h)
	if principal, ok := AuthenticatedPrincipal(accepted); !ok || principal != "alice" {
		t.Fatalf("missing accepted identity: %q %v", principal, ok)
	}
	if _, ok := AuthenticatedPrincipal(client); ok {
		t.Fatal("client-side connection claimed server-authorized identity")
	}
}
