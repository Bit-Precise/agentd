// SPDX-License-Identifier: MPL-2.0
package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type ClientConfig struct {
	// HTTPClient supplies TLS trust and connection pooling. Timeout must be zero
	// because the GET response lasts for the connection lifetime. Redirects are
	// disabled regardless of its CheckRedirect setting. Clients must support at
	// least two connections to the origin for HTTP/1.1.
	HTTPClient *http.Client
	Headers    http.Header
	AllowHTTP  bool // explicit loopback-only development exception
	// MaxEachPostBytes is Xray's scMaxEachPostBytes: the largest POST body and
	// the size of the upload buffer. It must not exceed the server's value.
	MaxEachPostBytes int
	// MinPostsInterval is Xray's scMinPostsIntervalMs: the minimum time between
	// the starts of two POSTs. It bounds the request rate seen by a CDN.
	MinPostsInterval time.Duration
	// MaxQueuedPackets bounds received download chunks not yet read.
	MaxQueuedPackets int
	HandshakeTimeout time.Duration
	PostTimeout      time.Duration
}

// Dial establishes an agents packet-up connection. ctx controls BOTH
// establishment and connection lifetime. Cancelling it closes the connection.
//
// Uploads follow Xray-core's packet-up client: Write only buffers bytes, an
// uploader takes everything buffered at once (so small writes coalesce), and
// each POST runs concurrently, the next one starting as soon as the previous
// request has been written. A failed POST closes the connection.
func Dial(ctx context.Context, endpoint string, cfg ClientConfig) (net.Conn, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("xhttp: invalid endpoint")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && cfg.AllowHTTP && loopbackHost(u.Hostname())) {
		return nil, errors.New("xhttp: HTTPS required (HTTP exception is loopback-only)")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || query.Has(SessionQuery) || query.Has(SequenceQuery) {
		return nil, errors.New("xhttp: invalid or reserved endpoint query")
	}
	if cfg.MaxEachPostBytes == 0 {
		cfg.MaxEachPostBytes = defaultMaxEachPostBytes
	}
	if cfg.MinPostsInterval == 0 {
		cfg.MinPostsInterval = defaultMinPostsInterval
	}
	if cfg.MaxQueuedPackets == 0 {
		cfg.MaxQueuedPackets = 8
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.PostTimeout == 0 {
		cfg.PostTimeout = 15 * time.Second
	}
	if cfg.MaxEachPostBytes < 1 || cfg.MaxEachPostBytes > 16<<20 || cfg.MinPostsInterval < 0 || cfg.MinPostsInterval > time.Minute ||
		cfg.MaxQueuedPackets < 1 || cfg.MaxQueuedPackets > 1024 || cfg.HandshakeTimeout < 0 || cfg.PostTimeout < 0 {
		return nil, errors.New("xhttp: invalid client limit")
	}
	client := http.Client{}
	var ownedTransport *http.Transport
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
		if client.Timeout != 0 {
			return nil, errors.New("xhttp: HTTPClient.Timeout must be zero")
		}
	} else {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("xhttp: custom default transport requires an explicit HTTPClient")
		}
		ownedTransport = base.Clone()
		ownedTransport.DisableCompression = true
		ownedTransport.ForceAttemptHTTP2 = true
		ownedTransport.ResponseHeaderTimeout = cfg.HandshakeTimeout
		client.Transport = ownedTransport
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	headers := cfg.Headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	headers.Set(VersionHeader, Version)
	// Session IDs correlate requests, but are not authentication credentials.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	query.Set(SessionQuery, hex.EncodeToString(idBytes))
	u.RawQuery = query.Encode()
	c := newConn(ctx, cfg.MaxQueuedPackets, cfg.MaxEachPostBytes)
	c.remote = address(u.Host)
	c.local = address("xhttp-client")
	request, err := http.NewRequestWithContext(c.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	request.Header = headers.Clone()
	timeoutDone := make(chan struct{})
	timeout := time.AfterFunc(cfg.HandshakeTimeout, func() {
		c.closeWithError(&timeoutError{"dial"})
		close(timeoutDone)
	})
	response, err := client.Do(request)
	if !timeout.Stop() {
		<-timeoutDone
	}
	if err != nil {
		c.closeWithError(err)
		if ownedTransport != nil {
			ownedTransport.CloseIdleConnections()
		}
		return nil, c.closedError()
	}
	if response.StatusCode != http.StatusOK || response.Header.Get(VersionHeader) != Version {
		response.Body.Close()
		c.Close()
		if ownedTransport != nil {
			ownedTransport.CloseIdleConnections()
		}
		return nil, fmt.Errorf("xhttp: GET rejected (status %d or transport version %q, want %q)", response.StatusCode, response.Header.Get(VersionHeader), Version)
	}
	c.onClose = func() {
		response.Body.Close()
		if ownedTransport != nil {
			ownedTransport.CloseIdleConnections()
		}
	}
	select {
	case <-c.done:
		response.Body.Close()
		return nil, c.closedError()
	default:
	}
	post := func(seq uint64, packet []byte, wrote func()) error {
		postURL := *u
		q := postURL.Query()
		q.Set(SequenceQuery, strconv.FormatUint(seq, 10))
		postURL.RawQuery = q.Encode()
		// Closing the connection cancels its in-flight POSTs. PostTimeout bounds
		// a POST that never completes, which then closes the connection.
		opCtx, cancel := context.WithTimeout(c.ctx, cfg.PostTimeout)
		defer cancel()
		opCtx = httptrace.WithClientTrace(opCtx, &httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { wrote() }})
		req, err := http.NewRequestWithContext(opCtx, http.MethodPost, postURL.String(), bytes.NewReader(packet))
		if err != nil {
			return err
		}
		req.Header = headers.Clone()
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("xhttp: upload failed: %w", err)
		}
		// The protocol response is empty. Bound draining even for a broken peer.
		_, drainErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent || resp.Header.Get(VersionHeader) != Version {
			return fmt.Errorf("xhttp: POST rejected (status %d or version mismatch)", resp.StatusCode)
		}
		return drainErr
	}
	upload := newUploadPipe(cfg.MaxEachPostBytes)
	c.writePacket = func(packet []byte) error { return upload.put(c, packet) }
	c.startContextWatch()
	go func() {
		var seq uint64
		var lastPost time.Time
		for {
			// Everything buffered since the previous POST goes out together.
			data, ok := upload.take(c.done)
			if !ok {
				return
			}
			for len(data) > 0 {
				chunk := data[:min(len(data), cfg.MaxEachPostBytes)]
				data = data[len(chunk):]
				if seq == math.MaxUint64 {
					c.closeWithError(errors.New("xhttp: sequence exhausted"))
					return
				}
				current := seq
				seq++
				if wait := cfg.MinPostsInterval - time.Since(lastPost); wait > 0 {
					timer := time.NewTimer(wait)
					select {
					case <-timer.C:
					case <-c.done:
						timer.Stop()
						return
					}
				}
				lastPost = time.Now()
				wrote := make(chan struct{})
				var once sync.Once
				markWrote := func() { once.Do(func() { close(wrote) }) }
				go func() {
					err := post(current, chunk, markWrote)
					markWrote()
					if err != nil {
						// Delivery is uncertain after a failed POST. Never continue
						// with a gap in the byte stream; close this connection.
						c.closeWithError(err)
					}
				}()
				// Start the next POST once this request is on the wire, not after
				// its response, so uploads are not limited to one per round trip.
				select {
				case <-wrote:
				case <-c.done:
					return
				}
			}
		}
	}()
	go func() {
		for {
			packet := make([]byte, downloadChunk)
			n, err := response.Body.Read(packet)
			if n > 0 {
				select {
				case c.in <- packet[:n]:
				case <-c.done:
					return
				}
			}
			if err != nil {
				c.closeWithError(normalizeReadError(err))
				return
			}
		}
	}()
	return c, nil
}

// uploadPipe mirrors Xray's size-limited upload pipe. Write returns once its
// bytes are buffered and blocks while a full POST's worth is waiting; the
// uploader removes everything buffered at once.
type uploadPipe struct {
	mu    sync.Mutex
	buf   []byte
	limit int
	data  chan struct{}
	space chan struct{}
}

func newUploadPipe(limit int) *uploadPipe {
	return &uploadPipe{limit: limit, data: make(chan struct{}, 1), space: make(chan struct{}, 1)}
}

// put runs under the connection's write lock, so it has a single caller. The
// write deadline bounds only the wait for buffer space.
func (p *uploadPipe) put(c *conn, chunk []byte) error {
	for {
		select {
		case <-c.done:
			return c.closedError()
		default:
		}
		p.mu.Lock()
		if len(p.buf) == 0 || len(p.buf)+len(chunk) <= p.limit {
			p.buf = append(p.buf, chunk...)
			p.mu.Unlock()
			select {
			case p.data <- struct{}{}:
			default:
			}
			return nil
		}
		p.mu.Unlock()
		at, changed := c.wd.watch()
		if !at.IsZero() && !time.Now().Before(at) {
			return &timeoutError{"write"}
		}
		tick, stop := timerFor(at)
		select {
		case <-p.space:
		case <-changed:
		case <-tick:
			stop()
			return &timeoutError{"write"}
		case <-c.done:
			stop()
			return c.closedError()
		}
		stop()
	}
}

func (p *uploadPipe) take(done <-chan struct{}) ([]byte, bool) {
	for {
		p.mu.Lock()
		if len(p.buf) > 0 {
			data := p.buf
			p.buf = nil
			p.mu.Unlock()
			select {
			case p.space <- struct{}{}:
			default:
			}
			return data, true
		}
		p.mu.Unlock()
		select {
		case <-p.data:
		case <-done:
			return nil, false
		}
	}
}
