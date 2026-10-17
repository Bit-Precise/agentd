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
	"net/url"
	"strconv"
	"time"
)

type ClientConfig struct {
	// HTTPClient supplies TLS trust and connection pooling. Timeout must be zero
	// because the GET response lasts for the connection lifetime. Redirects are
	// disabled regardless of its CheckRedirect setting. Clients must support at
	// least two connections to the origin for HTTP/1.1.
	HTTPClient       *http.Client
	Headers          http.Header
	AllowHTTP        bool // explicit loopback-only development exception
	PacketSize       int
	MaxQueuedPackets int
	HandshakeTimeout time.Duration
	PostTimeout      time.Duration
}

// Dial establishes a modified agents packet-up connection. ctx controls BOTH
// establishment and connection lifetime. Cancelling it closes the connection.
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
	if cfg.PacketSize == 0 {
		cfg.PacketSize = defaultPacket
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
	if cfg.PacketSize < 1 || cfg.PacketSize > 4<<20 || cfg.MaxQueuedPackets < 1 || cfg.MaxQueuedPackets > 1024 || cfg.HandshakeTimeout < 0 || cfg.PostTimeout < 0 {
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
	c := newConn(ctx, cfg.MaxQueuedPackets, cfg.PacketSize)
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
		return nil, fmt.Errorf("xhttp: GET rejected (status %d or version mismatch)", response.StatusCode)
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
	var seq uint64
	c.writePacket = func(packet []byte) error {
		if seq == math.MaxUint64 {
			c.Close()
			return errors.New("xhttp: sequence exhausted")
		}
		postURL := *u
		q := postURL.Query()
		q.Set(SequenceQuery, strconv.FormatUint(seq, 10))
		postURL.RawQuery = q.Encode()
		opCtx, cancel := context.WithCancelCause(c.ctx)
		finished := make(chan struct{})
		go watchWriteDeadline(opCtx, c.wd, cfg.PostTimeout, finished, cancel)
		defer func() { close(finished); cancel(context.Canceled) }()
		req, err := http.NewRequestWithContext(opCtx, http.MethodPost, postURL.String(), bytes.NewReader(packet))
		if err != nil {
			return err
		}
		req.Header = headers.Clone()
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err == nil {
			// The protocol response is empty. Bound draining even for a broken peer.
			_, drainErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent || resp.Header.Get(VersionHeader) != Version {
				err = fmt.Errorf("xhttp: POST rejected (status %d or version mismatch)", resp.StatusCode)
			} else {
				err = drainErr
			}
		}
		if err != nil {
			if cause := context.Cause(opCtx); cause != nil {
				err = cause
			}
			// Delivery is uncertain after a failed POST. Never retry or continue with
			// a gap in the byte stream; close this logical connection instead.
			c.closeWithError(err)
			return err
		}
		seq++
		return nil
	}
	c.startContextWatch()
	go func() {
		for {
			packet := make([]byte, cfg.PacketSize)
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

func watchWriteDeadline(ctx context.Context, d *deadline, maxDuration time.Duration, finished <-chan struct{}, cancel context.CancelCauseFunc) {
	limit := time.Now().Add(maxDuration)
	for {
		at, changed := d.watch()
		if at.IsZero() || limit.Before(at) {
			at = limit
		}
		tick, stop := timerFor(at)
		select {
		case <-tick:
			stop()
			cancel(&timeoutError{"write"})
			return
		case <-changed:
		case <-finished:
			stop()
			return
		case <-ctx.Done():
			stop()
			return
		}
		stop()
	}
}
