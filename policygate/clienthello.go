// Package policygate inspects bounded TLS ClientHello metadata without
// terminating TLS. Successful callers must replay the returned bytes unchanged
// before copying the remainder of the connection to the approved destination.
package policygate

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/bit-precise/agentd/policy"
)

const (
	MaxClientHelloBytes = 64 << 10
	InspectTimeout      = 5 * time.Second
	maxRecordBytes      = 16 << 10
)

var (
	ErrMalformed = errors.New("malformed TLS ClientHello")
	ErrLimit     = errors.New("TLS ClientHello exceeds inspection limit")
	ErrNoSNI     = errors.New("TLS ClientHello requires a DNS server name")
	ErrMismatch  = errors.New("TLS server name does not match approved destination")
	ErrECH       = errors.New("encrypted ClientHello is unsupported by strict SNI policy")
)

// Inspect owns the connection's read deadline while inspecting the first
// ClientHello, then clears it. Cancellation interrupts the read without closing
// the connection, so the caller retains ownership of the stream. No decrypted
// application content or server-side TLS handshake is involved.
func Inspect(ctx context.Context, conn net.Conn, expectedDomain string) ([]byte, error) {
	if conn == nil {
		return nil, errors.New("nil TLS inspection connection")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expected, err := policy.CanonicalDomain(expectedDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid expected TLS domain: %w", err)
	}
	deadline := time.Now().Add(InspectTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set TLS inspection deadline: %w", err)
	}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Now())
		close(canceled)
	})
	defer func() {
		if !stop() {
			<-canceled
		}
		_ = conn.SetReadDeadline(time.Time{})
	}()

	var raw, handshake []byte
	for {
		if len(raw)+5 > MaxClientHelloBytes {
			return nil, ErrLimit
		}
		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("read TLS record header: %w", err)
		}
		if header[0] != 22 || header[1] != 3 || header[2] < 1 || header[2] > 3 {
			return nil, ErrMalformed
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length == 0 || length > maxRecordBytes {
			return nil, ErrMalformed
		}
		if len(raw)+len(header)+length > MaxClientHelloBytes {
			return nil, ErrLimit
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("read TLS record payload: %w", err)
		}
		raw = append(raw, header[:]...)
		raw = append(raw, payload...)
		handshake = append(handshake, payload...)
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 {
			return nil, ErrMalformed
		}
		length = int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if length > MaxClientHelloBytes-4 {
			return nil, ErrLimit
		}
		if len(handshake) < length+4 {
			continue
		}
		domain, err := serverName(handshake[4 : 4+length])
		if err != nil {
			return nil, err
		}
		if domain != expected {
			return nil, ErrMismatch
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return raw, nil
	}
}

type cursor []byte

func (c *cursor) take(n int) ([]byte, bool) {
	if n < 0 || len(*c) < n {
		return nil, false
	}
	value := (*c)[:n]
	*c = (*c)[n:]
	return value, true
}

func (c *cursor) vector(sizeBytes int) ([]byte, bool) {
	prefix, ok := c.take(sizeBytes)
	if !ok {
		return nil, false
	}
	length := int(prefix[0])
	if sizeBytes == 2 {
		length = int(binary.BigEndian.Uint16(prefix))
	}
	return c.take(length)
}

func serverName(hello []byte) (string, error) {
	c := cursor(hello)
	version, ok := c.take(2)
	if !ok || version[0] != 3 || version[1] < 1 || version[1] > 3 {
		return "", ErrMalformed
	}
	if _, ok := c.take(32); !ok {
		return "", ErrMalformed
	}
	if id, ok := c.vector(1); !ok || len(id) > 32 {
		return "", ErrMalformed
	}
	if suites, ok := c.vector(2); !ok || len(suites) == 0 || len(suites)%2 != 0 {
		return "", ErrMalformed
	}
	if compression, ok := c.vector(1); !ok || len(compression) == 0 {
		return "", ErrMalformed
	}
	if len(c) == 0 {
		return "", ErrNoSNI
	}
	extensions, ok := c.vector(2)
	if !ok || len(c) != 0 {
		return "", ErrMalformed
	}
	seen := make(map[uint16]bool)
	var name string
	c = cursor(extensions)
	for len(c) != 0 {
		kind, ok := c.take(2)
		if !ok {
			return "", ErrMalformed
		}
		extensionType := binary.BigEndian.Uint16(kind)
		if seen[extensionType] {
			return "", ErrMalformed
		}
		seen[extensionType] = true
		data, ok := c.vector(2)
		if !ok {
			return "", ErrMalformed
		}
		if extensionType == 0xfe0d {
			return "", ErrECH
		}
		if extensionType != 0 {
			continue
		}
		sni := cursor(data)
		list, ok := sni.vector(2)
		if !ok || len(sni) != 0 || len(list) == 0 {
			return "", ErrMalformed
		}
		sni = cursor(list)
		for len(sni) != 0 {
			kind, ok := sni.take(1)
			if !ok || kind[0] != 0 || name != "" {
				return "", ErrMalformed
			}
			value, ok := sni.vector(2)
			if !ok || len(value) == 0 {
				return "", ErrMalformed
			}
			for _, b := range value {
				if b > 127 {
					return "", ErrMalformed
				}
			}
			canonical, err := policy.CanonicalDomain(string(value))
			if err != nil {
				return "", ErrMalformed
			}
			name = canonical
		}
	}
	if name == "" {
		return "", ErrNoSNI
	}
	return name, nil
}
