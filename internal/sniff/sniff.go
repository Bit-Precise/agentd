// Package sniff recognises the protocol of a connection from its first bytes:
// a TLS ClientHello (and its SNI, accumulated across records and TCP
// segments) or an SSH identification line (design 6.3, protocol 6.4).
package sniff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// Kind of first bytes.
type Kind int

const (
	Unknown Kind = iota
	TLS
	SSH
	HTTP
)

func (k Kind) String() string {
	return [...]string{"unknown", "tls", "ssh", "http"}[k]
}

// Result of sniffing. Data holds every byte consumed, to be replayed.
type Result struct {
	Kind Kind
	SNI  string
	ECH  bool
	Data []byte
	Err  error
}

var errNotTLS = errors.New("not a TLS handshake")

// IsSSH reports whether data starts like an SSH identification string.
func IsSSH(data []byte) bool { return bytes.HasPrefix(data, []byte("SSH-")) }

func isHTTP(data []byte) bool {
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE ", "PATCH ", "CONNECT "} {
		if bytes.HasPrefix(data, []byte(m)) {
			return true
		}
	}
	return false
}

// Sniff reads from r until the protocol is known or max bytes were read.
// The caller bounds the time with a read deadline on the underlying
// connection; a deadline error simply ends sniffing with what was read.
func Sniff(r io.Reader, max int) Result {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for len(buf) < max {
		n, err := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if len(buf) >= 4 {
			switch {
			case IsSSH(buf):
				return Result{Kind: SSH, Data: buf}
			case isHTTP(buf):
				return Result{Kind: HTTP, Data: buf}
			}
		}
		if len(buf) > 0 && buf[0] == 0x16 {
			sni, complete, perr := ParseClientHello(buf)
			if perr != nil {
				return Result{Kind: Unknown, Data: buf, Err: perr}
			}
			if complete {
				return Result{Kind: TLS, SNI: sni, ECH: hasECH(buf), Data: buf}
			}
		} else if len(buf) >= 4 {
			return Result{Kind: Unknown, Data: buf}
		}
		if err != nil {
			return Result{Kind: Unknown, Data: buf, Err: err}
		}
	}
	return Result{Kind: Unknown, Data: buf}
}

// handshakeBody concatenates the payloads of the leading handshake records.
// It returns the bytes available so far and an error for non-TLS input.
func handshakeBody(data []byte) ([]byte, error) {
	var body []byte
	for len(data) >= 5 {
		if data[0] != 0x16 {
			if body == nil {
				return nil, errNotTLS
			}
			break
		}
		if data[1] != 0x03 {
			return nil, errNotTLS
		}
		n := int(binary.BigEndian.Uint16(data[3:5]))
		if n == 0 || n > 1<<14+256 {
			return nil, errNotTLS
		}
		if len(data) < 5+n {
			body = append(body, data[5:]...)
			return body, nil
		}
		body = append(body, data[5:5+n]...)
		data = data[5+n:]
	}
	if len(data) > 0 && len(data) < 5 && data[0] != 0x16 && body == nil {
		return nil, errNotTLS
	}
	return body, nil
}

// ParseClientHello extracts the SNI. complete is false while more bytes are
// needed; err is set when the data is not a TLS ClientHello.
func ParseClientHello(data []byte) (sni string, complete bool, err error) {
	if len(data) > 0 && data[0] != 0x16 {
		return "", false, errNotTLS
	}
	body, err := handshakeBody(data)
	if err != nil {
		return "", false, err
	}
	if len(body) < 4 {
		return "", false, nil
	}
	if body[0] != 0x01 {
		return "", false, errors.New("first handshake message is not a ClientHello")
	}
	msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+msgLen {
		return "", false, nil
	}
	sni, _, err = parseHello(body[4 : 4+msgLen])
	return sni, true, err
}

func hasECH(data []byte) bool {
	body, err := handshakeBody(data)
	if err != nil || len(body) < 4 {
		return false
	}
	msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) < 4+msgLen {
		return false
	}
	_, ech, _ := parseHello(body[4 : 4+msgLen])
	return ech
}

func parseHello(h []byte) (sni string, ech bool, err error) {
	bad := errors.New("malformed ClientHello")
	p := 2 + 32 // legacy_version, random
	if len(h) < p+1 {
		return "", false, bad
	}
	p += 1 + int(h[p]) // session id
	if len(h) < p+2 {
		return "", false, bad
	}
	p += 2 + int(binary.BigEndian.Uint16(h[p:])) // cipher suites
	if len(h) < p+1 {
		return "", false, bad
	}
	p += 1 + int(h[p]) // compression methods
	if len(h) < p+2 {
		return "", false, nil // no extensions
	}
	end := p + 2 + int(binary.BigEndian.Uint16(h[p:]))
	p += 2
	if end > len(h) {
		return "", false, bad
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(h[p:])
		n := int(binary.BigEndian.Uint16(h[p+2:]))
		p += 4
		if p+n > end {
			return "", false, bad
		}
		ext := h[p : p+n]
		switch typ {
		case 0x0000: // server_name
			if len(ext) >= 5 && ext[2] == 0 {
				l := int(binary.BigEndian.Uint16(ext[3:]))
				if 5+l <= len(ext) {
					sni = strings.ToLower(string(ext[5 : 5+l]))
				}
			}
		case 0xfe0d: // encrypted_client_hello
			ech = true
		}
		p += n
	}
	return sni, ech, nil
}
