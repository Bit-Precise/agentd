// Package session implements the encrypted session layer (protocol 3):
// a Noise_IK_25519_ChaChaPoly_BLAKE2s handshake whose payloads are
// ClientHello / ServerHello, framed as [u16 length][message] on a byte stream,
// followed by encrypted frames of at most 16 KiB plaintext with periodic rekey,
// and yamux multiplexing on top.
package session

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"

	"agentd/internal/identity"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// FrameMaxPlaintext is the largest plaintext carried in one encrypted frame.
const FrameMaxPlaintext = 16 << 10

// HandshakeTimeout bounds the two handshake messages.
const HandshakeTimeout = 5 * time.Second

// rekeyInterval is the number of messages per direction between rekeys
// (protocol 3.3). A variable so tests can exercise rekeying quickly.
var rekeyInterval uint64 = 1 << 20

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// HelloError is returned by Client when the responder completed the handshake
// but rejected the session; Hello carries the status and message.
type HelloError struct{ Hello *pb.ServerHello }

func (e *HelloError) Error() string {
	return fmt.Sprintf("session rejected: %s %s", e.Hello.Status, e.Hello.Message)
}

// InitiatorConfig configures Client.
type InitiatorConfig struct {
	Local  ed25519.PrivateKey
	Remote ed25519.PublicKey // responder's Ed25519 identity
	Hello  *pb.ClientHello   // identity, timestamp and versions are filled in when empty
}

// DecideFunc inspects a verified ClientHello and returns the ServerHello to
// send. A non-OK status rejects the session after the handshake completes.
type DecideFunc func(hello *pb.ClientHello, remote ed25519.PublicKey) *pb.ServerHello

// ResponderConfig configures Server.
type ResponderConfig struct {
	Local  ed25519.PrivateKey
	Decide DecideFunc
}

// Conn is an established encrypted session. It implements net.Conn.
type Conn struct {
	raw    net.Conn
	remote ed25519.PublicKey
	send   *noise.CipherState
	recv   *noise.CipherState

	wmu   sync.Mutex
	sent  uint64
	rmu   sync.Mutex
	rcvd  uint64
	rbuf  []byte
	frame []byte
}

// Client runs the initiator side of the handshake over raw.
func Client(raw net.Conn, cfg InitiatorConfig) (*Conn, *pb.ServerHello, error) {
	hello := proto.Clone(cfg.Hello).(*pb.ClientHello)
	if hello == nil {
		hello = &pb.ClientHello{}
	}
	if len(hello.Identity) == 0 {
		hello.Identity = identity.Public(cfg.Local)
	}
	if len(hello.Timestamp) == 0 {
		hello.Timestamp = wire.TAI64N(time.Now())
	}
	if hello.MinVersion == 0 && hello.MaxVersion == 0 {
		hello.MinVersion, hello.MaxVersion = wire.MinorVersion, wire.MinorVersion
	}
	peerX, err := identity.X25519Public(cfg.Remote)
	if err != nil {
		return nil, nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte(wire.Prologue),
		StaticKeypair: staticKey(cfg.Local),
		PeerStatic:    peerX,
	})
	if err != nil {
		return nil, nil, err
	}
	payload, err := proto.Marshal(hello)
	if err != nil {
		return nil, nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer raw.SetDeadline(time.Time{})
	// Not every transport supports deadlines (XHTTP); close on a timer as well.
	timer := time.AfterFunc(HandshakeTimeout, func() { raw.Close() })
	defer timer.Stop()
	msg1, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(raw, msg1); err != nil {
		return nil, nil, err
	}
	msg2, err := readFrame(raw, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	payload2, csSend, csRecv, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: responder key does not match (%w)", err)
	}
	var sh pb.ServerHello
	if err := proto.Unmarshal(payload2, &sh); err != nil {
		return nil, nil, fmt.Errorf("handshake: decode ServerHello: %w", err)
	}
	if sh.Status != pb.Status_OK {
		return nil, &sh, &HelloError{Hello: &sh}
	}
	return &Conn{raw: raw, remote: cfg.Remote, send: csSend, recv: csRecv}, &sh, nil
}

// Server runs the responder side. On rejection it sends the ServerHello,
// closes raw and returns an error together with the decoded ClientHello.
func Server(raw net.Conn, cfg ResponderConfig) (*Conn, *pb.ClientHello, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      []byte(wire.Prologue),
		StaticKeypair: staticKey(cfg.Local),
	})
	if err != nil {
		return nil, nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(HandshakeTimeout))
	timer := time.AfterFunc(HandshakeTimeout, func() { raw.Close() })
	defer timer.Stop()
	msg1, err := readFrame(raw, nil)
	if err != nil {
		raw.Close()
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	payload, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil {
		raw.Close() // scanners and wrong keys get nothing back
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	var hello pb.ClientHello
	sh := &pb.ServerHello{}
	if err := proto.Unmarshal(payload, &hello); err != nil {
		sh.Status, sh.Message = pb.Status_BAD_REQUEST, "undecodable ClientHello"
	} else if len(hello.Identity) != ed25519.PublicKeySize || len(hello.Timestamp) != 12 {
		sh.Status, sh.Message = pb.Status_BAD_REQUEST, "identity or timestamp malformed"
	} else if hello.MinVersion > wire.MinorVersion || hello.MaxVersion < wire.MinorVersion {
		sh.Status, sh.Message = pb.Status_VERSION_MISMATCH, fmt.Sprintf("server supports minor version %d", wire.MinorVersion)
	} else if x, err := identity.X25519Public(hello.Identity); err != nil || !bytes.Equal(x, hs.PeerStatic()) {
		sh.Status, sh.Message = pb.Status_IDENTITY_MISMATCH, "identity does not match the handshake key"
	} else {
		sh = cfg.Decide(&hello, ed25519.PublicKey(hello.Identity))
		if sh == nil {
			sh = &pb.ServerHello{Status: pb.Status_SERVER_BUSY}
		}
	}
	sh.Version = wire.MinorVersion
	sh.ServerIdentity = identity.Public(cfg.Local)
	sh.ServerTime = uint64(time.Now().Unix())
	if len(sh.SessionId) == 0 {
		sh.SessionId = make([]byte, 16)
		_, _ = rand.Read(sh.SessionId)
	}
	payload2, err := proto.Marshal(sh)
	if err != nil {
		raw.Close()
		return nil, &hello, err
	}
	msg2, csRecv, csSend, err := hs.WriteMessage(nil, payload2)
	if err != nil {
		raw.Close()
		return nil, &hello, err
	}
	if err := writeFrame(raw, msg2); err != nil {
		raw.Close()
		return nil, &hello, err
	}
	_ = raw.SetDeadline(time.Time{})
	if sh.Status != pb.Status_OK {
		// Give the client a moment to read the rejection before closing.
		go func() { time.Sleep(100 * time.Millisecond); raw.Close() }()
		return nil, &hello, &HelloError{Hello: sh}
	}
	return &Conn{raw: raw, remote: ed25519.PublicKey(hello.Identity), send: csSend, recv: csRecv}, &hello, nil
}

func staticKey(priv ed25519.PrivateKey) noise.DHKey {
	pub, _ := identity.X25519Public(identity.Public(priv))
	return noise.DHKey{Private: identity.X25519Private(priv), Public: pub}
}

func writeFrame(w io.Writer, msg []byte) error {
	if len(msg) > noise.MaxMsgLen {
		return errors.New("frame too large")
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	buf = buf[:n]
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// RemoteIdentity is the peer's Ed25519 public key.
func (c *Conn) RemoteIdentity() ed25519.PublicKey { return c.remote }

// Write encrypts p in frames of at most FrameMaxPlaintext bytes.
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > FrameMaxPlaintext {
			chunk = chunk[:FrameMaxPlaintext]
		}
		out := make([]byte, 2, 2+len(chunk)+16)
		ct, err := c.send.Encrypt(out, nil, chunk)
		if err != nil {
			return written, err
		}
		binary.BigEndian.PutUint16(ct, uint16(len(ct)-2))
		if _, err := c.raw.Write(ct); err != nil {
			return written, err
		}
		c.sent++
		if c.sent%rekeyInterval == 0 {
			c.send.Rekey()
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Read returns decrypted bytes. A decryption failure is fatal.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.rbuf) == 0 {
		frame, err := readFrame(c.raw, c.frame)
		if err != nil {
			return 0, err
		}
		c.frame = frame
		pt, err := c.recv.Decrypt(frame[:0], nil, frame)
		if err != nil {
			c.raw.Close()
			return 0, fmt.Errorf("session: decrypt failed: %w", err)
		}
		c.rcvd++
		if c.rcvd%rekeyInterval == 0 {
			c.recv.Rekey()
		}
		c.rbuf = pt
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *Conn) Close() error                       { return c.raw.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
