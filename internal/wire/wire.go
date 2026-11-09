// Package wire implements the on-the-wire framing and signed envelopes of the
// agentd protocol (protocol 0, 4, 5.1, 5.7, 7.2): length-prefixed protobuf
// messages, Ed25519ctx signatures, the replay cache and TAI64N timestamps.
package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/wire/pb"
)

// Signature contexts and protocol constants (protocol 0.5).
const (
	CtxOpen       = "agentd/open/v1"
	CtxTaskResult = "agentd/task-result/v1"
	CtxMembership = "agentd/membership/v1"
	CtxRelay      = "agentd/relay/v1"
	CtxControl    = "agentd/control/v1"

	Prologue      = "agentd/1"
	MinorVersion  = 1
	OpenMax       = 1 << 20
	AckMax        = 64 << 10
	TaskResultMax = 2 << 20
	ControlMsgMax = 16 << 20
	OpenMaxCerts  = 16

	OpenTimeWindow  = 300 * time.Second
	NonceCacheTTL   = 600 * time.Second
	MembershipTTL   = time.Hour
	MembershipRenew = 30 * time.Minute
	RelayCertTTL    = 30 * 24 * time.Hour
	EarlyDataMax    = 16 << 10
)

// Error carries a protocol status code.
type Error struct {
	Status pb.Status
	Msg    string
}

func (e *Error) Error() string {
	if e.Msg == "" {
		return e.Status.String()
	}
	return e.Status.String() + ": " + e.Msg
}

// Errorf returns an *Error with the given status.
func Errorf(st pb.Status, format string, args ...any) error {
	return &Error{Status: st, Msg: fmt.Sprintf(format, args...)}
}

// StatusOf extracts the protocol status of err; errors without one map to BAD_REQUEST.
func StatusOf(err error) pb.Status {
	if err == nil {
		return pb.Status_OK
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return pb.Status_BAD_REQUEST
}

// WriteMsg writes m as [u32 big-endian length][protobuf bytes].
func WriteMsg(w io.Writer, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err = w.Write(buf)
	return err
}

// ReadMsg reads one length-prefixed message, rejecting lengths above max
// before allocating.
func ReadMsg(r io.Reader, m proto.Message, max int) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int64(n) > int64(max) {
		return Errorf(pb.Status_BAD_REQUEST, "message of %d bytes exceeds limit %d", n, max)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	if err := proto.Unmarshal(b, m); err != nil {
		return Errorf(pb.Status_BAD_REQUEST, "decode: %v", err)
	}
	return nil
}

// Sign returns the Ed25519ctx signature of body under ctx.
func Sign(priv ed25519.PrivateKey, ctx string, body []byte) []byte {
	sig, err := priv.Sign(nil, body, &ed25519.Options{Context: ctx})
	if err != nil {
		panic(err) // only fails for malformed options
	}
	return sig
}

// Verify checks an Ed25519ctx signature.
func Verify(pub []byte, ctx string, body, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.VerifyWithOptions(ed25519.PublicKey(pub), body, sig, &ed25519.Options{Context: ctx}) == nil
}

// WithinWindow reports whether unix-seconds ts is within ±OpenTimeWindow of now.
func WithinWindow(ts uint64, now time.Time) bool {
	d := time.Duration(int64(ts)-now.Unix()) * time.Second
	if d < 0 {
		d = -d
	}
	return d <= OpenTimeWindow
}

// SignOpen marshals and signs an OpenBody. KIND_CONTROL opens are unsigned.
func SignOpen(priv ed25519.PrivateKey, body *pb.OpenBody) (*pb.Open, error) {
	b, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}
	o := &pb.Open{Body: b}
	if body.Kind != pb.Kind_KIND_CONTROL {
		o.Sig = Sign(priv, CtxOpen, b)
	}
	return o, nil
}

// DecodeOpen decodes the body and, except for KIND_CONTROL, verifies the
// signature over the received bytes with body.from.
func DecodeOpen(o *pb.Open) (*pb.OpenBody, error) {
	if o == nil {
		return nil, Errorf(pb.Status_BAD_REQUEST, "missing open")
	}
	var body pb.OpenBody
	if err := proto.Unmarshal(o.Body, &body); err != nil {
		return nil, Errorf(pb.Status_BAD_REQUEST, "decode open: %v", err)
	}
	if body.Kind == pb.Kind_KIND_CONTROL {
		return &body, nil
	}
	if !Verify(body.From, CtxOpen, o.Body, o.Sig) {
		return nil, Errorf(pb.Status_BAD_SIGNATURE, "open signature does not verify with from")
	}
	return &body, nil
}

// SignControl wraps msg for recipient and signs it with the workspace key.
func SignControl(wsPriv ed25519.PrivateKey, recipient []byte, msg *pb.ControlMessage, now time.Time) (*pb.Signed, error) {
	b, err := proto.Marshal(&pb.SignedBody{Recipient: recipient, IssuedAt: uint64(now.Unix()), Msg: msg})
	if err != nil {
		return nil, err
	}
	return &pb.Signed{Body: b, Sig: Sign(wsPriv, CtxControl, b)}, nil
}

// OpenSigned verifies a Signed envelope from the workspace key, checks that it
// is addressed to self and fresh, and returns the inner message.
func OpenSigned(wsPub, self []byte, s *pb.Signed, now time.Time) (*pb.ControlMessage, error) {
	if s == nil || !Verify(wsPub, CtxControl, s.Body, s.Sig) {
		return nil, Errorf(pb.Status_BAD_SIGNATURE, "control message is not signed by the workspace key")
	}
	var body pb.SignedBody
	if err := proto.Unmarshal(s.Body, &body); err != nil {
		return nil, Errorf(pb.Status_BAD_REQUEST, "decode signed body: %v", err)
	}
	if !bytes.Equal(body.Recipient, self) {
		return nil, Errorf(pb.Status_BAD_REQUEST, "control message addressed to another node")
	}
	if !WithinWindow(body.IssuedAt, now) {
		return nil, Errorf(pb.Status_TIMESTAMP_OUT_OF_WINDOW, "control message issued at %d", body.IssuedAt)
	}
	if body.Msg == nil {
		return nil, Errorf(pb.Status_BAD_REQUEST, "empty control message")
	}
	return body.Msg, nil
}

// IssueMembership signs a membership certificate for member.
func IssueMembership(issuerPriv ed25519.PrivateKey, member []byte, workspace, name string, now time.Time, ttl time.Duration) (*pb.MembershipCert, error) {
	body := &pb.MembershipCertBody{
		Member:    member,
		Issuer:    issuerPriv.Public().(ed25519.PublicKey),
		Workspace: workspace,
		IssuedAt:  uint64(now.Unix()),
		ExpiresAt: uint64(now.Add(ttl).Unix()),
		Name:      name,
	}
	b, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &pb.MembershipCert{Body: b, Sig: Sign(issuerPriv, CtxMembership, b)}, nil
}

// DecodeMembership returns the body without verifying it (to read the issuer).
func DecodeMembership(c *pb.MembershipCert) (*pb.MembershipCertBody, error) {
	var body pb.MembershipCertBody
	if err := proto.Unmarshal(c.GetBody(), &body); err != nil {
		return nil, err
	}
	return &body, nil
}

// VerifyMembership checks a certificate presented by member (protocol 5.7).
// revoked may be nil.
func VerifyMembership(c *pb.MembershipCert, member []byte, workspace string, now time.Time, revoked func(member, issuer []byte) bool) (*pb.MembershipCertBody, error) {
	body, err := DecodeMembership(c)
	if err != nil {
		return nil, err
	}
	if !Verify(body.Issuer, CtxMembership, c.Body, c.Sig) {
		return nil, errors.New("membership signature invalid")
	}
	if !bytes.Equal(body.Member, member) {
		return nil, errors.New("membership issued to another member")
	}
	if body.Workspace != workspace {
		return nil, errors.New("membership for another workspace")
	}
	if int64(body.IssuedAt) > now.Unix()+int64(OpenTimeWindow/time.Second) {
		return nil, errors.New("membership issued in the future")
	}
	if int64(body.ExpiresAt) <= now.Unix() {
		return nil, errors.New("membership expired")
	}
	if revoked != nil && revoked(body.Member, body.Issuer) {
		return nil, errors.New("membership revoked")
	}
	return body, nil
}

// IssueRelayCert signs a relay certificate with the workspace key.
func IssueRelayCert(wsPriv ed25519.PrivateKey, body *pb.RelayCertBody) (*pb.RelayCert, error) {
	b, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &pb.RelayCert{Body: b, Sig: Sign(wsPriv, CtxRelay, b)}, nil
}

// DecodeRelayCert returns the body without verification.
func DecodeRelayCert(c *pb.RelayCert) (*pb.RelayCertBody, error) {
	var body pb.RelayCertBody
	if err := proto.Unmarshal(c.GetBody(), &body); err != nil {
		return nil, err
	}
	return &body, nil
}

// VerifyRelayCert checks a relay certificate against the workspace key.
func VerifyRelayCert(wsPub []byte, c *pb.RelayCert, workspace string, now time.Time) (*pb.RelayCertBody, error) {
	if c == nil || !Verify(wsPub, CtxRelay, c.Body, c.Sig) {
		return nil, errors.New("relay certificate is not signed by the workspace key")
	}
	body, err := DecodeRelayCert(c)
	if err != nil {
		return nil, err
	}
	if body.Workspace != workspace {
		return nil, fmt.Errorf("relay certificate is for workspace %q", body.Workspace)
	}
	if int64(body.ExpiresAt) <= now.Unix() {
		return nil, errors.New("relay certificate expired")
	}
	if len(body.Identity) != ed25519.PublicKeySize {
		return nil, errors.New("relay certificate has no identity")
	}
	return body, nil
}

// SignTaskResult signs a task result with the executor key.
func SignTaskResult(priv ed25519.PrivateKey, body *pb.TaskResultBody) (*pb.TaskResult, error) {
	b, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &pb.TaskResult{Body: b, Sig: Sign(priv, CtxTaskResult, b)}, nil
}

// VerifyTaskResult checks a result returned by executor to self for callID.
func VerifyTaskResult(executor, self []byte, callID string, r *pb.TaskResult, now time.Time) (*pb.TaskResultBody, error) {
	if r == nil || !Verify(executor, CtxTaskResult, r.Body, r.Sig) {
		return nil, errors.New("task result signature invalid")
	}
	var body pb.TaskResultBody
	if err := proto.Unmarshal(r.Body, &body); err != nil {
		return nil, err
	}
	if !bytes.Equal(body.From, executor) || !bytes.Equal(body.To, self) {
		return nil, errors.New("task result from/to mismatch")
	}
	if body.CallId != callID {
		return nil, errors.New("task result call_id mismatch")
	}
	if !WithinWindow(body.IssuedAt, now) {
		return nil, errors.New("task result timestamp outside window")
	}
	return &body, nil
}

// NonceCache remembers (from, nonce) pairs for ttl, bounded per sender.
type NonceCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	perFrom int
	seen    map[string]map[string]time.Time
	sweep   time.Time
}

// NewNonceCache creates a cache; perFrom bounds entries per sender (protocol 10).
func NewNonceCache(ttl time.Duration, perFrom int) *NonceCache {
	return &NonceCache{ttl: ttl, perFrom: perFrom, seen: map[string]map[string]time.Time{}}
}

// Check records the pair and reports whether it was fresh. It returns false
// for a replay or when the sender exceeded its bound.
func (c *NonceCache) Check(from, nonce []byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.sweep) > c.ttl {
		for f, m := range c.seen {
			for n, exp := range m {
				if !now.Before(exp) {
					delete(m, n)
				}
			}
			if len(m) == 0 {
				delete(c.seen, f)
			}
		}
		c.sweep = now
	}
	m := c.seen[string(from)]
	if m == nil {
		m = map[string]time.Time{}
		c.seen[string(from)] = m
	}
	if exp, ok := m[string(nonce)]; ok && now.Before(exp) {
		return false
	}
	if len(m) >= c.perFrom {
		for n, exp := range m {
			if !now.Before(exp) {
				delete(m, n)
			}
		}
		if len(m) >= c.perFrom {
			return false
		}
	}
	m[string(nonce)] = now.Add(c.ttl)
	return true
}

// TAI64N encodes t as 12 bytes (wireguard-go's tai64n): 8 bytes of 2^62+10+seconds, 4 bytes of nanoseconds.
func TAI64N(t time.Time) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b, uint64(1<<62)+10+uint64(t.Unix()))
	binary.BigEndian.PutUint32(b[8:], uint32(t.Nanosecond()))
	return b
}

// RandomID returns a random 10-byte identifier in base32-like lowercase hex.
func RandomID() string {
	var b [10]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
