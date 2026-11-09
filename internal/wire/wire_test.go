package wire

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/wire/pb"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestLPRoundTripAndLimit(t *testing.T) {
	var buf bytes.Buffer
	in := &pb.Ack{Status: pb.Status_NO_RULE, Message: "x", RulesVersion: 7}
	if err := WriteMsg(&buf, in); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), buf.Bytes()...)
	var out pb.Ack
	if err := ReadMsg(&buf, &out, AckMax); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(in, &out) {
		t.Fatalf("got %v", &out)
	}
	if err := ReadMsg(bytes.NewReader(raw), &out, 2); err == nil {
		t.Fatal("expected size limit error")
	}
}

func TestOpenSignVerify(t *testing.T) {
	pub, priv := key(t)
	body := &pb.OpenBody{Kind: pb.Kind_KIND_TCP, Workspace: "home.example.com", From: pub, To: []byte("relay-key-32-bytes-..........."), IssuedAt: 100, Nonce: bytes.Repeat([]byte{1}, 16), Tcp: &pb.TcpOpen{Proto: pb.Proto_PROTO_TLS, Domain: "a.example", Port: 443}}
	open, err := SignOpen(priv, body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeOpen(open)
	if err != nil || got.GetTcp().GetDomain() != "a.example" {
		t.Fatalf("DecodeOpen: %v %v", got, err)
	}
	open.Body[len(open.Body)-1] ^= 1
	if _, err := DecodeOpen(open); StatusOf(err) != pb.Status_BAD_SIGNATURE {
		t.Fatalf("tampered body: %v", err)
	}
}

func TestSignedControlEnvelope(t *testing.T) {
	wsPub, wsPriv := key(t)
	self, _ := key(t)
	other, _ := key(t)
	now := time.Unix(1_000_000, 0)
	msg := &pb.ControlMessage{Msg: &pb.ControlMessage_Notice{Notice: &pb.Notice{Kind: pb.Notice_MESSAGE, Message: "hi"}}}
	s, err := SignControl(wsPriv, self, msg, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenSigned(wsPub, self, s, now.Add(10*time.Second))
	if err != nil || got.GetNotice().GetMessage() != "hi" {
		t.Fatalf("OpenSigned: %v %v", got, err)
	}
	if _, err := OpenSigned(wsPub, other, s, now); err == nil {
		t.Fatal("expected recipient mismatch")
	}
	if _, err := OpenSigned(wsPub, self, s, now.Add(time.Hour)); err == nil {
		t.Fatal("expected stale envelope to be rejected")
	}
	impostorPub, _ := key(t)
	if _, err := OpenSigned(impostorPub, self, s, now); err == nil {
		t.Fatal("expected signature failure with a different workspace key")
	}
}

func TestMembershipCert(t *testing.T) {
	issuerPub, issuerPriv := key(t)
	member, _ := key(t)
	now := time.Unix(2_000_000, 0)
	c, err := IssueMembership(issuerPriv, member, "home.example.com", "pc", now, MembershipTTL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := VerifyMembership(c, member, "home.example.com", now.Add(time.Minute), nil)
	if err != nil || !bytes.Equal(b.Issuer, issuerPub) {
		t.Fatalf("verify: %v %v", b, err)
	}
	if _, err := VerifyMembership(c, member, "home.example.com", now.Add(2*time.Hour), nil); err == nil {
		t.Fatal("expected expiry")
	}
	other, _ := key(t)
	if _, err := VerifyMembership(c, other, "home.example.com", now, nil); err == nil {
		t.Fatal("expected member mismatch")
	}
	revoked := func(m, i []byte) bool { return bytes.Equal(m, member) && bytes.Equal(i, issuerPub) }
	if _, err := VerifyMembership(c, member, "home.example.com", now, revoked); err == nil {
		t.Fatal("expected revocation")
	}
}

func TestRelayCert(t *testing.T) {
	wsPub, wsPriv := key(t)
	relayPub, _ := key(t)
	now := time.Unix(3_000_000, 0)
	c, err := IssueRelayCert(wsPriv, &pb.RelayCertBody{Identity: relayPub, Name: "relay-hk", Urls: map[string]string{"ws": "https://r/ws"}, IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(RelayCertTTL).Unix()), Workspace: "home.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := VerifyRelayCert(wsPub, c, "home.example.com", now)
	if err != nil || b.Name != "relay-hk" {
		t.Fatalf("verify: %v %v", b, err)
	}
	if _, err := VerifyRelayCert(wsPub, c, "other.example.com", now); err == nil {
		t.Fatal("expected workspace mismatch")
	}
}

func TestTaskResult(t *testing.T) {
	execPub, execPriv := key(t)
	sub, _ := key(t)
	now := time.Unix(4_000_000, 0)
	r, err := SignTaskResult(execPriv, &pb.TaskResultBody{CallId: "c1", From: execPub, To: sub, IssuedAt: uint64(now.Unix()), Final: true, Output: &pb.FunctionCallOutput{OutputText: "ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTaskResult(execPub, sub, "c1", r, now); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTaskResult(execPub, sub, "c2", r, now); err == nil {
		t.Fatal("expected call_id mismatch")
	}
}

func TestNonceCache(t *testing.T) {
	c := NewNonceCache(NonceCacheTTL, 3)
	from := []byte("a")
	now := time.Unix(10, 0)
	if !c.Check(from, []byte("n1"), now) {
		t.Fatal("first use rejected")
	}
	if c.Check(from, []byte("n1"), now) {
		t.Fatal("replay accepted")
	}
	if !c.Check(from, []byte("n1"), now.Add(NonceCacheTTL+time.Second)) {
		t.Fatal("expired nonce still remembered")
	}
	c.Check(from, []byte("n2"), now)
	c.Check(from, []byte("n3"), now)
	if c.Check(from, []byte("n4"), now) {
		t.Fatal("per-sender bound exceeded but accepted")
	}
}

func TestTAI64NOrdering(t *testing.T) {
	a := TAI64N(time.Unix(100, 5))
	b := TAI64N(time.Unix(100, 6))
	c := TAI64N(time.Unix(101, 0))
	if len(a) != 12 || bytes.Compare(a, b) >= 0 || bytes.Compare(b, c) >= 0 {
		t.Fatalf("bad ordering %x %x %x", a, b, c)
	}
}

func TestStatusOf(t *testing.T) {
	err := Errorf(pb.Status_REPLAY, "dup %d", 1)
	if StatusOf(err) != pb.Status_REPLAY || StatusOf(errors.New("x")) != pb.Status_BAD_REQUEST {
		t.Fatal("StatusOf mismatch")
	}
}
