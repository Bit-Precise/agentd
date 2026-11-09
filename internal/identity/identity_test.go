package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestKeyFileRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")
	priv, created, err := LoadOrCreateKey(path)
	if err != nil || !created {
		t.Fatalf("first LoadOrCreateKey: created=%v err=%v", created, err)
	}
	again, created, err := LoadOrCreateKey(path)
	if err != nil || created {
		t.Fatalf("second LoadOrCreateKey: created=%v err=%v", created, err)
	}
	if !bytes.Equal(priv, again) {
		t.Fatal("reloaded key differs")
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "# agentd node key v1\nprivate-key: ") {
		t.Fatalf("unexpected key file format: %q", data)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKey(path); err == nil {
			t.Fatal("expected error for world-readable key file")
		}
	}
}

func TestLoadKeyAcceptsStandardBase64Seed(t *testing.T) {
	// Helm generates seeds with `randBytes 32 | b64enc` (standard alphabet, padded).
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	seed := bytes.Repeat([]byte{0xfb}, 32)
	content := base64.StdEncoding.EncodeToString(seed) + "\n" // bare seed, as mounted from a Secret
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	priv, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if !bytes.Equal(priv.Seed(), seed) {
		t.Fatalf("seed mismatch")
	}
}

func TestX25519DerivationMatchesScalarBaseMult(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	xpriv := X25519Private(priv)
	xpub, err := X25519Public(pub)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := curve25519.X25519(xpriv, curve25519.Basepoint)
	if !bytes.Equal(xpub, want) {
		t.Fatal("X25519 public key derived from Ed25519 public key does not match the derived private key")
	}
}

func TestEncodeDecodeKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	s := EncodeKey(pub)
	if len(s) != 43 || strings.ContainsAny(s, "+/=") {
		t.Fatalf("bad encoding %q", s)
	}
	for _, in := range []string{s, "agentd://" + s} {
		got, err := DecodeKey(in)
		if err != nil || !bytes.Equal(got, pub) {
			t.Fatalf("DecodeKey(%q) = %x, %v", in, got, err)
		}
	}
	if _, err := DecodeKey("short"); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestValidLabel(t *testing.T) {
	good := []string{"a", "laptop", "dorm-2", "x1", strings.Repeat("a", 63)}
	bad := []string{"", "-a", "a-", "A", "a_b", "a.b", strings.Repeat("a", 64)}
	for _, s := range good {
		if !ValidLabel(s) {
			t.Errorf("ValidLabel(%q) = false", s)
		}
	}
	for _, s := range bad {
		if ValidLabel(s) {
			t.Errorf("ValidLabel(%q) = true", s)
		}
	}
	if got := SanitizeLabel("My_MacBook.Pro-"); got != "my-macbook-pro" {
		t.Errorf("SanitizeLabel = %q", got)
	}
}

func TestParseURI(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	k := EncodeKey(pub)
	u, err := ParseURI("agentd://" + k)
	if err != nil || !bytes.Equal(u.Key, pub) {
		t.Fatalf("key form: %+v %v", u, err)
	}
	u, err = ParseURI("agentd://home.agentsrv.example.com/laptop")
	if err != nil || u.Workspace != "home.agentsrv.example.com" || u.Name != "laptop" {
		t.Fatalf("name form: %+v %v", u, err)
	}
	u, err = ParseURI("agentd://home.agentsrv.example.com/group/pc")
	if err != nil || u.Group != "pc" {
		t.Fatalf("group form: %+v %v", u, err)
	}
	u, err = ParseURI("agentd://home.agentsrv.example.com/")
	if err != nil || u.Workspace == "" || u.Name != "" || u.Group != "" {
		t.Fatalf("workspace form: %+v %v", u, err)
	}
	if _, err := ParseURI("https://x"); err == nil {
		t.Fatal("expected error for non-agentd scheme")
	}
}

func TestParseJoinLink(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	link := "agentd://home.agentsrv.example.com/dorm?relay=https://relay-hk.agentsrv.example.com&key=" + EncodeKey(pub) + "&token=Qm9vb29vb29vb29vb29vb28"
	j, err := ParseJoinLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if j.Workspace != "home.agentsrv.example.com" || j.Name != "dorm" || j.RelayURL != "https://relay-hk.agentsrv.example.com" || !bytes.Equal(j.Key, pub) || j.Token != "Qm9vb29vb29vb29vb29vb28" {
		t.Fatalf("unexpected %+v", j)
	}
	if got := j.String(); got != link {
		t.Fatalf("String() = %q", got)
	}
	if _, err := ParseJoinLink("agentd://home.agentsrv.example.com/dorm?relay=http://insecure&key=" + EncodeKey(pub) + "&token=x"); err == nil {
		t.Fatal("expected error for non-https relay")
	}
}
