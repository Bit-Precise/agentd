// Package identity holds node keys, the Ed25519 to X25519 derivation, key
// encoding, instance names and the agentd:// URI forms (design 3.1, protocol 3.1, 8).
package identity

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"filippo.io/edwards25519"
)

const keyHeader = "# agentd node key v1\n"

// GenerateKey returns a new Ed25519 private key.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// LoadKey reads a key file. Accepted contents: the canonical format
// ("private-key: <base64url seed>"), or a bare 32-byte seed in base64url or
// standard base64 (as mounted from a Kubernetes Secret).
func LoadKey(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key file %s has permissions %v; it must not be readable by group or others (chmod 600)", path, st.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKey(data)
}

// ParseKey parses key file contents (see LoadKey).
func ParseKey(data []byte) (ed25519.PrivateKey, error) {
	var seedText string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "private-key:"); ok {
			seedText = strings.TrimSpace(v)
			break
		}
		if seedText == "" {
			seedText = line
		}
	}
	if seedText == "" {
		return nil, errors.New("key file has no private-key")
	}
	seed, err := decodeAny(seedText)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key file: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// SaveKey writes priv in the canonical format with mode 0600, creating the
// directory (0700) if needed.
func SaveKey(path string, priv ed25519.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content := keyHeader + "private-key: " + base64.RawURLEncoding.EncodeToString(priv.Seed()) + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadOrCreateKey loads path, or generates and saves a new key if the file does
// not exist. created reports whether a new key was generated.
func LoadOrCreateKey(path string) (priv ed25519.PrivateKey, created bool, err error) {
	priv, err = LoadKey(path)
	if err == nil {
		return priv, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	priv, err = GenerateKey()
	if err != nil {
		return nil, false, err
	}
	if err := SaveKey(path, priv); err != nil {
		return nil, false, err
	}
	return priv, true, nil
}

// Public returns the public half of priv.
func Public(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

// X25519Private derives the X25519 private key used by Noise from an Ed25519
// private key (libsodium crypto_sign_ed25519_sk_to_curve25519).
func X25519Private(priv ed25519.PrivateKey) []byte {
	h := sha512.Sum512(priv.Seed())
	out := make([]byte, 32)
	copy(out, h[:32])
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return out
}

// X25519Public derives the X25519 public key from an Ed25519 public key
// (birational map u = (1+y)/(1-y)).
func X25519Public(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	return p.BytesMontgomery(), nil
}

// EncodeKey renders a public key as base64url without padding (43 characters).
func EncodeKey(pub []byte) string { return base64.RawURLEncoding.EncodeToString(pub) }

// DecodeKey parses a 43-character base64url public key, optionally prefixed
// with "agentd://".
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "agentd://")
	if len(s) != 43 {
		return nil, fmt.Errorf("public key must be 43 base64url characters, got %d", len(s))
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	return b, nil
}

// MustDecodeKey is DecodeKey for tests and constants.
func MustDecodeKey(s string) []byte {
	b, err := DecodeKey(s)
	if err != nil {
		panic(err)
	}
	return b
}

func decodeAny(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64")
}

// ValidLabel reports whether s is a lowercase RFC 1123 label (instance,
// service, group and workspace names).
func ValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !alnum && !(c == '-' && i > 0 && i < len(s)-1) {
			return false
		}
	}
	return true
}

// SanitizeLabel turns an arbitrary hostname into a valid label: lowercase,
// non-alphanumerics replaced by '-', trimmed and truncated to 63 characters.
func SanitizeLabel(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-")
	}
	if out == "" {
		out = "node"
	}
	return out
}
