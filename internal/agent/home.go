package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"agentd/internal/identity"
)

// Home resolves an instance directory: override (--home or AGENTD_HOME) wins;
// otherwise ~/.agentd for the default instance and
// ~/.agentd/instances/<name> for the others (design 9.2).
func Home(instance, override string) (string, error) {
	if override == "" {
		override = os.Getenv("AGENTD_HOME")
	}
	if override != "" {
		return filepath.Abs(override)
	}
	if instance == "" {
		instance = os.Getenv("AGENTD_INSTANCE")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	base := filepath.Join(home, ".agentd")
	if instance == "" || instance == "default" {
		return base, nil
	}
	if !identity.ValidLabel(instance) {
		return "", errors.New("instance names are RFC 1123 labels")
	}
	return filepath.Join(base, "instances", instance), nil
}

// KeyPath is the node key inside an instance directory.
func KeyPath(dir string) string { return filepath.Join(dir, "node.key") }

// SocketPath is the local API socket of an instance. Unix socket paths are
// limited to about 104 bytes, so a deep instance directory gets its socket in
// the per-user cache directory under a hash of the instance path.
func SocketPath(dir string) string {
	p := filepath.Join(dir, "agentd.sock")
	if len(p) < 100 {
		return p
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	sum := sha256.Sum256([]byte(dir))
	short := filepath.Join(base, "agentd", hex.EncodeToString(sum[:6])+".sock")
	_ = os.MkdirAll(filepath.Dir(short), 0o700)
	return short
}

// StatePath caches what the daemon learned from agentserver.
func StatePath(dir string) string { return filepath.Join(dir, "state.json") }

// EnsureDir creates an instance directory with 0700.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

func identityEncode(k []byte) string { return identity.EncodeKey(k) }
