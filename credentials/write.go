package credentials

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Save atomically replaces credentials in an already private profile. Callers
// own the profile lock; temporary files inherit its private Windows DACL.
func Save(stateDir string, c *Credentials) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(stateDir, ".credentials-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(stateDir, Filename))
}

// ReadSecret uses the same platform-specific private-file checks as credentials.
func ReadSecret(path string) (string, error) {
	f, err := openPrivate(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if err := validatePrivateFile(info); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if len(b) > 8192 || len(s) < 24 {
		return "", errors.New("secret file requires a high-entropy token of 24 to 8192 bytes")
	}
	return s, nil
}
