//go:build linux || darwin

package credentials

import (
	"os"
	"testing"
)

func privateTempDir(t *testing.T) string { t.Helper(); return t.TempDir() }

func credentialSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialsPOSIXPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0644, 0640, 0604, 0660} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			writeCredentials(t, dir, validCredentials(), mode)
			if _, err := Load(dir); err == nil {
				t.Fatal("accepted credentials readable by another account")
			}
		})
	}
}
