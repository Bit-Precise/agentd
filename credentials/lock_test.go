//go:build linux || darwin

package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileLockExclusiveAndReleased(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new-profile")
	release, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release() })
	if secondRelease, err := Lock(dir); err == nil {
		_ = secondRelease()
		t.Fatal("same profile acquired twice")
	}
	otherRelease, err := Lock(filepath.Join(t.TempDir(), "other-profile"))
	if err != nil {
		t.Fatalf("another profile blocked by existing lock: %v", err)
	}
	_ = otherRelease()
	if err := release(); err != nil {
		t.Fatal(err)
	}
	reacquired, err := Lock(dir)
	if err != nil {
		t.Fatalf("released lock could not be reacquired: %v", err)
	}
	_ = reacquired()
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("new profile directory is not private: %v, %v", info, err)
	}
}

func TestProfileLockRejectsUnsafeDirectoryAndSymlinks(t *testing.T) {
	t.Run("shared directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0777); err != nil {
			t.Fatal(err)
		}
		if release, err := Lock(dir); err == nil {
			_ = release()
			t.Fatal("lock accepted a directory writable by other users")
		}
	})
	t.Run("symlink directory", func(t *testing.T) {
		target := t.TempDir()
		if err := os.Chmod(target, 0700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "profile")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if release, err := Lock(link); err == nil {
			_ = release()
			t.Fatal("lock accepted a symlinked state directory")
		}
	})
	t.Run("symlink lock", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, ".lock")); err != nil {
			t.Fatal(err)
		}
		if release, err := Lock(dir); err == nil {
			_ = release()
			t.Fatal("lock followed a symlink")
		}
		got, err := os.ReadFile(target)
		if err != nil || string(got) != "untouched" {
			t.Fatal("failed lock modified another file")
		}
	})
}
