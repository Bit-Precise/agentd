//go:build linux || darwin

package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Lock prevents two local processes from using the same profile. The kernel
// releases the lock on exit, including crashes; no stale PID-file recovery is needed.
func Lock(stateDir string) (func() error, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	info, err := os.Lstat(stateDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("state directory must be owned by the current user with permissions 0700")
	}
	fd, err := syscall.Open(filepath.Join(stateDir, ".lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open profile lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), ".lock")
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("profile already in use or cannot be locked: %w", err)
	}
	return f.Close, nil
}

func openPrivate(path string) (*privateFile, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		_ = f.Close()
		return nil, errors.New("credentials must be owned by the current user")
	}
	return &privateFile{File: f}, nil
}

func validatePrivateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("credentials must be a regular file readable only by its owner (chmod 600)")
	}
	return nil
}
