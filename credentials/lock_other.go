//go:build !linux && !darwin && !windows

package credentials

import (
	"errors"
	"os"
)

func Lock(string) (func() error, error) {
	return nil, errors.New("profile locking is supported on Linux, macOS and Windows only")
}

func openPrivate(string) (*privateFile, error) {
	return nil, errors.New("credential loading is supported on Linux, macOS and Windows only")
}

func validatePrivateFile(os.FileInfo) error {
	return errors.New("credential permissions are unsupported on this platform")
}
