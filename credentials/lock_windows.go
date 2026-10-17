//go:build windows

package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SYSTEM and Administrators are trusted host administrators; an elevated user's
// token can make Administrators the default owner of newly provisioned files.
func trustedSID(sid, user *windows.SID) bool {
	return sid != nil && sid.IsValid() && (sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func currentUser() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read current Windows user: %w", err)
	}
	return user.User.Sid.Copy()
}

func privateSecurity(user *windows.SID) (*windows.SecurityAttributes, error) {
	// Protected ACL; the current user and SYSTEM entries inherit to children.
	sd, err := windows.SecurityDescriptorFromString("O:" + user.String() + "D:P(A;OICI;FA;;;" + user.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, nil
}

func checkPrivateACL(handle windows.Handle, user *windows.SID) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read credential security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !trustedSID(owner, user) {
		return errors.New("state and credential owners must be the current user or a trusted Windows administrator")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("state and credentials require a restrictive Windows DACL")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read Windows ACL entry: %w", err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			// A deny entry only restricts the private allow set further.
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !trustedSID(sid, user) {
				return errors.New("Windows ACL grants access to another account; allow only the current user, SYSTEM and Administrators")
			}
		default:
			return errors.New("unsupported Windows ACL entry; use an explicit private file ACL")
		}
	}
	return nil
}

func checkedAttributes(handle windows.Handle, directory bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("reparse points are not permitted in state or credential paths")
	}
	if (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return errors.New("unexpected state or credential object type")
	}
	return nil
}

func localWindowsPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	volume := filepath.VolumeName(abs)
	if len(volume) != 2 || volume[1] != ':' {
		return "", errors.New("state paths require a local Windows drive; UNC and device paths are unsupported")
	}
	// Reject alternate data streams and Win32 aliases with trailing dots/spaces.
	for _, component := range strings.Split(abs[len(volume)+1:], `\`) {
		if strings.Contains(component, ":") || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return "", errors.New("state paths cannot contain alternate streams or ambiguous Windows names")
		}
	}
	return filepath.Clean(abs), nil
}

func closeHandles(handles []windows.Handle) {
	for i := len(handles) - 1; i >= 0; i-- {
		_ = windows.CloseHandle(handles[i])
	}
}

// Each directory handle excludes FILE_SHARE_DELETE, pinning checked ancestors
// against rename while a descendant is opened or the profile lock is held.
func pinDirectories(path string, create bool, user *windows.SID) (string, []windows.Handle, error) {
	abs, err := localWindowsPath(path)
	if err != nil {
		return "", nil, err
	}
	current := filepath.VolumeName(abs) + `\`
	paths := []string{current}
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), `\`) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		paths = append(paths, current)
	}
	sa, err := privateSecurity(user)
	if err != nil {
		return "", nil, err
	}
	var handles []windows.Handle
	for i, dir := range paths {
		ptr, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			closeHandles(handles)
			return "", nil, err
		}
		if create && i != 0 {
			if err := windows.CreateDirectory(ptr, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				closeHandles(handles)
				return "", nil, fmt.Errorf("create private state directory: %w", err)
			}
		}
		access := uint32(windows.FILE_READ_ATTRIBUTES)
		if i == len(paths)-1 {
			access |= windows.READ_CONTROL
		}
		handle, err := windows.CreateFile(ptr, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			closeHandles(handles)
			return "", nil, fmt.Errorf("open state directory: %w", err)
		}
		handles = append(handles, handle)
		if err := checkedAttributes(handle, true); err != nil {
			closeHandles(handles)
			return "", nil, err
		}
		if i == len(paths)-1 {
			if err := checkPrivateACL(handle, user); err != nil {
				closeHandles(handles)
				return "", nil, err
			}
		}
	}
	return abs, handles, nil
}

// Lock is a nonblocking kernel byte-range lock; process exit releases it without
// PID files or stale-lock recovery. Existing broad ACLs are rejected, not changed.
func Lock(stateDir string) (func() error, error) {
	user, err := currentUser()
	if err != nil {
		return nil, err
	}
	dir, handles, err := pinDirectories(stateDir, true, user)
	if err != nil {
		return nil, err
	}
	sa, err := privateSecurity(user)
	if err != nil {
		closeHandles(handles)
		return nil, err
	}
	ptr, err := windows.UTF16PtrFromString(filepath.Join(dir, ".lock"))
	if err != nil {
		closeHandles(handles)
		return nil, err
	}
	handle, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.OPEN_ALWAYS, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		closeHandles(handles)
		return nil, fmt.Errorf("open private profile lock: %w", err)
	}
	failed := func(err error) (func() error, error) {
		_ = windows.CloseHandle(handle)
		closeHandles(handles)
		return nil, err
	}
	if err := checkedAttributes(handle, false); err != nil {
		return failed(err)
	}
	if err := checkPrivateACL(handle, user); err != nil {
		return failed(err)
	}
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		return failed(fmt.Errorf("profile already in use or cannot be locked: %w", err))
	}
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() { closeErr = windows.CloseHandle(handle); closeHandles(handles) })
		return closeErr
	}, nil
}

func openPrivate(path string) (*privateFile, error) {
	user, err := currentUser()
	if err != nil {
		return nil, err
	}
	abs, err := localWindowsPath(path)
	if err != nil {
		return nil, err
	}
	_, handles, err := pinDirectories(filepath.Dir(abs), false, user)
	if err != nil {
		return nil, err
	}
	ptr, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		closeHandles(handles)
		return nil, err
	}
	handle, err := windows.CreateFile(ptr, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		closeHandles(handles)
		return nil, err
	}
	failed := func(err error) (*privateFile, error) {
		_ = windows.CloseHandle(handle)
		closeHandles(handles)
		return nil, err
	}
	if err := checkedAttributes(handle, false); err != nil {
		return failed(err)
	}
	if err := checkPrivateACL(handle, user); err != nil {
		return failed(err)
	}
	return &privateFile{File: os.NewFile(uintptr(handle), abs), release: func() { closeHandles(handles) }}, nil
}

func validatePrivateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("credentials must be a regular file")
	}
	// Windows mode bits are synthetic; openPrivate checked the owner and DACL.
	return nil
}
