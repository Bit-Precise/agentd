//go:build windows

package credentials

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	release, err := Lock(dir)
	if err != nil {
		t.Fatalf("create private Windows test profile: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func credentialSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("this Windows runner cannot create symlink/reparse fixtures: %v", err)
		}
		t.Fatal(err)
	}
}

func setWindowsDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPrivateDirectoryAndInheritedCredentialACL(t *testing.T) {
	dir := privateTempDir(t)
	writeCredentials(t, dir, validCredentials(), 0600)
	// The synthetic Windows Unix mode is not 0600; the inherited DACL is what
	// makes this a valid credential, even after chmod marks it writable.
	if err := os.Chmod(filepath.Join(dir, Filename), 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("private inherited ACL rejected: %v", err)
	}
	user, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	_, handles, err := pinDirectories(dir, false, user)
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandles(handles)
	if err := checkPrivateACL(handles[len(handles)-1], user); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsRejectsBroadAndNullDACL(t *testing.T) {
	user, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, principal := range []string{"WD", "AU", "BU"} {
		t.Run(principal, func(t *testing.T) {
			dir := privateTempDir(t)
			path := writeCredentials(t, dir, validCredentials(), 0600)
			setWindowsDACL(t, path, "D:P(A;;FA;;;"+user.String()+")(A;;FR;;;"+principal+")")
			if _, err := Load(dir); err == nil {
				t.Fatal("broad credential DACL was accepted")
			}
		})
	}
	t.Run("null DACL", func(t *testing.T) {
		dir := privateTempDir(t)
		path := writeCredentials(t, dir, validCredentials(), 0600)
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Fatal("unrestricted NULL DACL accepted")
		}
	})
	t.Run("shared state directory", func(t *testing.T) {
		dir := privateTempDir(t)
		setWindowsDACL(t, dir, "D:P(A;OICI;FA;;;"+user.String()+")(A;OICI;FA;;;WD)")
		if release, err := Lock(dir); err == nil {
			_ = release()
			t.Fatal("shared profile directory accepted")
		}
	})
}

func TestWindowsProfileLockExclusiveAndReleased(t *testing.T) {
	dir := privateTempDir(t)
	release, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = release() })
	if other, err := Lock(dir); err == nil {
		_ = other()
		t.Fatal("same Windows profile locked twice")
	}
	if err := os.Rename(dir, dir+"-renamed"); err == nil {
		t.Fatal("locked state directory could be replaced")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	other, err := Lock(dir)
	if err != nil {
		t.Fatalf("released lock unavailable: %v", err)
	}
	_ = other()
	if err := os.Rename(dir, dir+"-renamed"); err != nil {
		t.Fatalf("directory handles leaked after release: %v", err)
	}
}

func TestWindowsRejectsReparseStateAndLockPaths(t *testing.T) {
	t.Run("ancestor", func(t *testing.T) {
		target := privateTempDir(t)
		link := filepath.Join(t.TempDir(), "link")
		credentialSymlink(t, target, link)
		if release, err := Lock(filepath.Join(link, "child")); err == nil {
			_ = release()
			t.Fatal("state path followed a reparse ancestor")
		}
	})
	t.Run("lock file", func(t *testing.T) {
		dir := privateTempDir(t)
		if err := os.Remove(filepath.Join(dir, ".lock")); err != nil {
			t.Fatal(err)
		}
		target := writeCredentials(t, privateTempDir(t), validCredentials(), 0600)
		credentialSymlink(t, target, filepath.Join(dir, ".lock"))
		if release, err := Lock(dir); err == nil {
			_ = release()
			t.Fatal("profile lock followed a reparse file")
		}
	})
}

func TestWindowsCredentialHandleBlocksReplacement(t *testing.T) {
	dir := privateTempDir(t)
	path := writeCredentials(t, dir, validCredentials(), 0600)
	f, err := openPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(path, path+".old"); err == nil {
		t.Fatal("credential could be replaced during validated read")
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err == nil {
		t.Fatal("credential could be modified during validated read")
	}
}

func TestWindowsProfileLockChild(t *testing.T) {
	if os.Getenv("AGENTD_WINDOWS_LOCK_HELPER") != "1" {
		return
	}
	_, err := Lock(os.Getenv("AGENTD_WINDOWS_LOCK_DIR"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println("locked")
	<-time.After(time.Minute)
	os.Exit(3)
}

func TestWindowsProfileLockReleasedAfterProcessExit(t *testing.T) {
	dir := privateTempDir(t)
	command := exec.Command(os.Args[0], "-test.run=^TestWindowsProfileLockChild$")
	command.Env = append(os.Environ(), "AGENTD_WINDOWS_LOCK_HELPER=1", "AGENTD_WINDOWS_LOCK_DIR="+dir)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "locked\n" {
			_ = command.Wait()
			t.Fatalf("lock child failed: %q, %s", line, stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("lock child did not become ready")
	}
	if release, err := Lock(dir); err == nil {
		_ = release()
		t.Fatal("child's kernel lock did not exclude parent")
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	release, err := Lock(dir)
	if err != nil {
		t.Fatalf("crashed process left a stale lock: %v", err)
	}
	_ = release()
}
