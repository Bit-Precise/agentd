//go:build windows

package elevator

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	serviceName = "agentd-elevator"
	wintunURL   = "https://www.wintun.net/builds/wintun-0.14.1.zip"
	wintunSHA   = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
)

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// CurrentSID is the SID of the user running this process.
func CurrentSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// ensureWintun puts wintun.dll next to the executable, downloading the
// pinned release (verified by SHA-256) when it is missing.
func ensureWintun(exe string) error {
	dst := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, wintunURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download wintun: %w (or place wintun.dll from %s next to agentd.exe)", err, wintunURL)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != wintunSHA {
		return errors.New("wintun download does not match the pinned SHA-256")
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	want := "wintun/bin/" + runtime.GOARCH + "/wintun.dll"
	for _, f := range zr.File {
		if f.Name != want {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.Create(dst)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return fmt.Errorf("%s not found in the wintun archive", want)
}

// Install registers the elevator as a Windows service for one user (run it
// from an administrator shell; allow is that user's SID, empty for the
// current user).
func Install(exe, allow string) error {
	if !elevated() {
		return errors.New("installing the elevator needs an administrator shell")
	}
	if allow == "" {
		sid, err := CurrentSID()
		if err != nil {
			return err
		}
		allow = sid
	}
	if err := ensureWintun(exe); err != nil {
		return err
	}
	_ = exec.Command("sc.exe", "stop", serviceName).Run()
	_ = exec.Command("sc.exe", "delete", serviceName).Run()
	bin := fmt.Sprintf(`"%s" elevator run --allow-sid %s`, exe, allow)
	if out, err := exec.Command("sc.exe", "create", serviceName, "binPath=", bin, "start=", "auto", "DisplayName=", "agentd elevator").CombinedOutput(); err != nil {
		return fmt.Errorf("sc create: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sc.exe", "start", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("sc start: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Uninstall removes the service.
func Uninstall() error {
	if !elevated() {
		return errors.New("needs an administrator shell")
	}
	_ = exec.Command("sc.exe", "stop", serviceName).Run()
	if out, err := exec.Command("sc.exe", "delete", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("sc delete: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RunService runs the server under the service control manager when started
// as a service, and directly otherwise.
func RunService(ctx context.Context, s *Server) error {
	if ok, _ := svc.IsWindowsService(); !ok {
		return s.Run(ctx)
	}
	return svc.Run(serviceName, &service{s: s})
}

type service struct{ s *Server }

func (h *service) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status <- svc.Status{State: svc.StartPending}
	errc := make(chan error, 1)
	go func() { errc <- h.s.Run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-errc
				return false, 0
			}
		case err := <-errc:
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}
