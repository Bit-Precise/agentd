//go:build linux || darwin

package elevator

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
)

const (
	launchdLabel = "dev.agentd.elevator"
	launchdPlist = "/Library/LaunchDaemons/dev.agentd.elevator.plist"
	systemdUnit  = "/etc/systemd/system/agentd-elevator.service"
)

// Install registers the elevator as a system service for one user's agentd.
// It must run as root (sudo agentd elevator install).
func Install(exe, allow string) error {
	uid, err := strconv.Atoi(allow)
	if err != nil {
		return fmt.Errorf("allowed user must be a uid, got %q", allow)
	}
	if os.Geteuid() != 0 {
		return errors.New("installing the elevator needs root: sudo agentd elevator install")
	}
	switch runtime.GOOS {
	case "darwin":
		plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + launchdLabel + `</string>
  <key>ProgramArguments</key>
  <array><string>` + exe + `</string><string>elevator</string><string>run</string><string>--allow-uid</string><string>` + strconv.Itoa(uid) + `</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/agentd-elevator.log</string>
</dict>
</plist>
`
		_, _ = run("launchctl", "bootout", "system/"+launchdLabel)
		if err := os.WriteFile(launchdPlist, []byte(plist), 0o644); err != nil {
			return err
		}
		_, err := run("launchctl", "bootstrap", "system", launchdPlist)
		return err
	case "linux":
		unit := fmt.Sprintf(`[Unit]
Description=agentd elevator (TUN helper)
After=network-online.target

[Service]
ExecStart=%s elevator run --allow-uid %d
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
`, exe, uid)
		if err := os.WriteFile(systemdUnit, []byte(unit), 0o644); err != nil {
			return err
		}
		if _, err := run("systemctl", "daemon-reload"); err != nil {
			return err
		}
		_, err := run("systemctl", "enable", "--now", "agentd-elevator.service")
		return err
	}
	return fmt.Errorf("unsupported OS %s", runtime.GOOS)
}

// Uninstall removes the service.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("needs root: sudo agentd elevator uninstall")
	}
	switch runtime.GOOS {
	case "darwin":
		_, _ = run("launchctl", "bootout", "system/"+launchdLabel)
		return removeIfExists(launchdPlist)
	case "linux":
		_, _ = run("systemctl", "disable", "--now", "agentd-elevator.service")
		err := removeIfExists(systemdUnit)
		_, _ = run("systemctl", "daemon-reload")
		return err
	}
	return nil
}

func removeIfExists(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
