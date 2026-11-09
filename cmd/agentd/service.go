package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// serviceCmd installs the daemon as a per-user service, one unit per
// instance (design 9.2).
func serviceCmd(g *globals, args []string) error {
	if len(args) != 1 || (args[0] != "install" && args[0] != "uninstall") {
		return errors.New("usage: agentd service install|uninstall")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	name := "agentd"
	if g.instance != "" && g.instance != "default" {
		name = "agentd-" + g.instance
	}
	runArgs := []string{exe}
	if g.home != "" {
		runArgs = append(runArgs, "--home", g.dir)
	} else if g.instance != "" {
		runArgs = append(runArgs, "-i", g.instance)
	}
	runArgs = append(runArgs, "run")
	install := args[0] == "install"
	switch runtime.GOOS {
	case "darwin":
		return launchd(name, runArgs, g.dir, install)
	case "linux":
		return systemdUser(name, runArgs, install)
	case "windows":
		return schtasks(name, runArgs, install)
	}
	return fmt.Errorf("service install is not supported on %s", runtime.GOOS)
}

func sh(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func launchd(name string, runArgs []string, dir string, install bool) error {
	home, _ := os.UserHomeDir()
	label := "dev.agentd." + name
	plist := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	_ = sh("launchctl", "bootout", domain+"/"+label)
	if !install {
		os.Remove(plist)
		fmt.Println("removed", plist)
		return nil
	}
	var argXML strings.Builder
	for _, a := range runArgs {
		argXML.WriteString("    <string>" + xmlEscape(a) + "</string>\n")
	}
	content := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + label + `</string>
  <key>ProgramArguments</key>
  <array>
` + argXML.String() + `  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>` + xmlEscape(filepath.Join(dir, "logs", "launchd.log")) + `</string>
</dict>
</plist>
`
	if err := os.MkdirAll(filepath.Dir(plist), 0o755); err != nil {
		return err
	}
	os.MkdirAll(filepath.Join(dir, "logs"), 0o700)
	if err := os.WriteFile(plist, []byte(content), 0o644); err != nil {
		return err
	}
	if err := sh("launchctl", "bootstrap", domain, plist); err != nil {
		return err
	}
	fmt.Println("installed and started", label)
	return nil
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func systemdUser(name string, runArgs []string, install bool) error {
	home, _ := os.UserHomeDir()
	unit := filepath.Join(home, ".config", "systemd", "user", name+".service")
	if !install {
		_ = sh("systemctl", "--user", "disable", "--now", name+".service")
		os.Remove(unit)
		_ = sh("systemctl", "--user", "daemon-reload")
		fmt.Println("removed", unit)
		return nil
	}
	quoted := make([]string, len(runArgs))
	for i, a := range runArgs {
		quoted[i] = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
	}
	content := `[Unit]
Description=agentd (` + name + `)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=` + strings.Join(quoted, " ") + `
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(unit, []byte(content), 0o644); err != nil {
		return err
	}
	if err := sh("systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if err := sh("systemctl", "--user", "enable", "--now", name+".service"); err != nil {
		return err
	}
	fmt.Println("installed and started", name+".service (to keep it running after logout: loginctl enable-linger)")
	return nil
}

func schtasks(name string, runArgs []string, install bool) error {
	if !install {
		_ = sh("schtasks", "/End", "/TN", name)
		if err := sh("schtasks", "/Delete", "/TN", name, "/F"); err != nil {
			return err
		}
		fmt.Println("removed scheduled task", name)
		return nil
	}
	quoted := make([]string, len(runArgs))
	for i, a := range runArgs {
		quoted[i] = `"` + a + `"`
	}
	if err := sh("schtasks", "/Create", "/TN", name, "/TR", strings.Join(quoted, " "), "/SC", "ONLOGON", "/RL", "LIMITED", "/F"); err != nil {
		return err
	}
	if err := sh("schtasks", "/Run", "/TN", name); err != nil {
		return err
	}
	fmt.Println("installed and started scheduled task", name)
	return nil
}
