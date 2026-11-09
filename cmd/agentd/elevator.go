package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"agentd/internal/cliutil"
	"agentd/internal/elevator"
)

// elevatorCmd manages the privileged TUN helper (design 5.2).
func elevatorCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentd elevator install|uninstall|run")
	}
	fs := flag.NewFlagSet("elevator", flag.ExitOnError)
	uid := fs.Int("allow-uid", -1, "uid whose agentd may use the TUN (macOS, Linux; install defaults to the sudo user)")
	sid := fs.String("allow-sid", "", "SID whose agentd may use the TUN (Windows; install defaults to the current user)")
	socket := fs.String("socket", cliutil.Env("AGENTD_ELEVATOR_SOCKET", elevator.DefaultSocket), "listening socket")
	if _, err := cliutil.ParseInterleaved(fs, args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "run":
		if *uid < 0 && *sid == "" {
			return errors.New("elevator run needs --allow-uid (or --allow-sid on Windows)")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return elevator.RunService(ctx, &elevator.Server{Socket: *socket, AllowUID: *uid, AllowSID: *sid})
	case "install":
		allow := *sid
		if runtime.GOOS != "windows" {
			if *uid < 0 {
				v, err := strconv.Atoi(os.Getenv("SUDO_UID"))
				if err != nil {
					return errors.New("run with sudo, or pass --allow-uid <uid>")
				}
				*uid = v
			}
			allow = strconv.Itoa(*uid)
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		exe, _ = filepath.EvalSymlinks(exe)
		if err := elevator.Install(exe, allow); err != nil {
			return err
		}
		fmt.Println("elevator installed; enable roles.ingress.tun in the instance config and restart agentd")
		return nil
	case "uninstall":
		if err := elevator.Uninstall(); err != nil {
			return err
		}
		fmt.Println("elevator removed")
		return nil
	}
	return fmt.Errorf("unknown elevator command %q", args[0])
}
