// Command agentserver is the agentd control plane (design 5.7). It is a
// server: `agentserver run` serves relay sessions, the admin API
// (docs/agentserver-openapi.yaml) and the web console. Workspaces, relays,
// tokens, routes and policies are managed through that API or the console;
// this binary has no client commands.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"agentd/internal/cliutil"
	"agentd/internal/control"
	"agentd/internal/store"
	"agentd/web"
)

const usage = `agentserver — agentd control plane

  agentserver run [-c config.yaml]             serve relays, the admin API and the web console
  agentserver backup <file> [-c config.yaml]   export the state database (sealed keys stay sealed)
  agentserver version

Everything else is managed through the web console or the admin API on
admin_listen (docs/agentserver-openapi.yaml), with the admin token as bearer.
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usage)
		return
	}
	switch args[0] {
	case "run":
		cliutil.Fatal(run(args[1:]))
	case "backup":
		cliutil.Fatal(backup(args[1:]))
	case "version":
		fmt.Println("agentserver", control.Version)
	default:
		cliutil.Fatal(fmt.Errorf("unknown command %q: agentserver has run, backup and version; manage workspaces through the web console or the admin API", args[0]))
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("c", cliutil.Env("AGENTSERVER_CONFIG", "/etc/agentserver/config.yaml"), "configuration file")
	if _, err := cliutil.ParseInterleaved(fs, args); err != nil {
		return err
	}
	cfg, err := control.LoadServerConfig(*cfgPath)
	if err != nil {
		return err
	}
	lg, err := cfg.Log.NewLogger()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := control.NewServer(ctx, cfg, control.ServerOptions{Logger: lg, UI: web.Handler()})
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfgPath := fs.String("c", cliutil.Env("AGENTSERVER_CONFIG", "/etc/agentserver/config.yaml"), "configuration file")
	pos, err := cliutil.ParseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: agentserver backup <file>")
	}
	cfg, err := control.LoadServerConfig(*cfgPath)
	if err != nil {
		return err
	}
	url, err := cfg.DatabaseURL()
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, url, cfg.StateKey())
	if err != nil {
		return err
	}
	defer st.Close()
	f, err := os.OpenFile(pos[0], os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := st.Backup(ctx, f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
