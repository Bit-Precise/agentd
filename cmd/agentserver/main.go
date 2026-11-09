// Command agentserver is the agentd control plane (design 5.7): `agentserver
// run` serves relays and the admin API; the other subcommands are a client of
// that API (docs/agentserver-openapi.yaml).
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"agentd/internal/adminapi"
	"agentd/internal/cliutil"
	"agentd/internal/control"
	"agentd/internal/store"
	"agentd/web"
)

const usage = `agentserver — agentd control plane

  agentserver run [-c config.yaml]                 serve relays, the admin API and the web console
  agentserver backup <file> [-c config.yaml]       export the state database (sealed keys stay sealed)
  agentserver version

Admin commands (talk to the admin API; set AGENTSERVER_ADMIN_URL, default
http://127.0.0.1:7800, and AGENTSERVER_ADMIN_TOKEN, or pass --server/--token):

  key show | status | apply -f workspace.yaml
  workspace list|get|create|update|delete|set-relay|key
  relay list|get|add|remove|certs     relay token list|create|revoke
  token list|create|revoke -w <ws>    node list|get|remove|rename|set-roles -w <ws>
  group list|get|create|delete|add|remove -w <ws>
  route list|add|remove|replace -w <ws>
  policy list|add|remove|replace -w <ws>
  service list -w <ws>                cert list|renew -w <ws>

Add -o json to any admin command for raw JSON.
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
		cliutil.Fatal(admin(args))
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

// client builds an admin API client from flags or the environment.
type client struct {
	api *adminapi.ClientWithResponses
	out string
	ws  string
}

func newClient(server, token, out, ws string) (*client, error) {
	if token == "" {
		return nil, fmt.Errorf("set AGENTSERVER_ADMIN_TOKEN or pass --token")
	}
	api, err := adminapi.NewClientWithResponses(strings.TrimSuffix(server, "/")+"/api/v1", adminapi.WithRequestEditorFn(func(ctx context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+token)
		return nil
	}))
	return &client{api: api, out: out, ws: ws}, err
}
