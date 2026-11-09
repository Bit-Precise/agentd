// Command agentd is the node daemon and its CLI (design 9.2).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"agentd/internal/agent"
	"agentd/internal/cliutil"
	"agentd/internal/identity"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

const usage = `agentd — node daemon of the agentd workspace network

Usage: agentd [-i instance] [--home dir] <command> [args]

  run                                   run the daemon in the foreground
  join <link|-> [--name n] [--replace]  join a workspace with a join link (- reads stdin)
  leave                                 leave the workspace (keeps node.key)
  key show                              print this node's names: agentd://<key> and agentd://<ws>/<name>
  status                                session, relay, versions
  peers                                 directory: members, groups, workspace key (to copy into policies)
  routes                                split-routing table and services
  connect <host> <port>                 bridge stdin/stdout to host:port (ssh ProxyCommand)
  reload                                reload config.yaml (policies, services)
  task exec <executor> [--workdir d] [--yield-ms n] -- <command…>
  task stdin <executor> <session-id> [text]
  mcp                                   stdio MCP server (tools <executor>__<tool>)
  service install|uninstall             run as a user service (LaunchAgent, systemd --user, scheduled task)
  elevator install|uninstall|run        TUN helper (macOS, Linux; install with sudo, once per device)
  version

Instances: the default instance lives in ~/.agentd; others in
~/.agentd/instances/<name> (-i <name> or AGENTD_INSTANCE). AGENTD_HOME or
--home points an instance anywhere. AGENTD_EXTRA_ROOTS adds trusted CA files
for private deployments; certificates are always verified.
`

type globals struct {
	instance string
	home     string
	dir      string
}

func main() {
	g := &globals{}
	args := os.Args[1:]
	// Global flags before the command.
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch a := args[0]; {
		case a == "-h" || a == "--help":
			fmt.Print(usage)
			return
		case a == "-i" || a == "--instance":
			if len(args) < 2 {
				cliutil.Fatal(errors.New("-i needs an instance name"))
			}
			g.instance, args = args[1], args[2:]
		case strings.HasPrefix(a, "--instance="):
			g.instance, args = strings.TrimPrefix(a, "--instance="), args[1:]
		case a == "--home":
			if len(args) < 2 {
				cliutil.Fatal(errors.New("--home needs a directory"))
			}
			g.home, args = args[1], args[2:]
		case strings.HasPrefix(a, "--home="):
			g.home, args = strings.TrimPrefix(a, "--home="), args[1:]
		default:
			cliutil.Fatal(fmt.Errorf("unknown flag %s", a))
		}
	}
	if len(args) == 0 || args[0] == "help" {
		fmt.Print(usage)
		return
	}
	dir, err := agent.Home(g.instance, g.home)
	cliutil.Fatal(err)
	g.dir = dir
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		cliutil.Fatal(run(g))
	case "join":
		cliutil.Fatal(join(g, rest))
	case "leave":
		cliutil.Fatal(leave(g))
	case "key":
		if len(rest) != 1 || rest[0] != "show" {
			cliutil.Fatal(errors.New("usage: agentd key show"))
		}
		cliutil.Fatal(keyShow(g))
	case "status":
		cliutil.Fatal(status(g))
	case "peers":
		cliutil.Fatal(peers(g))
	case "routes":
		cliutil.Fatal(routesCmd(g))
	case "connect":
		cliutil.Fatal(connect(g, rest))
	case "reload":
		cliutil.Fatal(agent.NewLocalClient(g.dir).Reload(context.Background()))
		fmt.Println("reloaded")
	case "task":
		cliutil.Fatal(taskCmd(g, rest))
	case "mcp":
		cliutil.Fatal(mcpStdio(g))
	case "service":
		cliutil.Fatal(serviceCmd(g, rest))
	case "elevator":
		cliutil.Fatal(elevatorCmd(rest))
	case "version":
		fmt.Println("agentd", agent.Version)
	default:
		cliutil.Fatal(fmt.Errorf("unknown command %q; see agentd --help", cmd))
	}
}

func run(g *globals) error {
	a, err := agent.New(g.dir, agent.Options{})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go reloadOnHUP(ctx, a)
	return a.Run(ctx)
}

func join(g *globals, args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	name := fs.String("name", "", "instance name to propose (default: hostname)")
	replace := fs.Bool("replace", false, "replace an existing membership of this instance")
	pos, err := cliutil.ParseInterleaved(fs, args)
	if err != nil {
		return err
	}
	link := ""
	if len(pos) > 0 && pos[0] != "-" {
		link = pos[0]
	} else {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		link = strings.TrimSpace(line)
	}
	if link == "" {
		return errors.New("usage: agentd join <link>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := agent.Join(ctx, g.dir, link, agent.JoinOptions{Name: *name, Replace: *replace})
	if err != nil {
		return err
	}
	fmt.Printf("joined %s as %s via relay %s\n", res.Workspace, res.Name, res.Relay)
	fmt.Printf("node key: agentd://%s\n", identity.EncodeKey(res.Key))
	fmt.Printf("config:   %s\n", g.dir+string(os.PathSeparator)+"config.yaml")
	fmt.Println("enable roles in the config, then start the daemon: agentd run (or agentd service install)")
	return nil
}

func leave(g *globals) error {
	err := agent.NewLocalClient(g.dir).Leave(context.Background())
	if errors.Is(err, agent.ErrNotRunning) {
		err = agent.LeaveDir(g.dir)
	}
	if err != nil {
		return err
	}
	fmt.Println("left the workspace; node.key was kept")
	return nil
}

func keyShow(g *globals) error {
	key, created, err := identity.LoadOrCreateKey(agent.KeyPath(g.dir))
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintln(os.Stderr, "generated", agent.KeyPath(g.dir))
	}
	fmt.Println("agentd://" + identity.EncodeKey(identity.Public(key)))
	if cfg, err := agent.LoadConfig(g.dir); err == nil {
		fmt.Println("agentd://" + cfg.Workspace.Domain + "/" + cfg.Metadata.Name)
	}
	return nil
}

func status(g *globals) error {
	st, err := agent.NewLocalClient(g.dir).Status(context.Background())
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(b))
	return nil
}

func peers(g *globals) error {
	ps, err := agent.NewLocalClient(g.dir).Peers(context.Background())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tNAME\tONLINE\tROLES\tPUBLIC KEY")
	for _, p := range ps {
		online := ""
		if p.Kind == "member" {
			online = map[bool]string{true: "yes", false: "no"}[p.Online]
		}
		name := p.Name
		if p.Self {
			name += " (self)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Kind, name, online, strings.Join(p.Roles, ","), p.Key)
	}
	return tw.Flush()
}

func routesCmd(g *globals) error {
	v, err := agent.NewLocalClient(g.dir).Routes(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("routes version %d, default %s\n", v.Version, v.Default)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "MATCH\tPROTO\tACTION")
	for _, r := range v.Routes {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Match, strings.Join(r.Protos, ","), r.Action)
	}
	tw.Flush()
	if len(v.Services) > 0 {
		fmt.Println()
		tw = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SERVICE\tPROTO\tNODE\tSTATE")
		for _, s := range v.Services {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.FQDN, s.Proto, s.Node, s.State)
		}
		tw.Flush()
	}
	return nil
}

func connect(g *globals, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: agentd connect <host> <port>")
	}
	port, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	c, err := agent.NewLocalClient(g.dir).Connect(context.Background(), args[0], port)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		io.Copy(os.Stdout, c)
		close(done)
	}()
	io.Copy(c, os.Stdin)
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	<-done
	return nil
}

func taskCmd(g *globals, args []string) error {
	if len(args) < 2 {
		return errors.New("usage: agentd task exec <executor> -- <command…> | agentd task stdin <executor> <session-id> [text]")
	}
	cl := agent.NewLocalClient(g.dir)
	ctx := context.Background()
	var req agent.TaskRequest
	switch args[0] {
	case "exec":
		fs := flag.NewFlagSet("task exec", flag.ExitOnError)
		workdir := fs.String("workdir", "", "working directory under the executor's root")
		yield := fs.Int("yield-ms", 0, "how long to wait for output (250-30000)")
		pos, err := cliutil.ParseInterleaved(fs, args[1:])
		if err != nil {
			return err
		}
		if len(pos) < 2 {
			return errors.New("usage: agentd task exec <executor> -- <command…>")
		}
		m := map[string]any{"cmd": strings.Join(pos[1:], " ")}
		if *workdir != "" {
			m["workdir"] = *workdir
		}
		if *yield > 0 {
			m["yield_time_ms"] = *yield
		}
		b, _ := json.Marshal(m)
		req = agent.TaskRequest{Executor: pos[0], Tool: "exec_command", Arguments: b}
	case "stdin":
		if len(args) < 3 {
			return errors.New("usage: agentd task stdin <executor> <session-id> [text]")
		}
		id, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return err
		}
		m := map[string]any{"session_id": id}
		if len(args) > 3 {
			m["chars"] = strings.Join(args[3:], " ") + "\n"
		}
		b, _ := json.Marshal(m)
		req = agent.TaskRequest{Executor: args[1], Tool: "write_stdin", Arguments: b}
	default:
		return fmt.Errorf("unknown task command %q", args[0])
	}
	res, err := cl.Task(ctx, req)
	if err != nil {
		return err
	}
	fmt.Print(res.OutputText)
	if !strings.HasSuffix(res.OutputText, "\n") {
		fmt.Println()
	}
	if res.IsError {
		os.Exit(1)
	}
	if res.ExitCode != nil && *res.ExitCode != 0 {
		os.Exit(int(*res.ExitCode))
	}
	return nil
}

// mcpStdio serves MCP on stdin/stdout, backed by the daemon's local API.
func mcpStdio(g *globals) error {
	cl := agent.NewLocalClient(g.dir)
	srv := agent.NewMCPServer(cl)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Refresh(ctx); err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = srv.Refresh(ctx)
			}
		}
	}()
	return srv.Server().Run(ctx, &mcp.StdioTransport{})
}

var _ = wire.StatusOf
var _ = pb.Status_OK
