// Command agentrelay is the agentd data plane (design 5.8).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"agentd/internal/cliutil"
	"agentd/internal/identity"
	"agentd/internal/relay"
)

const usage = `agentrelay — agentd data plane

  agentrelay run [-c config.yaml]        serve node sessions, forwarding and the edge
  agentrelay key show [-c config.yaml]   print the relay public key (for agentserver relay add)
  agentrelay version
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usage)
		return
	}
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	cfgPath := fs.String("c", cliutil.Env("AGENTRELAY_CONFIG", "/etc/agentrelay/config.yaml"), "configuration file")
	switch args[0] {
	case "run":
		_, err := cliutil.ParseInterleaved(fs, args[1:])
		cliutil.Fatal(err)
		cliutil.Fatal(run(*cfgPath))
	case "key":
		pos, err := cliutil.ParseInterleaved(fs, args[1:])
		cliutil.Fatal(err)
		if len(pos) != 1 || pos[0] != "show" {
			cliutil.Fatal(fmt.Errorf("usage: agentrelay key show"))
		}
		cfg, err := relay.LoadConfig(*cfgPath)
		cliutil.Fatal(err)
		key, created, err := identity.LoadOrCreateKey(cfg.KeyFile)
		cliutil.Fatal(err)
		if created {
			fmt.Fprintln(os.Stderr, "generated", cfg.KeyFile)
		}
		fmt.Println(identity.EncodeKey(identity.Public(key)))
	case "version":
		fmt.Println("agentrelay", relay.Version)
	default:
		cliutil.Fatal(fmt.Errorf("unknown command %q", args[0]))
	}
}

func run(path string) error {
	cfg, err := relay.LoadConfig(path)
	if err != nil {
		return err
	}
	lg, err := cfg.Log.NewLogger()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv, err := relay.NewServer(cfg, relay.Options{Logger: lg})
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}
