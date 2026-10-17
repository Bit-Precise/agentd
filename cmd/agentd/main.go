package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/credentials"
	"github.com/bit-precise/agentd/supervisor"
	"github.com/rs/zerolog"
)

var Version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log := zerolog.New(os.Stderr).With().Timestamp().Logger()
		log.Error().Err(err).Msg("agentd stopped")
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		_, err := fmt.Fprintln(out, "agentd run --config config.yaml\nagentd config validate --config config.yaml\nagentd version")
		return err
	}
	if args[0] == "version" || args[0] == "--version" {
		_, err := fmt.Fprintln(out, Version)
		return err
	}
	command := args[0]
	args = args[1:]
	if command == "config" {
		if len(args) == 0 || args[0] != "validate" {
			return errors.New("expected: agentd config validate --config FILE")
		}
		command = "validate"
		args = args[1:]
	}
	if command != "run" && command != "validate" {
		return errors.New("unknown command; use agentd help")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("config", "config.yaml", "path to the agent configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if command == "validate" {
		_, err := fmt.Fprintln(out, "configuration is valid")
		return err
	}
	c, err := credentials.Load(cfg.Agent.StateDir)
	if err != nil {
		return err
	}
	log := zerolog.New(os.Stderr).With().Timestamp().Logger()
	s, err := supervisor.New(cfg, c, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()
	var hup chan os.Signal
	if sig := reloadSignal(); sig != nil {
		hup = make(chan os.Signal, 1)
		signal.Notify(hup, sig)
		defer signal.Stop(hup)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				next, err := config.Load(*path)
				if err == nil {
					err = s.Reload(next)
				}
				if err != nil {
					log.Error().Err(err).Msg("configuration reload rejected; previous configuration retained")
				} else {
					log.Info().Msg("provider configuration reloaded")
				}
			}
		}
	}()
	return s.Run(ctx)
}
