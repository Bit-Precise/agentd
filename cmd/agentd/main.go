package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/controlclient"
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
		_, err := fmt.Fprintln(out, "agentd enroll --config config.yaml --key-file enrollment.key\nagentd run --config config.yaml\nagentd config validate --config config.yaml\nagentd version")
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
	if command != "run" && command != "validate" && command != "enroll" {
		return errors.New("unknown command; use agentd help")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("config", "config.yaml", "path to the agent configuration")
	keyFile := flags.String("key-file", "", "private enrollment key file (enroll only)")
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
	if command == "enroll" {
		if *keyFile == "" {
			return errors.New("enroll requires --key-file")
		}
		key, err := credentials.ReadSecret(*keyFile)
		if err != nil {
			return err
		}
		unlock, err := credentials.Lock(cfg.Agent.StateDir)
		if err != nil {
			return err
		}
		defer unlock()
		if _, err := os.Lstat(filepath.Join(cfg.Agent.StateDir, credentials.Filename)); !os.IsNotExist(err) {
			return errors.New("profile already has credentials; refusing to replace its registration")
		}
		client, err := controlclient.New(cfg)
		if err != nil {
			return err
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		response, err := client.Enroll(ctx, key)
		if err != nil {
			return err
		}
		if err := credentials.Save(cfg.Agent.StateDir, &response.Credentials); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Registered %s (%s), status: %s\n", response.Agent.Name, response.Agent.ID, response.Agent.Status)
		return err
	}
	c, err := credentials.Load(cfg.Agent.StateDir)
	if err != nil {
		return err
	}
	if c.ControlToken != "" {
		client, err := controlclient.New(cfg)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		next, err := client.Refresh(ctx, *c)
		cancel()
		client.Close()
		if err != nil {
			return err
		}
		c = &next
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
					log.Error().Err(err).Msg("configuration reload incomplete; see error for applied local restrictions")
				} else {
					log.Info().Msg("provider configuration reloaded")
				}
			}
		}
	}()
	return s.Run(ctx)
}
