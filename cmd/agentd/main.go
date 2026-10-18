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
		_, err := fmt.Fprintln(out, "agentd enroll --config config.yaml --key-file enrollment.key [--replace]\nagentd run --config config.yaml\nagentd config validate --config config.yaml\nagentd version")
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
	replace := flags.Bool("replace", false, "enroll only: replace credentials that Control has revoked or that expired")
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
		client, err := controlclient.New(cfg)
		if err != nil {
			return err
		}
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := os.Lstat(filepath.Join(cfg.Agent.StateDir, credentials.Filename)); !os.IsNotExist(err) {
			if !*replace {
				return errors.New("profile already has credentials; use --replace only after the registration was revoked or expired")
			}
			if err := retireCredentials(ctx, client, cfg.Agent.StateDir, out); err != nil {
				return err
			}
		}
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
	log := zerolog.New(os.Stderr).With().Timestamp().Logger()
	if c.ControlToken != "" {
		client, err := controlclient.New(cfg)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		next, err := client.Refresh(ctx, *c)
		cancel()
		client.Close()
		switch {
		case err == nil:
			c = &next
		case controlclient.AuthenticationRejected(err):
			return fmt.Errorf("device credential revoked or expired; run agentd enroll --replace to register again: %w", err)
		case c.Effective.ExpiresAt.After(time.Now()):
			// Supervision keeps retrying; the stored snapshot bounds offline operation.
			log.Warn().Err(err).Time("effectiveUntil", c.Effective.ExpiresAt).Msg("control unreachable at startup; using the stored effective configuration")
		default:
			return fmt.Errorf("control unreachable and the stored effective configuration expired: %w", err)
		}
	}
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
					log.Error().Err(err).Msg("configuration reload incomplete; runtime-changeable sections were applied")
				} else {
					log.Info().Msg("configuration reloaded")
				}
			}
		}
	}()
	return s.Run(ctx)
}

// retireCredentials allows re-enrollment only when Control no longer accepts
// the stored registration. The old file is kept beside the new one for audit.
func retireCredentials(ctx context.Context, client *controlclient.Client, stateDir string, out io.Writer) error {
	current, err := credentials.Load(stateDir)
	if err == nil && current.ControlToken != "" {
		_, err = client.Refresh(ctx, *current)
		if err == nil {
			return errors.New("the stored registration is still active; revoke it in Control before replacing it")
		}
		if !controlclient.AuthenticationRejected(err) {
			return fmt.Errorf("cannot confirm the stored registration was revoked: %w", err)
		}
	}
	retired := filepath.Join(stateDir, credentials.Filename+".replaced-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.Rename(filepath.Join(stateDir, credentials.Filename), retired); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Retired previous credentials to %s\n", retired)
	return err
}
