package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/bit-precise/agentd/control"
	"github.com/bit-precise/agentd/credentials"
	"github.com/rs/zerolog"
	"golang.org/x/net/netutil"
	"gopkg.in/yaml.v3"
)

var Version = "dev"

func main() {
	log := zerolog.New(os.Stderr).With().Timestamp().Logger()
	if err := run(os.Args[1:], os.Stdout, log); err != nil {
		log.Error().Err(err).Msg("agents stopped")
		os.Exit(1)
	}
}
func run(args []string, out io.Writer, log zerolog.Logger) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		_, err := fmt.Fprintln(out, "agents init --config agents.yaml\nagents serve --config agents.yaml\nagents version")
		return err
	}
	if args[0] == "version" || args[0] == "--version" {
		_, err := fmt.Fprintln(out, Version)
		return err
	}
	command := args[0]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(out)
	path := fs.String("config", "agents.yaml", "server configuration")
	var listen, serverURL, edgeURL, stateDir, certFile, keyFile *string
	var development *bool
	if command == "init" {
		listen = fs.String("listen", "127.0.0.1:8080", "listener")
		serverURL = fs.String("server-url", "http://localhost:8080", "console/control origin")
		edgeURL = fs.String("edge-url", "", "public XHTTP endpoint")
		stateDir = fs.String("state-dir", "./state/agents", "private state directory")
		development = fs.Bool("development-http", true, "loopback-only HTTP development mode")
		certFile = fs.String("tls-cert", "", "TLS certificate")
		keyFile = fs.String("tls-key", "", "TLS private key")
	}
	if command != "init" && command != "serve" && command != "run" {
		return errors.New("unknown agents command")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if command == "init" {
		cfg := control.Config{ListenAddress: *listen, ServerURL: *serverURL, EdgeURL: *edgeURL, StateDir: *stateDir, DevelopmentHTTP: *development}
		if cfg.EdgeURL == "" {
			cfg.EdgeURL = cfg.ServerURL + "/agent"
		}
		cfg.Database.Type = "sqlite"
		cfg.TLS.CertFile = *certFile
		cfg.TLS.KeyFile = *keyFile
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return err
		}
		base := filepath.Dir(absolute)
		dataDir := cfg.StateDir
		if !filepath.IsAbs(dataDir) {
			dataDir = filepath.Join(base, dataDir)
		}
		cfg.AdminTokenFile = filepath.Join(cfg.StateDir, "admin.token")
		cfg.Database.DSN = filepath.Join(cfg.StateDir, "agents.db")
		if err := cfg.Validate(); err != nil {
			return err
		}
		if _, err := os.Lstat(absolute); !os.IsNotExist(err) {
			return errors.New("configuration already exists or cannot be inspected")
		}
		unlock, err := credentials.Lock(dataDir)
		if err != nil {
			return err
		}
		defer unlock()
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return err
		}
		tokenPath := filepath.Join(dataDir, "admin.token")
		f, err := os.OpenFile(tokenPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.WriteString(hex.EncodeToString(secret[:]) + "\n")
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(base, 0700); err != nil {
			return err
		}
		f, err = os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		closeErr = f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		_, err = fmt.Fprintf(out, "Configuration: %s\nAdmin token file: %s\nConsole: %s/console/\n", absolute, tokenPath, cfg.ServerURL)
		return err
	}
	cfg, err := control.LoadConfig(*path)
	if err != nil {
		return err
	}
	token, err := credentials.ReadSecret(cfg.AdminTokenFile)
	if err != nil {
		return fmt.Errorf("read admin token: %w", err)
	}
	unlock, err := credentials.Lock(cfg.StateDir)
	if err != nil {
		return err
	}
	defer unlock()
	ctx, cancel := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer cancel()
	app, err := control.New(ctx, cfg, token)
	if err != nil {
		return err
	}
	defer app.Close()
	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 32 << 10, IdleTimeout: 2 * time.Minute}
	result := make(chan error, 1)
	go func() {
		l := netutil.LimitListener(listener, 256)
		if cfg.DevelopmentHTTP {
			result <- server.Serve(l)
		} else {
			result <- server.ServeTLS(l, cfg.TLS.CertFile, cfg.TLS.KeyFile)
		}
	}()
	log.Info().Str("listen", listener.Addr().String()).Str("console", cfg.ServerURL+"/console/").Msg("agents control, edge and console ready")
	select {
	case err := <-result:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	_ = app.Close()
	shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return err
	}
	return nil
}
