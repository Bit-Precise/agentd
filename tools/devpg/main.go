// Command devpg runs a throwaway PostgreSQL for local development (the same
// embedded binaries the tests use). It prints the connection URL and runs
// until interrupted.
//
//	go run ./tools/devpg -port 55432 -data .dev/pg
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

func main() {
	port := flag.Uint("port", 55432, "port")
	data := flag.String("data", ".dev/pg", "data directory (kept between runs)")
	flag.Parse()
	abs, _ := filepath.Abs(*data)
	home, _ := os.UserHomeDir()
	cfg := embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V17).
		Port(uint32(*port)).
		Username("agentd").Password("agentd").Database("agentd").
		DataPath(filepath.Join(abs, "data")).
		RuntimePath(filepath.Join(abs, "runtime")).
		BinariesPath(filepath.Join(abs, "bin")).
		CachePath(filepath.Join(home, ".cache", "agentd", "embedded-postgres")).
		Logger(io.Discard)
	pg := embeddedpostgres.NewDatabase(cfg)
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "devpg:", err)
		os.Exit(1)
	}
	fmt.Printf("postgres://agentd:agentd@127.0.0.1:%d/agentd?sslmode=disable\n", *port)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	_ = pg.Stop()
}
