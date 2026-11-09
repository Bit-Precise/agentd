// Package pgtest gives tests a fresh PostgreSQL database each.
//
// It uses AGENTD_TEST_DATABASE_URL when set (CI runs a postgres service);
// otherwise it starts one embedded PostgreSQL per test binary. When neither is
// available, NewDB skips the test unless AGENTD_REQUIRE_POSTGRES=1.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
)

var (
	mu       sync.Mutex
	adminURL string // connection URL with rights to CREATE DATABASE
	startErr error
)

// Main wraps testing.M: it prepares the server, runs the tests and stops the
// server. Use it as `func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }`.
func Main(m *testing.M) int {
	stop := setup()
	code := m.Run()
	stop()
	return code
}

func setup() func() {
	if u := os.Getenv("AGENTD_TEST_DATABASE_URL"); u != "" {
		adminURL = u
		return func() {}
	}
	port, err := freePort()
	if err != nil {
		startErr = err
		return func() {}
	}
	dir, err := os.MkdirTemp("", "agentd-pgtest-")
	if err != nil {
		startErr = err
		return func() {}
	}
	cache := os.Getenv("AGENTD_PG_CACHE")
	if cache == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cache = filepath.Join(home, ".cache", "agentd", "embedded-postgres")
		}
	}
	cfg := embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V17).
		Port(uint32(port)).
		Username("postgres").
		Password("postgres").
		Database("postgres").
		RuntimePath(filepath.Join(dir, "runtime")).
		DataPath(filepath.Join(dir, "data")).
		BinariesPath(filepath.Join(dir, "bin")).
		CachePath(cache).
		StartTimeout(60 * time.Second).
		Logger(io.Discard)
	pg := embeddedpostgres.NewDatabase(cfg)
	if err := pg.Start(); err != nil {
		startErr = fmt.Errorf("start embedded postgres: %w", err)
		os.RemoveAll(dir)
		return func() {}
	}
	adminURL = fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	return func() {
		_ = pg.Stop()
		os.RemoveAll(dir)
	}
}

// NewDB creates an empty database and returns its connection URL. The database
// is dropped when the test finishes.
func NewDB(t testing.TB) string {
	t.Helper()
	mu.Lock()
	base, err := adminURL, startErr
	mu.Unlock()
	if base == "" {
		if err == nil {
			err = fmt.Errorf("pgtest.Main was not called from TestMain")
		}
		if os.Getenv("AGENTD_REQUIRE_POSTGRES") == "1" {
			t.Fatalf("postgres unavailable: %v", err)
		}
		t.Skipf("postgres unavailable: %v", err)
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer conn.Close(ctx)
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "t_" + hex.EncodeToString(b[:])
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse admin url: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
