package pgtest_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"agentd/internal/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

func TestNewDBIsIsolatedAndQueryable(t *testing.T) {
	ctx := context.Background()
	a := pgtest.NewDB(t)
	b := pgtest.NewDB(t)
	if a == b {
		t.Fatalf("two calls returned the same database: %s", a)
	}
	conn, err := pgx.Connect(ctx, a)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `create table marker (x int)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	conn2, err := pgx.Connect(ctx, b)
	if err != nil {
		t.Fatalf("connect b: %v", err)
	}
	defer conn2.Close(ctx)
	var n int
	if err := conn2.QueryRow(ctx, `select count(*) from information_schema.tables where table_name = 'marker'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 0 {
		t.Fatalf("table from database a leaked into database b")
	}
}
