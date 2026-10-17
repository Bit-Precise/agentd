package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bit-precise/agentd/control/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// The test creates a dedicated schema rather than deleting records from a
// caller's database. CI grants its disposable PostgreSQL user CREATE privilege.
func TestPostgresPersistenceAndConstraints(t *testing.T) {
	dsn := os.Getenv("AGENTS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set AGENTS_TEST_POSTGRES_DSN to run real PostgreSQL persistence tests")
	}
	connection, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	var random [12]byte
	if _, err = rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schemaName := "agentd_test_" + hex.EncodeToString(random[:])
	if _, err = connection.ExecContext(t.Context(), "CREATE SCHEMA "+schemaName); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := connection.Exec("DROP SCHEMA " + schemaName + " CASCADE")
		if err != nil {
			t.Errorf("clean PostgreSQL test schema: %v", err)
		}
		_ = connection.Close()
	})
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if config.RuntimeParams == nil {
		config.RuntimeParams = map[string]string{}
	}
	config.RuntimeParams["search_path"] = schemaName
	registered := stdlib.RegisterConnConfig(config)
	defer stdlib.UnregisterConnConfig(registered)
	options := Options{Driver: "postgres", DSN: registered}
	store, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	baseline := types.Snapshot{Revision: 1, Users: []types.User{{ID: "user", Name: "alice"}}, Workspaces: []types.Workspace{{ID: "w1", Name: "one"}, {ID: "w2", Name: "two"}}, Memberships: []types.Membership{{WorkspaceID: "w1", UserID: "user", Role: "owner"}}, Agents: []types.Agent{{ID: "agent", WorkspaceID: "w1", UserID: "user", Name: "provider"}}, Services: []types.Service{{ID: "service", WorkspaceID: "w1", AgentID: "agent", Name: "demo", Hostname: "demo.one.example"}}, Tokens: []types.Token{{ID: "token", Hash: strings.Repeat("a", 64), Kind: "provider", UserID: "user", WorkspaceID: "w1", AgentID: "agent", ExpiresAt: time.Now().Add(time.Hour)}}}
	if err = store.Save(t.Context(), baseline, 0); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != 1 || len(loaded.Services) != 1 || len(loaded.Tokens) != 1 || loaded.Tokens[0].Hash != baseline.Tokens[0].Hash {
		t.Fatal("PostgreSQL restart lost records or token hashes")
	}
	if err = store.Save(t.Context(), types.Snapshot{Revision: 1}, 0); types.KindOf(err) != "conflict" {
		t.Fatalf("stale PostgreSQL writer not fenced: %v", err)
	}
	for _, resource := range []string{"service", "grant"} {
		t.Run(resource, func(t *testing.T) {
			invalid := baseline
			invalid.Revision = 2
			if resource == "service" {
				invalid.Services = []types.Service{{ID: "foreign", WorkspaceID: "w2", AgentID: "agent", Name: "foreign", Hostname: "foreign.two.example"}}
			} else {
				invalid.Grants = []types.Grant{{ID: "foreign", WorkspaceID: "w2", ResourceType: "service", ResourceID: "service", SubjectType: "anonymous", StartsAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}}
			}
			if err := store.Save(t.Context(), invalid, 1); err == nil {
				t.Fatal("cross-workspace composite foreign key accepted")
			}
			got, err := store.Load(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if got.Revision != 1 || len(got.Services) != 1 || got.Services[0].ID != "service" || len(got.Tokens) != 1 {
				t.Fatal("failed PostgreSQL transaction partially replaced state")
			}
		})
	}
}
