package db

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bit-precise/agentd/control/types"
)

func TestSQLiteCompositeForeignKeysAndRollback(t *testing.T) {
	store, err := Open(t.Context(), Options{DSN: filepath.Join(t.TempDir(), "db.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := store.sql.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO users(id,name,payload) VALUES('u','alice','{}')")
	exec("INSERT INTO workspaces(id,name,payload) VALUES('w1','one','{}'),('w2','two','{}')")
	exec("INSERT INTO agents(id,workspace_id,user_id,name,payload) VALUES('a','w1','u','agent','{}')")
	if _, err := store.sql.Exec("INSERT INTO services(id,workspace_id,agent_id,name,hostname,payload) VALUES('foreign','w2','a','demo','demo.two.test','{}')"); err == nil {
		t.Fatal("cross-workspace service FK accepted")
	}
	exec("INSERT INTO services(id,workspace_id,agent_id,name,hostname,payload) VALUES('svc','w1','a','demo','demo.one.test','{}')")
	if _, err := store.sql.Exec("INSERT INTO grants(id,workspace_id,resource_type,service_id,subject_type,payload) VALUES('g','w2','service','svc','anonymous','{}')"); err == nil {
		t.Fatal("cross-workspace grant FK accepted")
	}
	if _, err := store.sql.Exec("INSERT INTO memberships(workspace_id,user_id,role,payload) VALUES('w1','u','superuser','{}')"); err == nil {
		t.Fatal("undefined membership role accepted")
	}
}

func TestSaveRevisionConflictAndTransactionRollback(t *testing.T) {
	store, err := Open(context.Background(), Options{DSN: filepath.Join(t.TempDir(), "db.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := types.Snapshot{Revision: 1, Users: []types.User{{ID: "u", Name: "alice"}}}
	if err = store.Save(t.Context(), first, 0); err != nil {
		t.Fatal(err)
	}
	bad := types.Snapshot{Revision: 2, Users: []types.User{{ID: "u2", Name: "bad"}}, Agents: []types.Agent{{ID: "a", WorkspaceID: "nonexistent", UserID: "u2", Name: "invalid"}}}
	if err = store.Save(t.Context(), bad, 1); err == nil {
		t.Fatal("invalid snapshot committed")
	}
	loaded, err := store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != 1 || len(loaded.Users) != 1 || loaded.Users[0].Name != "alice" {
		t.Fatal("failed transaction partially changed control state")
	}
	if err = store.Save(t.Context(), types.Snapshot{Revision: 2}, 0); types.KindOf(err) != "conflict" {
		t.Fatalf("stale control writer was not fenced: %v", err)
	}
}
