// Package db owns explicit SQL migrations and atomic control-plane persistence.
package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bit-precise/agentd/control/types"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type Options struct {
	Driver string
	DSN    string
}
type Store struct{ sql *sql.DB }

func Open(ctx context.Context, options Options) (*Store, error) {
	driver := options.Driver
	if driver == "" {
		driver = "sqlite"
	}
	if driver == "postgres" || driver == "postgresql" {
		driver = "pgx"
	}
	if driver != "sqlite" && driver != "pgx" {
		return nil, fmt.Errorf("unsupported SQL driver %q", driver)
	}
	dsn := options.DSN
	if dsn == "" {
		if driver == "pgx" {
			return nil, errors.New("PostgreSQL DSN is required")
		}
		dsn = "agents.db"
	}
	conn, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1)
	fail := func(err error) (*Store, error) { _ = conn.Close(); return nil, err }
	if err = conn.PingContext(ctx); err != nil {
		return fail(err)
	}
	if driver == "sqlite" {
		for _, q := range []string{"PRAGMA foreign_keys = ON", "PRAGMA busy_timeout = 5000"} {
			if _, err = conn.ExecContext(ctx, q); err != nil {
				return fail(err)
			}
		}
	}
	store := &Store{sql: conn}
	if err = store.migrate(ctx); err != nil {
		return fail(err)
	}
	return store, nil
}
func (s *Store) Close() error { return s.sql.Close() }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range schema {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("control schema migration: %w", err)
		}
	}
	var version int
	if err = tx.QueryRowContext(ctx, "SELECT schema_version FROM control_meta WHERE id=1").Scan(&version); err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("unsupported control schema version %d", version)
	}
	return tx.Commit()
}

var schema = []string{
	`CREATE TABLE IF NOT EXISTS control_meta (id INTEGER PRIMARY KEY CHECK(id=1), revision BIGINT NOT NULL, schema_version INTEGER NOT NULL)`,
	`INSERT INTO control_meta(id,revision,schema_version) VALUES(1,0,1) ON CONFLICT(id) DO NOTHING`,
	`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, payload TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, payload TEXT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS memberships (workspace_id TEXT NOT NULL REFERENCES workspaces(id), user_id TEXT NOT NULL REFERENCES users(id), role TEXT NOT NULL CHECK(role IN ('owner','maintainer','developer','guest')), payload TEXT NOT NULL, PRIMARY KEY(workspace_id,user_id))`,
	`CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL REFERENCES workspaces(id), user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL,payload TEXT NOT NULL,UNIQUE(workspace_id,id),UNIQUE(workspace_id,name))`,
	`CREATE TABLE IF NOT EXISTS enrollment_keys (id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL REFERENCES workspaces(id), user_id TEXT NOT NULL REFERENCES users(id),payload TEXT NOT NULL,UNIQUE(workspace_id,id))`,
	`CREATE TABLE IF NOT EXISTS services (id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL REFERENCES workspaces(id),agent_id TEXT NOT NULL,name TEXT NOT NULL,hostname TEXT NOT NULL UNIQUE,payload TEXT NOT NULL,UNIQUE(workspace_id,id),UNIQUE(workspace_id,name),FOREIGN KEY(workspace_id,agent_id) REFERENCES agents(workspace_id,id))`,
	`CREATE TABLE IF NOT EXISTS egress_routes (id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL REFERENCES workspaces(id),agent_id TEXT NOT NULL,name TEXT NOT NULL,payload TEXT NOT NULL,UNIQUE(workspace_id,id),UNIQUE(workspace_id,name),FOREIGN KEY(workspace_id,agent_id) REFERENCES agents(workspace_id,id))`,
	`CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL REFERENCES workspaces(id),resource_type TEXT NOT NULL CHECK(resource_type IN ('service','egress')),service_id TEXT,route_id TEXT,subject_type TEXT NOT NULL CHECK(subject_type IN ('user','workspace','anonymous')),subject_user_id TEXT REFERENCES users(id),subject_workspace_id TEXT REFERENCES workspaces(id),payload TEXT NOT NULL,FOREIGN KEY(workspace_id,service_id) REFERENCES services(workspace_id,id),FOREIGN KEY(workspace_id,route_id) REFERENCES egress_routes(workspace_id,id),CHECK((resource_type='service' AND service_id IS NOT NULL AND route_id IS NULL) OR (resource_type='egress' AND route_id IS NOT NULL AND service_id IS NULL)),CHECK((subject_type='user' AND subject_user_id IS NOT NULL AND subject_workspace_id IS NULL) OR (subject_type='workspace' AND subject_workspace_id IS NOT NULL AND subject_user_id IS NULL) OR (subject_type='anonymous' AND subject_user_id IS NULL AND subject_workspace_id IS NULL AND resource_type='service')))`,
	`CREATE TABLE IF NOT EXISTS names (workspace_id TEXT NOT NULL REFERENCES workspaces(id),label TEXT NOT NULL,agent_id TEXT,service_id TEXT,PRIMARY KEY(workspace_id,label),FOREIGN KEY(workspace_id,agent_id) REFERENCES agents(workspace_id,id),FOREIGN KEY(workspace_id,service_id) REFERENCES services(workspace_id,id),CHECK((agent_id IS NOT NULL AND service_id IS NULL) OR (agent_id IS NULL AND service_id IS NOT NULL)))`,
	`CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY,hash TEXT NOT NULL UNIQUE,kind TEXT NOT NULL CHECK(kind IN ('user','enrollment','control','provider','access')),user_id TEXT REFERENCES users(id),workspace_id TEXT REFERENCES workspaces(id),agent_id TEXT,enrollment_key_id TEXT,payload TEXT NOT NULL,FOREIGN KEY(workspace_id,agent_id) REFERENCES agents(workspace_id,id),FOREIGN KEY(workspace_id,enrollment_key_id) REFERENCES enrollment_keys(workspace_id,id))`,
	`CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY,payload TEXT NOT NULL)`,
}

func loadRows[T any](ctx context.Context, tx *sql.Tx, table string, dst *[]T) error {
	rows, err := tx.QueryContext(ctx, "SELECT payload FROM "+table)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return err
		}
		var value T
		if err := json.Unmarshal([]byte(data), &value); err != nil {
			return fmt.Errorf("decode %s: %w", table, err)
		}
		*dst = append(*dst, value)
	}
	return rows.Err()
}
func (s *Store) Load(ctx context.Context) (types.Snapshot, error) {
	var snap types.Snapshot
	tx, err := s.sql.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return snap, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "SELECT revision FROM control_meta WHERE id=1").Scan(&snap.Revision); err != nil {
		return snap, err
	}
	calls := []func() error{func() error { return loadRows(ctx, tx, "users", &snap.Users) }, func() error { return loadRows(ctx, tx, "workspaces", &snap.Workspaces) }, func() error { return loadRows(ctx, tx, "memberships", &snap.Memberships) }, func() error { return loadRows(ctx, tx, "agents", &snap.Agents) }, func() error { return loadRows(ctx, tx, "enrollment_keys", &snap.EnrollmentKeys) }, func() error { return loadRows(ctx, tx, "services", &snap.Services) }, func() error { return loadRows(ctx, tx, "egress_routes", &snap.EgressRoutes) }, func() error { return loadRows(ctx, tx, "grants", &snap.Grants) }, func() error { return loadRows(ctx, tx, "tokens", &snap.Tokens) }, func() error { return loadRows(ctx, tx, "audit", &snap.Audit) }}
	for _, load := range calls {
		if err = load(); err != nil {
			return snap, err
		}
	}
	return snap, tx.Commit()
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func (s *Store) Save(ctx context.Context, snap types.Snapshot, expected uint64) error {
	if snap.Revision != expected+1 {
		return &types.Error{Kind: types.KindConflict, Message: "snapshot revision must advance exactly once"}
	}
	tx, err := s.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE control_meta SET revision=$1 WHERE id=1 AND revision=$2", snap.Revision, expected)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return &types.Error{Kind: types.KindConflict, Message: "control state changed; reload before writing"}
	}
	for _, table := range []string{"tokens", "names", "grants", "egress_routes", "services", "enrollment_keys", "agents", "memberships", "audit", "users", "workspaces"} {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	insert := func(query string, value any, args ...any) error {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		args = append(args, string(data))
		_, err = tx.ExecContext(ctx, query, args...)
		return err
	}
	for _, v := range snap.Users {
		if err = insert("INSERT INTO users(id,name,payload) VALUES($1,$2,$3)", v, v.ID, v.Name); err != nil {
			return err
		}
	}
	for _, v := range snap.Workspaces {
		if err = insert("INSERT INTO workspaces(id,name,payload) VALUES($1,$2,$3)", v, v.ID, v.Name); err != nil {
			return err
		}
	}
	for _, v := range snap.Memberships {
		if err = insert("INSERT INTO memberships(workspace_id,user_id,role,payload) VALUES($1,$2,$3,$4)", v, v.WorkspaceID, v.UserID, v.Role); err != nil {
			return err
		}
	}
	for _, v := range snap.Agents {
		if err = insert("INSERT INTO agents(id,workspace_id,user_id,name,payload) VALUES($1,$2,$3,$4,$5)", v, v.ID, v.WorkspaceID, v.UserID, v.Name); err != nil {
			return err
		}
	}
	for _, v := range snap.EnrollmentKeys {
		if err = insert("INSERT INTO enrollment_keys(id,workspace_id,user_id,payload) VALUES($1,$2,$3,$4)", v, v.ID, v.WorkspaceID, v.UserID); err != nil {
			return err
		}
	}
	for _, v := range snap.Services {
		if err = insert("INSERT INTO services(id,workspace_id,agent_id,name,hostname,payload) VALUES($1,$2,$3,$4,$5,$6)", v, v.ID, v.WorkspaceID, v.AgentID, v.Name, v.Hostname); err != nil {
			return err
		}
	}
	for _, v := range snap.EgressRoutes {
		if err = insert("INSERT INTO egress_routes(id,workspace_id,agent_id,name,payload) VALUES($1,$2,$3,$4,$5)", v, v.ID, v.WorkspaceID, v.AgentID, v.Name); err != nil {
			return err
		}
	}
	for _, v := range snap.Grants {
		var service, route, user, workspace any
		if v.ResourceType == "service" {
			service = v.ResourceID
		} else {
			route = v.ResourceID
		}
		if v.SubjectType == "user" {
			user = v.SubjectID
		} else if v.SubjectType == "workspace" {
			workspace = v.SubjectID
		}
		if err = insert("INSERT INTO grants(id,workspace_id,resource_type,service_id,route_id,subject_type,subject_user_id,subject_workspace_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", v, v.ID, v.WorkspaceID, v.ResourceType, service, route, v.SubjectType, user, workspace); err != nil {
			return err
		}
	}
	for _, v := range snap.Agents {
		if _, err = tx.ExecContext(ctx, "INSERT INTO names(workspace_id,label,agent_id) VALUES($1,$2,$3)", v.WorkspaceID, v.Name, v.ID); err != nil {
			return err
		}
	}
	for _, v := range snap.Services {
		if _, err = tx.ExecContext(ctx, "INSERT INTO names(workspace_id,label,service_id) VALUES($1,$2,$3)", v.WorkspaceID, v.Name, v.ID); err != nil {
			return err
		}
	}
	for _, v := range snap.Tokens {
		var key any
		if v.Kind == "enrollment" {
			key = v.ID
		}
		if err = insert("INSERT INTO tokens(id,hash,kind,user_id,workspace_id,agent_id,enrollment_key_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", v, v.ID, v.Hash, v.Kind, nullable(v.UserID), nullable(v.WorkspaceID), nullable(v.AgentID), key); err != nil {
			return err
		}
	}
	for _, v := range snap.Audit {
		if err = insert("INSERT INTO audit(id,payload) VALUES($1,$2)", v, v.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
