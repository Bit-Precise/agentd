package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"agentd/internal/identity"
	"agentd/internal/routes"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// ReservedNames cannot be used for nodes or services (protocol 8.4).
var ReservedNames = map[string]bool{"www": true, "agentserver": true, "group": true}

// ---------------------------------------------------------------- relays

// Relay is a registered relay.
type Relay struct {
	Name       string
	PublicKey  []byte
	URL        string
	Transports map[string]string
	STUN       string
	CreatedAt  time.Time
	LastSeen   *time.Time
}

const relayCols = `name, public_key, url, transports, stun, created_at, last_seen`

func scanRelay(row pgx.Row) (Relay, error) {
	var r Relay
	var tr []byte
	err := row.Scan(&r.Name, &r.PublicKey, &r.URL, &tr, &r.STUN, &r.CreatedAt, &r.LastSeen)
	if err != nil {
		return r, notFound(err)
	}
	_ = json.Unmarshal(tr, &r.Transports)
	return r, nil
}

// CreateRelay registers a relay.
func (s *Store) CreateRelay(ctx context.Context, r Relay) error {
	tr, _ := json.Marshal(r.Transports)
	if r.Transports == nil {
		tr = []byte("{}")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO relays(name, public_key, url, transports, stun) VALUES ($1,$2,$3,$4,$5)`, r.Name, r.PublicKey, r.URL, tr, r.STUN)
	if isUnique(err) {
		return fmt.Errorf("%w: relay name or key already registered", ErrConflict)
	}
	return err
}

// UpsertRelayByKey registers or updates the relay owning key (self-registration).
func (s *Store) UpsertRelayByKey(ctx context.Context, r Relay) error {
	tr, _ := json.Marshal(r.Transports)
	tag, err := s.pool.Exec(ctx, `UPDATE relays SET url=$2, transports=$3, stun=$4 WHERE public_key=$1`, r.PublicKey, r.URL, tr, r.STUN)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	return s.CreateRelay(ctx, r)
}

// GetRelay returns a relay by name.
func (s *Store) GetRelay(ctx context.Context, name string) (Relay, error) {
	return scanRelay(s.pool.QueryRow(ctx, `SELECT `+relayCols+` FROM relays WHERE name=$1`, name))
}

// GetRelayByKey returns a relay by public key.
func (s *Store) GetRelayByKey(ctx context.Context, key []byte) (Relay, error) {
	return scanRelay(s.pool.QueryRow(ctx, `SELECT `+relayCols+` FROM relays WHERE public_key=$1`, key))
}

// ListRelays lists relays by name.
func (s *Store) ListRelays(ctx context.Context) ([]Relay, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+relayCols+` FROM relays ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Relay
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRelay removes a relay that no workspace uses.
func (s *Store) DeleteRelay(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM relays WHERE name=$1`, name)
	if isFK(err) {
		return fmt.Errorf("%w: relay is assigned to a workspace", ErrConflict)
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TouchRelay records that a relay connected.
func (s *Store) TouchRelay(ctx context.Context, name string) error {
	_, err := s.pool.Exec(ctx, `UPDATE relays SET last_seen=now() WHERE name=$1`, name)
	return err
}

// RelayToken is a one-time relay registration token.
type RelayToken struct {
	ID        string
	Hash      []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// CreateRelayToken stores a token hash.
func (s *Store) CreateRelayToken(ctx context.Context, t RelayToken) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO relay_tokens(id, token_hash, expires_at) VALUES ($1,$2,$3)`, t.ID, t.Hash, t.ExpiresAt)
	return err
}

// ListRelayTokens lists unused relay tokens.
func (s *Store) ListRelayTokens(ctx context.Context) ([]RelayToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, expires_at, created_at FROM relay_tokens WHERE used_at IS NULL ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RelayToken
	for rows.Next() {
		var t RelayToken
		if err := rows.Scan(&t.ID, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteRelayToken revokes a relay token.
func (s *Store) DeleteRelayToken(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM relay_tokens WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ConsumeRelayToken marks a valid unused token as used.
func (s *Store) ConsumeRelayToken(ctx context.Context, hash []byte) error {
	tag, err := s.pool.Exec(ctx, `UPDATE relay_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now()`, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return wire.Errorf(pb.Status_TOKEN_INVALID, "relay registration token invalid, used or expired")
	}
	return nil
}

// ---------------------------------------------------------------- workspaces

// Workspace is a tenant.
type Workspace struct {
	Name             string
	BaseDomain       string
	PrivateKey       ed25519.PrivateKey
	PublicKey        []byte
	Relay            string
	PublishDNS       bool
	RoutesVersion    uint64
	RoutesDefault    string
	DirectoryVersion uint64
	CreatedAt        time.Time
}

const wsCols = `name, base_domain, private_key, public_key, relay, publish_dns, routes_version, routes_default, directory_version, created_at`

func (s *Store) scanWS(row pgx.Row) (Workspace, error) {
	var w Workspace
	var sealed []byte
	err := row.Scan(&w.Name, &w.BaseDomain, &sealed, &w.PublicKey, &w.Relay, &w.PublishDNS, &w.RoutesVersion, &w.RoutesDefault, &w.DirectoryVersion, &w.CreatedAt)
	if err != nil {
		return w, notFound(err)
	}
	w.PrivateKey, err = s.box.openKey(sealed)
	return w, err
}

// CreateWorkspace inserts a workspace. PublicKey is derived from PrivateKey.
func (s *Store) CreateWorkspace(ctx context.Context, w Workspace) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO workspaces(name, base_domain, private_key, public_key, relay, publish_dns) VALUES ($1,$2,$3,$4,$5,$6)`,
		w.Name, w.BaseDomain, s.box.sealKey(w.PrivateKey), []byte(identity.Public(w.PrivateKey)), w.Relay, w.PublishDNS)
	if isUnique(err) {
		return fmt.Errorf("%w: workspace name or base domain already used", ErrConflict)
	}
	if isFK(err) {
		return fmt.Errorf("%w: relay %q", ErrNotFound, w.Relay)
	}
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO certs(workspace) VALUES ($1) ON CONFLICT DO NOTHING`, w.Name)
	return err
}

// GetWorkspace returns a workspace by name.
func (s *Store) GetWorkspace(ctx context.Context, name string) (Workspace, error) {
	return s.scanWS(s.pool.QueryRow(ctx, `SELECT `+wsCols+` FROM workspaces WHERE name=$1`, name))
}

// GetWorkspaceByDomain returns a workspace by base domain.
func (s *Store) GetWorkspaceByDomain(ctx context.Context, domain string) (Workspace, error) {
	return s.scanWS(s.pool.QueryRow(ctx, `SELECT `+wsCols+` FROM workspaces WHERE base_domain=$1`, domain))
}

// ListWorkspaces lists workspaces by name.
func (s *Store) ListWorkspaces(ctx context.Context) ([]Workspace, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+wsCols+` FROM workspaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Workspace
	for rows.Next() {
		w, err := s.scanWS(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// WorkspacesOfRelay lists the workspaces assigned to a relay.
func (s *Store) WorkspacesOfRelay(ctx context.Context, relay string) ([]Workspace, error) {
	all, err := s.ListWorkspaces(ctx)
	if err != nil {
		return nil, err
	}
	var out []Workspace
	for _, w := range all {
		if w.Relay == relay {
			out = append(out, w)
		}
	}
	return out, nil
}

// UpdateWorkspace changes relay assignment or DNS publication.
func (s *Store) UpdateWorkspace(ctx context.Context, name string, relay *string, publish *bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE workspaces SET relay=COALESCE($2, relay), publish_dns=COALESCE($3, publish_dns), directory_version=directory_version+1 WHERE name=$1`, name, relay, publish)
	if isFK(err) {
		return fmt.Errorf("%w: relay %q", ErrNotFound, *relay)
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteWorkspace removes a workspace and everything in it.
func (s *Store) DeleteWorkspace(ctx context.Context, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM workspaces WHERE name=$1`, name)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// BumpDirectory increments the directory version and returns it.
func (s *Store) BumpDirectory(ctx context.Context, ws string) (uint64, error) {
	var v uint64
	err := s.pool.QueryRow(ctx, `UPDATE workspaces SET directory_version=directory_version+1 WHERE name=$1 RETURNING directory_version`, ws).Scan(&v)
	return v, notFound(err)
}

// ---------------------------------------------------------------- join tokens

// JoinToken is a one-time node join token.
type JoinToken struct {
	ID        string
	Workspace string
	Hash      []byte
	Name      string
	Roles     []string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// CreateJoinToken stores a token; the name, if any, must be free.
func (s *Store) CreateJoinToken(ctx context.Context, t JoinToken) error {
	if t.Roles == nil {
		t.Roles = []string{}
	}
	if t.Name != "" {
		if taken, err := s.nameTaken(ctx, s.pool, t.Workspace, t.Name); err != nil {
			return err
		} else if taken {
			return wire.Errorf(pb.Status_NAME_TAKEN, "name %q is used by a node or service", t.Name)
		}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO join_tokens(id, workspace, token_hash, name, roles, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`, t.ID, t.Workspace, t.Hash, t.Name, t.Roles, t.ExpiresAt)
	if isFK(err) {
		return ErrNotFound
	}
	return err
}

// ListJoinTokens lists unused tokens of a workspace.
func (s *Store) ListJoinTokens(ctx context.Context, ws string) ([]JoinToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, workspace, name, roles, expires_at, created_at FROM join_tokens WHERE workspace=$1 AND used_at IS NULL ORDER BY created_at`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JoinToken
	for rows.Next() {
		var t JoinToken
		if err := rows.Scan(&t.ID, &t.Workspace, &t.Name, &t.Roles, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteJoinToken revokes a token.
func (s *Store) DeleteJoinToken(ctx context.Context, ws, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM join_tokens WHERE workspace=$1 AND id=$2`, ws, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *Store) nameTaken(ctx context.Context, q querier, ws, name string) (bool, error) {
	var taken bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE workspace=$1 AND name=$2) OR EXISTS(SELECT 1 FROM services WHERE workspace=$1 AND name=$2)`, ws, name).Scan(&taken)
	return taken, err
}

// JoinRequest is a join attempt relayed from a handshake.
type JoinRequest struct {
	TokenHash       []byte
	WorkspaceDomain string
	Identity        []byte
	ProposedName    string
	Timestamp       []byte
}

// Join registers a new node with a one-time token, in the order of protocol 8.3.
func (s *Store) Join(ctx context.Context, r JoinRequest) (Node, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Node{}, err
	}
	defer tx.Rollback(ctx)
	var t JoinToken
	var used *time.Time
	err = tx.QueryRow(ctx, `SELECT id, workspace, name, roles, expires_at, used_at FROM join_tokens WHERE token_hash=$1 FOR UPDATE`, r.TokenHash).Scan(&t.ID, &t.Workspace, &t.Name, &t.Roles, &t.ExpiresAt, &used)
	if errors.Is(err, pgx.ErrNoRows) {
		return Node{}, wire.Errorf(pb.Status_TOKEN_INVALID, "unknown join token")
	}
	if err != nil {
		return Node{}, err
	}
	var domain string
	if err := tx.QueryRow(ctx, `SELECT base_domain FROM workspaces WHERE name=$1`, t.Workspace).Scan(&domain); err != nil {
		return Node{}, err
	}
	if domain != r.WorkspaceDomain {
		return Node{}, wire.Errorf(pb.Status_WORKSPACE_MISMATCH, "token belongs to another workspace")
	}
	if used != nil {
		return Node{}, wire.Errorf(pb.Status_TOKEN_USED, "join token already used")
	}
	if time.Now().After(t.ExpiresAt) {
		return Node{}, wire.Errorf(pb.Status_TOKEN_EXPIRED, "join token expired")
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE public_key=$1)`, r.Identity).Scan(&exists); err != nil {
		return Node{}, err
	}
	if exists {
		return Node{}, wire.Errorf(pb.Status_IDENTITY_IN_USE, "this key already belongs to an instance")
	}
	name := t.Name
	if name == "" {
		name = r.ProposedName
	}
	if !identity.ValidLabel(name) || ReservedNames[name] {
		return Node{}, wire.Errorf(pb.Status_BAD_NAME, "invalid instance name %q", name)
	}
	if taken, err := s.nameTaken(ctx, tx, t.Workspace, name); err != nil {
		return Node{}, err
	} else if taken {
		return Node{}, wire.Errorf(pb.Status_NAME_TAKEN, "name %q is already used", name)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO nodes(workspace, name, public_key, role_caps, handshake_ts) VALUES ($1,$2,$3,$4,$5)`, t.Workspace, name, r.Identity, t.Roles, r.Timestamp); err != nil {
		if isUnique(err) {
			return Node{}, wire.Errorf(pb.Status_NAME_TAKEN, "name or key already used")
		}
		return Node{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE join_tokens SET used_at=now() WHERE id=$1`, t.ID); err != nil {
		return Node{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE workspaces SET directory_version=directory_version+1 WHERE name=$1`, t.Workspace); err != nil {
		return Node{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Node{}, err
	}
	n, _, err := s.GetNodeByKey(ctx, r.Identity)
	return n, err
}

// ---------------------------------------------------------------- nodes

// Node is a workspace member.
type Node struct {
	Workspace        string
	Name             string
	PublicKey        []byte
	RoleCaps         []string
	JoinedAt         time.Time
	LastSeen         *time.Time
	PolicySources    map[string]string // role -> "local" | "server"
	AdvertisedPolicy *pb.Policy
	Executor         *pb.ExecutorDecl
	P2P              bool
	PolicyVersion    uint64
	PolicyHash       []byte
	PolicyApplied    uint64
}

// HasRole reports whether role is within the node's role caps (empty caps allow all).
func (n Node) HasRole(role string) bool {
	if len(n.RoleCaps) == 0 {
		return true
	}
	for _, r := range n.RoleCaps {
		if r == role {
			return true
		}
	}
	return false
}

const nodeCols = `workspace, name, public_key, role_caps, joined_at, last_seen, policy_sources, advertised_policy, executor, p2p_enabled, policy_version, policy_hash, policy_applied`

func scanNode(row pgx.Row) (Node, error) {
	var n Node
	var ps, pol, ex []byte
	err := row.Scan(&n.Workspace, &n.Name, &n.PublicKey, &n.RoleCaps, &n.JoinedAt, &n.LastSeen, &ps, &pol, &ex, &n.P2P, &n.PolicyVersion, &n.PolicyHash, &n.PolicyApplied)
	if err != nil {
		return n, notFound(err)
	}
	_ = json.Unmarshal(ps, &n.PolicySources)
	if len(pol) > 0 {
		n.AdvertisedPolicy = &pb.Policy{}
		_ = proto.Unmarshal(pol, n.AdvertisedPolicy)
	}
	if len(ex) > 0 {
		n.Executor = &pb.ExecutorDecl{}
		_ = proto.Unmarshal(ex, n.Executor)
	}
	return n, nil
}

// GetNodeByKey returns the node owning key and its workspace.
func (s *Store) GetNodeByKey(ctx context.Context, key []byte) (Node, Workspace, error) {
	n, err := scanNode(s.pool.QueryRow(ctx, `SELECT `+nodeCols+` FROM nodes WHERE public_key=$1`, key))
	if err != nil {
		return n, Workspace{}, err
	}
	w, err := s.GetWorkspace(ctx, n.Workspace)
	return n, w, err
}

// GetNode returns a node by name.
func (s *Store) GetNode(ctx context.Context, ws, name string) (Node, error) {
	return scanNode(s.pool.QueryRow(ctx, `SELECT `+nodeCols+` FROM nodes WHERE workspace=$1 AND name=$2`, ws, name))
}

// ListNodes lists a workspace's nodes by name.
func (s *Store) ListNodes(ctx context.Context, ws string) ([]Node, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+nodeCols+` FROM nodes WHERE workspace=$1 ORDER BY name`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// RenameNode renames a node; group memberships and services follow.
func (s *Store) RenameNode(ctx context.Context, ws, from, to string) error {
	if !identity.ValidLabel(to) || ReservedNames[to] {
		return wire.Errorf(pb.Status_BAD_NAME, "invalid name %q", to)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if taken, err := s.nameTaken(ctx, tx, ws, to); err != nil {
		return err
	} else if taken {
		return wire.Errorf(pb.Status_NAME_TAKEN, "name %q is already used", to)
	}
	tag, err := tx.Exec(ctx, `UPDATE nodes SET name=$3 WHERE workspace=$1 AND name=$2`, ws, from, to)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE workspaces SET directory_version=directory_version+1 WHERE name=$1`, ws); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetRoleCaps replaces a node's role caps.
func (s *Store) SetRoleCaps(ctx context.Context, ws, name string, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	tag, err := s.pool.Exec(ctx, `UPDATE nodes SET role_caps=$3 WHERE workspace=$1 AND name=$2`, ws, name, roles)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.BumpDirectory(ctx, ws)
	}
	return err
}

// DeleteNode removes a node (its services and memberships go with it).
func (s *Store) DeleteNode(ctx context.Context, ws, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM nodes WHERE workspace=$1 AND name=$2`, ws, name)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.BumpDirectory(ctx, ws)
	}
	return err
}

// SaveAdvert records a node's Advertise (policy sources, local policy, executor).
func (s *Store) SaveAdvert(ctx context.Context, ws, name string, sources map[string]string, pol *pb.Policy, ex *pb.ExecutorDecl, p2p bool) error {
	ps, _ := json.Marshal(sources)
	var polB, exB []byte
	if pol != nil {
		polB, _ = proto.Marshal(pol)
	}
	if ex != nil {
		exB, _ = proto.Marshal(ex)
	}
	_, err := s.pool.Exec(ctx, `UPDATE nodes SET policy_sources=$3, advertised_policy=$4, executor=$5, p2p_enabled=$6 WHERE workspace=$1 AND name=$2`, ws, name, ps, polB, exB, p2p)
	return err
}

// TouchNode records the last time a node was seen.
func (s *Store) TouchNode(ctx context.Context, key []byte) error {
	_, err := s.pool.Exec(ctx, `UPDATE nodes SET last_seen=now() WHERE public_key=$1`, key)
	return err
}

// SetPolicyVersion stores the rendered policy hash and version sent to a node.
func (s *Store) SetPolicyVersion(ctx context.Context, ws, name string, version uint64, hash []byte) error {
	_, err := s.pool.Exec(ctx, `UPDATE nodes SET policy_version=$3, policy_hash=$4 WHERE workspace=$1 AND name=$2`, ws, name, version, hash)
	return err
}

// SetPolicyApplied records the version a node confirmed.
func (s *Store) SetPolicyApplied(ctx context.Context, key []byte, version uint64) error {
	_, err := s.pool.Exec(ctx, `UPDATE nodes SET policy_applied=$2 WHERE public_key=$1`, key, version)
	return err
}

// ---------------------------------------------------------------- groups

// Group is a named set of nodes with its own key.
type Group struct {
	Workspace  string
	Name       string
	PrivateKey ed25519.PrivateKey
	PublicKey  []byte
	Members    []string
}

// CreateGroup creates a group.
func (s *Store) CreateGroup(ctx context.Context, g Group) error {
	if !identity.ValidLabel(g.Name) {
		return wire.Errorf(pb.Status_BAD_NAME, "invalid group name %q", g.Name)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO groups(workspace, name, private_key, public_key) VALUES ($1,$2,$3,$4)`, g.Workspace, g.Name, s.box.sealKey(g.PrivateKey), []byte(identity.Public(g.PrivateKey)))
	if isUnique(err) {
		return fmt.Errorf("%w: group %q", ErrConflict, g.Name)
	}
	if isFK(err) {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.BumpDirectory(ctx, g.Workspace)
	}
	return err
}

// ListGroups lists groups with members.
func (s *Store) ListGroups(ctx context.Context, ws string) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `SELECT g.name, g.private_key, g.public_key, COALESCE(array_agg(m.node_name ORDER BY m.node_name) FILTER (WHERE m.node_name IS NOT NULL), '{}')
		FROM groups g LEFT JOIN group_members m ON m.workspace=g.workspace AND m.group_name=g.name WHERE g.workspace=$1 GROUP BY g.name, g.private_key, g.public_key ORDER BY g.name`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		g := Group{Workspace: ws}
		var sealed []byte
		if err := rows.Scan(&g.Name, &sealed, &g.PublicKey, &g.Members); err != nil {
			return nil, err
		}
		if g.PrivateKey, err = s.box.openKey(sealed); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetGroup returns one group.
func (s *Store) GetGroup(ctx context.Context, ws, name string) (Group, error) {
	gs, err := s.ListGroups(ctx, ws)
	if err != nil {
		return Group{}, err
	}
	for _, g := range gs {
		if g.Name == name {
			return g, nil
		}
	}
	return Group{}, ErrNotFound
}

// DeleteGroup removes a group.
func (s *Store) DeleteGroup(ctx context.Context, ws, name string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM groups WHERE workspace=$1 AND name=$2`, ws, name)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.BumpDirectory(ctx, ws)
	}
	return err
}

// AddGroupMember adds a node to a group (idempotent).
func (s *Store) AddGroupMember(ctx context.Context, ws, group, node string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO group_members(workspace, group_name, node_name) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, ws, group, node)
	if isFK(err) {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.BumpDirectory(ctx, ws)
	}
	return err
}

// RemoveGroupMember removes a node from a group.
func (s *Store) RemoveGroupMember(ctx context.Context, ws, group, node string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM group_members WHERE workspace=$1 AND group_name=$2 AND node_name=$3`, ws, group, node)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err == nil {
		_, err = s.BumpDirectory(ctx, ws)
	}
	return err
}

// GroupsOfNode lists the groups a node belongs to.
func (s *Store) GroupsOfNode(ctx context.Context, ws, node string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT group_name FROM group_members WHERE workspace=$1 AND node_name=$2 ORDER BY group_name`, ws, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- routes

type matchJSON struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func encodeMatches(ms []*pb.Match) []byte {
	out := make([]matchJSON, 0, len(ms))
	for _, m := range ms {
		k := "suffix"
		if m.Kind == pb.Match_DOMAIN {
			k = "domain"
		}
		out = append(out, matchJSON{k, m.Value})
	}
	b, _ := json.Marshal(out)
	return b
}

func decodeMatches(b []byte) []*pb.Match {
	var in []matchJSON
	_ = json.Unmarshal(b, &in)
	out := make([]*pb.Match, 0, len(in))
	for _, m := range in {
		k := pb.Match_SUFFIX
		if m.Kind == "domain" {
			k = pb.Match_DOMAIN
		}
		out = append(out, &pb.Match{Kind: k, Value: m.Value})
	}
	return out
}

func protoNames(ps []pb.Proto) []string {
	out := []string{}
	for _, p := range ps {
		if p == pb.Proto_PROTO_SSH {
			out = append(out, "ssh")
		} else {
			out = append(out, "tls")
		}
	}
	return out
}

func protosFrom(names []string) []pb.Proto {
	var out []pb.Proto
	for _, n := range names {
		if n == "ssh" {
			out = append(out, pb.Proto_PROTO_SSH)
		} else {
			out = append(out, pb.Proto_PROTO_TLS)
		}
	}
	return out
}

// GetRouteTable returns a workspace's route table.
func (s *Store) GetRouteTable(ctx context.Context, ws string) (routes.Table, error) {
	var t routes.Table
	if err := s.pool.QueryRow(ctx, `SELECT routes_version, routes_default FROM workspaces WHERE name=$1`, ws).Scan(&t.Version, &t.Default); err != nil {
		return t, notFound(err)
	}
	rows, err := s.pool.Query(ctx, `SELECT id, from_subject, protos, domains, to_target FROM routes WHERE workspace=$1 ORDER BY position`, ws)
	if err != nil {
		return t, err
	}
	defer rows.Close()
	for rows.Next() {
		var r routes.Route
		var protos []string
		var doms []byte
		if err := rows.Scan(&r.ID, &r.From, &protos, &doms, &r.To); err != nil {
			return t, err
		}
		r.Protos = protosFrom(protos)
		r.Domains = decodeMatches(doms)
		t.Routes = append(t.Routes, r)
	}
	return t, rows.Err()
}

func newID() string { return wire.RandomID() }

// AddRoute appends a route and bumps the version.
func (s *Store) AddRoute(ctx context.Context, ws string, r routes.Route) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	id := newID()
	if _, err := tx.Exec(ctx, `INSERT INTO routes(workspace, id, position, from_subject, protos, domains, to_target) VALUES ($1,$2,(SELECT COALESCE(MAX(position),0)+1 FROM routes WHERE workspace=$1),$3,$4,$5,$6)`,
		ws, id, r.From, protoNames(r.Protos), encodeMatches(r.Domains), r.To); err != nil {
		if isFK(err) {
			return "", ErrNotFound
		}
		return "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE workspaces SET routes_version=routes_version+1 WHERE name=$1`, ws); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

// ReplaceRoutes replaces the whole table and bumps the version.
func (s *Store) ReplaceRoutes(ctx context.Context, ws string, rs []routes.Route, def string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM routes WHERE workspace=$1`, ws); err != nil {
		return err
	}
	for i, r := range rs {
		if _, err := tx.Exec(ctx, `INSERT INTO routes(workspace, id, position, from_subject, protos, domains, to_target) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			ws, newID(), i+1, r.From, protoNames(r.Protos), encodeMatches(r.Domains), r.To); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE workspaces SET routes_version=routes_version+1, routes_default=$2 WHERE name=$1`, ws, def)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return tx.Commit(ctx)
}

// DeleteRoute removes one route and bumps the version.
func (s *Store) DeleteRoute(ctx context.Context, ws, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM routes WHERE workspace=$1 AND id=$2`, ws, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE workspaces SET routes_version=routes_version+1 WHERE name=$1`, ws); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------- policies

// PolicyRecord is a stored central policy statement (JSON as written by the admin API).
type PolicyRecord struct {
	ID        string
	Statement json.RawMessage
}

// ListPolicies lists statements in order.
func (s *Store) ListPolicies(ctx context.Context, ws string) ([]PolicyRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, statement FROM policies WHERE workspace=$1 ORDER BY position`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicyRecord
	for rows.Next() {
		var p PolicyRecord
		if err := rows.Scan(&p.ID, &p.Statement); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// AddPolicy appends a statement and returns its id.
func (s *Store) AddPolicy(ctx context.Context, ws string, stmt json.RawMessage) (string, error) {
	id := newID()
	_, err := s.pool.Exec(ctx, `INSERT INTO policies(workspace, id, position, statement) VALUES ($1,$2,(SELECT COALESCE(MAX(position),0)+1 FROM policies WHERE workspace=$1),$3)`, ws, id, stmt)
	if isFK(err) {
		return "", ErrNotFound
	}
	return id, err
}

// ReplacePolicies replaces all statements.
func (s *Store) ReplacePolicies(ctx context.Context, ws string, stmts []json.RawMessage) ([]string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM policies WHERE workspace=$1`, ws); err != nil {
		return nil, err
	}
	ids := make([]string, len(stmts))
	for i, st := range stmts {
		ids[i] = newID()
		if _, err := tx.Exec(ctx, `INSERT INTO policies(workspace, id, position, statement) VALUES ($1,$2,$3,$4)`, ws, ids[i], i+1, st); err != nil {
			if isFK(err) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	}
	return ids, tx.Commit(ctx)
}

// DeletePolicy removes a statement.
func (s *Store) DeletePolicy(ctx context.Context, ws, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM policies WHERE workspace=$1 AND id=$2`, ws, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---------------------------------------------------------------- services

// Service is a registered service.
type Service struct {
	Workspace string
	Name      string
	Node      string
	Proto     string // "http" | "ssh"
}

// ReplaceNodeServices replaces a node's services. Names used by other nodes
// or services are rejected; the rest are registered.
func (s *Store) ReplaceNodeServices(ctx context.Context, ws, node string, svcs []Service) (accepted []Service, rejected []string, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM services WHERE workspace=$1 AND node_name=$2`, ws, node); err != nil {
		return nil, nil, err
	}
	for _, sv := range svcs {
		if !identity.ValidLabel(sv.Name) || ReservedNames[sv.Name] {
			rejected = append(rejected, sv.Name)
			continue
		}
		var conflict bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE workspace=$1 AND name=$2 AND name<>$3) OR EXISTS(SELECT 1 FROM services WHERE workspace=$1 AND name=$2)`, ws, sv.Name, node).Scan(&conflict); err != nil {
			return nil, nil, err
		}
		if conflict {
			rejected = append(rejected, sv.Name)
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO services(workspace, name, node_name, proto) VALUES ($1,$2,$3,$4)`, ws, sv.Name, node, sv.Proto); err != nil {
			return nil, nil, err
		}
		sv.Workspace, sv.Node = ws, node
		accepted = append(accepted, sv)
	}
	return accepted, rejected, tx.Commit(ctx)
}

// ListServices lists a workspace's services.
func (s *Store) ListServices(ctx context.Context, ws string) ([]Service, error) {
	rows, err := s.pool.Query(ctx, `SELECT workspace, name, node_name, proto FROM services WHERE workspace=$1 ORDER BY name`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var sv Service
		if err := rows.Scan(&sv.Workspace, &sv.Name, &sv.Node, &sv.Proto); err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- certs

// Cert is a workspace wildcard certificate record.
type Cert struct {
	Workspace string
	State     string // pending | ready | renewing | failed
	ChainPEM  []byte
	KeyPEM    []byte
	NotBefore *time.Time
	NotAfter  *time.Time
	Issuer    string
	LastError string
}

// GetCert returns a workspace's certificate record.
func (s *Store) GetCert(ctx context.Context, ws string) (Cert, error) {
	var c Cert
	var sealed []byte
	err := s.pool.QueryRow(ctx, `SELECT workspace, state, cert_chain_pem, key_pem, not_before, not_after, issuer, last_error FROM certs WHERE workspace=$1`, ws).
		Scan(&c.Workspace, &c.State, &c.ChainPEM, &sealed, &c.NotBefore, &c.NotAfter, &c.Issuer, &c.LastError)
	if err != nil {
		return c, notFound(err)
	}
	if len(sealed) > 0 {
		c.KeyPEM, err = s.box.open(sealed)
	}
	return c, err
}

// PutCert stores a certificate record.
func (s *Store) PutCert(ctx context.Context, c Cert) error {
	var sealed []byte
	if len(c.KeyPEM) > 0 {
		sealed = s.box.seal(c.KeyPEM)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO certs(workspace, state, cert_chain_pem, key_pem, not_before, not_after, issuer, last_error, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
		ON CONFLICT (workspace) DO UPDATE SET state=EXCLUDED.state, cert_chain_pem=COALESCE(EXCLUDED.cert_chain_pem, certs.cert_chain_pem), key_pem=COALESCE(EXCLUDED.key_pem, certs.key_pem),
		not_before=COALESCE(EXCLUDED.not_before, certs.not_before), not_after=COALESCE(EXCLUDED.not_after, certs.not_after), issuer=EXCLUDED.issuer, last_error=EXCLUDED.last_error, updated_at=now()`,
		c.Workspace, c.State, c.ChainPEM, sealed, c.NotBefore, c.NotAfter, c.Issuer, c.LastError)
	return err
}

// ---------------------------------------------------------------- revocations

// AddRevocation records that (member, issuer) certificates are revoked until t.
func (s *Store) AddRevocation(ctx context.Context, ws string, member, issuer []byte, until time.Time) error {
	if member == nil {
		member = []byte{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO revocations(workspace, member, issuer, until_at) VALUES ($1,$2,$3,$4) ON CONFLICT (workspace, member, issuer) DO UPDATE SET until_at=EXCLUDED.until_at`, ws, member, issuer, until)
	return err
}

// Revocations lists unexpired revocations of a workspace.
func (s *Store) Revocations(ctx context.Context, ws string) ([]*pb.MembershipRevocation, error) {
	rows, err := s.pool.Query(ctx, `SELECT member, issuer, until_at FROM revocations WHERE workspace=$1 AND until_at > now()`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*pb.MembershipRevocation
	for rows.Next() {
		var m, i []byte
		var u time.Time
		if err := rows.Scan(&m, &i, &u); err != nil {
			return nil, err
		}
		out = append(out, &pb.MembershipRevocation{Member: m, Issuer: i, Until: uint64(u.Unix())})
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- acme

// ACMEAccountKey returns the stored PEM key of an ACME account.
func (s *Store) ACMEAccountKey(ctx context.Context, id string) ([]byte, error) {
	var sealed []byte
	if err := s.pool.QueryRow(ctx, `SELECT key_pem FROM acme_accounts WHERE id=$1`, id).Scan(&sealed); err != nil {
		return nil, notFound(err)
	}
	return s.box.open(sealed)
}

// AddACMEAccountKey stores keyPEM as ACME account key id unless a key is
// stored under id already, and returns the stored key: an account key is
// never replaced, since its account may hold a spent single-use EAB key.
func (s *Store) AddACMEAccountKey(ctx context.Context, id string, keyPEM []byte) ([]byte, error) {
	if _, err := s.pool.Exec(ctx, `INSERT INTO acme_accounts(id, key_pem) VALUES ($1,$2) ON CONFLICT (id) DO NOTHING`, id, s.box.seal(keyPEM)); err != nil {
		return nil, err
	}
	return s.ACMEAccountKey(ctx, id)
}

// CacheGet reads an autocert cache entry (ErrNotFound when absent).
func (s *Store) CacheGet(ctx context.Context, key string) ([]byte, error) {
	var sealed []byte
	if err := s.pool.QueryRow(ctx, `SELECT data FROM autocert_cache WHERE key=$1`, key).Scan(&sealed); err != nil {
		return nil, notFound(err)
	}
	return s.box.open(sealed)
}

// CachePut writes an autocert cache entry.
func (s *Store) CachePut(ctx context.Context, key string, data []byte) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO autocert_cache(key, data) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET data=EXCLUDED.data, updated_at=now()`, key, s.box.seal(data))
	return err
}

// CacheDelete removes an autocert cache entry.
func (s *Store) CacheDelete(ctx context.Context, key string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM autocert_cache WHERE key=$1`, key)
	return err
}
