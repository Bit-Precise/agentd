// Package state coordinates policy, authorization and durable control mutations.
// A committed SQL transaction precedes publication of each immutable snapshot.
package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/control/db"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/credentials"
	"github.com/bit-precise/agentd/policy"
	"gopkg.in/yaml.v3"
)

const ApprovalTTL = 24 * time.Hour
const TokenTTL = 30 * 24 * time.Hour
const TokenRenewBefore = 7 * 24 * time.Hour
const DefaultGrantTTL = 24 * time.Hour

type State struct {
	mu          sync.RWMutex
	store       *db.Store
	snapshot    types.Snapshot
	baseDomain  string
	subscribers map[chan struct{}]struct{}
	closed      bool
}

func Open(ctx context.Context, options db.Options, baseDomain string) (*State, error) {
	store, err := db.Open(ctx, options)
	if err != nil {
		return nil, err
	}
	s, err := New(ctx, store, baseDomain)
	if err != nil {
		_ = store.Close()
	}
	return s, err
}
func New(ctx context.Context, store *db.Store, baseDomain string) (*State, error) {
	domain, err := policy.CanonicalDomain(baseDomain)
	if err != nil {
		return nil, err
	}
	snap, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	return &State{store: store, snapshot: snap, baseDomain: domain, subscribers: make(map[chan struct{}]struct{})}, nil
}
func (s *State) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = nil
	return s.store.Close()
}
func (s *State) Subscribe() (<-chan struct{}, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan struct{}, 1)
	if s.closed {
		close(ch)
	} else {
		s.subscribers[ch] = struct{}{}
	}
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if _, ok := s.subscribers[ch]; ok {
				delete(s.subscribers, ch)
				close(ch)
			}
		})
	}
}

func problem(kind types.ErrorKind, message string) error {
	return &types.Error{Kind: kind, Message: message}
}
func clone(snap types.Snapshot) (types.Snapshot, error) {
	data, err := json.Marshal(snap)
	if err != nil {
		return types.Snapshot{}, err
	}
	var out types.Snapshot
	if err = json.Unmarshal(data, &out); err != nil {
		return out, err
	}
	out.Tokens = append([]types.Token(nil), snap.Tokens...)
	return out, nil
}
func (s *State) mutate(fn func(*types.Snapshot) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return problem(types.KindUnavailable, "control state is closed")
	}
	next, err := clone(s.snapshot)
	if err != nil {
		return err
	}
	if err = fn(&next); err != nil {
		return err
	}
	if reflect.DeepEqual(next, s.snapshot) {
		return nil
	}
	next.Revision = s.snapshot.Revision + 1
	// Mutation arguments and return values can contain caller-owned slices.
	// Publish a second detached copy so callers cannot mutate committed policy.
	next, err = clone(next)
	if err != nil {
		return err
	}
	commitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = s.store.Save(commitCtx, next, s.snapshot.Revision); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return problem(types.KindUnavailable, "control database commit timed out")
		}
		return err
	}
	s.snapshot = next
	for ch := range s.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return nil
}
func randomID() string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data[:])
}
func randomToken() string {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data[:])
}
func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func label(name string) (string, error) {
	name = strings.ToLower(name)
	canonical, err := policy.CanonicalDomain(name + ".name.invalid")
	if err != nil {
		return "", problem(types.KindInvalid, "invalid DNS label")
	}
	canonical = strings.TrimSuffix(canonical, ".name.invalid")
	if strings.Contains(canonical, ".") || canonical == "" {
		return "", problem(types.KindInvalid, "name must be one DNS label")
	}
	return canonical, nil
}
func user(snap *types.Snapshot, id string) *types.User {
	for i := range snap.Users {
		if snap.Users[i].ID == id {
			return &snap.Users[i]
		}
	}
	return nil
}
func workspace(snap *types.Snapshot, id string) *types.Workspace {
	for i := range snap.Workspaces {
		if snap.Workspaces[i].ID == id || snap.Workspaces[i].Name == id {
			return &snap.Workspaces[i]
		}
	}
	return nil
}
func agent(snap *types.Snapshot, id string) *types.Agent {
	for i := range snap.Agents {
		if snap.Agents[i].ID == id {
			return &snap.Agents[i]
		}
	}
	return nil
}
func member(snap *types.Snapshot, workspaceID, userID string) *types.Membership {
	for i := range snap.Memberships {
		v := &snap.Memberships[i]
		if v.WorkspaceID == workspaceID && v.UserID == userID {
			return v
		}
	}
	return nil
}
func requireUser(snap *types.Snapshot, id string) (*types.User, error) {
	u := user(snap, id)
	if u == nil || u.Disabled {
		return nil, problem(types.KindUnauthorized, "user is missing or disabled")
	}
	return u, nil
}
func requireAdmin(snap *types.Snapshot, id string) error {
	u, err := requireUser(snap, id)
	if err != nil {
		return err
	}
	if !u.Admin {
		return problem(types.KindForbidden, "instance administrator required")
	}
	return nil
}
func requireManager(snap *types.Snapshot, actorID, workspaceID string) error {
	u, err := requireUser(snap, actorID)
	if err != nil {
		return err
	}
	if u.Admin {
		return nil
	}
	m := member(snap, workspaceID, actorID)
	if m == nil || (m.Role != "owner" && m.Role != "maintainer") {
		return problem(types.KindForbidden, "workspace manager required")
	}
	return nil
}
func agentAllowed(snap *types.Snapshot, a *types.Agent) bool {
	u := user(snap, a.UserID)
	return a.Status != "revoked" && u != nil && !u.Disabled && member(snap, a.WorkspaceID, a.UserID) != nil
}
func audit(snap *types.Snapshot, actor, action, resourceID string) {
	snap.Audit = append(snap.Audit, types.Audit{ID: randomID(), At: time.Now().UTC(), ActorID: actor, Action: action, ResourceID: resourceID})
}
func tokenRecord(kind, plain, userID, workspaceID, agentID string, expires time.Time) types.Token {
	return types.Token{ID: randomID(), Hash: hash(plain), Kind: kind, UserID: userID, WorkspaceID: workspaceID, AgentID: agentID, ExpiresAt: expires}
}
func tokenIn(snap *types.Snapshot, plain string) (*types.Token, error) {
	if plain == "" {
		return nil, problem(types.KindUnauthorized, "token required")
	}
	hashed := hash(plain)
	for i := range snap.Tokens {
		t := &snap.Tokens[i]
		if t.Hash == hashed {
			if t.Revoked {
				return nil, problem(types.KindUnauthorized, "token revoked")
			}
			if !t.ExpiresAt.IsZero() && !t.ExpiresAt.After(time.Now()) {
				return nil, problem(types.KindExpired, "token expired")
			}
			return t, nil
		}
	}
	return nil, problem(types.KindUnauthorized, "invalid token")
}
func identity(snap *types.Snapshot, plain string) (types.Identity, error) {
	t, err := tokenIn(snap, plain)
	if err != nil {
		return types.Identity{}, err
	}
	if t.Kind == "enrollment" {
		return types.Identity{}, problem(types.KindUnauthorized, "enrollment keys cannot authenticate ordinary API sessions")
	}
	if _, err = requireUser(snap, t.UserID); err != nil {
		return types.Identity{}, err
	}
	if t.AgentID != "" {
		a := agent(snap, t.AgentID)
		if a == nil || !agentAllowed(snap, a) {
			return types.Identity{}, problem(types.KindUnauthorized, "agent is inactive")
		}
		if t.Kind == "provider" && (a.Status != "active" || member(snap, a.WorkspaceID, a.UserID).Role == "guest" || (!a.Desired.Serve.Enabled && !a.Desired.Egress.Enabled)) {
			return types.Identity{}, problem(types.KindForbidden, "provider awaits approval")
		}
		if t.Kind == "access" && (!slices.Contains(a.Roles, "ingress") || !a.Desired.Ingress.Enabled) {
			return types.Identity{}, problem(types.KindForbidden, "access role is not enabled")
		}
	}
	id := types.Identity{TokenID: t.ID, Kind: t.Kind, UserID: t.UserID, AgentID: t.AgentID, WorkspaceID: t.WorkspaceID, ExpiresAt: t.ExpiresAt}
	if w := workspace(snap, t.WorkspaceID); w != nil {
		id.Workspace = w.Name
	}
	return id, nil
}
func (s *State) Identity(token string) (types.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return identity(&s.snapshot, token)
}

// KnownToken recognizes platform credentials even after revocation/expiry. It is
// used only at the trusted gateway to avoid forwarding secrets to tenant apps.
func (s *State) KnownToken(plain string) bool {
	if plain == "" {
		return false
	}
	digest := hash(plain)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, token := range s.snapshot.Tokens {
		if token.Hash == digest {
			return true
		}
	}
	return false
}
func (s *State) CheckUser(id string) (types.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, err := requireUser(&s.snapshot, id)
	if err != nil {
		return types.User{}, err
	}
	return *u, nil
}
func (s *State) User(id string) (types.User, error) { return s.CheckUser(id) }

func (s *State) BootstrapAdmin(plain string) (types.User, error) {
	var out types.User
	if plain == "" {
		return out, problem(types.KindInvalid, "bootstrap token is required")
	}
	err := s.mutate(func(snap *types.Snapshot) error {
		// The bootstrap file identifies the initialized database; after a user
		// credential rotation it must not become a mechanism to revive that key.
		for _, token := range snap.Tokens {
			if token.Hash == hash(plain) && token.Kind == "user" {
				if u := user(snap, token.UserID); u != nil && u.Admin {
					out = *u
					return nil
				}
			}
		}
		if len(snap.Users) != 0 {
			return problem(types.KindConflict, "control already bootstrapped with another administrator credential")
		}
		out = types.User{ID: randomID(), Name: "admin", Admin: true, CreatedAt: time.Now().UTC()}
		snap.Users = append(snap.Users, out)
		snap.Tokens = append(snap.Tokens, tokenRecord("user", plain, out.ID, "", "", time.Time{}))
		audit(snap, out.ID, "bootstrap", out.ID)
		return nil
	})
	return out, err
}
func (s *State) CreateUser(actorID, name string, admin bool) (types.User, string, error) {
	var out types.User
	plain := randomToken()
	err := s.mutate(func(snap *types.Snapshot) error {
		if err := requireAdmin(snap, actorID); err != nil {
			return err
		}
		if strings.TrimSpace(name) != name || name == "" || len(name) > 128 {
			return problem(types.KindInvalid, "invalid user name")
		}
		for _, u := range snap.Users {
			if u.Name == name {
				return problem(types.KindConflict, "user name already exists")
			}
		}
		out = types.User{ID: randomID(), Name: name, Admin: admin, CreatedAt: time.Now().UTC()}
		snap.Users = append(snap.Users, out)
		snap.Tokens = append(snap.Tokens, tokenRecord("user", plain, out.ID, "", "", time.Now().Add(TokenTTL)))
		audit(snap, actorID, "user.create", out.ID)
		return nil
	})
	if err != nil {
		plain = ""
	}
	return out, plain, err
}
func (s *State) CreateWorkspace(actorID, name string) (types.Workspace, error) {
	var out types.Workspace
	name, err := label(name)
	if err != nil {
		return out, err
	}
	err = s.mutate(func(snap *types.Snapshot) error {
		if err := requireAdmin(snap, actorID); err != nil {
			return err
		}
		if workspace(snap, name) != nil {
			return problem(types.KindConflict, "workspace already exists")
		}
		out = types.Workspace{ID: randomID(), Name: name, CreatedAt: time.Now().UTC()}
		snap.Workspaces = append(snap.Workspaces, out)
		snap.Memberships = append(snap.Memberships, types.Membership{WorkspaceID: out.ID, UserID: actorID, Role: "owner"})
		audit(snap, actorID, "workspace.create", out.ID)
		return nil
	})
	return out, err
}
func validRole(role string) bool {
	return slices.Contains([]string{"owner", "maintainer", "developer", "guest"}, role)
}
func lastOwner(snap *types.Snapshot, workspaceID, userID string) bool {
	for _, m := range snap.Memberships {
		u := user(snap, m.UserID)
		if m.WorkspaceID == workspaceID && m.Role == "owner" && m.UserID != userID && u != nil && !u.Disabled {
			return false
		}
	}
	return true
}
func (s *State) SetMembership(actorID, workspaceID, userID, role string) (types.Membership, error) {
	var out types.Membership
	err := s.mutate(func(snap *types.Snapshot) error {
		w := workspace(snap, workspaceID)
		if w == nil {
			return problem(types.KindNotFound, "workspace not found")
		}
		if err := requireManager(snap, actorID, w.ID); err != nil {
			return err
		}
		if !validRole(role) {
			return problem(types.KindInvalid, "invalid membership role")
		}
		if _, err := requireUser(snap, userID); err != nil {
			return err
		}
		actor := user(snap, actorID)
		current := member(snap, w.ID, userID)
		actorMember := member(snap, w.ID, actorID)
		if !actor.Admin && (role == "owner" || role == "maintainer" || (current != nil && (current.Role == "owner" || current.Role == "maintainer"))) && (actorMember == nil || actorMember.Role != "owner") {
			return problem(types.KindForbidden, "owner required to change privileged membership")
		}
		if current != nil && current.Role == "owner" && role != "owner" && lastOwner(snap, w.ID, userID) {
			return problem(types.KindConflict, "workspace must retain an active owner")
		}
		out = types.Membership{WorkspaceID: w.ID, UserID: userID, Role: role}
		if current == nil {
			snap.Memberships = append(snap.Memberships, out)
		} else {
			*current = out
		}
		audit(snap, actorID, "membership.set", userID)
		return nil
	})
	return out, err
}
func (s *State) RemoveMembership(actorID, workspaceID, userID string) error {
	return s.mutate(func(snap *types.Snapshot) error {
		w := workspace(snap, workspaceID)
		if w == nil {
			return problem(types.KindNotFound, "workspace not found")
		}
		if err := requireManager(snap, actorID, w.ID); err != nil {
			return err
		}
		m := member(snap, w.ID, userID)
		if m == nil {
			return problem(types.KindNotFound, "membership not found")
		}
		actor := user(snap, actorID)
		am := member(snap, w.ID, actorID)
		if !actor.Admin && (m.Role == "owner" || m.Role == "maintainer") && (am == nil || am.Role != "owner") {
			return problem(types.KindForbidden, "owner required")
		}
		if m.Role == "owner" && lastOwner(snap, w.ID, userID) {
			return problem(types.KindConflict, "workspace must retain an active owner")
		}
		snap.Memberships = slices.DeleteFunc(snap.Memberships, func(v types.Membership) bool { return v.WorkspaceID == w.ID && v.UserID == userID })
		for i := range snap.Agents {
			if snap.Agents[i].WorkspaceID == w.ID && snap.Agents[i].UserID == userID {
				snap.Agents[i].Status = "revoked"
			}
		}
		for i := range snap.Tokens {
			if snap.Tokens[i].WorkspaceID == w.ID && snap.Tokens[i].UserID == userID {
				snap.Tokens[i].Revoked = true
			}
		}
		audit(snap, actorID, "membership.remove", userID)
		return nil
	})
}
func (s *State) DisableUser(actorID, userID string) error {
	return s.mutate(func(snap *types.Snapshot) error {
		if err := requireAdmin(snap, actorID); err != nil {
			return err
		}
		u := user(snap, userID)
		if u == nil {
			return problem(types.KindNotFound, "user not found")
		}
		if u.Admin {
			found := false
			for _, v := range snap.Users {
				if v.ID != u.ID && v.Admin && !v.Disabled {
					found = true
				}
			}
			if !found {
				return problem(types.KindConflict, "instance must retain an active administrator")
			}
		}
		for _, m := range snap.Memberships {
			if m.UserID == u.ID && m.Role == "owner" && lastOwner(snap, m.WorkspaceID, u.ID) {
				return problem(types.KindConflict, "transfer workspace ownership before disabling this user")
			}
		}
		u.Disabled = true
		audit(snap, actorID, "user.disable", u.ID)
		return nil
	})
}

func validateDesired(cfg config.Config) (config.Config, error) {
	for _, rules := range []struct {
		values   []policy.Rule
		required bool
	}{{cfg.Ingress.Routes, true}, {cfg.Egress.Allow, true}, {cfg.Egress.Deny, false}} {
		for _, rule := range rules.values {
			if err := rule.Validate(rules.required); err != nil {
				return cfg, problem(types.KindInvalid, err.Error())
			}
		}
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return cfg, err
	}
	var object any
	if err = json.Unmarshal(encoded, &object); err != nil {
		return cfg, err
	}
	var prune func(any)
	prune = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for k, child := range v {
				if child == nil {
					delete(v, k)
				} else {
					prune(child)
				}
			}
		case []any:
			for _, child := range v {
				prune(child)
			}
		}
	}
	prune(object)
	data, err := yaml.Marshal(object)
	if err != nil {
		return cfg, err
	}
	parsed, err := config.Parse(data, ".")
	if err != nil {
		return cfg, problem(types.KindInvalid, "invalid agent configuration: "+err.Error())
	}
	parsed.Agent.StateDir = cfg.Agent.StateDir
	parsed.Transport.CAFile = cfg.Transport.CAFile
	return *parsed, nil
}
func declaredRoles(cfg config.Config) []string {
	var roles []string
	if cfg.Ingress.Enabled {
		roles = append(roles, "ingress")
	}
	if cfg.Serve.Enabled {
		roles = append(roles, "serve")
	}
	if cfg.Egress.Enabled {
		roles = append(roles, "egress")
	}
	return roles
}
func (s *State) CreateEnrollmentKey(actorID string, key types.EnrollmentKey) (types.EnrollmentKey, string, error) {
	plain := randomToken()
	err := s.mutate(func(snap *types.Snapshot) error {
		w := workspace(snap, key.WorkspaceID)
		if w == nil {
			return problem(types.KindNotFound, "workspace not found")
		}
		actor, err := requireUser(snap, actorID)
		if err != nil {
			return err
		}
		m := member(snap, w.ID, actorID)
		manager := actor.Admin || (m != nil && (m.Role == "owner" || m.Role == "maintainer"))
		if m == nil && !actor.Admin {
			return problem(types.KindForbidden, "workspace membership required")
		}
		if key.UserID == "" {
			key.UserID = actorID
		}
		if key.UserID != actorID && !manager {
			return problem(types.KindForbidden, "cannot enroll for another user")
		}
		if _, err := requireUser(snap, key.UserID); err != nil {
			return err
		}
		owner := member(snap, w.ID, key.UserID)
		if owner == nil {
			return problem(types.KindForbidden, "enrollment owner must be a workspace member")
		}
		if len(key.Roles) == 0 {
			return problem(types.KindInvalid, "enrollment roles required")
		}
		seen := map[string]bool{}
		for _, role := range key.Roles {
			if !slices.Contains([]string{"ingress", "serve", "egress"}, role) || seen[role] {
				return problem(types.KindInvalid, "invalid or duplicate enrollment role")
			}
			seen[role] = true
			if owner.Role == "guest" && role != "ingress" {
				return problem(types.KindForbidden, "guests can only enroll ingress")
			}
		}
		if key.AutoApprove && !manager {
			return problem(types.KindForbidden, "auto-approval requires a workspace manager")
		}
		if key.MaxUses == 0 {
			key.MaxUses = 1
		}
		if key.MaxUses < 1 || key.MaxUses > 10000 {
			return problem(types.KindInvalid, "invalid key usage limit")
		}
		if key.ExpiresAt.IsZero() {
			key.ExpiresAt = time.Now().Add(24 * time.Hour)
		}
		if !key.ExpiresAt.After(time.Now()) || key.ExpiresAt.After(time.Now().Add(TokenTTL)) {
			return problem(types.KindInvalid, "key expiration must be within 30 days")
		}
		key.ID = randomID()
		key.WorkspaceID = w.ID
		key.Uses = 0
		key.Revoked = false
		snap.EnrollmentKeys = append(snap.EnrollmentKeys, key)
		token := tokenRecord("enrollment", plain, key.UserID, w.ID, "", key.ExpiresAt)
		token.ID = key.ID
		snap.Tokens = append(snap.Tokens, token)
		audit(snap, actorID, "enrollment_key.create", key.ID)
		return nil
	})
	if err != nil {
		plain = ""
	}
	return key, plain, err
}

func nameTaken(snap *types.Snapshot, workspaceID, name string) bool {
	for _, a := range snap.Agents {
		if a.WorkspaceID == workspaceID && a.Name == name {
			return true
		}
	}
	for _, v := range snap.Services {
		if v.WorkspaceID == workspaceID && v.Name == name {
			return true
		}
	}
	return false
}
func (s *State) Enroll(request types.EnrollRequest) (types.EnrollResponse, error) {
	var response types.EnrollResponse
	cfg, err := validateDesired(request.Config)
	if err != nil {
		return response, err
	}
	controlToken, providerToken, accessToken := randomToken(), randomToken(), randomToken()
	err = s.mutate(func(snap *types.Snapshot) error {
		tk, err := tokenIn(snap, request.EnrollmentKey)
		if err != nil {
			return err
		}
		if tk.Kind != "enrollment" {
			return problem(types.KindUnauthorized, "an enrollment key is required")
		}
		var key *types.EnrollmentKey
		for i := range snap.EnrollmentKeys {
			if snap.EnrollmentKeys[i].ID == tk.ID {
				key = &snap.EnrollmentKeys[i]
			}
		}
		if key == nil || key.Revoked || key.Uses >= key.MaxUses || !key.ExpiresAt.After(time.Now()) {
			return problem(types.KindForbidden, "enrollment key unavailable")
		}
		if _, err := requireUser(snap, key.UserID); err != nil {
			return err
		}
		m := member(snap, key.WorkspaceID, key.UserID)
		if m == nil {
			return problem(types.KindForbidden, "enrollment owner is no longer a member")
		}
		w := workspace(snap, key.WorkspaceID)
		if w == nil || cfg.Workspace != w.Name {
			return problem(types.KindForbidden, "enrollment key belongs to a different workspace")
		}
		roles := declaredRoles(cfg)
		for _, role := range roles {
			if !slices.Contains(key.Roles, role) || (m.Role == "guest" && role != "ingress") {
				return problem(types.KindForbidden, "enrollment role exceeds key permissions")
			}
		}
		if nameTaken(snap, w.ID, cfg.Agent.Name) {
			return problem(types.KindConflict, "agent name already reserved")
		}
		a := types.Agent{ID: randomID(), WorkspaceID: w.ID, Workspace: w.Name, UserID: key.UserID, Name: cfg.Agent.Name, Status: "pending", Desired: cfg, Roles: slices.Clone(key.Roles), PendingApproval: true, CreatedAt: time.Now().UTC(), Approval: credentials.Approval{Revision: snap.Revision + 1, ExpiresAt: time.Now().Add(ApprovalTTL)}}
		if err := s.ensureServices(snap, &a); err != nil {
			return err
		}
		key.Uses++
		snap.Agents = append(snap.Agents, a)
		ap := &snap.Agents[len(snap.Agents)-1]
		if key.AutoApprove {
			if err := s.approve(snap, ap); err != nil {
				return err
			}
		}
		expiry := time.Now().Add(TokenTTL)
		snap.Tokens = append(snap.Tokens, tokenRecord("control", controlToken, a.UserID, w.ID, a.ID, expiry))
		creds := credentials.Credentials{Version: 1, Workspace: w.Name, AgentID: a.ID, ControlToken: controlToken}
		if slices.Contains(a.Roles, "serve") || slices.Contains(a.Roles, "egress") {
			snap.Tokens = append(snap.Tokens, tokenRecord("provider", providerToken, a.UserID, w.ID, a.ID, expiry))
			creds.ProviderToken = providerToken
		}
		if slices.Contains(a.Roles, "ingress") {
			snap.Tokens = append(snap.Tokens, tokenRecord("access", accessToken, a.UserID, w.ID, a.ID, expiry))
			creds.AccessToken = accessToken
		}
		view := agentView(snap, *ap)
		creds.Approval = view.Approval
		response = types.EnrollResponse{Agent: view, Credentials: creds}
		audit(snap, a.UserID, "agent.enroll", a.ID)
		return nil
	})
	return response, err
}

func (s *State) ensureServices(snap *types.Snapshot, a *types.Agent) error {
	if !a.Desired.Serve.Enabled {
		return nil
	}
	for _, desired := range a.Desired.Serve.Services {
		found := false
		for _, v := range snap.Services {
			if v.AgentID == a.ID && v.Name == desired.Name {
				found = true
			}
		}
		if found {
			continue
		}
		if desired.Name == a.Name || nameTaken(snap, a.WorkspaceID, desired.Name) {
			return problem(types.KindConflict, "service name already reserved")
		}
		snap.Services = append(snap.Services, types.Service{ID: randomID(), WorkspaceID: a.WorkspaceID, AgentID: a.ID, Name: desired.Name, Hostname: desired.Name + "." + a.Workspace + "." + s.baseDomain, Enabled: true})
	}
	return nil
}
func (s *State) approve(snap *types.Snapshot, a *types.Agent) error {
	if !agentAllowed(snap, a) {
		return problem(types.KindForbidden, "agent is revoked or its owner is inactive")
	}
	if member(snap, a.WorkspaceID, a.UserID).Role == "guest" && (a.Desired.Serve.Enabled || a.Desired.Egress.Enabled) {
		return problem(types.KindForbidden, "guests cannot provide services or egress")
	}
	if err := s.ensureServices(snap, a); err != nil {
		return err
	}
	a.Status = "active"
	a.PendingApproval = false
	a.Approval = credentials.Approval{Revision: snap.Revision + 1, ExpiresAt: time.Now().Add(ApprovalTTL), Services: map[string]string{}}
	if a.Desired.Serve.Enabled {
		for _, v := range a.Desired.Serve.Services {
			a.Approval.Services[v.Name] = v.Origin
		}
	}
	if a.Desired.Egress.Enabled {
		a.Approval.Egress = slices.Clone(a.Desired.Egress.Allow)
		a.Approval.Deny = slices.Clone(a.Desired.Egress.Deny)
	}
	for _, service := range snap.Services {
		if service.AgentID != a.ID {
			continue
		}
		_, approved := a.Approval.Services[service.Name]
		if !approved {
			continue
		}
		everGranted := false
		for _, g := range snap.Grants {
			if g.ResourceType == "service" && g.ResourceID == service.ID {
				everGranted = true
			}
		}
		if !everGranted {
			snap.Grants = append(snap.Grants, types.Grant{ID: randomID(), WorkspaceID: a.WorkspaceID, ResourceType: "service", ResourceID: service.ID, SubjectType: "workspace", SubjectID: a.WorkspaceID, StartsAt: time.Now().UTC(), ExpiresAt: time.Now().Add(DefaultGrantTTL)})
		}
	}
	return nil
}
func (s *State) ApproveAgent(actorID, agentID string) (types.Agent, error) {
	err := s.mutate(func(snap *types.Snapshot) error {
		a := agent(snap, agentID)
		if a == nil {
			return problem(types.KindNotFound, "agent not found")
		}
		if err := requireManager(snap, actorID, a.WorkspaceID); err != nil {
			return err
		}
		if !agentAllowed(snap, a) {
			return problem(types.KindForbidden, "agent or owner is inactive")
		}
		if member(snap, a.WorkspaceID, a.UserID).Role == "guest" && (a.Desired.Serve.Enabled || a.Desired.Egress.Enabled) {
			return problem(types.KindForbidden, "guests cannot provide services or egress")
		}
		if a.Status == "active" && !a.PendingApproval {
			return nil
		}
		if err := s.approve(snap, a); err != nil {
			return err
		}
		audit(snap, actorID, "agent.approve", agentID)
		return nil
	})
	if err != nil {
		return types.Agent{}, err
	}
	return s.Agent(agentID)
}

func intersectRules(a, b []policy.Rule) []policy.Rule {
	var out []policy.Rule
	for _, x := range a {
		for _, y := range b {
			var d policy.Domain
			switch {
			case x.Domain.Exact != "":
				if y.Domain.Exact == x.Domain.Exact || y.Domain.Suffix != "" && (x.Domain.Exact == y.Domain.Suffix || strings.HasSuffix(x.Domain.Exact, "."+y.Domain.Suffix)) {
					d.Exact = x.Domain.Exact
				}
			case y.Domain.Exact != "":
				if x.Domain.Suffix != "" && (y.Domain.Exact == x.Domain.Suffix || strings.HasSuffix(y.Domain.Exact, "."+x.Domain.Suffix)) {
					d.Exact = y.Domain.Exact
				}
			default:
				if x.Domain.Suffix == y.Domain.Suffix || strings.HasSuffix(x.Domain.Suffix, "."+y.Domain.Suffix) {
					d.Suffix = x.Domain.Suffix
				} else if strings.HasSuffix(y.Domain.Suffix, "."+x.Domain.Suffix) {
					d.Suffix = y.Domain.Suffix
				}
			}
			if d.Exact == "" && d.Suffix == "" {
				continue
			}
			var ports []int
			for _, p := range x.Ports {
				if slices.Contains(y.Ports, p) {
					ports = append(ports, p)
				}
			}
			if len(ports) > 0 {
				out = append(out, policy.Rule{Domain: d, Ports: ports, Protocol: "tls"})
			}
		}
	}
	return out
}
func agentView(snap *types.Snapshot, a types.Agent) types.Agent {
	if !agentAllowed(snap, &a) {
		a.Status = "revoked"
	}
	if a.Status != "active" || member(snap, a.WorkspaceID, a.UserID).Role == "guest" {
		a.Approval = credentials.Approval{Revision: a.Approval.Revision, ExpiresAt: time.Now().Add(ApprovalTTL)}
		return a
	}
	approved := a.Approval
	a.Approval.Services = map[string]string{}
	if a.Desired.Serve.Enabled {
		for _, service := range a.Desired.Serve.Services {
			if approved.Services[service.Name] == service.Origin {
				a.Approval.Services[service.Name] = service.Origin
			}
		}
	}
	a.Approval.Egress = nil
	a.Approval.Deny = nil
	if a.Desired.Egress.Enabled {
		a.Approval.Egress = intersectRules(approved.Egress, a.Desired.Egress.Allow)
		a.Approval.Deny = append(slices.Clone(approved.Deny), a.Desired.Egress.Deny...)
	}
	a.Approval.ExpiresAt = time.Now().Add(ApprovalTTL)
	return a
}
func (s *State) Agent(id string) (types.Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap, err := clone(s.snapshot)
	if err != nil {
		return types.Agent{}, err
	}
	a := agent(&snap, id)
	if a == nil {
		return types.Agent{}, problem(types.KindNotFound, "agent not found")
	}
	return agentView(&snap, *a), nil
}
func (s *State) GetAgentCredentials(controlToken string) (credentials.Credentials, error) {
	if err := s.renewAgentTokens(controlToken); err != nil {
		return credentials.Credentials{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, err := identity(&s.snapshot, controlToken)
	if err != nil {
		return credentials.Credentials{}, err
	}
	if id.Kind != "control" {
		return credentials.Credentials{}, problem(types.KindUnauthorized, "agent control token required")
	}
	snap, err := clone(s.snapshot)
	if err != nil {
		return credentials.Credentials{}, err
	}
	a := agentView(&snap, *agent(&snap, id.AgentID))
	return credentials.Credentials{Version: 1, Workspace: a.Workspace, AgentID: a.ID, Approval: a.Approval}, nil
}

func agentTokensNeedRenewal(snap *types.Snapshot, agentID string, now time.Time) bool {
	for _, token := range snap.Tokens {
		if token.AgentID == agentID && !token.Revoked && (token.Kind == "control" || token.Kind == "provider" || token.Kind == "access") && !token.ExpiresAt.IsZero() && token.ExpiresAt.Before(now.Add(TokenRenewBefore)) {
			return true
		}
	}
	return false
}

// Normal polling is read-only. Renewal commits only close to expiry and keeps
// hashes/IDs unchanged so established, independently authorized flows survive.
func (s *State) renewAgentTokens(plain string) error {
	s.mu.RLock()
	id, err := identity(&s.snapshot, plain)
	needed := false
	if err == nil && id.Kind == "control" {
		needed = agentTokensNeedRenewal(&s.snapshot, id.AgentID, time.Now())
	}
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if id.Kind != "control" {
		return problem(types.KindUnauthorized, "agent control token required")
	}
	if !needed {
		return nil
	}
	return s.mutate(func(snap *types.Snapshot) error {
		current, err := identity(snap, plain)
		if err != nil {
			return err
		}
		if current.Kind != "control" {
			return problem(types.KindUnauthorized, "agent control token required")
		}
		now := time.Now()
		if !agentTokensNeedRenewal(snap, current.AgentID, now) {
			return nil
		}
		for i := range snap.Tokens {
			token := &snap.Tokens[i]
			if token.AgentID == current.AgentID && !token.Revoked && (token.Kind == "control" || token.Kind == "provider" || token.Kind == "access") {
				token.ExpiresAt = now.Add(TokenTTL).UTC()
			}
		}
		audit(snap, current.UserID, "agent.tokens.renew", current.AgentID)
		return nil
	})
}

// RotateUserToken replaces API/login credentials without changing stable user
// IDs, grants or existing browser sessions. Old bearer tokens stay recognizable
// to the gateway but can no longer authenticate.
func (s *State) RotateUserToken(actorID, userID string) (string, error) {
	plain := randomToken()
	err := s.mutate(func(snap *types.Snapshot) error {
		actor, err := requireUser(snap, actorID)
		if err != nil {
			return err
		}
		if actorID != userID && !actor.Admin {
			return problem(types.KindForbidden, "only the user or an instance administrator can rotate a user token")
		}
		target := user(snap, userID)
		if target == nil {
			return problem(types.KindNotFound, "user not found")
		}
		if target.Disabled {
			return problem(types.KindForbidden, "user is disabled")
		}
		for i := range snap.Tokens {
			if snap.Tokens[i].Kind == "user" && snap.Tokens[i].UserID == userID {
				snap.Tokens[i].Revoked = true
			}
		}
		snap.Tokens = append(snap.Tokens, tokenRecord("user", plain, userID, "", "", time.Now().Add(TokenTTL).UTC()))
		audit(snap, actorID, "user.token.rotate", userID)
		return nil
	})
	if err != nil {
		return "", err
	}
	return plain, nil
}
func (s *State) UpdateAgent(controlToken string, cfg config.Config) (types.Agent, error) {
	next, err := validateDesired(cfg)
	if err != nil {
		return types.Agent{}, err
	}
	var id string
	err = s.mutate(func(snap *types.Snapshot) error {
		ident, err := identity(snap, controlToken)
		if err != nil {
			return err
		}
		if ident.Kind != "control" {
			return problem(types.KindUnauthorized, "agent control token required")
		}
		a := agent(snap, ident.AgentID)
		if next.Workspace != a.Workspace || next.Agent.Name != a.Name {
			return problem(types.KindForbidden, "cannot switch registered workspace or name")
		}
		if next.Instance != a.Desired.Instance || next.Transport.Endpoint != a.Desired.Transport.Endpoint {
			return problem(types.KindForbidden, "registered control and Edge origins cannot change")
		}
		m := member(snap, a.WorkspaceID, a.UserID)
		for _, role := range declaredRoles(next) {
			if !slices.Contains(a.Roles, role) || (m.Role == "guest" && role != "ingress") {
				return problem(types.KindForbidden, "desired role exceeds enrollment permission")
			}
		}
		id = a.ID
		if reflect.DeepEqual(a.Desired, next) {
			return nil
		}
		a.Desired = next
		a.PendingApproval = true
		if err := s.ensureServices(snap, a); err != nil {
			return err
		}
		audit(snap, a.UserID, "agent.desired", a.ID)
		return nil
	})
	if err != nil {
		return types.Agent{}, err
	}
	return s.Agent(id)
}

// SnapshotForUser returns a detached, scoped view; token hashes never leave state.
func (s *State) SnapshotForUser(userID string) (types.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, err := requireUser(&s.snapshot, userID)
	if err != nil {
		return types.Snapshot{}, err
	}
	snap, err := clone(s.snapshot)
	if err != nil {
		return snap, err
	}
	snap.Tokens = nil
	if u.Admin {
		return snap, nil
	}
	visible := map[string]bool{}
	managed := map[string]bool{}
	for _, m := range snap.Memberships {
		if m.UserID == userID {
			visible[m.WorkspaceID] = true
			managed[m.WorkspaceID] = m.Role == "owner" || m.Role == "maintainer"
		}
	}
	snap.Workspaces = slices.DeleteFunc(snap.Workspaces, func(w types.Workspace) bool { return !visible[w.ID] })
	snap.Memberships = slices.DeleteFunc(snap.Memberships, func(m types.Membership) bool { return !visible[m.WorkspaceID] })
	users := map[string]bool{userID: true}
	for _, m := range snap.Memberships {
		users[m.UserID] = true
	}
	snap.Users = slices.DeleteFunc(snap.Users, func(v types.User) bool { return !users[v.ID] })
	snap.Agents = slices.DeleteFunc(snap.Agents, func(a types.Agent) bool {
		return !visible[a.WorkspaceID] || (!managed[a.WorkspaceID] && a.UserID != userID)
	})
	snap.EnrollmentKeys = slices.DeleteFunc(snap.EnrollmentKeys, func(k types.EnrollmentKey) bool {
		return !visible[k.WorkspaceID] || (!managed[k.WorkspaceID] && k.UserID != userID)
	})
	snap.Services = slices.DeleteFunc(snap.Services, func(v types.Service) bool { return !visible[v.WorkspaceID] })
	snap.EgressRoutes = slices.DeleteFunc(snap.EgressRoutes, func(v types.EgressRoute) bool { return !visible[v.WorkspaceID] })
	snap.Grants = slices.DeleteFunc(snap.Grants, func(g types.Grant) bool { return !managed[g.WorkspaceID] })
	snap.Audit = nil
	return snap, nil
}
