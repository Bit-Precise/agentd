package store_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"agentd/internal/identity"
	"agentd/internal/pgtest"
	"agentd/internal/routes"
	"agentd/internal/store"
	"agentd/internal/wire/pb"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

func open(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), pgtest.NewDB(t), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func seed(t *testing.T, s *store.Store) store.Workspace {
	t.Helper()
	ctx := context.Background()
	relayKey, _ := identity.GenerateKey()
	if err := s.CreateRelay(ctx, store.Relay{Name: "relay-hk", PublicKey: identity.Public(relayKey), URL: "https://relay.example.com", Transports: map[string]string{"ws": "/ws"}}); err != nil {
		t.Fatal(err)
	}
	wsKey, _ := identity.GenerateKey()
	ws := store.Workspace{Name: "home", BaseDomain: "home.example.com", PrivateKey: wsKey, Relay: "relay-hk"}
	if err := s.CreateWorkspace(ctx, ws); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWorkspace(ctx, "home")
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestMigrationsAreIdempotentAndServerKeyPersists(t *testing.T) {
	ctx := context.Background()
	url := pgtest.NewDB(t)
	box := []byte("0123456789abcdef0123456789abcdef")
	s1, err := store.Open(ctx, url, box)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := s1.ServerKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s1.Close()
	s2, err := store.Open(ctx, url, box)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	k2, _ := s2.ServerKey(ctx)
	if !bytes.Equal(k1, k2) {
		t.Fatal("server key changed across restarts")
	}
	if _, err := store.Open(ctx, url, []byte("ffffffffffffffffffffffffffffffff")); err == nil {
		s3, _ := store.Open(ctx, url, []byte("ffffffffffffffffffffffffffffffff"))
		if s3 != nil {
			if _, err := s3.ServerKey(ctx); err == nil {
				t.Fatal("server key decrypted with the wrong state key")
			}
			s3.Close()
		}
	}
}

func TestWorkspaceRoundTripKeepsKeyEncrypted(t *testing.T) {
	s := open(t)
	ws := seed(t, s)
	if ws.BaseDomain != "home.example.com" || len(ws.PrivateKey) != 64 || !bytes.Equal(ws.PublicKey, identity.Public(ws.PrivateKey)) {
		t.Fatalf("workspace: %+v", ws)
	}
	byDomain, err := s.GetWorkspaceByDomain(context.Background(), "home.example.com")
	if err != nil || byDomain.Name != "home" {
		t.Fatalf("by domain: %v %v", byDomain, err)
	}
	if err := s.CreateWorkspace(context.Background(), store.Workspace{Name: "home", BaseDomain: "x.example.com", PrivateKey: ws.PrivateKey, Relay: "relay-hk"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate workspace: %v", err)
	}
}

func TestJoinConsumesTokenOnce(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	seed(t, s)
	hash := store.HashToken("secret-token")
	if err := s.CreateJoinToken(ctx, store.JoinToken{ID: "t1", Workspace: "home", Hash: hash, Name: "dorm", Roles: []string{"egress"}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	key, _ := identity.GenerateKey()
	node, err := s.Join(ctx, store.JoinRequest{TokenHash: hash, WorkspaceDomain: "home.example.com", Identity: identity.Public(key), ProposedName: "ignored"})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if node.Name != "dorm" || len(node.RoleCaps) != 1 || node.RoleCaps[0] != "egress" {
		t.Fatalf("node: %+v", node)
	}
	key2, _ := identity.GenerateKey()
	if _, err := s.Join(ctx, store.JoinRequest{TokenHash: hash, WorkspaceDomain: "home.example.com", Identity: identity.Public(key2)}); store.StatusOf(err) != pb.Status_TOKEN_USED {
		t.Fatalf("second use: %v", err)
	}
	got, ws, err := s.GetNodeByKey(ctx, identity.Public(key))
	if err != nil || got.Name != "dorm" || ws.Name != "home" {
		t.Fatalf("lookup by key: %+v %v", got, err)
	}
}

func TestJoinRejections(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	seed(t, s)
	mk := func(id, name string, exp time.Time) []byte {
		h := store.HashToken(id)
		if err := s.CreateJoinToken(ctx, store.JoinToken{ID: id, Workspace: "home", Hash: h, Name: name, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
		return h
	}
	k1, _ := identity.GenerateKey()
	if _, err := s.Join(ctx, store.JoinRequest{TokenHash: mk("a", "laptop", time.Now().Add(time.Hour)), WorkspaceDomain: "home.example.com", Identity: identity.Public(k1)}); err != nil {
		t.Fatal(err)
	}
	k2, _ := identity.GenerateKey()
	cases := []struct {
		req  store.JoinRequest
		want pb.Status
	}{
		{store.JoinRequest{TokenHash: store.HashToken("nope"), WorkspaceDomain: "home.example.com", Identity: identity.Public(k2)}, pb.Status_TOKEN_INVALID},
		{store.JoinRequest{TokenHash: mk("b", "", time.Now().Add(-time.Minute)), WorkspaceDomain: "home.example.com", Identity: identity.Public(k2), ProposedName: "x"}, pb.Status_TOKEN_EXPIRED},
		{store.JoinRequest{TokenHash: mk("c", "", time.Now().Add(time.Hour)), WorkspaceDomain: "home.example.com", Identity: identity.Public(k2), ProposedName: "laptop"}, pb.Status_NAME_TAKEN},
		{store.JoinRequest{TokenHash: mk("d", "", time.Now().Add(time.Hour)), WorkspaceDomain: "home.example.com", Identity: identity.Public(k1), ProposedName: "again"}, pb.Status_IDENTITY_IN_USE},
		{store.JoinRequest{TokenHash: mk("e", "", time.Now().Add(time.Hour)), WorkspaceDomain: "other.example.com", Identity: identity.Public(k2), ProposedName: "y"}, pb.Status_WORKSPACE_MISMATCH},
		{store.JoinRequest{TokenHash: mk("f", "", time.Now().Add(time.Hour)), WorkspaceDomain: "home.example.com", Identity: identity.Public(k2), ProposedName: "Bad_Name"}, pb.Status_BAD_NAME},
	}
	for i, c := range cases {
		if _, err := s.Join(ctx, c.req); store.StatusOf(err) != c.want {
			t.Errorf("case %d: got %v (%v), want %v", i, store.StatusOf(err), err, c.want)
		}
	}
}

func TestServicesShareNamespaceWithNodes(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	seed(t, s)
	for i, name := range []string{"homepc", "laptop"} {
		k, _ := identity.GenerateKey()
		h := store.HashToken(name)
		s.CreateJoinToken(ctx, store.JoinToken{ID: name, Workspace: "home", Hash: h, Name: name, ExpiresAt: time.Now().Add(time.Hour)})
		if _, err := s.Join(ctx, store.JoinRequest{TokenHash: h, WorkspaceDomain: "home.example.com", Identity: identity.Public(k)}); err != nil {
			t.Fatalf("join %d: %v", i, err)
		}
	}
	accepted, rejected, err := s.ReplaceNodeServices(ctx, "home", "homepc", []store.Service{{Name: "nas", Proto: "http"}, {Name: "homepc", Proto: "ssh"}, {Name: "laptop", Proto: "ssh"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 2 || len(rejected) != 1 || rejected[0] != "laptop" {
		t.Fatalf("accepted %v rejected %v", accepted, rejected)
	}
	svcs, _ := s.ListServices(ctx, "home")
	if len(svcs) != 2 {
		t.Fatalf("services: %v", svcs)
	}
	// Re-advertising replaces the set.
	s.ReplaceNodeServices(ctx, "home", "homepc", []store.Service{{Name: "nas", Proto: "http"}})
	svcs, _ = s.ListServices(ctx, "home")
	if len(svcs) != 1 || svcs[0].Name != "nas" || svcs[0].Node != "homepc" {
		t.Fatalf("after replace: %v", svcs)
	}
}

func TestRouteTableVersioning(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	seed(t, s)
	t0, err := s.GetRouteTable(ctx, "home")
	if err != nil {
		t.Fatal(err)
	}
	r := routes.Route{From: "group:pc", Protos: []pb.Proto{pb.Proto_PROTO_TLS}, Domains: []*pb.Match{{Kind: pb.Match_SUFFIX, Value: "ucas.edu.cn"}}, To: "dorm"}
	id, err := s.AddRoute(ctx, "home", r)
	if err != nil {
		t.Fatal(err)
	}
	t1, _ := s.GetRouteTable(ctx, "home")
	if t1.Version != t0.Version+1 || len(t1.Routes) != 1 || t1.Routes[0].ID != id || t1.Routes[0].Domains[0].Value != "ucas.edu.cn" {
		t.Fatalf("after add: %+v", t1)
	}
	if err := s.ReplaceRoutes(ctx, "home", []routes.Route{r, r}, "reject"); err != nil {
		t.Fatal(err)
	}
	t2, _ := s.GetRouteTable(ctx, "home")
	if t2.Version != t1.Version+1 || len(t2.Routes) != 2 || t2.Default != "reject" {
		t.Fatalf("after replace: %+v", t2)
	}
	if err := s.DeleteRoute(ctx, "home", t2.Routes[0].ID); err != nil {
		t.Fatal(err)
	}
	t3, _ := s.GetRouteTable(ctx, "home")
	if len(t3.Routes) != 1 || t3.Version != t2.Version+1 {
		t.Fatalf("after delete: %+v", t3)
	}
}

func TestGroupsAndMembership(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	seed(t, s)
	k, _ := identity.GenerateKey()
	h := store.HashToken("x")
	s.CreateJoinToken(ctx, store.JoinToken{ID: "x", Workspace: "home", Hash: h, Name: "laptop", ExpiresAt: time.Now().Add(time.Hour)})
	s.Join(ctx, store.JoinRequest{TokenHash: h, WorkspaceDomain: "home.example.com", Identity: identity.Public(k)})
	gk, _ := identity.GenerateKey()
	if err := s.CreateGroup(ctx, store.Group{Workspace: "home", Name: "pc", PrivateKey: gk}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddGroupMember(ctx, "home", "pc", "laptop"); err != nil {
		t.Fatal(err)
	}
	groups, err := s.ListGroups(ctx, "home")
	if err != nil || len(groups) != 1 || len(groups[0].Members) != 1 || !bytes.Equal(groups[0].PrivateKey, gk) {
		t.Fatalf("groups: %+v %v", groups, err)
	}
	names, _ := s.GroupsOfNode(ctx, "home", "laptop")
	if len(names) != 1 || names[0] != "pc" {
		t.Fatalf("groups of node: %v", names)
	}
	if err := s.RenameNode(ctx, "home", "laptop", "laptop2"); err != nil {
		t.Fatal(err)
	}
	names, _ = s.GroupsOfNode(ctx, "home", "laptop2")
	if len(names) != 1 {
		t.Fatalf("membership did not follow the rename: %v", names)
	}
	if err := s.AddGroupMember(ctx, "home", "pc", "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown member: %v", err)
	}
}
