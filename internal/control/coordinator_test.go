package control

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"agentd/internal/identity"
	"agentd/internal/pgtest"
	"agentd/internal/routes"
	"agentd/internal/store"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

type fixture struct {
	c     *Coordinator
	ws    store.Workspace
	keys  map[string][]byte
	relay string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, pgtest.NewDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	srvKey, _ := identity.GenerateKey()
	certs := NewCertManager(st, nil, nil, "", nil)
	c := New(Options{Store: st, ServerKey: srvKey, Certs: certs})
	relayKey, _ := identity.GenerateKey()
	if err := st.CreateRelay(ctx, store.Relay{Name: "relay-hk", PublicKey: identity.Public(relayKey), URL: "https://relay.example.com"}); err != nil {
		t.Fatal(err)
	}
	other, _ := identity.GenerateKey()
	st.CreateRelay(ctx, store.Relay{Name: "relay-sg", PublicKey: identity.Public(other), URL: "https://sg.example.com"})
	wsKey, _ := identity.GenerateKey()
	if err := st.CreateWorkspace(ctx, store.Workspace{Name: "home", BaseDomain: "home.example.com", PrivateKey: wsKey, Relay: "relay-hk"}); err != nil {
		t.Fatal(err)
	}
	ws, _ := st.GetWorkspace(ctx, "home")
	if err := certs.IssueNow(ctx, ws); err != nil {
		t.Fatal(err)
	}
	f := &fixture{c: c, ws: ws, keys: map[string][]byte{}, relay: "relay-hk"}
	for name, roles := range map[string][]string{"laptop": {"ingress", "submitter"}, "dorm": {"egress"}, "office": {"executor"}, "homepc": {"service"}} {
		k, _ := identity.GenerateKey()
		tok := "tok-" + name
		st.CreateJoinToken(ctx, store.JoinToken{ID: name, Workspace: "home", Hash: store.HashToken(tok), Name: name, Roles: roles, ExpiresAt: time.Now().Add(time.Hour)})
		a := c.Lookup(ctx, "relay-hk", &pb.RelayLookup{Query: &pb.RelayLookup_Join{Join: &pb.JoinLookup{Identity: identity.Public(k), Token: tok, Workspace: "home.example.com"}}})
		if a.Status != pb.Status_OK {
			t.Fatalf("join %s: %v %s", name, a.Status, a.Message)
		}
		f.keys[name] = identity.Public(k)
	}
	return f
}

func (f *fixture) stream(t *testing.T, from string, q *pb.StreamLookup) *pb.RelayAnswer {
	t.Helper()
	q.Workspace = "home.example.com"
	if from != "" {
		q.From = f.keys[from]
	}
	return f.c.Lookup(context.Background(), f.relay, &pb.RelayLookup{Query: &pb.RelayLookup_Stream{Stream: q}})
}

func TestJoinWelcomeIsSignedForTheNode(t *testing.T) {
	f := setup(t)
	a := f.c.Lookup(context.Background(), "relay-hk", &pb.RelayLookup{Query: &pb.RelayLookup_Node{Node: &pb.NodeLookup{Identity: f.keys["laptop"]}}})
	if a.Status != pb.Status_OK {
		t.Fatalf("node lookup: %v", a.Status)
	}
	msg, err := wire.OpenSigned(f.ws.PublicKey, f.keys["laptop"], a.GetNode().Welcome, time.Now())
	if err != nil {
		t.Fatalf("welcome signature: %v", err)
	}
	w := msg.GetWelcome()
	if w.Self.Name != "laptop" || len(w.Directory.Members) != 4 || w.Routes == nil || len(w.Memberships) != 1 || len(w.Relays) != 1 {
		t.Fatalf("welcome: self=%v members=%d routes=%v certs=%d relays=%d", w.Self, len(w.Directory.Members), w.Routes, len(w.Memberships), len(w.Relays))
	}
	if _, err := wire.VerifyRelayCert(f.ws.PublicKey, w.Relays[0], "home.example.com", time.Now()); err != nil {
		t.Fatalf("relay cert: %v", err)
	}
	if w.Policy != nil {
		t.Fatal("a consumer-only node must not receive a policy")
	}
}

func TestWrongRelayAndUnknownKey(t *testing.T) {
	f := setup(t)
	a := f.c.Lookup(context.Background(), "relay-sg", &pb.RelayLookup{Query: &pb.RelayLookup_Node{Node: &pb.NodeLookup{Identity: f.keys["laptop"]}}})
	if a.Status != pb.Status_WRONG_RELAY || a.GetAssignedRelay() == nil {
		t.Fatalf("wrong relay: %v", a)
	}
	stranger, _ := identity.GenerateKey()
	a = f.c.Lookup(context.Background(), "relay-hk", &pb.RelayLookup{Query: &pb.RelayLookup_Node{Node: &pb.NodeLookup{Identity: identity.Public(stranger)}}})
	if a.Status != pb.Status_NOT_A_MEMBER {
		t.Fatalf("stranger: %v", a.Status)
	}
}

func TestStreamLookupRoutesAndPrechecks(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	st := f.c.Store()
	tls := pb.Proto_PROTO_TLS
	if a := f.stream(t, "laptop", &pb.StreamLookup{Kind: pb.Kind_KIND_TCP, Proto: tls, Domain: "course.ucas.edu.cn", Port: 443}); a.Status != pb.Status_NO_RULE || a.GetRoute().GetRulesVersion() == 0 {
		t.Fatalf("no route yet: %v", a)
	}
	st.AddRoute(ctx, "home", routes.Route{From: "workspace", Domains: []*pb.Match{{Kind: pb.Match_SUFFIX, Value: "ucas.edu.cn"}}, To: "dorm"})
	if a := f.stream(t, "laptop", &pb.StreamLookup{Kind: pb.Kind_KIND_TCP, Proto: tls, Domain: "course.ucas.edu.cn", Port: 443}); a.Status != pb.Status_ACL_DENIED {
		t.Fatalf("dorm has no policy yet: %v", a.Status)
	}
	// dorm self-manages and reports a local policy allowing laptop.
	pol := &pb.Policy{Egress: []*pb.EgressRule{{PublicKey: f.keys["laptop"], Proto: tls, Domains: []*pb.Match{{Kind: pb.Match_SUFFIX, Value: "ucas.edu.cn"}}}}}
	st.SaveAdvert(ctx, "home", "dorm", map[string]string{"egress": "local"}, pol, nil, false)
	a := f.stream(t, "laptop", &pb.StreamLookup{Kind: pb.Kind_KIND_TCP, Proto: tls, Domain: "course.ucas.edu.cn", Port: 443})
	if a.Status != pb.Status_OK || a.GetRoute().TargetName != "dorm" || a.GetRoute().TargetKind != pb.StreamRoute_EGRESS {
		t.Fatalf("egress route: %v", a)
	}
	if a := f.stream(t, "dorm", &pb.StreamLookup{Kind: pb.Kind_KIND_TCP, Proto: tls, Domain: "course.ucas.edu.cn", Port: 443}); a.Status != pb.Status_ROLE_NOT_ALLOWED {
		t.Fatalf("dorm has no ingress role: %v", a.Status)
	}
	// Tasks: office is server-managed; a central statement grants laptop.
	st.SaveAdvert(ctx, "home", "office", map[string]string{"executor": "server"}, nil, &pb.ExecutorDecl{Description: "office"}, false)
	task := &pb.StreamLookup{Kind: pb.Kind_KIND_TASK, Executor: f.keys["office"]}
	if a := f.stream(t, "laptop", task); a.Status != pb.Status_ACL_DENIED {
		t.Fatalf("task before policy: %v", a.Status)
	}
	stmt, _ := json.Marshal(Statement{Subjects: []string{"node:laptop"}, Allow: []Target{{Exec: "office", Argv: []string{"lark-cli"}}}})
	st.AddPolicy(ctx, "home", stmt)
	if a := f.stream(t, "laptop", &pb.StreamLookup{Kind: pb.Kind_KIND_TASK, Executor: f.keys["office"]}); a.Status != pb.Status_OK || a.GetRoute().TargetKind != pb.StreamRoute_EXECUTOR {
		t.Fatalf("task after policy: %v", a)
	}
}

func TestServiceLookupEdgeAndPublic(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	st := f.c.Store()
	st.ReplaceNodeServices(ctx, "home", "homepc", []store.Service{{Name: "nas", Proto: "http"}, {Name: "grafana", Proto: "http"}, {Name: "box", Proto: "ssh"}})
	pol := &pb.Policy{Services: []*pb.ServiceRule{{PublicKey: f.keys["laptop"], Name: "nas"}, {PublicKey: f.keys["laptop"], Name: "box"}, {Name: "grafana"}}}
	st.SaveAdvert(ctx, "home", "homepc", map[string]string{"service": "local"}, pol, nil, false)
	tls := pb.Proto_PROTO_TLS
	if a := f.stream(t, "laptop", &pb.StreamLookup{Kind: pb.Kind_KIND_TCP, Proto: tls, Domain: "nas.home.example.com", Port: 443}); a.Status != pb.Status_OK || a.GetRoute().TargetKind != pb.StreamRoute_EDGE {
		t.Fatalf("member to nas: %v", a)
	}
	if a := f.stream(t, "", &pb.StreamLookup{Kind: pb.Kind_KIND_TCP, Proto: tls, Domain: "nas.home.example.com", Port: 443}); a.Status != pb.Status_ACL_DENIED {
		t.Fatalf("public to nas must be denied: %v", a.Status)
	}
	if a := f.stream(t, "", &pb.StreamLookup{Kind: pb.Kind_KIND_TCP, Proto: tls, Domain: "grafana.home.example.com", Port: 443}); a.Status != pb.Status_OK {
		t.Fatalf("public to grafana: %v", a.Status)
	}
	if a := f.stream(t, "laptop", &pb.StreamLookup{Kind: pb.Kind_KIND_TCP, Proto: pb.Proto_PROTO_SSH, Domain: "box.home.example.com", Port: 22}); a.Status != pb.Status_OK || a.GetRoute().TargetKind != pb.StreamRoute_SERVICE_NODE {
		t.Fatalf("ssh service: %v", a)
	}
	if a := f.stream(t, "laptop", &pb.StreamLookup{Kind: pb.Kind_KIND_TCP, Proto: tls, Domain: "nope.home.example.com", Port: 443}); a.Status != pb.Status_SERVICE_UNKNOWN {
		t.Fatalf("unknown service: %v", a.Status)
	}
}
