package policy

import (
	"testing"

	"agentd/internal/wire/pb"
)

var (
	laptop = []byte("laptop-key-0000000000000000000000")[:32]
	pc     = []byte("pc-group-key-00000000000000000000")[:32]
	ws     = []byte("workspace-key-000000000000000000")[:32]
	other  = []byte("other-key-00000000000000000000000")[:32]
)

func suffix(v string) *pb.Match { return &pb.Match{Kind: pb.Match_SUFFIX, Value: v} }
func exact(v string) *pb.Match  { return &pb.Match{Kind: pb.Match_DOMAIN, Value: v} }

func TestMatchDomain(t *testing.T) {
	cases := []struct {
		m    *pb.Match
		d    string
		want bool
	}{
		{suffix("ucas.edu.cn"), "ucas.edu.cn", true},
		{suffix("ucas.edu.cn"), "course.ucas.edu.cn", true},
		{suffix("ucas.edu.cn"), "xucas.edu.cn", false},
		{exact("login.ucas.edu.cn"), "login.ucas.edu.cn", true},
		{exact("login.ucas.edu.cn"), "a.login.ucas.edu.cn", false},
		{suffix("EXAMPLE.com"), "a.example.COM.", true},
	}
	for _, c := range cases {
		if got := MatchDomain(c.m, c.d); got != c.want {
			t.Errorf("MatchDomain(%v, %q) = %v", c.m, c.d, got)
		}
	}
}

func TestEgressDenyOverridesAndDefaults(t *testing.T) {
	rules := []*pb.EgressRule{
		{PublicKey: pc, Action: pb.Action_ACTION_ALLOW, Proto: pb.Proto_PROTO_TLS, Domains: []*pb.Match{suffix("ucas.edu.cn")}},
		{PublicKey: pc, Action: pb.Action_ACTION_ALLOW, Proto: pb.Proto_PROTO_SSH, Domains: []*pb.Match{suffix("ucas.edu.cn")}},
		{Action: pb.Action_ACTION_DENY, Proto: pb.Proto_PROTO_TLS, Domains: []*pb.Match{exact("login.ucas.edu.cn")}},
	}
	ids := [][]byte{laptop, pc, ws}
	check := func(proto pb.Proto, domain string, port uint32, idset [][]byte, want pb.Status) {
		t.Helper()
		if got := Egress(rules, idset, proto, domain, port).Status; got != want {
			t.Errorf("Egress(%v,%s,%d) = %v, want %v", proto, domain, port, got, want)
		}
	}
	check(pb.Proto_PROTO_TLS, "course.ucas.edu.cn", 443, ids, pb.Status_OK)
	check(pb.Proto_PROTO_SSH, "lab.ucas.edu.cn", 22, ids, pb.Status_OK)
	check(pb.Proto_PROTO_TLS, "login.ucas.edu.cn", 443, ids, pb.Status_POLICY_DENIED)
	check(pb.Proto_PROTO_TLS, "course.ucas.edu.cn", 8443, ids, pb.Status_PORT_NOT_ALLOWED)
	check(pb.Proto_PROTO_TLS, "example.com", 443, ids, pb.Status_POLICY_DENIED)
	check(pb.Proto_PROTO_TLS, "course.ucas.edu.cn", 443, [][]byte{other}, pb.Status_POLICY_DENIED)
}

func TestExecPrefixMatching(t *testing.T) {
	rules := []*pb.ExecRule{
		{PublicKey: pc, Action: pb.Action_ACTION_ALLOW, Argv: []string{"/opt/homebrew/bin/lark-cli", "msg"}},
		{PublicKey: pc, Action: pb.Action_ACTION_ALLOW, Argv: []string{"lark-cli", "doc"}, Stdin: true},
		{PublicKey: laptop, Action: pb.Action_ACTION_ALLOW, Argv: []string{"git", "status"}},
		{Action: pb.Action_ACTION_DENY, Shell: true},
	}
	ids := [][]byte{laptop, pc}
	d := Exec(rules, ids, [][]string{{"lark-cli", "msg", "send", "--to", "ops"}})
	if d.Status != pb.Status_OK || d.Matched[0].Argv[0] != "/opt/homebrew/bin/lark-cli" || d.Stdin {
		t.Fatalf("lark-cli msg: %+v", d)
	}
	if d := Exec(rules, ids, [][]string{{"/tmp/evil/lark-cli", "msg", "send"}}); d.Status != pb.Status_OK || d.Matched[0].Argv[0] != "/opt/homebrew/bin/lark-cli" {
		t.Fatalf("basename match must still execute the rule's program: %+v", d)
	}
	if d := Exec(rules, ids, [][]string{{"lark-cli", "--json", "msg"}}); d.Status != pb.Status_POLICY_DENIED {
		t.Fatalf("reordered flags must not match the prefix: %+v", d)
	}
	if d := Exec(rules, ids, [][]string{{"lark-cli", "doc", "get"}}); !d.Stdin {
		t.Fatalf("stdin flag not propagated: %+v", d)
	}
	if d := Exec(rules, ids, [][]string{{"git", "status"}, {"rm", "-rf", "/"}}); d.Status != pb.Status_POLICY_DENIED {
		t.Fatalf("one denied command in a pipeline must deny the whole request: %+v", d)
	}
	if d := Exec(rules, [][]byte{other}, [][]string{{"git", "status"}}); d.Status != pb.Status_POLICY_DENIED {
		t.Fatalf("unknown requester allowed: %+v", d)
	}
}

func TestExecShell(t *testing.T) {
	rules := []*pb.ExecRule{
		{PublicKey: laptop, Action: pb.Action_ACTION_ALLOW, Shell: true},
	}
	if !ShellAllowed(rules, [][]byte{laptop}) {
		t.Fatal("shell allow ignored")
	}
	rules = append(rules, &pb.ExecRule{Action: pb.Action_ACTION_DENY, Shell: true})
	if ShellAllowed(rules, [][]byte{laptop}) {
		t.Fatal("shell deny brake ignored")
	}
}

func TestServiceAndPublic(t *testing.T) {
	rules := []*pb.ServiceRule{
		{PublicKey: laptop, Action: pb.Action_ACTION_ALLOW, Name: "nas"},
		{Action: pb.Action_ACTION_ALLOW, Name: "grafana"},
	}
	if Service(rules, [][]byte{laptop}, "nas").Status != pb.Status_OK {
		t.Fatal("laptop denied nas")
	}
	if Service(rules, [][]byte{other}, "nas").Status == pb.Status_OK {
		t.Fatal("other allowed nas")
	}
	if Service(rules, nil, "grafana").Status != pb.Status_OK {
		t.Fatal("anonymous denied a * service")
	}
	if Service(rules, nil, "nas").Status == pb.Status_OK {
		t.Fatal("anonymous allowed a member-only service")
	}
}

func TestPrecheckExecIsWhoOnly(t *testing.T) {
	rules := []*pb.ExecRule{{PublicKey: pc, Action: pb.Action_ACTION_ALLOW, Argv: []string{"lark-cli", "msg"}}}
	if PrecheckExec(rules, [][]byte{laptop, pc}).Status != pb.Status_OK {
		t.Fatal("precheck should allow a requester named by any allow rule")
	}
	if PrecheckExec(rules, [][]byte{other}).Status == pb.Status_OK {
		t.Fatal("precheck allowed an unknown requester")
	}
	rules = append(rules, &pb.ExecRule{PublicKey: laptop, Action: pb.Action_ACTION_DENY})
	if PrecheckExec(rules, [][]byte{laptop, pc}).Status == pb.Status_OK {
		t.Fatal("blanket deny ignored by precheck")
	}
}

func TestKnowsAndMerge(t *testing.T) {
	p := &pb.Policy{Egress: []*pb.EgressRule{{PublicKey: pc}}, Exec: []*pb.ExecRule{{Action: pb.Action_ACTION_DENY, Shell: true}}}
	k := Keys(p)
	if !k.Has(pc) || k.Has(laptop) || !k.Any {
		t.Fatalf("Keys = %+v", k)
	}
	server := &pb.Policy{Exec: []*pb.ExecRule{{PublicKey: laptop, Action: pb.Action_ACTION_ALLOW, Argv: []string{"git"}}}}
	local := &pb.Policy{Exec: []*pb.ExecRule{{PublicKey: laptop, Action: pb.Action_ACTION_ALLOW, Argv: []string{"rm"}}, {Action: pb.Action_ACTION_DENY, Argv: []string{"git", "push"}}}}
	m := Effective(pb.PolicySource_POLICY_SOURCE_SERVER, local, server)
	if len(m.Exec) != 2 || m.Exec[1].Action != pb.Action_ACTION_DENY {
		t.Fatalf("server mode must keep server rules plus local denies only: %v", m.Exec)
	}
	if Effective(pb.PolicySource_POLICY_SOURCE_LOCAL, local, server) != local {
		t.Fatal("local mode must use the local policy")
	}
}
