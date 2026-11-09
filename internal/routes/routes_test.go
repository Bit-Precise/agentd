package routes

import (
	"testing"

	"agentd/internal/wire/pb"
)

func sfx(v string) *pb.Match { return &pb.Match{Kind: pb.Match_SUFFIX, Value: v} }
func dom(v string) *pb.Match { return &pb.Match{Kind: pb.Match_DOMAIN, Value: v} }

var table = Table{
	Version: 7,
	Default: "direct",
	Routes: []Route{
		{ID: "r1", From: "group:pc", Protos: []pb.Proto{pb.Proto_PROTO_TLS, pb.Proto_PROTO_SSH}, Domains: []*pb.Match{sfx("ucas.edu.cn"), sfx("ucas.ac.cn")}, To: "dorm"},
		{ID: "r2", From: "workspace", Protos: []pb.Proto{pb.Proto_PROTO_TLS}, Domains: []*pb.Match{dom("login.ucas.edu.cn")}, To: "direct"},
		{ID: "r3", From: "workspace", Domains: []*pb.Match{sfx("internal.example.com")}, To: "office"},
		{ID: "r4", From: "node:laptop", Domains: []*pb.Match{sfx("blocked.example.com")}, To: "reject"},
	},
}

func TestSelectMostSpecificForRequester(t *testing.T) {
	laptop := Requester{Name: "laptop", Groups: []string{"pc"}}
	guest := Requester{Name: "guest"}
	cases := []struct {
		req    Requester
		proto  pb.Proto
		domain string
		want   string
	}{
		{laptop, pb.Proto_PROTO_TLS, "course.ucas.edu.cn", "dorm"},
		{laptop, pb.Proto_PROTO_SSH, "lab.ucas.ac.cn", "dorm"},
		{laptop, pb.Proto_PROTO_TLS, "login.ucas.edu.cn", "direct"},
		{laptop, pb.Proto_PROTO_SSH, "login.ucas.edu.cn", "dorm"}, // r2 is tls-only
		{guest, pb.Proto_PROTO_TLS, "course.ucas.edu.cn", "direct"},
		{guest, pb.Proto_PROTO_SSH, "git.internal.example.com", "office"},
		{laptop, pb.Proto_PROTO_TLS, "x.blocked.example.com", "reject"},
		{guest, pb.Proto_PROTO_TLS, "x.blocked.example.com", "direct"},
		{laptop, pb.Proto_PROTO_TLS, "example.org", "direct"},
	}
	for _, c := range cases {
		if got := table.Select(c.req, c.proto, c.domain); got != c.want {
			t.Errorf("Select(%s, %v, %s) = %q, want %q", c.req.Name, c.proto, c.domain, got, c.want)
		}
	}
}

func TestRenderIngressHidesDestinations(t *testing.T) {
	laptop := Requester{Name: "laptop", Groups: []string{"pc"}}
	ir := table.RenderIngress(laptop)
	if ir.Version != 7 || ir.Default != pb.RouteAction_ROUTE_DIRECT {
		t.Fatalf("header: %v", ir)
	}
	if len(ir.Routes) != 5 { // r1 has two patterns, r2, r3, r4
		t.Fatalf("routes: %v", ir.Routes)
	}
	for _, c := range []struct {
		proto  pb.Proto
		domain string
		want   pb.RouteAction
	}{
		{pb.Proto_PROTO_TLS, "course.ucas.edu.cn", pb.RouteAction_ROUTE_VIA},
		{pb.Proto_PROTO_TLS, "login.ucas.edu.cn", pb.RouteAction_ROUTE_DIRECT},
		{pb.Proto_PROTO_SSH, "login.ucas.edu.cn", pb.RouteAction_ROUTE_VIA},
		{pb.Proto_PROTO_TLS, "a.blocked.example.com", pb.RouteAction_ROUTE_REJECT},
		{pb.Proto_PROTO_TLS, "github.com", pb.RouteAction_ROUTE_DIRECT},
	} {
		if got := EvalIngress(ir, c.proto, c.domain); got != c.want {
			t.Errorf("EvalIngress(%v,%s) = %v, want %v", c.proto, c.domain, got, c.want)
		}
	}
	guest := table.RenderIngress(Requester{Name: "guest"})
	if EvalIngress(guest, pb.Proto_PROTO_TLS, "course.ucas.edu.cn") != pb.RouteAction_ROUTE_DIRECT {
		t.Fatal("guest must not see the pc group's route")
	}
}

func TestTieBreakByOrder(t *testing.T) {
	tb := Table{Default: "reject", Routes: []Route{
		{From: "workspace", Domains: []*pb.Match{sfx("example.com")}, To: "a"},
		{From: "workspace", Domains: []*pb.Match{sfx("example.com")}, To: "b"},
	}}
	if got := tb.Select(Requester{Name: "x"}, pb.Proto_PROTO_TLS, "www.example.com"); got != "a" {
		t.Fatalf("tie should go to the first route, got %q", got)
	}
	if got := tb.Select(Requester{Name: "x"}, pb.Proto_PROTO_TLS, "other.org"); got != "reject" {
		t.Fatalf("default not applied, got %q", got)
	}
}

func TestValidate(t *testing.T) {
	if err := (Route{From: "workspace", Domains: []*pb.Match{sfx("a.com")}, To: "dorm"}).Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Route{
		{From: "everyone", Domains: []*pb.Match{sfx("a.com")}, To: "dorm"},
		{From: "workspace", To: "dorm"},
		{From: "workspace", Domains: []*pb.Match{{Kind: pb.Match_SET, Value: "campus"}}, To: "dorm"},
		{From: "workspace", Domains: []*pb.Match{sfx("a.com")}, To: "Bad_Name"},
	}
	for i, r := range bad {
		if r.Validate() == nil {
			t.Errorf("route %d should be invalid", i)
		}
	}
}
