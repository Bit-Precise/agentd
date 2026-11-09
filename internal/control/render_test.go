package control

import (
	"encoding/json"
	"testing"

	"agentd/internal/wire/pb"
)

func TestRenderStatements(t *testing.T) {
	wsKey := []byte("ws-key-0000000000000000000000000")[:32]
	laptop := []byte("laptop-000000000000000000000000000")[:32]
	pc := []byte("pc-group-0000000000000000000000000")[:32]
	in := RenderInput{
		WorkspaceKey: wsKey,
		Nodes:        map[string][]byte{"laptop": laptop, "dorm": []byte("dorm-0000000000000000000000000000")[:32], "office": []byte("office-00000000000000000000000000")[:32], "homepc": []byte("homepc-00000000000000000000000000")[:32]},
		Groups:       map[string][]byte{"pc": pc},
		Services:     map[string]string{"nas": "homepc", "grafana": "homepc"},
	}
	raw := `[
	 {"subjects":["group:pc"],"allow":[
	   {"egress":"dorm","proto":"tls","domains":[{"kind":"suffix","value":"ucas.edu.cn"}]},
	   {"exec":"office","argv":["lark-cli","msg"]},
	   {"service":"nas"}]},
	 {"subjects":["workspace"],"deny":[{"egress":"dorm","domains":[{"kind":"domain","value":"login.ucas.edu.cn"}]}]},
	 {"subjects":["public"],"allow":[{"service":"grafana"}]},
	 {"subjects":["node:ghost"],"allow":[{"service":"nas"}]}
	]`
	var stmts []Statement
	if err := json.Unmarshal([]byte(raw), &stmts); err != nil {
		t.Fatal(err)
	}
	out := Render(stmts, in)
	dorm := out["dorm"]
	if len(dorm.GetEgress()) != 2 {
		t.Fatalf("dorm egress: %v", dorm.GetEgress())
	}
	if string(dorm.Egress[0].PublicKey) != string(pc) || dorm.Egress[0].Proto != pb.Proto_PROTO_TLS || dorm.Egress[0].Domains[0].Kind != pb.Match_SUFFIX {
		t.Fatalf("first egress rule: %v", dorm.Egress[0])
	}
	if dorm.Egress[1].Action != pb.Action_ACTION_DENY || string(dorm.Egress[1].PublicKey) != string(wsKey) {
		t.Fatalf("deny rule: %v", dorm.Egress[1])
	}
	office := out["office"]
	if len(office.GetExec()) != 1 || office.Exec[0].Argv[1] != "msg" {
		t.Fatalf("office exec: %v", office.GetExec())
	}
	homepc := out["homepc"]
	if len(homepc.GetServices()) != 2 {
		t.Fatalf("homepc services (unknown subject must be skipped): %v", homepc.GetServices())
	}
	if homepc.Services[1].Name != "grafana" || len(homepc.Services[1].PublicKey) != 0 {
		t.Fatalf("public must render as *: %v", homepc.Services[1])
	}
}

func TestValidateStatement(t *testing.T) {
	good := Statement{Subjects: []string{"group:pc"}, Allow: []Target{{Egress: "dorm", Domains: []MatchJSON{{Kind: "suffix", Value: "a.com"}}}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Statement{
		{Allow: []Target{{Service: "nas"}}},
		{Subjects: []string{"everyone"}, Allow: []Target{{Service: "nas"}}},
		{Subjects: []string{"workspace"}, Allow: []Target{{Service: "nas", Exec: "office"}}},
		{Subjects: []string{"workspace"}, Allow: []Target{{Egress: "dorm"}}},
		{Subjects: []string{"workspace"}, Allow: []Target{{Exec: "office"}}},
		{Subjects: []string{"workspace"}, Allow: []Target{{Egress: "dorm", Proto: "udp", Domains: []MatchJSON{{Kind: "suffix", Value: "a.com"}}}}},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("statement %d should be invalid", i)
		}
	}
}
