package servertest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/policy"
)

func TestSameRevisionDisableReconnectAndReenableService(t *testing.T) {
	h := newHarness(t)
	w, u := h.workspace("workspace", "alice")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "service-restored") }))
	defer origin.Close()
	cfg := h.agentConfig(w.Name, "provider")
	cfg.Serve = config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: origin.URL}}}
	cfg.Egress = config.EgressConfig{Enabled: true, Allow: []policy.Rule{tlsRule("example.com")}}
	enrolled, _ := h.enroll(cfg, w, u, []string{"serve", "egress"}, true)
	runtime, _ := h.runAgentInstance(cfg, enrolled)
	await(t, func() bool { return h.connected(enrolled.Agent.ID, "provider") })
	originalRevision := enrolled.Credentials.Approval.Revision
	disabled := *cfg
	disabled.Serve.Enabled = false
	if err := runtime.Reload(&disabled); err != nil {
		t.Fatal(err)
	}
	// A local reduction must not reconnect a shared provider just to update its
	// declaration. Exercise re-enabling after an independent network interruption
	// has re-established the session with the reduced declaration instead.
	h.server.CloseClientConnections()
	await(t, func() bool {
		for _, c := range h.app.Edge.Snapshot().Connections {
			if c.AgentID == enrolled.Agent.ID && c.Role == "provider" && !slices.Contains(c.Services, "demo") {
				return true
			}
		}
		return false
	})
	response, err := h.serveRequest(serviceHost("demo", w.Name), u.Token, "/")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response, 503)
	if err := runtime.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool {
		for _, c := range h.app.Edge.Snapshot().Connections {
			if c.AgentID == enrolled.Agent.ID && c.Role == "provider" && slices.Contains(c.Services, "demo") && c.Revision == originalRevision {
				return true
			}
		}
		return false
	})
	response, err = h.serveRequest(serviceHost("demo", w.Name), u.Token, "/")
	if err != nil {
		t.Fatal(err)
	}
	if body := readResponse(t, response, 200); body != "service-restored" {
		t.Fatal(body)
	}
	agent, err := h.app.State.Agent(enrolled.Agent.ID)
	if err != nil || agent.Approval.Revision != originalRevision {
		t.Fatal("same approved capability unexpectedly required a new approval revision")
	}
}
