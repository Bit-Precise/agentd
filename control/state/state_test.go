package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/control/db"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/policy"
)

type fixture struct {
	s           *State
	path        string
	admin, user types.User
	userToken   string
	workspace   types.Workspace
}

func setup(t *testing.T) fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.db")
	s, err := Open(t.Context(), db.Options{DSN: path}, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	admin, err := s.BootstrapAdmin("bootstrap-token-for-state-tests")
	if err != nil {
		t.Fatal(err)
	}
	u, token, err := s.CreateUser(admin.ID, "alice", false)
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.CreateWorkspace(admin.ID, "w1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetMembership(admin.ID, w.ID, u.ID, "developer"); err != nil {
		t.Fatal(err)
	}
	return fixture{s, path, admin, u, token, w}
}
func rule(domain string) policy.Rule {
	return policy.Rule{Domain: policy.Domain{Exact: domain}, Ports: []int{443}, Protocol: "tls"}
}
func desired() config.Config {
	return config.Config{APIVersion: "agents/v1alpha1", Kind: "AgentConfig", Instance: "https://instance.test", Workspace: "w1", Agent: config.AgentConfig{Name: "provider", StateDir: "./state"}, Transport: config.TransportConfig{Type: "xhttp", Mode: "packet-up", Endpoint: "https://connect.instance.test/agent"}, Ingress: config.IngressConfig{Enabled: true, HTTP: config.ListenerConfig{Enabled: true, Listen: "127.0.0.1:8088"}, Routes: []policy.Rule{rule("oa.test")}, OnUnmatched: "reject"}, Serve: config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: "http://127.0.0.1:8080"}}}, Egress: config.EgressConfig{Enabled: true, Allow: []policy.Rule{rule("oa.test"), rule("blocked.test")}, Deny: []policy.Rule{{Domain: policy.Domain{Suffix: "blocked.test"}, Protocol: "tls"}}}}
}
func (f fixture) enroll(t *testing.T, automatic bool) types.EnrollResponse {
	t.Helper()
	_, key, err := f.s.CreateEnrollmentKey(f.admin.ID, types.EnrollmentKey{WorkspaceID: f.workspace.ID, UserID: f.user.ID, Roles: []string{"ingress", "serve", "egress"}, AutoApprove: automatic, MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	out, err := f.s.Enroll(types.EnrollRequest{EnrollmentKey: key, Config: desired()})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func requireKind(t *testing.T, err error, want types.ErrorKind) {
	t.Helper()
	if err == nil || types.KindOf(err) != string(want) {
		t.Fatalf("error=%v kind=%s want=%s", err, types.KindOf(err), want)
	}
}

func TestSQLiteRestartPreservesTokenHashesAndApprovals(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	first, err := f.s.ResolveServe("demo.w1.instance.test", f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(t.Context(), db.Options{DSN: f.path}, "instance.test")
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	for _, token := range []string{f.userToken, enrolled.Credentials.ControlToken, enrolled.Credentials.ProviderToken, enrolled.Credentials.AccessToken} {
		if _, err := again.Identity(token); err != nil {
			t.Fatalf("registered token lost after restart: %v", err)
		}
	}
	second, err := again.ResolveServe("DEMO.w1.instance.test.:443", f.user.ID)
	if err != nil || second.AgentID != first.AgentID || second.Revision != first.Revision {
		t.Fatalf("persisted decision changed: %+v %v", second, err)
	}
	refreshed, err := again.GetAgentCredentials(enrolled.Credentials.ControlToken)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.ProviderToken != "" || refreshed.AccessToken != "" || refreshed.AgentID != enrolled.Agent.ID {
		t.Fatal("refresh recovered secret tokens or lost identity")
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.userToken, enrolled.Credentials.ControlToken, enrolled.Credentials.ProviderToken, "bootstrap-token-for-state-tests"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("plaintext token persisted to SQLite")
		}
	}
}

func TestPendingProviderButAccessAllowedAndApprovalPublishes(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, false)
	if enrolled.Agent.Status != "pending" || len(enrolled.Credentials.Approval.Services) != 0 || enrolled.Credentials.Approval.Revision == 0 || !enrolled.Credentials.Approval.ExpiresAt.After(time.Now()) {
		t.Fatal("pending enrollment returned usable provider approval")
	}
	if _, err := f.s.Identity(enrolled.Credentials.AccessToken); err != nil {
		t.Fatalf("approved ingress role should work while provider is pending: %v", err)
	}
	_, err := f.s.Identity(enrolled.Credentials.ProviderToken)
	requireKind(t, err, types.KindForbidden)
	approved, err := f.s.ApproveAgent(f.admin.ID, enrolled.Agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != "active" || approved.Approval.Revision <= enrolled.Agent.Approval.Revision {
		t.Fatal("approval did not advance revision")
	}
	if _, err := f.s.ResolveServe("demo.w1.instance.test", f.user.ID); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ResolveEgress("w1", f.user.ID, "oa.test", 443)
	requireKind(t, err, types.KindForbidden)
}

func TestEnrollmentKeyConsumedExactlyOnceConcurrently(t *testing.T) {
	f := setup(t)
	key, plain, err := f.s.CreateEnrollmentKey(f.admin.ID, types.EnrollmentKey{WorkspaceID: f.workspace.ID, UserID: f.user.ID, Roles: []string{"ingress"}, MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cfg := desired()
			cfg.Agent.Name = fmt.Sprintf("access%d", i)
			cfg.Serve.Enabled = false
			cfg.Egress.Enabled = false
			if _, err := f.s.Enroll(types.EnrollRequest{EnrollmentKey: plain, Config: cfg}); err == nil {
				success.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("single-use key admitted %d agents", success.Load())
	}
	snap, err := f.s.SnapshotForUser(f.admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Agents) != 1 {
		t.Fatal("failed enrollment left partial agents")
	}
	for _, k := range snap.EnrollmentKeys {
		if k.ID == key.ID && k.Uses != 1 {
			t.Fatal("key usage not committed atomically")
		}
	}
}

func TestServiceGrantUnionExpirySharingAndAdminNoBypass(t *testing.T) {
	f := setup(t)
	f.enroll(t, true)
	otherAdmin, _, err := f.s.CreateUser(f.admin.ID, "operator", true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ResolveServe("demo.w1.instance.test", otherAdmin.ID)
	requireKind(t, err, types.KindForbidden)
	bob, _, err := f.s.CreateUser(f.admin.ID, "bob", false)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := f.s.SnapshotForUser(f.admin.ID)
	svc := snap.Services[0]
	direct, err := f.s.CreateGrant(f.admin.ID, types.Grant{WorkspaceID: f.workspace.ID, ResourceType: "service", ResourceID: svc.ID, SubjectType: "user", SubjectID: bob.ID, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.ResolveServe(svc.Hostname, bob.ID); err != nil {
		t.Fatalf("explicit nonmember share denied: %v", err)
	}
	anonymous, err := f.s.CreateGrant(f.admin.ID, types.Grant{WorkspaceID: f.workspace.ID, ResourceType: "service", ResourceID: svc.ID, SubjectType: "anonymous", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ResolveServe(svc.Hostname, ""); err != nil {
		t.Fatal(err)
	}
	if err = f.s.RevokeGrant(f.admin.ID, anonymous.ID); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ResolveServe(svc.Hostname, "")
	requireKind(t, err, types.KindForbidden)
	if _, err = f.s.ResolveServe(svc.Hostname, bob.ID); err != nil {
		t.Fatal("revoking anonymous incorrectly removed explicit user grant")
	}
	if err = f.s.RevokeGrant(f.admin.ID, direct.ID); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ResolveServe(svc.Hostname, bob.ID)
	requireKind(t, err, types.KindForbidden)
	if _, err = f.s.ResolveServe(svc.Hostname, f.user.ID); err != nil {
		t.Fatal("independent workspace grant was removed")
	}
	if err = f.s.mutate(func(snapshot *types.Snapshot) error {
		for i := range snapshot.Grants {
			snapshot.Grants[i].ExpiresAt = time.Now().Add(-time.Second)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ResolveServe(svc.Hostname, f.user.ID)
	requireKind(t, err, types.KindForbidden)
}

func TestEgressRequiresRouteGrantAndBothCapabilitySides(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	route, err := f.s.CreateEgressRoute(f.admin.ID, types.EgressRoute{WorkspaceID: f.workspace.ID, AgentID: enrolled.Agent.ID, Name: "office", Rule: rule("oa.test"), Priority: 10})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ResolveEgress("w1", f.user.ID, "oa.test", 443)
	requireKind(t, err, types.KindForbidden)
	grant, err := f.s.CreateGrant(f.admin.ID, types.Grant{WorkspaceID: f.workspace.ID, ResourceType: "egress", ResourceID: route.ID, SubjectType: "user", SubjectID: f.user.ID, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := f.s.ResolveEgress("w1", f.user.ID, "OA.TEST.", 443)
	if err != nil || decision.AgentID != enrolled.Agent.ID || decision.Destination.Host != "oa.test" {
		t.Fatalf("wrong routed destination: %+v %v", decision, err)
	}
	cfg := desired()
	cfg.Egress.Allow = nil
	if _, err = f.s.UpdateAgent(enrolled.Credentials.ControlToken, cfg); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ResolveEgress("w1", f.user.ID, "oa.test", 443)
	requireKind(t, err, types.KindForbidden)
	if _, err = f.s.ResolveServe("demo.w1.instance.test", f.user.ID); err != nil {
		t.Fatal("egress withdrawal interrupted serve")
	}
	if err = f.s.RevokeGrant(f.admin.ID, grant.ID); err != nil {
		t.Fatal(err)
	}
}

func TestTenantScopeAndGuestRoleCannotBeBypassed(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	w2, err := f.s.CreateWorkspace(f.admin.ID, "w2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.CreateEgressRoute(f.admin.ID, types.EgressRoute{WorkspaceID: w2.ID, AgentID: enrolled.Agent.ID, Name: "foreign", Rule: rule("oa.test")})
	requireKind(t, err, types.KindForbidden)
	snap, _ := f.s.SnapshotForUser(f.admin.ID)
	_, err = f.s.CreateGrant(f.admin.ID, types.Grant{WorkspaceID: w2.ID, ResourceType: "service", ResourceID: snap.Services[0].ID, SubjectType: "anonymous", ExpiresAt: time.Now().Add(time.Hour)})
	requireKind(t, err, types.KindForbidden)
	guest, _, err := f.s.CreateUser(f.admin.ID, "guest", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.SetMembership(f.admin.ID, w2.ID, guest.ID, "guest"); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.s.CreateEnrollmentKey(guest.ID, types.EnrollmentKey{WorkspaceID: w2.ID, Roles: []string{"serve"}})
	requireKind(t, err, types.KindForbidden)
	_, _, err = f.s.CreateEnrollmentKey(f.user.ID, types.EnrollmentKey{WorkspaceID: f.workspace.ID, Roles: []string{"serve"}, AutoApprove: true})
	requireKind(t, err, types.KindForbidden)
	cfg := desired()
	cfg.Workspace = "w2"
	_, err = f.s.UpdateAgent(enrolled.Credentials.ControlToken, cfg)
	requireKind(t, err, types.KindForbidden)
}

func TestRevokeAndMembershipRemovalPublishAndDoNotResurrect(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	updates, cancel := f.s.Subscribe()
	defer cancel()
	if err := f.s.RemoveMembership(f.admin.ID, f.workspace.ID, f.user.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("committed revocation was not published")
	}
	_, err := f.s.Identity(enrolled.Credentials.ProviderToken)
	requireKind(t, err, types.KindUnauthorized)
	if _, err = f.s.SetMembership(f.admin.ID, f.workspace.ID, f.user.ID, "developer"); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Identity(enrolled.Credentials.ProviderToken)
	requireKind(t, err, types.KindUnauthorized)
	if _, err = f.s.GetAgentCredentials(enrolled.Credentials.ControlToken); err == nil {
		t.Fatal("removed registration credentials revived")
	}
	if err = f.s.RemoveMembership(f.admin.ID, f.workspace.ID, f.admin.ID); err == nil {
		t.Fatal("last workspace owner removed")
	}
}

func TestSnapshotAndMutationReturnsCannotModifyPublishedState(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	enrolled.Agent.Desired.Serve.Services[0].Origin = "http://127.0.0.1:9999"
	enrolled.Agent.Approval.Services["demo"] = "http://127.0.0.1:9999"
	snap, err := f.s.SnapshotForUser(f.admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Tokens != nil {
		t.Fatal("token hashes escaped snapshot boundary")
	}
	data, _ := json.Marshal(snap)
	if strings.Contains(string(data), f.userToken) || strings.Contains(string(data), "Hash") {
		t.Fatal("snapshot exposed credentials")
	}
	snap.Agents[0].Desired.Egress.Allow[0].Ports[0] = 1
	a, err := f.s.Agent(enrolled.Agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Approval.Services["demo"] != "http://127.0.0.1:8080" || a.Desired.Egress.Allow[0].Ports[0] != 443 {
		t.Fatal("caller changed published immutable snapshot")
	}
}

func TestLocalExpansionPendingAndGrantNotResetByApproval(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	snap, _ := f.s.SnapshotForUser(f.admin.ID)
	for _, g := range snap.Grants {
		if err := f.s.RevokeGrant(f.admin.ID, g.ID); err != nil {
			t.Fatal(err)
		}
	}
	cfg := desired()
	cfg.Egress.Allow = append(cfg.Egress.Allow, rule("new.test"))
	changed, err := f.s.UpdateAgent(enrolled.Credentials.ControlToken, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !changed.PendingApproval || policy.Allowed(changed.Approval.Egress, changed.Approval.Deny, "new.test", 443, "tls") {
		t.Fatal("local expansion activated without approval")
	}
	if !policy.Allowed(changed.Approval.Egress, changed.Approval.Deny, "oa.test", 443, "tls") {
		t.Fatal("pending expansion disabled old approved scope")
	}
	if _, err = f.s.ApproveAgent(f.admin.ID, enrolled.Agent.ID); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ResolveServe("demo.w1.instance.test", f.user.ID)
	requireKind(t, err, types.KindForbidden)
}

func TestEgressPriorityDoesNotFallbackAndProviderDenyWins(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	exact, err := f.s.CreateEgressRoute(f.admin.ID, types.EgressRoute{WorkspaceID: f.workspace.ID, AgentID: enrolled.Agent.ID, Name: "restricted", Priority: 0, Rule: rule("oa.test")})
	if err != nil {
		t.Fatal(err)
	}
	broad, err := f.s.CreateEgressRoute(f.admin.ID, types.EgressRoute{WorkspaceID: f.workspace.ID, AgentID: enrolled.Agent.ID, Name: "broad", Priority: 100, Rule: policy.Rule{Domain: policy.Domain{Suffix: "test"}, Ports: []int{443}, Protocol: "tls"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.CreateGrant(f.admin.ID, types.Grant{WorkspaceID: f.workspace.ID, ResourceType: "egress", ResourceID: broad.ID, SubjectType: "workspace", SubjectID: f.workspace.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.ResolveEgress("w1", f.user.ID, "oa.test", 443)
	requireKind(t, err, types.KindForbidden)
	if _, err = f.s.SetEgressRouteEnabled(f.admin.ID, exact.ID, false); err != nil {
		t.Fatal(err)
	}
	decision, err := f.s.ResolveEgress("w1", f.user.ID, "oa.test", 443)
	if err != nil || decision.ResourceID != broad.ID {
		t.Fatalf("broad route not selected after exact disabled: %+v %v", decision, err)
	}
	_, err = f.s.ResolveEgress("w1", f.user.ID, "blocked.test", 443)
	requireKind(t, err, types.KindForbidden)
}

func TestRejectedEnrollmentRollsBackReservationsAndKeyUse(t *testing.T) {
	f := setup(t)
	f.enroll(t, true)
	key, plain, err := f.s.CreateEnrollmentKey(f.admin.ID, types.EnrollmentKey{WorkspaceID: f.workspace.ID, UserID: f.user.ID, Roles: []string{"serve"}, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	cfg := desired()
	cfg.Ingress.Enabled = false
	cfg.Egress.Enabled = false
	cfg.Agent.Name = "second"
	cfg.Serve.Services = append([]config.ServiceConfig{{Name: "fresh", Origin: "http://127.0.0.1:3000"}}, cfg.Serve.Services...)
	_, err = f.s.Enroll(types.EnrollRequest{EnrollmentKey: plain, Config: cfg})
	requireKind(t, err, types.KindConflict)
	snap, _ := f.s.SnapshotForUser(f.admin.ID)
	for _, k := range snap.EnrollmentKeys {
		if k.ID == key.ID && k.Uses != 0 {
			t.Fatal("failed enrollment consumed its key")
		}
	}
	for _, v := range snap.Services {
		if v.Name == "fresh" {
			t.Fatal("failed enrollment left a service reservation")
		}
	}
	cfg.Serve.Services = cfg.Serve.Services[:1]
	if _, err = f.s.Enroll(types.EnrollRequest{EnrollmentKey: plain, Config: cfg}); err != nil {
		t.Fatalf("rolled back key or reservation could not be reused: %v", err)
	}
}

func TestExpiredUserTokenAndGuestDowngradeLoseAuthorization(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	if _, err := f.s.SetMembership(f.admin.ID, f.workspace.ID, f.user.ID, "guest"); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.Identity(enrolled.Credentials.ProviderToken)
	requireKind(t, err, types.KindForbidden)
	if _, err = f.s.Identity(enrolled.Credentials.AccessToken); err != nil {
		t.Fatal("guest downgrade unexpectedly removed ingress permission")
	}
	_, err = f.s.ResolveServe("demo.w1.instance.test", f.user.ID)
	requireKind(t, err, types.KindUnavailable)
	if err = f.s.mutate(func(snapshot *types.Snapshot) error {
		for i := range snapshot.Tokens {
			if snapshot.Tokens[i].Hash == hash(f.userToken) {
				snapshot.Tokens[i].ExpiresAt = time.Now().Add(-time.Second)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Identity(f.userToken)
	requireKind(t, err, types.KindExpired)
}

func TestDesiredRetriesAndRepeatedApprovalAreIdempotent(t *testing.T) {
	f := setup(t)
	enrolled := f.enroll(t, true)
	before, _ := f.s.SnapshotForUser(f.admin.ID)
	updates, cancel := f.s.Subscribe()
	defer cancel()
	for i := 0; i < 2; i++ {
		got, err := f.s.UpdateAgent(enrolled.Credentials.ControlToken, desired())
		if err != nil {
			t.Fatal(err)
		}
		if got.PendingApproval {
			t.Fatal("identical desired marked approved agent pending")
		}
	}
	after, _ := f.s.SnapshotForUser(f.admin.ID)
	if after.Revision != before.Revision || len(after.Audit) != len(before.Audit) {
		t.Fatal("identical desired retry changed revision or audit")
	}
	select {
	case <-updates:
		t.Fatal("no-op desired emitted a policy update")
	default:
	}
	cfg := desired()
	cfg.Egress.Allow = append(cfg.Egress.Allow, rule("new.test"))
	changed, err := f.s.UpdateAgent(enrolled.Credentials.ControlToken, cfg)
	if err != nil || !changed.PendingApproval {
		t.Fatalf("new desired not pending: %v", err)
	}
	if _, err = f.s.ApproveAgent(f.admin.ID, enrolled.Agent.ID); err != nil {
		t.Fatal(err)
	}
	before, _ = f.s.SnapshotForUser(f.admin.ID)
	if got, err := f.s.UpdateAgent(enrolled.Credentials.ControlToken, cfg); err != nil || got.PendingApproval {
		t.Fatalf("delayed retry undid approval: %v", err)
	}
	if _, err = f.s.ApproveAgent(f.admin.ID, enrolled.Agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.BootstrapAdmin("bootstrap-token-for-state-tests"); err != nil {
		t.Fatal(err)
	}
	after, _ = f.s.SnapshotForUser(f.admin.ID)
	if after.Revision != before.Revision || len(after.Audit) != len(before.Audit) {
		t.Fatal("idempotent approval/bootstrap/desired retry changed policy")
	}
	if _, err = f.s.UpdateAgent("invalid", cfg); err == nil {
		t.Fatal("idempotency fast path bypassed authentication")
	}
}

func TestEnrollmentPreissuesOnlyPermittedRoleTokens(t *testing.T) {
	f := setup(t)
	_, key, err := f.s.CreateEnrollmentKey(f.admin.ID, types.EnrollmentKey{WorkspaceID: f.workspace.ID, UserID: f.user.ID, Roles: []string{"ingress", "serve"}, AutoApprove: true, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	cfg := desired()
	cfg.Serve.Enabled = false
	cfg.Egress.Enabled = false
	enrolled, err := f.s.Enroll(types.EnrollRequest{EnrollmentKey: key, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.Credentials.ProviderToken == "" || enrolled.Credentials.AccessToken == "" {
		t.Fatal("future permitted role token missing")
	}
	if _, err = f.s.Identity(enrolled.Credentials.ProviderToken); err == nil {
		t.Fatal("disabled provider role authenticated")
	}
	cfg.Serve.Enabled = true
	if _, err = f.s.UpdateAgent(enrolled.Credentials.ControlToken, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ApproveAgent(f.admin.ID, enrolled.Agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Identity(enrolled.Credentials.ProviderToken); err != nil {
		t.Fatal("preissued provider token unusable after explicit approval")
	}
	if !f.s.KnownToken(enrolled.Credentials.AccessToken) {
		t.Fatal("platform token not recognized")
	}
	if err = f.s.RevokeAgent(f.admin.ID, enrolled.Agent.ID); err != nil {
		t.Fatal(err)
	}
	if !f.s.KnownToken(enrolled.Credentials.AccessToken) {
		t.Fatal("revoked platform token forgotten")
	}
}
