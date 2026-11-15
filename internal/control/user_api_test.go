package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"agentd/internal/adminapi"
	"agentd/internal/userapi"
)

func TestGeneratedUserSurface(t *testing.T) {
	srv, admin := startServer(t)
	ctx := context.Background()
	if response, err := admin.CreateWorkspaceWithResponse(ctx, adminapi.WorkspaceCreate{Name: "home"}); err != nil || response.JSON201 == nil {
		t.Fatalf("create workspace: %v %s", err, response.Body)
	}
	if response, err := admin.UpsertWorkspaceMemberWithResponse(ctx, "home", adminapi.WorkspaceMemberWrite{Subject: "oidc|alice", Role: adminapi.Owner}); err != nil || response.JSON200 == nil {
		t.Fatalf("add workspace member: %v %s", err, response.Body)
	}

	user, err := userapi.NewClientWithResponses("http://"+srv.AdminAddr().String()+"/api/v1", userapi.WithRequestEditorFn(func(ctx context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer oidc|alice")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	workspaces, err := user.ListMyWorkspacesWithResponse(ctx)
	if err != nil || workspaces.StatusCode() != http.StatusOK || workspaces.JSON200 == nil || len(*workspaces.JSON200) != 1 {
		t.Fatalf("list user workspaces: %v %d %s", err, workspaces.StatusCode(), workspaces.Body)
	}
	missing, err := user.RemoveMyWorkspaceMemberWithResponse(ctx, "home", "00000000-0000-4000-8000-000000000000")
	if err != nil || missing.StatusCode() != http.StatusNotFound || missing.JSON404 == nil {
		t.Fatalf("missing member status: %v %d %s", err, missing.StatusCode(), missing.Body)
	}
}

func TestOIDCInstanceAdminCanEnterWorkspaceMode(t *testing.T) {
	srv, admin := startServer(t)
	ctx := context.Background()
	if response, err := admin.CreateWorkspaceWithResponse(ctx, adminapi.WorkspaceCreate{Name: "home"}); err != nil || response.JSON201 == nil {
		t.Fatalf("create workspace: %v %s", err, response.Body)
	}
	if response, err := admin.UpsertWorkspaceMemberWithResponse(ctx, "home", adminapi.WorkspaceMemberWrite{Subject: "email|admin@example.com", Role: adminapi.Owner}); err != nil || response.JSON200 == nil {
		t.Fatalf("add workspace member: %v %s", err, response.Body)
	}
	oidc := NewOIDCAuth(OIDCConfig{Enabled: true})
	oidc.sessions["workspace-mode"] = oidcSession{OIDCIdentity: OIDCIdentity{UserSubject: "email|admin@example.com", InstanceAdmin: true}, ExpiresAt: time.Now().Add(time.Hour)}
	h := (&Admin{C: srv.Coordinator, Config: srv.Config, Domain: srv.Config.Domain, OIDC: oidc}).Handler(testAdminToken, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/"+idFor("workspace", "home")+"/members", nil)
	req.AddCookie(&http.Cookie{Name: oidcSessionCookie, Value: "workspace-mode"})
	response := httptest.NewRecorder()
	h.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("workspace mode status: %d %s", response.Code, response.Body.String())
	}
}
