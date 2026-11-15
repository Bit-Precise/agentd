package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCCallbackPersistsUserSubjectInSession(t *testing.T) {
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": provider.URL + "/authorize",
				"token_endpoint":         provider.URL + "/token",
				"userinfo_endpoint":      provider.URL + "/userinfo",
			})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "access", "token_type": "Bearer"})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"sub": "oidc-sub", "email": "Admin@Example.com"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()

	oidc := NewOIDCAuth(OIDCConfig{Enabled: true, Issuer: provider.URL, ClientID: "client", RedirectURL: "http://127.0.0.1/callback"})
	oidc.states["state"] = time.Now().Add(time.Minute)
	oidc.SetIdentityHook(func(_ context.Context, _ OIDCIdentity) (bool, error) { return true, nil })
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=state&code=code", nil)
	response := httptest.NewRecorder()
	identity, err := oidc.Callback(response, req)
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserSubject != "email|admin@example.com" || !identity.InstanceAdmin {
		t.Fatalf("callback identity: %+v", identity)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("session cookie count: %d", len(cookies))
	}
	sessionRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	sessionRequest.AddCookie(cookies[0])
	got, ok := oidc.Session(sessionRequest)
	if !ok || got.UserSubject != "email|admin@example.com" {
		t.Fatalf("session identity: ok=%v identity=%+v", ok, got)
	}
}
