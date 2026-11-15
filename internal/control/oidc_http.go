package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"agentd/internal/store"
)

func (a *Admin) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if err := a.OIDC.Login(w, r); err != nil {
		writeJSONError(w, http.StatusBadGateway, "OIDC_UNAVAILABLE", err.Error())
	}
}

func (a *Admin) oidcCallback(w http.ResponseWriter, r *http.Request) {
	identity, err := a.OIDC.Callback(w, r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "OIDC_LOGIN_FAILED", err.Error())
		return
	}
	// Callback has already persisted the identity through the hook. Redirect to
	// the embedded console after setting the HttpOnly session cookie.
	_ = identity
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *Admin) oidcLogout(w http.ResponseWriter, r *http.Request) {
	a.OIDC.Logout(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *Admin) oidcMe(w http.ResponseWriter, r *http.Request) {
	identity, ok := a.OIDC.Session(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "OIDC session required")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"email": identity.Email, "subject": identity.Subject, "name": identity.Name, "picture": identity.Picture, "instance_admin": identity.InstanceAdmin})
}

func (a *Admin) oidcIdentityHook(ctx context.Context, identity OIDCIdentity) (bool, error) {
	identity.UserSubject = "email|" + strings.ToLower(strings.TrimSpace(identity.Email))
	admin := false
	if a.Config != nil {
		for _, email := range a.Config.OIDC.InstanceAdminEmails {
			if strings.EqualFold(strings.TrimSpace(email), identity.Email) {
				admin = true
				break
			}
		}
	}
	u := store.User{Subject: identity.UserSubject, Provider: identity.Provider, Email: identity.Email, Name: identity.Name, Picture: identity.Picture, Status: "active", InstanceAdmin: admin}
	if err := a.C.st.UpsertUser(ctx, u); err != nil {
		return false, err
	}
	if err := a.C.st.SetUserInstanceAdmin(ctx, identity.UserSubject, admin); err != nil {
		return false, err
	}
	if err := a.C.st.AddUserIdentity(ctx, store.UserIdentity{UserSubject: identity.UserSubject, ProviderID: identity.Provider, Subject: identity.Subject, Status: "active"}); err != nil {
		return false, err
	}
	return admin, nil
}
