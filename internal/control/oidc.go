package control

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const oidcSessionCookie = "agentd_oidc_session"

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type OIDCIdentity struct {
	Subject       string
	Email         string
	Name          string
	Picture       string
	Provider      string
	UserSubject   string
	InstanceAdmin bool
}

type oidcSession struct {
	OIDCIdentity
	ExpiresAt time.Time
}

// OIDCAuth implements discovery, authorization-code login, userinfo lookup,
// and the short-lived browser session used by the admin/user HTTP surfaces.
// It intentionally keeps sessions in memory: the chart runs one agentserver
// replica, and a restart simply requires logging in again.
type OIDCAuth struct {
	cfg        OIDCConfig
	client     *http.Client
	onIdentity func(context.Context, OIDCIdentity) (bool, error)

	mu        sync.Mutex
	discovery *oidcDiscovery
	states    map[string]time.Time
	sessions  map[string]oidcSession
}

func NewOIDCAuth(cfg OIDCConfig) *OIDCAuth {
	if !cfg.Enabled {
		return nil
	}
	return &OIDCAuth{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}, states: map[string]time.Time{}, sessions: map[string]oidcSession{}}
}

func (o *OIDCAuth) Enabled() bool { return o != nil && o.cfg.Enabled }
func (o *OIDCAuth) SetIdentityHook(h func(context.Context, OIDCIdentity) (bool, error)) {
	if o != nil {
		o.onIdentity = h
	}
}

func (o *OIDCAuth) discover(ctx context.Context) (oidcDiscovery, error) {
	o.mu.Lock()
	if o.discovery != nil {
		d := *o.discovery
		o.mu.Unlock()
		return d, nil
	}
	o.mu.Unlock()
	endpoint := strings.TrimSuffix(o.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return oidcDiscovery{}, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return oidcDiscovery{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return oidcDiscovery{}, fmt.Errorf("oidc discovery returned HTTP %d", resp.StatusCode)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return d, err
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.UserinfoEndpoint == "" {
		return d, errors.New("oidc discovery lacks authorization, token or userinfo endpoint")
	}
	o.mu.Lock()
	o.discovery = &d
	o.mu.Unlock()
	return d, nil
}

func randomOpaque(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (o *OIDCAuth) Login(w http.ResponseWriter, r *http.Request) error {
	if !o.Enabled() {
		return errors.New("oidc login is disabled")
	}
	d, err := o.discover(r.Context())
	if err != nil {
		return err
	}
	state := randomOpaque(24)
	o.mu.Lock()
	o.states[state] = time.Now().Add(10 * time.Minute)
	o.mu.Unlock()
	cfg := oauth2.Config{ClientID: o.cfg.ClientID, ClientSecret: envValue(o.cfg.ClientSecretEnv), Endpoint: oauth2.Endpoint{AuthURL: d.AuthorizationEndpoint, TokenURL: d.TokenEndpoint}, RedirectURL: o.cfg.RedirectURL, Scopes: o.cfg.Scopes}
	http.Redirect(w, r, cfg.AuthCodeURL(state), http.StatusFound)
	return nil
}

func envValue(name string) string {
	if name == "" {
		return ""
	}
	return strings.TrimSpace(getenv(name))
}

// getenv is a small seam for tests without exposing configuration secrets.
var getenv = func(name string) string { return os.Getenv(name) }

func (o *OIDCAuth) Callback(w http.ResponseWriter, r *http.Request) (OIDCIdentity, error) {
	if !o.Enabled() {
		return OIDCIdentity{}, errors.New("oidc login is disabled")
	}
	state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	if state == "" || code == "" {
		return OIDCIdentity{}, errors.New("missing OIDC state or code")
	}
	o.mu.Lock()
	exp, ok := o.states[state]
	if ok {
		delete(o.states, state)
	}
	o.mu.Unlock()
	if !ok || time.Now().After(exp) {
		return OIDCIdentity{}, errors.New("invalid or expired OIDC state")
	}
	d, err := o.discover(r.Context())
	if err != nil {
		return OIDCIdentity{}, err
	}
	cfg := oauth2.Config{ClientID: o.cfg.ClientID, ClientSecret: envValue(o.cfg.ClientSecretEnv), Endpoint: oauth2.Endpoint{TokenURL: d.TokenEndpoint}, RedirectURL: o.cfg.RedirectURL}
	tok, err := cfg.Exchange(r.Context(), code)
	if err != nil {
		return OIDCIdentity{}, fmt.Errorf("OIDC token exchange: %w", err)
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, d.UserinfoEndpoint, nil)
	if err != nil {
		return OIDCIdentity{}, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := o.client.Do(req)
	if err != nil {
		return OIDCIdentity{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return OIDCIdentity{}, fmt.Errorf("OIDC userinfo returned HTTP %d", resp.StatusCode)
	}
	var claims struct {
		Sub     string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return OIDCIdentity{}, err
	}
	if claims.Sub == "" || claims.Email == "" {
		return OIDCIdentity{}, errors.New("OIDC userinfo must contain sub and email")
	}
	identity := OIDCIdentity{Subject: claims.Sub, Email: strings.ToLower(strings.TrimSpace(claims.Email)), Name: claims.Name, Picture: claims.Picture, Provider: o.cfg.Issuer}
	if o.onIdentity != nil {
		identity.InstanceAdmin, err = o.onIdentity(r.Context(), identity)
		if err != nil {
			return OIDCIdentity{}, err
		}
	}
	session := randomOpaque(32)
	o.mu.Lock()
	o.sessions[session] = oidcSession{OIDCIdentity: identity, ExpiresAt: time.Now().Add(8 * time.Hour)}
	o.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: oidcSessionCookie, Value: session, Path: "/", HttpOnly: true, Secure: r.TLS != nil || strings.HasPrefix(o.cfg.RedirectURL, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: 8 * 60 * 60})
	return identity, nil
}

func (o *OIDCAuth) Session(r *http.Request) (OIDCIdentity, bool) {
	if !o.Enabled() {
		return OIDCIdentity{}, false
	}
	c, err := r.Cookie(oidcSessionCookie)
	if err != nil {
		return OIDCIdentity{}, false
	}
	o.mu.Lock()
	s, ok := o.sessions[c.Value]
	if ok && time.Now().After(s.ExpiresAt) {
		delete(o.sessions, c.Value)
		ok = false
	}
	o.mu.Unlock()
	if !ok {
		return OIDCIdentity{}, false
	}
	return s.OIDCIdentity, true
}
func (o *OIDCAuth) Logout(w http.ResponseWriter, r *http.Request) {
	if o != nil {
		if c, err := r.Cookie(oidcSessionCookie); err == nil {
			o.mu.Lock()
			delete(o.sessions, c.Value)
			o.mu.Unlock()
		}
	}
	http.SetCookie(w, &http.Cookie{Name: oidcSessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
