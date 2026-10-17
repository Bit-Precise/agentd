package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bit-precise/agentd/control/types"
)

type browserSession struct {
	UserID, CSRF, ResourceID, Host string
	ExpiresAt                      time.Time
}
type loginCode struct {
	UserID, ResourceID, Host, State, ReturnTo string
	ExpiresAt                                 time.Time
	IdentityExpiresAt                         time.Time
}
type browserAuth struct {
	mu       sync.Mutex
	sessions map[string]browserSession
	codes    map[string]loginCode
}

func newBrowserAuth() *browserAuth {
	return &browserAuth{sessions: map[string]browserSession{}, codes: map[string]loginCode{}}
}
func randomSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func secretHash(v string) string { sum := sha256.Sum256([]byte(v)); return hex.EncodeToString(sum[:]) }
func bearerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}
func (a *App) cookieName(purpose string) string {
	if a.Config.DevelopmentHTTP {
		return "agents-dev-" + purpose
	}
	return "__Host-agents-" + purpose
}
func (a *App) setCookie(w http.ResponseWriter, purpose, value string, expiry time.Time) {
	http.SetCookie(w, &http.Cookie{Name: a.cookieName(purpose), Value: value, Path: "/", HttpOnly: true, Secure: !a.Config.DevelopmentHTTP, SameSite: http.SameSiteLaxMode, Expires: expiry})
}
func (a *App) readCookie(r *http.Request, purpose string) (string, bool) {
	var value string
	n := 0
	for _, c := range r.Cookies() {
		if c.Name == a.cookieName(purpose) {
			value = c.Value
			n++
		}
	}
	return value, n == 1 && value != ""
}
func (a *App) newSession(w http.ResponseWriter, user, resource, host string, expiry time.Time) (browserSession, error) {
	token := randomSecret()
	s := browserSession{UserID: user, CSRF: randomSecret(), ResourceID: resource, Host: host, ExpiresAt: expiry}
	a.auth.mu.Lock()
	a.pruneAuth()
	count := 0
	for _, existing := range a.auth.sessions {
		if existing.UserID == user {
			count++
		}
	}
	if len(a.auth.sessions) >= 16384 || count >= 256 {
		a.auth.mu.Unlock()
		return browserSession{}, errors.New("browser session capacity reached")
	}
	a.auth.sessions[secretHash(token)] = s
	a.auth.mu.Unlock()
	purpose := "session"
	if resource != "" {
		purpose = "service"
	}
	a.setCookie(w, purpose, token, expiry)
	return s, nil
}
func (a *App) pruneAuth() {
	now := time.Now()
	for key, s := range a.auth.sessions {
		if !s.ExpiresAt.After(now) {
			delete(a.auth.sessions, key)
		}
	}
	for key, c := range a.auth.codes {
		if !c.ExpiresAt.After(now) {
			delete(a.auth.codes, key)
		}
	}
}
func (a *App) session(r *http.Request, purpose string) (browserSession, bool) {
	token, ok := a.readCookie(r, purpose)
	if !ok {
		return browserSession{}, false
	}
	a.auth.mu.Lock()
	defer a.auth.mu.Unlock()
	s, ok := a.auth.sessions[secretHash(token)]
	return s, ok && s.ExpiresAt.After(time.Now()) && s.Host == authorityKey(r.Host, a.publicScheme())
}

func (a *App) actor(r *http.Request, mutating bool) (types.User, browserSession, error) {
	if token, ok := bearerToken(r); ok {
		identity, err := a.State.Identity(token)
		if err != nil || identity.Kind != "user" {
			return types.User{}, browserSession{}, errors.New("authentication required")
		}
		user, err := a.State.CheckUser(identity.UserID)
		return user, browserSession{UserID: identity.UserID, ExpiresAt: identity.ExpiresAt}, err
	}
	s, ok := a.session(r, "session")
	if !ok || s.ResourceID != "" {
		return types.User{}, s, errors.New("authentication required")
	}
	if mutating {
		origin := r.Header.Get("Origin")
		if origin == "" || !a.validOrigin(origin) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
			return types.User{}, s, errors.New("CSRF validation failed")
		}
	}
	user, err := a.State.CheckUser(s.UserID)
	return user, s, err
}
func (a *App) validOrigin(origin string) bool {
	u, err := url.Parse(origin)
	server, _ := url.Parse(a.Config.ServerURL)
	return err == nil && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && (u.Path == "" || u.Path == "/") && u.Scheme == server.Scheme && sameAuthority(u.Host, server)
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !a.validOrigin(origin) {
		apiError(w, http.StatusForbidden, "origin", "origin rejected")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &body) {
		return
	}
	identity, err := a.State.Identity(body.Token)
	if err != nil || identity.Kind != "user" {
		apiError(w, 401, "unauthorized", "invalid user token")
		return
	}
	user, err := a.State.CheckUser(identity.UserID)
	if err != nil {
		respond(w, nil, err, 200)
		return
	}
	expiry := time.Now().Add(8 * time.Hour)
	if !identity.ExpiresAt.IsZero() && identity.ExpiresAt.Before(expiry) {
		expiry = identity.ExpiresAt
	}
	s, err := a.newSession(w, user.ID, "", authorityKey(r.Host, a.publicScheme()), expiry)
	if err != nil {
		apiError(w, 429, "capacity", "browser session limit reached")
		return
	}
	writeJSON(w, 200, map[string]any{"user": user, "csrfToken": s.CSRF})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if _, _, err := a.actor(r, true); err != nil {
		apiError(w, 403, "forbidden", "authentication or CSRF rejected")
		return
	}
	if token, ok := a.readCookie(r, "session"); ok {
		a.auth.mu.Lock()
		delete(a.auth.sessions, secretHash(token))
		a.auth.mu.Unlock()
	}
	a.setCookie(w, "session", "", time.Unix(1, 0))
	w.WriteHeader(http.StatusNoContent)
}

// authorizeService issues a short-lived, one-use code bound to a known service
// origin and browser state. The console's login cookie never leaves its host.
func (a *App) authorizeService(w http.ResponseWriter, r *http.Request) {
	target, err := url.Parse(r.URL.Query().Get("return_to"))
	state := r.URL.Query().Get("state")
	if err != nil || target.Host == "" || target.User != nil || target.Fragment != "" || len(state) != 64 || target.Scheme != a.publicScheme() {
		apiError(w, 400, "invalid", "invalid service login target")
		return
	}
	user, loginSession, err := a.actor(r, false)
	if err != nil {
		http.Redirect(w, r, "/console/?returnTo="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	decision, err := a.State.ResolveServe(target.Host, user.ID)
	if err != nil {
		respond(w, nil, err, 200)
		return
	}
	serverURL, _ := url.Parse(a.Config.ServerURL)
	if !strings.EqualFold(target.Hostname(), decision.Hostname) || effectivePort(target) != effectivePort(serverURL) {
		apiError(w, 400, "invalid", "service origin mismatch")
		return
	}
	code := randomSecret()
	identityExpiry := loginSession.ExpiresAt
	if identityExpiry.IsZero() {
		identityExpiry = time.Now().Add(time.Hour)
	}
	entry := loginCode{UserID: user.ID, ResourceID: decision.ResourceID, Host: authorityKey(target.Host, target.Scheme), State: state, ReturnTo: target.String(), ExpiresAt: time.Now().Add(time.Minute), IdentityExpiresAt: identityExpiry}
	a.auth.mu.Lock()
	a.pruneAuth()
	count := 0
	for _, existing := range a.auth.codes {
		if existing.UserID == user.ID {
			count++
		}
	}
	if len(a.auth.codes) >= 4096 || count >= 32 {
		a.auth.mu.Unlock()
		apiError(w, 429, "capacity", "too many pending service logins")
		return
	}
	a.auth.codes[secretHash(code)] = entry
	a.auth.mu.Unlock()
	callback := *target
	callback.Path = "/__agents/callback"
	callback.RawPath = ""
	callback.RawQuery = url.Values{"code": {code}, "state": {state}}.Encode()
	http.Redirect(w, r, callback.String(), http.StatusSeeOther)
}
func (a *App) serviceCallback(w http.ResponseWriter, r *http.Request) {
	state, ok := a.readCookie(r, "state")
	if !ok || state != r.URL.Query().Get("state") {
		apiError(w, 403, "forbidden", "login state mismatch")
		return
	}
	key := secretHash(r.URL.Query().Get("code"))
	a.auth.mu.Lock()
	entry, found := a.auth.codes[key]
	if found && entry.Host == authorityKey(r.Host, a.publicScheme()) && entry.State == state && entry.ExpiresAt.After(time.Now()) {
		delete(a.auth.codes, key)
	} else {
		found = false
	}
	a.auth.mu.Unlock()
	if !found {
		apiError(w, 403, "forbidden", "expired or invalid login code")
		return
	}
	decision, err := a.State.ResolveServe(r.Host, entry.UserID)
	if err != nil || decision.ResourceID != entry.ResourceID {
		apiError(w, 403, "forbidden", "service access revoked")
		return
	}
	expiry := time.Now().Add(time.Hour)
	if entry.IdentityExpiresAt.Before(expiry) {
		expiry = entry.IdentityExpiresAt
	}
	if _, err := a.newSession(w, entry.UserID, entry.ResourceID, entry.Host, expiry); err != nil {
		apiError(w, 429, "capacity", "browser session limit reached")
		return
	}
	a.setCookie(w, "state", "", time.Unix(1, 0))
	http.Redirect(w, r, entry.ReturnTo, http.StatusSeeOther)
}
func (a *App) publicScheme() string { u, _ := url.Parse(a.Config.ServerURL); return u.Scheme }

func effectivePort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func authorityKey(host, scheme string) string {
	u, err := url.Parse(scheme + "://" + host)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return strings.ToLower(u.Hostname()) + ":" + effectivePort(u)
}
func sameAuthority(host string, target *url.URL) bool {
	key := authorityKey(host, target.Scheme)
	return key != "" && key == authorityKey(target.Host, target.Scheme)
}

// Direct Bearer streams retain token revocation semantics. Browser sessions are
// separately issued credentials and keep their own expiry/user checks.
func (a *App) watchToken(parent context.Context, token string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	events, unsubscribe := a.State.Subscribe()
	go func() {
		defer unsubscribe()
		for {
			// Subscribe before checking to close the authentication/revocation race.
			if identity, err := a.State.Identity(token); err != nil || identity.Kind != "user" {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case _, ok := <-events:
				if !ok {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}
