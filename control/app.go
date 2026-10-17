// Package control assembles the server in the style of Headscale's hscontrol:
// state coordinates persistence/policy; HTTP and data-plane adapters consume it.
package control

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bit-precise/agentd/control/assets"
	"github.com/bit-precise/agentd/control/state"
	"github.com/bit-precise/agentd/control/types"
	"github.com/bit-precise/agentd/edge"
)

type App struct {
	Config Config
	State  *state.State
	Edge   *edge.Edge
	auth   *browserAuth
	router *http.ServeMux
	assets http.Handler
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(ctx context.Context, cfg Config, adminToken string) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(adminToken) < 24 {
		return nil, errors.New("admin token must contain at least 24 high-entropy characters")
	}
	s, err := state.Open(ctx, cfg.DBOptions(), cfg.BaseDomain())
	if err != nil {
		return nil, err
	}
	if _, err = s.BootstrapAdmin(adminToken); err != nil {
		s.Close()
		return nil, err
	}
	e, err := edge.New(s, edge.Config{AllowLoopbackHTTP: cfg.DevelopmentHTTP})
	if err != nil {
		s.Close()
		return nil, err
	}
	a := &App{Config: cfg, State: s, Edge: e, auth: newBrowserAuth(), router: http.NewServeMux(), assets: assets.Handler()}
	a.routes()
	runtimeCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.wg.Add(1)
	go func() { defer a.wg.Done(); _ = e.Run(runtimeCtx) }()
	return a, nil
}

func (a *App) Close() error {
	a.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = a.Edge.Shutdown(ctx)
	a.wg.Wait()
	return a.State.Close()
}
func (a *App) Handler() http.Handler { return http.HandlerFunc(a.serve) }
func (a *App) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Authorization-dependent responses must never be served from a CDN cache.
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/healthz" {
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	edgeURL, _ := url.Parse(a.Config.EdgeURL)
	controlURL, _ := url.Parse(a.Config.ServerURL)
	if r.URL.Path == "/agent" && sameAuthority(r.Host, edgeURL) {
		a.Edge.Handler().ServeHTTP(w, r)
		return
	}
	if sameAuthority(r.Host, controlURL) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/auth/authorize" {
			a.router.ServeHTTP(w, r)
			return
		}
		a.assets.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/__agents/callback" {
		a.serviceCallback(w, r)
		return
	}
	a.servePublished(w, r)
}

func (a *App) servePublished(w http.ResponseWriter, r *http.Request) {
	userID := ""
	resourceID := ""
	var identityExpiry time.Time
	consumeBearer := false
	platformToken := ""
	if s, ok := a.session(r, "service"); ok {
		if _, err := a.State.CheckUser(s.UserID); err == nil {
			userID = s.UserID
			resourceID = s.ResourceID
			identityExpiry = s.ExpiresAt
		}
	}
	if len(r.Header.Values("Authorization")) > 1 {
		apiError(w, 401, "unauthorized", "ambiguous authorization header")
		return
	}
	if token, ok := bearerToken(r); ok {
		if a.State.KnownToken(token) {
			id, err := a.State.Identity(token)
			if err != nil || id.Kind != "user" || (userID != "" && userID != id.UserID) {
				apiError(w, 401, "unauthorized", "conflicting or invalid platform credential")
				return
			}
			userID = id.UserID
			resourceID = ""
			identityExpiry = id.ExpiresAt
			consumeBearer = true
			platformToken = token
		}
	}
	decision, err := a.State.ResolveServe(r.Host, userID)
	if err != nil {
		if types.KindOf(err) == string(types.KindForbidden) && userID == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.Header.Get("Accept"), "text/html") {
			// Only a recognized, private service starts a browser login exchange.
			nonce := randomSecret()
			a.setCookie(w, "state", nonce, time.Now().Add(5*time.Minute))
			returnTo := a.publicScheme() + "://" + r.Host + r.URL.RequestURI()
			location := strings.TrimSuffix(a.Config.ServerURL, "/") + "/auth/authorize?" + url.Values{"return_to": {returnTo}, "state": {nonce}}.Encode()
			http.Redirect(w, r, location, http.StatusSeeOther)
			return
		}
		respond(w, nil, err, 200)
		return
	}
	if resourceID != "" && resourceID != decision.ResourceID {
		apiError(w, 403, "forbidden", "service session scope mismatch")
		return
	}
	ctx := r.Context()
	if !identityExpiry.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, identityExpiry)
		defer cancel()
	}
	if platformToken != "" {
		var cancel context.CancelFunc
		ctx, cancel = a.watchToken(ctx, platformToken)
		defer cancel()
	}
	request := r.Clone(ctx)
	request.Header = r.Header.Clone()
	if consumeBearer {
		request.Header.Del("Authorization")
	}
	cookies := request.Cookies()
	request.Header.Del("Cookie")
	for _, c := range cookies {
		if !strings.HasPrefix(c.Name, "__Host-agents-") && !strings.HasPrefix(c.Name, "agents-dev-") {
			request.AddCookie(c)
		}
	}
	a.Edge.ServeHTTP(w, request, userID)
}
