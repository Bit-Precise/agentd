package servertest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bit-precise/agentd/config"
)

func TestPlatformBearerNeverLeaksToOriginWithServiceCookie(t *testing.T) {
	h := newHarness(t)
	w, u := h.workspace("workspace", "alice")
	var originCalls atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	defer origin.Close()
	cfg := h.agentConfig(w.Name, "provider")
	cfg.Serve = config.ServeConfig{Enabled: true, Services: []config.ServiceConfig{{Name: "demo", Origin: origin.URL}}}
	enrolled, _ := h.enroll(cfg, w, u, []string{"serve"}, true)
	h.runAgent(cfg, enrolled)
	await(t, func() bool { return h.connected(enrolled.Agent.ID, "provider") })
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request := func(method, path, host, token string, cookies []*http.Cookie, body any, html bool) *http.Response {
		t.Helper()
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		r, err := http.NewRequestWithContext(t.Context(), method, h.base+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			r.Host = host
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", h.base)
		}
		if html {
			r.Header.Set("Accept", "text/html")
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	login := request("POST", "/api/v1/login", "", "", nil, map[string]string{"token": u.Token}, false)
	loginCookies := login.Cookies()
	readResponse(t, login, 200)
	serverURL, _ := url.Parse(h.base)
	host := serviceHost("demo", w.Name) + ":" + serverURL.Port()
	first := request("GET", "/", host, "", nil, nil, true)
	stateCookies := first.Cookies()
	authorizeURL, err := url.Parse(first.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, first, http.StatusSeeOther)
	approved := request("GET", authorizeURL.RequestURI(), "", "", loginCookies, nil, false)
	callbackURL, err := url.Parse(approved.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, approved, http.StatusSeeOther)
	callback := request("GET", callbackURL.RequestURI(), host, "", stateCookies, nil, false)
	serviceCookies := callback.Cookies()
	readResponse(t, callback, http.StatusSeeOther)
	var disabled userCredential
	h.api("POST", "/api/v1/users", adminToken, map[string]any{"name": "disabled", "admin": false}, &disabled, 201)
	h.api("DELETE", "/api/v1/users/"+disabled.User.ID, adminToken, nil, nil, 200)
	for _, platformToken := range []string{enrolled.Credentials.ControlToken, enrolled.Credentials.ProviderToken, disabled.Token} {
		response := request("GET", "/", host, platformToken, serviceCookies, nil, false)
		readResponse(t, response, 401)
	}
	if originCalls.Load() != 0 {
		t.Fatal("rejected platform token reached tenant origin")
	}
	response := request("GET", "/", host, u.Token, serviceCookies, nil, false)
	if body := readResponse(t, response, 200); body != "" {
		t.Fatalf("valid platform user token leaked: %q", body)
	}
	response = request("GET", "/", host, "tenant-business-token", serviceCookies, nil, false)
	if body := readResponse(t, response, 200); body != "Bearer tenant-business-token" {
		t.Fatalf("tenant bearer stripped or corrupted: %q", body)
	}
}
