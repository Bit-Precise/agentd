package assets

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestConsoleRoutesAndSecurityHeaders(t *testing.T) {
	t.Parallel()
	handler := Handler()
	for _, test := range []struct{ path, contentType, contains string }{
		{"/", "text/html", "agents · 控制台"},
		{"/agents", "text/html", `id="content"`},
		{"/assets/app.js", "text/javascript", "X-CSRF-Token"},
		{"/assets/styles.css", "text/css", ".sidebar"},
	} {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), test.contentType) || !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("unexpected embedded response: %d %q", response.Code, response.Header().Get("Content-Type"))
			}
			csp := response.Header().Get("Content-Security-Policy")
			for _, required := range []string{"script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
				if !strings.Contains(csp, required) {
					t.Errorf("CSP missing %q", required)
				}
			}
			if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
				t.Fatal("unsafe script policy")
			}
			if response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing nosniff")
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("console must not be persistently cached")
			}
		})
	}
}

func TestMissingAssetsAndAPIsDoNotBecomeSPAPages(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"/api/v1/missing", "/assets/missing.js", "/missing.css", "/../go.mod", "/assets/%2e%2e/go.mod"} {
		response := httptest.NewRecorder()
		Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("%s returned %d", target, response.Code)
		}
	}
	response := httptest.NewRecorder()
	Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/agents", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("unexpected mutation accepted by static handler")
	}
}

func TestHeadAndSelfContainedDocument(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(Handler())
	defer server.Close()
	response, err := http.Head(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || len(data) != 0 || response.StatusCode != 200 {
		t.Fatal("HEAD must return headers without a body")
	}
	html, err := files.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?i)\bon[a-z]+\s*=|<style\b|<script[^>]*>\s*[^<\s]`).Match(html) {
		t.Fatal("document contains inline script/style or handlers")
	}
	for _, asset := range []string{"/assets/app.js", "/assets/styles.css"} {
		if !strings.Contains(string(html), asset) {
			t.Errorf("missing local asset %s", asset)
		}
	}
	js, err := files.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, dangerous := range []string{".innerHTML", "insertAdjacentHTML", "localStorage", "sessionStorage", "eval("} {
		if strings.Contains(string(js), dangerous) {
			t.Errorf("unsafe console primitive %s", dangerous)
		}
	}
}
