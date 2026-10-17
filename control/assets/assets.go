// Package assets serves the embedded agents management console.
package assets

import (
	"bytes"
	"embed"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed web/index.html web/app.js web/styles.css
var files embed.FS

const policy = "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

// Handler serves static files and extensionless console navigation. API paths
// never fall back to HTML, so a missing API route remains an explicit error.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", policy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name, mime := "index.html", "text/html; charset=utf-8"
		switch r.URL.Path {
		case "/assets/app.js":
			name, mime = "app.js", "text/javascript; charset=utf-8"
		case "/assets/styles.css":
			name, mime = "styles.css", "text/css; charset=utf-8"
		case "/", "/index.html", "/console", "/console/":
		default:
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/assets/") || path.Ext(r.URL.Path) != "" || path.Clean(r.URL.Path) != r.URL.Path {
				http.NotFound(w, r)
				return
			}
		}
		data, err := files.ReadFile("web/" + name)
		if err != nil {
			http.Error(w, "console unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", mime)
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	})
}
