package agent

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"agentd/internal/session"
	"agentd/internal/stream"
	"agentd/internal/wire/pb"

	"os"
	"path/filepath"
)

// serviceProxy serves edge streams for one HTTP service: each stream is an
// HTTP/1.1 connection, proxied to the plaintext target with the original
// Host preserved (protocol 6.3).
type serviceProxy struct {
	ln  *stream.Listener
	srv *http.Server
}

var (
	proxyMu sync.Mutex
)

func (a *Agent) httpProxy(sv *ServerConfig, target string) *serviceProxy {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if a.proxies == nil {
		a.proxies = map[string]*serviceProxy{}
	}
	key := sv.Name + "|" + target
	if p := a.proxies[key]; p != nil {
		return p
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = target
			pr.Out.Host = pr.In.Host
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				if v := pr.In.Header.Values(h); len(v) > 0 {
					pr.Out.Header[h] = v
				}
			}
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: EgressDialTimeout, KeepAlive: 30 * time.Second}
				return d.DialContext(ctx, "tcp", target)
			},
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			a.log.Debug("service proxy error", "service", sv.Name, "err", err)
			http.Error(w, "service target unreachable", http.StatusBadGateway)
		},
	}
	p := &serviceProxy{ln: stream.NewListener(), srv: &http.Server{Handler: rp, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 5 * time.Minute}}
	go p.srv.Serve(p.ln)
	a.proxies[key] = p
	return p
}

func (p *serviceProxy) serve(st *session.Stream, _ *pb.HttpPeer) {
	if !p.ln.Push(st) {
		st.Reset()
	}
}

// rewriteName changes metadata.name in config.yaml, keeping comments.
func rewriteName(dir, name string) error {
	path := filepath.Join(dir, "config.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "metadata" {
			m := root.Content[i+1]
			for j := 0; j+1 < len(m.Content); j += 2 {
				if m.Content[j].Value == "name" {
					m.Content[j+1].Value = name
				}
			}
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}
