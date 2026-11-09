package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"agentd/internal/identity"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// The local API is HTTP over the instance's unix socket (design 9.2). Unix
// sockets work on Windows 10 and later too. The socket is 0600 in a 0700
// directory, so only the instance owner can use it.

func (a *Agent) startLocalAPI(ctx context.Context) error {
	path := SocketPath(a.dir)
	if c, err := net.DialTimeout("unix", path, 500*time.Millisecond); err == nil {
		c.Close()
		return fmt.Errorf("another agentd is already running for %s", a.dir)
	}
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("local api: %w", err)
	}
	os.Chmod(path, 0o600)
	a.apiLn = ln
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.Status()) })
	mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.Peers()) })
	mux.HandleFunc("GET /v1/routes", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.Routes()) })
	mux.HandleFunc("GET /v1/executors", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, a.Executors()) })
	mux.HandleFunc("POST /v1/task", a.apiTask)
	mux.HandleFunc("POST /v1/connect", a.apiConnect)
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Reload(); err != nil {
			apiError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, map[string]string{"status": "reloaded"})
	})
	mux.HandleFunc("POST /v1/leave", func(w http.ResponseWriter, r *http.Request) {
		if err := a.Leave(); err != nil {
			apiError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, map[string]string{"status": "left"})
		go func() { time.Sleep(100 * time.Millisecond); a.Stop() }()
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	st := wire.StatusOf(err)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "status": st.String()})
}

// TaskRequest is POST /v1/task.
type TaskRequest struct {
	Executor  string          `json:"executor"` // name or key
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	CallID    string          `json:"call_id,omitempty"`
}

// TaskResponse mirrors FunctionCallOutput.
type TaskResponse struct {
	OutputText   string  `json:"output_text"`
	Output       string  `json:"output"`
	WallTime     float64 `json:"wall_time_seconds"`
	ExitCode     *int32  `json:"exit_code,omitempty"`
	SessionID    *int64  `json:"session_id,omitempty"`
	IsError      bool    `json:"is_error"`
	ErrorMessage string  `json:"error_message,omitempty"`
}

func (a *Agent) apiTask(w http.ResponseWriter, r *http.Request) {
	var req TaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, err)
		return
	}
	key, _, err := a.ResolveExecutor(req.Executor)
	if err != nil {
		apiError(w, http.StatusNotFound, err)
		return
	}
	if len(req.Arguments) == 0 {
		req.Arguments = json.RawMessage("{}")
	}
	out, err := a.Submit(r.Context(), key, &pb.FunctionCall{CallId: req.CallID, Name: req.Tool, Arguments: string(req.Arguments)})
	if err != nil {
		apiError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, toTaskResponse(out))
}

func toTaskResponse(o *pb.FunctionCallOutput) TaskResponse {
	return TaskResponse{OutputText: o.OutputText, Output: o.Output, WallTime: o.WallTimeSeconds, ExitCode: o.ExitCode, SessionID: o.SessionId, IsError: o.IsError, ErrorMessage: o.ErrorMessage}
}

func (a *Agent) apiConnect(w http.ResponseWriter, r *http.Request) {
	cfg := a.config()
	host := r.URL.Query().Get("host")
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	if host == "" || err != nil || port < 1 || port > 65535 {
		apiError(w, http.StatusBadRequest, errors.New("host and port are required"))
		return
	}
	if !cfg.Roles.Ingress.Enabled {
		apiError(w, http.StatusBadRequest, errors.New("the ingress role is not enabled on this instance"))
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		apiError(w, http.StatusInternalServerError, errors.New("hijack unsupported"))
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: agentd-connect\r\n\r\n"))
	var c net.Conn = conn
	if buf.Reader.Buffered() > 0 {
		c = &prefixConn{Conn: conn, r: io.MultiReader(buf.Reader, conn)}
	}
	a.handleConn(context.Background(), c, "connect", host, port)
}

// PeerView is one directory entry for `agentd peers`.
type PeerView struct {
	Kind   string   `json:"kind"` // member | group | workspace
	Name   string   `json:"name"`
	Key    string   `json:"key"`
	Roles  []string `json:"roles,omitempty"`
	Online bool     `json:"online,omitempty"`
	Self   bool     `json:"self,omitempty"`
}

// Peers lists the directory: members, groups and the workspace key.
func (a *Agent) Peers() []PeerView {
	cfg := a.config()
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	out := []PeerView{{Kind: "workspace", Name: cfg.Workspace.Domain, Key: cfg.Workspace.PublicKey}}
	var ms []PeerView
	for _, m := range a.state.members {
		p := PeerView{Kind: "member", Name: m.Name, Key: identity.EncodeKey(m.Identity), Online: m.Online, Self: bytes.Equal(m.Identity, a.pub)}
		for _, r := range m.RoleCaps {
			p.Roles = append(p.Roles, roleName(r))
		}
		ms = append(ms, p)
	}
	sortPeers(ms)
	out = append(out, ms...)
	for _, g := range a.state.groups {
		out = append(out, PeerView{Kind: "group", Name: g.Name, Key: identity.EncodeKey(g.Identity)})
	}
	return out
}

func sortPeers(p []PeerView) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].Name < p[j-1].Name; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

// RoutesView is `agentd routes`.
type RoutesView struct {
	Version  uint64          `json:"version"`
	Default  string          `json:"default"`
	Routes   []RouteLineView `json:"routes"`
	Services []ServiceView   `json:"services"`
}

// RouteLineView is one ingress route.
type RouteLineView struct {
	Match  string   `json:"match"`
	Protos []string `json:"protos"`
	Action string   `json:"action"`
}

// ServiceView is one service in the directory.
type ServiceView struct {
	FQDN  string `json:"fqdn"`
	Proto string `json:"proto"`
	Node  string `json:"node"`
	State string `json:"state"`
}

// Routes returns the split-routing table and services.
func (a *Agent) Routes() RoutesView {
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	v := RoutesView{Default: "direct"}
	actName := map[pb.RouteAction]string{pb.RouteAction_ROUTE_DIRECT: "direct", pb.RouteAction_ROUTE_VIA: "via relay", pb.RouteAction_ROUTE_REJECT: "reject"}
	if ir := a.state.routes; ir != nil {
		v.Version, v.Default = ir.Version, actName[ir.Default]
		for _, r := range ir.Routes {
			l := RouteLineView{Action: actName[r.Action]}
			if r.Match != nil {
				kind := "suffix"
				if r.Match.Kind == pb.Match_DOMAIN {
					kind = "domain"
				}
				l.Match = kind + ":" + r.Match.Value
			}
			for _, p := range r.Protos {
				l.Protos = append(l.Protos, protoName(p))
			}
			v.Routes = append(v.Routes, l)
		}
	}
	for _, s := range a.state.services {
		name := ""
		if m := a.state.members[string(s.NodeIdentity)]; m != nil {
			name = m.Name
		}
		v.Services = append(v.Services, ServiceView{FQDN: s.Fqdn, Proto: protoName(s.Proto), Node: name, State: stateName(s.State)})
	}
	return v
}

func protoName(p pb.Proto) string {
	switch p {
	case pb.Proto_PROTO_TLS:
		return "tls"
	case pb.Proto_PROTO_SSH:
		return "ssh"
	case pb.Proto_PROTO_HTTP:
		return "http"
	}
	return "any"
}

func stateName(s pb.ServiceState) string {
	switch s {
	case pb.ServiceState_STATE_READY:
		return "ready"
	case pb.ServiceState_STATE_CERT_PENDING:
		return "cert pending"
	}
	return "registered"
}

// Reload re-reads config.yaml: policies, services and the executor
// description apply at once; listener changes need a restart.
func (a *Agent) Reload() error {
	cfg, err := LoadConfig(a.dir)
	if err != nil {
		return err
	}
	old := a.config()
	if cfg.Workspace.Domain != old.Workspace.Domain || cfg.Workspace.PublicKey != old.Workspace.PublicKey {
		return errors.New("workspace changed; restart agentd")
	}
	a.cfg.Store(cfg)
	if cfg.Roles.Executor.Enabled && a.tasks == nil {
		a.tasks = a.newTaskHandler(cfg)
	}
	if as := a.current(); as != nil {
		_ = a.advertise(as)
	}
	a.log.Info("configuration reloaded")
	return nil
}

// Leave forgets the workspace: config.yaml and state.json go, node.key stays.
func (a *Agent) Leave() error {
	return LeaveDir(a.dir)
}

// LeaveDir removes an instance's workspace files, keeping the key.
func LeaveDir(dir string) error {
	for _, f := range []string{"config.yaml", "state.json"} {
		if err := os.Remove(dir + string(os.PathSeparator) + f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// ------------------------------------------------------------------ client

// LocalClient talks to a running daemon over its socket.
type LocalClient struct {
	path string
	hc   *http.Client
}

// NewLocalClient returns a client for an instance directory.
func NewLocalClient(dir string) *LocalClient {
	path := SocketPath(dir)
	return &LocalClient{path: path, hc: &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}}}}
}

// ErrNotRunning means no daemon listens on the socket.
var ErrNotRunning = errors.New("agentd is not running for this instance (start it with `agentd run`)")

func (c *LocalClient) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://agentd"+path, rd)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ne *net.OpError
		if errors.As(err, &ne) {
			return ErrNotRunning
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var e struct{ Error, Status string }
		json.NewDecoder(resp.Body).Decode(&e)
		if st, ok := pb.Status_value[e.Status]; ok && st != 0 {
			return wire.Errorf(pb.Status(st), "%s", strings.TrimPrefix(e.Error, e.Status+": "))
		}
		return fmt.Errorf("%s", e.Error)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Status returns the daemon status.
func (c *LocalClient) Status(ctx context.Context) (map[string]any, error) {
	var v map[string]any
	return v, c.do(ctx, http.MethodGet, "/v1/status", nil, &v)
}

// Peers lists the directory.
func (c *LocalClient) Peers(ctx context.Context) ([]PeerView, error) {
	var v []PeerView
	return v, c.do(ctx, http.MethodGet, "/v1/peers", nil, &v)
}

// Routes returns the ingress table.
func (c *LocalClient) Routes(ctx context.Context) (RoutesView, error) {
	var v RoutesView
	return v, c.do(ctx, http.MethodGet, "/v1/routes", nil, &v)
}

// Executors lists executors (ToolSource).
func (c *LocalClient) Executors(ctx context.Context) ([]ExecutorTool, error) {
	var v []ExecutorTool
	return v, c.do(ctx, http.MethodGet, "/v1/executors", nil, &v)
}

// Task runs a tool call.
func (c *LocalClient) Task(ctx context.Context, req TaskRequest) (TaskResponse, error) {
	var v TaskResponse
	return v, c.do(ctx, http.MethodPost, "/v1/task", req, &v)
}

// Call implements ToolSource.
func (c *LocalClient) Call(ctx context.Context, executor, tool string, args json.RawMessage) (*pb.FunctionCallOutput, error) {
	r, err := c.Task(ctx, TaskRequest{Executor: executor, Tool: tool, Arguments: args, CallID: NewCallID()})
	if err != nil {
		return nil, err
	}
	return &pb.FunctionCallOutput{OutputText: r.OutputText, Output: r.Output, WallTimeSeconds: r.WallTime, ExitCode: r.ExitCode, SessionId: r.SessionID, IsError: r.IsError, ErrorMessage: r.ErrorMessage}, nil
}

// Reload asks the daemon to reload its configuration.
func (c *LocalClient) Reload(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/reload", nil, nil)
}

// Leave asks the daemon to leave and stop.
func (c *LocalClient) Leave(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/leave", nil, nil)
}

// Connect opens a byte stream to host:port through the daemon's ingress.
func (c *LocalClient) Connect(ctx context.Context, host string, port int) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		return nil, ErrNotRunning
	}
	fmt.Fprintf(conn, "POST /v1/connect?host=%s&port=%d HTTP/1.1\r\nHost: agentd\r\nConnection: Upgrade\r\nUpgrade: agentd-connect\r\nContent-Length: 0\r\n\r\n", host, port)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		var e struct{ Error string }
		json.NewDecoder(resp.Body).Decode(&e)
		conn.Close()
		return nil, fmt.Errorf("connect: %s", e.Error)
	}
	if br.Buffered() > 0 {
		return &prefixConn{Conn: conn, r: io.MultiReader(br, conn)}, nil
	}
	return conn, nil
}
