package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// ExecutorTool describes an executor for MCP (shared by the daemon and the
// stdio bridge).
type ExecutorTool struct {
	Name        string   `json:"name"`
	Key         string   `json:"key"`
	Description string   `json:"description"`
	Tools       []string `json:"tools"`
	Online      bool     `json:"online"`
}

// ToolSource lists executors and runs calls.
type ToolSource interface {
	Executors(ctx context.Context) ([]ExecutorTool, error)
	Call(ctx context.Context, executor, tool string, args json.RawMessage) (*pb.FunctionCallOutput, error)
}

var toolSchemas = map[string]json.RawMessage{
	"exec_command": json.RawMessage(`{"type":"object","properties":{
"cmd":{"type":"string","description":"Command line to run (no shell features unless the executor allows a shell)"},
"workdir":{"type":"string","description":"Working directory under the executor's root; defaults to the root"},
"yield_time_ms":{"type":"integer","description":"How long to wait for output before returning (250-30000 ms)"},
"max_output_tokens":{"type":"integer","description":"Output budget in tokens"}},"required":["cmd"],"additionalProperties":false}`),
	"write_stdin": json.RawMessage(`{"type":"object","properties":{
"session_id":{"type":"integer","description":"Session id returned by exec_command for a still-running process"},
"chars":{"type":"string","description":"Bytes to write to the process stdin; empty to just poll for output"},
"yield_time_ms":{"type":"integer","description":"How long to wait for output (250-30000 ms)"},
"max_output_tokens":{"type":"integer","description":"Output budget in tokens"}},"required":["session_id"],"additionalProperties":false}`),
}

var toolDescriptions = map[string]string{
	"exec_command": "Runs a command on the remote executor and returns its output. If the process is still running after yield_time_ms, the result carries a session id for write_stdin.",
	"write_stdin":  "Writes to the stdin of a running exec_command session on the remote executor and returns new output.",
}

// mcpServer exposes executors as <executor>__<tool> tools.
type mcpServer struct {
	srv *mcp.Server
	src ToolSource

	mu    sync.Mutex
	tools map[string]bool
}

// NewMCPServer builds an MCP server over a tool source.
func NewMCPServer(src ToolSource) *mcpServer {
	return &mcpServer{srv: mcp.NewServer(&mcp.Implementation{Name: "agentd", Version: Version}, &mcp.ServerOptions{
		Instructions: "Tools are named <executor>__<tool>; each runs on the named agentd executor node, subject to that node's policy."}),
		src: src, tools: map[string]bool{}}
}

// Server returns the underlying MCP server.
func (m *mcpServer) Server() *mcp.Server { return m.srv }

// Refresh synchronizes the tool list with the executors.
func (m *mcpServer) Refresh(ctx context.Context) error {
	exs, err := m.src.Executors(ctx)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range exs {
		if e.Name == "" {
			continue
		}
		tools := e.Tools
		if len(tools) == 0 {
			tools = []string{"exec_command", "write_stdin"}
		}
		for _, t := range tools {
			schema, ok := toolSchemas[t]
			if !ok {
				continue
			}
			name := e.Name + "__" + t
			want[name] = true
			desc := fmt.Sprintf("[agentd executor %q", e.Name)
			if !e.Online {
				desc += ", offline"
			}
			desc += "] " + toolDescriptions[t]
			if e.Description != "" {
				desc += " Node description (from node " + e.Name + "): " + e.Description
			}
			if m.tools[name] {
				continue
			}
			executor, tool := e.Key, t
			m.srv.AddTool(&mcp.Tool{Name: name, Description: desc, InputSchema: schema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return m.call(ctx, executor, tool, req.Params.Arguments), nil
			})
			m.tools[name] = true
		}
	}
	var gone []string
	for name := range m.tools {
		if !want[name] {
			gone = append(gone, name)
			delete(m.tools, name)
		}
	}
	if len(gone) > 0 {
		sort.Strings(gone)
		m.srv.RemoveTools(gone...)
	}
	return nil
}

func (m *mcpServer) call(ctx context.Context, executor, tool string, args json.RawMessage) *mcp.CallToolResult {
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	out, err := m.src.Call(ctx, executor, tool, args)
	if err != nil {
		msg := err.Error()
		if st := wire.StatusOf(err); st != pb.Status_OK && !strings.Contains(msg, st.String()) {
			msg = st.String() + ": " + msg
		}
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "agentd: " + msg}}}
	}
	text := out.OutputText
	if text == "" {
		text = out.Output
	}
	if out.IsError && out.ErrorMessage != "" {
		text = strings.TrimSpace(text + "\n" + out.ErrorMessage)
	}
	return &mcp.CallToolResult{IsError: out.IsError, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// agentSource serves tools from the daemon itself.
type agentSource struct{ a *Agent }

func (s agentSource) Executors(ctx context.Context) ([]ExecutorTool, error) {
	return s.a.Executors(), nil
}

func (s agentSource) Call(ctx context.Context, executor, tool string, args json.RawMessage) (*pb.FunctionCallOutput, error) {
	key, _, err := s.a.ResolveExecutor(executor)
	if err != nil {
		return nil, err
	}
	return s.a.Submit(ctx, key, &pb.FunctionCall{CallId: NewCallID(), Name: tool, Arguments: string(args)})
}

// Executors lists the executors this submitter can see.
func (a *Agent) Executors() []ExecutorTool {
	var out []ExecutorTool
	for _, e := range a.state.executorList() {
		t := ExecutorTool{Name: e.Name, Key: keyString(e.Identity), Description: e.Info.Description, Online: e.Info.Online}
		for _, ti := range e.Info.Tools {
			t.Tools = append(t.Tools, ti.Name)
		}
		out = append(out, t)
	}
	return out
}

func (a *Agent) startMCP(ctx context.Context, cfg *Config) error {
	a.mcp = NewMCPServer(agentSource{a})
	_ = a.mcp.Refresh(ctx)
	addr := net.JoinHostPort(cfg.Roles.Submitter.MCP.Address, fmt.Sprint(cfg.Roles.Submitter.MCP.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	a.mcpLn = ln
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return a.mcp.srv }, nil)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	a.log.Info("mcp server listening", "url", "http://"+ln.Addr().String()+"/mcp")
	return nil
}

// MCPAddr reports the MCP listener (tests).
func (a *Agent) MCPAddr() string {
	if a.mcpLn == nil {
		return ""
	}
	return a.mcpLn.Addr().String()
}

// onDirectoryChange refreshes what depends on the directory.
func (a *Agent) onDirectoryChange() {
	if a.mcp != nil {
		go a.mcp.Refresh(context.Background())
	}
}
