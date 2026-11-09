// Package task executes Codex-style tool calls on an executor node (design
// 5.6, 7.6): exec_command and write_stdin with unified exec sessions, no
// shell, argv-prefix policy, de-duplication by (from, call_id) and an audit log.
package task

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"agentd/internal/policy"
	"agentd/internal/task/cmdline"
	"agentd/internal/wire/pb"
)

// Config holds executor settings (AgentdConfiguration roles.executor).
type Config struct {
	Workdir        string
	Shell          string
	EnvPassthrough []string
	MaxSessions    int
	DefaultYield   time.Duration
	MaxOutputBytes int
	SessionIdle    time.Duration
	AuditLog       string // empty: no audit log
}

func (c *Config) defaults() {
	if c.MaxSessions <= 0 {
		c.MaxSessions = 4
	}
	if c.DefaultYield <= 0 {
		c.DefaultYield = 10 * time.Second
	}
	if c.MaxOutputBytes <= 0 {
		c.MaxOutputBytes = 1 << 20
	}
	if c.SessionIdle <= 0 {
		c.SessionIdle = 10 * time.Minute
	}
	if c.Shell == "" {
		if runtime.GOOS == "windows" {
			c.Shell = "cmd.exe"
		} else {
			c.Shell = "/bin/sh"
		}
	}
	if len(c.EnvPassthrough) == 0 {
		c.EnvPassthrough = []string{"HOME", "PATH", "LANG", "TERM", "USER", "LOGNAME", "TMPDIR", "SystemRoot", "USERPROFILE"}
	}
}

// DedupTTL is how long a finished call's output is kept (TASK_DEDUP_TTL).
const DedupTTL = 10 * time.Minute

// Handler executes tool calls. Rules are read through SetRules on each call so
// policy updates take effect immediately.
type Handler struct {
	cfg   Config
	rules func() []*pb.ExecRule

	mu       sync.Mutex
	sessions map[int64]*session
	nextID   int64
	calls    map[string]*callEntry
	auditMu  sync.Mutex
	stop     chan struct{}
}

type callEntry struct {
	name, args string
	done       chan struct{}
	out        *pb.FunctionCallOutput
	expires    time.Time
}

// NewHandler creates a handler and starts its reaper.
func NewHandler(cfg Config) *Handler {
	cfg.defaults()
	h := &Handler{cfg: cfg, rules: func() []*pb.ExecRule { return nil }, sessions: map[int64]*session{}, calls: map[string]*callEntry{}, nextID: 1, stop: make(chan struct{})}
	go h.reaper()
	return h
}

// SetRules installs the source of the effective exec rules.
func (h *Handler) SetRules(f func() []*pb.ExecRule) { h.rules = f }

// Tools lists the tools this executor supports.
func Tools() []*pb.ToolInfo {
	return []*pb.ToolInfo{{Name: "exec_command"}, {Name: "write_stdin"}}
}

// Prepared is an accepted call ready to run (the caller sends Ack OK first).
type Prepared interface {
	Run() *pb.FunctionCallOutput
}

type preparedFunc func() *pb.FunctionCallOutput

func (f preparedFunc) Run() *pb.FunctionCallOutput { return f() }

type execArgs struct {
	Cmd             string `json:"cmd"`
	Workdir         string `json:"workdir"`
	TTY             bool   `json:"tty"`
	YieldTimeMs     *int64 `json:"yield_time_ms"`
	MaxOutputTokens *int64 `json:"max_output_tokens"`
}

type stdinArgs struct {
	SessionID       *int64 `json:"session_id"`
	Chars           string `json:"chars"`
	YieldTimeMs     *int64 `json:"yield_time_ms"`
	MaxOutputTokens *int64 `json:"max_output_tokens"`
}

func decodeStrict(args string, allowed []string, v any) error {
	if strings.TrimSpace(args) == "" {
		args = "{}"
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(args), &keys); err != nil {
		return fmt.Errorf("arguments must be a JSON object: %v", err)
	}
	for k := range keys {
		ok := false
		for _, a := range allowed {
			ok = ok || a == k
		}
		if !ok {
			return fmt.Errorf("parameter %q is not accepted", k)
		}
	}
	return json.Unmarshal([]byte(args), v)
}

func clamp(v *int64, def, lo, hi int64) time.Duration {
	x := def
	if v != nil {
		x = *v
	}
	if x < lo {
		x = lo
	}
	if x > hi {
		x = hi
	}
	return time.Duration(x) * time.Millisecond
}

func tokens(v *int64) int {
	if v == nil || *v <= 0 {
		return 10000
	}
	return int(*v)
}

// Prepare validates a call, applies the policy and returns a runnable call,
// or a status for the Ack (protocol 7.3 error classification).
func (h *Handler) Prepare(from []byte, ids [][]byte, fc *pb.FunctionCall) (Prepared, pb.Status, string) {
	key := string(from) + "\x00" + fc.GetCallId()
	if fc.GetCallId() == "" {
		return nil, pb.Status_INVALID_ARGUMENTS, "call_id is required"
	}
	h.mu.Lock()
	if e, ok := h.calls[key]; ok && time.Now().Before(e.expires) {
		h.mu.Unlock()
		if e.name != fc.Name || e.args != fc.Arguments {
			return nil, pb.Status_BAD_REQUEST, "call_id reused with different arguments"
		}
		return preparedFunc(func() *pb.FunctionCallOutput { <-e.done; return e.out }), pb.Status_OK, ""
	}
	h.mu.Unlock()

	var run func() *pb.FunctionCallOutput
	var st pb.Status
	var msg string
	switch fc.Name {
	case "exec_command":
		run, st, msg = h.prepareExec(from, ids, fc)
	case "write_stdin":
		run, st, msg = h.prepareStdin(from, fc)
	default:
		return nil, pb.Status_UNSUPPORTED_TOOL, fmt.Sprintf("tool %q is not supported by this executor", fc.Name)
	}
	if st != pb.Status_OK {
		return nil, st, msg
	}
	e := &callEntry{name: fc.Name, args: fc.Arguments, done: make(chan struct{}), expires: time.Now().Add(DedupTTL)}
	h.mu.Lock()
	h.calls[key] = e
	h.mu.Unlock()
	return preparedFunc(func() *pb.FunctionCallOutput {
		e.out = run()
		close(e.done)
		h.audit(from, fc, e.out)
		return e.out
	}), pb.Status_OK, ""
}

func (h *Handler) resolveWorkdir(dir string) (string, error) {
	root, err := filepath.Abs(h.cfg.Workdir)
	if err != nil {
		return "", err
	}
	if dir == "" {
		return root, nil
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	dir = filepath.Clean(dir)
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("workdir %s is outside %s", dir, root)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("workdir %s does not exist", dir)
	}
	return dir, nil
}

func (h *Handler) env() []string {
	var out []string
	for _, k := range h.cfg.EnvPassthrough {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

func (h *Handler) prepareExec(from []byte, ids [][]byte, fc *pb.FunctionCall) (func() *pb.FunctionCallOutput, pb.Status, string) {
	var a execArgs
	if err := decodeStrict(fc.Arguments, []string{"cmd", "workdir", "tty", "yield_time_ms", "max_output_tokens"}, &a); err != nil {
		return nil, pb.Status_INVALID_ARGUMENTS, err.Error()
	}
	if strings.TrimSpace(a.Cmd) == "" {
		return nil, pb.Status_INVALID_ARGUMENTS, "cmd is required"
	}
	if a.TTY {
		return nil, pb.Status_INVALID_ARGUMENTS, "tty is not supported by this executor"
	}
	dir, err := h.resolveWorkdir(a.Workdir)
	if err != nil {
		return nil, pb.Status_INVALID_ARGUMENTS, err.Error()
	}
	rules := h.rules()
	var rp *runPlan
	script, perr := cmdline.Parse(a.Cmd)
	if perr != nil {
		if !policy.ShellAllowed(rules, ids) {
			return nil, pb.Status_INVALID_ARGUMENTS, "command is not a plain command line (" + perr.Error() + "); this executor does not run a shell for you"
		}
		rp = &runPlan{shell: h.cfg.Shell, cmd: a.Cmd, stdin: policy.ShellStdin(rules, ids)}
	} else {
		d := policy.Exec(rules, ids, script.Commands())
		if d.Status != pb.Status_OK {
			return nil, d.Status, d.Reason
		}
		progs := make([]string, len(d.Matched))
		for i, r := range d.Matched {
			p, err := resolveProgram(r.Argv, script.Commands()[i][0])
			if err != nil {
				return nil, pb.Status_INVALID_ARGUMENTS, err.Error()
			}
			progs[i] = p
		}
		rp = &runPlan{script: script, programs: progs, stdin: d.Stdin}
	}
	h.mu.Lock()
	running := 0
	for _, s := range h.sessions {
		if !s.isExited() {
			running++
		}
	}
	h.mu.Unlock()
	if running >= h.cfg.MaxSessions {
		return nil, pb.Status_BUSY, fmt.Sprintf("executor already runs %d sessions", running)
	}
	yield := clamp(a.YieldTimeMs, h.cfg.DefaultYield.Milliseconds(), 250, 30000)
	maxTok := tokens(a.MaxOutputTokens)
	return func() *pb.FunctionCallOutput {
		start := time.Now()
		s, err := h.startSession(from, rp, dir)
		if err != nil {
			return errorOutput(start, err)
		}
		return h.collect(s, start, yield, maxTok)
	}, pb.Status_OK, ""
}

// runPlan describes what a session runs.
type runPlan struct {
	script   cmdline.Script
	programs []string // resolved program per command, in Commands() order
	shell    string
	cmd      string
	stdin    bool
}

func resolveProgram(ruleArgv []string, requested string) (string, error) {
	name := requested
	if len(ruleArgv) > 0 {
		name = ruleArgv[0]
	}
	if filepath.IsAbs(name) {
		return name, nil
	}
	p, err := exec.LookPath(filepath.Base(name))
	if err != nil {
		return "", fmt.Errorf("program %q not found on the executor's PATH", name)
	}
	return p, nil
}

func (h *Handler) prepareStdin(from []byte, fc *pb.FunctionCall) (func() *pb.FunctionCallOutput, pb.Status, string) {
	var a stdinArgs
	if err := decodeStrict(fc.Arguments, []string{"session_id", "chars", "yield_time_ms", "max_output_tokens"}, &a); err != nil {
		return nil, pb.Status_INVALID_ARGUMENTS, err.Error()
	}
	if a.SessionID == nil {
		return nil, pb.Status_INVALID_ARGUMENTS, "session_id is required"
	}
	h.mu.Lock()
	s := h.sessions[*a.SessionID]
	h.mu.Unlock()
	if s == nil || !bytes.Equal(s.owner, from) {
		return nil, pb.Status_SESSION_NOT_FOUND, fmt.Sprintf("no session %d for this caller", *a.SessionID)
	}
	if a.Chars != "" && s.stdin == nil {
		return nil, pb.Status_POLICY_DENIED, "write_stdin is not allowed for this session (the matching rule lacks stdin: true)"
	}
	var yield time.Duration
	if a.Chars == "" {
		yield = clamp(a.YieldTimeMs, 5000, 250, 300000)
	} else {
		yield = clamp(a.YieldTimeMs, 250, 250, 30000)
	}
	maxTok := tokens(a.MaxOutputTokens)
	return func() *pb.FunctionCallOutput {
		start := time.Now()
		if a.Chars != "" {
			if _, err := s.stdin.Write([]byte(a.Chars)); err != nil && !s.isExited() {
				return errorOutput(start, fmt.Errorf("write stdin: %w", err))
			}
		}
		return h.collect(s, start, yield, maxTok)
	}, pb.Status_OK, ""
}

func errorOutput(start time.Time, err error) *pb.FunctionCallOutput {
	out := &pb.FunctionCallOutput{IsError: true, ErrorMessage: err.Error(), WallTimeSeconds: time.Since(start).Seconds(), Output: err.Error() + "\n"}
	out.OutputText = formatText(out)
	return out
}

func (h *Handler) collect(s *session, start time.Time, yield time.Duration, maxTok int) *pb.FunctionCallOutput {
	select {
	case <-s.done:
	case <-time.After(yield):
	}
	text, dropped := s.drain()
	out := &pb.FunctionCallOutput{WallTimeSeconds: time.Since(start).Seconds()}
	if s.isExited() {
		code := int32(s.exitCode)
		out.ExitCode = &code
		h.mu.Lock()
		delete(h.sessions, s.id)
		h.mu.Unlock()
	} else {
		id := s.id
		out.SessionId = &id
	}
	truncated, orig := truncateTokens(text, maxTok)
	if dropped > 0 && orig == 0 {
		orig = (len(text) + dropped + 3) / 4
	}
	if orig > 0 {
		o := int64(orig)
		out.OriginalTokenCount = &o
	}
	out.Output = truncated
	out.OutputText = formatText(out)
	return out
}

func formatText(out *pb.FunctionCallOutput) string {
	var b strings.Builder
	if out.ChunkId != nil {
		fmt.Fprintf(&b, "Chunk ID: %s\n", out.GetChunkId())
	}
	fmt.Fprintf(&b, "Wall time: %.4f seconds\n", out.WallTimeSeconds)
	switch {
	case out.ExitCode != nil:
		fmt.Fprintf(&b, "Process exited with code %d\n", out.GetExitCode())
	case out.SessionId != nil:
		fmt.Fprintf(&b, "Process running with session ID %d\n", out.GetSessionId())
	}
	if out.OriginalTokenCount != nil {
		fmt.Fprintf(&b, "Original token count: %d\n", out.GetOriginalTokenCount())
	}
	b.WriteString("Output:\n")
	b.WriteString(out.Output)
	return b.String()
}

// truncateTokens keeps the head and tail of text within maxTokens (≈4 bytes
// per token) and reports the original token count when it truncated.
func truncateTokens(text string, maxTokens int) (string, int) {
	tok := (len(text) + 3) / 4
	if tok <= maxTokens {
		return text, 0
	}
	keep := maxTokens * 4
	head := keep / 2
	tail := keep - head
	marker := fmt.Sprintf("\n…%d tokens truncated…\n", tok-maxTokens)
	return text[:head] + marker + text[len(text)-tail:], tok
}

type auditRecord struct {
	Time     string   `json:"time"`
	From     string   `json:"from"`
	CallID   string   `json:"call_id"`
	Tool     string   `json:"tool"`
	Args     string   `json:"arguments"`
	ExitCode *int32   `json:"exit_code,omitempty"`
	Session  *int64   `json:"session_id,omitempty"`
	Wall     float64  `json:"wall_time_seconds"`
	Error    string   `json:"error,omitempty"`
	Argv     []string `json:"argv,omitempty"`
}

func (h *Handler) audit(from []byte, fc *pb.FunctionCall, out *pb.FunctionCallOutput) {
	if h.cfg.AuditLog == "" {
		return
	}
	rec := auditRecord{Time: time.Now().UTC().Format(time.RFC3339Nano), From: base64.RawURLEncoding.EncodeToString(from), CallID: fc.CallId, Tool: fc.Name, Args: fc.Arguments, ExitCode: out.ExitCode, Session: out.SessionId, Wall: out.WallTimeSeconds, Error: out.ErrorMessage}
	line, _ := json.Marshal(rec)
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(h.cfg.AuditLog), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(h.cfg.AuditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	f.Write(append(line, '\n'))
	f.Close()
}

func (h *Handler) reaper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case now := <-t.C:
			h.mu.Lock()
			for k, e := range h.calls {
				if now.After(e.expires) {
					delete(h.calls, k)
				}
			}
			var idle []*session
			for id, s := range h.sessions {
				if now.Sub(s.lastUsed()) > h.cfg.SessionIdle {
					delete(h.sessions, id)
					idle = append(idle, s)
				}
			}
			h.mu.Unlock()
			for _, s := range idle {
				s.kill()
			}
		}
	}
}

// Close kills every session.
func (h *Handler) Close() {
	select {
	case <-h.stop:
		return
	default:
		close(h.stop)
	}
	h.mu.Lock()
	ss := h.sessions
	h.sessions = map[int64]*session{}
	h.mu.Unlock()
	for _, s := range ss {
		s.kill()
	}
}
