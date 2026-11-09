package task

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"agentd/internal/wire/pb"
)

var (
	alice = []byte("alice-key-0000000000000000000000")[:32]
	bob   = []byte("bob-key-000000000000000000000000")[:32]
)

func newHandler(t *testing.T, rules []*pb.ExecRule) *Handler {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("executor tests use POSIX utilities")
	}
	dir := t.TempDir()
	h := NewHandler(Config{Workdir: dir, MaxSessions: 2, EnvPassthrough: []string{"PATH"}, AuditLog: filepath.Join(dir, "audit.log")})
	h.rules = func() []*pb.ExecRule { return rules }
	t.Cleanup(h.Close)
	return h
}

func call(id, name string, args any) *pb.FunctionCall {
	b, _ := json.Marshal(args)
	return &pb.FunctionCall{CallId: id, Name: name, Arguments: string(b)}
}

func run(t *testing.T, h *Handler, from []byte, fc *pb.FunctionCall) (pb.Status, *pb.FunctionCallOutput) {
	t.Helper()
	p, st, msg := h.Prepare(from, [][]byte{from}, fc)
	if st != pb.Status_OK {
		t.Logf("prepare: %v %s", st, msg)
		return st, nil
	}
	return st, p.Run()
}

func allowAll(key []byte, stdin bool, argv ...string) *pb.ExecRule {
	return &pb.ExecRule{PublicKey: key, Action: pb.Action_ACTION_ALLOW, Argv: argv, Stdin: stdin}
}

func TestExecCommandOutputFormat(t *testing.T) {
	h := newHandler(t, []*pb.ExecRule{allowAll(alice, false, "echo")})
	st, out := run(t, h, alice, call("c1", "exec_command", map[string]any{"cmd": "echo hello world"}))
	if st != pb.Status_OK {
		t.Fatal(st)
	}
	if out.GetExitCode() != 0 || out.Output != "hello world\n" || out.SessionId != nil {
		t.Fatalf("output: %+v", out)
	}
	for _, want := range []string{"Wall time: ", " seconds\n", "Process exited with code 0\n", "Output:\nhello world\n"} {
		if !strings.Contains(out.OutputText, want) {
			t.Errorf("output_text %q lacks %q", out.OutputText, want)
		}
	}
}

func TestPipelineAndChains(t *testing.T) {
	h := newHandler(t, []*pb.ExecRule{allowAll(alice, false, "printf"), allowAll(alice, false, "wc"), allowAll(alice, false, "false"), allowAll(alice, false, "echo")})
	_, out := run(t, h, alice, call("c1", "exec_command", map[string]any{"cmd": `printf 'a\nb\nc\n' | wc -l`}))
	if strings.TrimSpace(out.Output) != "3" {
		t.Fatalf("pipeline output %q", out.Output)
	}
	_, out = run(t, h, alice, call("c2", "exec_command", map[string]any{"cmd": "false && echo no || echo yes"}))
	if out.Output != "yes\n" || out.GetExitCode() != 0 {
		t.Fatalf("chain output %q exit %d", out.Output, out.GetExitCode())
	}
}

func TestPolicyAndParseErrorsAreAckStatuses(t *testing.T) {
	h := newHandler(t, []*pb.ExecRule{allowAll(alice, false, "echo")})
	if st, _ := run(t, h, alice, call("c1", "exec_command", map[string]any{"cmd": "rm -rf /tmp/x"})); st != pb.Status_POLICY_DENIED {
		t.Fatalf("denied command: %v", st)
	}
	if st, _ := run(t, h, bob, call("c2", "exec_command", map[string]any{"cmd": "echo hi"})); st != pb.Status_POLICY_DENIED {
		t.Fatalf("unknown requester: %v", st)
	}
	if st, _ := run(t, h, alice, call("c3", "exec_command", map[string]any{"cmd": "echo $HOME"})); st != pb.Status_INVALID_ARGUMENTS {
		t.Fatalf("expansion: %v", st)
	}
	if st, _ := run(t, h, alice, call("c4", "apply_patch", map[string]any{})); st != pb.Status_UNSUPPORTED_TOOL {
		t.Fatalf("unknown tool: %v", st)
	}
	if st, _ := run(t, h, alice, call("c5", "exec_command", map[string]any{"cmd": "echo hi", "shell": "/bin/bash"})); st != pb.Status_INVALID_ARGUMENTS {
		t.Fatalf("shell parameter must be rejected: %v", st)
	}
	if st, _ := run(t, h, alice, call("c6", "exec_command", map[string]any{"cmd": "echo hi", "workdir": "/"})); st != pb.Status_INVALID_ARGUMENTS {
		t.Fatalf("workdir outside the root: %v", st)
	}
}

func TestLongRunningSessionAndStdin(t *testing.T) {
	h := newHandler(t, []*pb.ExecRule{allowAll(alice, true, "head"), allowAll(alice, false, "sleep")})
	_, out := run(t, h, alice, call("c1", "exec_command", map[string]any{"cmd": "head -n 1", "yield_time_ms": 300}))
	if out.SessionId == nil || out.ExitCode != nil || !strings.Contains(out.OutputText, "Process running with session ID") {
		t.Fatalf("expected a running session: %+v", out)
	}
	sid := out.GetSessionId()
	if st, _ := run(t, h, bob, call("c2", "write_stdin", map[string]any{"session_id": sid, "chars": "x\n"})); st != pb.Status_SESSION_NOT_FOUND {
		t.Fatalf("another caller reached the session: %v", st)
	}
	_, out = run(t, h, alice, call("c3", "write_stdin", map[string]any{"session_id": sid, "chars": "line one\n", "yield_time_ms": 3000}))
	if out.Output != "line one\n" || out.GetExitCode() != 0 {
		t.Fatalf("stdin round trip: %+v", out)
	}
	_, out = run(t, h, alice, call("c4", "exec_command", map[string]any{"cmd": "sleep 5", "yield_time_ms": 250}))
	if out.SessionId == nil {
		t.Fatalf("sleep should keep running: %+v", out)
	}
	if st, _ := run(t, h, alice, call("c5", "write_stdin", map[string]any{"session_id": out.GetSessionId(), "chars": "x"})); st != pb.Status_POLICY_DENIED {
		t.Fatalf("stdin must be refused when the rule lacks stdin: true: %v", st)
	}
}

func TestSessionLimit(t *testing.T) {
	h := newHandler(t, []*pb.ExecRule{allowAll(alice, false, "sleep")})
	for i := 0; i < 2; i++ {
		_, out := run(t, h, alice, call("s"+string(rune('a'+i)), "exec_command", map[string]any{"cmd": "sleep 5", "yield_time_ms": 250}))
		if out.SessionId == nil {
			t.Fatalf("session %d not kept", i)
		}
	}
	if st, _ := run(t, h, alice, call("s-over", "exec_command", map[string]any{"cmd": "sleep 5", "yield_time_ms": 250})); st != pb.Status_BUSY {
		t.Fatalf("expected BUSY, got %v", st)
	}
}

func TestDedupByCallID(t *testing.T) {
	h := newHandler(t, []*pb.ExecRule{allowAll(alice, false, "date")})
	_, a := run(t, h, alice, call("same", "exec_command", map[string]any{"cmd": "date +%N"}))
	time.Sleep(10 * time.Millisecond)
	_, b := run(t, h, alice, call("same", "exec_command", map[string]any{"cmd": "date +%N"}))
	if a.Output != b.Output {
		t.Fatalf("retry with the same call_id re-executed: %q vs %q", a.Output, b.Output)
	}
	if st, _ := run(t, h, alice, call("same", "exec_command", map[string]any{"cmd": "date"})); st != pb.Status_BAD_REQUEST {
		t.Fatalf("same call_id with different arguments: %v", st)
	}
}

func TestOutputTruncation(t *testing.T) {
	text := strings.Repeat("0123456789", 1000)
	got, orig := truncateTokens(text, 100)
	if orig == 0 || len(got) > 500 || !strings.Contains(got, "tokens truncated") {
		t.Fatalf("truncate: len=%d orig=%d", len(got), orig)
	}
	if got, orig := truncateTokens("short", 100); got != "short" || orig != 0 {
		t.Fatal("short output must not be truncated")
	}
}

func TestAuditLogWritten(t *testing.T) {
	h := newHandler(t, []*pb.ExecRule{allowAll(alice, false, "echo")})
	run(t, h, alice, call("c1", "exec_command", map[string]any{"cmd": "echo audited"}))
	data, err := os.ReadFile(h.cfg.AuditLog)
	if err != nil || !strings.Contains(string(data), `"call_id":"c1"`) || !strings.Contains(string(data), "audited") {
		t.Fatalf("audit log: %s %v", data, err)
	}
}
