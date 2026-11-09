package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"agentd/internal/identity"
	"agentd/internal/stream"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// TaskTimeout bounds waiting for a TaskResult after the Ack (yield ≤ 30 s
// plus process start and transfer).
const TaskTimeout = 2 * time.Minute

// NewCallID returns a fresh call id.
func NewCallID() string { return "call_" + hex.EncodeToString(randomBytes(12)) }

// ResolveExecutor finds an executor by name or key.
func (a *Agent) ResolveExecutor(ref string) ([]byte, string, error) {
	for _, e := range a.state.executorList() {
		if e.Name == ref || identity.EncodeKey(e.Identity) == ref || "agentd://"+identity.EncodeKey(e.Identity) == ref {
			return e.Identity, e.Name, nil
		}
	}
	return nil, "", fmt.Errorf("no executor named %q in the directory", ref)
}

// Submit runs one tool call on an executor (protocol 7.1). Retrying with the
// same call id is safe: the executor deduplicates by (from, call_id).
func (a *Agent) Submit(ctx context.Context, executor []byte, fc *pb.FunctionCall) (*pb.FunctionCallOutput, error) {
	cfg := a.config()
	if !cfg.Roles.Submitter.Enabled {
		return nil, errors.New("the submitter role is not enabled on this instance")
	}
	if fc.CallId == "" {
		fc.CallId = NewCallID()
	}
	as := a.waitSession(ctx, 5*time.Second)
	if as == nil {
		return nil, wire.Errorf(pb.Status_CONTROL_NOT_READY, "no session to the relay")
	}
	octx, cancel := context.WithTimeout(ctx, AckTimeout)
	st, err := as.mux.OpenStream(octx)
	cancel()
	if err != nil {
		return nil, wire.Errorf(pb.Status_CONTROL_NOT_READY, "open stream: %v", err)
	}
	open, err := wire.SignOpen(a.key, &pb.OpenBody{Kind: pb.Kind_KIND_TASK, Workspace: cfg.Workspace.Domain, From: a.pub, To: as.relayKey,
		IssuedAt: uint64(time.Now().Unix()), Nonce: randomBytes(16), Task: &pb.TaskOpen{Call: fc, Executor: executor}})
	if err != nil {
		st.Reset()
		return nil, err
	}
	if err := wire.WriteMsg(st, &pb.StreamOpen{Open: open, Certs: a.state.certsToAttach()}); err != nil {
		st.Reset()
		return nil, err
	}
	st.CloseWrite()
	start := time.Now()
	ack, err := stream.ReadAck(st, AckTimeout)
	if err != nil {
		st.Reset()
		return nil, wire.Errorf(pb.Status_TIMEOUT, "no Ack: %v", err)
	}
	if ack.Status != pb.Status_OK {
		st.Reset()
		a.decision("submit", "executor", a.state.memberName(executor), "tool", fc.Name, "call_id", fc.CallId, "status", ack.Status.String(), "message", ack.Message)
		return nil, wire.Errorf(ack.Status, "%s", ack.Message)
	}
	st.SetReadDeadline(time.Now().Add(TaskTimeout))
	var res pb.TaskResult
	if err := wire.ReadMsg(st, &res, wire.TaskResultMax); err != nil {
		st.Reset()
		return nil, wire.Errorf(pb.Status_TIMEOUT, "no result: %v", err)
	}
	st.Close()
	body, err := wire.VerifyTaskResult(executor, a.pub, fc.CallId, &res, time.Now())
	if err != nil {
		return nil, err
	}
	a.decision("submit", "executor", a.state.memberName(executor), "tool", fc.Name, "call_id", fc.CallId, "status", "OK", "ms", time.Since(start).Milliseconds())
	return body.Output, nil
}
