// Package policy evaluates (public_key, action, target) rules (design 6.6):
// a rule applies when its public_key is in the requester's identity set (an
// empty key means "*"); any applicable deny wins, otherwise any applicable
// allow, otherwise the request is denied.
package policy

import (
	"bytes"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"

	"agentd/internal/wire/pb"
)

// Decision is the result of an evaluation.
type Decision struct {
	Status pb.Status
	Reason string
	// Exec only: the allow rule matched by each command, and whether
	// write_stdin is permitted for the session.
	Matched []*pb.ExecRule
	Stdin   bool
}

func allow() Decision                      { return Decision{Status: pb.Status_OK} }
func deny(st pb.Status, r string) Decision { return Decision{Status: st, Reason: r} }

// NormalizeDomain lowercases and strips a trailing dot.
func NormalizeDomain(d string) string { return strings.TrimSuffix(strings.ToLower(d), ".") }

// MatchDomain reports whether domain matches a DOMAIN or SUFFIX pattern.
func MatchDomain(m *pb.Match, domain string) bool {
	d := NormalizeDomain(domain)
	v := NormalizeDomain(m.GetValue())
	switch m.GetKind() {
	case pb.Match_DOMAIN:
		return d == v
	case pb.Match_SUFFIX:
		return d == v || strings.HasSuffix(d, "."+v)
	default:
		return false
	}
}

func keyApplies(key []byte, ids [][]byte) bool {
	if len(key) == 0 {
		return true
	}
	for _, id := range ids {
		if bytes.Equal(id, key) {
			return true
		}
	}
	return false
}

// memberKeyApplies is keyApplies for targets reachable only by members: an
// empty identity set (anonymous) matches nothing, not even "*".
func memberKeyApplies(key []byte, ids [][]byte) bool {
	return len(ids) > 0 && keyApplies(key, ids)
}

func effectiveProto(p pb.Proto) pb.Proto {
	if p == pb.Proto_PROTO_UNSPECIFIED {
		return pb.Proto_PROTO_TLS
	}
	return p
}

// DefaultPort returns the default destination port of a protocol.
func DefaultPort(p pb.Proto) uint32 {
	if effectiveProto(p) == pb.Proto_PROTO_SSH {
		return 22
	}
	return 443
}

func egressTargetMatches(r *pb.EgressRule, proto pb.Proto, domain string) bool {
	if effectiveProto(r.Proto) != effectiveProto(proto) {
		return false
	}
	for _, m := range r.Domains {
		if MatchDomain(m, domain) {
			return true
		}
	}
	return false
}

func portAllowed(r *pb.EgressRule, proto pb.Proto, port uint32) bool {
	if len(r.Ports) == 0 {
		return port == DefaultPort(proto)
	}
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// Egress evaluates an egress request.
func Egress(rules []*pb.EgressRule, ids [][]byte, proto pb.Proto, domain string, port uint32) Decision {
	if port == 0 {
		port = DefaultPort(proto)
	}
	for _, r := range rules {
		if r.Action == pb.Action_ACTION_DENY && memberKeyApplies(r.PublicKey, ids) && egressTargetMatches(r, proto, domain) {
			if len(r.Ports) == 0 || portAllowed(r, proto, port) {
				return deny(pb.Status_POLICY_DENIED, "denied by rule")
			}
		}
	}
	portMismatch := false
	for _, r := range rules {
		if r.Action == pb.Action_ACTION_ALLOW && memberKeyApplies(r.PublicKey, ids) && egressTargetMatches(r, proto, domain) {
			if portAllowed(r, proto, port) {
				return allow()
			}
			portMismatch = true
		}
	}
	if portMismatch {
		return deny(pb.Status_PORT_NOT_ALLOWED, "port not allowed")
	}
	return deny(pb.Status_POLICY_DENIED, "no allow rule")
}

func argvMatches(prefix, argv []string) bool {
	if len(prefix) == 0 {
		return true
	}
	if len(argv) < len(prefix) {
		return false
	}
	if filepath.Base(prefix[0]) != filepath.Base(argv[0]) {
		return false
	}
	for i := 1; i < len(prefix); i++ {
		if prefix[i] != argv[i] {
			return false
		}
	}
	return true
}

// Exec evaluates a parsed command request: every command must be allowed and
// none denied. Shell-only rules (shell: true) do not apply to plain commands.
func Exec(rules []*pb.ExecRule, ids [][]byte, commands [][]string) Decision {
	if len(commands) == 0 {
		return deny(pb.Status_INVALID_ARGUMENTS, "empty command")
	}
	d := allow()
	for i, argv := range commands {
		for _, r := range rules {
			if r.Action == pb.Action_ACTION_DENY && !r.Shell && memberKeyApplies(r.PublicKey, ids) && argvMatches(r.Argv, argv) {
				return deny(pb.Status_POLICY_DENIED, "denied: "+strings.Join(argv, " "))
			}
		}
		var matched *pb.ExecRule
		for _, r := range rules {
			if r.Action == pb.Action_ACTION_ALLOW && !r.Shell && memberKeyApplies(r.PublicKey, ids) && argvMatches(r.Argv, argv) {
				if matched == nil || (r.Stdin && !matched.Stdin) {
					matched = r
				}
			}
		}
		if matched == nil {
			return deny(pb.Status_POLICY_DENIED, "not allowed: "+strings.Join(argv, " "))
		}
		d.Matched = append(d.Matched, matched)
		if i == 0 {
			d.Stdin = matched.Stdin
		}
	}
	return d
}

// ShellAllowed reports whether the requester may run a full shell command.
func ShellAllowed(rules []*pb.ExecRule, ids [][]byte) bool {
	for _, r := range rules {
		if r.Action == pb.Action_ACTION_DENY && r.Shell && memberKeyApplies(r.PublicKey, ids) {
			return false
		}
	}
	for _, r := range rules {
		if r.Action == pb.Action_ACTION_ALLOW && r.Shell && memberKeyApplies(r.PublicKey, ids) {
			return true
		}
	}
	return false
}

// ShellStdin reports whether a shell session may receive write_stdin.
func ShellStdin(rules []*pb.ExecRule, ids [][]byte) bool {
	for _, r := range rules {
		if r.Action == pb.Action_ACTION_ALLOW && r.Shell && r.Stdin && memberKeyApplies(r.PublicKey, ids) {
			return true
		}
	}
	return false
}

// Service evaluates access to a named service. An empty identity set is an
// anonymous public visitor, matched only by "*" rules.
func Service(rules []*pb.ServiceRule, ids [][]byte, name string) Decision {
	for _, r := range rules {
		if r.Action == pb.Action_ACTION_DENY && r.Name == name && keyApplies(r.PublicKey, ids) {
			return deny(pb.Status_POLICY_DENIED, "denied by rule")
		}
	}
	for _, r := range rules {
		if r.Action == pb.Action_ACTION_ALLOW && r.Name == name && keyApplies(r.PublicKey, ids) {
			return allow()
		}
	}
	return deny(pb.Status_POLICY_DENIED, "no allow rule")
}

// PrecheckExec is the control plane's who-only check for tasks: some allow
// rule names the requester and no blanket deny does.
func PrecheckExec(rules []*pb.ExecRule, ids [][]byte) Decision {
	for _, r := range rules {
		if r.Action == pb.Action_ACTION_DENY && !r.Shell && len(r.Argv) == 0 && memberKeyApplies(r.PublicKey, ids) {
			return deny(pb.Status_ACL_DENIED, "denied by rule")
		}
	}
	for _, r := range rules {
		if r.Action == pb.Action_ACTION_ALLOW && memberKeyApplies(r.PublicKey, ids) {
			return allow()
		}
	}
	return deny(pb.Status_ACL_DENIED, "no allow rule for this requester")
}

// KeySet is the set of keys named by a policy.
type KeySet struct {
	keys map[string]bool
	Any  bool // some rule uses "*"
}

// Has reports whether k is named by some rule.
func (s KeySet) Has(k []byte) bool { return s.keys[string(k)] }

// Keys collects every public key named by p (used to select which membership
// certificates are worth verifying, and for UNKNOWN_PEER).
func Keys(p *pb.Policy) KeySet {
	s := KeySet{keys: map[string]bool{}}
	add := func(k []byte) {
		if len(k) == 0 {
			s.Any = true
		} else {
			s.keys[string(k)] = true
		}
	}
	for _, r := range p.GetEgress() {
		add(r.PublicKey)
	}
	for _, r := range p.GetExec() {
		add(r.PublicKey)
	}
	for _, r := range p.GetServices() {
		add(r.PublicKey)
	}
	return s
}

// Effective returns the policy a role enforces: the local policy in local
// mode; in server mode the rendered server policy plus the local deny rules.
func Effective(source pb.PolicySource, local, server *pb.Policy) *pb.Policy {
	if source != pb.PolicySource_POLICY_SOURCE_SERVER {
		return local
	}
	out := &pb.Policy{}
	if server != nil {
		out = proto.Clone(server).(*pb.Policy)
	}
	for _, r := range local.GetEgress() {
		if r.Action == pb.Action_ACTION_DENY {
			out.Egress = append(out.Egress, r)
		}
	}
	for _, r := range local.GetExec() {
		if r.Action == pb.Action_ACTION_DENY {
			out.Exec = append(out.Exec, r)
		}
	}
	for _, r := range local.GetServices() {
		if r.Action == pb.Action_ACTION_DENY {
			out.Services = append(out.Services, r)
		}
	}
	return out
}
