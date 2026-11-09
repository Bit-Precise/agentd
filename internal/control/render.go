// Package control is agentserver: the control plane and backend of the
// relays (design 5.7): membership, routing, policy rendering and prechecks,
// certificates, signed control messages and the admin API.
package control

import (
	"errors"
	"fmt"
	"strings"

	"agentd/internal/identity"
	"agentd/internal/routes"
	"agentd/internal/wire/pb"
)

// MatchJSON is a domain pattern as written in the admin API.
type MatchJSON struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// Target is a policy target (design 6.8 YAML form).
type Target struct {
	Egress  string      `json:"egress,omitempty"`
	Proto   string      `json:"proto,omitempty"`
	Domains []MatchJSON `json:"domains,omitempty"`
	Ports   []int       `json:"ports,omitempty"`
	Exec    string      `json:"exec,omitempty"`
	Argv    []string    `json:"argv,omitempty"`
	Stdin   bool        `json:"stdin,omitempty"`
	Shell   bool        `json:"shell,omitempty"`
	Service string      `json:"service,omitempty"`
}

// Statement is a central policy statement.
type Statement struct {
	Subjects []string `json:"subjects"`
	Allow    []Target `json:"allow,omitempty"`
	Deny     []Target `json:"deny,omitempty"`
	Comment  string   `json:"comment,omitempty"`
}

// ToMatch converts an API pattern.
func (m MatchJSON) ToMatch() *pb.Match {
	k := pb.Match_SUFFIX
	if m.Kind == "domain" {
		k = pb.Match_DOMAIN
	}
	return &pb.Match{Kind: k, Value: strings.TrimSuffix(strings.ToLower(m.Value), ".")}
}

// FromMatch converts to the API form.
func FromMatch(m *pb.Match) MatchJSON {
	if m.Kind == pb.Match_DOMAIN {
		return MatchJSON{Kind: "domain", Value: m.Value}
	}
	return MatchJSON{Kind: "suffix", Value: m.Value}
}

// ProtoFromName maps "tls"/"ssh" (empty means tls).
func ProtoFromName(s string) (pb.Proto, error) {
	switch s {
	case "", "tls":
		return pb.Proto_PROTO_TLS, nil
	case "ssh":
		return pb.Proto_PROTO_SSH, nil
	}
	return 0, fmt.Errorf("protocol must be tls or ssh, got %q", s)
}

// Validate checks a target.
func (t Target) Validate() error {
	n := 0
	for _, s := range []string{t.Egress, t.Exec, t.Service} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return errors.New("a target names exactly one of egress, exec or service")
	}
	switch {
	case t.Egress != "":
		if !identity.ValidLabel(t.Egress) {
			return fmt.Errorf("invalid egress node %q", t.Egress)
		}
		if _, err := ProtoFromName(t.Proto); err != nil {
			return err
		}
		if len(t.Domains) == 0 {
			return errors.New("an egress target needs domains")
		}
		for _, m := range t.Domains {
			if err := routes.ValidateMatch(m.ToMatch()); err != nil {
				return err
			}
			if m.Kind != "domain" && m.Kind != "suffix" {
				return fmt.Errorf("domain kind must be domain or suffix, got %q", m.Kind)
			}
		}
		for _, p := range t.Ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("invalid port %d", p)
			}
		}
	case t.Exec != "":
		if !identity.ValidLabel(t.Exec) {
			return fmt.Errorf("invalid executor node %q", t.Exec)
		}
		if len(t.Argv) == 0 && !t.Shell {
			return errors.New("an exec target needs argv (or shell: true)")
		}
	case t.Service != "":
		if !identity.ValidLabel(t.Service) {
			return fmt.Errorf("invalid service %q", t.Service)
		}
	}
	return nil
}

// Validate checks a statement.
func (s Statement) Validate() error {
	if len(s.Subjects) == 0 {
		return errors.New("statement needs at least one subject")
	}
	for _, sub := range s.Subjects {
		if !routes.ValidSubject(sub, true) && !strings.HasPrefix(sub, "user:") && !strings.HasPrefix(sub, "usergroup:") {
			return fmt.Errorf("invalid subject %q", sub)
		}
	}
	if len(s.Allow)+len(s.Deny) == 0 {
		return errors.New("statement has no allow or deny targets")
	}
	for _, t := range append(append([]Target{}, s.Allow...), s.Deny...) {
		if err := t.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// RenderInput resolves subjects and services for rendering.
type RenderInput struct {
	WorkspaceKey []byte
	Nodes        map[string][]byte // node name -> key
	Groups       map[string][]byte // group name -> key
	Services     map[string]string // service name -> node name
}

// subjectKey maps a subject to the key placed in rules; ok=false means skip.
// "public" maps to nil (the "*" key).
func subjectKey(sub string, in RenderInput) ([]byte, bool) {
	switch {
	case sub == "workspace":
		return in.WorkspaceKey, true
	case sub == "public":
		return nil, true
	case strings.HasPrefix(sub, "node:"):
		k, ok := in.Nodes[strings.TrimPrefix(sub, "node:")]
		return k, ok
	case strings.HasPrefix(sub, "group:"):
		k, ok := in.Groups[strings.TrimPrefix(sub, "group:")]
		return k, ok
	case strings.HasPrefix(sub, "agentd://"):
		k, err := identity.DecodeKey(sub)
		return k, err == nil
	}
	return nil, false // user:, usergroup: are edge-only and not rendered
}

// Render turns statements into per-node policies (design 6.8): subjects become
// keys (members are not expanded), each target lands on the node it names.
func Render(stmts []Statement, in RenderInput) map[string]*pb.Policy {
	out := map[string]*pb.Policy{}
	get := func(node string) *pb.Policy {
		p := out[node]
		if p == nil {
			p = &pb.Policy{}
			out[node] = p
		}
		return p
	}
	for _, st := range stmts {
		for _, sub := range st.Subjects {
			key, ok := subjectKey(sub, in)
			if !ok {
				continue
			}
			emit := func(t Target, action pb.Action) {
				switch {
				case t.Egress != "":
					proto, _ := ProtoFromName(t.Proto)
					r := &pb.EgressRule{PublicKey: key, Action: action, Proto: proto}
					for _, m := range t.Domains {
						r.Domains = append(r.Domains, m.ToMatch())
					}
					for _, p := range t.Ports {
						r.Ports = append(r.Ports, uint32(p))
					}
					get(t.Egress).Egress = append(get(t.Egress).Egress, r)
				case t.Exec != "":
					get(t.Exec).Exec = append(get(t.Exec).Exec, &pb.ExecRule{PublicKey: key, Action: action, Argv: t.Argv, Stdin: t.Stdin, Shell: t.Shell})
				case t.Service != "":
					node, ok := in.Services[t.Service]
					if !ok {
						return
					}
					get(node).Services = append(get(node).Services, &pb.ServiceRule{PublicKey: key, Action: action, Name: t.Service})
				}
			}
			for _, t := range st.Allow {
				emit(t, pb.Action_ACTION_ALLOW)
			}
			for _, t := range st.Deny {
				emit(t, pb.Action_ACTION_DENY)
			}
		}
	}
	return out
}
