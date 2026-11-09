// Package routes implements the workspace route table (design 6.5): each
// route is (source subject, protocols, domain patterns, destination). The
// control plane selects the destination; ingress nodes only receive a
// projection without destinations (IngressRoutes).
package routes

import (
	"errors"
	"fmt"
	"strings"

	"agentd/internal/identity"
	"agentd/internal/policy"
	"agentd/internal/wire/pb"
)

// Destinations other than a node name.
const (
	Direct = "direct"
	Reject = "reject"
)

// Route is one entry of the route table.
type Route struct {
	ID      string      `json:"id"`
	From    string      `json:"from"`            // "workspace", "node:<name>", "group:<name>" or "agentd://<key>"
	Protos  []pb.Proto  `json:"proto,omitempty"` // empty: TLS and SSH
	Domains []*pb.Match `json:"domains"`
	To      string      `json:"to"` // egress node name, "direct" or "reject"
}

// Table is a workspace's route table.
type Table struct {
	Version uint64
	Routes  []Route
	Default string // "direct" or "reject"
}

// Requester identifies who opens a connection.
type Requester struct {
	Name   string
	Groups []string
	Key    []byte
}

// Covers reports whether subject includes the requester.
func Covers(subject string, r Requester) bool {
	switch {
	case subject == "" || subject == "workspace":
		return true
	case strings.HasPrefix(subject, "node:"):
		return strings.TrimPrefix(subject, "node:") == r.Name
	case strings.HasPrefix(subject, "group:"):
		g := strings.TrimPrefix(subject, "group:")
		for _, x := range r.Groups {
			if x == g {
				return true
			}
		}
		return false
	case strings.HasPrefix(subject, "agentd://"):
		k, err := identity.DecodeKey(subject)
		return err == nil && string(k) == string(r.Key)
	}
	return false
}

func protoMatches(protos []pb.Proto, p pb.Proto) bool {
	if len(protos) == 0 {
		return true
	}
	for _, x := range protos {
		if x == p {
			return true
		}
	}
	return false
}

// specificity ranks a matching pattern: exact matches beat any suffix, longer
// suffixes beat shorter ones; -1 means no match.
func specificity(m *pb.Match, domain string) int {
	if !policy.MatchDomain(m, domain) {
		return -1
	}
	n := len(policy.NormalizeDomain(m.GetValue()))
	if m.GetKind() == pb.Match_DOMAIN {
		return 1<<20 + n
	}
	return n
}

// Select returns the destination for a request, falling back to the default.
func (t Table) Select(r Requester, proto pb.Proto, domain string) string {
	best, bestScore := "", -1
	for _, rt := range t.Routes {
		if !Covers(rt.From, r) || !protoMatches(rt.Protos, proto) {
			continue
		}
		for _, m := range rt.Domains {
			if s := specificity(m, domain); s > bestScore {
				best, bestScore = rt.To, s
			}
		}
	}
	if bestScore < 0 {
		if t.Default == Reject {
			return Reject
		}
		return Direct
	}
	return best
}

func action(to string) pb.RouteAction {
	switch to {
	case Direct, "":
		return pb.RouteAction_ROUTE_DIRECT
	case Reject:
		return pb.RouteAction_ROUTE_REJECT
	default:
		return pb.RouteAction_ROUTE_VIA
	}
}

// RenderIngress projects the table for one ingress node: only routes whose
// source covers it, destinations reduced to via / direct / reject.
func (t Table) RenderIngress(r Requester) *pb.IngressRoutes {
	out := &pb.IngressRoutes{Version: t.Version, Default: action(t.Default)}
	if t.Default != Reject {
		out.Default = pb.RouteAction_ROUTE_DIRECT
	}
	for _, rt := range t.Routes {
		if !Covers(rt.From, r) {
			continue
		}
		for _, m := range rt.Domains {
			out.Routes = append(out.Routes, &pb.IngressRoute{Match: m, Protos: rt.Protos, Action: action(rt.To)})
		}
	}
	return out
}

// EvalIngress decides direct / via / reject for a connection on an ingress
// node from its projection, with the same most-specific rule as Select.
func EvalIngress(ir *pb.IngressRoutes, proto pb.Proto, domain string) pb.RouteAction {
	if ir == nil {
		return pb.RouteAction_ROUTE_DIRECT
	}
	best, bestScore := ir.Default, -1
	for _, rt := range ir.Routes {
		if !protoMatches(rt.Protos, proto) {
			continue
		}
		if s := specificity(rt.Match, domain); s > bestScore {
			best, bestScore = rt.Action, s
		}
	}
	return best
}

// ValidSubject reports whether s is a valid route or policy subject.
func ValidSubject(s string, allowPublic bool) bool {
	switch {
	case s == "workspace":
		return true
	case s == "public":
		return allowPublic
	case strings.HasPrefix(s, "node:"):
		return identity.ValidLabel(strings.TrimPrefix(s, "node:"))
	case strings.HasPrefix(s, "group:"):
		return identity.ValidLabel(strings.TrimPrefix(s, "group:"))
	case strings.HasPrefix(s, "agentd://"):
		_, err := identity.DecodeKey(s)
		return err == nil
	}
	return false
}

// ValidateMatch checks a domain pattern written in a route or policy.
func ValidateMatch(m *pb.Match) error {
	if m == nil {
		return errors.New("empty domain pattern")
	}
	if m.Kind != pb.Match_DOMAIN && m.Kind != pb.Match_SUFFIX {
		return errors.New("domain pattern kind must be domain or suffix (sets are not supported yet)")
	}
	if !identity.ValidDomain(policy.NormalizeDomain(m.Value)) && !identity.ValidLabel(policy.NormalizeDomain(m.Value)) {
		return fmt.Errorf("invalid domain %q", m.Value)
	}
	return nil
}

// Validate checks a route.
func (r Route) Validate() error {
	if !ValidSubject(r.From, false) {
		return fmt.Errorf("invalid source %q (want workspace, node:<name>, group:<name> or agentd://<key>)", r.From)
	}
	if len(r.Domains) == 0 {
		return errors.New("route needs at least one domain pattern")
	}
	for _, m := range r.Domains {
		if err := ValidateMatch(m); err != nil {
			return err
		}
	}
	for _, p := range r.Protos {
		if p != pb.Proto_PROTO_TLS && p != pb.Proto_PROTO_SSH {
			return fmt.Errorf("route protocol must be tls or ssh")
		}
	}
	if r.To != Direct && r.To != Reject && !identity.ValidLabel(r.To) {
		return fmt.Errorf("invalid destination %q", r.To)
	}
	return nil
}
