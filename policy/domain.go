// Package policy provides the shared domain policy used by client ingress and
// provider egress. A successful match is a local filter, not a remote grant.
package policy

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// Domain selects exactly one DNS name or a DNS-label suffix including its apex.
type Domain struct {
	Exact  string `yaml:"exact" json:"exact,omitempty"`
	Suffix string `yaml:"suffix" json:"suffix,omitempty"`
}

type Rule struct {
	Domain   Domain `yaml:"domain" json:"domain"`
	Ports    []int  `yaml:"ports" json:"ports,omitempty"`
	Protocol string `yaml:"protocol" json:"protocol"`
}

// CanonicalDomain returns an ASCII, lowercase DNS name without its final dot.
// Addresses, address-like numeric names, URLs, wildcards and empty labels are
// deliberately not accepted as domain policy selectors.
func CanonicalDomain(s string) (string, error) {
	if s == "" || strings.TrimSpace(s) != s {
		return "", fmt.Errorf("domain must be nonempty and contain no surrounding whitespace")
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid IDNA domain: %w", err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if _, err := netip.ParseAddr(ascii); err == nil {
		return "", fmt.Errorf("IP addresses are not domain selectors")
	}
	if len(ascii) == 0 || len(ascii) > 253 {
		return "", fmt.Errorf("domain length must be between 1 and 253 bytes")
	}
	labels := strings.Split(ascii, ".")
	allNumeric := true
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label in %q", s)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid DNS character in %q", s)
			}
		}
		numeric := label
		hex := strings.HasPrefix(numeric, "0x")
		if hex {
			numeric = numeric[2:]
		}
		isNumeric := numeric != ""
		for _, c := range numeric {
			if !(c >= '0' && c <= '9' || hex && c >= 'a' && c <= 'f') {
				isNumeric = false
			}
		}
		allNumeric = allNumeric && isNumeric
	}
	if allNumeric {
		return "", fmt.Errorf("numeric address-like names are not domain selectors")
	}
	return ascii, nil
}

// Label canonicalizes one DNS label, such as an Agent, Workspace or service
// name. A label may be entirely numeric even though a complete numeric name is
// not a domain selector.
func Label(s string) (string, error) {
	const suffix = ".agent-label.invalid"
	canonical, err := CanonicalDomain(s + suffix)
	if err != nil {
		return "", err
	}
	canonical = strings.TrimSuffix(canonical, suffix)
	if canonical == "" || strings.Contains(canonical, ".") {
		return "", fmt.Errorf("must be a single DNS label")
	}
	return canonical, nil
}

// Validate normalizes the selector and checks the rule. Allow and ingress rules
// require ports. A deny rule can omit ports (nil) to cover every TLS port, but an
// explicitly empty list is always invalid.
func (r *Rule) Validate(requirePorts bool) error {
	if (r.Domain.Exact == "") == (r.Domain.Suffix == "") {
		return fmt.Errorf("domain must contain exactly one of exact or suffix")
	}
	selector := r.Domain.Exact
	if selector == "" {
		selector = r.Domain.Suffix
	}
	domain, err := CanonicalDomain(selector)
	if err != nil {
		return err
	}
	if r.Protocol != "tls" {
		return fmt.Errorf("protocol must be tls")
	}
	if len(r.Ports) == 0 && (requirePorts || r.Ports != nil) {
		return fmt.Errorf("ports must be a nonempty list")
	}
	seen := make(map[int]bool, len(r.Ports))
	for _, port := range r.Ports {
		if port < 1 || port > 65535 || seen[port] {
			return fmt.Errorf("ports must be unique integers between 1 and 65535")
		}
		seen[port] = true
	}
	if r.Domain.Exact != "" {
		r.Domain.Exact = domain
	} else {
		r.Domain.Suffix = domain
	}
	return nil
}

// Match matches a rule; omitted ports are interpreted as a deny-style wildcard.
// Use Allowed for allow/deny decisions, which requires explicit allow ports.
func Match(rule Rule, domain string, port int, protocol string) bool {
	canonical, err := CanonicalDomain(domain)
	if err != nil || rule.Validate(false) != nil || port < 1 || port > 65535 || protocol != "tls" {
		return false
	}
	return matchCanonical(rule, canonical, port, protocol)
}

func (r Rule) Match(domain string, port int, protocol string) bool {
	return Match(r, domain, port, protocol)
}

func matchCanonical(r Rule, domain string, port int, protocol string) bool {
	if protocol != r.Protocol {
		return false
	}
	if r.Domain.Exact != "" {
		if domain != r.Domain.Exact {
			return false
		}
	} else if domain != r.Domain.Suffix && !strings.HasSuffix(domain, "."+r.Domain.Suffix) {
		return false
	}
	if r.Ports == nil {
		return true
	}
	for _, p := range r.Ports {
		if port == p {
			return true
		}
	}
	return false
}

// Allowed applies the union of allow rules minus all deny rules. Any malformed
// policy fails closed, including a malformed deny that would otherwise be lost.
func Allowed(allow, deny []Rule, domain string, port int, protocol string) bool {
	canonical, err := CanonicalDomain(domain)
	if err != nil || port < 1 || port > 65535 || protocol != "tls" {
		return false
	}
	allowed := false
	for _, rule := range allow {
		if rule.Validate(true) != nil {
			return false
		}
		allowed = allowed || matchCanonical(rule, canonical, port, protocol)
	}
	for _, rule := range deny {
		if rule.Validate(false) != nil || matchCanonical(rule, canonical, port, protocol) {
			return false
		}
	}
	return allowed
}
