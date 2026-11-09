package identity

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// URI is a parsed agentd:// name (design 3.1). Exactly one of these shapes:
//   - key form:       Key set
//   - instance name:  Workspace and Name set
//   - group name:     Workspace and Group set
//   - workspace name: only Workspace set (stands for the workspace public key)
type URI struct {
	Key       []byte
	Workspace string
	Name      string
	Group     string
}

// String renders the URI back to text.
func (u URI) String() string {
	switch {
	case u.Key != nil:
		return "agentd://" + EncodeKey(u.Key)
	case u.Group != "":
		return "agentd://" + u.Workspace + "/group/" + u.Group
	default:
		return "agentd://" + u.Workspace + "/" + u.Name
	}
}

// ParseURI parses an agentd:// URI without query parameters.
func ParseURI(s string) (URI, error) {
	rest, ok := strings.CutPrefix(s, "agentd://")
	if !ok {
		return URI{}, errors.New("not an agentd:// URI")
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	authority, path, hasPath := strings.Cut(rest, "/")
	if !hasPath && !strings.Contains(authority, ".") && len(authority) == 43 {
		key, err := DecodeKey(authority)
		if err != nil {
			return URI{}, err
		}
		return URI{Key: key}, nil
	}
	ws := strings.ToLower(authority)
	if !validDomain(ws) {
		return URI{}, fmt.Errorf("invalid workspace domain %q", authority)
	}
	u := URI{Workspace: ws}
	path = strings.ToLower(path)
	switch {
	case path == "":
	case strings.HasPrefix(path, "group/"):
		g := strings.TrimPrefix(path, "group/")
		if !ValidLabel(g) {
			return URI{}, fmt.Errorf("invalid group name %q", g)
		}
		u.Group = g
	default:
		if !ValidLabel(path) {
			return URI{}, fmt.Errorf("invalid instance name %q", path)
		}
		u.Name = path
	}
	return u, nil
}

// JoinLink is a parsed join link (protocol 8.2):
// agentd://<workspace>/[name]?relay=<https url>&key=<workspace public key>&token=<token>
type JoinLink struct {
	Workspace string
	Name      string // empty: the joining instance proposes one
	RelayURL  string
	Key       []byte // workspace public key; may be nil, then fetched and confirmed
	Token     string
}

// ParseJoinLink parses a join link.
func ParseJoinLink(s string) (JoinLink, error) {
	s = strings.TrimSpace(s)
	u, err := ParseURI(s)
	if err != nil {
		return JoinLink{}, err
	}
	if u.Key != nil || u.Group != "" {
		return JoinLink{}, errors.New("join link must be agentd://<workspace domain>/[name]?…")
	}
	_, query, _ := strings.Cut(s, "?")
	q, err := url.ParseQuery(query)
	if err != nil {
		return JoinLink{}, fmt.Errorf("join link query: %w", err)
	}
	j := JoinLink{Workspace: u.Workspace, Name: u.Name, RelayURL: q.Get("relay"), Token: q.Get("token")}
	if j.Token == "" {
		return JoinLink{}, errors.New("join link has no token")
	}
	ru, err := url.Parse(j.RelayURL)
	if err != nil || ru.Scheme != "https" || ru.Host == "" {
		return JoinLink{}, fmt.Errorf("join link relay must be an https URL, got %q", j.RelayURL)
	}
	if k := q.Get("key"); k != "" {
		if j.Key, err = DecodeKey(k); err != nil {
			return JoinLink{}, fmt.Errorf("join link key: %w", err)
		}
	}
	return j, nil
}

// String renders the link with a stable parameter order.
func (j JoinLink) String() string {
	var b strings.Builder
	b.WriteString("agentd://")
	b.WriteString(j.Workspace)
	b.WriteString("/")
	b.WriteString(j.Name)
	b.WriteString("?relay=")
	b.WriteString(j.RelayURL)
	if j.Key != nil {
		b.WriteString("&key=")
		b.WriteString(EncodeKey(j.Key))
	}
	b.WriteString("&token=")
	b.WriteString(url.QueryEscape(j.Token))
	return b.String()
}

func validDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !ValidLabel(label) {
			return false
		}
	}
	return true
}

// ValidDomain reports whether s is a lowercase dotted name made of valid labels.
func ValidDomain(s string) bool { return validDomain(s) }
