package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"agentd/internal/identity"
	"agentd/internal/session"
	"agentd/internal/tlsutil"
	"agentd/internal/transport"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// JoinOptions configure Join.
type JoinOptions struct {
	Name    string // proposed instance name when the token does not fix one
	Replace bool   // overwrite an existing membership in this instance directory
	Dial    transport.Options
}

// JoinResult reports what agentserver assigned.
type JoinResult struct {
	Name      string
	Workspace string
	Relay     string
	Key       []byte
}

// Join enrolls an instance with a join link (protocol 8.2): it verifies the
// relay with the workspace key from the link, presents the token in the
// handshake, waits for the signed Welcome and writes config.yaml.
func Join(ctx context.Context, dir, rawLink string, o JoinOptions) (*JoinResult, error) {
	link, err := identity.ParseJoinLink(rawLink)
	if err != nil {
		return nil, err
	}
	if len(link.Key) == 0 {
		return nil, errors.New("the join link has no workspace key")
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if _, err := os.Stat(cfgPath); err == nil && !o.Replace {
		return nil, fmt.Errorf("%s already belongs to a workspace; use --replace or another instance (-i)", dir)
	}
	if err := EnsureDir(dir); err != nil {
		return nil, err
	}
	key, _, err := identity.LoadOrCreateKey(KeyPath(dir))
	if err != nil {
		return nil, err
	}
	if o.Dial.RootCAs == nil {
		if o.Dial.RootCAs, err = tlsutil.RootsWithExtra("AGENTD_EXTRA_ROOTS"); err != nil {
			return nil, err
		}
	}
	cert, body, err := FetchRelayCert(ctx, link.RelayURL, link.Workspace, link.Key, o.Dial)
	if err != nil {
		return nil, err
	}
	proposed := o.Name
	if proposed == "" && link.Name == "" {
		host, _ := os.Hostname()
		proposed = identity.SanitizeLabel(strings.Split(host, ".")[0])
	}
	pub := identity.Public(key)
	conn, sh, err := dialSession(ctx, pub, key, body, transport.WebSocket, o.Dial, &pb.ClientHello{JoinToken: link.Token, ProposedName: proposed, Workspace: link.Workspace})
	if err != nil {
		var he *session.HelloError
		if errors.As(err, &he) {
			return nil, fmt.Errorf("join refused: %s %s", he.Hello.Status, he.Hello.Message)
		}
		return nil, err
	}
	mux, err := session.NewMux(conn, true)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer mux.Close()
	ctrl, err := openControl(ctx, mux, key, pub, body.Identity, link.Workspace)
	if err != nil {
		return nil, err
	}
	ctrl.SetReadDeadline(time.Now().Add(10 * time.Second))
	st := newState()
	for {
		var m pb.ControlMessage
		if err := wire.ReadMsg(ctrl, &m, wire.ControlMsgMax); err != nil {
			return nil, fmt.Errorf("waiting for the welcome: %w", err)
		}
		msg, err := wire.OpenSigned(link.Key, pub, m.GetSigned(), time.Now())
		if err != nil {
			continue
		}
		if w := msg.GetWelcome(); w != nil {
			st.applyWelcome(w, link.Key, link.Workspace)
			break
		}
	}
	if len(st.relays) == 0 {
		st.relays = []*pb.RelayCert{cert}
	}
	if len(st.assigned) == 0 {
		st.assigned = body.Identity
	}
	name := sh.Name
	if err := writeJoinedConfig(dir, name, link.Workspace, identity.EncodeKey(link.Key), link.RelayURL); err != nil {
		return nil, err
	}
	if err := st.save(StatePath(dir)); err != nil {
		return nil, err
	}
	return &JoinResult{Name: name, Workspace: link.Workspace, Relay: body.Name, Key: pub}, nil
}

const configTemplate = `# agentd instance configuration. Every field is documented in
# docs/agentd-config.yaml. Enable the roles this machine should play, then
# run: agentd reload (or restart agentd).
apiVersion: agentd/v1
kind: AgentdConfiguration
metadata:
  name: %s
workspace:
  domain: %s
  public_key: "%s"
  relay:
    url: %s
roles:
  ingress:
    enabled: false
    http: { enabled: true, address: 127.0.0.1, port: 7890 }
    socks5: { enabled: true, address: 127.0.0.1, port: 7891 }
    fallback: direct
  submitter:
    enabled: false
    mcp: { address: 127.0.0.1, port: 7900 }
  egress:
    enabled: false
    policy_source: local
    policies: []
  service:
    enabled: false
    policy_source: local
    servers: []
    policies: []
  executor:
    enabled: false
    policy_source: local
    workdir: %q
    policies: []
`

// writeJoinedConfig writes a fresh config, or updates metadata and workspace
// in an existing one (keeping its roles).
func writeJoinedConfig(dir, name, domain, wsKey, relayURL string) error {
	path := filepath.Join(dir, "config.yaml")
	if b, err := os.ReadFile(path); err == nil {
		var doc yaml.Node
		if yaml.Unmarshal(b, &doc) == nil && len(doc.Content) > 0 {
			root := doc.Content[0]
			set := func(m *yaml.Node, k, v string) {
				for i := 0; i+1 < len(m.Content); i += 2 {
					if m.Content[i].Value == k {
						m.Content[i+1].Value = v
						return
					}
				}
				m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, &yaml.Node{Kind: yaml.ScalarNode, Value: v})
			}
			child := func(m *yaml.Node, k string) *yaml.Node {
				for i := 0; i+1 < len(m.Content); i += 2 {
					if m.Content[i].Value == k {
						return m.Content[i+1]
					}
				}
				n := &yaml.Node{Kind: yaml.MappingNode}
				m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, n)
				return n
			}
			set(child(root, "metadata"), "name", name)
			ws := child(root, "workspace")
			set(ws, "domain", domain)
			set(ws, "public_key", wsKey)
			set(child(ws, "relay"), "url", relayURL)
			out, err := yaml.Marshal(&doc)
			if err != nil {
				return err
			}
			return os.WriteFile(path, out, 0o600)
		}
	}
	home, _ := os.UserHomeDir()
	return os.WriteFile(path, []byte(fmt.Sprintf(configTemplate, name, domain, wsKey, relayURL, home)), 0o600)
}
