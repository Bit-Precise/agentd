package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/routes"
	"agentd/internal/store"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// Answer TTLs (protocol 5.8).
const (
	ttlOK    = 60
	ttlError = 30
)

// Options configure a Coordinator.
type Options struct {
	Store     *store.Store
	ServerKey ed25519.PrivateKey
	Certs     *CertManager
	Logger    *slog.Logger
	// RelayBootstrapToken lets relays self-register with a shared secret
	// (relay_join_token_env); empty disables it.
	RelayBootstrapToken string
	// PushDelay debounces workspace-wide pushes.
	PushDelay time.Duration
	// RelayCertTTL is the relay certificate lifetime (default 30 days).
	RelayCertTTL time.Duration
}

// Coordinator holds agentserver's runtime state on top of the store.
type Coordinator struct {
	st        *store.Store
	key       ed25519.PrivateKey
	certs     *CertManager
	log       *slog.Logger
	bootstrap string
	pushDelay time.Duration
	relayTTL  time.Duration
	started   time.Time

	mu     sync.Mutex
	relays map[string]*relayConn // by relay name
	online map[string]onlineNode // by node key
	timers map[string]*time.Timer
	issued map[string]time.Time // node key -> when its membership certs were last issued
}

type onlineNode struct {
	relay string
	ws    string
}

type relayConn struct {
	name  string
	key   []byte
	since time.Time
	send  func(*pb.ControlMessage) error
}

// New creates a Coordinator.
func New(o Options) *Coordinator {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.PushDelay == 0 {
		o.PushDelay = 100 * time.Millisecond
	}
	if o.RelayCertTTL == 0 {
		o.RelayCertTTL = wire.RelayCertTTL
	}
	c := &Coordinator{st: o.Store, key: o.ServerKey, certs: o.Certs, log: o.Logger, bootstrap: o.RelayBootstrapToken, pushDelay: o.PushDelay, relayTTL: o.RelayCertTTL, started: time.Now(),
		relays: map[string]*relayConn{}, online: map[string]onlineNode{}, timers: map[string]*time.Timer{}, issued: map[string]time.Time{}}
	if c.certs != nil {
		c.certs.onReady = c.pushCertsForWorkspace
	}
	return c
}

// Store exposes the store (admin API, tests).
func (c *Coordinator) Store() *store.Store { return c.st }

// PublicKey is agentserver's own public key.
func (c *Coordinator) PublicKey() []byte { return c.key.Public().(ed25519.PublicKey) }

// ---------------------------------------------------------------- roles

var roleByName = map[string]pb.Role{"ingress": pb.Role_ROLE_INGRESS, "egress": pb.Role_ROLE_EGRESS, "service": pb.Role_ROLE_SERVICE, "submitter": pb.Role_ROLE_SUBMITTER, "executor": pb.Role_ROLE_EXECUTOR}

// AllRoles lists role names in display order.
var AllRoles = []string{"ingress", "submitter", "egress", "service", "executor"}

func pbRoles(names []string) []pb.Role {
	if len(names) == 0 {
		names = AllRoles
	}
	out := make([]pb.Role, 0, len(names))
	for _, n := range names {
		if r, ok := roleByName[n]; ok {
			out = append(out, r)
		}
	}
	return out
}

func hasProviderRole(n store.Node) bool {
	return n.HasRole("egress") || n.HasRole("service") || n.HasRole("executor")
}

// ---------------------------------------------------------------- online state

func (c *Coordinator) isOnline(key []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.online[string(key)]
	return ok
}

func (c *Coordinator) onlineIn(ws string) [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out [][]byte
	for k, o := range c.online {
		if o.ws == ws {
			out = append(out, []byte(k))
		}
	}
	return out
}

func (c *Coordinator) relayOf(key []byte) *relayConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	o, ok := c.online[string(key)]
	if !ok {
		return nil
	}
	return c.relays[o.relay]
}

// ---------------------------------------------------------------- delivery

// deliver signs msg with the workspace key and hands it to the node's relay.
func (c *Coordinator) deliver(ws store.Workspace, node []byte, msg *pb.ControlMessage) {
	rc := c.relayOf(node)
	if rc == nil {
		return
	}
	s, err := wire.SignControl(ws.PrivateKey, node, msg, time.Now())
	if err != nil {
		c.log.Error("sign control message", "err", err)
		return
	}
	if err := rc.send(&pb.ControlMessage{Msg: &pb.ControlMessage_Deliver{Deliver: &pb.Deliver{Identity: node, Signed: s}}}); err != nil {
		c.log.Debug("deliver failed", "relay", rc.name, "err", err)
	}
}

// invalidate tells the workspace's relay to drop cached answers.
func (c *Coordinator) invalidate(ws store.Workspace, removed ...[]byte) {
	c.mu.Lock()
	rc := c.relays[ws.Relay]
	c.mu.Unlock()
	if rc == nil {
		return
	}
	_ = rc.send(&pb.ControlMessage{Msg: &pb.ControlMessage_RelayInvalidate{RelayInvalidate: &pb.RelayInvalidate{Workspace: ws.BaseDomain, Removed: removed}}})
}

// Changed records that something in a workspace changed: relays drop their
// caches and every online member receives a fresh Welcome (debounced).
func (c *Coordinator) Changed(ctx context.Context, wsName string) {
	ws, err := c.st.GetWorkspace(ctx, wsName)
	if err != nil {
		return
	}
	c.invalidate(ws)
	c.mu.Lock()
	defer c.mu.Unlock()
	if t := c.timers[wsName]; t != nil {
		t.Stop()
	}
	c.timers[wsName] = time.AfterFunc(c.pushDelay, func() { c.pushWelcomes(context.Background(), wsName) })
}

func (c *Coordinator) pushWelcomes(ctx context.Context, wsName string) {
	ws, err := c.st.GetWorkspace(ctx, wsName)
	if err != nil {
		return
	}
	for _, key := range c.onlineIn(wsName) {
		n, _, err := c.st.GetNodeByKey(ctx, key)
		if err != nil {
			continue
		}
		w, err := c.buildWelcome(ctx, ws, n)
		if err != nil {
			c.log.Error("build welcome", "node", n.Name, "err", err)
			continue
		}
		c.deliver(ws, key, &pb.ControlMessage{Msg: &pb.ControlMessage_Welcome{Welcome: w}})
	}
}

// presence broadcasts a node's online state to the other online members.
func (c *Coordinator) presence(ctx context.Context, wsName string, key []byte, online bool) {
	ws, err := c.st.GetWorkspace(ctx, wsName)
	if err != nil {
		return
	}
	for _, other := range c.onlineIn(wsName) {
		if bytes.Equal(other, key) {
			continue
		}
		c.deliver(ws, other, &pb.ControlMessage{Msg: &pb.ControlMessage_Update{Update: &pb.Update{Presence: []*pb.Presence{{Identity: key, Online: online}}}}})
	}
}

// notify sends a Notice to one node.
func (c *Coordinator) notify(ws store.Workspace, key []byte, n *pb.Notice) {
	c.deliver(ws, key, &pb.ControlMessage{Msg: &pb.ControlMessage_Notice{Notice: n}})
}

// ---------------------------------------------------------------- welcome

func (c *Coordinator) fqdn(ws store.Workspace, name string) string { return name + "." + ws.BaseDomain }

func (c *Coordinator) certReady(ctx context.Context, ws store.Workspace) bool {
	cert, err := c.st.GetCert(ctx, ws.Name)
	return err == nil && cert.State != "pending" && len(cert.ChainPEM) > 0
}

func (c *Coordinator) pbService(ctx context.Context, ws store.Workspace, sv store.Service, nodeKey []byte, certReady bool) *pb.Service {
	out := &pb.Service{Name: sv.Name, Fqdn: c.fqdn(ws, sv.Name), NodeIdentity: nodeKey, State: pb.ServiceState_STATE_READY}
	if sv.Proto == "ssh" {
		out.Proto, out.Port = pb.Proto_PROTO_SSH, 22
	} else {
		out.Proto, out.Port = pb.Proto_PROTO_HTTP, 443
		if !certReady {
			out.State = pb.ServiceState_STATE_CERT_PENDING
		}
	}
	return out
}

// renderInput gathers what Render needs for a workspace.
func (c *Coordinator) renderInput(ctx context.Context, ws store.Workspace) (RenderInput, []Statement, error) {
	in := RenderInput{WorkspaceKey: ws.PublicKey, Nodes: map[string][]byte{}, Groups: map[string][]byte{}, Services: map[string]string{}}
	nodes, err := c.st.ListNodes(ctx, ws.Name)
	if err != nil {
		return in, nil, err
	}
	for _, n := range nodes {
		in.Nodes[n.Name] = n.PublicKey
	}
	groups, err := c.st.ListGroups(ctx, ws.Name)
	if err != nil {
		return in, nil, err
	}
	for _, g := range groups {
		in.Groups[g.Name] = g.PublicKey
	}
	svcs, err := c.st.ListServices(ctx, ws.Name)
	if err != nil {
		return in, nil, err
	}
	for _, s := range svcs {
		in.Services[s.Name] = s.Node
	}
	recs, err := c.st.ListPolicies(ctx, ws.Name)
	if err != nil {
		return in, nil, err
	}
	stmts := make([]Statement, 0, len(recs))
	for _, r := range recs {
		var s Statement
		if json.Unmarshal(r.Statement, &s) == nil {
			stmts = append(stmts, s)
		}
	}
	return in, stmts, nil
}

// renderedPolicy returns the server-rendered policy of one node.
func (c *Coordinator) renderedPolicy(ctx context.Context, ws store.Workspace, node string) (*pb.Policy, error) {
	in, stmts, err := c.renderInput(ctx, ws)
	if err != nil {
		return nil, err
	}
	p := Render(stmts, in)[node]
	if p == nil {
		p = &pb.Policy{}
	}
	return p, nil
}

// effectivePolicy is the policy the control plane prechecks a role against:
// the rendered one for server-managed roles, the advertised one otherwise.
func (c *Coordinator) effectivePolicy(ctx context.Context, ws store.Workspace, n store.Node, role string) (*pb.Policy, error) {
	if n.PolicySources[role] == "server" {
		return c.renderedPolicy(ctx, ws, n.Name)
	}
	if n.AdvertisedPolicy == nil {
		return &pb.Policy{}, nil
	}
	return n.AdvertisedPolicy, nil
}

// policyUpdate renders a node's policy, bumping its version when it changed.
func (c *Coordinator) policyUpdate(ctx context.Context, ws store.Workspace, n store.Node) (*pb.PolicyUpdate, error) {
	p, err := c.renderedPolicy(ctx, ws, n.Name)
	if err != nil {
		return nil, err
	}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(p)
	sum := sha256.Sum256(b)
	version := n.PolicyVersion
	if version == 0 || !bytes.Equal(sum[:], n.PolicyHash) {
		version++
		if err := c.st.SetPolicyVersion(ctx, ws.Name, n.Name, version, sum[:]); err != nil {
			return nil, err
		}
	}
	return &pb.PolicyUpdate{Version: version, Policy: p}, nil
}

// memberships issues fresh workspace and group certificates for a node.
func (c *Coordinator) memberships(ctx context.Context, ws store.Workspace, n store.Node, groups []store.Group) []*pb.MembershipCert {
	now := time.Now()
	var out []*pb.MembershipCert
	if cert, err := wire.IssueMembership(ws.PrivateKey, n.PublicKey, ws.BaseDomain, "", now, wire.MembershipTTL); err == nil {
		out = append(out, cert)
	}
	for _, g := range groups {
		for _, m := range g.Members {
			if m == n.Name {
				if cert, err := wire.IssueMembership(g.PrivateKey, n.PublicKey, ws.BaseDomain, g.Name, now, wire.MembershipTTL); err == nil {
					out = append(out, cert)
				}
			}
		}
	}
	c.mu.Lock()
	c.issued[string(n.PublicKey)] = now
	c.mu.Unlock()
	return out
}

// relayCert issues the workspace's certificate for a relay.
func (c *Coordinator) relayCert(ws store.Workspace, r store.Relay) (*pb.RelayCert, error) {
	now := time.Now()
	urls := map[string]string{}
	base := strings.TrimSuffix(r.URL, "/")
	tr := r.Transports
	if len(tr) == 0 {
		tr = map[string]string{"ws": "/ws", "httpupgrade": "/up", "xhttp": "/x"}
	}
	for k, p := range tr {
		urls[k] = base + p
	}
	return wire.IssueRelayCert(ws.PrivateKey, &pb.RelayCertBody{Identity: r.PublicKey, Name: r.Name, Urls: urls, Stun: r.STUN,
		IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(c.relayTTL).Unix()), Workspace: ws.BaseDomain})
}

func groupsOf(groups []store.Group, node string) []string {
	var out []string
	for _, g := range groups {
		for _, m := range g.Members {
			if m == node {
				out = append(out, g.Name)
			}
		}
	}
	return out
}

// buildWelcome assembles the full state for one node (protocol 5.2).
func (c *Coordinator) buildWelcome(ctx context.Context, ws store.Workspace, n store.Node) (*pb.Welcome, error) {
	nodes, err := c.st.ListNodes(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	groups, err := c.st.ListGroups(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	svcs, err := c.st.ListServices(ctx, ws.Name)
	if err != nil {
		return nil, err
	}
	relay, err := c.st.GetRelay(ctx, ws.Relay)
	if err != nil {
		return nil, err
	}
	keyOf := map[string][]byte{}
	dir := &pb.Directory{Version: ws.DirectoryVersion, WorkspaceIdentity: ws.PublicKey}
	for _, m := range nodes {
		keyOf[m.Name] = m.PublicKey
		dir.Members = append(dir.Members, &pb.Member{Identity: m.PublicKey, Name: m.Name, RoleCaps: pbRoles(m.RoleCaps), Online: c.isOnline(m.PublicKey), JoinedAt: uint64(m.JoinedAt.Unix())})
	}
	for _, g := range groups {
		pg := &pb.Group{Identity: g.PublicKey, Name: g.Name}
		for _, m := range g.Members {
			pg.Members = append(pg.Members, keyOf[m])
		}
		dir.Groups = append(dir.Groups, pg)
	}
	w := &pb.Welcome{
		Directory:     dir,
		Self:          &pb.Self{Identity: n.PublicKey, Name: n.Name, Workspace: ws.BaseDomain, RoleCaps: pbRoles(n.RoleCaps)},
		AssignedRelay: relay.PublicKey,
	}
	ready := c.certReady(ctx, ws)
	for _, sv := range svcs {
		w.Services = append(w.Services, c.pbService(ctx, ws, sv, keyOf[sv.Node], ready))
	}
	if n.HasRole("ingress") {
		table, err := c.st.GetRouteTable(ctx, ws.Name)
		if err != nil {
			return nil, err
		}
		w.Routes = table.RenderIngress(routes.Requester{Name: n.Name, Groups: groupsOf(groups, n.Name), Key: n.PublicKey})
	}
	if n.HasRole("submitter") {
		for _, m := range nodes {
			if m.Executor != nil && m.HasRole("executor") {
				w.Executors = append(w.Executors, &pb.ExecutorInfo{Identity: m.PublicKey, Description: m.Executor.Description, Tools: m.Executor.Tools, Online: c.isOnline(m.PublicKey)})
			}
		}
	}
	if hasProviderRole(n) {
		if w.Policy, err = c.policyUpdate(ctx, ws, n); err != nil {
			return nil, err
		}
	}
	w.Memberships = c.memberships(ctx, ws, n, groups)
	if rc, err := c.relayCert(ws, relay); err == nil {
		w.Relays = []*pb.RelayCert{rc}
	}
	return w, nil
}

// signedWelcome builds and signs a Welcome for a node.
func (c *Coordinator) signedWelcome(ctx context.Context, ws store.Workspace, n store.Node) (*pb.Signed, error) {
	w, err := c.buildWelcome(ctx, ws, n)
	if err != nil {
		return nil, err
	}
	return wire.SignControl(ws.PrivateKey, n.PublicKey, &pb.ControlMessage{Msg: &pb.ControlMessage_Welcome{Welcome: w}}, time.Now())
}

// ---------------------------------------------------------------- relays

func (c *Coordinator) registerRelay(rc *relayConn) {
	c.mu.Lock()
	old := c.relays[rc.name]
	c.relays[rc.name] = rc
	c.mu.Unlock()
	_ = old
	ctx := context.Background()
	_ = c.st.TouchRelay(ctx, rc.name)
	c.pushRelayState(ctx, rc.name)
}

func (c *Coordinator) unregisterRelay(rc *relayConn) {
	c.mu.Lock()
	if c.relays[rc.name] != rc {
		c.mu.Unlock()
		return
	}
	delete(c.relays, rc.name)
	var gone []onlineNode
	var keys [][]byte
	for k, o := range c.online {
		if o.relay == rc.name {
			gone = append(gone, o)
			keys = append(keys, []byte(k))
			delete(c.online, k)
		}
	}
	c.mu.Unlock()
	for i, o := range gone {
		c.presence(context.Background(), o.ws, keys[i], false)
	}
}

// pushRelayState sends a relay its certificates for every assigned workspace.
func (c *Coordinator) pushRelayState(ctx context.Context, relayName string) {
	c.mu.Lock()
	rc := c.relays[relayName]
	c.mu.Unlock()
	if rc == nil {
		return
	}
	r, err := c.st.GetRelay(ctx, relayName)
	if err != nil {
		return
	}
	wss, err := c.st.WorkspacesOfRelay(ctx, relayName)
	if err != nil {
		return
	}
	certs := &pb.WorkspaceCerts{}
	for _, ws := range wss {
		if cert, err := c.relayCert(ws, r); err == nil {
			_ = rc.send(&pb.ControlMessage{Msg: &pb.ControlMessage_RelayCert{RelayCert: cert}})
		}
		if wc := c.workspaceCert(ctx, ws); wc != nil {
			certs.Certs = append(certs.Certs, wc)
		}
	}
	if len(certs.Certs) > 0 {
		_ = rc.send(&pb.ControlMessage{Msg: &pb.ControlMessage_WorkspaceCerts{WorkspaceCerts: certs}})
	}
}

func (c *Coordinator) workspaceCert(ctx context.Context, ws store.Workspace) *pb.WorkspaceCert {
	cert, err := c.st.GetCert(ctx, ws.Name)
	if err != nil || len(cert.ChainPEM) == 0 || len(cert.KeyPEM) == 0 {
		return nil
	}
	var exp uint64
	if cert.NotAfter != nil {
		exp = uint64(cert.NotAfter.Unix())
	}
	return &pb.WorkspaceCert{Workspace: ws.BaseDomain, CertChainPem: cert.ChainPEM, KeyPem: cert.KeyPEM, ExpiresAt: exp}
}

func (c *Coordinator) pushCertsForWorkspace(ctx context.Context, wsName string) {
	ws, err := c.st.GetWorkspace(ctx, wsName)
	if err != nil {
		return
	}
	c.mu.Lock()
	rc := c.relays[ws.Relay]
	c.mu.Unlock()
	if rc != nil {
		if wc := c.workspaceCert(ctx, ws); wc != nil {
			_ = rc.send(&pb.ControlMessage{Msg: &pb.ControlMessage_WorkspaceCerts{WorkspaceCerts: &pb.WorkspaceCerts{Certs: []*pb.WorkspaceCert{wc}}}})
		}
	}
	c.Changed(ctx, wsName) // services may turn ready
}

// handlePresence applies a relay's RelayPresence.
func (c *Coordinator) handlePresence(ctx context.Context, relay string, p *pb.RelayPresence) {
	for _, k := range p.Online {
		n, ws, err := c.st.GetNodeByKey(ctx, k)
		if err != nil || ws.Relay != relay {
			continue
		}
		c.mu.Lock()
		_, was := c.online[string(k)]
		c.online[string(k)] = onlineNode{relay: relay, ws: ws.Name}
		c.mu.Unlock()
		_ = c.st.TouchNode(ctx, k)
		if !was {
			c.log.Info("node online", "workspace", ws.Name, "node", n.Name, "relay", relay)
			c.presence(ctx, ws.Name, k, true)
		}
	}
	for _, k := range p.Offline {
		c.mu.Lock()
		o, was := c.online[string(k)]
		if was && o.relay == relay {
			delete(c.online, string(k))
		}
		c.mu.Unlock()
		if was && o.relay == relay {
			_ = c.st.TouchNode(ctx, k)
			c.presence(ctx, o.ws, k, false)
		}
	}
}

// RenewLoop re-issues membership certificates before they expire.
func (c *Coordinator) RenewLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.mu.Lock()
		var due [][]byte
		for k := range c.online {
			if time.Since(c.issued[k]) > wire.MembershipTTL-wire.MembershipRenew {
				due = append(due, []byte(k))
			}
		}
		c.mu.Unlock()
		for _, k := range due {
			n, ws, err := c.st.GetNodeByKey(ctx, k)
			if err != nil {
				continue
			}
			groups, _ := c.st.ListGroups(ctx, ws.Name)
			certs := c.memberships(ctx, ws, n, groups)
			c.deliver(ws, k, &pb.ControlMessage{Msg: &pb.ControlMessage_Update{Update: &pb.Update{Memberships: certs}}})
		}
	}
}

// Stats summarises runtime state for the admin API.
func (c *Coordinator) Stats() (relays int, online int, uptime time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.relays), len(c.online), time.Since(c.started)
}

// RelayConnected reports whether a relay session is up and since when.
func (c *Coordinator) RelayConnected(name string) (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rc := c.relays[name]
	if rc == nil {
		return false, time.Time{}
	}
	return true, rc.since
}

// NodeOnline reports whether a node is online and via which relay.
func (c *Coordinator) NodeOnline(key []byte) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o, ok := c.online[string(key)]
	return ok, o.relay
}

// OnlineCount counts online nodes of a workspace.
func (c *Coordinator) OnlineCount(ws string) int { return len(c.onlineIn(ws)) }

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var errNotFound = errors.New("not found")

// broadcastRevocations pushes the workspace's unexpired revocations to every online member.
func (c *Coordinator) broadcastRevocations(ctx context.Context, ws store.Workspace) {
	revs, err := c.st.Revocations(ctx, ws.Name)
	if err != nil || len(revs) == 0 {
		return
	}
	for _, k := range c.onlineIn(ws.Name) {
		c.deliver(ws, k, &pb.ControlMessage{Msg: &pb.ControlMessage_Update{Update: &pb.Update{RevokedMemberships: revs}}})
	}
}
