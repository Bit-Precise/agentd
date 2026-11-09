package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"agentd/internal/policy"
	"agentd/internal/wire"
	"agentd/internal/wire/pb"
)

// State is what the node knows about its workspace, built from Welcome and
// Update messages (protocol 5.2, 5.4). Every message was verified with the
// workspace key before it gets here.
type State struct {
	mu sync.RWMutex

	self          *pb.Self
	dirVersion    uint64
	members       map[string]*pb.Member // by identity
	groups        []*pb.Group
	wsIdentity    []byte
	routes        *pb.IngressRoutes
	services      map[string]*pb.Service // by fqdn
	executors     map[string]*pb.ExecutorInfo
	memberships   []*pb.MembershipCert
	revoked       []*pb.MembershipRevocation
	relays        []*pb.RelayCert
	assigned      []byte
	serverPolicy  *pb.Policy
	policyVersion uint64
	advertised    *pb.AdvertiseResult
}

func newState() *State {
	return &State{members: map[string]*pb.Member{}, services: map[string]*pb.Service{}, executors: map[string]*pb.ExecutorInfo{}}
}

// applyWelcome replaces the state; parts older than what we have are kept.
// It returns the policy update to apply, if any.
func (s *State) applyWelcome(w *pb.Welcome, wsKey []byte, workspace string) *pb.PolicyUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.Self != nil {
		s.self = w.Self
	}
	if d := w.Directory; d != nil && d.Version >= s.dirVersion {
		s.dirVersion = d.Version
		s.members = map[string]*pb.Member{}
		for _, m := range d.Members {
			s.members[string(m.Identity)] = m
		}
		s.groups = d.Groups
		s.wsIdentity = d.WorkspaceIdentity
	}
	if w.Routes != nil && (s.routes == nil || w.Routes.Version >= s.routes.Version) {
		s.routes = w.Routes
	}
	s.services = map[string]*pb.Service{}
	for _, sv := range w.Services {
		s.services[sv.Fqdn] = sv
	}
	s.executors = map[string]*pb.ExecutorInfo{}
	for _, e := range w.Executors {
		s.executors[string(e.Identity)] = e
	}
	if len(w.Memberships) > 0 {
		s.memberships = w.Memberships
	}
	s.setRelays(w.Relays, wsKey, workspace)
	if len(w.AssignedRelay) > 0 {
		s.assigned = w.AssignedRelay
	}
	return w.Policy
}

func (s *State) setRelays(certs []*pb.RelayCert, wsKey []byte, workspace string) {
	var ok []*pb.RelayCert
	for _, c := range certs {
		if _, err := wire.VerifyRelayCert(wsKey, c, workspace, time.Now()); err == nil {
			ok = append(ok, c)
		}
	}
	if len(ok) > 0 {
		s.relays = ok
	}
}

// applyUpdate merges an incremental update. It reports whether the relay
// assignment changed.
func (s *State) applyUpdate(u *pb.Update, wsKey []byte, workspace string) (reassigned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.DirectoryVersion == 0 || u.DirectoryVersion >= s.dirVersion {
		if u.DirectoryVersion > 0 {
			s.dirVersion = u.DirectoryVersion
		}
		for _, m := range u.UpsertMembers {
			s.members[string(m.Identity)] = m
		}
		for _, id := range u.RemovedMembers {
			delete(s.members, string(id))
		}
	}
	for _, p := range u.Presence {
		if m := s.members[string(p.Identity)]; m != nil {
			m.Online = p.Online
		}
		if e := s.executors[string(p.Identity)]; e != nil {
			e.Online = p.Online
		}
	}
	if u.Routes != nil && (s.routes == nil || u.Routes.Version >= s.routes.Version) {
		s.routes = u.Routes
	}
	for _, sv := range u.UpsertServices {
		s.services[sv.Fqdn] = sv
	}
	for _, f := range u.RemovedServices {
		delete(s.services, f)
	}
	for _, e := range u.UpsertExecutors {
		s.executors[string(e.Identity)] = e
	}
	for _, id := range u.RemovedExecutors {
		delete(s.executors, string(id))
	}
	if len(u.Memberships) > 0 {
		byIssuer := map[string]*pb.MembershipCert{}
		for _, c := range s.memberships {
			if b, err := wire.DecodeMembership(c); err == nil {
				byIssuer[string(b.Issuer)] = c
			}
		}
		for _, c := range u.Memberships {
			if b, err := wire.DecodeMembership(c); err == nil {
				byIssuer[string(b.Issuer)] = c
			}
		}
		s.memberships = s.memberships[:0]
		for _, c := range byIssuer {
			s.memberships = append(s.memberships, c)
		}
	}
	if len(u.RevokedMemberships) > 0 {
		s.revoked = append(s.revoked, u.RevokedMemberships...)
		// Drop our own certificates that were revoked.
		var keep []*pb.MembershipCert
		for _, c := range s.memberships {
			b, err := wire.DecodeMembership(c)
			if err == nil && !s.isRevokedLocked(b.Member, b.Issuer) {
				keep = append(keep, c)
			}
		}
		s.memberships = keep
	}
	if len(u.Relays) > 0 {
		s.setRelays(u.Relays, wsKey, workspace)
	}
	if len(u.AssignedRelay) > 0 && !bytes.Equal(u.AssignedRelay, s.assigned) {
		s.assigned = u.AssignedRelay
		reassigned = true
	}
	return reassigned
}

func (s *State) isRevokedLocked(member, issuer []byte) bool {
	now := uint64(time.Now().Unix())
	for _, r := range s.revoked {
		if r.Until < now {
			continue
		}
		if bytes.Equal(r.Issuer, issuer) && (len(r.Member) == 0 || bytes.Equal(r.Member, member)) {
			return true
		}
	}
	return false
}

func (s *State) isRevoked(member, issuer []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isRevokedLocked(member, issuer)
}

// setServerPolicy stores a newer rendered policy; false when not newer.
func (s *State) setServerPolicy(u *pb.PolicyUpdate) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u == nil || u.Version <= s.policyVersion {
		return false
	}
	s.policyVersion = u.Version
	s.serverPolicy = u.Policy
	return true
}

func (s *State) server() (*pb.Policy, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverPolicy, s.policyVersion
}

// certsToAttach returns up to 16 unexpired membership certificates.
func (s *State) certsToAttach() []*pb.MembershipCert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := uint64(time.Now().Unix())
	var out []*pb.MembershipCert
	for _, c := range s.memberships {
		if b, err := wire.DecodeMembership(c); err == nil && b.ExpiresAt > now {
			out = append(out, c)
		}
		if len(out) == wire.OpenMaxCerts {
			break
		}
	}
	return out
}

func (s *State) ingressRoutes() *pb.IngressRoutes {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routes
}

func (s *State) service(fqdn string) *pb.Service {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.services[fqdn]
}

func (s *State) isRelayKey(k []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.relays {
		if b, err := wire.DecodeRelayCert(c); err == nil && bytes.Equal(b.Identity, k) {
			return true
		}
	}
	return false
}

func (s *State) memberName(id []byte) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m := s.members[string(id)]; m != nil {
		return m.Name
	}
	return ""
}

// executorList returns the executors sorted by name.
func (s *State) executorList() []executorView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []executorView
	for id, e := range s.executors {
		name := ""
		if m := s.members[id]; m != nil {
			name = m.Name
		}
		out = append(out, executorView{Name: name, Identity: []byte(id), Info: proto.Clone(e).(*pb.ExecutorInfo)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type executorView struct {
	Name     string
	Identity []byte
	Info     *pb.ExecutorInfo
}

// relayChoice returns the relay certificates to try, the assigned one first.
func (s *State) relayChoice() []*pb.RelayCert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var first, rest []*pb.RelayCert
	for _, c := range s.relays {
		b, err := wire.DecodeRelayCert(c)
		if err != nil || time.Unix(int64(b.ExpiresAt), 0).Before(time.Now()) {
			continue
		}
		if bytes.Equal(b.Identity, s.assigned) {
			first = append(first, c)
		} else {
			rest = append(rest, c)
		}
	}
	return append(first, rest...)
}

func (s *State) setAssigned(c *pb.RelayCert, wsKey []byte, workspace string) bool {
	b, err := wire.VerifyRelayCert(wsKey, c, workspace, time.Now())
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assigned = b.Identity
	for i, old := range s.relays {
		if ob, err := wire.DecodeRelayCert(old); err == nil && bytes.Equal(ob.Identity, b.Identity) {
			s.relays[i] = c
			return true
		}
	}
	s.relays = append([]*pb.RelayCert{c}, s.relays...)
	return true
}

// identitySet runs checklist B step 7: {from} plus the issuers of attached
// membership certificates that some rule names and that verify.
func (s *State) identitySet(from []byte, certs []*pb.MembershipCert, keys policy.KeySet, workspace string) [][]byte {
	ids := [][]byte{from}
	now := time.Now()
	for _, c := range certs {
		b, err := wire.DecodeMembership(c)
		if err != nil || !keys.Has(b.Issuer) {
			continue
		}
		if _, err := wire.VerifyMembership(c, from, workspace, now, s.isRevoked); err == nil {
			ids = append(ids, b.Issuer)
		}
	}
	return ids
}

// persisted is the on-disk cache (relay certificates and the assignment),
// so a restart can reach a reassigned relay without a fresh join link.
type persisted struct {
	Relays   [][]byte `json:"relays"`
	Assigned []byte   `json:"assigned"`
}

func (s *State) save(path string) error {
	s.mu.RLock()
	p := persisted{Assigned: s.assigned}
	for _, c := range s.relays {
		b, _ := proto.Marshal(c)
		p.Relays = append(p.Relays, b)
	}
	s.mu.RUnlock()
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *State) load(path string, wsKey []byte, workspace string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var p persisted
	if json.Unmarshal(b, &p) != nil {
		return
	}
	var certs []*pb.RelayCert
	for _, raw := range p.Relays {
		var c pb.RelayCert
		if proto.Unmarshal(raw, &c) == nil {
			certs = append(certs, &c)
		}
	}
	s.mu.Lock()
	s.setRelays(certs, wsKey, workspace)
	s.assigned = p.Assigned
	s.mu.Unlock()
}

func keyString(k []byte) string { return identityEncode(k) }
