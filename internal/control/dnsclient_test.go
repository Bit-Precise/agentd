package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"agentd/internal/store"
)

// fakeCloudflare answers the Cloudflare v4 DNS endpoints CloudflareClient
// uses, in Cloudflare's envelope ({"success": ..., "errors": ..., "result": ...}).
type fakeCloudflare struct {
	token string
	zones map[string]string // zone name -> id

	mu      sync.Mutex
	records map[string]DNSRecord // record id -> record
	next    int
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(status int, result any, errs ...string) {
		list := []map[string]string{}
		for _, e := range errs {
			list = append(list, map[string]string{"message": e})
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": len(errs) == 0, "errors": list, "result": result})
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		reply(http.StatusForbidden, nil, "Invalid API Token")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/zones":
		name := r.URL.Query().Get("name")
		zones := []map[string]string{}
		if id, ok := f.zones[name]; ok {
			zones = append(zones, map[string]string{"id": id, "name": name})
		}
		reply(http.StatusOK, zones)
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records":
		var rec DNSRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			reply(http.StatusBadRequest, nil, err.Error())
			return
		}
		if f.records == nil {
			f.records = map[string]DNSRecord{}
		}
		f.next++
		rec.ID = fmt.Sprintf("%s-rec-%d", parts[1], f.next)
		f.records[rec.ID] = rec
		reply(http.StatusOK, rec)
	case r.Method == http.MethodDelete && len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records":
		if _, ok := f.records[parts[3]]; !ok || !strings.HasPrefix(parts[3], parts[1]+"-") {
			reply(http.StatusNotFound, nil, "Record does not exist")
			return
		}
		delete(f.records, parts[3])
		reply(http.StatusOK, map[string]string{"id": parts[3]})
	default:
		reply(http.StatusNotFound, nil, "no route "+r.Method+" "+r.URL.Path)
	}
}

func (f *fakeCloudflare) has(name, value string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.records {
		if r.Type == "TXT" && r.Name == name && r.Content == value {
			return true
		}
	}
	return false
}

// The ACME issuer only sees DNSClient: both providers must answer a DNS-01
// challenge the same way and refuse names outside their account.
func TestDNSClientsAnswerDNS01Challenges(t *testing.T) {
	pod := &fakeDNSPod{domains: []string{"cs.ac.cn"}}
	cf := &fakeCloudflare{token: "cf-token", zones: map[string]string{"mryao.org": "zone-mryao"}}
	cfSrv := httptest.NewServer(cf)
	t.Cleanup(cfSrv.Close)
	cases := []struct {
		name   string
		client DNSClient
		base   string // workspace base domain
		zone   string // the zone handle the provider returns
		has    func(name, value string) bool
	}{
		{"dnspod", newTestDNSPod(t, pod), "home.agent.ucas.cs.ac.cn", "cs.ac.cn", pod.has},
		{"cloudflare", &CloudflareClient{Token: "cf-token", BaseURL: cfSrv.URL}, "home.agent.mryao.org", "zone-mryao", cf.has},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			name := "_acme-challenge." + tc.base
			zone, err := tc.client.ZoneFor(ctx, name)
			if err != nil || zone != tc.zone {
				t.Fatalf("ZoneFor(%s) = %q, %v; want %q", name, zone, err, tc.zone)
			}
			id, err := tc.client.CreateRecord(ctx, zone, DNSRecord{Type: "TXT", Name: name, Content: "challenge-1", TTL: 60})
			if err != nil || id == "" {
				t.Fatalf("CreateRecord: %q %v", id, err)
			}
			// A wildcard and its base share the record name: two values coexist.
			id2, err := tc.client.CreateRecord(ctx, zone, DNSRecord{Type: "TXT", Name: name, Content: "challenge-2", TTL: 60})
			if err != nil || id2 == id {
				t.Fatalf("second CreateRecord: %q %v", id2, err)
			}
			if !tc.has(name, "challenge-1") || !tc.has(name, "challenge-2") {
				t.Fatal("the challenge records were not created")
			}
			if err := tc.client.DeleteRecord(ctx, zone, id); err != nil {
				t.Fatalf("DeleteRecord: %v", err)
			}
			if tc.has(name, "challenge-1") || !tc.has(name, "challenge-2") {
				t.Fatal("DeleteRecord must remove exactly its own record")
			}
			if err := tc.client.DeleteRecord(ctx, zone, id2); err != nil {
				t.Fatalf("DeleteRecord: %v", err)
			}
			if _, err := tc.client.ZoneFor(ctx, "_acme-challenge.home.example.net"); err == nil {
				t.Fatal("a name outside the account must not resolve to a zone")
			}
		})
	}
}

func TestCloudflareErrorsNameTheAPIButNotTheToken(t *testing.T) {
	cf := &fakeCloudflare{token: "right-token", zones: map[string]string{"mryao.org": "zone-mryao"}}
	srv := httptest.NewServer(cf)
	t.Cleanup(srv.Close)
	c := &CloudflareClient{Token: "wrong-token-must-not-leak", BaseURL: srv.URL}
	_, err := c.ZoneFor(context.Background(), "_acme-challenge.home.agent.mryao.org")
	if err == nil || !strings.Contains(err.Error(), "Invalid API Token") || strings.Contains(err.Error(), "wrong-token-must-not-leak") {
		t.Fatalf("error: %v", err)
	}
}

type stubIssuer string

func (s stubIssuer) Issue(context.Context, []string) ([]byte, []byte, time.Time, time.Time, error) {
	return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("stub %s", string(s))
}

// One agentserver serves workspaces in zones of different DNS providers: the
// base domain selects the provider whose zone holds it (the longest zone
// wins, so a delegated subzone can use another provider).
func TestCertManagerPicksTheProviderByDomain(t *testing.T) {
	m := NewCertManager(nil, map[string]Issuer{"dnspod": stubIssuer("dnspod"), "cloudflare": stubIssuer("cloudflare")},
		map[string]string{"cs.ac.cn": "dnspod", "mryao.org": "cloudflare", "lab.agent.ucas.cs.ac.cn": "selfsigned"}, "selfsigned", nil)
	for domain, want := range map[string]string{
		"home.agent.ucas.cs.ac.cn":  "dnspod",
		"cs.ac.cn":                  "dnspod",
		"lab.agent.ucas.cs.ac.cn":   "selfsigned",
		"x.lab.agent.ucas.cs.ac.cn": "selfsigned",
		"home.agent.mryao.org":      "cloudflare",
		"HOME.Agent.MRYAO.org.":     "cloudflare",
		"xmryao.org":                "selfsigned",
		"home.agentsrv.example.net": "selfsigned",
	} {
		if got := m.ProviderFor(domain); got != want {
			t.Errorf("ProviderFor(%s) = %q, want %q", domain, got, want)
		}
	}
	is, name, err := m.issuerFor(store.Workspace{Name: "home", BaseDomain: "home.agent.mryao.org"})
	if err != nil || name != "cloudflare" || is != Issuer(stubIssuer("cloudflare")) {
		t.Fatalf("issuer for home: %v %q %v", is, name, err)
	}
	if _, _, err := NewCertManager(nil, nil, map[string]string{"cs.ac.cn": "route53"}, "selfsigned", nil).issuerFor(store.Workspace{Name: "x", BaseDomain: "x.cs.ac.cn"}); err == nil {
		t.Fatal("a zone naming an unconfigured provider must be an error")
	}
}
