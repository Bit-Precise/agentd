package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeDNSPod answers the DNSPod API 3.0 actions the ACME issuer uses, in the
// API's JSON envelope ({"Response": {...}}).
type fakeDNSPod struct {
	domains []string
	fail    map[string][2]string // action -> error code, message

	mu      sync.Mutex
	calls   []dnspodCall
	records map[uint64]map[string]any // RecordId -> CreateRecord parameters
	next    uint64
}

type dnspodCall struct {
	Action, Version, Auth string
	Params                map[string]any
}

func (f *fakeDNSPod) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	params := map[string]any{}
	_ = json.Unmarshal(body, &params)
	action := r.Header.Get("X-TC-Action")
	f.mu.Lock()
	f.calls = append(f.calls, dnspodCall{Action: action, Version: r.Header.Get("X-TC-Version"), Auth: r.Header.Get("Authorization"), Params: params})
	f.mu.Unlock()
	respond := func(v map[string]any) {
		v["RequestId"] = "req-1"
		_ = json.NewEncoder(w).Encode(map[string]any{"Response": v})
	}
	if e, ok := f.fail[action]; ok {
		respond(map[string]any{"Error": map[string]any{"Code": e[0], "Message": e[1]}})
		return
	}
	num := func(k string, def int) int {
		if v, ok := params[k].(float64); ok {
			return int(v)
		}
		return def
	}
	switch action {
	case "DescribeDomainList":
		off, lim := num("Offset", 0), num("Limit", 20)
		var page []map[string]any
		for i := off; i < len(f.domains) && i < off+lim; i++ {
			page = append(page, map[string]any{"DomainId": i + 1, "Name": f.domains[i], "Status": "ENABLE"})
		}
		respond(map[string]any{"DomainCountInfo": map[string]any{"AllTotal": len(f.domains), "DomainTotal": len(f.domains)}, "DomainList": page})
	case "CreateRecord":
		f.mu.Lock()
		if f.records == nil {
			f.records, f.next = map[uint64]map[string]any{}, 12345
		}
		id := f.next
		f.next++
		f.records[id] = params
		f.mu.Unlock()
		respond(map[string]any{"RecordId": id})
	case "DeleteRecord":
		id := uint64(num("RecordId", 0))
		f.mu.Lock()
		_, ok := f.records[id]
		delete(f.records, id)
		f.mu.Unlock()
		if !ok {
			respond(map[string]any{"Error": map[string]any{"Code": "InvalidParameter.RecordIdInvalid", "Message": "no such record"}})
			return
		}
		respond(map[string]any{})
	default:
		respond(map[string]any{"Error": map[string]any{"Code": "InvalidAction", "Message": action}})
	}
}

func (f *fakeDNSPod) recorded() []dnspodCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dnspodCall(nil), f.calls...)
}

const testDNSPodSecret = "test-secret-key-must-not-leak"

func newTestDNSPod(t *testing.T, f *fakeDNSPod) *DNSPodClient {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &DNSPodClient{SecretID: "AKIDtest", SecretKey: testDNSPodSecret,
		Endpoint: strings.TrimPrefix(srv.URL, "http://"), Scheme: "HTTP", PageSize: 2}
}

func TestDNSPodZoneForPicksTheLongestZoneInTheAccount(t *testing.T) {
	f := &fakeDNSPod{domains: []string{"example.org", "cs.ac.cn", "a.test", "ucas.cs.ac.cn", "xcs.ac.cn"}}
	c := newTestDNSPod(t, f)
	ctx := context.Background()
	for name, want := range map[string]string{
		"_acme-challenge.home.agent.ucas.cs.ac.cn": "ucas.cs.ac.cn",
		"_acme-challenge.home.agent.cs.ac.cn":      "cs.ac.cn",
		"_acme-challenge.cs.ac.cn.":                "cs.ac.cn",
		"_acme-challenge.web.xcs.ac.cn":            "xcs.ac.cn",
		"cs.ac.cn":                                 "cs.ac.cn",
	} {
		if got, err := c.ZoneFor(ctx, name); err != nil || got != want {
			t.Errorf("ZoneFor(%s) = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := c.ZoneFor(ctx, "_acme-challenge.app.example.com"); err == nil || !strings.Contains(err.Error(), "no DNSPod zone") {
		t.Fatalf("a name outside every zone: %v", err)
	}
	// Five domains with a page size of 2 take three requests per lookup.
	var offsets []string
	for _, call := range f.recorded()[:3] {
		if call.Action != "DescribeDomainList" || call.Version != "2021-03-23" ||
			!strings.HasPrefix(call.Auth, "TC3-HMAC-SHA256 Credential=AKIDtest/") || call.Params["Limit"] != float64(2) {
			t.Fatalf("unexpected request %+v", call)
		}
		offsets = append(offsets, fmt.Sprint(call.Params["Offset"]))
	}
	if strings.Join(offsets, ",") != "0,2,4" {
		t.Fatalf("pagination offsets %v", offsets)
	}
}

func TestDNSPodCreatesAndDeletesChallengeRecords(t *testing.T) {
	f := &fakeDNSPod{domains: []string{"cs.ac.cn"}}
	c := newTestDNSPod(t, f)
	ctx := context.Background()
	id, err := c.CreateRecord(ctx, "cs.ac.cn", DNSRecord{Type: "TXT", Name: "_acme-challenge.home.agent.ucas.cs.ac.cn", Content: "tok-1", TTL: 60})
	if err != nil || id != "12345" {
		t.Fatalf("create: %q %v", id, err)
	}
	if err := c.DeleteRecord(ctx, "cs.ac.cn", id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.CreateRecord(ctx, "cs.ac.cn", DNSRecord{Type: "TXT", Name: "cs.ac.cn", Content: "tok-2", TTL: 3600}); err != nil {
		t.Fatalf("create at the apex: %v", err)
	}
	calls := f.recorded()
	if len(calls) != 3 {
		t.Fatalf("calls: %+v", calls)
	}
	want := map[string]any{"Domain": "cs.ac.cn", "SubDomain": "_acme-challenge.home.agent.ucas", "RecordType": "TXT",
		"RecordLine": "默认", "Value": "tok-1", "TTL": float64(600)}
	for k, v := range want {
		if calls[0].Action != "CreateRecord" || calls[0].Params[k] != v {
			t.Fatalf("create %s = %v, want %v (%+v)", k, calls[0].Params[k], v, calls[0])
		}
	}
	if calls[1].Action != "DeleteRecord" || calls[1].Params["Domain"] != "cs.ac.cn" || calls[1].Params["RecordId"] != float64(12345) {
		t.Fatalf("delete request %+v", calls[1])
	}
	if calls[2].Params["SubDomain"] != "@" || calls[2].Params["TTL"] != float64(3600) {
		t.Fatalf("apex record request %+v", calls[2])
	}
}

func TestDNSPodRejectsBadInputWithoutCallingTheAPI(t *testing.T) {
	f := &fakeDNSPod{domains: []string{"cs.ac.cn"}}
	c := newTestDNSPod(t, f)
	ctx := context.Background()
	if _, err := c.CreateRecord(ctx, "cs.ac.cn", DNSRecord{Type: "TXT", Name: "_acme-challenge.example.org", Content: "x"}); err == nil {
		t.Fatal("a record outside its zone must be rejected")
	}
	if _, err := c.CreateRecord(ctx, "cs.ac.cn", DNSRecord{Type: "TXT", Name: "_acme-challenge.xcs.ac.cn", Content: "x"}); err == nil {
		t.Fatal("a suffix that is not a whole label must be rejected")
	}
	if err := c.DeleteRecord(ctx, "cs.ac.cn", "not-a-number"); err == nil {
		t.Fatal("a non-numeric record id must be rejected")
	}
	if calls := f.recorded(); len(calls) != 0 {
		t.Fatalf("no request should reach the API: %+v", calls)
	}
}

func TestDNSPodErrorsNameTheActionButNotTheSecret(t *testing.T) {
	f := &fakeDNSPod{domains: []string{"cs.ac.cn"}, fail: map[string][2]string{
		"CreateRecord":       {"AuthFailure.SignatureFailure", "The provided credentials could not be validated."},
		"DescribeDomainList": {"RequestLimitExceeded", "too many requests"},
	}}
	c := newTestDNSPod(t, f)
	ctx := context.Background()
	_, err := c.CreateRecord(ctx, "cs.ac.cn", DNSRecord{Type: "TXT", Name: "_acme-challenge.a.cs.ac.cn", Content: "x"})
	if err == nil || !strings.Contains(err.Error(), "CreateRecord") || !strings.Contains(err.Error(), "AuthFailure.SignatureFailure") {
		t.Fatalf("create error: %v", err)
	}
	_, zerr := c.ZoneFor(ctx, "_acme-challenge.a.cs.ac.cn")
	if zerr == nil || !strings.Contains(zerr.Error(), "RequestLimitExceeded") {
		t.Fatalf("zone error: %v", zerr)
	}
	for _, e := range []error{err, zerr} {
		if strings.Contains(e.Error(), testDNSPodSecret) {
			t.Fatalf("error leaks the secret key: %v", e)
		}
	}
}

// Both providers answer DNS-01 challenges for the ACME issuer.
var (
	_ DNSClient = (*DNSPodClient)(nil)
	_ DNSClient = (*CloudflareClient)(nil)
)

// has reports whether a record name (fully qualified) holds value.
func (f *fakeDNSPod) has(name, value string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.records {
		fqdn := r["SubDomain"].(string) + "." + r["Domain"].(string)
		if r["SubDomain"] == "@" {
			fqdn = r["Domain"].(string)
		}
		if fqdn == name && r["Value"] == value && r["RecordType"] == "TXT" {
			return true
		}
	}
	return false
}
