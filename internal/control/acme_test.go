package control

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"agentd/internal/pgtest"
	"agentd/internal/store"
)

// memDNS is an in-memory DNSClient for one zone.
type memDNS struct {
	zone string

	mu      sync.Mutex
	records map[string]DNSRecord
	next    int
}

func (m *memDNS) ZoneFor(_ context.Context, name string) (string, error) {
	if !inZone(strings.TrimSuffix(name, "."), m.zone) {
		return "", fmt.Errorf("no zone holds %s", name)
	}
	return m.zone, nil
}

func (m *memDNS) CreateRecord(_ context.Context, zone string, r DNSRecord) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if zone != m.zone {
		return "", fmt.Errorf("unknown zone %s", zone)
	}
	if m.records == nil {
		m.records = map[string]DNSRecord{}
	}
	m.next++
	r.ID = fmt.Sprint(m.next)
	m.records[r.ID] = r
	return r.ID, nil
}

func (m *memDNS) DeleteRecord(_ context.Context, zone, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.records[id]; !ok || zone != m.zone {
		return fmt.Errorf("no record %s in %s", id, zone)
	}
	delete(m.records, id)
	return nil
}

func (m *memDNS) txt(name string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, r := range m.records {
		if r.Type == "TXT" && r.Name == name {
			out = append(out, r.Content)
		}
	}
	return out
}

func (m *memDNS) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.records)
}

// fakeACME is a small RFC 8555 CA. It checks nonces and JWS signatures,
// validates dns-01 challenges against the records in its DNS clients and,
// with eab set, behaves like Google Trust Services: a new account needs an
// external account binding, an EAB key registers one account and is spent,
// and a spent EAB key is refused even next to a registered account key.
type fakeACME struct {
	srv *httptest.Server
	dns []*memDNS
	eab map[string][]byte // EAB key id -> HMAC key; nil: no binding required
	// lookupDelay holds back "no such account" answers, so that clients
	// looking an account up at the same time all hear it does not exist.
	lookupDelay time.Duration

	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate

	mu            sync.Mutex
	n             int
	nonces        map[string]bool
	accounts      map[string]crypto.PublicKey // account URL -> key
	byThumbprint  map[string]string           // key thumbprint -> account URL
	spent         map[string]bool             // EAB key ids bound to an account
	orders        map[string]*fakeOrder
	authzs        map[string]*fakeAuthz
	registrations int
}

type fakeAuthz struct {
	account, domain, token, status string
	wildcard                       bool
}

type fakeOrder struct {
	account string
	names   []string
	authzs  []string
	chain   []byte
}

func newFakeACME(t *testing.T, eab map[string][]byte, dns ...*memDNS) *fakeACME {
	t.Helper()
	f := &fakeACME{dns: dns, eab: eab, nonces: map[string]bool{}, accounts: map[string]crypto.PublicKey{},
		byThumbprint: map[string]string{}, spent: map[string]bool{}, orders: map[string]*fakeOrder{}, authzs: map[string]*fakeAuthz{}}
	var err error
	if f.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake ACME CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.caKey.PublicKey, f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	if f.caCert, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// issuer returns an ACMEIssuer for this CA with a short propagation wait.
func (f *fakeACME) issuer(st *store.Store, dns DNSClient) *ACMEIssuer {
	return &ACMEIssuer{Store: st, Directory: f.srv.URL + "/directory", Email: "ops@example.test", DNS: dns,
		PropagationWait: time.Millisecond, http: f.srv.Client()}
}

func (f *fakeACME) regs() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registrations
}

type jwsJSON struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type jwsHeader struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	KID   string          `json:"kid"`
	JWK   json.RawMessage `json:"jwk"`
}

func parseJWK(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var k struct{ Kty, Crv, X, Y string }
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported jwk %s %s", k.Kty, k.Crv)
	}
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err := errors.Join(err1, err2); err != nil {
		return nil, err
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), slices.Concat([]byte{4}, x, y))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail})
}

func (f *fakeACME) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	nonce := fmt.Sprintf("nonce-%d", f.n)
	f.nonces[nonce] = true
	w.Header().Set("Replay-Nonce", nonce)
	base := f.srv.URL
	switch r.URL.Path {
	case "/directory":
		writeJSON(w, http.StatusOK, map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/account",
			"newOrder": base + "/order", "meta": map[string]any{"externalAccountRequired": f.eab != nil}})
		return
	case "/nonce":
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		problem(w, http.StatusMethodNotAllowed, "malformed", "POST only")
		return
	}
	var msg jwsJSON
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		problem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	ph, _ := base64.RawURLEncoding.DecodeString(msg.Protected)
	var hdr jwsHeader
	if err := json.Unmarshal(ph, &hdr); err != nil {
		problem(w, http.StatusBadRequest, "malformed", "protected header: "+err.Error())
		return
	}
	if !f.nonces[hdr.Nonce] {
		problem(w, http.StatusBadRequest, "badNonce", "unknown nonce")
		return
	}
	delete(f.nonces, hdr.Nonce)
	if hdr.URL != base+r.URL.Path {
		problem(w, http.StatusBadRequest, "unauthorized", "url "+hdr.URL+" does not match the request")
		return
	}
	var pub *ecdsa.PublicKey
	switch {
	case hdr.KID != "" && hdr.JWK == nil:
		k, ok := f.accounts[hdr.KID].(*ecdsa.PublicKey)
		if !ok {
			problem(w, http.StatusBadRequest, "accountDoesNotExist", "no account "+hdr.KID)
			return
		}
		pub = k
	case hdr.KID == "" && hdr.JWK != nil && r.URL.Path == "/account":
		k, err := parseJWK(hdr.JWK)
		if err != nil {
			problem(w, http.StatusBadRequest, "badPublicKey", err.Error())
			return
		}
		pub = k
	default:
		problem(w, http.StatusBadRequest, "malformed", "a request carries exactly one of kid and jwk (jwk on newAccount only)")
		return
	}
	sig, _ := base64.RawURLEncoding.DecodeString(msg.Signature)
	digest := sha256.Sum256([]byte(msg.Protected + "." + msg.Payload))
	if hdr.Alg != "ES256" || len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		problem(w, http.StatusUnauthorized, "unauthorized", "bad JWS signature")
		return
	}
	payload, _ := base64.RawURLEncoding.DecodeString(msg.Payload)
	path := r.URL.Path
	switch {
	case path == "/account":
		f.newAccount(w, hdr, pub, payload)
	case path == "/order":
		f.newOrder(w, hdr.KID, payload)
	case strings.HasPrefix(path, "/authz/"):
		az, ok := f.authzs[base+path]
		if !ok || az.account != hdr.KID {
			problem(w, http.StatusNotFound, "malformed", "no authorization "+path)
			return
		}
		writeJSON(w, http.StatusOK, f.authzJSON(base+path, az))
	case strings.HasPrefix(path, "/chal/"):
		f.validate(w, hdr.KID, base+strings.Replace(path, "/chal/", "/authz/", 1))
	case strings.HasSuffix(path, "/finalize"):
		f.finalize(w, hdr.KID, base+strings.TrimSuffix(path, "/finalize"), payload)
	case strings.HasSuffix(path, "/cert"):
		o, ok := f.orders[base+strings.TrimSuffix(path, "/cert")]
		if !ok || o.account != hdr.KID || o.chain == nil {
			problem(w, http.StatusNotFound, "malformed", "no certificate "+path)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(o.chain)
	case strings.HasPrefix(path, "/orders/"):
		o, ok := f.orders[base+path]
		if !ok || o.account != hdr.KID {
			problem(w, http.StatusNotFound, "malformed", "no order "+path)
			return
		}
		writeJSON(w, http.StatusOK, f.orderJSON(base+path, o))
	default:
		problem(w, http.StatusNotFound, "malformed", "no route "+path)
	}
}

func (f *fakeACME) newAccount(w http.ResponseWriter, hdr jwsHeader, pub *ecdsa.PublicKey, payload []byte) {
	var req struct {
		Contact            []string `json:"contact"`
		OnlyReturnExisting bool     `json:"onlyReturnExisting"`
		EAB                *jwsJSON `json:"externalAccountBinding"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		problem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	tp, _ := acme.JWKThumbprint(pub)
	existing, known := f.byThumbprint[tp]
	if req.OnlyReturnExisting {
		if !known {
			f.mu.Unlock()
			time.Sleep(f.lookupDelay)
			f.mu.Lock()
			problem(w, http.StatusBadRequest, "accountDoesNotExist", "no account for this key")
			return
		}
		w.Header().Set("Location", existing)
		writeJSON(w, http.StatusOK, map[string]any{"status": "valid"})
		return
	}
	if f.eab != nil {
		if req.EAB == nil {
			problem(w, http.StatusBadRequest, "externalAccountRequired", "this CA requires an external account binding")
			return
		}
		kid, err := f.checkEAB(req.EAB, pub)
		if err != nil {
			problem(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		if f.spent[kid] {
			problem(w, http.StatusUnauthorized, "unauthorized", "external account key "+kid+" is already bound to an account")
			return
		}
		if !known {
			f.spent[kid] = true
		}
	}
	if known {
		w.Header().Set("Location", existing)
		writeJSON(w, http.StatusOK, map[string]any{"status": "valid"})
		return
	}
	u := fmt.Sprintf("%s/acct/%d", f.srv.URL, len(f.accounts)+1)
	f.accounts[u] = pub
	f.byThumbprint[tp] = u
	f.registrations++
	w.Header().Set("Location", u)
	writeJSON(w, http.StatusCreated, map[string]any{"status": "valid", "contact": req.Contact})
}

// checkEAB verifies an external account binding (RFC 8555 7.3.4): an HS256
// JWS by the EAB key over the account key, addressed to newAccount.
func (f *fakeACME) checkEAB(e *jwsJSON, account *ecdsa.PublicKey) (string, error) {
	ph, _ := base64.RawURLEncoding.DecodeString(e.Protected)
	var h struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(ph, &h); err != nil {
		return "", fmt.Errorf("binding header: %w", err)
	}
	key, ok := f.eab[h.KID]
	if !ok || h.Alg != "HS256" || h.URL != f.srv.URL+"/account" {
		return "", fmt.Errorf("bad binding header %+v", h)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(e.Protected + "." + e.Payload))
	sig, _ := base64.RawURLEncoding.DecodeString(e.Signature)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", errors.New("bad binding signature")
	}
	inner, _ := base64.RawURLEncoding.DecodeString(e.Payload)
	bound, err := parseJWK(inner)
	if err != nil || !bound.Equal(account) {
		return "", errors.New("the binding covers another account key")
	}
	return h.KID, nil
}

func (f *fakeACME) newOrder(w http.ResponseWriter, account string, payload []byte) {
	var req struct {
		Identifiers []struct{ Type, Value string } `json:"identifiers"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || len(req.Identifiers) == 0 {
		problem(w, http.StatusBadRequest, "malformed", "identifiers")
		return
	}
	o := &fakeOrder{account: account}
	for _, id := range req.Identifiers {
		domain := strings.TrimPrefix(id.Value, "*.")
		token := make([]byte, 16)
		_, _ = rand.Read(token)
		u := fmt.Sprintf("%s/authz/%d", f.srv.URL, len(f.authzs)+1)
		f.authzs[u] = &fakeAuthz{account: account, domain: domain, wildcard: domain != id.Value,
			token: base64.RawURLEncoding.EncodeToString(token), status: "pending"}
		o.names = append(o.names, id.Value)
		o.authzs = append(o.authzs, u)
	}
	u := fmt.Sprintf("%s/orders/%d", f.srv.URL, len(f.orders)+1)
	f.orders[u] = o
	w.Header().Set("Location", u)
	writeJSON(w, http.StatusCreated, f.orderJSON(u, o))
}

func (f *fakeACME) orderStatus(o *fakeOrder) string {
	if o.chain != nil {
		return "valid"
	}
	status := "ready"
	for _, u := range o.authzs {
		switch f.authzs[u].status {
		case "invalid":
			return "invalid"
		case "pending":
			status = "pending"
		}
	}
	return status
}

func (f *fakeACME) orderJSON(u string, o *fakeOrder) map[string]any {
	ids := []map[string]string{}
	for _, n := range o.names {
		ids = append(ids, map[string]string{"type": "dns", "value": n})
	}
	out := map[string]any{"status": f.orderStatus(o), "identifiers": ids, "authorizations": o.authzs, "finalize": u + "/finalize"}
	if o.chain != nil {
		out["certificate"] = u + "/cert"
	}
	return out
}

func (f *fakeACME) authzJSON(u string, az *fakeAuthz) map[string]any {
	chal := map[string]any{"type": "dns-01", "url": strings.Replace(u, "/authz/", "/chal/", 1), "token": az.token, "status": az.status}
	if az.status == "invalid" {
		chal["error"] = map[string]string{"type": "urn:ietf:params:acme:error:incorrectResponse", "detail": "no matching TXT record"}
	}
	return map[string]any{"status": az.status, "identifier": map[string]string{"type": "dns", "value": az.domain},
		"wildcard": az.wildcard, "challenges": []any{chal}}
}

// validate answers a challenge: the authorization is valid when a TXT
// record at _acme-challenge.<domain> holds the key authorization digest.
func (f *fakeACME) validate(w http.ResponseWriter, account, authzURL string) {
	az, ok := f.authzs[authzURL]
	if !ok || az.account != account {
		problem(w, http.StatusNotFound, "malformed", "no challenge")
		return
	}
	tp, _ := acme.JWKThumbprint(f.accounts[account])
	sum := sha256.Sum256([]byte(az.token + "." + tp))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	az.status = "invalid"
	for _, d := range f.dns {
		if slices.Contains(d.txt("_acme-challenge."+az.domain), want) {
			az.status = "valid"
		}
	}
	writeJSON(w, http.StatusOK, f.authzJSON(authzURL, az)["challenges"].([]any)[0])
}

func (f *fakeACME) finalize(w http.ResponseWriter, account, orderURL string, payload []byte) {
	o, ok := f.orders[orderURL]
	if !ok || o.account != account {
		problem(w, http.StatusNotFound, "malformed", "no order")
		return
	}
	if f.orderStatus(o) != "ready" {
		problem(w, http.StatusForbidden, "orderNotReady", "order is "+f.orderStatus(o))
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	_ = json.Unmarshal(payload, &req)
	der, _ := base64.RawURLEncoding.DecodeString(req.CSR)
	csr, err := x509.ParseCertificateRequest(der)
	if err == nil {
		err = csr.CheckSignature()
	}
	if err != nil || !slices.Equal(slices.Sorted(slices.Values(csr.DNSNames)), slices.Sorted(slices.Values(o.names))) {
		problem(w, http.StatusBadRequest, "badCSR", fmt.Sprintf("csr %v does not match the order %v (%v)", csr, o.names, err))
		return
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(f.n)), Subject: pkix.Name{CommonName: o.names[0]}, DNSNames: csr.DNSNames,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		problem(w, http.StatusInternalServerError, "serverInternal", err.Error())
		return
	}
	o.chain = slices.Concat(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw}))
	w.Header().Set("Location", orderURL)
	writeJSON(w, http.StatusOK, f.orderJSON(orderURL, o))
}

// forgetACMEAccounts makes the next issuance look its account up again, as
// after a restart.
func forgetACMEAccounts() {
	acmeAccounts.Lock()
	defer acmeAccounts.Unlock()
	clear(acmeAccounts.ready)
}

func acmeStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), pgtest.NewDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

// checkChain verifies that chain is a certificate for base and *.base
// issued by the fake CA.
func checkChain(t *testing.T, ca *fakeACME, chain []byte, base string) {
	t.Helper()
	blk, rest := pem.Decode(chain)
	if blk == nil {
		t.Fatalf("no certificate in %q", chain)
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if next, _ := pem.Decode(rest); next == nil || string(next.Bytes) != string(ca.caCert.Raw) {
		t.Fatal("the chain does not include the issuer")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.caCert)
	for _, name := range []string{base, "svc." + base} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestACMEIssuerRegistersOnceWithAnExternalAccountBinding(t *testing.T) {
	ctx := context.Background()
	st := acmeStore(t)
	cs, mryao := &memDNS{zone: "cs.ac.cn"}, &memDNS{zone: "mryao.org"}
	ca := newFakeACME(t, map[string][]byte{"kid-1": []byte("an HMAC key from the CA, 32 bytes")}, cs, mryao)
	eab := &acme.ExternalAccountBinding{KID: "kid-1", Key: ca.eab["kid-1"]}
	ca.lookupDelay = 100 * time.Millisecond
	dnspod, cloudflare := ca.issuer(st, cs), ca.issuer(st, mryao)
	dnspod.EAB, cloudflare.EAB = eab, eab

	// Two providers with the same CA and email share one account. Issuing
	// through both at once registers it once: the EAB key is single-use.
	jobs := []struct {
		is   *ACMEIssuer
		base string
	}{{dnspod, "home.agent.ucas.cs.ac.cn"}, {cloudflare, "lab.mryao.org"}, {dnspod, "ops.agent.ucas.cs.ac.cn"}}
	chains, errs := make([][]byte, len(jobs)), make([]error, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Go(func() {
			chains[i], _, _, _, errs[i] = j.is.Issue(ctx, []string{"*." + j.base, j.base})
		})
	}
	wg.Wait()
	for i, j := range jobs {
		if errs[i] != nil {
			t.Fatalf("%s: %v", j.base, errs[i])
		}
		checkChain(t, ca, chains[i], j.base)
	}
	if n := ca.regs(); n != 1 {
		t.Fatalf("%d accounts registered, want 1", n)
	}
	if cs.len() != 0 || mryao.len() != 0 {
		t.Fatalf("challenge records left behind: %d in cs.ac.cn, %d in mryao.org", cs.len(), mryao.len())
	}

	// After a restart the stored account key is looked up, not registered
	// again: this CA refuses a spent EAB key even for a known account key.
	forgetACMEAccounts()
	again := ca.issuer(st, cs)
	again.EAB = eab
	chain, _, _, _, err := again.Issue(ctx, []string{"*.home.agent.ucas.cs.ac.cn", "home.agent.ucas.cs.ac.cn"})
	if err != nil {
		t.Fatalf("issuing after a restart: %v", err)
	}
	checkChain(t, ca, chain, "home.agent.ucas.cs.ac.cn")
	if n := ca.regs(); n != 1 {
		t.Fatalf("%d accounts registered after the restart, want 1", n)
	}
}

func TestACMEIssuerNamesTheMissingExternalAccountBinding(t *testing.T) {
	st := acmeStore(t)
	cs := &memDNS{zone: "cs.ac.cn"}
	ca := newFakeACME(t, map[string][]byte{"kid-1": []byte("an HMAC key from the CA, 32 bytes")}, cs)
	_, _, _, _, err := ca.issuer(st, cs).Issue(context.Background(), []string{"*.home.cs.ac.cn", "home.cs.ac.cn"})
	if err == nil || !strings.Contains(err.Error(), "eab_key_id_env") {
		t.Fatalf("a CA that requires EAB must ask for it: %v", err)
	}
	if ca.regs() != 0 || cs.len() != 0 {
		t.Fatalf("registrations %d, records %d", ca.regs(), cs.len())
	}
}

func TestACMEIssuerReportsAFailedChallenge(t *testing.T) {
	st := acmeStore(t)
	cs := &memDNS{zone: "cs.ac.cn"}
	ca := newFakeACME(t, nil) // looks in no DNS: every challenge fails
	_, _, _, _, err := ca.issuer(st, cs).Issue(context.Background(), []string{"*.home.cs.ac.cn", "home.cs.ac.cn"})
	if err == nil || !strings.Contains(err.Error(), "acme authorization") {
		t.Fatalf("a failed challenge must fail issuance: %v", err)
	}
	if cs.len() != 0 {
		t.Fatalf("%d challenge records left behind", cs.len())
	}
}

func TestACMEIssuerUsesAConfiguredAccountKey(t *testing.T) {
	ctx := context.Background()
	st := acmeStore(t)
	cs := &memDNS{zone: "cs.ac.cn"}
	ca := newFakeACME(t, map[string][]byte{"kid-1": []byte("an HMAC key from the CA, 32 bytes")}, cs)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first := ca.issuer(st, cs)
	first.AccountKey = key
	first.EAB = &acme.ExternalAccountBinding{KID: "kid-1", Key: ca.eab["kid-1"]}
	if _, _, _, _, err := first.Issue(ctx, []string{"*.home.cs.ac.cn", "home.cs.ac.cn"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ACMEAccountKey(ctx, first.Directory+"|"+first.Email); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a configured account key must not be stored: %v", err)
	}
	// The same key without the (now spent) EAB key, as with a new state
	// database, finds its account.
	forgetACMEAccounts()
	second := ca.issuer(acmeStore(t), cs)
	second.AccountKey = key
	if _, _, _, _, err := second.Issue(ctx, []string{"*.home.cs.ac.cn", "home.cs.ac.cn"}); err != nil {
		t.Fatalf("issuing with the configured key again: %v", err)
	}
	if n := ca.regs(); n != 1 {
		t.Fatalf("%d accounts registered, want 1", n)
	}
}

func TestParseACMEAccountKey(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	block := func(typ string, der []byte, err error) []byte {
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	}
	sec1, err := x509.MarshalECPrivateKey(ec)
	ok := map[string]struct {
		pem  []byte
		want crypto.Signer
	}{
		"sec1":      {block("EC PRIVATE KEY", sec1, err), ec},
		"pkcs8 ec":  {block("PRIVATE KEY", mustPKCS8(t, ec), nil), ec},
		"pkcs1":     {block("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk), nil), rk},
		"pkcs8 rsa": {block("PRIVATE KEY", mustPKCS8(t, rk), nil), rk},
		"cert-manager tls.key with trailing data": {append(block("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk), nil), "\n"...), rk},
	}
	for name, c := range ok {
		got, err := ParseACMEAccountKey(c.pem)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !got.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(c.want.Public()) {
			t.Errorf("%s: parsed another key", name)
		}
	}
	for name, b := range map[string][]byte{
		"not pem":     []byte("hello"),
		"ed25519":     block("PRIVATE KEY", mustPKCS8(t, ed), nil),
		"certificate": block("CERTIFICATE", []byte{1, 2, 3}, nil),
		"broken":      block("EC PRIVATE KEY", []byte{1, 2, 3}, nil),
	} {
		if _, err := ParseACMEAccountKey(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustPKCS8(t *testing.T, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestDecodeEABKey(t *testing.T) {
	key := []byte{0xfb, 0xff, 0xfe, 0x01, 0x02, 0x03, 0x04}
	for _, s := range []string{
		base64.RawURLEncoding.EncodeToString(key),
		base64.URLEncoding.EncodeToString(key),
		base64.StdEncoding.EncodeToString(key),
		" " + base64.RawURLEncoding.EncodeToString(key) + "\n",
	} {
		got, err := DecodeEABKey(s)
		if err != nil || string(got) != string(key) {
			t.Errorf("DecodeEABKey(%q) = %x, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "====", "not base64!"} {
		if _, err := DecodeEABKey(s); err == nil {
			t.Errorf("DecodeEABKey(%q) accepted", s)
		}
	}
}
