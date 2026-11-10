package control

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"agentd/internal/store"
)

// LetsEncrypt is the production ACME directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// GoogleTrustServices is the production ACME directory of Google Trust
// Services. It requires an external account binding (EAB).
const GoogleTrustServices = "https://dv.acme-v02.api.pki.goog/directory"

// DNSClient manages the records that answer ACME DNS-01 challenges.
// CloudflareClient and DNSPodClient implement it.
type DNSClient interface {
	// ZoneFor returns the zone holding name, in the form the other
	// methods take.
	ZoneFor(ctx context.Context, name string) (string, error)
	// CreateRecord creates r, whose Name is fully qualified, and returns
	// the record's id.
	CreateRecord(ctx context.Context, zone string, r DNSRecord) (string, error)
	DeleteRecord(ctx context.Context, zone, id string) error
}

// ACMEIssuer obtains certificates with ACME DNS-01 challenges answered
// through a DNS provider (design 6.2).
type ACMEIssuer struct {
	Store           *store.Store
	Directory       string // default LetsEncrypt
	Email           string
	DNS             DNSClient
	PropagationWait time.Duration // default 30s
	// EAB binds a new account to the operator's account at a CA that
	// requires it (Google Trust Services, ZeroSSL). It is sent only when
	// the account key is not registered yet: at Google Trust Services an
	// EAB key registers one account and is spent.
	EAB *acme.ExternalAccountBinding
	// AccountKey is the ACME account key. When nil, a key is generated on
	// first use and kept sealed in the state database; issuers with the
	// same directory and email share it.
	AccountKey crypto.Signer

	http *http.Client // tests
}

// acmeAccounts serializes ACME account set-up across issuers, so that
// issuers sharing an account (same directory, same key) register it once
// and a single-use EAB key is never presented twice.
var acmeAccounts = struct {
	sync.Mutex
	ready map[string]bool // directory|key thumbprint
}{ready: map[string]bool{}}

func (a *ACMEIssuer) directory() string {
	if a.Directory == "" {
		return LetsEncrypt
	}
	return a.Directory
}

func (a *ACMEIssuer) accountKey(ctx context.Context) (crypto.Signer, error) {
	if a.AccountKey != nil {
		return a.AccountKey, nil
	}
	id := a.directory() + "|" + a.Email
	b, err := a.Store.ACMEAccountKey(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		k, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		der, _ := x509.MarshalECPrivateKey(k)
		// Another agentserver may have stored a key meanwhile; the first
		// one stored wins.
		b, err = a.Store.AddACMEAccountKey(ctx, id, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	}
	if err != nil {
		return nil, err
	}
	k, err := ParseACMEAccountKey(b)
	if err != nil {
		return nil, fmt.Errorf("stored ACME account key: %w", err)
	}
	return k, nil
}

// client returns an ACME client whose account exists at the CA, registering
// the account on first use.
func (a *ACMEIssuer) client(ctx context.Context) (*acme.Client, error) {
	acmeAccounts.Lock()
	defer acmeAccounts.Unlock()
	key, err := a.accountKey(ctx)
	if err != nil {
		return nil, err
	}
	cl := &acme.Client{Key: key, DirectoryURL: a.directory(), UserAgent: "agentserver/" + Version, HTTPClient: a.http}
	tp, err := acme.JWKThumbprint(key.Public())
	if err != nil {
		return nil, fmt.Errorf("ACME account key: %w", err)
	}
	id := a.directory() + "|" + tp
	if acmeAccounts.ready[id] {
		return cl, nil
	}
	// Look the key up before registering: a CA may refuse a spent EAB key
	// even when the account key itself is already registered.
	if _, err := cl.GetReg(ctx, ""); errors.Is(err, acme.ErrNoAccount) {
		if err := a.register(ctx, cl); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("acme account lookup: %w", err)
	}
	acmeAccounts.ready[id] = true
	return cl, nil
}

func (a *ACMEIssuer) register(ctx context.Context, cl *acme.Client) error {
	dir, err := cl.Discover(ctx)
	if err != nil {
		return fmt.Errorf("acme directory: %w", err)
	}
	if dir.ExternalAccountRequired && a.EAB == nil {
		return fmt.Errorf("the ACME CA at %s requires an external account binding: set eab_key_id_env and eab_hmac_key_env", a.directory())
	}
	acct := &acme.Account{ExternalAccountBinding: a.EAB}
	if a.Email != "" {
		acct.Contact = []string{"mailto:" + a.Email}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("acme register: %w", err)
	}
	return nil
}

// ParseACMEAccountKey parses a PEM ECDSA or RSA private key (SEC 1, PKCS #1
// or PKCS #8), the key types ACME account keys use.
func ParseACMEAccountKey(b []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not a PEM private key")
	}
	switch blk.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := k.(type) {
		case *ecdsa.PrivateKey:
			return k, nil
		case *rsa.PrivateKey:
			return k, nil
		}
		return nil, fmt.Errorf("unsupported key type %T: ACME account keys are ECDSA or RSA", k)
	}
	return nil, fmt.Errorf("unsupported PEM block %q", blk.Type)
}

// DecodeEABKey decodes an EAB HMAC key the way CAs hand it out: base64url,
// with or without padding (standard base64 is accepted too).
func DecodeEABKey(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, errors.New("not a base64url HMAC key")
}

// Issue runs an ACME order for names.
func (a *ACMEIssuer) Issue(ctx context.Context, names []string) ([]byte, []byte, time.Time, time.Time, error) {
	var zero time.Time
	if a.DNS == nil {
		return nil, nil, zero, zero, errors.New("acme issuer has no DNS provider")
	}
	cl, err := a.client(ctx)
	if err != nil {
		return nil, nil, zero, zero, err
	}
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return nil, nil, zero, zero, fmt.Errorf("acme order: %w", err)
	}
	type pending struct {
		zone, record string
		chal         *acme.Challenge
		authz        string
	}
	var todo []pending
	defer func() {
		for _, p := range todo {
			if p.record != "" {
				_ = a.DNS.DeleteRecord(context.Background(), p.zone, p.record)
			}
		}
	}()
	for _, u := range order.AuthzURLs {
		z, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return nil, nil, zero, zero, err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				chal = c
			}
		}
		if chal == nil {
			return nil, nil, zero, zero, fmt.Errorf("no dns-01 challenge for %s", z.Identifier.Value)
		}
		val, err := cl.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, nil, zero, zero, err
		}
		name := "_acme-challenge." + strings.TrimPrefix(z.Identifier.Value, "*.")
		zone, err := a.DNS.ZoneFor(ctx, name)
		if err != nil {
			return nil, nil, zero, zero, err
		}
		id, err := a.DNS.CreateRecord(ctx, zone, DNSRecord{Type: "TXT", Name: name, Content: val, TTL: 60})
		if err != nil {
			return nil, nil, zero, zero, err
		}
		todo = append(todo, pending{zone: zone, record: id, chal: chal, authz: z.URI})
	}
	wait := a.PropagationWait
	if wait == 0 {
		wait = 30 * time.Second
	}
	if len(todo) > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, nil, zero, zero, ctx.Err()
		}
	}
	for _, p := range todo {
		if _, err := cl.Accept(ctx, p.chal); err != nil {
			return nil, nil, zero, zero, fmt.Errorf("acme accept: %w", err)
		}
	}
	for _, p := range todo {
		if _, err := cl.WaitAuthorization(ctx, p.authz); err != nil {
			return nil, nil, zero, zero, fmt.Errorf("acme authorization: %w", err)
		}
	}
	if order, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return nil, nil, zero, zero, fmt.Errorf("acme order: %w", err)
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, zero, zero, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, certKey)
	if err != nil {
		return nil, nil, zero, zero, err
	}
	ders, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, zero, zero, fmt.Errorf("acme finalize: %w", err)
	}
	var chain []byte
	for _, d := range ders {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, nil, zero, zero, err
	}
	kb, _ := x509.MarshalECPrivateKey(certKey)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), leaf.NotBefore, leaf.NotAfter, nil
}
