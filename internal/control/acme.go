package control

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"agentd/internal/store"
)

// LetsEncrypt is the production ACME directory.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// ACMEIssuer obtains certificates with ACME DNS-01 challenges answered
// through Cloudflare DNS (design 6.2).
type ACMEIssuer struct {
	Store           *store.Store
	Directory       string
	Email           string
	DNS             *CloudflareClient
	PropagationWait time.Duration // default 30s
}

func (a *ACMEIssuer) accountKey(ctx context.Context) (crypto.Signer, error) {
	id := a.Directory + "|" + a.Email
	if b, err := a.Store.ACMEAccountKey(ctx, id); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("stored ACME key is not PEM")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := a.Store.PutACMEAccountKey(ctx, id, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return k, nil
}

// Issue runs an ACME order for names.
func (a *ACMEIssuer) Issue(ctx context.Context, names []string) ([]byte, []byte, time.Time, time.Time, error) {
	var zero time.Time
	if a.Directory == "" {
		a.Directory = LetsEncrypt
	}
	if a.DNS == nil {
		return nil, nil, zero, zero, errors.New("acme issuer has no DNS provider")
	}
	key, err := a.accountKey(ctx)
	if err != nil {
		return nil, nil, zero, zero, err
	}
	cl := &acme.Client{Key: key, DirectoryURL: a.Directory}
	acct := &acme.Account{}
	if a.Email != "" {
		acct.Contact = []string{"mailto:" + a.Email}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, nil, zero, zero, fmt.Errorf("acme register: %w", err)
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
