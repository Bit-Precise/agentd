package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestSignLeafWithECAndRSACAs(t *testing.T) {
	ecCert, ecKey, err := NewCA("ec")
	if err != nil {
		t.Fatal(err)
	}
	// An RSA CA like the ones Helm's genCA produces.
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rsa"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rk.PublicKey, rk)
	rsaCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	rsaKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
	for name, ca := range map[string][2][]byte{"ec": {ecCert, ecKey}, "rsa": {rsaCert, rsaKey}} {
		certPEM, keyPEM, _, _, err := SignLeaf(ca[0], ca[1], []string{"a.example.com"}, nil, time.Hour)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		leaf, _ := x509.ParseCertificate(pair.Certificate[0])
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: Pool(ca[0]), DNSName: "a.example.com"}); err != nil {
			t.Fatalf("%s: leaf does not verify: %v", name, err)
		}
	}
}
