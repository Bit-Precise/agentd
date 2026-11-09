// Package pki creates the small private CAs and leaf certificates used for
// development, tests and the built-in self-signed issuer.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

// NewCA creates a self-signed ECDSA CA valid for ten years.
func NewCA(cn string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"agentd"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}

// SignLeaf issues a server certificate for DNS names and IP addresses.
func SignLeaf(caPEM, caKeyPEM []byte, names, ips []string, validity time.Duration) (certPEM, keyPEM []byte, notBefore, notAfter time.Time, err error) {
	ca, caKey, err := ParseCertKey(caPEM, caKeyPEM)
	if err != nil {
		return nil, nil, notBefore, notAfter, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, notBefore, notAfter, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	notBefore, notAfter = time.Now().Add(-time.Hour), time.Now().Add(validity)
	cn := "agentd"
	if len(names) > 0 {
		cn = names[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	for _, ip := range ips {
		if p := net.ParseIP(ip); p != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, p)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, notBefore, notAfter, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), notBefore, notAfter, nil
}

// ParseCertKey parses a PEM certificate and its private key (EC, RSA in
// PKCS#1, or any PKCS#8 key; CAs made by other tools such as Helm's genCA
// are RSA).
func ParseCertKey(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("invalid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if k, err := x509.ParseECPrivateKey(kb.Bytes); err == nil {
		return cert, k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		return cert, k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, errors.New("unsupported private key")
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("private key cannot sign")
	}
	return cert, signer, nil
}

// Pool returns a cert pool containing the PEM certificates.
func Pool(pems ...[]byte) *x509.CertPool {
	p := x509.NewCertPool()
	for _, b := range pems {
		p.AppendCertsFromPEM(b)
	}
	return p
}

// SelfSigned creates a throwaway CA and a leaf for names/IPs, returning a
// tls.Certificate and the CA PEM clients must trust (relay/agentserver
// `tls.mode: selfsigned`).
func SelfSigned(names, ips []string) (tls.Certificate, []byte, error) {
	caPEM, caKey, err := NewCA("agentd self-signed CA")
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM, keyPEM, _, _, err := SignLeaf(caPEM, caKey, names, ips, 365*24*time.Hour)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	cert, err := tls.X509KeyPair(append(certPEM, caPEM...), keyPEM)
	return cert, caPEM, err
}
