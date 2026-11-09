package sim

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"strings"
)

func tlsConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func contains(b []byte, sub string) bool { return strings.Contains(string(b), sub) }
