#!/usr/bin/env bash
# Creates a throwaway self-signed code signing identity for dry runs of
# sign-macos.sh and prints it as KEY=VALUE lines (no spaces or quotes, so the
# output works both for $GITHUB_ENV and for `set -a; . file; set +a`).
#
#   scripts/release/test-identity.sh > id.env
set -euo pipefail
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/agentd-testid.XXXXXX")
trap 'rm -f "$work/cs.cnf" "$work/key.pem" "$work/cert.pem" "$work/id.p12"; rmdir "$work"' EXIT
cat > "$work/cs.cnf" <<'CNF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = agentd-test-signing
[ext]
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
basicConstraints = critical, CA:false
CNF
# The system LibreSSL writes the PKCS#12 encryption that `security import`
# accepts; newer OpenSSL defaults need -legacy.
ossl=/usr/bin/openssl
"$ossl" req -x509 -newkey rsa:2048 -nodes -days 2 -config "$work/cs.cnf" \
  -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
pass=$("$ossl" rand -hex 16)
"$ossl" pkcs12 -export -inkey "$work/key.pem" -in "$work/cert.pem" -name agentd-test-signing \
  -passout "pass:$pass" -out "$work/id.p12"
echo "APPLE_APPLICATION_IDENTITY=agentd-test-signing"
echo "APPLE_TEAM_ID=NONE"
echo "APPLE_APPLICATION_P12_PASSWORD=$pass"
echo "APPLE_APPLICATION_P12_BASE64=$(base64 < "$work/id.p12" | tr -d '\n')"
