#!/usr/bin/env bash
# Signs the darwin binaries in DIST with the org's Developer ID Application
# identity (hardened runtime, secure timestamp), notarizes one ZIP per
# architecture with notarytool and checks the result with Gatekeeper.
#
#   scripts/release/sign-macos.sh <dist-dir> <version>
#
# DIST holds agentd|agentserver|agentrelay-darwin-{amd64,arm64} (make dist);
# the script writes DIST/agentd_<version>_darwin_<arch>.zip.
#
# Environment (Bit-Precise org variables and secrets):
#   APPLE_APPLICATION_IDENTITY APPLE_TEAM_ID APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID
#   APPLE_APPLICATION_P12_BASE64 APPLE_APPLICATION_P12_PASSWORD APPLE_NOTARY_KEY_P8_BASE64
# SKIP_NOTARIZE=1 signs and verifies the signature only, for dry runs with a
# throwaway identity from test-identity.sh.
set -euo pipefail
dist=${1:?usage: sign-macos.sh <dist-dir> <version>}
version=${2:?usage: sign-macos.sh <dist-dir> <version>}
dist=$(cd "$dist" && pwd)
dry=${SKIP_NOTARIZE:-}

required="APPLE_APPLICATION_IDENTITY APPLE_TEAM_ID APPLE_APPLICATION_P12_BASE64 APPLE_APPLICATION_P12_PASSWORD"
[ "$dry" = 1 ] || required="$required APPLE_NOTARY_KEY_ID APPLE_NOTARY_ISSUER_ID APPLE_NOTARY_KEY_P8_BASE64"
for v in $required; do
  [ -n "${!v:-}" ] || { echo "missing signing configuration: $v" >&2; exit 1; }
done

work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/agentd-sign.XXXXXX")
keychain="$work/signing.keychain-db"
kcpass=$(openssl rand -hex 24)
old_keychains=$(security list-keychains -d user | sed 's/"//g')
cleanup() {
  security list-keychains -d user -s $old_keychains >/dev/null 2>&1 || true
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -f "$work/app.p12" "$work/notary.p8"
}
trap cleanup EXIT

# A temporary keychain holds the identity for this run only.
printf '%s' "$APPLE_APPLICATION_P12_BASE64" | base64 --decode > "$work/app.p12"
security create-keychain -p "$kcpass" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$kcpass" "$keychain"
security import "$work/app.p12" -k "$keychain" -P "$APPLE_APPLICATION_P12_PASSWORD" -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$kcpass" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain" $old_keychains
if ! security find-identity -p codesigning "$keychain" | grep -qF "\"$APPLE_APPLICATION_IDENTITY\""; then
  echo "identity not found in the imported certificate: $APPLE_APPLICATION_IDENTITY" >&2
  security find-identity -p codesigning "$keychain" >&2
  exit 1
fi
if [ "$dry" != 1 ]; then
  printf '%s' "$APPLE_NOTARY_KEY_P8_BASE64" | base64 --decode > "$work/notary.p8"
fi
notary() { xcrun notarytool "$@" --key "$work/notary.p8" --key-id "$APPLE_NOTARY_KEY_ID" --issuer "$APPLE_NOTARY_ISSUER_ID"; }
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$1" "$2" 2>/dev/null || true; }

for arch in amd64 arm64; do
  name="agentd_${version}_darwin_${arch}"
  stage="$work/$name"
  mkdir -p "$stage"
  for c in agentd agentserver agentrelay; do
    install -m 0755 "$dist/$c-darwin-$arch" "$stage/$c"
    codesign --force --timestamp --options runtime --identifier "dev.agentd.$c" \
      --sign "$APPLE_APPLICATION_IDENTITY" --keychain "$keychain" "$stage/$c"
    codesign --verify --strict --verbose=2 "$stage/$c"
    info=$(codesign -dv --verbose=2 "$stage/$c" 2>&1)
    ok=1
    grep -q 'flags=0x10000(runtime)' <<<"$info" || ok=0
    if [ "$dry" != 1 ]; then
      grep -q '^Authority=Developer ID Application: ' <<<"$info" || ok=0
      grep -qx "TeamIdentifier=$APPLE_TEAM_ID" <<<"$info" || ok=0
      grep -q '^Timestamp=' <<<"$info" || ok=0
    fi
    [ "$ok" = 1 ] || { echo "$c: signature lacks hardened runtime, Developer ID, team or timestamp" >&2; echo "$info" >&2; exit 1; }
  done
  zip="$dist/$name.zip"
  rm -f "$zip"
  (cd "$work" && ditto -c -k --norsrc --noextattr --keepParent "$name" "$zip")
  if [ "$dry" = 1 ]; then
    echo "signed $zip (notarization skipped)"
    continue
  fi
  out="$work/notary-$arch.json"
  notary submit "$zip" --wait --timeout 30m --output-format json > "$out" || true
  status=$(field "$out" status)
  id=$(field "$out" id)
  echo "notarization of $name: ${status:-unknown} (${id:-no submission id})"
  if [ "$status" != Accepted ]; then
    cat "$out" >&2 || true
    if [ -n "$id" ]; then notary log "$id" >&2 || true; fi
    exit 1
  fi
  # Bare executables cannot be stapled, so Gatekeeper looks the ticket up
  # online. spctl calls command-line tools "not an app" even when they pass;
  # the source line is what shows the notarization.
  for c in agentd agentserver agentrelay; do
    for try in 1 2 3 4 5 6; do
      verdict=$(spctl --assess --type execute -vv "$stage/$c" 2>&1 || true)
      grep -q '^source=Notarized Developer ID' <<<"$verdict" && break
      [ "$try" = 6 ] && { echo "$c: Gatekeeper does not see a notarization ticket" >&2; echo "$verdict" >&2; exit 1; }
      sleep 10
    done
    echo "$c: $(grep '^source=' <<<"$verdict")"
  done
done

host=amd64; [ "$(uname -m)" = arm64 ] && host=arm64
got=$("$work/agentd_${version}_darwin_$host/agentd" version)
echo "$got"
case "$got" in *"$version"*) ;; *) echo "signed agentd reports an unexpected version (want $version)" >&2; exit 1 ;; esac
