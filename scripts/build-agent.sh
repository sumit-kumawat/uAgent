#!/usr/bin/env bash
# Builds the self-contained, single-file Windows agent installer and publishes it for the portal to serve.
#
# Output (portal/agent-dist/):
#   uAgent-Setup.exe   the installer/service binary
#   manifest.json      { version, sha256, size, signed, builtUtc } describing that binary
#   SHA256SUMS         release hash, for release notes and for Microsoft file submissions
#
# Unsigned development builds are personalized at download: the portal appends this portal's address. Signed builds
# are never modified after signing: the portal serves them byte for byte, and the connection settings travel
# as uagent-install.json or /manager= /enrollkey= switches.
#
# Code signing (Authenticode, SHA-256, RFC 3161 timestamp). Pick one with SIGN_MODE:
#   none          default; unsigned development build
#   osslsigncode  OV/EV certificate from a public CA. Either a hardware token or HSM through PKCS#11
#                 (SIGN_PKCS11_MODULE, SIGN_PKCS11_KEY, SIGN_CERT) or, where the CA still allows it, a PFX
#                 (SIGN_PFX, SIGN_PFX_PASSWORD_FILE).
#   azure         Azure Artifact Signing (formerly Trusted Signing) through jsign. Needs SIGN_AZURE_ENDPOINT
#                 (e.g. eus.codesigning.azure.net), SIGN_AZURE_ACCOUNT, SIGN_AZURE_PROFILE and an Azure CLI
#                 login (az login, or a managed identity on the build host).
#   custom        SIGN_CMD signs "$SIGN_TARGET" in place, for example signtool on a Windows signing host:
#                 signtool sign /fd SHA256 /tr <tsa> /td SHA256 /dlib Azure.CodeSigning.Dlib.dll /dmdf meta.json
# SIGN_TIMESTAMP_URL overrides the RFC 3161 timestamp server; SIGN_VERIFY_CAFILE adds a root for verification. A build is recorded as signed only after the
# signature verifies. Run this on any OS with the .NET SDK 10 (the agent targets net8.0 and cross-compiles).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/uAgent.Agent/uAgent.Agent.csproj"
DIST="$ROOT/portal/agent-dist"
STAGE="$(mktemp -d)"
OUT_EXE="$DIST/uAgent-Setup.exe"
trap 'rm -rf "$STAGE"' EXIT

SIGN_MODE="${SIGN_MODE:-}"
if [ -z "$SIGN_MODE" ]; then
  if [ -n "${SIGN_CMD:-}" ]; then SIGN_MODE=custom; else SIGN_MODE=none; fi
fi
SIGN_DESCRIPTION="${SIGN_DESCRIPTION:-uAgent Endpoint Agent}"
SIGN_URL="${SIGN_URL:-https://github.com/sumit-kumawat/uAgent}"

die() { echo "ERROR: $*" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "sha256sum or shasum is required to hash the installer."
  fi
}

sign_osslsigncode() {
  local in="$1" out="$2"
  command -v osslsigncode >/dev/null 2>&1 || die "SIGN_MODE=osslsigncode needs osslsigncode (dnf install osslsigncode)."
  local tsa="${SIGN_TIMESTAMP_URL:-http://timestamp.digicert.com}"
  local args=(sign -h sha256 -n "$SIGN_DESCRIPTION" -i "$SIGN_URL" -ts "$tsa")
  if [ -n "${SIGN_PKCS11_MODULE:-}" ]; then
    [ -n "${SIGN_PKCS11_KEY:-}" ] && [ -s "${SIGN_CERT:-}" ] || die "PKCS#11 signing needs SIGN_PKCS11_KEY and SIGN_CERT."
    args+=(-pkcs11module "$SIGN_PKCS11_MODULE" -key "$SIGN_PKCS11_KEY" -certs "$SIGN_CERT")
  elif [ -n "${SIGN_PFX:-}" ]; then
    [ -s "$SIGN_PFX" ] || die "SIGN_PFX does not exist: $SIGN_PFX"
    args+=(-pkcs12 "$SIGN_PFX")
    if [ -n "${SIGN_PFX_PASSWORD_FILE:-}" ]; then
      args+=(-readpass "$SIGN_PFX_PASSWORD_FILE")
    fi
  else
    die "SIGN_MODE=osslsigncode needs SIGN_PKCS11_MODULE or SIGN_PFX."
  fi
  osslsigncode "${args[@]}" -in "$in" -out "$out"
}

sign_azure() {
  local file="$1"
  command -v jsign >/dev/null 2>&1 || die "SIGN_MODE=azure needs jsign 6 or newer (https://ebourg.github.io/jsign/)."
  command -v az >/dev/null 2>&1 || die "SIGN_MODE=azure needs the Azure CLI for an access token."
  [ -n "${SIGN_AZURE_ENDPOINT:-}" ] && [ -n "${SIGN_AZURE_ACCOUNT:-}" ] && [ -n "${SIGN_AZURE_PROFILE:-}" ] \
    || die "SIGN_MODE=azure needs SIGN_AZURE_ENDPOINT, SIGN_AZURE_ACCOUNT and SIGN_AZURE_PROFILE."
  local token
  token="$(az account get-access-token --resource https://codesigning.azure.net --query accessToken -o tsv)"
  jsign --storetype TRUSTEDSIGNING --keystore "$SIGN_AZURE_ENDPOINT" --storepass "$token" \
    --alias "${SIGN_AZURE_ACCOUNT}/${SIGN_AZURE_PROFILE}" \
    --tsaurl "${SIGN_TIMESTAMP_URL:-http://timestamp.acs.microsoft.com}" --tsmode RFC3161 \
    --name "$SIGN_DESCRIPTION" --url "$SIGN_URL" --alg SHA-256 "$file"
}

verify_signature() {
  local file="$1"
  if command -v osslsigncode >/dev/null 2>&1; then
    local ca=()
    [ -z "${SIGN_VERIFY_CAFILE:-}" ] || ca=(-CAfile "$SIGN_VERIFY_CAFILE")
    osslsigncode verify "${ca[@]+"${ca[@]}"}" -in "$file" >"$STAGE/verify.txt" 2>&1 || { cat "$STAGE/verify.txt"; return 1; }
    grep -qi "timestamp" "$STAGE/verify.txt" || { echo "The signature has no timestamp." >&2; return 1; }
    awk '/Subject:|Signing time|Timestamp time|Signature verification/ { print "  " $0; if (++shown == 6) exit }' "$STAGE/verify.txt"
    return 0
  fi
  if command -v jsign >/dev/null 2>&1; then
    jsign extract --format PEM "$file" >/dev/null 2>&1 && { echo "  Signature present (install osslsigncode for full verification)."; return 0; }
    return 1
  fi
  echo "  Install osslsigncode to verify the signature on this host; on Windows run: signtool verify /pa /all /tw \"$file\"" >&2
  return 1
}

echo "Publishing win-x64 single-file installer…"
dotnet publish "$PROJECT" \
  -c Release -r win-x64 \
  -p:PublishSingleFile=true -p:SelfContained=true \
  -o "$STAGE/publish" >/dev/null

mkdir -p "$DIST"
UNSIGNED="$STAGE/uAgent.exe"
cp "$STAGE/publish/uAgent.exe" "$UNSIGNED"

SIGNED=false
case "$SIGN_MODE" in
  none)
    echo "SIGN_MODE=none: publishing an unsigned development build. Sign release builds."
    cp "$UNSIGNED" "$STAGE/out.exe"
    ;;
  osslsigncode)
    echo "Signing with osslsigncode (RFC 3161 timestamp)…"
    sign_osslsigncode "$UNSIGNED" "$STAGE/out.exe"
    SIGNED=true
    ;;
  azure)
    echo "Signing with Azure Artifact Signing (${SIGN_AZURE_ACCOUNT:-?}/${SIGN_AZURE_PROFILE:-?})…"
    cp "$UNSIGNED" "$STAGE/out.exe"
    sign_azure "$STAGE/out.exe"
    SIGNED=true
    ;;
  custom)
    [ -n "${SIGN_CMD:-}" ] || die "SIGN_MODE=custom needs SIGN_CMD."
    echo "Signing with: $SIGN_CMD"
    cp "$UNSIGNED" "$STAGE/out.exe"
    SIGN_TARGET="$STAGE/out.exe" bash -c "$SIGN_CMD"
    SIGNED=true
    ;;
  *) die "Unknown SIGN_MODE '$SIGN_MODE' (none, osslsigncode, azure, custom)." ;;
esac

if [ "$SIGNED" = true ]; then
  echo "Verifying the signature…"
  verify_signature "$STAGE/out.exe" || die "The signature did not verify; the build was not published."
fi

# Publish atomically so the portal never serves a half-written file.
cp "$STAGE/out.exe" "$OUT_EXE.tmp"
mv -f "$OUT_EXE.tmp" "$OUT_EXE"

VERSION="$(dotnet msbuild "$PROJECT" -nologo -getProperty:Version 2>/dev/null | tr -d '[:space:]')"
[ -n "$VERSION" ] || VERSION="0.0.0"
SHA="$(sha256 "$OUT_EXE")"
SIZE="$(wc -c < "$OUT_EXE" | tr -d '[:space:]')"
BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "$DIST/manifest.json.tmp" <<JSON
{
  "version": "$VERSION",
  "sha256": "$SHA",
  "size": $SIZE,
  "signed": $SIGNED,
  "builtUtc": "$BUILT"
}
JSON
mv -f "$DIST/manifest.json.tmp" "$DIST/manifest.json"
printf '%s  uAgent_Version%s.exe\n' "$SHA" "$VERSION" > "$DIST/SHA256SUMS"

echo "Built uAgent-Setup.exe v$VERSION ($((SIZE / 1048576)) MB, signed=$SIGNED)"
echo "  $OUT_EXE"
echo "  SHA-256 $SHA  (also in $DIST/SHA256SUMS)"
if [ "$SIGNED" = false ]; then
  echo "  Downloads are personalized, so a downloaded file's hash differs from this base hash."
fi
