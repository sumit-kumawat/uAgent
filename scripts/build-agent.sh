#!/usr/bin/env bash
# Builds the self-contained, single-file Windows agent installer and publishes it for the portal to serve.
#
# Output (portal/agent-dist/):
#   uAgent-Setup.exe   the base installer/service binary (served as-is for self-update; the download
#                      endpoint appends the per-portal connection block for one-click installs)
#   manifest.json      { version, sha256, size, signed, builtUtc } describing the base binary
#
# Code signing: set SIGN_CMD to a command that signs "$OUT_EXE" in place (e.g. osslsigncode or a call to a
# Windows signing host). When set, manifest.json records signed=true and the agent enforces the signature
# on self-update. Run this on any OS with the .NET SDK 10 (the agent targets net8.0 and uses
# 10.0 packages; the SDK cross-compiles to win-x64).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/uAgent.Agent/uAgent.Agent.csproj"
DIST="$ROOT/portal/agent-dist"
STAGE="$(mktemp -d)"
OUT_EXE="$DIST/uAgent-Setup.exe"
trap 'rm -rf "$STAGE"' EXIT

echo "Publishing win-x64 single-file installer…"
dotnet publish "$PROJECT" \
  -c Release -r win-x64 \
  -p:PublishSingleFile=true -p:SelfContained=true \
  -o "$STAGE" >/dev/null

mkdir -p "$DIST"
cp "$STAGE/uAgent.exe" "$OUT_EXE"

if [ -n "${SIGN_CMD:-}" ]; then
  echo "Signing installer with: $SIGN_CMD"
  SIGN_TARGET="$OUT_EXE" bash -c "$SIGN_CMD"
  SIGNED=true
else
  echo "No SIGN_CMD set; producing an unsigned build (lab)."
  SIGNED=false
fi

VERSION="$(dotnet msbuild "$PROJECT" -nologo -getProperty:Version 2>/dev/null | tr -d '[:space:]')"
[ -n "$VERSION" ] || VERSION="0.0.0"
if command -v sha256sum >/dev/null 2>&1; then
  SHA="$(sha256sum "$OUT_EXE" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  SHA="$(shasum -a 256 "$OUT_EXE" | awk '{print $1}')"
else
  echo "sha256sum or shasum is required to hash the installer." >&2
  exit 1
fi
SIZE="$(wc -c < "$OUT_EXE" | tr -d '[:space:]')"
BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "$DIST/manifest.json" <<JSON
{
  "version": "$VERSION",
  "sha256": "$SHA",
  "size": $SIZE,
  "signed": $SIGNED,
  "builtUtc": "$BUILT"
}
JSON

echo "Built uAgent-Setup.exe v$VERSION ($((SIZE / 1048576)) MB, signed=$SIGNED)"
echo "  $OUT_EXE"
echo "  SHA-256 $SHA"
