#!/usr/bin/env bash
# Generate a self-signed TLS certificate for the uAgent portal.
# Usage: scripts/gencert.sh [extra-SAN ...]
# The certificate covers the public host (PUBLIC_HOST, default uagent.example.com), localhost,
# 127.0.0.1, this host's primary LAN IP, an optional PUBLIC_IP, and any extra SANs passed in.
# Intended for evaluation. For production, use scripts/uagent-tls.sh or a public CA and point
# TLS_CERT_FILE / TLS_KEY_FILE at it.
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../certs"
CRT="$CERT_DIR/portal.crt"
KEY="$CERT_DIR/portal.key"

mkdir -p "$CERT_DIR"

# Detect the primary LAN IPv4 address across macOS and Linux.
detect_ip() {
  if command -v ipconfig >/dev/null 2>&1; then
    for iface in en0 en1 eth0; do
      ip=$(ipconfig getifaddr "$iface" 2>/dev/null || true)
      [ -n "$ip" ] && { echo "$ip"; return; }
    done
  fi
  if command -v hostname >/dev/null 2>&1; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -n "$ip" ] && { echo "$ip"; return; }
  fi
  echo ""
}

LAN_IP="$(detect_ip)"
PUBLIC_HOST="${PUBLIC_HOST:-uagent.example.com}"
PUBLIC_IP="${PUBLIC_IP:-}"

add_ip() {
  local ip="$1"
  [ -n "$ip" ] || return 0
  case ",$ALT_NAMES," in
    *",IP:${ip},"*) ;;
    *) ALT_NAMES="${ALT_NAMES},IP:${ip}" ;;
  esac
}

ALT_NAMES="DNS:$PUBLIC_HOST,DNS:localhost,IP:127.0.0.1"
add_ip "$LAN_IP"
add_ip "$PUBLIC_IP"
for extra in "$@"; do
  if [[ "$extra" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ALT_NAMES="$ALT_NAMES,IP:$extra"
  else
    ALT_NAMES="$ALT_NAMES,DNS:$extra"
  fi
done

echo "Generating self-signed certificate with SANs: $ALT_NAMES"

# Reuse the existing key so the public-key pin embedded in installed agents stays valid across reissues.
if [ ! -s "$KEY" ]; then
  (umask 077; openssl genrsa -out "$KEY" 2048 2>/dev/null)
fi
openssl req -x509 -key "$KEY" -sha256 \
  -out "$CRT" \
  -days 397 \
  -subj "/CN=$PUBLIC_HOST" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "subjectAltName=$ALT_NAMES"

chmod 600 "$KEY"
echo "Wrote:"
echo "  $CRT"
echo "  $KEY"
echo "This certificate is self-signed: browsers show ERR_CERT_AUTHORITY_INVALID. For production use"
echo "scripts/uagent-tls.sh (private CA) or a public CA certificate."
echo "A running portal picks up the new certificate within 30 seconds."
