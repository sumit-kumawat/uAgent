#!/usr/bin/env bash
# TLS certificate management for the uAgent portal. Run as root.
#
#   uagent-tls.sh init-ca                      Create the private root CA (once; reruns keep it).
#   uagent-tls.sh issue   --host NAME [--ip IP]...
#                                              Issue the portal certificate from the private CA, reusing the key.
#   uagent-tls.sh import  --cert FILE --key FILE [--chain FILE] [--ca FILE]
#                                              Install a certificate from a public or enterprise CA.
#   uagent-tls.sh check   --host NAME [--port 443]
#                                              Check files, chain, SAN and what the running portal presents.
#
# Files live in /etc/uagent/tls (override with TLS_DIR). The portal reloads the certificate within 30
# seconds of a change; no restart is needed. Validation is never disabled: agents and browsers must trust
# the issuing root, either because it is public or because it is deployed by Group Policy or Intune.
set -euo pipefail

TLS_DIR="${TLS_DIR:-/etc/uagent/tls}"
CA_KEY="${TLS_DIR}/ca.key"
CA_CRT="${TLS_DIR}/ca.crt"
KEY="${TLS_DIR}/portal.key"
CRT="${TLS_DIR}/portal.crt"
OWNER="${TLS_OWNER:-uagent}"
LEAF_DAYS=397

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '  %s\n' "$*"; }
ok() { printf '  [OK]     %s\n' "$*"; }
bad() { printf '  [FAILED] %s\n' "$*"; FAILED=1; }
require_value() {
  [ $# -ge 2 ] || die "$1 requires a value."
}

own() {
  if id "$OWNER" >/dev/null 2>&1; then
    chown "$OWNER:$OWNER" "$@"
  fi
}

prepare_dir() {
  install -d -m 0750 "$TLS_DIR"
  own "$TLS_DIR"
}

init_ca() {
  prepare_dir
  if [ -s "$CA_KEY" ] && [ -s "$CA_CRT" ]; then
    info "Private CA already exists: $(openssl x509 -in "$CA_CRT" -noout -subject | sed 's/^subject=//')"
    return 0
  fi
  local name="${CA_NAME:-uAgent Internal Root CA ($(hostname -s))}"
  umask 077
  openssl genrsa -out "$CA_KEY" 3072 2>/dev/null
  openssl req -x509 -new -key "$CA_KEY" -sha256 -days 3650 -subj "/CN=${name}/O=uAgent" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$CA_CRT"
  umask 022
  chmod 600 "$CA_KEY"
  chmod 644 "$CA_CRT"
  own "$CA_KEY" "$CA_CRT"
  info "Created the private root CA: ${name}"
  info "Deploy ${CA_CRT} to Trusted Root Certification Authorities with Group Policy or Intune."
}

san_list() {
  local host="$1"; shift
  local names=()
  if [[ "$host" =~ ^[0-9.]+$ ]]; then names+=("IP:${host}"); else names+=("DNS:${host}"); fi
  for ip in "$@"; do
    [ -n "$ip" ] || continue
    case " ${names[*]} " in *" IP:${ip} "*) ;; *) names+=("IP:${ip}") ;; esac
  done
  names+=("DNS:localhost" "IP:127.0.0.1")
  local IFS=,
  printf '%s' "${names[*]}"
}

issue() {
  local host="" ips=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --host) require_value "$@"; host="$2"; shift 2 ;;
      --ip) require_value "$@"; ips+=("$2"); shift 2 ;;
      *) die "Unknown option for issue: $1" ;;
    esac
  done
  [ -n "$host" ] || die "issue needs --host NAME"
  [ -s "$CA_KEY" ] || init_ca
  prepare_dir
  if [ ! -s "$KEY" ]; then
    umask 077
    openssl genrsa -out "$KEY" 2048 2>/dev/null
    umask 022
  fi
  chmod 600 "$KEY"
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  cat > "${tmp}/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$(san_list "$host" "${ips[@]+"${ips[@]}"}")
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
  openssl req -new -key "$KEY" -subj "/CN=${host}" -out "${tmp}/leaf.csr"
  openssl x509 -req -in "${tmp}/leaf.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" \
    -set_serial "0x$(openssl rand -hex 16)" -days "$LEAF_DAYS" -sha256 \
    -extfile "${tmp}/ext.cnf" -out "${tmp}/leaf.crt" 2>/dev/null
  cat "${tmp}/leaf.crt" "$CA_CRT" > "${tmp}/full.crt"
  install -m 0644 "${tmp}/full.crt" "$CRT"
  own "$KEY" "$CRT"
  info "Issued ${CRT} for $(san_list "$host" "${ips[@]+"${ips[@]}"}"), valid ${LEAF_DAYS} days."
}

pubkey_of_cert() { openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}'; }
pubkey_of_key() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}'; }

import() {
  local cert="" key="" chain="" ca=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --cert) require_value "$@"; cert="$2"; shift 2 ;;
      --key) require_value "$@"; key="$2"; shift 2 ;;
      --chain) require_value "$@"; chain="$2"; shift 2 ;;
      --ca) require_value "$@"; ca="$2"; shift 2 ;;
      *) die "Unknown option for import: $1" ;;
    esac
  done
  [ -s "$cert" ] || die "import needs --cert FILE (PEM)"
  [ -s "$key" ] || die "import needs --key FILE (PEM)"
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  cat "$cert" > "${tmp}/full.crt"
  [ -z "$chain" ] || { printf '\n' >> "${tmp}/full.crt"; cat "$chain" >> "${tmp}/full.crt"; }
  openssl x509 -in "$cert" -noout >/dev/null 2>&1 || die "$cert is not a PEM certificate."
  [ "$(pubkey_of_cert "$cert")" = "$(pubkey_of_key "$key")" ] || die "The private key does not belong to the certificate."
  openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null || die "The certificate expires within a day or has expired."
  local verify=(openssl verify -purpose sslserver)
  [ -z "$chain" ] || verify+=(-untrusted "$chain")
  [ -z "$ca" ] || verify+=(-CAfile "$ca")
  if ! "${verify[@]}" "$cert" >/dev/null 2>&1; then
    "${verify[@]}" "$cert" || true
    die "The chain does not verify. Pass every intermediate with --chain, and --ca for an enterprise root."
  fi
  prepare_dir
  install -m 0644 "${tmp}/full.crt" "$CRT"
  install -m 0600 "$key" "$KEY"
  own "$CRT" "$KEY"
  if [ -n "$ca" ]; then
    install -m 0644 "$ca" "$CA_CRT"
    own "$CA_CRT"
  fi
  info "Installed ${CRT}: $(openssl x509 -in "$cert" -noout -subject | sed 's/^subject=//')"
  info "Names: $(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | xargs)"
}

check() {
  local host="" port=443
  FAILED=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --host) require_value "$@"; host="$2"; shift 2 ;;
      --port) require_value "$@"; port="$2"; shift 2 ;;
      *) die "Unknown option for check: $1" ;;
    esac
  done
  [ -n "$host" ] || die "check needs --host NAME"
  [ -s "$CRT" ] || die "${CRT} does not exist."
  if [ "$(pubkey_of_cert "$CRT")" = "$(pubkey_of_key "$KEY")" ]; then ok "Private key matches the certificate"; else bad "Private key does not match the certificate"; fi
  if openssl x509 -in "$CRT" -noout -checkend $((30*86400)) >/dev/null; then ok "Valid for more than 30 days ($(openssl x509 -in "$CRT" -noout -enddate | cut -d= -f2))"; else bad "Expires within 30 days"; fi
  local check_opt=(-checkhost "$host")
  [[ "$host" =~ ^[0-9.]+$ ]] && check_opt=(-checkip "$host")
  if openssl x509 -in "$CRT" -noout "${check_opt[@]}" | grep -q "does match"; then ok "SAN includes ${host}"; else bad "SAN does not include ${host}"; fi
  local cafile=()
  [ -s "$CA_CRT" ] && cafile=(-CAfile "$CA_CRT")
  local verify_opt=(-verify_hostname "$host")
  [[ "$host" =~ ^[0-9.]+$ ]] && verify_opt=(-verify_ip "$host")
  local out
  out="$(openssl s_client -connect "127.0.0.1:${port}" -servername "$host" "${verify_opt[@]}" -showcerts "${cafile[@]}" </dev/null 2>&1 || true)"
  local count; count="$(printf '%s' "$out" | grep -c 'BEGIN CERTIFICATE' || true)"
  if printf '%s' "$out" | grep -q 'Verify return code: 0 (ok)'; then
    ok "The running portal presents a chain of ${count} certificate(s) that verifies for ${host}"
  else
    bad "The running portal's certificate does not verify for ${host}: $(printf '%s' "$out" | grep -m1 'Verify return code' || echo 'no TLS answer on port '"${port}")"
  fi
  [ "$FAILED" -eq 0 ] || exit 2
}

[ $# -ge 1 ] || { sed -n '2,13p' "$0"; exit 1; }
[ "$(id -u)" -eq 0 ] || [ "$TLS_DIR" != /etc/uagent/tls ] || die "Run as root."
cmd="$1"; shift
case "$cmd" in
  init-ca) init_ca ;;
  issue) issue "$@" ;;
  import) import "$@" ;;
  check) check "$@" ;;
  *) die "Unknown command: $cmd" ;;
esac
