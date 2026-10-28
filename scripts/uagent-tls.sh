#!/usr/bin/env bash
# TLS certificate management for the uAgent portal. Run as root.
#
#   uagent-tls.sh init-ca                      Create the private root CA (once; reruns keep it).
#   uagent-tls.sh issue   --host NAME [--ip IP]...
#                                              Issue the portal certificate from the private CA, reusing the key.
#   uagent-tls.sh import  --cert FILE --key FILE [--chain FILE] [--ca FILE]
#                                              Install a certificate from a public or enterprise CA.
#                                              --cert and --chain accept PEM, DER, or a PKCS#7 bundle
#                                              (certnew.cer and certnew.p7b from a Windows CA).
#   uagent-tls.sh import  --pfx FILE [--password PASS]
#                                              Install from PKCS#12, which carries the key and the chain.
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
  trap 'rm -rf "$tmp"' RETURN EXIT
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

# Certificates reach administrators in whichever container their CA happens to use, and a Windows CA
# writes its PKCS#7 chain under a "CERTIFICATE" header, which makes it look like a single certificate.
# Everything is normalised to PEM here so the rest of the script, and the portal, see one consistent form.
extract_certs() {
  local file="$1" out="$2"
  : > "$out"
  if openssl x509 -in "$file" -noout >/dev/null 2>&1; then
    openssl x509 -in "$file" -outform PEM >> "$out"
    return 0
  fi
  if openssl x509 -in "$file" -inform DER -noout >/dev/null 2>&1; then
    openssl x509 -in "$file" -inform DER -outform PEM >> "$out"
    return 0
  fi
  local form
  for form in PEM DER; do
    if openssl pkcs7 -in "$file" -inform "$form" -print_certs >/dev/null 2>&1; then
      openssl pkcs7 -in "$file" -inform "$form" -print_certs 2>/dev/null \
        | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' >> "$out"
      [ -s "$out" ] && return 0
    fi
  done
  # A base64 body under a CERTIFICATE header that is really PKCS#7.
  local der="${out}.der"
  if awk '/BEGIN/{flag=1;next}/END/{flag=0}flag' "$file" | tr -d '\r\n ' | openssl base64 -d -A > "$der" 2>/dev/null; then
    if openssl pkcs7 -in "$der" -inform DER -print_certs >/dev/null 2>&1; then
      openssl pkcs7 -in "$der" -inform DER -print_certs 2>/dev/null \
        | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' >> "$out"
      rm -f "$der"
      [ -s "$out" ] && return 0
    fi
  fi
  rm -f "$der"
  return 1
}

# Splits a PEM file into one certificate per file and reports which is the leaf, the intermediates, and the
# self-signed root, so the root can be stored as the trust anchor rather than served.
import() {
  local cert="" key="" chain="" ca="" pfx="" password=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --cert) require_value "$@"; cert="$2"; shift 2 ;;
      --key) require_value "$@"; key="$2"; shift 2 ;;
      --chain) require_value "$@"; chain="$2"; shift 2 ;;
      --ca) require_value "$@"; ca="$2"; shift 2 ;;
      --pfx|--pkcs12) require_value "$@"; pfx="$2"; shift 2 ;;
      --password) require_value "$@"; password="$2"; shift 2 ;;
      *) die "Unknown option for import: $1" ;;
    esac
  done
  local tmp; tmp="$(mktemp -d)"
  chmod 700 "$tmp"
  trap 'rm -rf "$tmp"' RETURN EXIT

  if [ -n "$pfx" ]; then
    [ -s "$pfx" ] || die "--pfx ${pfx} does not exist."
    # Through the environment, not the command line, where any local user could read it with ps.
    export UAGENT_PFX_PASS="$password"
    openssl pkcs12 -in "$pfx" -nokeys -passin env:UAGENT_PFX_PASS > "${tmp}/all.pem" 2>/dev/null \
      || die "${pfx} could not be read. If it has a password, pass --password."
    ( umask 077; openssl pkcs12 -in "$pfx" -nocerts -nodes -passin env:UAGENT_PFX_PASS > "${tmp}/key.pem" 2>/dev/null ) \
      || die "${pfx} contains no private key."
    key="${tmp}/key.pem"
  else
    [ -s "$cert" ] || die "import needs --cert FILE, or --pfx FILE"
    [ -s "$key" ] || die "import needs --key FILE (the key that was used for the certificate request)"
    extract_certs "$cert" "${tmp}/cert.pem" || die "${cert} is not a certificate the script recognises (PEM, DER or PKCS#7)."
    cat "${tmp}/cert.pem" > "${tmp}/all.pem"
    if [ -n "$chain" ]; then
      [ -s "$chain" ] || die "--chain ${chain} does not exist."
      extract_certs "$chain" "${tmp}/chain.pem" || die "${chain} is not a certificate bundle the script recognises."
      cat "${tmp}/chain.pem" >> "${tmp}/all.pem"
    fi
  fi
  [ -n "$ca" ] && { [ -s "$ca" ] || die "--ca ${ca} does not exist."; extract_certs "$ca" "${tmp}/ca.pem" && cat "${tmp}/ca.pem" >> "${tmp}/all.pem"; }

  # One file per certificate, de-duplicated.
  ( cd "$tmp" && awk 'BEGIN{n=0} /BEGIN CERTIFICATE/{n++} {print > sprintf("part-%02d.pem", n)}' all.pem )
  local keyhash; keyhash="$(pubkey_of_key "$key")"
  [ -n "$keyhash" ] || die "The private key could not be read."

  local leaf="" root="" inter=() seen=()
  local part fp
  for part in "${tmp}"/part-*.pem; do
    openssl x509 -in "$part" -noout >/dev/null 2>&1 || continue
    fp="$(openssl x509 -in "$part" -noout -fingerprint -sha256 | cut -d= -f2)"
    case " ${seen[*]:-} " in *" ${fp} "*) continue ;; esac
    seen+=("$fp")
    if [ "$(pubkey_of_cert "$part")" = "$keyhash" ]; then
      leaf="$part"
    elif [ "$(openssl x509 -in "$part" -noout -subject)" = "$(openssl x509 -in "$part" -noout -issuer | sed 's/^issuer=/subject=/')" ]; then
      root="$part"
    else
      inter+=("$part")
    fi
  done
  [ -n "$leaf" ] || die "None of the supplied certificates belongs to the private key. Export the certificate issued for this server's key, or supply the matching key."
  openssl x509 -in "$leaf" -noout -checkend 86400 >/dev/null || die "The certificate expires within a day or has expired."

  local verify=(openssl verify -purpose sslserver)
  [ "${#inter[@]}" -gt 0 ] && verify+=(-untrusted <(cat "${inter[@]}"))
  [ -n "$root" ] && verify+=(-CAfile "$root")
  if ! "${verify[@]}" "$leaf" >/dev/null 2>&1; then
    "${verify[@]}" "$leaf" || true
    die "The chain does not verify. Supply every intermediate (a Windows CA puts them in certnew.p7b) and the internal root."
  fi

  # The root goes last: the portal takes it as the trust anchor, serves only what precedes it, and embeds
  # it in agent installers so endpoints can verify this portal.
  cat "$leaf" > "${tmp}/full.crt"
  [ "${#inter[@]}" -gt 0 ] && cat "${inter[@]}" >> "${tmp}/full.crt"
  [ -n "$root" ] && cat "$root" >> "${tmp}/full.crt"

  prepare_dir
  install -m 0644 "${tmp}/full.crt" "$CRT"
  install -m 0600 "$key" "$KEY"
  own "$CRT" "$KEY"
  if [ -n "$root" ]; then
    install -m 0644 "$root" "$CA_CRT"
    own "$CA_CRT"
  fi

  info "Installed ${CRT}: $(openssl x509 -in "$leaf" -noout -subject | sed 's/^subject=//')"
  info "Names: $(openssl x509 -in "$leaf" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | xargs)"
  info "Serving the server certificate and ${#inter[@]} intermediate(s)."
  if [ -n "$root" ]; then
    info "Trust anchor: $(openssl x509 -in "$root" -noout -subject | sed 's/^subject=//') (stored in ${CA_CRT} and embedded in agent downloads)."
  else
    info "No internal root was supplied, so agent downloads carry no trust material. Every endpoint must"
    info "already trust the issuing root, through Group Policy, Intune, or a public CA."
  fi
  info "The portal reloads within 30 seconds. Check it with: uagent-tls.sh check --host NAME"
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
