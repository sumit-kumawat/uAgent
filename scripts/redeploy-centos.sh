#!/usr/bin/env bash
# Clean redeployment of the uAgent portal on CentOS Stream 8 / RHEL-family servers from GitHub, with the
# CA-issued certificate kept in the repository, verified HTTPS, a verified backup and automatic rollback.
#
# Usage (as root on the portal server):
#   bash redeploy-centos.sh                                   # host uagent.corp.helixops.ai, branch main
#   bash redeploy-centos.sh --key /root/uagent.corp.helixops.ai.key
#   bash redeploy-centos.sh --host portal.example.com --cert-zip /root/portal-cert.zip --key /root/portal.key
#
# Steps: preflight -> review the current installation (secrets masked) -> stage and validate a fresh
# clone of the branch -> validate the certificate, chain and private key -> verified backup -> stop and set
# the old code aside -> run install-centos.sh with the certificate -> verify the service, firewall, TLS
# chain and HTTPS -> remove obsolete files. Any failure after the backup rolls back to the previous code
# and configuration and restarts the previous portal.
#
# Kept across the redeploy: /etc/uagent (portal.env with its secrets, TLS key, private CA, host setting),
# /var/lib/uagent (agents, accounts, audit log, backups). The private key is never copied into the
# repository, printed or logged; the log masks passwords the installer prints.
set -Eeuo pipefail
umask 077

REPO_URL="https://github.com/sumit-kumawat/uAgent.git"
BRANCH="main"
HOST="uagent.corp.helixops.ai"
INSTALL_DIR="/opt/uagent"
ETC_DIR="/etc/uagent"
STATE_DIR="/var/lib/uagent"
SERVICE="uagent-portal"
BACKUP_DIR="/root/uagent-backups"
LOG_DIR="/var/log/uagent"
KEY_FILE=""
CERT_ZIP=""
SKIP_AGENT=0
KEEP_OLD=2
ASSUME_YES=0
CHECK_ONLY=0
EXTRA_ARGS=()

usage() {
  cat <<EOF
Usage: redeploy-centos.sh [options]
  --host NAME        Portal DNS name (default ${HOST}). Must be in the certificate's SAN.
  --branch NAME      Git branch to deploy (default ${BRANCH}).
  --repo URL         Git repository (default ${REPO_URL}).
  --key FILE         Private key of the certificate. Default: search /etc/uagent/tls, /root and
                     /etc/pki/tls/private for a key whose public key matches the certificate.
  --cert-zip PATH    ZIP with the certificate and chain. Default: <host>.zip in the cloned repository.
                     A https:// URL is accepted; GitHub "blob" page URLs are converted to raw downloads
                     and the result is checked to really be a ZIP.
  --skip-agent       Do not rebuild the Windows agent installer.
  --keep-old N       Previous code directories to keep for manual rollback (default ${KEEP_OLD}).
  --yes              Do not ask for confirmation.
  --check-cert       Only validate the certificate ZIP and private key (no root needed, no changes).
  Other install-centos.sh options (--http-port, --https-port, --bind, --public-ip, --allow-from,
  --skip-firewall) are passed through.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="${2:?--host needs a value}"; shift 2 ;;
    --branch) BRANCH="${2:?--branch needs a value}"; shift 2 ;;
    --repo) REPO_URL="${2:?--repo needs a value}"; shift 2 ;;
    --key) KEY_FILE="${2:?--key needs a value}"; shift 2 ;;
    --cert-zip) CERT_ZIP="${2:?--cert-zip needs a value}"; shift 2 ;;
    --skip-agent) SKIP_AGENT=1; shift ;;
    --keep-old) KEEP_OLD="${2:?--keep-old needs a value}"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --check-cert) CHECK_ONLY=1; shift ;;
    --http-port|--https-port|--bind|--public-ip|--allow-from) EXTRA_ARGS+=("$1" "${2:?$1 needs a value}"); shift 2 ;;
    --skip-firewall) EXTRA_ARGS+=("$1"); shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

HOST="$(printf '%s' "$HOST" | tr 'A-Z' 'a-z')"
[[ "$HOST" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || { echo "--host must be a DNS name." >&2; exit 2; }
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]{1,100}$ ]] || { echo "--branch is not a valid branch name." >&2; exit 2; }
[[ "$KEEP_OLD" =~ ^[0-9]{1,2}$ ]] || { echo "--keep-old must be a number." >&2; exit 2; }

TS="$(date +%Y%m%d-%H%M%S)"
STAGE="/var/tmp/uagent-stage-${TS}"
CERT_WORK="$(mktemp -d /var/tmp/uagent-cert-XXXXXX)"
PREV_DIR=""
BACKUP=""
PHASE="preflight"


step() { printf '\n==> [%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    WARNING: %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*"; exit 1; }

cleanup() {
  rm -rf "$CERT_WORK"
  [ -d "$STAGE" ] && rm -rf "$STAGE"
  return 0
}

rollback() {
  local status=$?
  # errtrace also fires this trap inside $(...); only the main shell rolls back.
  [ "$BASHPID" = "$$" ] || return 0
  trap - ERR
  set +e
  printf '\nERROR: the redeploy failed during "%s" (exit %s). Log: %s\n' "$PHASE" "$status" "$LOG"
  case "$PHASE" in
    preflight|review|stage|certificate|backup)
      printf 'Nothing on the server was changed. Fix the cause above and run the script again.\n' ;;
    *)
      printf '\n==> Rolling back to the previous installation\n'
      systemctl stop "$SERVICE" 2>/dev/null
      if [ -n "$PREV_DIR" ] && [ -d "$PREV_DIR" ]; then
        rm -rf "${INSTALL_DIR}.failed-${TS}"
        [ -d "$INSTALL_DIR" ] && mv "$INSTALL_DIR" "${INSTALL_DIR}.failed-${TS}"
        mv "$PREV_DIR" "$INSTALL_DIR" && printf '    Restored the previous code to %s (the failed one is in %s.failed-%s)\n' "$INSTALL_DIR" "$INSTALL_DIR" "$TS"
      fi
      if [ -n "$BACKUP" ] && [ -s "$BACKUP" ]; then
        tar -xzpf "$BACKUP" -C / && printf '    Restored configuration, certificates, state, units and sudoers from %s\n' "$BACKUP"
      fi
      systemctl daemon-reload
      firewall-cmd --reload >/dev/null 2>&1
      systemctl enable --now "$SERVICE" >/dev/null 2>&1
      systemctl start uagent-portal-watch.timer >/dev/null 2>&1
      sleep 5
      if systemctl is-active --quiet "$SERVICE"; then
        printf '    The previous portal is running again.\n'
      else
        printf '    The previous portal did not start. Check: journalctl -u %s -n 100\n' "$SERVICE"
      fi ;;
  esac
  cleanup
  exit "$status"
}
trap rollback ERR
trap cleanup EXIT

mask_env() {
  sed -E 's/^([A-Za-z_]*(SECRET|PASS|PASSWORD|KEY|TOKEN|USERS)[A-Za-z_]*=).*/\1********/' "$1"
}

pubkey_hash() { { openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform DER | openssl sha256 | awk '{print $NF}'; } 2>/dev/null || true; }
san_names() {
  openssl x509 -in "$1" -noout -text 2>/dev/null | awk '/Subject Alternative Name/ {getline; print; exit}' | tr ',' '\n' | sed -n 's/^ *DNS://p' | tr 'A-Z' 'a-z'
}
san_matches() {
  local name
  while IFS= read -r name; do
    [ "$name" = "$2" ] && return 0
    [[ "$name" == \*.* && "${2#*.}" = "${name#*.}" ]] && return 0
  done < <(san_names "$1")
  return 1
}
key_hash() { { openssl pkey -in "$1" -pubout -outform DER -passin pass: | openssl sha256 | awk '{print $NF}'; } 2>/dev/null || true; }

# Finds the server certificate, chain, root and matching private key; sets LEAF, CHAIN, ROOT, KEY_FILE.
validate_certificate() {
  ZIP="${CERT_WORK}/cert.zip"
  if [ -z "$CERT_ZIP" ]; then
    [ -s "${CERT_SOURCE_DIR}/${HOST}.zip" ] || die "${HOST}.zip is not in the repository. Give --cert-zip PATH or URL."
    cp "${CERT_SOURCE_DIR}/${HOST}.zip" "$ZIP"
    info "Using ${HOST}.zip from the repository"
  elif [[ "$CERT_ZIP" =~ ^https:// ]]; then
    url="$CERT_ZIP"
    # A github.com/<owner>/<repo>/blob/<ref>/<path> URL is an HTML page, not the file.
    if [[ "$url" =~ ^https://github\.com/([^/]+)/([^/]+)/blob/(.+)$ ]]; then
      url="https://raw.githubusercontent.com/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/${BASH_REMATCH[3]}"
      info "GitHub page URL converted to ${url}"
    fi
    curl -fsSL --max-time 60 -o "$ZIP" "$url" || die "Could not download ${url}."
  else
    [ -s "$CERT_ZIP" ] || die "${CERT_ZIP} does not exist."
    cp "$CERT_ZIP" "$ZIP"
  fi
  [ "$(head -c 2 "$ZIP")" = "PK" ] || die "The certificate archive is not a ZIP file (an HTML page was probably downloaded)."
  unzip -tq "$ZIP" >/dev/null || die "The certificate ZIP is damaged."
  unzip -qo "$ZIP" -d "${CERT_WORK}/x"

  # Every certificate in every file (PEM, DER or PKCS#7) goes into one list.
  ALL="${CERT_WORK}/all.pem"
  : > "$ALL"
  while IFS= read -r -d '' file; do
    tmp="${CERT_WORK}/one.pem"
    if openssl pkcs7 -in "$file" -print_certs -out "$tmp" 2>/dev/null || openssl pkcs7 -inform DER -in "$file" -print_certs -out "$tmp" 2>/dev/null; then
      :
    elif grep -q "BEGIN CERTIFICATE" "$file" 2>/dev/null; then
      tr -d '\r' < "$file" > "$tmp"
    elif openssl x509 -inform DER -in "$file" -out "$tmp" 2>/dev/null; then
      :
    else
      grep -q "PRIVATE KEY" "$file" 2>/dev/null && warn "$(basename "$file") holds a private key; it is used only if it matches, and is never copied anywhere else."
      continue
    fi
    cat "$tmp" >> "$ALL"
  done < <(find "${CERT_WORK}/x" -type f -print0)

  # Split into separate files and classify.
  split_dir="${CERT_WORK}/certs"
  mkdir -p "$split_dir"
  awk -v dir="$split_dir" '/BEGIN CERTIFICATE/ {n++; f=sprintf("%s/%03d.pem", dir, n)} f {print > f} /END CERTIFICATE/ {f=""}' "$ALL"
  LEAF=""; ROOT="${CERT_WORK}/root.pem"; CHAIN="${CERT_WORK}/chain.pem"
  : > "$ROOT"; : > "$CHAIN"
  seen=" "
  for c in "$split_dir"/*.pem; do
    [ -e "$c" ] || die "No certificates were found in the ZIP."
    fp="$(openssl x509 -in "$c" -noout -fingerprint -sha256 | cut -d= -f2)"
    [[ "$seen" != *" $fp "* ]] || continue
    seen="${seen}${fp} "
    subject="$(openssl x509 -in "$c" -noout -subject -nameopt RFC2253 | sed 's/^subject= *//')"
    issuer="$(openssl x509 -in "$c" -noout -issuer -nameopt RFC2253 | sed 's/^issuer= *//')"
    if openssl x509 -in "$c" -noout -text | grep -q "CA:TRUE"; then
      if [ "$subject" = "$issuer" ]; then cat "$c" >> "$ROOT"; info "Root CA:      ${subject}"; else cat "$c" >> "$CHAIN"; info "Intermediate: ${subject}"; fi
    elif san_matches "$c" "$HOST"; then
      LEAF="${CERT_WORK}/leaf.pem"; cp "$c" "$LEAF"; info "Server:       ${subject}"
    else
      info "Ignored (not for ${HOST}): ${subject}"
    fi
  done
  [ -n "$LEAF" ] || die "No certificate in the ZIP is valid for ${HOST} (checked the SAN)."
  openssl x509 -in "$LEAF" -noout -checkend 0 >/dev/null || die "The certificate for ${HOST} has expired ($(openssl x509 -in "$LEAF" -noout -enddate))."
  openssl x509 -in "$LEAF" -noout -checkend $((30 * 86400)) >/dev/null || warn "The certificate expires within 30 days: $(openssl x509 -in "$LEAF" -noout -enddate)."
  info "Valid $(openssl x509 -in "$LEAF" -noout -startdate | cut -d= -f2) to $(openssl x509 -in "$LEAF" -noout -enddate | cut -d= -f2)"
  info "SAN: $(san_names "$LEAF" | tr '\n' ' ')"
  openssl x509 -in "$LEAF" -noout -text | grep -A1 "Extended Key Usage" | grep -q "TLS Web Server Authentication" || die "The certificate is not issued for TLS servers (no serverAuth EKU)."
  verify_args=(-purpose sslserver)
  [ -s "$CHAIN" ] && verify_args+=(-untrusted "$CHAIN")
  if [ -s "$ROOT" ]; then
    verify_args+=(-CAfile "$ROOT")
  else
    warn "The ZIP has no root CA certificate; the chain is checked against the system trust store."
  fi
  result="$(openssl verify "${verify_args[@]}" "$LEAF" 2>&1)" || die "The certificate chain does not verify: $(printf '%s' "$result" | tail -1)"
  info "Chain verified up to the root for TLS server use"

  want="$(pubkey_hash "$LEAF")"
  [ -n "$want" ] || die "Could not read the public key of the certificate."
  if [ -n "$KEY_FILE" ]; then
    [ -s "$KEY_FILE" ] || die "--key ${KEY_FILE} does not exist."
    [ "$(key_hash "$KEY_FILE")" = "$want" ] || die "${KEY_FILE} is not the private key of this certificate (or it is passphrase-protected)."
  else
    mapfile -t candidates < <({ echo "${ETC_DIR}/tls/portal.key"; find "${CERT_WORK}/x" /root /etc/pki/tls/private -maxdepth 3 -type f \( -name '*.key' -o -name '*.pem' \) -size -64k 2>/dev/null; } | sort -u)
    for candidate in "${candidates[@]}"; do
      [ -f "$candidate" ] && grep -q "PRIVATE KEY" "$candidate" 2>/dev/null || continue
      grep -q "ENCRYPTED" "$candidate" && { warn "${candidate} is passphrase-protected; decrypt it with: openssl pkey -in ${candidate} -out /root/${HOST}.key"; continue; }
      if [ "$(key_hash "$candidate")" = "$want" ]; then KEY_FILE="$candidate"; break; fi
    done
    [ -n "$KEY_FILE" ] || die "The private key for this certificate was not found on this server. It is not in the ZIP (which holds only public certificates). Copy the key created with the certificate request to /root/${HOST}.key (chmod 600) and run again with --key /root/${HOST}.key."
  fi
  info "Private key: ${KEY_FILE} (matches the certificate)"
  # The key in /etc/uagent/tls is replaced during the import; work from a private copy.
  cp -p "$KEY_FILE" "${CERT_WORK}/portal.key"
  KEY_FILE="${CERT_WORK}/portal.key"
}

if [ "$CHECK_ONLY" -eq 1 ]; then
  PHASE="certificate"
  CERT_SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  step "Checking the certificate for ${HOST} (nothing on this server is changed)"
  validate_certificate
  step "The certificate, chain and private key are valid for ${HOST}"
  exit 0
fi

[ "$(id -u)" -eq 0 ] || { echo "Run this as root." >&2; exit 1; }
install -d -m 0700 "$LOG_DIR" "$BACKUP_DIR"
LOG="${LOG_DIR}/redeploy-${TS}.log"
# Everything goes to the terminal and the log; the copy in the log has passwords masked.
exec > >(tee >(sed -u -E 's/((Password|password|PORTAL_PASS|SESSION_SECRET|ENROLLMENT_KEY)[:=] *)[^ ]+/\1********/g' >> "$LOG")) 2>&1

# --- 1. Preflight -------------------------------------------------------------------------------------
step "Preflight checks"
. /etc/os-release
case "${ID:-}" in centos|rhel|rocky|almalinux|ol) info "OS: ${PRETTY_NAME}" ;; *) die "Unsupported OS ${ID:-unknown}; use a CentOS/RHEL-family server." ;; esac
[ -d /run/systemd/system ] || die "systemd is required."
missing=()
for tool in git curl openssl unzip tar sha256sum; do command -v "$tool" >/dev/null 2>&1 || missing+=("$tool"); done
if [ ${#missing[@]} -gt 0 ]; then
  info "Installing missing tools: ${missing[*]}"
  dnf -y install git curl openssl unzip tar coreutils >/dev/null
fi
for path in /opt /var /root; do
  free_kb="$(df -Pk "$path" | awk 'NR==2 {print $4}')"
  [ "${free_kb:-0}" -ge 2097152 ] || die "Less than 2 GB free on the filesystem holding ${path}."
done
info "Disk space: OK"
getent hosts github.com >/dev/null || die "github.com does not resolve. Check /etc/resolv.conf and the network."
curl -fsS --max-time 20 -o /dev/null https://github.com || die "https://github.com is not reachable (proxy or firewall?)."
REMOTE_COMMIT="$(git ls-remote "$REPO_URL" "refs/heads/${BRANCH}" | awk '{print $1}')"
[ -n "$REMOTE_COMMIT" ] || die "Branch ${BRANCH} was not found in ${REPO_URL}."
info "Remote ${BRANCH}: ${REMOTE_COMMIT}"
if getent hosts "$HOST" >/dev/null; then
  RESOLVED="$(getent hosts "$HOST" | awk '{print $1}' | sort -u | tr '\n' ' ')"
  info "${HOST} resolves to ${RESOLVED}"
  LOCAL_IPS=" $(hostname -I) "
  match=0
  for ip in $RESOLVED; do [[ "$LOCAL_IPS" == *" $ip "* ]] && match=1; done
  [ "$match" -eq 1 ] || warn "${HOST} does not resolve to an address of this server ($(hostname -I | xargs)). Browsers and agents will not reach it until DNS is fixed."
else
  warn "${HOST} does not resolve yet. Create an A record pointing to $(hostname -I | awk '{print $1}') before agents use it."
fi

# --- 2. Review the current installation ---------------------------------------------------------------
PHASE="review"
step "Current installation"
if [ -d "${INSTALL_DIR}/.git" ]; then
  info "Code: ${INSTALL_DIR} at $(git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
else
  info "Code: ${INSTALL_DIR} $( [ -d "$INSTALL_DIR" ] && echo "(not a git checkout)" || echo "(not installed)")"
fi
info "Service: $(systemctl is-active "$SERVICE" 2>/dev/null || true), $(systemctl is-enabled "$SERVICE" 2>/dev/null || true) at boot"
if [ -f "${ETC_DIR}/portal.env" ]; then
  info "Configuration (${ETC_DIR}/portal.env, secrets masked):"
  mask_env "${ETC_DIR}/portal.env" | grep -Ev '^\s*(#|$)' | sed 's/^/      /'
fi
if [ -s "${ETC_DIR}/tls/portal.crt" ]; then
  info "Current certificate: $(openssl x509 -in "${ETC_DIR}/tls/portal.crt" -noout -subject -enddate 2>/dev/null | tr '\n' ' ')"
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  info "Firewall (default zone): services $(firewall-cmd --list-services | xargs), ports $(firewall-cmd --list-ports | xargs)"
fi
info "Listening: $(ss -Htln | awk '{print $4}' | sed 's/.*://' | sort -un | tr '\n' ' ')"

# --- 3. Stage and validate the new code ---------------------------------------------------------------
PHASE="stage"
step "Cloning ${BRANCH} into a staging directory"
git clone --quiet --branch "$BRANCH" "$REPO_URL" "$STAGE"
STAGE_COMMIT="$(git -C "$STAGE" rev-parse HEAD)"
[ "$STAGE_COMMIT" = "$REMOTE_COMMIT" ] || die "The clone (${STAGE_COMMIT}) is not the remote head (${REMOTE_COMMIT}); someone pushed meanwhile. Run again."
info "Commit $(git -C "$STAGE" log -1 --format='%h %s (%an, %cd)' --date=short)"
for file in scripts/install-centos.sh scripts/uagent-tls.sh scripts/uagent-maintenance.sh scripts/uagent-sysadmin.py portal/server.js portal/package.json portal/package-lock.json; do
  [ -s "${STAGE}/${file}" ] || die "The clone is missing ${file}; it is not a complete uAgent repository."
done
for script in "$STAGE"/scripts/*.sh; do bash -n "$script" || die "$(basename "$script") has a syntax error."; done
if command -v node >/dev/null 2>&1; then
  node --check "${STAGE}/portal/server.js" || die "portal/server.js does not parse."
fi
info "Repository validated"

# --- 4. Certificate -----------------------------------------------------------------------------------
PHASE="certificate"
step "Validating the certificate for ${HOST}"
CERT_SOURCE_DIR="$STAGE"
validate_certificate

if [ "$ASSUME_YES" -ne 1 ] && [ -t 0 ]; then
  printf '\nRedeploy %s (%s) on this server with the certificate above? [y/N] ' "$BRANCH" "${STAGE_COMMIT:0:12}"
  read -r answer
  [[ "$answer" =~ ^[Yy] ]] || die "Cancelled; nothing was changed."
fi

# --- 5. Backup ----------------------------------------------------------------------------------------
PHASE="backup"
step "Backing up configuration, certificates and state"
BACKUP="${BACKUP_DIR}/uagent-${TS}.tgz"
paths=()
for p in "$ETC_DIR" "$STATE_DIR" /etc/systemd/system/${SERVICE}.service /etc/systemd/system/uagent-portal-watch.service /etc/systemd/system/uagent-portal-watch.timer \
         /etc/sudoers.d/uagent-maintenance /etc/sudoers.d/uagent-sysadmin /usr/local/sbin/uagent-maintenance /usr/local/sbin/uagent-sysadmin /usr/local/sbin/uagent-tls \
         /usr/local/bin/uagent-portal-watch /etc/firewalld/zones /var/lib/uagent-sysadmin; do
  [ -e "$p" ] && paths+=("${p#/}")
done
if [ ${#paths[@]} -gt 0 ]; then
  tar -czpf "$BACKUP" -C / "${paths[@]}"
  tar -tzf "$BACKUP" >/dev/null || die "The backup ${BACKUP} cannot be read back."
  chmod 600 "$BACKUP"
  info "Backup: ${BACKUP} ($(du -h "$BACKUP" | cut -f1), sha256 $(sha256sum "$BACKUP" | cut -c1-16)...)"
else
  BACKUP=""
  info "No existing installation to back up"
fi

# --- 6. Replace the code ------------------------------------------------------------------------------
PHASE="install"
step "Stopping the portal and setting the old code aside"
systemctl stop uagent-portal-watch.timer 2>/dev/null || true
systemctl stop "$SERVICE" 2>/dev/null || true
if [ -d "$INSTALL_DIR" ]; then
  PREV_DIR="${INSTALL_DIR}.prev-${TS}"
  mv "$INSTALL_DIR" "$PREV_DIR"
  info "Previous code: ${PREV_DIR}"
fi
mv "$STAGE" "$INSTALL_DIR"
chown -R uagent:uagent "$INSTALL_DIR" 2>/dev/null || true

step "Running the installer"
args=(--host "$HOST" --tls import --cert "$LEAF" --key "$KEY_FILE")
[ -s "$CHAIN" ] && args+=(--chain "$CHAIN")
[ -s "$ROOT" ] && args+=(--ca "$ROOT")
[ "$SKIP_AGENT" -eq 1 ] && args+=(--skip-agent)
bash "${INSTALL_DIR}/scripts/install-centos.sh" "${args[@]}" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"

# --- 7. Verify ----------------------------------------------------------------------------------------
PHASE="verify"
step "Verifying the deployment"
get_env() { grep -E "^$1=" "${ETC_DIR}/portal.env" | tail -1 | cut -d= -f2- | tr -d "\"'"; }
HTTPS_PORT="$(get_env PORTAL_HTTPS_PORT)"; HTTPS_PORT="${HTTPS_PORT:-443}"
HTTP_PORT="$(get_env PORTAL_HTTP_PORT)"; HTTP_PORT="${HTTP_PORT:-80}"
BIND_ADDRESS="$(get_env PORTAL_BIND_ADDRESS)"
case "$BIND_ADDRESS" in ""|0.0.0.0|::|localhost) PROBE="127.0.0.1" ;; *:*) PROBE="$BIND_ADDRESS" ;; *) PROBE="$BIND_ADDRESS" ;; esac
case "$PROBE" in *:*) PROBE_URL="[${PROBE}]" ;; *) PROBE_URL="$PROBE" ;; esac
systemctl is-enabled --quiet "$SERVICE" || die "${SERVICE} is not enabled at boot."
for i in $(seq 1 30); do systemctl is-active --quiet "$SERVICE" && break; sleep 2; done
systemctl is-active --quiet "$SERVICE" || die "${SERVICE} is not running: $(journalctl -u "$SERVICE" -n 20 --no-pager)"
info "Service: running and enabled at boot"
TRUST="${CERT_WORK}/trust.pem"
if [ -s "$ROOT" ]; then cp "$ROOT" "$TRUST"; else cp /etc/pki/tls/certs/ca-bundle.crt "$TRUST"; fi
ok=0
for i in $(seq 1 30); do
  if curl -fsS --max-time 5 --cacert "$TRUST" --resolve "${HOST}:${HTTPS_PORT}:${PROBE}" "https://${HOST}:${HTTPS_PORT}/healthz" -o "${CERT_WORK}/health.json"; then ok=1; break; fi
  sleep 2
done
[ "$ok" -eq 1 ] || die "https://${HOST}:${HTTPS_PORT}/healthz did not answer with a certificate trusted by the CA chain."
info "HTTPS: https://${HOST}:${HTTPS_PORT}/healthz answers, certificate verified against the CA (no -k)"
served="$(openssl s_client -connect "${PROBE_URL}:${HTTPS_PORT}" -servername "$HOST" </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 | cut -d= -f2 || true)"
[ "$served" = "$(openssl x509 -in "$LEAF" -noout -fingerprint -sha256 | cut -d= -f2)" ] || die "The portal serves a different certificate than the one imported."
chain_count="$(openssl s_client -connect "${PROBE_URL}:${HTTPS_PORT}" -servername "$HOST" -showcerts </dev/null 2>/dev/null | grep -c 'BEGIN CERTIFICATE' || true)"
info "Served certificate matches; the server sends ${chain_count} certificate(s) in the chain"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 --resolve "${HOST}:${HTTP_PORT}:${PROBE}" "http://${HOST}:${HTTP_PORT}/login" || true)"
case "$code" in 301|302|307|308) info "HTTP: redirects to HTTPS (${code})" ;; 200) warn "HTTP answers 200 without redirecting (FORCE_HTTPS=false?)." ;; *) warn "HTTP on port ${HTTP_PORT} answered ${code}." ;; esac
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  open="$(firewall-cmd --list-ports) $(firewall-cmd --list-services)"
  for p in "$HTTP_PORT" "$HTTPS_PORT"; do
    if [[ " $open " == *" ${p}/tcp "* ]] || { [ "$p" = 80 ] && [[ " $open " == *" http "* ]]; } || { [ "$p" = 443 ] && [[ " $open " == *" https "* ]]; }; then
      info "Firewall: ${p}/tcp open"
    else
      warn "Firewall: ${p}/tcp is not open in the default zone (unless --allow-from rich rules allow it)."
    fi
  done
fi
if command -v uagent-tls >/dev/null 2>&1; then
  uagent-tls check --host "$HOST" --port "$HTTPS_PORT" | sed 's/^/    /' || warn "uagent-tls check reported a problem (see above)."
fi
[ -x /usr/local/sbin/uagent-sysadmin ] && info "Server administration helper: installed" || warn "The server administration helper is not installed; the Portal server page is read-only."

# --- 8. Remove obsolete files -------------------------------------------------------------------------
PHASE="cleanup"
step "Removing obsolete files"
mapfile -t old < <(ls -1dt "${INSTALL_DIR}".prev-* 2>/dev/null || true)
for ((i = KEEP_OLD; i < ${#old[@]}; i++)); do rm -rf "${old[$i]}"; info "Removed ${old[$i]}"; done
rm -rf "${INSTALL_DIR}".failed-* /tmp/dotnet-install.sh 2>/dev/null || true
mapfile -t backups < <(ls -1t "${BACKUP_DIR}"/uagent-*.tgz 2>/dev/null || true)
for ((i = 10; i < ${#backups[@]}; i++)); do rm -f "${backups[$i]}"; done
trap - ERR

step "Done"
cat <<EOF
    Commit:       ${STAGE_COMMIT}
    Portal:       https://${HOST}$( [ "$HTTPS_PORT" = 443 ] || echo ":${HTTPS_PORT}")/
    Backup:       ${BACKUP:-none}
    Previous code ${PREV_DIR:-none} (kept for manual rollback)
    Log:          ${LOG}

    Browsers and agents must trust the issuing CA (HELIX-CA for the bundled certificate): deploy the
    root with Group Policy or Intune if it is not already in the Windows trust store.
    Manual rollback: systemctl stop ${SERVICE}; mv ${INSTALL_DIR} ${INSTALL_DIR}.bad; mv ${PREV_DIR:-<prev>} ${INSTALL_DIR};
                     tar -xzpf ${BACKUP:-<backup>} -C /; systemctl daemon-reload; systemctl start ${SERVICE}
EOF
