#!/usr/bin/env bash
# One-command install of the uAgent portal on CentOS and other RHEL-family systems.
#
# Installs the OS packages, Node.js 22 LTS, and the .NET SDK 10, clones this repo to /opt/uagent,
# creates a private certificate authority and a TLS certificate, generates portal secrets, builds the
# Windows agent so /download/agent works, and runs the portal under systemd on ports 80 and 443.
#
# Usage (on the server, as root):
#   curl -fsSL https://raw.githubusercontent.com/sumit-kumawat/uAgent/main/scripts/install-centos.sh | bash
#   bash install-centos.sh --host uagent.example.com
#   bash install-centos.sh --tls import --cert portal.crt --key portal.key --chain intermediates.pem
#
# Re-running is safe: it updates the code, rebuilds the agent, and restarts the service. Secrets, the
# TLS private key, the private CA, the host setting, and agent records are kept.
set -euo pipefail

REPO_URL="https://github.com/sumit-kumawat/uAgent.git"
INSTALL_DIR="/opt/uagent"
ENV_FILE="/etc/uagent/portal.env"
TLS_DIR="/etc/uagent/tls"
STATE_DIR="/var/lib/uagent"
SERVICE_NAME="uagent-portal"
NODE_MAJOR="22"
DOTNET_CHANNEL="10.0"

PUBLIC_HOST="${PUBLIC_HOST:-}"
TLS_MODE_ARG=""
IMPORT_CERT=""
IMPORT_KEY=""
IMPORT_CHAIN=""
IMPORT_CA=""
ALLOW_FROM=()
SKIP_AGENT=0
SKIP_FIREWALL=0

usage() {
  cat <<EOF
Usage: install-centos.sh [--host NAME] [--tls MODE] [options]

  --host NAME          DNS name (FQDN) agents and browsers use. Optional: without it the portal starts
                       on this server's IP and asks the administrator to set the name in Settings.
  --tls MODE           internal-ca  A private root CA on this server issues and renews the certificate
                                    (default for new installs). Deploy /etc/uagent/tls/ca.crt with
                                    Group Policy or Intune so browsers trust it.
                       import       Use a certificate from a public or enterprise CA (--cert/--key).
                       self-signed  Development only. Browsers show ERR_CERT_AUTHORITY_INVALID.
                       Re-runs keep the current mode unless --tls is given.
  --cert FILE          PEM certificate to import (implies --tls import).
  --key FILE           PEM private key for --cert.
  --chain FILE         PEM intermediate certificates for --cert.
  --ca FILE            PEM enterprise root that issued --cert (embedded in agents for validation).
  --allow-from CIDR    Accept HTTP/HTTPS only from this source range (repeatable), for example
                       --allow-from 10.0.0.0/8. Default: any source.
  --skip-agent         Do not install the .NET SDK or build the Windows installer.
  --skip-firewall      Do not install or change firewalld.
EOF
}

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need() { [ $# -ge 2 ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --host) need "$@"; PUBLIC_HOST="$2"; shift 2 ;;
    --tls) need "$@"; TLS_MODE_ARG="$2"; shift 2 ;;
    --cert) need "$@"; IMPORT_CERT="$2"; TLS_MODE_ARG="import"; shift 2 ;;
    --key) need "$@"; IMPORT_KEY="$2"; shift 2 ;;
    --chain) need "$@"; IMPORT_CHAIN="$2"; shift 2 ;;
    --ca) need "$@"; IMPORT_CA="$2"; shift 2 ;;
    --allow-from) need "$@"; ALLOW_FROM+=("$2"); shift 2 ;;
    --skip-agent) SKIP_AGENT=1; shift ;;
    --skip-firewall) SKIP_FIREWALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

PUBLIC_HOST="$(printf '%s' "$PUBLIC_HOST" | tr 'A-Z' 'a-z')"
if [ -n "$PUBLIC_HOST" ]; then
  [[ "$PUBLIC_HOST" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "Host '${PUBLIC_HOST}' may contain only letters, digits, dots, and hyphens."
fi
case "$TLS_MODE_ARG" in
  ""|internal-ca|import|self-signed) ;;
  *) die "--tls must be internal-ca, import, or self-signed." ;;
esac
if [ -n "$IMPORT_CERT" ] && [ -z "$IMPORT_KEY" ]; then
  die "--cert needs --key."
fi
for cidr in "${ALLOW_FROM[@]+"${ALLOW_FROM[@]}"}"; do
  [[ "$cidr" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || die "--allow-from '${cidr}' is not an IPv4 address or CIDR range."
done

[ "$(id -u)" -eq 0 ] || die "Run this script as root."
[ -f /etc/os-release ] || die "Cannot read /etc/os-release."
# shellcheck disable=SC1091
. /etc/os-release

case "${ID:-}" in
  centos|rhel|rocky|almalinux|ol) ;;
  *) die "This installer supports CentOS, RHEL, Rocky Linux, AlmaLinux, and Oracle Linux. This system is '${ID:-unknown}'." ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) NODE_ARCH="x64" ;;
  aarch64) NODE_ARCH="arm64" ;;
  *) die "Unsupported CPU architecture: $ARCH. Use x86_64 or aarch64." ;;
esac

GLIBC="$(ldd --version | awk 'NR==1 { print $NF }')"
awk -v v="$GLIBC" 'BEGIN { split(v, a, "."); if (a[1] < 2 || (a[1] == 2 && a[2] < 28)) exit 1; }' \
  || die "glibc ${GLIBC} is too old. Node.js ${NODE_MAJOR} needs glibc 2.28 or newer (CentOS Stream 8/9, Rocky 8/9, AlmaLinux 8/9, or RHEL 8/9). CentOS 7 cannot run this portal."

if command -v dnf >/dev/null 2>&1; then
  PM="dnf"
else
  PM="yum"
fi

# CentOS Linux 8 mirrors were removed at end of life. Without vault.centos.org, dnf cannot
# install git, firewalld, or anything else. Rocky, Alma, and RHEL keep their own repositories.
fix_centos8_vault() {
  [ "${ID:-}" = "centos" ] || return 0
  case "${VERSION_ID:-}" in
    8|8.*) ;;
    *) return 0 ;;
  esac
  log "CentOS 8 is end of life. Switching yum repositories to vault.centos.org 8.5.2111."
  mkdir -p /etc/yum.repos.d/backup
  shopt -s nullglob
  local repos=(/etc/yum.repos.d/CentOS-*.repo)
  if [ "${#repos[@]}" -gt 0 ]; then
    mv "${repos[@]}" /etc/yum.repos.d/backup/
  fi
  shopt -u nullglob
  cat > /etc/yum.repos.d/CentOS-Vault.repo <<'EOF'
[baseos]
name=CentOS 8.5.2111 - BaseOS
baseurl=http://vault.centos.org/8.5.2111/BaseOS/$basearch/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial

[appstream]
name=CentOS 8.5.2111 - AppStream
baseurl=http://vault.centos.org/8.5.2111/AppStream/$basearch/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial

[extras]
name=CentOS 8.5.2111 - Extras
baseurl=http://vault.centos.org/8.5.2111/extras/$basearch/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial
EOF
  $PM clean all || true
}

fix_centos8_vault

log "Installing OS packages (${PRETTY_NAME:-$ID})"
$PM install -y git curl ca-certificates tar xz openssl openssl-libs libicu iproute
if [ "$SKIP_FIREWALL" -eq 0 ]; then
  $PM install -y firewalld
fi
$PM install -y policycoreutils-python-utils 2>/dev/null || $PM install -y policycoreutils-python 2>/dev/null || true

log "Installing Node.js ${NODE_MAJOR} LTS"
NODE_JSON="$(curl -fsSL https://nodejs.org/dist/index.json)"
set +o pipefail
NODE_VERSION="$(printf '%s\n' "$NODE_JSON" | sed -n "s/.*\"version\": *\"\\(v${NODE_MAJOR}\\.[0-9][0-9.]*\\)\".*/\\1/p" | head -1)"
set -o pipefail
[ -n "$NODE_VERSION" ] || die "Could not find a Node.js ${NODE_MAJOR} release on nodejs.org."
if [ "$(/usr/local/bin/node -v 2>/dev/null || true)" != "$NODE_VERSION" ]; then
  NODE_TARBALL="node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"
  curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/${NODE_TARBALL}" -o "/tmp/${NODE_TARBALL}"
  curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/SHASUMS256.txt" -o /tmp/node-SHASUMS256.txt
  (cd /tmp && grep " ${NODE_TARBALL}\$" node-SHASUMS256.txt | sha256sum -c -) || die "Node.js download failed its SHA-256 check."
  tar -xJf "/tmp/${NODE_TARBALL}" -C /usr/local --strip-components=1
  rm -f "/tmp/${NODE_TARBALL}" /tmp/node-SHASUMS256.txt
  hash -r
fi
# sudo on RHEL uses a secure_path that omits /usr/local/bin. npm is "#!/usr/bin/env node", so node
# has to be on the default PATH or that lookup fails with "node: No such file or directory".
export PATH="/usr/local/bin:${PATH}"
for cmd in node npm npx corepack; do
  if [ -e "/usr/local/bin/${cmd}" ]; then
    ln -sfn "/usr/local/bin/${cmd}" "/usr/bin/${cmd}"
  fi
done
if command -v restorecon >/dev/null 2>&1; then
  restorecon -v /usr/local/bin/node /usr/bin/node /usr/local/bin/npm /usr/bin/npm || true
fi
node -v
npm -v

if [ "$SKIP_AGENT" -eq 0 ]; then
  log "Installing .NET SDK ${DOTNET_CHANNEL} (builds the Windows agent download)"
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  bash /tmp/dotnet-install.sh --channel "$DOTNET_CHANNEL" --install-dir /usr/share/dotnet
  ln -sfn /usr/share/dotnet/dotnet /usr/local/bin/dotnet
  ln -sfn /usr/share/dotnet/dotnet /usr/bin/dotnet
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -v /usr/local/bin/dotnet /usr/bin/dotnet /usr/share/dotnet/dotnet || true
  fi
  rm -f /tmp/dotnet-install.sh
  DOTNET_ROOT=/usr/share/dotnet /usr/local/bin/dotnet --version
fi

if ! id uagent >/dev/null 2>&1; then
  log "Creating service account uagent"
  useradd --system --home-dir "$STATE_DIR" --create-home --shell /sbin/nologin uagent
fi
install -d -m 0750 -o uagent -g uagent "$STATE_DIR"
install -d -m 0755 -o root -g root /etc/uagent

log "Installing application into ${INSTALL_DIR}"
if [ ! -d "${INSTALL_DIR}/.git" ]; then
  git clone --branch main "$REPO_URL" "$INSTALL_DIR"
else
  git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" fetch origin main
  git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" checkout -B main origin/main
fi
chown -R uagent:uagent "$INSTALL_DIR"

log "Installing portal npm packages"
npm_ok=0
for attempt in 1 2 3 4 5; do
  if (
    cd "${INSTALL_DIR}/portal"
    runuser -u uagent -- env \
      HOME="$STATE_DIR" \
      PATH="/usr/local/bin:${PATH}" \
      NODE_OPTIONS="--dns-result-order=ipv4first" \
      npm_config_fetch_retries=5 \
      npm_config_fetch_retry_mintimeout=10000 \
      npm_config_fetch_retry_maxtimeout=60000 \
      /usr/local/bin/npm ci --omit=dev
  ); then
    npm_ok=1
    break
  fi
  echo "  npm download failed (attempt ${attempt} of 5). Retrying..."
  sleep $((attempt * 5))
done
[ "$npm_ok" -eq 1 ] || die "Could not download the portal packages from registry.npmjs.org. Check this server's HTTPS access, then re-run this script."

set_env() {
  local key="$1" value="${2:-}"
  sed -i "/^${key}=/d" "$ENV_FILE"
  [ -z "$value" ] || printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
}
get_env() { sed -n "s/^${1}=//p" "$ENV_FILE" | tail -1; }

INITIAL_PASS=""
if [ ! -f "$ENV_FILE" ]; then
  log "Creating ${ENV_FILE}"
  INITIAL_PASS="$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-16)"
  umask 077
  cat > "$ENV_FILE" <<EOF
PORTAL_USER=admin
PORTAL_PASS=${INITIAL_PASS}
ENROLLMENT_KEY=$(openssl rand -hex 24)
SESSION_SECRET=$(openssl rand -hex 32)
FORCE_HTTPS=true
EOF
  umask 022
fi
chown root:root "$ENV_FILE"
chmod 600 "$ENV_FILE"
# The host is kept in the portal's Settings (and seeded below by --host), not in this file.
set_env PUBLIC_HOST ""
PORTAL_USER="$(get_env PORTAL_USER)"
PORTAL_USER="${PORTAL_USER:-admin}"

LAN_IPS=()
for ip in $(hostname -I 2>/dev/null); do
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
  LAN_IPS+=("$ip")
done
LAN_IP="${LAN_IPS[0]:-}"
SAVED_HOST="$(sed -n 's/.*"host":"\([^"]*\)".*/\1/p' "${STATE_DIR}/portal-host.json" 2>/dev/null || true)"
CERT_HOST="${PUBLIC_HOST:-${SAVED_HOST:-${LAN_IP:-localhost}}}"
IP_ARGS=()
for ip in "${LAN_IPS[@]+"${LAN_IPS[@]}"}"; do
  IP_ARGS+=(--ip "$ip")
done
[ "${#IP_ARGS[@]}" -gt 0 ] || IP_ARGS=(--ip 127.0.0.1)

TLS_MODE="${TLS_MODE_ARG:-$(get_env TLS_MODE)}"
TLS_MODE="${TLS_MODE:-internal-ca}"
log "Configuring TLS (${TLS_MODE})"
install -d -m 0750 -o uagent -g uagent "$TLS_DIR"
LEGACY_KEY="${INSTALL_DIR}/portal/certs/portal.key"
if [ ! -s "${TLS_DIR}/portal.key" ] && [ -s "$LEGACY_KEY" ]; then
  # Retain the existing key so installed development agents with a public-key pin remain valid.
  install -m 0600 -o uagent -g uagent "$LEGACY_KEY" "${TLS_DIR}/portal.key"
fi
chmod +x "${INSTALL_DIR}/scripts/uagent-tls.sh"
ln -sfn "${INSTALL_DIR}/scripts/uagent-tls.sh" /usr/local/sbin/uagent-tls
TLS_TOOL=(env TLS_DIR="$TLS_DIR" TLS_OWNER=uagent bash "${INSTALL_DIR}/scripts/uagent-tls.sh")
issued_by_ca() {
  [ -s "${TLS_DIR}/portal.crt" ] && [ -s "${TLS_DIR}/ca.crt" ] &&
    openssl verify -CAfile "${TLS_DIR}/ca.crt" "${TLS_DIR}/portal.crt" >/dev/null 2>&1
}
self_signed_cert() {
  [ -s "${TLS_DIR}/portal.crt" ] &&
    openssl verify -CAfile "${TLS_DIR}/portal.crt" "${TLS_DIR}/portal.crt" >/dev/null 2>&1
}
case "$TLS_MODE" in
  internal-ca)
    "${TLS_TOOL[@]}" init-ca
    if ! issued_by_ca; then
      "${TLS_TOOL[@]}" issue --host "$CERT_HOST" "${IP_ARGS[@]}"
    fi
    set_env TLS_CA_FILE "${TLS_DIR}/ca.crt"
    set_env TLS_CA_KEY_FILE "${TLS_DIR}/ca.key"
    set_env TLS_MANAGE_SELF_SIGNED false
    ;;
  import)
    if [ -n "$IMPORT_CERT" ]; then
      args=(import --cert "$IMPORT_CERT" --key "$IMPORT_KEY")
      [ -z "$IMPORT_CHAIN" ] || args+=(--chain "$IMPORT_CHAIN")
      [ -z "$IMPORT_CA" ] || args+=(--ca "$IMPORT_CA")
      "${TLS_TOOL[@]}" "${args[@]}"
      if [ -n "$IMPORT_CA" ]; then
        set_env TLS_CA_FILE "${TLS_DIR}/ca.crt"
      else
        set_env TLS_CA_FILE ""
      fi
    fi
    [ -s "${TLS_DIR}/portal.crt" ] || die "--tls import needs --cert FILE --key FILE the first time."
    set_env TLS_CA_KEY_FILE ""
    set_env TLS_MANAGE_SELF_SIGNED false
    ;;
  self-signed)
    if ! self_signed_cert; then
      if [ ! -s "${TLS_DIR}/portal.key" ]; then
        (umask 077; openssl genrsa -out "${TLS_DIR}/portal.key" 2048 2>/dev/null)
      fi
      SAN=""
      if [[ "$CERT_HOST" =~ ^[0-9.]+$ ]]; then
        SAN="IP:${CERT_HOST}"
      else
        SAN="DNS:${CERT_HOST}"
      fi
      for ip in "${LAN_IPS[@]+"${LAN_IPS[@]}"}"; do
        case ",${SAN}," in
          *",IP:${ip},"*) ;;
          *) SAN="${SAN},IP:${ip}" ;;
        esac
      done
      SAN="${SAN},DNS:localhost,IP:127.0.0.1"
      openssl req -x509 -key "${TLS_DIR}/portal.key" -sha256 -days 397 -subj "/CN=${CERT_HOST}" \
        -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" \
        -addext "subjectAltName=${SAN}" \
        -out "${TLS_DIR}/portal.crt" 2>/dev/null
      chown uagent:uagent "${TLS_DIR}/portal.key" "${TLS_DIR}/portal.crt"
      chmod 600 "${TLS_DIR}/portal.key"
    fi
    set_env TLS_CA_FILE ""
    set_env TLS_CA_KEY_FILE ""
    set_env TLS_MANAGE_SELF_SIGNED true
    ;;
esac
set_env TLS_MODE "$TLS_MODE"
set_env TLS_CERT_FILE "${TLS_DIR}/portal.crt"
set_env TLS_KEY_FILE "${TLS_DIR}/portal.key"

if [ -n "$PUBLIC_HOST" ]; then
  log "Setting the agent and dashboard host to ${PUBLIC_HOST}"
  printf '{"host":"%s","updatedUtc":"%s","updatedBy":"install-centos.sh"}\n' \
    "$PUBLIC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${STATE_DIR}/portal-host.json"
  chown uagent:uagent "${STATE_DIR}/portal-host.json"
  chmod 600 "${STATE_DIR}/portal-host.json"
fi

if [ "$SKIP_AGENT" -eq 0 ]; then
  log "Building the Windows agent (this can take several minutes)"
  runuser -u uagent -- env \
    HOME="$STATE_DIR" \
    DOTNET_ROOT=/usr/share/dotnet \
    DOTNET_CLI_HOME="$STATE_DIR" \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    NUGET_PACKAGES="${STATE_DIR}/.nuget/packages" \
    PATH="/usr/share/dotnet:/usr/local/bin:${PATH}" \
    bash "${INSTALL_DIR}/scripts/build-agent.sh"
  chown -R uagent:uagent "${INSTALL_DIR}/portal/agent-dist"
fi

if command -v semanage >/dev/null 2>&1 && command -v restorecon >/dev/null 2>&1; then
  log "Labeling ${INSTALL_DIR} for SELinux"
  semanage fcontext -a -t usr_t "${INSTALL_DIR}(/.*)?" 2>/dev/null \
    || semanage fcontext -m -t usr_t "${INSTALL_DIR}(/.*)?" \
    || true
  restorecon -Rv "$INSTALL_DIR" || true
  restorecon -R /etc/uagent "$STATE_DIR" || true
fi

log "Installing systemd service ${SERVICE_NAME}"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=uAgent management portal
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=uagent
Group=uagent
WorkingDirectory=${INSTALL_DIR}/portal
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/local/bin/node server.js
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65535
StateDirectory=uagent
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${TLS_DIR} ${STATE_DIR}

[Install]
WantedBy=multi-user.target
EOF

if ss -lnt | awk '{print $4}' | grep -Eq '(^|:)80$' || ss -lnt | awk '{print $4}' | grep -Eq '(^|:)443$'; then
  if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Port 80 or 443 is already in use"
    ss -lntup | grep -E ':80 |:443 ' || true
    die "Stop the program using port 80/443 (often httpd or nginx), then re-run this script."
  fi
fi

install -m 0755 "${INSTALL_DIR}/scripts/uagent-portal-watch.sh" /usr/local/bin/uagent-portal-watch
cat > /etc/systemd/system/uagent-portal-watch.service <<'EOF'
[Unit]
Description=Check that the uAgent portal answers
After=uagent-portal.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/uagent-portal-watch
EOF
cat > /etc/systemd/system/uagent-portal-watch.timer <<'EOF'
[Unit]
Description=Keep the uAgent portal running

[Timer]
OnBootSec=45
OnUnitActiveSec=60
AccuracySec=10

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" uagent-portal-watch.timer
systemctl restart "$SERVICE_NAME"
systemctl restart uagent-portal-watch.timer

# Idempotent: each rule is queried first and added only when missing. Only SSH, HTTP (redirects to
# HTTPS), and HTTPS are opened; with --allow-from, HTTP and HTTPS are limited to those source ranges.
fw_ensure() {
  if firewall-cmd --permanent "--query-$1=$2" >/dev/null 2>&1; then
    echo "  [present] $1 $2"
  else
    firewall-cmd --permanent "--add-$1=$2" >/dev/null && echo "  [added]   $1 $2"
  fi
}
fw_remove() {
  if firewall-cmd --permanent "--query-$1=$2" >/dev/null 2>&1; then
    firewall-cmd --permanent "--remove-$1=$2" >/dev/null && echo "  [removed] $1 $2"
  fi
}
if [ "$SKIP_FIREWALL" -eq 0 ] && command -v firewall-cmd >/dev/null 2>&1; then
  log "Configuring firewalld (zone $(firewall-cmd --get-default-zone 2>/dev/null || echo default))"
  systemctl enable --now firewalld
  fw_ensure service ssh
  if [ "${#ALLOW_FROM[@]}" -eq 0 ]; then
    fw_ensure service http
    fw_ensure service https
  else
    fw_remove service http
    fw_remove service https
    for cidr in "${ALLOW_FROM[@]}"; do
      for svc in http https; do
        fw_ensure rich-rule "rule family=\"ipv4\" source address=\"${cidr}\" service name=\"${svc}\" accept"
      done
    done
  fi
  firewall-cmd --reload >/dev/null
  if [ "${#ALLOW_FROM[@]}" -eq 0 ] && ! firewall-cmd --query-service=https >/dev/null 2>&1; then
    echo "  WARNING: HTTPS is not open in the active zone. Check: firewall-cmd --get-active-zones; firewall-cmd --list-all"
  fi
fi

log "Waiting for the portal on localhost and this server's IP addresses"
ready=0
for _ in $(seq 1 20); do
  if curl -fsS --max-time 3 "http://127.0.0.1/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
[ "$ready" -eq 1 ] || die "The portal did not answer http://127.0.0.1/healthz. Check: journalctl -u ${SERVICE_NAME} -n 80 --no-pager"

probe_http() {
  local url="$1"
  if curl -fsS --max-time 5 -o /dev/null "$url"; then
    echo "  [OK] ${url}"
    return 0
  fi
  echo "  [FAILED] ${url}"
  return 1
}
# Liveness only: confirms 443 completes a TLS handshake. Certificate trust is reported by the portal.
probe_https() {
  local ip="$1"
  if timeout 5 openssl s_client -connect "${ip}:443" -servername "${PUBLIC_HOST:-$ip}" </dev/null >/dev/null 2>&1; then
    echo "  [OK] https://${ip}/"
    return 0
  fi
  echo "  [FAILED] https://${ip}/"
  return 1
}
REACH_FAILED=0
probe_http "http://127.0.0.1/healthz" || REACH_FAILED=1
probe_https "127.0.0.1" || REACH_FAILED=1
for ip in "${LAN_IPS[@]+"${LAN_IPS[@]}"}"; do
  probe_http "http://${ip}/healthz" || REACH_FAILED=1
  probe_https "$ip" || REACH_FAILED=1
done
[ "$REACH_FAILED" -eq 0 ] || die "The portal is not answering on localhost or a detected IP. Check: ss -lntup | grep -E ':80|:443'; firewall-cmd --list-all"

# On first start the portal stores operator passwords as scrypt hashes, so the plaintext seed can go.
if [ -s "${STATE_DIR}/operators.json" ] && [ -n "$(get_env PORTAL_PASS)" ]; then
  set_env PORTAL_PASS ""
fi

HEALTH="$(curl -fsS --max-time 3 http://127.0.0.1/healthz)"
AGENT_URL="$(printf '%s' "$HEALTH" | sed -n 's/.*"agentUrl":"\([^"]*\)".*/\1/p')"
AGENT_URL="${AGENT_URL:-https://${LAN_IP:-127.0.0.1}}"
NEEDS_DNS="$(printf '%s' "$HEALTH" | sed -n 's/.*"needsDns":\([a-z]*\).*/\1/p')"
SHOWN_HOST="$(printf '%s' "$AGENT_URL" | sed -E 's#^https?://##; s#[:/].*$##')"
sleep 1
TLS_CHECK="$("${TLS_TOOL[@]}" check --host "${SHOWN_HOST:-$CERT_HOST}" 2>&1 || true)"

cat <<EOF

uAgent portal is running.
  On this server:  https://127.0.0.1/
  On the network:  https://${LAN_IP:-127.0.0.1}/
  Agents use:      ${AGENT_URL}
  Health:          http://127.0.0.1/healthz
  Username:        ${PORTAL_USER}
EOF
if [ -n "$INITIAL_PASS" ]; then
  cat <<EOF
  Password:   ${INITIAL_PASS}
              Shown only now and not stored in plain text. You must change it at first sign-in.
EOF
else
  echo "  Password:   unchanged (the one set in the dashboard)."
fi
cat <<EOF
  TLS mode:   ${TLS_MODE}
${TLS_CHECK}
EOF
if [ "$TLS_MODE" = "internal-ca" ]; then
  cat <<EOF
  Root CA:    ${TLS_DIR}/ca.crt  (also ${AGENT_URL}/download/ca.crt)
              Deploy it to Trusted Root Certification Authorities with Group Policy or Intune so
              browsers trust the portal. Agents downloaded from the portal already include it.
EOF
elif [ "$TLS_MODE" = "self-signed" ]; then
  echo "  WARNING:    Self-signed certificates are for labs only. Browsers show ERR_CERT_AUTHORITY_INVALID."
fi
if [ "$NEEDS_DNS" = "true" ]; then
  cat <<EOF

Next: sign in and set the DNS name (FQDN) in Settings, or re-run with --host NAME.
Until then, agents and links use this server's IP address.
EOF
fi
cat <<EOF

The portal restarts if it crashes or the machine reboots, and its data is kept in ${STATE_DIR}.
  journalctl -u ${SERVICE_NAME} -f
  uagent-tls check --host ${SHOWN_HOST:-$CERT_HOST}
EOF
