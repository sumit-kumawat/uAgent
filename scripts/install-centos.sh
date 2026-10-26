#!/usr/bin/env bash
# One-command install of the uAgent portal on CentOS and other RHEL-family systems.
#
# Installs the OS packages, Node.js 22 LTS, and the .NET SDK 10, clones this repo to /opt/uagent,
# generates a TLS certificate and portal secrets, builds the Windows agent so /download/agent works,
# and runs the portal under systemd on ports 80 and 443.
#
# Usage (on the server, as root):
#   curl -fsSL https://raw.githubusercontent.com/sumit-kumawat/uAgent/main/scripts/install-centos.sh | bash
#   bash install-centos.sh --host uagent.sumitkumawat.com
#
# Re-running updates the code, rebuilds the agent, and restarts the service. Existing secrets in
# /etc/uagent/portal.env are kept unless you pass --host (that updates PUBLIC_HOST and renews the cert).
set -euo pipefail

REPO_URL="https://github.com/sumit-kumawat/uAgent.git"
INSTALL_DIR="/opt/uagent"
ENV_FILE="/etc/uagent/portal.env"
SERVICE_NAME="uagent-portal"
DEFAULT_HOST="uagent.sumitkumawat.com"
NODE_MAJOR="22"
DOTNET_CHANNEL="10.0"

HOST_SET=0
if [ -n "${PUBLIC_HOST+x}" ] && [ -n "$PUBLIC_HOST" ]; then
  HOST_SET=1
else
  PUBLIC_HOST="$DEFAULT_HOST"
fi
SKIP_AGENT=0
SKIP_FIREWALL=0

usage() {
  cat <<EOF
Usage: install-centos.sh [--host NAME] [--skip-agent] [--skip-firewall]

  --host NAME       Public DNS name embedded in links, the certificate, and the agent download.
                    Default: ${DEFAULT_HOST} (or the PUBLIC_HOST environment variable).
  --skip-agent      Do not install the .NET SDK or build the Windows installer.
  --skip-firewall   Do not install or change firewalld.
EOF
}

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --host)
      [ $# -ge 2 ] || die "--host needs a value"
      PUBLIC_HOST="$2"
      HOST_SET=1
      shift 2
      ;;
    --skip-agent) SKIP_AGENT=1; shift ;;
    --skip-firewall) SKIP_FIREWALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

[[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9.-]+$ ]] || die "Host '${PUBLIC_HOST}' may contain only letters, digits, dots, and hyphens."

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
  log "CentOS 8 is end of life. Switching yum repositories to vault.centos.org 8.5.2111"
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
baseurl=http://vault.centos.org/8.5.2111/BaseOS/x86_64/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial

[appstream]
name=CentOS 8.5.2111 - AppStream
baseurl=http://vault.centos.org/8.5.2111/AppStream/x86_64/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial

[extras]
name=CentOS 8.5.2111 - Extras
baseurl=http://vault.centos.org/8.5.2111/extras/x86_64/os/
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
NODE_TARBALL="node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"
curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/${NODE_TARBALL}" -o "/tmp/${NODE_TARBALL}"
tar -xJf "/tmp/${NODE_TARBALL}" -C /usr/local --strip-components=1
rm -f "/tmp/${NODE_TARBALL}"
hash -r
if command -v restorecon >/dev/null 2>&1; then
  restorecon -v /usr/local/bin/node /usr/local/bin/npm || true
fi
/usr/local/bin/node -v
/usr/local/bin/npm -v

if [ "$SKIP_AGENT" -eq 0 ]; then
  log "Installing .NET SDK ${DOTNET_CHANNEL} (builds the Windows agent download)"
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
  bash /tmp/dotnet-install.sh --channel "$DOTNET_CHANNEL" --install-dir /usr/share/dotnet
  ln -sfn /usr/share/dotnet/dotnet /usr/local/bin/dotnet
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -v /usr/local/bin/dotnet /usr/share/dotnet/dotnet || true
  fi
  rm -f /tmp/dotnet-install.sh
  DOTNET_ROOT=/usr/share/dotnet /usr/local/bin/dotnet --version
fi

if ! id uagent >/dev/null 2>&1; then
  log "Creating service account uagent"
  useradd --system --home-dir /var/lib/uagent --create-home --shell /sbin/nologin uagent
fi
install -d -m 0750 -o uagent -g uagent /var/lib/uagent /etc/uagent

log "Installing application into ${INSTALL_DIR}"
if [ ! -d "${INSTALL_DIR}/.git" ]; then
  git clone --branch main "$REPO_URL" "$INSTALL_DIR"
else
  git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" fetch origin main
  git -c safe.directory="$INSTALL_DIR" -C "$INSTALL_DIR" checkout -B main origin/main
fi
chown -R uagent:uagent "$INSTALL_DIR"

log "Installing portal npm packages"
(
  cd "${INSTALL_DIR}/portal"
  runuser -u uagent -- env HOME=/var/lib/uagent PATH="/usr/local/bin:${PATH}" \
    /usr/local/bin/npm ci --omit=dev
)

if [ ! -f "$ENV_FILE" ]; then
  log "Creating ${ENV_FILE}"
  umask 077
  cat > "$ENV_FILE" <<EOF
PUBLIC_HOST=${PUBLIC_HOST}
PORTAL_USER=admin
PORTAL_PASS=$(openssl rand -hex 12)
ENROLLMENT_KEY=$(openssl rand -hex 24)
SESSION_SECRET=$(openssl rand -hex 32)
FORCE_HTTPS=true
EOF
  chmod 600 "$ENV_FILE"
  umask 022
elif [ "$HOST_SET" -eq 1 ]; then
  if grep -q '^PUBLIC_HOST=' "$ENV_FILE"; then
    sed -i "s/^PUBLIC_HOST=.*/PUBLIC_HOST=${PUBLIC_HOST}/" "$ENV_FILE"
  else
    echo "PUBLIC_HOST=${PUBLIC_HOST}" >> "$ENV_FILE"
  fi
fi
# shellcheck disable=SC1090
set -a
. "$ENV_FILE"
set +a

CERT="${INSTALL_DIR}/portal/certs/portal.crt"
if [ ! -f "$CERT" ] || [ "$HOST_SET" -eq 1 ]; then
  log "Generating a self-signed TLS certificate for ${PUBLIC_HOST}"
  PUBLIC_HOST="$PUBLIC_HOST" bash "${INSTALL_DIR}/portal/scripts/gencert.sh"
  chown -R uagent:uagent "${INSTALL_DIR}/portal/certs"
  chmod 600 "${INSTALL_DIR}/portal/certs/portal.key"
fi

if [ "$SKIP_AGENT" -eq 0 ]; then
  log "Building the Windows agent (this can take several minutes)"
  runuser -u uagent -- env \
    HOME=/var/lib/uagent \
    DOTNET_ROOT=/usr/share/dotnet \
    DOTNET_CLI_HOME=/var/lib/uagent \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    NUGET_PACKAGES=/var/lib/uagent/.nuget/packages \
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
fi

log "Installing systemd service ${SERVICE_NAME}"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=uAgent management portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=uagent
Group=uagent
WorkingDirectory=${INSTALL_DIR}/portal
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/local/bin/node server.js
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65535

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

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

if [ "$SKIP_FIREWALL" -eq 0 ] && command -v firewall-cmd >/dev/null 2>&1; then
  log "Opening HTTP, HTTPS, and SSH in firewalld"
  systemctl enable --now firewalld
  firewall-cmd --permanent --add-service=ssh
  firewall-cmd --permanent --add-service=http
  firewall-cmd --permanent --add-service=https
  firewall-cmd --reload
fi

log "Waiting for the portal"
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if curl -fsS "http://127.0.0.1/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
[ "$ready" -eq 1 ] || die "The portal did not answer /healthz. Check: journalctl -u ${SERVICE_NAME} -n 80 --no-pager"

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

uAgent portal is running.
  URL:        https://${PUBLIC_HOST}/
  Health:     http://127.0.0.1/healthz
  Username:   ${PORTAL_USER}
  Password:   ${PORTAL_PASS}
  Secrets:    ${ENV_FILE}
  This host:  ${LAN_IP:-unknown}

Point DNS (or every client's hosts file) so ${PUBLIC_HOST} resolves to this server.
The sign-in page serves the Windows agent. The certificate is self-signed until you replace
${INSTALL_DIR}/portal/certs/portal.crt and portal.key and restart ${SERVICE_NAME}.

  systemctl status ${SERVICE_NAME}
  journalctl -u ${SERVICE_NAME} -f
EOF
