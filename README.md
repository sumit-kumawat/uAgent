# uAgent

uAgent is a centralized endpoint and Windows account management system with two separate, independently deployable components:

- **Windows Agent (`uAgent.Agent`)** — one self-contained `uAgent-Setup.exe` that is both the installer and the service. Double-clicking it installs the `uAgent` Windows service (auto-start, self-healing), registers the machine with the manager, and then runs in the background reporting system details, account inventory and connection status, and executing authorised remote actions.
- **Node.js Portal / Manager (`portal/`)** — an Express application served at **`uagent.example.com`** over HTTP and HTTPS. It is the central dashboard, hosts the operator and agent APIs, and serves the one-click installer for download.

The two components are separate processes that talk over HTTP(S). Agents **enrol** with a shared enrollment key and then receive a **unique per-agent credential**; every later request is authenticated with that credential (`X-Api-Key`). Operators use a signed session cookie with role-based access control.

**The agent cannot prevent a local administrator from stopping the service or modifying accounts. It is a management tool, not a security boundary.** The service is hardened so non-administrators cannot stop, reconfigure or delete it, but a local administrator always can. Keep the portal on a trusted network and protect the enrollment key.

## How onboarding works

1. Build the installer once with `scripts/build-agent.sh`; the portal serves it at `/download/agent`.
2. On the dashboard (or the sign-in page) click **Download Agent EXE**, or copy the link and share it.
3. Run the installer on a Windows host. It elevates, installs the service, and registers automatically — no manual configuration, because the manager URL, certificate pin and enrollment key are embedded in the download.
4. The machine appears in the dashboard within a few seconds, with live heartbeat and connection status.

```
  Windows host                      Windows host
  ┌────────────────────┐           ┌────────────────────┐
  │ uAgent-Setup.exe   │           │ uAgent-Setup.exe   │
  │  → uAgent service  │           │  → uAgent service  │
  └─────────┬──────────┘           └─────────┬──────────┘
            │  enrol (enrollment key) → unique per-agent credential
            │  HTTPS: heartbeat / report / commands / results
            └───────────────┬───────────────┘
                            ▼
              ┌──────────────────────────────┐
              │  uAgent Manager (Node.js)     │  dashboard, RBAC, audit,
              │  http(s)://uagent.example.com │  installer download
              └──────────────────────────────┘
```

Each agent has a stable enrollment id and a short, zero-padded **Agent ID** (`00001`, `00002`, …) shown in the UI and used in page URLs (`/agents/00001`).

## Prerequisites

**Portal**
- Node.js 18+ (tested on Node 24).
- A DNS name of your own, saved in Settings after the first sign-in. The repository uses `uagent.example.com` only as a dummy name.
- A TLS certificate for `uagent.example.com` (`npm run gencert` makes a self-signed one for labs; use a CA certificate in production).

**Building the installer**
- .NET SDK 10 on the build machine (any OS — the agent targets `net8.0` and uses 10.0 packages; the SDK cross-compiles to `win-x64`).

**Running the agent**
- Windows x64. The installer is self-contained, so the .NET runtime is **not** required on the endpoint.
- An administrator to install (the installer self-elevates).

## Host the portal on CentOS

One command installs every package, clones this repository, creates the TLS certificate and sign-in password, builds the Windows agent, and starts the portal. When it finishes, open the URL it prints and download the agent from the sign-in page.

Supported systems: CentOS Stream 8 and 9, CentOS Linux 8, RHEL 8 and 9, Rocky Linux 8 and 9, AlmaLinux 8 and 9, Oracle Linux 8 and 9. x86_64 and aarch64. CentOS 7 cannot run it (glibc 2.17; Node.js 22 needs glibc 2.28 or newer). CentOS Linux 8 is end of life, so the installer points `dnf` at `vault.centos.org` (8.5.2111) before installing packages.

The first start serves the portal on this server's own IP address. Ports **80** and **443** must be free, and the VM needs about **2 GB** of RAM (4 GB is more comfortable while the agent is compiling). After you sign in, Settings asks for the DNS name or FQDN. Saving it changes the host embedded in later agent downloads and the line printed in the service log. `uagent.example.com` in this document is a dummy name, not a live host.

### One command

Run this on the CentOS server:

```bash
curl -fsSL https://raw.githubusercontent.com/sumit-kumawat/uAgent/main/scripts/install-centos.sh -o /tmp/install-uagent.sh
sudo bash /tmp/install-uagent.sh
```

Use a different DNS name:

```bash
sudo bash /tmp/install-uagent.sh --host uagent.example.com
```

The script is safe to run again. A second run pulls the latest `main`, rebuilds the agent, and restarts the service. It keeps the password and enrollment key already stored in `/etc/uagent/portal.env`. Passing `--host` updates that name and issues a new certificate.

| Flag | Effect |
| --- | --- |
| `--host NAME` | Host embedded in links, the certificate, and every agent download. Default `uagent.example.com`. |
| `--skip-agent` | Skip the .NET SDK and the Windows build. The portal runs, and the download stays disabled until you build the agent. |
| `--skip-firewall` | Leave firewalld unchanged. |

### What that command installs

OS packages (`dnf`, or `yum` on older releases):

| Package | Why |
| --- | --- |
| `git` | Clone and update `https://github.com/sumit-kumawat/uAgent.git`. |
| `curl`, `ca-certificates`, `tar`, `xz` | Download Node.js and the .NET SDK. |
| `openssl`, `openssl-libs` | Create the TLS certificate and the portal secrets. |
| `libicu` | Required by the .NET SDK. |
| `iproute` | Provides `ss`, used to see whether ports 80 and 443 are free. |
| `firewalld` | Opens SSH, HTTP, and HTTPS. SSH is included so the installer does not lock you out. |
| `policycoreutils-python-utils` | `semanage` / `restorecon`, so SELinux allows the service to read `/opt/uagent`. |

Tools installed outside the distro repositories (the CentOS Node.js module is too old):

| Tool | Where | Why |
| --- | --- | --- |
| Node.js 22 LTS (latest 22.x) | `/usr/local/bin/node` | Runs the portal. The portal requires Node.js 18 or newer. |
| npm (shipped with Node.js) | `/usr/local/bin/npm` | Installs `express`, `ejs`, and `express-session` from `portal/package-lock.json`. |
| .NET SDK 10 | `/usr/share/dotnet` | Cross-compiles the Windows agent to `win-x64`. |

npm packages (no database, no extra native addons): `express`, `ejs`, `express-session`.

Files the installer creates:

| Path | Purpose |
| --- | --- |
| `/opt/uagent` | Application checkout. |
| `/etc/uagent/portal.env` | `PUBLIC_HOST`, `PORTAL_USER`, `PORTAL_PASS`, `ENROLLMENT_KEY`, `SESSION_SECRET`. Mode `600`, root only. |
| `/opt/uagent/portal/certs/portal.crt` and `portal.key` | Self-signed certificate for the public host, localhost, and this server's LAN address. |
| `/opt/uagent/portal/agent-dist/uAgent-Setup.exe` | Base Windows installer. The portal serves it as `uAgent_Version<version>.exe`. |
| `/etc/systemd/system/uagent-portal.service` | Auto-start service, user `uagent`, ports 80 and 443. |

### After it finishes

The script prints the server IP, username, and a random password. Example:

```text
URL:        https://<server-ip>/
Username:   admin
Password:   <generated, also stored in /etc/uagent/portal.env>
```

1. Open `https://<server-ip>/` and accept the self-signed certificate once. Sign in with the printed password. The portal asks you to replace it before anything else opens.
2. Open Settings and save the DNS name or FQDN agents should call. Until you do, downloads stay bound to the server IP, and the service log says so. After you save, new downloads and the log use that name. Point the name at the server, or add it on each Windows endpoint in `C:\Windows\System32\drivers\etc\hosts`:

   ```text
   <server-ip>  <your-dns-name>
   ```

3. On the sign-in page, download the agent (`uAgent_Version1.2.0.exe`, the version follows the build). Run it as Administrator. It installs the service and registers with the host saved in Settings.

From another machine that already trusts the certificate (or with `-k` while it is self-signed):

```bash
curl -fL -k -o uAgent-Setup.exe https://uagent.example.com/download/agent
```

Confirm the service:

```bash
curl -fsS http://127.0.0.1/healthz
systemctl status uagent-portal
journalctl -u uagent-portal -n 50 --no-pager
```

`/healthz` stays on HTTP. Every other HTTP request redirects to HTTPS.

### Same steps, command by command

Use this when you want to run each part yourself. All of these commands are run as root on the server.

**1. Packages**

```bash
dnf install -y git curl ca-certificates tar xz openssl openssl-libs libicu iproute firewalld policycoreutils-python-utils
```

**2. Node.js 22 LTS** into `/usr/local`

```bash
NODE_VERSION=$(curl -fsSL https://nodejs.org/dist/index.json | sed -n 's/.*"version": *"\(v22\.[0-9][0-9.]*\)".*/\1/p' | head -1)
curl -fsSL "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz" -o /tmp/node.tar.xz
tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1
node -v && npm -v
```

On aarch64, replace `linux-x64` with `linux-arm64`.

**3. .NET SDK 10** (only needed so the Windows download can be built on this server)

```bash
curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
bash /tmp/dotnet-install.sh --channel 10.0 --install-dir /usr/share/dotnet
ln -sfn /usr/share/dotnet/dotnet /usr/local/bin/dotnet
DOTNET_ROOT=/usr/share/dotnet dotnet --version
```

**4. Service account and checkout**

```bash
useradd --system --home-dir /var/lib/uagent --create-home --shell /sbin/nologin uagent || true
install -d -m 0750 -o uagent -g uagent /var/lib/uagent /etc/uagent
git clone --branch main https://github.com/sumit-kumawat/uAgent.git /opt/uagent
chown -R uagent:uagent /opt/uagent
```

**5. Portal libraries**

```bash
cd /opt/uagent/portal
runuser -u uagent -- env HOME=/var/lib/uagent /usr/local/bin/npm ci --omit=dev
```

**6. Secrets.** Replace the host if you are not using `uagent.example.com`.

```bash
umask 077
cat > /etc/uagent/portal.env <<'EOF'
PUBLIC_HOST=uagent.example.com
PORTAL_USER=admin
PORTAL_PASS=change-this-password
ENROLLMENT_KEY=change-this-enrollment-key
SESSION_SECRET=change-this-session-secret
FORCE_HTTPS=true
EOF
chmod 600 /etc/uagent/portal.env
# Or generate them:
# PORTAL_PASS=$(openssl rand -hex 12)
# ENROLLMENT_KEY=$(openssl rand -hex 24)
# SESSION_SECRET=$(openssl rand -hex 32)
```

**7. TLS certificate** for that host

```bash
set -a; . /etc/uagent/portal.env; set +a
PUBLIC_HOST="${PUBLIC_HOST:-uagent.example.com}" bash /opt/uagent/portal/scripts/gencert.sh
chown -R uagent:uagent /opt/uagent/portal/certs
chmod 600 /opt/uagent/portal/certs/portal.key
```

**8. Windows agent**, so Download on the sign-in page returns a real installer

```bash
runuser -u uagent -- env \
  HOME=/var/lib/uagent \
  DOTNET_ROOT=/usr/share/dotnet \
  DOTNET_CLI_HOME=/var/lib/uagent \
  DOTNET_NOLOGO=1 \
  PATH="/usr/share/dotnet:/usr/local/bin:$PATH" \
  bash /opt/uagent/scripts/build-agent.sh
```

**9. systemd.** The `uagent` user is allowed to bind ports 80 and 443 without running Node.js as root.

```bash
cat > /etc/systemd/system/uagent-portal.service <<'EOF'
[Unit]
Description=uAgent management portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=uagent
Group=uagent
WorkingDirectory=/opt/uagent/portal
EnvironmentFile=/etc/uagent/portal.env
ExecStart=/usr/local/bin/node server.js
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now uagent-portal
```

**10. Firewall** (SSH stays open)

```bash
systemctl enable --now firewalld
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

**11. SELinux label** for the checkout

```bash
semanage fcontext -a -t usr_t '/opt/uagent(/.*)?' || semanage fcontext -m -t usr_t '/opt/uagent(/.*)?'
restorecon -Rv /opt/uagent
```

**12. Check**

```bash
curl -fsS http://127.0.0.1/healthz
curl -kfsS -o /dev/null -D - https://127.0.0.1/download/agent | head
```

The download response is `200` with `Content-Disposition: attachment; filename="uAgent_Version<version>.exe"`. A `503` means step 8 did not produce `/opt/uagent/portal/agent-dist/uAgent-Setup.exe`.

### Operate the service

```bash
systemctl restart uagent-portal
systemctl status uagent-portal
journalctl -u uagent-portal -f
```

Change the password or host by editing `/etc/uagent/portal.env`, then restart. After a host or certificate change, download the agent again so new machines embed the new URL and certificate fingerprint. Machines that already enrolled keep their own credential.

Update to the latest GitHub `main` by re-running the installer:

```bash
sudo bash /tmp/install-uagent.sh
```

Stop and remove the service:

```bash
systemctl disable --now uagent-portal
rm -f /etc/systemd/system/uagent-portal.service
systemctl daemon-reload
rm -rf /opt/uagent
# Secrets stay in /etc/uagent/portal.env until you delete that file.
```

A production certificate replaces the self-signed files. Put the PEM certificate and key somewhere the `uagent` user can read, point `TLS_CERT_FILE` and `TLS_KEY_FILE` at them in `/etc/uagent/portal.env`, and restart. Then download a fresh agent so the embedded pin matches the new certificate.

## Run the portal

On CentOS, use [Host the portal on CentOS](#host-the-portal-on-centos). That path installs the service and the Windows download. The commands below are for a local or lab start.

From `portal/`:

```bash
npm install
npm run gencert                 # lab only: self-signed certificate for uagent.example.com
ENROLLMENT_KEY="$(openssl rand -hex 24)" npm start
```

The portal listens on port **80** (HTTP) and **443** (HTTPS, when a certificate is present). On a server it binds downloads to that machine's IP until Settings has a DNS name. `GET /healthz` is an unauthenticated liveness probe. A lab start signs in with **username `admin`, password `admin`**, then requires a new password. The CentOS installer prints a random password instead and requires the same change.

On Linux, binding ports below 1024 needs `sudo setcap cap_net_bind_service=+ep "$(which node)"` or high ports via `PORTAL_HTTP_PORT` / `PORTAL_HTTPS_PORT` behind a proxy.

## Build the Windows installer

```bash
./scripts/build-agent.sh
```

This publishes a self-contained, single-file `win-x64` executable and writes:

- `portal/agent-dist/uAgent-Setup.exe` — the base installer/service binary.
- `portal/agent-dist/manifest.json` — `{ version, sha256, size, signed, builtUtc }`.

The portal serves this immediately; the dashboard Download button activates once it exists. To sign the binary, set `SIGN_CMD` to a command that signs `$SIGN_TARGET` in place (e.g. `osslsigncode` or a Windows signing host); the manifest then records `signed: true` and agents enforce the signature on self-update.

## Install on an endpoint

Download `uAgent-Setup.exe` from the dashboard and run it (double-click, or `uAgent-Setup.exe /install`). It self-elevates, then:

- installs to `C:\Program Files\uAgent`, with data and credentials under `C:\ProgramData\uAgent` (both ACL'd to SYSTEM and Administrators);
- creates the `uAgent` service (LocalSystem, automatic start) with recovery to restart after 5 s, 10 s, then every 30 s;
- restricts the service so only administrators can stop, change or delete it;
- adds an **Installed apps** entry;
- registers with the manager and shows the connection result.

Maintenance commands (all require an administrator; the exe self-elevates):

| Command | Purpose |
| --- | --- |
| `uAgent.exe /status` | Service, registration and live connection status. |
| `uAgent.exe /configure /manager=URL [/enrollkey=KEY] [/pin=SHA256] [/reenroll]` | Change the manager connection and restart the service. |
| `uAgent.exe /uninstall [/quiet] [/keepdata]` | Deregister, stop and remove the service and files. |
| `uAgent.exe /run` | Run in the console for troubleshooting. |

Uninstalling also notifies the manager so the agent is removed from the dashboard.

## Download access

- **Download Agent EXE** appears on the dashboard and on the sign-in page, so it is reachable **without logging in**.
- The dashboard shows a **copyable link** administrators can share.
- The download endpoint (`/download/agent`) is separate from all management APIs and is read-only; the portal never writes to the installer directory.
- The human download is personalised (the base build plus an appended connection block). The agent **self-update** uses the untouched base binary so its Authenticode signature stays valid; the agent validates the SHA-256 against the manifest and, when the running build is signed, requires the update to be signed by the same publisher before installing.

## Remote actions

Actions are executed by the installed agent; the portal shows the real result the agent returns.

| Action | Category | Minimum role | Sensitive |
| --- | --- | --- | --- |
| Test connection, Refresh inventory, Collect diagnostics, Cancel restart | System | Operator | |
| Restart agent service, Restart computer, Update agent | System | Administrator | Yes |
| Unlock / Enable account | Account | Operator | |
| Disable account, Reset password | Account | Administrator | Yes |
| Password never expires / Cannot change password | Account | Administrator | |

Before queuing, the portal checks (in order): the action exists; the role allows it; an account and/or password is supplied where required; sensitive actions are confirmed; the agent supports the action; the agent is **Active** (not pending approval or revoked); and the agent is online. Every rejection is audited. Statuses are Pending → Running (delivered) → Succeeded / Failed / Timed out, plus Unavailable and Denied for rejected attempts.

## Agent lifecycle (Administrator)

From an agent's detail page, **Manage agent**:

- **Approve** — activate an agent that enrolled while approval was required.
- **Revoke** — disable an agent's credential; it cannot communicate until reinstated or reinstalled.
- **Rotate credential** — issue a new per-agent key, delivered on the next heartbeat (brief overlap so nothing is missed).
- **Remove** — delete the agent from the portal (it re-registers on its next heartbeat unless uninstalled).

Roles: **Monitor** (read-only), **Operator** (non-sensitive actions), **Administrator** (everything, including lifecycle management). Sign-ins, sign-outs, enrollments, every action, denial, and lifecycle change are written to the audit log with the user and source address.

## Configuration

### Portal

Every value in `portal/config.js` can be overridden with an environment variable.

| Setting | Env var | Default | Purpose |
| --- | --- | --- | --- |
| Public host | `PUBLIC_HOST` | `uagent.example.com` | Dummy fallback used only when the server has no IPv4 address. The first run uses the machine IP. Settings → Agent contact host replaces it with your DNS name or FQDN. |
| Extra certificate IP | `PUBLIC_IP` | empty | Optional extra address on the TLS certificate. The machine's own IPv4 address is always included. |
| HTTP / HTTPS port | `PORTAL_HTTP_PORT` / `PORTAL_HTTPS_PORT` | `80` / `443` | Listen ports. |
| TLS certificate | `TLS_CERT_FILE` / `TLS_KEY_FILE` | `certs/portal.crt` / `.key` | PEM certificate and key for HTTPS. |
| Single user | `PORTAL_USER` / `PORTAL_PASS` | `admin` / `admin` | Default Administrator. |
| Multiple users | `PORTAL_USERS` | — | JSON array of `{ "username", "password", "role" }` (`Monitor` / `Operator` / `Administrator`). |
| Enrollment key | `ENROLLMENT_KEY` | `change-me-enroll` | Embedded in the installer; used only to register. Not a permanent per-agent secret — rotate anytime. |
| Require approval | `AGENT_REQUIRE_APPROVAL` | `false` | When true, new agents stay pending (no actions) until approved. |
| Installer directory | `INSTALLER_DIR` | `portal/agent-dist` | Where `uAgent-Setup.exe` and `manifest.json` live. |
| Embed cert pin | `EMBED_CERT_PIN` | `true` | Embed this portal's TLS fingerprint in the installer (harmless with a public-CA certificate). |
| Online window | `ONLINE_WINDOW_MS` | `120000` | An agent is online if seen within this window. |
| Session secret | `SESSION_SECRET` | dev value | Signs the session cookie. |

The session cookie is HttpOnly, `SameSite=Lax`, `Secure` over HTTPS, 8-hour sliding. Five failed sign-ins from one IP trigger a short lockout.

```bash
PORTAL_USERS='[{"username":"admin","password":"strong","role":"Administrator"},{"username":"helpdesk","password":"strong2","role":"Operator"}]' \
ENROLLMENT_KEY="$(openssl rand -hex 24)" SESSION_SECRET="$(openssl rand -hex 32)" \
TLS_CERT_FILE=/etc/ssl/uagent.crt TLS_KEY_FILE=/etc/ssl/uagent.key npm start
```

**The defaults `admin`/`admin` and `change-me-enroll`, and plaintext values in environment variables, are for a lab only.** In production, load them from a secret store, enable approval if desired, and sign the installer.

### Agent

The installer embeds the manager URL, enrollment key and certificate pin, so no manual configuration is normally needed. Optional `C:\ProgramData\uAgent\appsettings.json` overrides:

| Setting | Default | Purpose |
| --- | --- | --- |
| `Dashboard:BaseUrl` | `https://uagent.example.com` | Manager origin (the embedded/saved value wins). |
| `Dashboard:ApiKey` | empty | Fallback enrollment key if none is embedded. |
| `Dashboard:TrustedCertificateThumbprint` | empty | Certificate pin for a self-signed manager (the embedded pin wins). |
| `Agent:PollIntervalSeconds` | `60` | Heartbeat and inventory interval. |
| `Agent:CommandPollSeconds` | `10` | Action-check interval (min 2, at most the poll interval). |
| `Agent:ProtectedAccounts` | `administrator`, `rdsroot`, `rdsmon`, `infosec` | Accounts to report and manage. |
| `Agent:AutoRemediate` | `false` | Unlock a locked protected account without a portal action. |

Registration (agent id, per-agent key, manager URL, pin) is stored in `C:\ProgramData\uAgent\agent-state.json`, with the key encrypted via Windows DPAPI (machine scope) and the folder ACL'd to SYSTEM and Administrators. Live health is in `status.json`.

## Reliability

- The service auto-starts with Windows and recovers automatically from failures (SCM recovery, plus `Restart agent service` which exits so recovery restarts it).
- The agent retries with capped exponential backoff during outages and reconnects automatically when the manager returns. If the manager no longer recognises the agent (for example after a portal reset), the agent re-enrols automatically.
- The agent writes a status file after every cycle; `uAgent.exe /status` and the installer surface it.

## Portal API

Agent endpoints:

| Method | Path | Auth | Behavior |
| --- | --- | --- | --- |
| `POST` | `/api/agents/enroll` | enrollment key | Register; returns a unique per-agent credential. |
| `POST` | `/api/agents/{id}/heartbeat` | agent key | Store heartbeat; may return a rotated key. |
| `POST` | `/api/agents/{id}/report` | agent key | Store account inventory. |
| `GET` | `/api/agents/{id}/commands` | agent key | Deliver queued actions. |
| `POST` | `/api/agents/{id}/command-results` | agent key | Store results. |
| `GET` | `/api/agents/{id}/update/manifest` and `/update/package` | agent key | Current validated build for self-update. |
| `POST` | `/api/agents/{id}/deregister` | agent key | Remove the agent (uninstall). |
| `GET` | `/download/agent` and `/download/agent/info` | none | Download the installer and its metadata. |

Operator endpoints require the session cookie (`401` if missing, `403` if the role is insufficient). `{id}` accepts the Agent ID (`00001`) or the enrollment id. These include `/api/me`, `/api/agents`, `/api/agents/{id}` (full detail), `/api/agents/{id}/commands` (POST to queue), `/api/agents/{id}/approve|revoke|rotate-key` (POST, Administrator), `DELETE /api/agents/{id}` (Administrator), and the cross-agent `/api/accounts`, `/api/commands`, `/api/audit`, `/api/dashboard/summary`.

The portal keeps all data in memory (`portal/lib/store.js`); restarting it clears agents, history and the audit log, and agents re-register on their next heartbeat. Use a database before running more than one instance or when history must survive restarts.

## Projects

- `uAgent.Agent` — .NET 8 self-contained installer and `uAgent` Windows service.
- `uAgent.Shared` — heartbeat, enrollment, report, command, result and update contracts.
- `portal/` — Node.js/Express manager: dashboard, operator API, agent API, installer download.
- `scripts/build-agent.sh` — builds and publishes the installer.
- `scripts/install-centos.sh` — one-command CentOS install: packages, Node.js, .NET SDK, TLS certificate, Windows agent, and the systemd service.
