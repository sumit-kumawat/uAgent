# uAgent

uAgent is a centralized endpoint and Windows account management system with two separate, independently deployable components:

- **Windows Agent (`uAgent.Agent`)** — one self-contained `uAgent-Setup.exe` that is both the installer and the service. Double-clicking it installs the `uAgent` Windows service (auto-start, self-healing), registers the machine with the manager, and then runs in the background reporting system details, account inventory and connection status, and executing authorised remote actions.
- **Node.js Portal / Manager (`portal/`)** — an Express application served at **`uagent.helixops.ai`** over HTTP and HTTPS. It is the central dashboard, hosts the operator and agent APIs, and serves the one-click installer for download.

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
              │  http(s)://uagent.helixops.ai │  installer download
              └──────────────────────────────┘
```

Each agent has a stable enrollment id and a short, zero-padded **Agent ID** (`00001`, `00002`, …) shown in the UI and used in page URLs (`/agents/00001`).

## Prerequisites

**Portal**
- Node.js 18+ (tested on Node 24).
- A DNS A record (or hosts entry) pointing `uagent.helixops.ai` at the portal host.
- A TLS certificate for `uagent.helixops.ai` (`npm run gencert` makes a self-signed one for labs; use a CA certificate in production).

**Building the installer**
- .NET 8+ SDK on the build machine (any OS — it cross-compiles to `win-x64`).

**Running the agent**
- Windows x64. The installer is self-contained, so the .NET runtime is **not** required on the endpoint.
- An administrator to install (the installer self-elevates).

## Run the portal

From `portal/`:

```bash
npm install
npm run gencert                 # lab only: self-signed certificate for uagent.helixops.ai
ENROLLMENT_KEY="$(openssl rand -hex 24)" npm start
```

The portal listens on port **80** (HTTP) and **443** (HTTPS, when a certificate is present) and serves both `http://uagent.helixops.ai` and `https://uagent.helixops.ai`. `GET /healthz` is an unauthenticated liveness probe. Sign in with **username `admin`, password `admin`** (change before exposing — see [Configuration](#configuration)).

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
| Public host | `PUBLIC_HOST` | `uagent.helixops.ai` | Canonical host for links, redirects and the embedded installer. |
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
| `Dashboard:BaseUrl` | `https://uagent.helixops.ai` | Manager origin (the embedded/saved value wins). |
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
