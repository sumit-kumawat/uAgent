# uAgent

uAgent is a centralized endpoint and Windows account management system with two separate, independently deployable components:

- **Windows Agent (`uAgent.Agent`)**: one self-contained `uAgent-Setup.exe` that is both the installer and the service. Running it installs the `uAgent` Windows service (automatic start, recovers from crashes), registers the machine with the manager, and then reports system details, account inventory, and connection status, and runs authorised remote actions.
- **Node.js Portal / Manager (`portal/`)**: an Express application served over HTTP and HTTPS. It is the dashboard, hosts the operator and agent APIs, and serves the installer for download.

The components talk over HTTPS. Agents **enrol** with an enrollment key and then receive a **unique per-agent credential**; every later request uses that credential (`X-Api-Key`). Operators sign in with a session cookie and role-based access control.

**The agent cannot prevent a local administrator from stopping the service or modifying accounts. It is a management tool, not a security boundary.** Non-administrators cannot stop, reconfigure, or delete the service; a local administrator always can, and every agent component is visible in Services, Installed apps, Windows Firewall, and the event log. Keep the portal on a trusted network and protect the enrollment key.

`uagent.example.com` and `192.0.2.10` in this document are placeholders. Replace them with your own DNS name and server address.

## How onboarding works

1. The CentOS installer builds the agent; the portal serves it at `/download/agent`.
2. The first start uses the server's IP address. An Administrator signs in, replaces the one-time password, and sets the DNS name (FQDN) in **Settings → Configure DNS / FQDN**.
3. Download the agent from the **Agent Download** page and run it as Administrator. It installs the service and registers. An unsigned development download carries this portal's address and TLS trust inside the file. A signed download is never modified, so it reads the same settings from `uagent-install.json` placed next to it.
4. The machine appears in the dashboard within seconds. If the name changes later, connected agents move to the new address on their next heartbeat, without reinstalling.

```
  Windows host                      Windows host
  ┌────────────────────┐           ┌────────────────────┐
  │ uAgent_Version*.exe│           │ uAgent_Version*.exe│
  │  → uAgent service  │           │  → uAgent service  │
  └─────────┬──────────┘           └─────────┬──────────┘
            │  enrol (enrollment key) → unique per-agent credential
            │  HTTPS: heartbeat / report / commands / results
            └───────────────┬───────────────┘
                            ▼
              ┌──────────────────────────────┐
              │  uAgent Manager (Node.js)     │  dashboard, RBAC, audit,
              │  https://uagent.example.com   │  installer download
              └──────────────────────────────┘
```

Each agent has a stable enrollment id and a short Agent ID (`00001`, `00002`, …) shown in the UI and used in page URLs (`/agents/00001`).

## Host the portal on CentOS (production)

### Before you start

| Item | Requirement |
| --- | --- |
| OS | CentOS Linux 8, CentOS Stream 8/9, RHEL 8/9, Rocky 8/9, AlmaLinux 8/9, Oracle Linux 8/9. x86_64 or aarch64. CentOS 7 is not supported (glibc 2.17; Node.js 22 needs 2.28). |
| VM size | 2 vCPU, 2 GB RAM minimum (4 GB while the agent compiles), 10 GB free disk. VMware, Hyper-V, KVM, and cloud VMs all work. |
| Network | A static IP (for example `192.0.2.10`). Inbound TCP 80 and 443 from the endpoints and administrators; TCP 22 for SSH. Outbound HTTPS to `github.com`, `nodejs.org`, `dot.net`, `api.nuget.org`, and `vault.centos.org` (CentOS 8) during install. |
| DNS | An A record, for example `uagent.example.com → 192.0.2.10`, in the DNS that endpoints use. You can add it after the install. |
| Ports | 80 and 443 must be free (stop `httpd` or `nginx` first). |
| Access | root, or a user with `sudo`. |

CentOS Linux 8 reached end of life and its mirrors were removed, so the installer points `dnf` at `vault.centos.org` (8.5.2111). Check the release with `cat /etc/centos-release` or `hostnamectl`.

### One command

```bash
curl -fsSL https://raw.githubusercontent.com/sumit-kumawat/uAgent/main/scripts/install-centos.sh -o /tmp/install-uagent.sh
sudo bash /tmp/install-uagent.sh
```

Optionally provide the DNS name during installation: `sudo bash /tmp/install-uagent.sh --host uagent.example.com`. Without it the portal starts on the server IP and asks for the name at the first sign-in. The script prints the dashboard URL, the one-time password, and a TLS check, for example:

```text
uAgent portal is running.
  Dashboard:  https://uagent.example.com/
  Agents use: https://uagent.example.com
  Health:     http://127.0.0.1/healthz
  Username:   admin
  Password:   <one-time password>
              Shown only now and not stored in plain text. You must change it at first sign-in.
  TLS mode:   internal-ca
  [OK]     Private key matches the certificate
  [OK]     Valid for more than 30 days (...)
  [OK]     SAN includes uagent.example.com
  [OK]     The running portal presents a chain of 2 certificate(s) that verifies for uagent.example.com
  Root CA:    /etc/uagent/tls/ca.crt  (also https://uagent.example.com/download/ca.crt)
```

The script is idempotent. Running it again pulls the latest `main`, rebuilds the agent, restarts the service, and keeps the secrets, the TLS key, the private CA, the saved host name, and the agent records.

| Flag | Effect |
| --- | --- |
| `--host NAME` | DNS name agents and browsers use. Saved as if an Administrator had set it in Settings. |
| `--tls internal-ca` | Default for new installs. A private root CA on the server issues and renews the portal certificate. |
| `--tls import --cert F --key F [--chain F] [--ca F]` | Use a certificate from a public or enterprise CA. Validated before it is installed. |
| `--tls self-signed` | Development only. Browsers show `ERR_CERT_AUTHORITY_INVALID`. |
| `--allow-from CIDR` | Accept HTTP/HTTPS only from this range (repeatable), for example `--allow-from 10.0.0.0/8`. |
| `--skip-agent` | Skip the .NET SDK and the Windows build. |
| `--skip-firewall` | Leave firewalld unchanged. |

### What gets installed

OS packages (`dnf`):

| Package | Why |
| --- | --- |
| `git` | Clone and update this repository into `/opt/uagent`. |
| `curl`, `ca-certificates`, `tar`, `xz` | Download Node.js and the .NET SDK. |
| `openssl`, `openssl-libs` | Private CA, certificates, and secrets. |
| `libicu` | Required by the .NET SDK. |
| `iproute` | `ss`, to check that ports 80 and 443 are free. |
| `firewalld` | Opens SSH, HTTP, and HTTPS (idempotently). |
| `policycoreutils-python-utils` | `semanage` and `restorecon` for SELinux labels. |

Tools from upstream (the CentOS 8 Node.js module is too old):

| Tool | Location | Why |
| --- | --- | --- |
| Node.js 22 LTS | `/usr/local/bin/node` | Runs the portal. The tarball is checked against the published SHA-256. |
| npm | `/usr/local/bin/npm` | Installs `express`, `ejs`, `express-session`, `compression` from `portal/package-lock.json`. |
| .NET SDK 10 | `/usr/share/dotnet` | Cross-compiles the Windows agent to `win-x64`. |

Files:

| Path | Purpose |
| --- | --- |
| `/opt/uagent` | Application checkout. |
| `/etc/uagent/portal.env` | `PORTAL_USER`, `ENROLLMENT_KEY`, `SESSION_SECRET`, TLS paths, `TLS_MODE`. Mode `600`, root only. The one-time password is removed after the first start. |
| `/etc/uagent/tls/` | `portal.key`, `portal.crt` (leaf plus chain), and for `internal-ca` also `ca.crt` and `ca.key`. Owned by `uagent`. |
| `/var/lib/uagent/` | Portal state: operators (scrypt hashes), host setting, agents, history, and audit log. Back this up. |
| `/opt/uagent/portal/agent-dist/` | `uAgent-Setup.exe`, `manifest.json`, `SHA256SUMS`. |
| `/etc/systemd/system/uagent-portal.service` | The portal, as user `uagent`, ports 80 and 443. |
| `/etc/systemd/system/uagent-portal-watch.{service,timer}` | Health check every 60 seconds; restarts the portal if `/healthz` stops answering. |
| `/usr/local/sbin/uagent-tls` | Certificate helper (`init-ca`, `issue`, `import`, `check`). |

### First sign-in

1. Open the dashboard URL. With `internal-ca`, the browser trusts it only after the root CA is deployed (next section). Until then, the warning is expected; do not tell users to click through it.
2. Sign in with `admin` and the one-time password. A dialog requires a new password (at least 6 characters, different from the current one and from the username) before anything else opens.
3. If no DNS name is set, the **Configure DNS / FQDN** dialog opens. Enter `uagent.example.com`, review the check (DNS lookup, whether it points at this server, certificate coverage), confirm, and save. The certificate is reissued for the new name without a restart, new downloads use the name, the service log prints it, and agents that are already connected switch to it after verifying they can reach it.

### TLS certificates and `ERR_CERT_AUTHORITY_INVALID`

`ERR_CERT_AUTHORITY_INVALID` means the browser does not trust whoever issued the certificate. It is fixed by making the issuer trusted, never by disabling validation. Pick one:

**A. Certificate from a public CA.** Use this when the name is public (for example `uagent.example.com` with public DNS). Browsers and agents trust it with no extra steps.

```bash
# The CA gives you the certificate, the intermediates, and you keep the key.
sudo bash /opt/uagent/scripts/install-centos.sh --tls import \
  --cert /root/uagent.example.com.crt --key /root/uagent.example.com.key --chain /root/intermediates.pem
```

The import refuses a certificate that does not match the key, is expiring, or does not chain. Renew before expiry (for example with your CA's ACME client) and re-run the import, or write the new files to `/etc/uagent/tls/portal.crt` and `portal.key`; the portal reloads them within 30 seconds.

**B. Enterprise CA (AD CS or similar).** Request a server certificate whose SAN contains the exact name (`DNS:uagent.example.com`, plus `IP:192.0.2.10` if users browse by IP). Import it with `--ca /root/enterprise-root.pem` so agents can validate the chain. The enterprise root is normally already deployed to domain machines.

**C. Private CA on this server (`internal-ca`, default).** The installer creates a root CA (`/etc/uagent/tls/ca.crt`, 10 years). The portal issues its own leaf certificate (397 days, SAN with the configured name and the server IP, `serverAuth` only). It renews within 30 days of expiry, or as soon as the name changes, and keeps the same key. Agents downloaded from the portal carry the root and validate the chain and the host name against it. Browsers need the root deployed:

- **Group Policy:** Group Policy Management → edit a GPO linked to the computers → Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → **Trusted Root Certification Authorities** → Import → `uAgent-Root-CA.crt` (download it from `https://uagent.example.com/download/ca.crt` or copy `/etc/uagent/tls/ca.crt`). Then run `gpupdate /force` on a test machine.
- **Intune:** Devices → Configuration → Create → Windows 10 and later → Templates → **Trusted certificate** → upload the `.crt` → Destination store: Computer certificate store - Root → assign to device groups.
- Firefox uses the Windows store when `security.enterprise_roots.enabled` is true (the default on managed Windows).

Protect `/etc/uagent/tls/ca.key`: whoever holds it can issue certificates your endpoints trust. It is readable only by the `uagent` service account. Copy it to offline backup.

**D. Self-signed (development only).** `--tls self-signed`. Agents trust it through a public-key pin embedded in the download; browsers always warn. Not for production.

Check the certificate at any time:

```bash
sudo uagent-tls check --host uagent.example.com
openssl s_client -connect uagent.example.com:443 -servername uagent.example.com -verify_hostname uagent.example.com </dev/null | grep -E "Verify return|subject|issuer"
```

On Windows: `uAgent.exe /diagnose` (TLS step) or `Test-NetConnection uagent.example.com -Port 443`.

### Keep it running

- `uagent-portal.service`: `Restart=always`, starts at boot, and runs as `uagent` with `ProtectSystem=full`, `ProtectHome`, `PrivateTmp`, and write access only to `/etc/uagent/tls` and `/var/lib/uagent`. It retains only `CAP_NET_BIND_SERVICE`, which is required to listen on ports 80 and 443.
- `uagent-portal-watch.timer`: checks `/healthz` every 60 seconds and restarts a hung portal.
- State is written to `/var/lib/uagent` every few seconds and reloaded at start, so agents, history, and the audit log survive restarts and reboots. Agents retry with backoff during an outage and reconnect by themselves.
- Certificates are reloaded within 30 seconds of a change and renewal is checked every 12 hours.

```bash
systemctl status uagent-portal uagent-portal-watch.timer
journalctl -u uagent-portal -f
curl -fsS http://127.0.0.1/healthz
```

### Firewall

The installer adds only `ssh`, `http`, and `https` to the default zone, after checking whether each is already present, so re-runs change nothing. `--allow-from` replaces the open HTTP/HTTPS services with rich rules for the given ranges:

```bash
sudo bash /opt/uagent/scripts/install-centos.sh --allow-from 10.0.0.0/8 --allow-from 172.16.0.0/12
firewall-cmd --list-all
```

Port 80 only redirects to HTTPS and serves `/healthz`. If you do not need redirects, remove `http` with `firewall-cmd --permanent --remove-service=http && firewall-cmd --reload`.

### Secrets

`/etc/uagent/portal.env` holds `ENROLLMENT_KEY` and `SESSION_SECRET` (mode `600`, root). Operator passwords are stored only as scrypt hashes in `/var/lib/uagent/operators.json`. For production, inject these values from a secret store (HashiCorp Vault Agent, CyberArk, or systemd credentials) and keep `portal.env` out of backups that leave the server.

Reset a lost Administrator password:

```bash
systemctl stop uagent-portal
mv /var/lib/uagent/operators.json /var/lib/uagent/operators.json.bak
systemctl start uagent-portal
journalctl -u uagent-portal | grep "First sign-in"   # prints a new one-time password
```

Rotate the enrollment key by editing `ENROLLMENT_KEY` and restarting. Enrolled agents keep working (they use their own credential); new downloads carry the new key.

### Update, back up, remove

```bash
sudo bash /opt/uagent/scripts/install-centos.sh            # update to the latest main
tar czf /root/uagent-backup-$(date +%F).tgz /etc/uagent /var/lib/uagent
```

Remove:

```bash
systemctl disable --now uagent-portal uagent-portal-watch.timer
rm -f /etc/systemd/system/uagent-portal.service /etc/systemd/system/uagent-portal-watch.*
systemctl daemon-reload
rm -rf /opt/uagent /usr/local/sbin/uagent-tls /usr/local/bin/uagent-portal-watch
# /etc/uagent and /var/lib/uagent keep secrets, the CA, and data until you delete them.
```

## Run the portal locally

From `portal/`:

```bash
npm install
npm run gencert                 # development only: self-signed certificate
ENROLLMENT_KEY="$(openssl rand -hex 24)" npm start
```

The portal listens on 80 and 443 (`PORTAL_HTTP_PORT` / `PORTAL_HTTPS_PORT` change them). Without `PORTAL_PASS`, the first start prints a one-time `admin` password in the terminal and requires a change at sign-in.

## Build and sign the Windows installer

```bash
./scripts/build-agent.sh
```

This publishes a self-contained, single-file `win-x64` executable and writes `portal/agent-dist/uAgent-Setup.exe`, `manifest.json` (`version`, `sha256`, `size`, `signed`, `builtUtc`), and `SHA256SUMS`. File properties (Product, Company, Description, Version, Copyright) come from `uAgent.Agent/uAgent.Agent.csproj`; its executable icon is built from `uAgent.Agent/uAgent.ico`.

### Code signing

Unsigned executables downloaded from the internet trigger SmartScreen and are more likely to be flagged by antivirus. Sign every release build with Authenticode (SHA-256) and an RFC 3161 timestamp, so the signature stays valid after the certificate expires.

| `SIGN_MODE` | Certificate | Required variables |
| --- | --- | --- |
| `azure` | Azure Artifact Signing (formerly Trusted Signing). Microsoft-managed identity validation and keys. | `SIGN_AZURE_ENDPOINT` (e.g. `eus.codesigning.azure.net`), `SIGN_AZURE_ACCOUNT`, `SIGN_AZURE_PROFILE`; `jsign` 6+ and an `az login` or managed identity. |
| `osslsigncode` | OV (or EV) certificate from a public CA, with the key on a hardware token or HSM. | `SIGN_PKCS11_MODULE`, `SIGN_PKCS11_KEY`, `SIGN_CERT`; or `SIGN_PFX` and `SIGN_PFX_PASSWORD_FILE` where the CA still issues PFX files. |
| `custom` | Anything else, e.g. `signtool` on a Windows signing host. | `SIGN_CMD`, which signs `$SIGN_TARGET` in place. |

```bash
# Azure Artifact Signing
SIGN_MODE=azure SIGN_AZURE_ENDPOINT=eus.codesigning.azure.net \
SIGN_AZURE_ACCOUNT=my-signing-account SIGN_AZURE_PROFILE=uagent-public ./scripts/build-agent.sh

# Windows signing host with signtool (Artifact Signing dlib or a token)
signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 \
  /dlib Azure.CodeSigning.Dlib.dll /dmdf metadata.json uAgent-Setup.exe
signtool verify /pa /all /tw uAgent-Setup.exe
```

`SIGN_TIMESTAMP_URL` overrides the timestamp server (defaults: DigiCert for `osslsigncode`, Microsoft for `azure`). The script verifies the signature and timestamp before publishing, and records `signed: true` only when verification succeeds.

**A signed file is never modified after signing.** Appending data to a signed PE invalidates its Authenticode signature, so the portal serves signed builds byte for byte and the published SHA-256 matches every download. The connection settings travel separately:

- **Agent Download page → Download uagent-install.json** (Administrators only, audited). Place it in the same folder as the `.exe` and run the `.exe`.
- Or: `uAgent_Version1.3.0.exe /install /quiet /manager=https://uagent.example.com /enrollkey=KEY [/cacert=ca.crt]` from Intune, Configuration Manager, or Group Policy.

Unsigned development builds are still personalized by appending a configuration block, so their hash differs from the base hash.

### Release hashes and false positives

Publish the line from `portal/agent-dist/SHA256SUMS` with each release, and the signer's name. Users can check a file with `Get-FileHash .\uAgent_Version1.3.0.exe -Algorithm SHA256` and `Get-AuthenticodeSignature .\uAgent_Version1.3.0.exe`.

If Microsoft Defender or SmartScreen flags a signed release incorrectly, submit that exact file at the [Microsoft Security Intelligence file submission portal](https://www.microsoft.com/wdsi/filesubmission) as a software developer, with the SHA-256, the signer, and a description of what the agent does. Do not ask users to disable Defender, SmartScreen, or any other control, and do not add exclusions to get the agent installed. A new signing certificate builds SmartScreen reputation over time; Azure Artifact Signing and EV certificates build it faster.

## Install on an endpoint

Run the download as Administrator (double-click, or `/install`). It:

- installs to `C:\Program Files\uAgent`, with data under `C:\ProgramData\uAgent` (SYSTEM and Administrators only);
- creates the `uAgent` service (LocalSystem, automatic start) with recovery after 5 s, 10 s, then every 30 s;
- lets only administrators stop, change, or delete the service;
- adds an **Installed apps** entry;
- adds an outbound Windows Firewall rule *only* if a firewall profile blocks outbound traffic by default. The rule is "uAgent - Manager connection (TCP-Out)": this program, TCP, the manager port, and the manager address when it is an IP. No inbound rule is created: the agent only makes outbound connections;
- registers with the manager and prints the result. Installation and registration are reported separately. If the manager cannot be reached yet, the install still completes, the service keeps retrying with backoff, and registration happens automatically when the manager becomes reachable. No reinstall is needed.

| Command | Purpose |
| --- | --- |
| `uAgent.exe /status` | Service, registration, connection status, and the last diagnosis. |
| `uAgent.exe /diagnose` | Checks URL, DNS, proxy, TCP, TLS (chain and name), `/healthz`, and the agent API in order, and names the first failing step. |
| `uAgent.exe /repair` | Re-applies service settings, recovery, permissions, and the firewall rule, then reconnects. |
| `uAgent.exe /configure /manager=URL [/enrollkey=KEY] [/cacert=FILE] [/pin=SHA256] [/reenroll]` | Change the manager connection and restart the service. |
| `uAgent.exe /uninstall [/quiet] [/keepdata]` | Deregister, stop and remove the service, the firewall rule, and the files. |
| `uAgent.exe /run` | Run in the console for troubleshooting. |

### "Not connected yet"

Run `uAgent.exe /diagnose` on the endpoint. The first failing step tells you what to fix:

| Step | Typical cause | Fix |
| --- | --- | --- |
| DNS | The name has no record in the endpoint's DNS. | Add the A record, or set the name to the IP in Settings. |
| TCP | Port 443 blocked by firewalld, a network firewall, or an outbound-block Windows policy. | `firewall-cmd --list-all` on the server; `uAgent.exe /repair` on the endpoint; check Group Policy firewall rules. |
| TLS | Untrusted issuer, or the name is not in the certificate SAN. | Use a public, enterprise, or internal-CA certificate that covers the exact name (see TLS above). |
| Agent API | A proxy or another web server answers instead of the portal. | Point the name at the portal, or add a proxy bypass. |
| Registration | Enrollment key rotated, agent revoked, or approval pending. | Download a new installer, reinstate the agent, or approve it. |

The service writes the same diagnosis to `C:\ProgramData\uAgent\status.json`. It runs it on the 1st, 3rd, and every 10th consecutive failure.

## Download access

- The **Agent Download** page and the sign-in page offer the download without signing in. The page shows the version, the signature state, and the SHA-256.
- `/download/agent` is read-only and separate from the management APIs. `/download/ca.crt` serves the private root for GPO or Intune.
- `uagent-install.json` (the connection settings, including the enrollment key) is available only to Administrators, and each download is audited.
- Self-update always uses the untouched base build. The agent checks the SHA-256 from the manifest and, if the running build is signed, requires the same publisher.

## Remote actions

Actions run on the agent; the portal shows the result the agent returns.

| Action | Category | Minimum role | Confirmation |
| --- | --- | --- | --- |
| Test connection, Refresh inventory, Collect diagnostics, Cancel restart | System | Operator | |
| Restart agent service, Restart computer, Update agent | System | Administrator | Confirm + reason |
| Stop agent service, Repair agent, Uninstall agent | Lifecycle | Administrator | Confirm + reason + your password |
| Unlock / Enable account | Account | Operator | |
| Disable account, Reset password | Account | Administrator | Confirm + reason |
| Password never expires / Cannot change password | Account | Administrator | |

Before queuing, the portal checks, in order: you are signed in; the action exists; your role allows it; account and password fields are present where needed; sensitive actions are confirmed with a reason; lifecycle actions are re-authenticated with your password; the agent supports the action on its platform; the agent is Active; and it is online. Every request and every refusal is audited with user, agent, reason, and source address.

The agent detail page shows system health (CPU, memory, disk, uptime), processes, services, installed applications, accounts, and, for Administrators when enabled, a file listing. Monitoring data comes from agents running on Windows.

## Agent lifecycle (Administrator)

On an agent's detail page:

- **Approve**: activate an agent that enrolled while approval was required.
- **Revoke**: disable the agent's credential.
- **Rotate credential**: issue a new per-agent key, delivered on the next heartbeat.
- **Stop / Repair / Uninstall**: remote lifecycle actions (see the table above). Uninstall removes the service, the firewall rule, and the files, and deregisters.
- **Remove**: delete the record from the portal (an installed agent re-registers on its next heartbeat unless uninstalled).

Roles: **Monitor** (read-only), **Operator** (non-sensitive actions), **Administrator** (everything).

## Configuration

### Portal

| Setting | Env var | Default | Purpose |
| --- | --- | --- | --- |
| Single user | `PORTAL_USER` / `PORTAL_PASS` | `admin` / one-time | Used only to create the first account. Empty password: a one-time password is printed to the log. A change is always required at first sign-in. |
| Multiple users | `PORTAL_USERS` | none | JSON array of `{ "username", "password", "role" }`, seeded once. |
| Enrollment key | `ENROLLMENT_KEY` | `change-me-enroll` | Registration only. Each agent then uses its own credential. Rotate any time. |
| Session secret | `SESSION_SECRET` | dev value | Signs the session cookie. |
| Ports | `PORTAL_HTTP_PORT` / `PORTAL_HTTPS_PORT` | `80` / `443` | Listen ports. `PUBLIC_HTTP_PORT` / `PUBLIC_HTTPS_PORT` set the ports used in links. |
| Certificate | `TLS_CERT_FILE` / `TLS_KEY_FILE` | `portal/certs/portal.crt` / `.key` | PEM leaf (plus chain) and key. Reloaded on change. |
| Private CA | `TLS_CA_FILE` / `TLS_CA_KEY_FILE` | empty | Root embedded in agent downloads; with the key, the portal issues and renews its own certificate. |
| Development certificates | `TLS_MANAGE_SELF_SIGNED` / `EMBED_CERT_PIN` | `true` / `true` | Reissue a self-signed certificate on host change; embed its public-key pin in development downloads. Ignored for CA-issued certificates. |
| Extra certificate IP | `PUBLIC_IP` | empty | Added to the certificate SAN. |
| Require approval | `AGENT_REQUIRE_APPROVAL` | `false` | New agents stay pending until approved. |
| State directory | `PORTAL_STATE_DIR` | `/var/lib/uagent` or `portal/data` | Where state is saved. |
| Installer directory | `INSTALLER_DIR` | `portal/agent-dist` | Built installer and manifest. |
| Online window | `ONLINE_WINDOW_MS` | `60000` | An agent is online if seen within this window. |
| Fallback host | `PUBLIC_HOST` | `uagent.example.com` | Only used when the server has no IPv4 address; the host is set in Settings. |

The session cookie is HttpOnly, `SameSite=Lax`, `Secure` over HTTPS, with an 8-hour sliding expiry. Five failed sign-ins from one IP trigger a short lockout.

### Agent

The download carries the manager URL, enrollment key, and TLS trust. Optional overrides in `C:\ProgramData\uAgent\appsettings.json`:

| Setting | Default | Purpose |
| --- | --- | --- |
| `Dashboard:BaseUrl` | `https://uagent.example.com` | Manager origin (the embedded or saved value wins). |
| `Dashboard:ApiKey` | empty | Fallback enrollment key if none is embedded. |
| `Dashboard:TrustedCertificateThumbprint` | empty | Development certificate pin (the embedded value wins). |
| `Agent:HeartbeatSeconds` | `15` | Heartbeat interval. |
| `Agent:PollIntervalSeconds` | `60` | Full inventory interval. |
| `Agent:CommandPollSeconds` / `Agent:LongPollSeconds` | `5` / `25` | Action delivery: the agent holds a request open for up to 25 s, so actions arrive within about a second. |
| `Agent:ServicesRefreshSeconds` / `Agent:ApplicationsRefreshMinutes` | `120` / `30` | Refresh intervals for the services and installed applications lists. |
| `Agent:AccountScope` | `All` | `All` reports every local account and, on domain members, the domain accounts that are members of local groups (the accounts authorised on that computer). `Protected` reports only `ProtectedAccounts`. |
| `Agent:MaxAccounts` | `5000` | Upper bound on reported accounts. |
| `Agent:ProtectedAccounts` | empty | Accounts that are always reported and flagged. |
| `Agent:AllowFileBrowsing` / `Agent:BrowseRoots` | `true` / all fixed drives | Administrator folder listings, read-only and audited. |
| `Agent:AutoRemediate` | `false` | Unlock a locked protected account without a portal action. |

TLS trust order on the agent: the Windows trust store (public or GPO/Intune-deployed roots); then the private root embedded in the download, with chain, `serverAuth`, and host-name checks; then, for development self-signed portals only, the embedded public-key pin. Anything else is refused and the reason is shown by `/status` and `/diagnose`.

Registration (agent id, per-agent key, manager URL, TLS trust) is stored in `C:\ProgramData\uAgent\agent-state.json`, with the key encrypted by Windows DPAPI (machine scope).

## Reliability

- The service starts with Windows and recovers from failures through SCM recovery.
- During an outage the agent retries with capped exponential backoff and reconnects by itself. If the manager no longer knows the agent, it re-enrols.
- When an Administrator changes the portal address, agents receive the new URL on their heartbeat. Each agent checks DNS, TCP, TLS, and its own credential against the new address before switching, retries every 10 minutes if that fails, and never downgrades HTTPS to HTTP. The switch is audited.
- The integrity monitor re-applies the binary path and permissions if they are changed. If an administrator changes the start type or recovery settings, it reports this and leaves the change in place; **Repair** restores the defaults.

## Portal API

Agent endpoints:

| Method | Path | Auth | Behavior |
| --- | --- | --- | --- |
| `POST` | `/api/agents/enroll` | enrollment key | Register; returns a per-agent credential and the manager URL. |
| `POST` | `/api/agents/{id}/heartbeat` | agent key | Store heartbeat; may return a rotated key or a new manager URL. |
| `GET` | `/api/agents/{id}/whoami` | agent key | Lets an agent verify a new manager address before switching. |
| `POST` | `/api/agents/{id}/report` | agent key | Store account inventory. |
| `GET` | `/api/agents/{id}/commands` | agent key | Deliver queued actions. |
| `POST` | `/api/agents/{id}/command-results` | agent key | Store results. |
| `GET` | `/api/agents/{id}/update/manifest`, `/update/package` | agent key | Validated build for self-update. |
| `POST` | `/api/agents/{id}/deregister` | agent key | Remove the agent (uninstall). |
| `GET` | `/download/agent`, `/download/agent/info`, `/download/ca.crt` | none | Installer, its metadata, private root CA. |
| `GET` | `/healthz` | none | Liveness, configured host, agent URL. |

Operator endpoints need the session cookie (`401` without it, `403` for an insufficient role, `403` until a forced password change is done). They include `/api/me`, `/api/account/password`, `/api/agents`, `/api/agents/{id}`, `/api/agents/{id}/commands`, `/api/agents/{id}/inventory/{section}`, `/api/agents/{id}/approve|revoke|rotate-key`, `DELETE /api/agents/{id}`, `/api/settings/host` (+ `/preview`), `/api/installer/config`, `/api/accounts`, `/api/commands`, `/api/audit`, `/api/downloads`, and `/api/dashboard/summary`.

## Projects

- `uAgent.Agent`: .NET 8 self-contained installer and `uAgent` Windows service.
- `uAgent.Shared`: enrollment, heartbeat, report, command, result, and update contracts.
- `portal/`: Node.js/Express manager.
- `scripts/install-centos.sh`: one-command CentOS install.
- `scripts/uagent-tls.sh`: private CA, certificate issue/import, and checks.
- `scripts/build-agent.sh`: build, sign, verify, and publish the installer.
- `MAINTENANCE.md`: root causes, changes, tests, and known limitations of the latest maintenance release.

© 2026 Sumit Kumawat · Developed by Sumit Kumawat
