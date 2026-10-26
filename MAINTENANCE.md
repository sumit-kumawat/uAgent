# Maintenance release 1.3.0: root causes, changes, tests, and limitations

Each item lists what was wrong, what changed, how it was tested, and its status. An item is **Verified** only when its tests ran and passed. **Implemented, not executed** means the code builds and its logic was reviewed, but the test needs Windows (or CentOS with systemd), which was not available in the development environment (macOS). Run the checks in [Windows validation](#windows-validation-still-to-run) before calling those items fixed.

Placeholders: `uagent.example.com`, `192.0.2.10`.

## 1. Password and DNS/FQDN dialogs

**Root cause.** The forced password change was a separate page with a 12-character rule that did not match the agreed minimum of 6. Setting the host was a plain form with no preview, no confirmation, and a "restart required" step.

**Change.**

- **Password dialog** (`portal/public/js/dialogs.js`, `views/partials/shell_bottom.ejs`, `views/password.ejs`):
  - a modal dialog with live validation (at least 6 characters, different from the current password and the username, matching confirmation) and field-level server errors
  - when the change is forced, the dialog cannot be dismissed
  - it ends with a success step, and the page keeps a no-JavaScript fallback form
- **Host wizard:**
  - three steps: enter, review, done
  - the server-side preview normalises the input, looks up DNS, compares it with this server's addresses, and reports certificate coverage
  - warnings are shown, and saving needs a confirmation checkbox
  - it opens automatically for Administrators while no DNS name is set
- **API:** `POST /api/account/password` (allowed before the forced-change gate), `GET /api/settings/host`, `POST /api/settings/host/preview`, `POST /api/settings/host` (requires `confirm: true`).
- **Agent console:** the agent's console prompts already validated input; no change was needed.

**Tests.** 6-character minimum and wrong-current-password errors come back with `field`. The API returns 403 until the forced change is done, and opens afterwards. `https://UAgent.Lab.Example:9443/path` is normalised to `uagent.lab.example`. Saving without `confirm` is rejected. The pages render. **Verified** (API and render). A manual click-through in a browser is still recommended.

## 2. Agent stuck at "Not connected yet"

**Root causes.**

- **Trust.**
  - The agent trusted the manager only through a pinned certificate fingerprint embedded at download time.
  - Reissuing the certificate (on every `install-centos.sh --host` run, which also generated a new key) broke every installed agent.
  - With a CA-issued certificate nothing was embedded, so agents relied on the Windows store, which did not contain a private root.
- **Identity.** Changing the manager URL with `/configure` or a reinstall wiped the agent's identity.
- **Errors.** Errors were reported as a generic "could not connect", so DNS, firewall, TLS, and credential problems looked the same.
- **Install versus registration.** The installer reported registration failures as install failures.

**Change.**

- **Trust order (`CertificateTrust.cs`):**
  1. the OS store
  2. the embedded private root, with chain, `serverAuth`, and host-name checks
  3. a lab public-key (SPKI) pin, which survives reissue because the key is reused

  The reason for any refusal is reported.
- **Layered diagnostics (`ConnectivityDiagnostics.cs`, `DiagnoseCommand.cs`):** URL, DNS, proxy, TCP, TLS, `/healthz`, then the agent API. Available as `/diagnose`, and run automatically on the 1st, 3rd, and every 10th consecutive failure. Results go to `status.json` (`Diagnosis`, `NextAttemptUtc`, `RunAs`).
- **Retries:** capped exponential backoff. Registration happens automatically when the manager becomes reachable, with no reinstall.
- **Installer summary:** "Installation: complete" is reported separately from "Registration: pending", together with the diagnosis.
- **Identity:** kept when the manager URL changes.
- **Address migration:**
  - heartbeats carry `managerUrl`
  - the agent diagnoses the new address and calls `GET /api/agents/{id}/whoami` with its own credential before switching
  - it retries every 10 minutes and never downgrades HTTPS to HTTP
  - the switch is audited as `AgentAddressChanged`

**Tests.**

- *Enrol and migrate:*
  - an agent enrolled by IP through the private CA, then migrated to the DNS name, keeping Agent ID 00001
  - the migration appeared in the audit log
- *Outage:*
  - with the portal stopped, the diagnosis named "TCP refused"
  - on restart the agent recovered by itself
- *Diagnostics* correctly identified:
  - an unknown host (DNS)
  - a closed port (TCP)
  - an untrusted issuer
  - a name mismatch (`[::1]`)
  - a wrong pin
- *Pin stability:* the SPKI pin still validated after reissue under a new name; a wrong pin failed.
- *Sidecar:* with `uagent-install.json` next to the binary, `/diagnose` reached the portal through the private root.

**Verified** on the cross-platform build. The Windows service path (SCM, DPAPI) is **implemented, not executed**.

## 3. Firewall

**Root causes.**

- **CentOS:** `install-centos.sh` added firewalld services unconditionally and could not restrict sources.
- **Windows:** the agent had no firewall handling. On hosts whose policy blocks outbound traffic it could never connect, and nothing explained why.

**Change.**

- **Windows (`WindowsFirewall.cs`):**
  - no inbound rule is ever created
  - the outbound rule "uAgent - Manager connection (TCP-Out)" is added only when a profile's outbound default is Block
  - the rule is scoped to the agent program, TCP, the manager port, and the manager IP when the manager is an IP literal
  - the rule is idempotent and checked after it is created
  - when Group Policy overrides local rules, the agent explains that instead of failing silently
  - the rule is removed on uninstall, re-applied by `/repair` and the portal **Repair** action, and reported by `/diagnose`
- **CentOS (`install-centos.sh`):**
  - each rule is queried before it is added, so re-runs report `[present]` and change nothing
  - only `ssh`, `http`, and `https` are opened
  - `--allow-from CIDR` replaces the open services with source-restricted rich rules

**Tests.** `bash -n` passes. The Windows rule logic is **implemented, not executed**. Running the CentOS installer is **not executed** because the Docker daemon on the development host was not running.

## 4. Code signing and SmartScreen

**Root causes.**

- The download was personalised by appending a configuration block to the exe. For a signed build this changes the file after signing: `osslsigncode verify` reports "Ignoring PE signature not at the end of the file", and Windows treats such a file as unsigned or invalid.
- Signing was a free-form `SIGN_CMD` with no timestamp requirement and no verification.

**Change.**

- **`build-agent.sh` signing modes:**
  - `SIGN_MODE=azure`: Azure Artifact Signing, through `jsign`
  - `SIGN_MODE=osslsigncode`: an OV or EV certificate on PKCS#11 hardware or in a PFX
  - `SIGN_MODE=custom`: `signtool` or any other command
- **Signature checks:** every mode signs with SHA-256 and an RFC 3161 timestamp. The script verifies the signature and timestamp before publishing, writes `signed: true` only after that, publishes atomically, and writes `SHA256SUMS`.
- **Serving:** signed builds are served byte for byte (`X-Agent-Signed: true`).
- **Connection settings for signed builds:** they travel as `uagent-install.json` (Administrator only, audited, from `GET /api/installer/config`) or as `/manager=` `/enrollkey=` `/cacert=` switches.
- **Agent:** reads the sidecar when it finds no appended block.
- **Downloads page:** shows the signature state and the SHA-256.
- **Docs:** the README documents Microsoft file submission for false positives. Nothing disables or bypasses Defender or SmartScreen.
- **File metadata:** Product, Company, Description, Version, and Copyright come from the project file.

**Tests.**

- *Test signing:*
  - signed with a throwaway test code-signing certificate and a DigiCert RFC 3161 timestamp
  - the script's verification passed and the manifest recorded `signed: true`
- *Signed download:*
  - its SHA-256 equals the build hash
  - `osslsigncode verify` on the download reported "Signature verification: ok"
  - an appended copy lost its signature
- *`/api/installer/config`:*
  - returns 401 without a session
  - an Administrator receives the URL, key, and root
  - each download is audited
- *Unsigned build:* still personalised.

**Verified.** Signing with a real OV or Artifact Signing account, and SmartScreen behaviour, need your certificate and Windows.

## 5. `ERR_CERT_AUTHORITY_INVALID`

**Root causes.**

- The portal used a self-signed certificate made by `openssl req -x509`. That certificate is also marked `CA:TRUE`, and no browser trusts it.
- Its SAN followed whatever `--host` was when it was generated, so browsing by another name or by IP also failed.
- Every re-run with `--host` created a new key.
- There was no supported way to use a public, enterprise, or private CA, and no renewal.

**Change.**

- **`tlsManager.js`:**
  - classifies the certificate: public, private-ca, self-signed, or untrusted
  - checks that the key matches, the chain order, expiry, the SAN, and that a leaf is not a CA
  - hot-reloads changed files within 30 seconds, with no restart
  - every 12 hours, renews within 30 days of expiry or when the name is not covered; leaf certificates last 397 days and keep the same key
  - rewrites only certificates the portal manages
- **Chain:** the portal serves leaf plus root. `/download/ca.crt` serves the private root for Group Policy and Intune.
- **Host changes:** reissue the certificate live, keeping the old names in the SAN.
- **`scripts/uagent-tls.sh`:** provides `init-ca`, `issue` (reuses the key), `import` (rejects a mismatched key, an expired certificate, or a broken chain) and `check` (key, expiry, SAN, and the live chain with host-name verification).
- **`install-centos.sh`:**
  - `--tls internal-ca` (the default), `import`, or `self-signed`
  - the files live in `/etc/uagent/tls`
  - the existing key is migrated, so lab pins stay valid
- **`gencert.sh`:** reuses its key and issues a `CA:FALSE` `serverAuth` leaf.
- **Settings page:** shows the issuer, trust mode, names, coverage, and the agent's trust method.
- **Agents:** validate the chain and the host name (item 2).

Validation is never disabled anywhere.

**Tests.**

- *Strict curl:* `curl --cacert` succeeds, and fails for a wrong name or a missing CA.
- *Chain:* the server presents 2 certificates.
- *Live reissue:* covers the new DNS name and the old IP.
- *`uagent-tls.sh`:*
  - `init-ca` is idempotent and `issue` reuses the key
  - the issued chain verifies with `-verify_hostname`
  - `import` passes a good certificate and rejects a wrong key or a missing root
  - `check` passes against the running portal, and exits with code 2 and two reasons for a wrong name
- *`gencert.sh`:* reuses its key and issues `CA:FALSE`.

**Verified.** Deploying the root through Group Policy or Intune and checking it in a browser need a Windows domain.

## 6. Agent manager

**Root causes.**

- **Accounts:** the agent reported only four hard-coded accounts.
- **Accounts page:** loaded every row in the browser; its script was also truncated, which caused a syntax error.
- **Lifecycle controls:** existed on the agent, but the details page drew only "system" controls, so Stop, Repair, and Uninstall never appeared.
- **Tamper monitor:** silently reverted changes an administrator made on purpose.
- **Monitoring message:** told an up-to-date agent on a non-Windows host to "update to 1.3".

**Change.**

- **Account discovery:** `AccountScope=All` reports every local account and the domain accounts in local groups.
- **Accounts page:** paged, sorted, and filtered on the server, and refreshed live.
- **Lifecycle:**
  - a new `RepairAgent` command, alongside Stop and Uninstall, under a new "Agent lifecycle" section on the details page
  - Administrator only, with confirmation, a reason, and password re-entry
  - every attempt and every refusal is audited
- **Tamper monitor:** start-type and recovery drift is reported, not reverted; Repair restores the defaults.
- **Monitoring message:** names the platform as the reason.
- **Efficiency:** response compression, long-poll delivery of actions, and section-level inventory refreshes.
- **Theme:** kept, with only small additions (`.tag`, `.wizard-steps`).

**Tests.**

- *Basic commands:* Ping, RefreshInventory, and CollectDiagnostics queued and completed on a live agent.
- *RepairAgent refusals:*
  - without confirmation: rejected
  - with a wrong password: 403 `reauth_failed`, audited as Denied
  - with the correct password on a console-mode agent: 409 `unsupported`, audited as Unavailable
- *Pages:* the details, downloads, and settings pages render the new sections.

Portal side **verified**. Collecting processes, services, applications, files, CPU, and memory, and running Stop, Repair, and Uninstall, are **implemented, not executed**: they need the agent running as a Windows service.

## 7. First run, background services, and secrets

**Root causes.**

- **Default sign-in:** a lab start fell back to `admin`/`admin`.
- **Plaintext password:** the CentOS install kept the initial password in plain text in `portal.env` forever.
- **Watchdog:** none, beyond `Restart=always`.

**Change.**

- **One-time password:** an empty `PORTAL_PASS` makes the first start generate a one-time password, print it to the log, and require a change. Only scrypt hashes are stored, and the installer removes the plaintext seed after the first start.
- **Watchdog:** `uagent-portal-watch.timer` checks `/healthz` every 60 seconds.
- **systemd hardening:** `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome`, `PrivateTmp`, and write access only to the TLS and state directories.
- **Installer summary:** reads the active URL from `/healthz` and prints a TLS check.

**Tests.** On a fresh state directory with an empty `PORTAL_PASS`:

- the log printed a one-time password
- `admin`/`admin` was refused (401)
- the one-time password led to the forced change page
- the API returned 403 before the change
- the stored value is an scrypt hash with `mustChangePassword: true`

**Verified.** The systemd units and the timer are **not executed** (no CentOS host).

## Changed files

Portal:

- `server.js`, `config.js`
- `lib/`: `tlsManager.js` (new), `hostChange.js` (new), `hostSettings.js`, `installerPackage.js`, `operators.js`, `store.js`, `commandTypes.js`
- `routes/`: `download.js`, `pages.js`, `portalApi.js`, `agentApi.js`
- `public/js/`: `dialogs.js` (new), `accounts.js`, `details.js`, `downloads.js`, `site.js`
- `public/css/site.css`
- `views/`: `partials/shell_top.ejs`, `partials/shell_bottom.ejs`, `password.ejs`, `settings.ejs`, `downloads.ejs`, `agentDetails.ejs`, `accounts.ejs`, `login.ejs`
- `scripts/gencert.sh`, `package.json`

Agent:

- `CertificateTrust.cs`, `ConnectivityDiagnostics.cs` (new), `DiagnoseCommand.cs` (new), `WindowsFirewall.cs` (new)
- `EmbeddedConfig.cs`, `AgentState.cs`, `ConnectionSettings.cs`, `Program.cs`, `AgentService.cs`, `AgentStatusFile.cs`, `CommandLine.cs`, `AgentInstaller.cs`, `ManagerClient.cs`
- `SystemControls.cs`, `AgentRuntime.cs`, `TamperGuard.cs`, `ServiceHardening.cs`, `SystemInventory.cs`, `WindowsAccountDirectory.cs`, `AgentOptions.cs`, `appsettings.json`

Shared: `Enrollment.cs`, `Inventory.cs`, `CommandTypes.cs`, `Heartbeat.cs`, `AgentCommand.cs`, `AccountStatus.cs`

Scripts and docs: `scripts/install-centos.sh`, `scripts/uagent-tls.sh` (new), `scripts/build-agent.sh`, `README.md`, `MAINTENANCE.md` (new).

## Known limitations

- The development environment is macOS. Windows-only code (SCM service install and recovery, DPAPI, `netsh advfirewall`, service DACLs, inventory collectors, account changes, Stop/Repair/Uninstall) builds with 0 warnings but was not executed.
- `install-centos.sh` was syntax-checked and its TLS helper was tested, but the full script was not run on CentOS.
- A local administrator can always stop or remove the agent; this is intended and documented.
- The enrollment key is shared by all downloads from one portal. It only registers agents (each then gets its own credential) and can be rotated at any time. Unsigned lab downloads carry it inside the file; for signed builds it is in the Administrator-only `uagent-install.json`.
- An unsigned download's hash differs from the base build hash because it is personalised.
- One portal instance per state directory; there is no clustering.

## Windows validation still to run

On a Windows 10/11 or Server 2019+ test machine, with the portal using `internal-ca` and the root deployed by Group Policy or Intune:

1. **Browser.** Open `https://uagent.example.com`: no certificate warning. Sign in, change the password, and set the FQDN.
2. **Signature and hash** (signed build). `Get-AuthenticodeSignature` reports Valid and shows the timestamp; `Get-FileHash` matches `SHA256SUMS`.
3. **Install with the manager reachable.** Install as Administrator: "Installation: complete", "Registration: connected". `sc qc uAgent`, `sc qfailure uAgent`.
4. **Install with the manager unreachable.** Block 443 and install: "Registration: pending" with the TCP diagnosis. Unblock: the agent registers within about 1 minute, with no reinstall.
5. **Outbound-block firewall.** Set the profile to outbound Block: the agent adds its rule; `/diagnose` passes; re-running `/repair` adds no duplicate; `/uninstall` removes the rule.
6. **Address change.** Change the FQDN in Settings: the agent switches, its Agent ID is unchanged, and the audit log shows `AgentAddressChanged`.
7. **Monitoring and controls.** Processes, services, applications, files, CPU, memory, and accounts populate. Run Repair, then Stop, then Uninstall from the portal, each with your password; check the results and the audit entries.
8. **Tamper reporting.** Change the start type with `sc config uAgent start= demand`: it is reported, not reverted; Repair restores it.
