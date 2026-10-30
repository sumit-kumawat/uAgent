# uAgent 1.5.1

**Agent installer.** Re-running install or upgrade no longer fails with `Access to the path '...\uAgent.exe' is denied` while saving the manager connection. Older builds applied folder ACL inherit flags directly onto the program file (`icacls /T` with `(OI)(CI)`), which left inherit-only ACEs so Administrators could not open the file to hash it. The installer now sets the folder ACL and resets children to inherit, heals the executable ACL before hashing, and still replaces the binary when a downloaded installer is run even if the version string matches. Agent version is **1.5.1**; the portal remains 1.5.0.

# uAgent 1.5.0

Fixes agent disconnections, adds a portal-specific uninstall verification key, and stabilises the core features. Placeholders: `uagent.example.com`, `192.0.2.10`, `pc-0142`.

**Status: release candidate.** Every automated test below passed on macOS, including the real agent binary against a real portal. The installer has not been signed and the Windows checks in [Still to validate](#still-to-validate) have not been run. Do not call 1.5.0 production-ready until they pass.

## Versions

| Component | Version | Where it is reported |
| --- | --- | --- |
| Windows agent | 1.5.0 | `uAgent.Agent.csproj` → file and product version, `manifest.json`, `SHA256SUMS`, `uAgent_Version1.5.0.exe`, heartbeat `agentVersion`, the Control panel |
| Portal | 1.5.0 | `portal/package.json`, `package-lock.json`, asset version |
| Portal state file | schema 2 | `portal-store.json` `schemaVersion` |

**Compatibility.** A 1.5.0 portal works with 1.2–1.4 agents: they keep their registration and are upgraded from Deployment Center. Until they are upgraded, they do not send an install ID, so the portal identifies them by host name as before (and learns nothing new), and they do not report which manager address they use. A 1.5.0 agent works with a 1.4 portal; the new fields are ignored.

**Upgrade.** Run the install command (this also installs the hardened update helper); the portal upgrades its state file on first start and keeps a copy of the old one (`portal-store.json.schema1-<time>.bak`). Generate an uninstall verification key in **Settings** before you need to remove an agent. **Rollback**: restore the previous release with **Reset & Recovery → Refresh** rollback or `uagent-maintenance rollback`, then put the `.bak` file back in place of `portal-store.json`.

## 1. Agent disconnections

| # | Root cause | Fix |
| --- | --- | --- |
| 1 | **Registration ping-pong.** Two computers with the same name (cloned images, workgroup machines) shared one portal record. Each enrolment took the record over and revoked the other computer's credential, which then re-enrolled and did the same. Reproduced against the 1.4 store. | Each installation has an install ID (`agent-state.json`). The portal never hands a connected computer's record to a different install; it creates a second record and raises a "duplicate name" issue. A re-imaged computer takes its old record over only when that record is no longer connected. |
| 2 | **Credential wiped on a single rejection.** One `unknown_agent` or `invalid_key` answer (for example during a manager restore) made the agent discard its identity and re-enrol. | The rejection must be confirmed again at least 15 s later. Re-enrolment is limited to three times an hour; beyond that the agent stops and explains that the computer may be a clone. |
| 3 | **No heartbeat during slow work.** Inventory, application scans and deployments ran on the same loop as the heartbeat, so a long task made the computer look disconnected. | A keep-alive sends the heartbeat while the main loop is busy. |
| 4 | **Upload failures counted as disconnections.** A failed inventory upload triggered the connection backoff. | The upload is retried later; the connection is not backed off. |
| 5 | **Thundering herd after a manager restart.** Every reconnecting agent re-uploaded its full inventory at once. | Overdue uploads are spread over 5–180 seconds after reconnecting; retries no longer reset the whole schedule. |
| 6 | **Idle connection races.** Pooled connections idle longer than the server's keep-alive were reused and reset. | Pooled connections are retired after 50 s idle. |
| 7 | **Hanging long poll for a removed agent.** | The poll answers `401 unknown_agent` and stops when the client has gone. |
| 8 | **Event-loop stalls.** The whole state file (over 100 MB at scale) was rewritten every 3 s for heartbeat-only changes, and every heartbeat ran an O(n) duplicate scan. | Heartbeat-only changes are saved at most once a minute and on shutdown; the scan runs only when durable fields change. |
| 9 | **A single unexpected exception stopped the portal without saving.** | An `uncaughtException` handler logs, saves state and exits; systemd restarts the service. |
| 10 | **Certificate name mismatch** (certificate for the DNS name, agents configured with the IP address). | A registered agent tries the names in the trusted certificate. Each candidate must first prove it holds the agent's credential (HMAC keyed by the stored key hash, over a fresh nonce and the manager's own names) before the agent sends its key there; then DNS, TCP, TLS and the credential are checked and the switch is audited. |

Backoff: 1 s doubling to 5 minutes, ±20 % jitter. The dashboard now distinguishes **Online**, **Reconnecting** (quiet for up to 6 minutes and not stopped on purpose), **Disconnected** and **Stale** (silent longer than `STALE_AFTER_HOURS`, default 24), with matching tiles and filters.

## 2. Uninstall verification key

- One key per portal: 25 uppercase letters and digits from the operating system's CSPRNG, shown once, formatted in five groups.
- Stored as a salted scrypt hash bound to the portal's random identity (`uninstall-key.json`, mode 600, included in backups). Keys from other portals never match.
- Required, together with an Administrator, a reason and their password, for **Remove agent**, **Remove record**, and Reset & Recovery operations that uninstall agents. Checked on the server; the uninstall command cannot be queued directly.
- Rotation and revocation from **Settings → Uninstall verification**, with reason and password. Revocation blocks removals until a new key exists; removals already queued for offline agents stay queued.
- Rate limited (5 wrong keys per user, 20 per portal, per 15 minutes). Every outcome is audited without the key.
- Not used by heartbeats, upgrades or repairs.

## 3. Security and integrity fixes from the code review

| Severity | Problem | Fix |
| --- | --- | --- |
| High | Address recovery trusted any certificate from a trusted CA, so someone on the network path with, for example, a public certificate for their own domain could redirect agents and receive their keys. | Candidates must prove they hold the agent's credential before the key is sent (see root cause 10). Unregistered agents never switch. Regression test with an impostor that answers every request with success. |
| High | A backup restore was overwritten by the running portal's next save, so it never took effect. Backups were also read from disk without saving first, so they could miss recent changes. | Every backup saves first. A restore stops all saving, restarts the portal on the restored files and audits itself after the restart. |
| High | The update helper ran git as root in a checkout the service account owns (hooks, fsmonitor), copied itself from that checkout into `/usr/local/sbin`, and kept its rollback record in a directory the account could write. | git runs as `uagent` with hooks and fsmonitor disabled; the archive is unpacked as `uagent`; the helper never replaces itself; the record lives in root-owned `/etc/uagent`. |
| High | A 1.5 agent's heartbeat deleted the record of a connected pre-1.5 agent with the same name, and the two kept knocking each other offline. | De-duplication never removes a connected record or one with a different install ID. |
| Medium | Destroy with agents and records selected cleared the uninstall commands before they were delivered; an audit-only destroy cleared agents; removals were attributed to `undefined`. | Agents being uninstalled keep their records until verified; audit-only clears only the audit log; the operator is recorded. |
| Medium | After an accounts reset, open sessions kept working, and whoever reached the setup page first could claim the portal (without a new session). | Accounts reset signs out every session. Setup needs a one-time code from the server, is throttled and audited, and starts a new session. A restore that brings accounts back ends setup instead of locking everyone out. |
| Medium | `systemctl restart` from a portal-started update killed the helper before its health check and rollback. | The helper runs in its own transient systemd unit and logs to the journal after the restart; the portal completes the job from the helper's record. |
| Medium | The installer wrote the sudoers rule into `/etc/sudoers.d` before validating it. | Validated in a temporary file, then installed. |
| Low | A late keep-alive answer could overwrite a new registration; one failing save could skip the other on crash; PFX passwords were visible in `ps`; extracted keys could stay in `/tmp` after an error; a malformed backup manifest could hang a request; wrong service name in a restart hint; revoked agents were selectable for maintenance. | Fixed individually. |

## 4. Other fixes

- Dashboard metric band: Registered, Online, Reconnecting, Disconnected (with "never connected" count), Stale. The separate Active and Never-connected tiles were removed as duplicates; the Never-connected filter remains on the Agents page.
- Every agent status pill (list, details, Control panel, Reset & Recovery) uses one connection-state helper.
- Reset clears in-memory presence, connection states, inventory and pending long polls, not only the files.
- Messages about agents that do not report their manager address now refer to builds older than 1.5.0, the version that adds it.

## Tests

`cd portal && npm test` (Node 18+). The two real-agent tests need `dotnet build uAgent.Agent -c Release` first.

| Area | Test | Result |
| --- | --- | --- |
| Registration: clones, re-image, legacy agents, connected record not stolen | `registration.test.js` (10) | Passed |
| Connection states and time-based change broadcasts | `registration.test.js` | Passed |
| State file upgrade with backup; steady heartbeats do not rewrite the file | `persistence.test.js` (2) | Passed |
| Real agent: connects, stays online, keeps one registration across a manager restart, does not re-enrol, keeps its identity | `agentConnectivity.test.js` | Passed |
| Real agent: recovers from a certificate name mismatch | `agentRecovery.test.js` | Passed |
| Real agent: an impostor with a trusted certificate gets no key and cannot redirect it | `agentSpoofing.test.js` | Passed |
| Restore takes effect after the automatic restart and is audited | `restore.test.js` | Passed |
| Setup code required; accounts reset signs out open sessions | `maintenance.test.js` | Passed |
| Connected older agent not deleted by a newer one with the same name; Destroy keeps agents being uninstalled | `registration.test.js` | Passed |
| Uninstall key: format and randomness, hash only, cross-portal, rotation, revocation, rate limit, audit without key | `uninstallKey.test.js` (5) | Passed |
| Removal needs the key over HTTP, no bypass through `/commands`, key not in audit | `maintenance.test.js` | Passed |
| Reset & Recovery, backups, restore refusal, setup, auth | `maintenance.test.js` | Passed |
| TLS import, renewal and trust | `tls.test.js` | Passed |
| Agent build | `dotnet build -c Release` | 0 warnings, 0 errors |
| Pages render (dashboard, Settings, Agents, Reset & Recovery) | HTTP smoke test | Passed |

## Still to validate

These need hardware or credentials that were not available, and block a production-ready label:

1. **Code signing.** No code-signing certificate was available, so `uAgent_Version1.5.0.exe` is unsigned. Sign it with `scripts/build-agent.sh` and your certificate (see README → Code signing), then check `Get-AuthenticodeSignature`.
2. **Windows.** Fresh install, upgrade from 1.4.0, repair, verified uninstall and rollback on Windows 10/11 and Server 2016+; service metadata shows 1.5.0.
3. **CentOS.** `install-centos.sh` upgrade from 1.4.0 with the schema backup; `uagent-maintenance` apply and rollback from the portal under systemd (transient unit, journal output, release record), and the setup code after an accounts reset. The helper changes passed `bash -n` only.
4. **Scale.** Behaviour with several thousand agents was reasoned about (write and scan costs above) but not load-tested.

## Known limitations

- A virtual machine cloned **after** its agent registered carries the same `agent-state.json` (identity, key and install ID), so the portal cannot tell the copies apart. Clone before installing the agent, or reinstall it on the copy.
- Agents older than 1.5.0 do not send an install ID; two such computers with the same name are told apart only by whether one of them is connected.
