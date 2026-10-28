"use strict";

// Reset & Recovery, exercised against a running portal on a disposable state directory.
//
// What these tests are protecting:
//   * a destructive operation cannot be triggered by a session alone. Reason, typed phrase,
//     acknowledgement and the operator's own password are each required and each refused separately.
//   * nothing destructive runs without a backup that was written and then read back successfully.
//   * a reset clears only what was selected, and keeps the audit log unless it is explicitly released.
//   * a reset that clears accounts returns the portal to the setup wizard rather than to a sign-in form
//     no one can satisfy, and the new Super Admin created there works while the old account does not.
//   * two operations never run at once.
const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../..");
const PORT = 18492;
const BASE = `http://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

function startPortal(stateDir) {
  fs.rmSync(stateDir, { recursive: true, force: true });
  fs.mkdirSync(stateDir, { recursive: true });
  // The marker is what a reset leaves behind: no accounts, and the environment password must not be
  // seeded again. Starting from it means these tests begin where a reset ends.
  fs.writeFileSync(path.join(stateDir, "setup-required"), new Date().toISOString());
  const portal = spawn("node", ["server.js"], {
    cwd: path.join(ROOT, "portal"),
    env: Object.assign({}, process.env, {
      PORTAL_STATE_DIR: stateDir,
      PORTAL_HTTP_PORT: String(PORT),
      PORTAL_HTTPS_PORT: "0",
      FORCE_HTTPS: "false",
      CANONICAL_REDIRECT: "false",
      TLS_MANAGE_SELF_SIGNED: "false",
      PUBLIC_HOST: "127.0.0.1",
      ENROLLMENT_KEY: "test-enroll-key"
    }),
    stdio: ["ignore", "pipe", "pipe"]
  });
  const log = [];
  portal.stdout.on("data", (d) => log.push(d.toString()));
  portal.stderr.on("data", (d) => log.push(d.toString()));
  return { portal, log };
}

function client() {
  let cookie = "";
  return async function call(path, options = {}) {
    const init = { method: options.method || (options.body || options.form ? "POST" : "GET"), headers: { Accept: "application/json" }, redirect: "manual" };
    if (cookie) { init.headers.Cookie = cookie; }
    if (options.key) { init.headers["X-Api-Key"] = options.key; }
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    if (options.form) {
      init.headers["Content-Type"] = "application/x-www-form-urlencoded";
      init.body = new URLSearchParams(options.form).toString();
    }
    const res = await fetch(BASE + path, init);
    for (const entry of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) {
      if (entry.startsWith("uagent.sid")) { cookie = entry.split(";")[0]; }
    }
    const type = res.headers.get("content-type") || "";
    return {
      status: res.status,
      location: res.headers.get("location"),
      body: type.includes("json") ? await res.json() : await res.text(),
      forget: () => { cookie = ""; }
    };
  };
}

async function waitForPortal(call) {
  for (let i = 0; i < 80; i++) {
    try {
      if ((await call("/healthz")).status === 200) { return true; }
    } catch (error) { /* not listening yet */ }
    await sleep(250);
  }
  return false;
}

async function waitForJob(call, id) {
  for (let i = 0; i < 60; i++) {
    const job = (await call(`/api/maintenance/jobs/${id}`)).body.job;
    if (!job || job.state !== "Running") { return job; }
    await sleep(500);
  }
  return null;
}

test("Reset & Recovery", { timeout: 180000 }, async (t) => {
  const stateDir = path.join(os.tmpdir(), "uagent-maintenance-test");
  const { portal, log } = startPortal(stateDir);
  const call = client();
  let resetJobId = "";
  let auditBeforeReset = 0;
  // The one-time code only someone on the server can read.
  const setupCode = () => {
    const file = path.join(stateDir, "setup-code");
    return fs.existsSync(file) ? fs.readFileSync(file, "utf8").trim() : "";
  };
  t.after(() => {
    portal.kill("SIGKILL");
    fs.rmSync(stateDir, { recursive: true, force: true });
  });
  assert.ok(await waitForPortal(call), `the test portal did not start: ${log.join("").slice(-800)}`);

  await t.test("a portal with no account leads to setup, not to sign-in", async () => {
    assert.equal((await call("/")).location, "/setup");
    assert.equal((await call("/login")).location, "/setup");
    assert.equal((await call("/setup")).status, 200);
    assert.equal((await call("/api/setup")).body.required, true);
  });

  await t.test("setup needs the one-time code from the server", async () => {
    assert.match(setupCode(), /^[A-Z0-9]{12}$/);
    assert.equal(fs.statSync(path.join(stateDir, "setup-code")).mode & 0o777, 0o600);
    const missing = await call("/api/setup", { body: { username: "superadmin", password: "Firstpass123!", confirmPassword: "Firstpass123!" } });
    assert.equal(missing.status, 400);
    assert.equal(missing.body.field, "setupCode");
    const wrong = await call("/api/setup", { body: { setupCode: "AAAAAAAAAAAA", username: "superadmin", password: "Firstpass123!", confirmPassword: "Firstpass123!" } });
    assert.equal(wrong.body.field, "setupCode");
    assert.equal((await call("/api/setup")).body.required, true, "no account was created");
  });

  await t.test("setup refuses a weak or mismatched password and names the field", async () => {
    const short = await call("/api/setup", { body: { setupCode: setupCode(), username: "superadmin", password: "abc", confirmPassword: "abc" } });
    assert.equal(short.status, 400);
    assert.equal(short.field || short.body.field, "password");
    const mismatch = await call("/api/setup", { body: { setupCode: setupCode(), username: "superadmin", password: "Firstpass123!", confirmPassword: "Nope123456" } });
    assert.equal(mismatch.body.field, "confirmPassword");
  });

  await t.test("setup creates the first administrator, once", async () => {
    const created = await call("/api/setup", { body: { setupCode: setupCode(), username: "superadmin", password: "Firstpass123!", confirmPassword: "Firstpass123!" } });
    assert.equal(created.status, 201);
    assert.equal(created.body.user.role, "Administrator");
    assert.equal((await call("/")).status, 200);
    const second = await call("/api/setup", { body: { setupCode: setupCode(), username: "sneak", password: "Another123!", confirmPassword: "Another123!" } });
    assert.equal(second.status, 409);
    assert.equal(second.body.code, "already_setup");
  });

  await t.test("preflight explains each operation without changing anything", async () => {
    const repair = (await call("/api/maintenance/repair/preflight", { body: {} })).body;
    assert.equal(repair.destructive, false);
    assert.equal(repair.confirmPhrase, "");
    assert.ok(repair.ready, repair.blockers.join("; "));
    assert.equal(repair.stages.length, 5);

    const reset = (await call("/api/maintenance/reset/preflight", { body: {} })).body;
    assert.equal(reset.destructive, true);
    assert.equal(reset.confirmPhrase, "RESET");
    assert.equal(reset.ready, false, "a reset with nothing selected must be blocked");
    assert.match(reset.blockers.join(" "), /Select at least one group/);
    assert.deepEqual(reset.scopes.map((group) => group.key), ["operational", "deployment", "secrets", "accounts"]);

    const destroy = (await call("/api/maintenance/destroy/preflight", { body: { scope: { auditHistory: true } } })).body;
    assert.equal(destroy.confirmPhrase, "DESTROY");
    assert.ok(destroy.scopes.some((group) => group.key === "agents"));
    assert.ok(destroy.scopes.some((group) => group.key === "backups"));
    assert.deepEqual(destroy.affects.map((item) => item.key), ["auditHistory"]);
  });

  await t.test("repair reports what it checked and corrects nothing it was not asked to", async () => {
    const started = await call("/api/maintenance/repair", { body: { reason: "Routine check" } });
    assert.equal(started.status, 202);
    const job = await waitForJob(call, started.body.job.id);
    assert.ok(job, "the repair did not finish");
    assert.ok(["Succeeded", "NeedsAttention"].includes(job.state), `${job.state}: ${job.error}`);
    assert.equal(job.stages.filter((stage) => stage.state === "failed").length, 0, JSON.stringify(job.stages));
    assert.equal(job.backupFile, "", "repair must not need a backup: it changes no records");
  });

  await t.test("every gate on a destructive operation is refused separately", async () => {
    const full = { reason: "Handing the lab portal over", confirm: "RESET", acknowledge: true, currentPassword: "Firstpass123!", scope: { deployment: true } };
    const cases = [
      [{ reason: "no" }, 400, /at least 5 characters/],
      [{ confirm: "reset" }, 400, /Type RESET exactly/],
      [{ confirm: "" }, 400, /Type RESET exactly/],
      [{ acknowledge: false }, 400, /read what this will affect/],
      [{ currentPassword: "wrong-password" }, 403, /password/i],
      [{ scope: {} }, 400, /Select at least one group/]
    ];
    for (const [override, status, message] of cases) {
      const response = await call("/api/maintenance/reset", { body: Object.assign({}, full, override) });
      assert.equal(response.status, status, `${JSON.stringify(override)} returned ${response.status}: ${JSON.stringify(response.body)}`);
      assert.match(response.body.error, message);
    }
  });

  await t.test("a backup is created, verified and listed", async () => {
    const made = await call("/api/maintenance/backups", { body: { reason: "Before the reset test" } });
    assert.equal(made.status, 201);
    assert.ok(made.body.backup.sizeBytes > 0);
    const verified = await call(`/api/maintenance/backups/${encodeURIComponent(made.body.backup.name)}/verify`, { method: "POST" });
    assert.equal(verified.body.ok, true, verified.body.problems && verified.body.problems.join("; "));
    const listed = (await call("/api/maintenance")).body.backups;
    assert.ok(listed.some((entry) => entry.name === made.body.backup.name && entry.readable));
  });

  await t.test("a damaged backup is reported as unusable rather than restored", async () => {
    const listed = (await call("/api/maintenance")).body.backups;
    const target = listed[0];
    const file = path.join(stateDir, "backups", target.name);
    const original = fs.readFileSync(file);
    fs.writeFileSync(file, Buffer.concat([original.subarray(0, original.length - 60), Buffer.alloc(60)]));
    const verified = await call(`/api/maintenance/backups/${encodeURIComponent(target.name)}/verify`, { method: "POST" });
    assert.equal(verified.body.ok, false);
    const restore = await call(`/api/maintenance/backups/${encodeURIComponent(target.name)}/restore`, {
      body: { reason: "Trying to restore a damaged backup", confirm: "RESTORE", acknowledge: true, currentPassword: "Firstpass123!" }
    });
    assert.equal(restore.status, 400);
    assert.match(restore.body.error, /cannot be restored/);
    fs.writeFileSync(file, original);
  });

  await t.test("agent maintenance acts only on the computers that were chosen", async () => {
    for (const machineName of ["pc-0142", "pc-0143", "pc-0144"]) {
      const enrolled = await call("/api/agents/enroll", {
        key: "test-enroll-key",
        body: { machineName, osVersion: "Windows 11 24H2", agentVersion: "1.5.0", ipAddresses: ["192.0.2.10"] }
      });
      assert.equal(enrolled.status, 201, JSON.stringify(enrolled.body));
    }
    const fleet = (await call("/api/agents")).body;
    assert.equal(fleet.length, 3);

    // With nothing chosen the operation is blocked, and the preflight names the computers it would reach.
    const empty = (await call("/api/maintenance/agent-repair/preflight", { body: { scope: { agentIds: [] } } })).body;
    assert.equal(empty.ready, false);
    assert.match(empty.blockers.join(" "), /Choose at least one agent/);

    const one = { agentIds: [fleet[0].agentId], includeOffline: true };
    const preview = (await call("/api/maintenance/agent-repair/preflight", { body: { scope: one } })).body;
    assert.equal(preview.ready, true, preview.blockers.join("; "));
    assert.equal(preview.selection.length, 1);
    assert.equal(preview.selection[0].machineName, fleet[0].machineName);
    assert.match(preview.notes.join(" "), /offline/, "offline agents must be explained before the operation runs");

    // Repair reaches an endpoint, so it needs the operator's password even though it removes nothing.
    const unauthorised = await call("/api/maintenance/agent-repair", { body: { reason: "Fixing the service", scope: one } });
    assert.equal(unauthorised.status, 403);

    const started = await call("/api/maintenance/agent-repair", {
      body: { reason: "Service start type drifted", currentPassword: "Firstpass123!", scope: one }
    });
    assert.equal(started.status, 202, JSON.stringify(started.body));
    const job = await waitForJob(call, started.body.job.id);
    assert.equal(job.state, "Succeeded", `${job.state}: ${job.error}`);
    assert.equal(job.backupFile, "", "a repair removes nothing, so it needs no backup");
    assert.match(job.corrections.join(" "), /authenticated repair to 1 agent/);

    // The command is queued on that agent only, and is attributable.
    const queued = (await call(`/api/agents/${fleet[0].agentId}/commands-history`)).body;
    const list = Array.isArray(queued) ? queued : queued.items || [];
    const repair = list.find((entry) => (entry.command || entry).commandType === "RepairAgent");
    assert.ok(repair, JSON.stringify(list).slice(0, 300));
    assert.equal(repair.enqueuedBy, "superadmin");
    assert.match(repair.reason, /Service start type drifted/);
    const untouched = (await call(`/api/agents/${fleet[1].agentId}/commands-history`)).body;
    const otherList = Array.isArray(untouched) ? untouched : untouched.items || [];
    assert.equal(otherList.filter((entry) => (entry.command || entry).commandType === "RepairAgent").length, 0);
  });

  await t.test("uninstalling agents is destructive, confirmed, and leaves them listed until verified", async () => {
    const fleet = (await call("/api/agents")).body;
    const target = { agentIds: [fleet[2].agentId], includeOffline: true };
    const preview = (await call("/api/maintenance/agent-removal/preflight", { body: { scope: target } })).body;
    assert.equal(preview.destructive, true);
    assert.equal(preview.confirmPhrase, "UNINSTALL");

    const noPhrase = await call("/api/maintenance/agent-removal", {
      body: { reason: "Decommissioning the computer", currentPassword: "Firstpass123!", acknowledge: true, scope: target }
    });
    assert.equal(noPhrase.status, 400);
    assert.match(noPhrase.body.error, /Type UNINSTALL exactly/);

    assert.equal(preview.requiresUninstallKey, true);
    const removal = { reason: "Decommissioning the computer", confirm: "UNINSTALL", acknowledge: true, currentPassword: "Firstpass123!", scope: target };
    const noKeyYet = await call("/api/maintenance/agent-removal", { body: removal });
    assert.equal(noKeyYet.status, 409);
    assert.equal(noKeyYet.body.code, "uninstall_key_missing");

    const issued = await call("/api/settings/uninstall-key", {
      body: { action: "issue", reason: "Enable agent removal", currentPassword: "Firstpass123!" }
    });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.match(issued.body.key, /^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$/);

    const wrongKey = await call("/api/maintenance/agent-removal", { body: { ...removal, uninstallKey: "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA" } });
    assert.equal(wrongKey.status, 403);
    assert.equal(wrongKey.body.field, "uninstallKey");
    assert.equal((await call("/api/agents")).body.filter((agent) => agent.removalState).length, 0, "a refused removal must not start");

    const started = await call("/api/maintenance/agent-removal", { body: { ...removal, uninstallKey: issued.body.key.toLowerCase() } });
    assert.equal(started.status, 202, JSON.stringify(started.body));
    const job = await waitForJob(call, started.body.job.id);
    assert.ok(["Succeeded", "NeedsAttention"].includes(job.state), `${job.state}: ${job.error}`);
    assert.ok(job.backupFile, "the agent records must be backed up first");
    assert.match(job.corrections.join(" "), /uninstall to 1 agent/);

    // The agent is still listed, because no endpoint has confirmed anything yet. That is the point.
    const after = (await call("/api/agents")).body;
    assert.equal(after.length, 3);
    const removing = after.find((agent) => agent.agentId === fleet[2].agentId);
    assert.ok(removing.removalState, "the agent must show that removal is in progress");
    assert.match(job.findings.map((finding) => finding.message).join(" "), /still being removed/);
  });

  await t.test("removing one agent needs this portal's key, and there is no way around it", async () => {
    const fleet = (await call("/api/agents")).body;
    const target = fleet.find((agent) => !agent.removalState);
    const remove = { confirmed: true, mode: "record", reason: "Retired computer", currentPassword: "Firstpass123!" };

    const noKey = await call(`/api/agents/${target.agentId}`, { method: "DELETE", body: remove });
    assert.equal(noKey.status, 403);
    assert.equal(noKey.body.field, "uninstallKey");

    // A well-formed key that this portal did not issue.
    const foreign = await call(`/api/agents/${target.agentId}`, { method: "DELETE", body: { ...remove, uninstallKey: "Q7K2M-9XW4P-T3N8R-B6V1Z-H5C0J" } });
    assert.equal(foreign.status, 403);

    const direct = await call(`/api/agents/${target.agentId}/commands`, { body: { commandType: "UninstallAgent", reason: "bypass", currentPassword: "Firstpass123!" } });
    assert.equal(direct.status, 400, "the uninstall command cannot be queued directly");
    assert.equal((await call("/api/agents")).body.length, fleet.length, "nothing was removed");

    const rotated = await call("/api/settings/uninstall-key", { body: { action: "issue", reason: "Rotate after test", currentPassword: "Firstpass123!" } });
    assert.equal(rotated.status, 200);
    const status = (await call("/api/settings/uninstall-key")).body;
    assert.equal(status.configured, true);
    assert.equal(status.key, undefined, "the key is shown only when it is generated");

    const removed = await call(`/api/agents/${target.agentId}`, { method: "DELETE", body: { ...remove, uninstallKey: rotated.body.key } });
    assert.equal(removed.status, 200, JSON.stringify(removed.body));
    assert.equal((await call("/api/agents")).body.length, fleet.length - 1);
    const audit = (await call("/api/audit")).body;
    assert.ok(audit.some((entry) => entry.action === "UninstallKeyCheck" && entry.result === "Denied"));
    assert.ok(!JSON.stringify(audit).includes(rotated.body.key.replace(/-/g, "")), "the audit log never holds the key");
  });

  await t.test("a reset clears what was selected, keeps the audit log, and returns to setup", async () => {
    assert.ok((await call("/api/agents")).body.length > 0);
    const auditBefore = (await call("/api/audit")).body.length;

    const started = await call("/api/maintenance/reset", {
      body: {
        reason: "Handing the lab portal to another team",
        confirm: "RESET",
        acknowledge: true,
        currentPassword: "Firstpass123!",
        scope: { operational: true, accounts: true }
      }
    });
    assert.equal(started.status, 202);
    resetJobId = started.body.job.id;
    auditBeforeReset = auditBefore;

    // Clearing accounts signs out every open session, including the one that ran the reset.
    let status = 200;
    for (let i = 0; i < 60 && status !== 401; i++) {
      status = (await call("/api/agents")).status;
      if (status !== 401) { await sleep(500); }
    }
    assert.equal(status, 401, "the session that existed before the reset must no longer work");

    const anonymous = client();
    assert.equal((await anonymous("/")).location, "/setup");
    assert.equal((await anonymous("/api/setup")).body.required, true);
    // Until a new administrator is created, even the sign-in form leads to setup.
    const refused = await anonymous("/login", { form: { username: "superadmin", password: "Firstpass123!" } });
    assert.equal(refused.location, "/setup", "the cleared account must not be able to sign in");
  });

  await t.test("a new Super Admin can be created after the reset and the old one cannot return", async () => {
    const fresh = client();
    const created = await fresh("/api/setup", { body: { setupCode: setupCode(), username: "newadmin", password: "Secondpass123!", confirmPassword: "Secondpass123!" } });
    assert.equal(created.status, 201);
    assert.equal((await fresh("/")).status, 200);

    const job = await waitForJob(fresh, resetJobId);
    assert.equal(job.state, "Succeeded", `${job.state}: ${job.error}`);
    assert.ok(job.backupFile, "a reset must take a backup first");
    assert.match(job.corrections.join(" "), /Cleared agent registrations/);
    assert.match(job.corrections.join(" "), /audit entr/);
    // The records are gone from memory, not only from disk: the store writes itself back every few
    // seconds, so a reset that only deleted files would undo itself.
    assert.equal((await fresh("/api/agents")).body.length, 0);
    assert.ok((await fresh("/api/audit")).body.length >= auditBeforeReset, "the audit log must survive this scope");
    // Deployment data was not in the reset scope, so it is still there.
    const state = (await fresh("/api/maintenance")).body;
    assert.equal(state.setupRequired, false);
    assert.ok(state.history.some((entry) => entry.type === "reset" && entry.state === "Succeeded"));
    assert.ok(state.backups.length >= 2, "the reset backup and the manual one must both be listed");
  });

  await t.test("the old account cannot sign in once setup is finished either", async () => {
    const fresh = client();
    const refused = await fresh("/login", { form: { username: "superadmin", password: "Firstpass123!" } });
    assert.equal(refused.status, 401);
  });

  await t.test("the audit log names the operator, the reason and the outcome", async () => {
    const fresh = client();
    await fresh("/login", { form: { username: "newadmin", password: "Secondpass123!" } });
    const entries = (await fresh("/api/audit")).body;
    const completed = entries.find((entry) => entry.action === "MaintenanceCompleted");
    assert.ok(completed, entries.map((entry) => entry.action).join(","));
    assert.equal(completed.user, "superadmin");
    assert.match(completed.details, /Reset the installation/);
    const refused = entries.find((entry) => entry.action === "ReauthFailed" || /password/i.test(entry.details || ""));
    assert.ok(refused, "the refused confirmation must be on the record too");
  });

  await t.test("two operations do not run at once", async () => {
    const fresh = client();
    await fresh("/login", { form: { username: "newadmin", password: "Secondpass123!" } });
    // Asked for at the same time, because a repair can finish in milliseconds on a small installation.
    const [first, second] = await Promise.all([
      fresh("/api/maintenance/repair", { body: { reason: "Checking the lock" } }),
      fresh("/api/maintenance/repair", { body: { reason: "Checking the lock again" } })
    ]);
    const accepted = [first, second].filter((response) => response.status === 202);
    const refused = [first, second].filter((response) => response.status === 409);
    assert.equal(accepted.length, 1, `statuses ${first.status} and ${second.status}`);
    assert.equal(refused.length, 1);
    assert.equal(refused[0].body.code, "busy");
    assert.match(refused[0].body.error, /already running/);
    await waitForJob(fresh, accepted[0].body.job.id);
  });

  await t.test("an update is refused when the helper is not installed as root", async () => {
    const fresh = client();
    await fresh("/login", { form: { username: "newadmin", password: "Secondpass123!" } });
    const check = (await fresh("/api/maintenance/refresh/preflight", { body: {} })).body;
    if (!fs.existsSync("/usr/local/sbin/uagent-maintenance")) {
      assert.equal(check.ready, false);
      assert.match(check.blockers.join(" "), /update helper is not installed|not a tracked checkout/);
    } else {
      assert.ok(check.ready || check.blockers.length, "the refresh preflight must reach a verdict");
    }
  });
});
