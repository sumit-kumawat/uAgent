"use strict";

// Restoring a backup must actually take effect. The running portal keeps its state in memory and saves
// it every few seconds, so a restore that only replaced the files was silently undone. Now the portal
// stops saving, restarts on the restored files, and records the restore in the restored audit log.
const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const ROOT = path.resolve(__dirname, "../..");
const PORT = 18493;
const BASE = `http://127.0.0.1:${PORT}`;
const STATE = path.join(os.tmpdir(), "uagent-restore-test");
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

function start() {
  const child = spawn("node", ["server.js"], {
    cwd: path.join(ROOT, "portal"),
    env: Object.assign({}, process.env, {
      PORTAL_STATE_DIR: STATE,
      PORTAL_HTTP_PORT: String(PORT),
      PORTAL_HTTPS_PORT: "0",
      FORCE_HTTPS: "false",
      CANONICAL_REDIRECT: "false",
      TLS_MANAGE_SELF_SIGNED: "false",
      PUBLIC_HOST: "127.0.0.1",
      ENROLLMENT_KEY: "test-enroll-key",
      PORTAL_USERS: JSON.stringify([{ username: "admin", password: "testpass123", role: "Administrator" }])
    }),
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.log = [];
  child.stdout.on("data", (d) => child.log.push(d.toString()));
  child.stderr.on("data", (d) => child.log.push(d.toString()));
  child.exited = new Promise((done) => child.once("exit", (code) => done(code)));
  return child;
}

function client() {
  let cookie = "";
  return async function call(urlPath, options = {}) {
    const init = { method: options.method || (options.body || options.form ? "POST" : "GET"), headers: { Accept: "application/json" }, redirect: "manual" };
    if (cookie) { init.headers.Cookie = cookie; }
    if (options.key) { init.headers["X-Api-Key"] = options.key; }
    if (options.body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(options.body); }
    if (options.form) { init.headers["Content-Type"] = "application/x-www-form-urlencoded"; init.body = new URLSearchParams(options.form).toString(); }
    const res = await fetch(BASE + urlPath, init);
    for (const entry of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) {
      if (entry.startsWith("uagent.sid")) { cookie = entry.split(";")[0]; }
    }
    const type = res.headers.get("content-type") || "";
    return { status: res.status, body: type.includes("json") ? await res.json() : await res.text() };
  };
}

async function ready() {
  for (let i = 0; i < 80; i++) {
    try { if ((await fetch(`${BASE}/healthz`)).status === 200) { return true; } } catch { /* starting */ }
    await sleep(250);
  }
  return false;
}

async function signIn(password) {
  const call = client();
  await call("/login", { form: { username: "admin", password } });
  return call;
}

const enroll = (call, name) => call("/api/agents/enroll", {
  key: "test-enroll-key",
  body: { machineName: name, osVersion: "Windows 11", agentVersion: "1.5.0", ipAddresses: ["192.0.2.20"] }
});

test("a restored backup is what the portal runs on after its restart", { timeout: 120000 }, async () => {
  fs.rmSync(STATE, { recursive: true, force: true });
  fs.mkdirSync(STATE, { recursive: true });
  let portal = start();
  try {
    assert.ok(await ready(), portal.log.join(""));
    let call = await signIn("testpass123");
    await call("/api/account/password", { body: { currentPassword: "testpass123", newPassword: "newpass12345", confirmPassword: "newpass12345" } });
    call = await signIn("newpass12345");

    assert.equal((await enroll(call, "PC-0142")).status, 201);
    const made = await call("/api/maintenance/backups", { body: { reason: "Before adding more computers" } });
    assert.equal(made.status, 201, JSON.stringify(made.body));
    assert.equal((await enroll(call, "PC-0143")).status, 201);
    assert.equal((await enroll(call, "PC-0144")).status, 201);
    await sleep(3500);
    assert.equal((await call("/api/agents")).body.length, 3);

    const restored = await call(`/api/maintenance/backups/${encodeURIComponent(made.body.backup.name)}/restore`, {
      body: { reason: "Undo the test enrolments", confirm: "RESTORE", acknowledge: true, currentPassword: "newpass12345" }
    });
    assert.equal(restored.status, 200, JSON.stringify(restored.body));
    assert.equal(restored.body.restarting, true);
    assert.equal(await portal.exited, 0, "the portal exits so the service manager restarts it");

    // The files on disk are the restored ones: nothing wrote over them on the way out.
    const onDisk = JSON.parse(fs.readFileSync(path.join(STATE, "portal-store.json"), "utf8"));
    assert.equal(onDisk.agents.length, 1);

    portal = start();
    assert.ok(await ready(), portal.log.join(""));
    call = await signIn("newpass12345");
    const agents = (await call("/api/agents")).body;
    assert.deepEqual(agents.map((agent) => agent.machineName), ["PC-0142"]);
    const audit = (await call("/api/audit")).body;
    assert.ok(audit.some((entry) => entry.action === "BackupRestored" && /Undo the test enrolments/.test(entry.details)), "the restore is in the restored audit log");
    assert.ok(!fs.existsSync(path.join(STATE, "restore-pending.json")));
  } finally {
    portal.kill("SIGKILL");
    fs.rmSync(STATE, { recursive: true, force: true });
  }
});
