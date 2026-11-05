"use strict";

// System administration of Windows endpoints from the portal.
//
// What these tests are protecting:
//   * settings are validated before queuing, with the failing field named, and essential services can't be stopped.
//   * only Administrators can queue changes, each needs a reason, confirmation and the portal password.
//   * a domain password reaches the agent once and is never stored, audited, logged or returned to a browser.
//   * one change at a time per computer; the admin snapshot is accepted, size-bounded and requires the feature.
//   * the Remote Desktop reachability probe reports open and closed ports.
const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const { validate, Invalid, isAdminCommand } = require("../lib/adminCommands");
const Store = require("../lib/store");
const { lanIpv4Addresses } = require("../lib/network");

const ROOT = path.resolve(__dirname, "../..");
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

function invalid(fn, field) {
  assert.throws(fn, (error) => error instanceof Invalid && (!field || error.field === field), `expected Invalid on ${field}`);
}

test("validation accepts good settings and names the field of bad ones", () => {
  assert.ok(isAdminCommand("SetDns") && !isAdminCommand("ResetPassword"));
  assert.deepEqual(validate("ServiceControl", { name: "Spooler", action: "Restart" }).parameters, { name: "Spooler", action: "restart" });
  invalid(() => validate("ServiceControl", { name: "mpssvc", action: "stop" }), "name");
  invalid(() => validate("ServiceControl", { name: "uAgent", action: "restart" }), "name");
  assert.equal(validate("ServiceControl", { name: "uAgent", action: "start" }).parameters.action, "start", "protected services may be started");
  invalid(() => validate("ServiceControl", { name: "a;b", action: "stop" }), "name");

  const rule = validate("FirewallRule", { op: "add", name: "Web", direction: "Inbound", action: "Allow", protocol: "TCP", localPort: "443, 8443", remoteAddress: "10.0.0.0/24" });
  assert.equal(rule.parameters.localPort, "443,8443");
  assert.equal(rule.parameters.profile, "Any");
  assert.match(rule.summary, /Add firewall rule "Web" \(Allow inbound TCP 443,8443 from 10\.0\.0\.0\/24\)/);
  invalid(() => validate("FirewallRule", { op: "add", name: "x", direction: "Inbound", action: "Allow", protocol: "TCP", localPort: "70000" }), "localPort");
  invalid(() => validate("FirewallRule", { op: "add", name: "x", direction: "Inbound", action: "Allow", protocol: "ICMPv4", localPort: "80" }), "localPort");
  invalid(() => validate("FirewallRule", { op: "add", name: "x", direction: "Inbound", action: "Allow", protocol: "TCP", program: "app.exe" }), "program");
  invalid(() => validate("FirewallRule", { op: "remove" }), "id");
  invalid(() => validate("FirewallRule", { op: "add", name: "x", direction: "Inbound", action: "Allow", protocol: "TCP", profile: "Any,Public" }), "profile");

  invalid(() => validate("SetHostname", { name: "1234" }), "name");
  invalid(() => validate("SetHostname", { name: "THIS-NAME-IS-TOO-LONG" }), "name");
  invalid(() => validate("SetHostname", { name: "PC-01", user: "CORP\\admin" }, ""), "secret");
  const rename = validate("SetHostname", { name: "PC-01", dnsSuffix: "corp.example.com" }, "");
  assert.equal(rename.secret, null, "no password is passed on without a domain account");
  invalid(() => validate("SetHostname", { name: "PC-01" }, "orphan-password"), "user");

  invalid(() => validate("SetDns", { interfaceIndex: "x", servers: "10.0.0.1" }), "interfaceIndex");
  invalid(() => validate("SetDns", { interfaceIndex: "4", servers: "10.0.0.300" }), "servers");
  assert.equal(validate("SetDns", { interfaceIndex: "4", servers: "DHCP" }).parameters.servers, "dhcp");
  invalid(() => validate("SetDns", { interfaceIndex: "4", servers: "10.0.0.1", setSearchList: true, searchList: "bad_suffix!" }), "searchList");

  invalid(() => validate("JoinDomain", { domain: "corp", user: "a", restart: true }, "pw"), "domain");
  invalid(() => validate("JoinDomain", { domain: "corp.example.com", user: "CORP\\a" }, ""), "secret");
  invalid(() => validate("JoinDomain", { domain: "corp.example.com", user: "CORP\\a", ouPath: "Workstations" }, "pw"), "ouPath");
  const join = validate("JoinDomain", { domain: "corp.example.com", user: "CORP\\a" }, "S3cret!");
  assert.equal(join.secret, "S3cret!");
  assert.ok(!JSON.stringify(join.parameters).includes("S3cret!") && !join.summary.includes("S3cret!"));
  invalid(() => validate("LeaveDomain", { workgroup: "WORK GROUP", user: "a" }, "pw"), "workgroup");
  invalid(() => validate("Bogus", {}));
});

test("the admin snapshot keeps its shape but is bounded", () => {
  const big = Object.assign(JSON.parse('{"__proto__":{"polluted":true}}'), { platform: "Windows", rules: Array.from({ length: 5000 }, (_, i) => ({ id: String(i) })),
    text: "x".repeat(5000), deep: { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } } });
  const out = Store.normalizeSection("admin", big);
  assert.ok(!Object.prototype.hasOwnProperty.call(out, "__proto__"));
  assert.equal(out.platform, "Windows");
  assert.equal(out.rules.length, 3000);
  assert.equal(out.text.length, 2000);
  assert.equal(out.deep.a.b.c.d.e, null, "nesting is cut off");
  assert.equal(Store.normalizeSection("admin", [1, 2]), null, "arrays are not a snapshot");
  assert.equal({}.polluted, undefined);
});

// --- Live portal ------------------------------------------------------------------------------------

function jar() {
  const cookies = new Map();
  return {
    header() { return [...cookies].map(([k, v]) => `${k}=${v}`).join("; "); },
    take(res) {
      for (const line of res.headers.getSetCookie ? res.headers.getSetCookie() : []) {
        const [pair] = line.split(";");
        const i = pair.indexOf("=");
        cookies.set(pair.slice(0, i), pair.slice(i + 1));
      }
    }
  };
}

async function signIn(base, username, password) {
  const cookies = jar();
  const send = async (url, options) => {
    const res = await fetch(base + url, Object.assign({ redirect: "manual" }, options, {
      headers: Object.assign({ Origin: base, Cookie: cookies.header() }, (options && options.headers) || {})
    }));
    cookies.take(res);
    return res;
  };
  await send("/login");
  let res = await send("/login", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username, password }) });
  assert.equal(res.status, 302, `${username} signs in`);
  let current = password;
  if (res.headers.get("location") === "/account/password") {
    const next = `${password}-New9`;
    res = await send("/account/password", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ currentPassword: password, newPassword: next, confirmPassword: next }) });
    assert.equal(res.status, 302, `${username} replaces the initial password`);
    current = next;
  }
  const api = async (url, method, body) => {
    const r = await send(url, { method: method || "GET", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch (error) { json = text; }
    return { status: r.status, body: json, raw: text };
  };
  return { api, password: current };
}

test("Windows administration through the portal", async (t) => {
  const port = 18571;
  const base = `http://127.0.0.1:${port}`;
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "uagent-sysadmin-"));
  const enrollKey = crypto.randomBytes(24).toString("hex");
  const users = [
    { username: "admin", password: "Adminpass123!", role: "Administrator" },
    { username: "ops", password: "Opspass123!", role: "Operator" },
    { username: "mon", password: "Monpass123!", role: "Monitor" }
  ];
  const env = Object.assign({}, process.env, {
    PORTAL_STATE_DIR: stateDir, PORTAL_HTTP_PORT: String(port), PORTAL_HTTPS_PORT: "0", FORCE_HTTPS: "false", CANONICAL_REDIRECT: "false",
    TLS_MANAGE_SELF_SIGNED: "false", PORTAL_USERS: JSON.stringify(users), ENROLLMENT_KEY: enrollKey, PORTAL_ENV_FILE: path.join(stateDir, "none.env")
  });
  const portal = spawn("node", ["server.js"], { cwd: path.join(ROOT, "portal"), env, stdio: ["ignore", "pipe", "pipe"] });
  const log = [];
  portal.stdout.on("data", (d) => log.push(d.toString()));
  portal.stderr.on("data", (d) => log.push(d.toString()));
  const listener = net.createServer((socket) => socket.destroy());
  t.after(() => {
    portal.kill("SIGKILL");
    listener.close();
    fs.rmSync(stateDir, { recursive: true, force: true });
  });
  let up = false;
  for (let i = 0; i < 80 && !up; i++) {
    try { up = (await fetch(`${base}/healthz`)).status === 200; } catch (error) { await sleep(250); }
  }
  assert.ok(up, log.join("").slice(-800));

  // A fake Windows agent that advertises system administration.
  const lanIp = lanIpv4Addresses()[0] || null;
  await new Promise((done) => listener.listen(0, lanIp || "127.0.0.1", done));
  const rdpPort = listener.address().port;
  const enrolled = await (await fetch(`${base}/api/agents/enroll`, { method: "POST", headers: { "Content-Type": "application/json", "X-Api-Key": enrollKey },
    body: JSON.stringify({ machineName: "PC-ADMIN", osVersion: "Windows 11", agentVersion: "1.6.0" }) })).json();
  const agentHeaders = { "Content-Type": "application/json", "X-Api-Key": enrolled.apiKey };
  const agentPost = (p, body) => fetch(`${base}/api/agents/${enrolled.agentId}${p}`, { method: "POST", headers: agentHeaders, body: JSON.stringify(body) });
  const capabilities = ["LongPoll", "Inventory", "SystemAdmin", "RestartComputer", "ServiceControl", "ShutdownComputer", "SetFirewallProfile", "FirewallRule",
    "SetRemoteDesktop", "SetNla", "SetHostname", "SetDns", "JoinDomain", "LeaveDomain"];
  assert.equal((await agentPost("/heartbeat", { machineName: "PC-ADMIN", osVersion: "Windows 11", agentVersion: "1.6.0", serviceMode: "WindowsService",
    capabilities, ipAddresses: lanIp ? [lanIp] : [] })).status, 200);

  const admin = await signIn(base, "admin", "Adminpass123!");
  const ops = await signIn(base, "ops", "Opspass123!");
  const mon = await signIn(base, "mon", "Monpass123!");
  const commands = `/api/agents/${enrolled.agentId}/commands`;
  const secret = "Dom@inS3cret-" + crypto.randomBytes(4).toString("hex");
  const join = (who, extra) => who.api(commands, "POST", Object.assign({
    commandType: "JoinDomain", parameters: { domain: "corp.example.com", user: "CORP\\joiner", restart: true }, secret,
    reason: "Onboarding", confirmed: true, currentPassword: who.password
  }, extra || {}));

  // Roles, confirmation, reason, validation and password checks.
  assert.equal((await ops.api(commands, "POST", { commandType: "SetNla", parameters: { enabled: true }, reason: "x", confirmed: true, currentPassword: ops.password })).status, 403);
  assert.equal((await mon.api(commands, "POST", { commandType: "ServiceControl", parameters: { name: "Spooler", action: "stop" }, reason: "x", confirmed: true })).status, 403);
  assert.equal((await join(admin, { confirmed: false })).body.code, "confirmation_required");
  assert.equal((await join(admin, { reason: "" })).body.code, "reason_required");
  const bad = await join(admin, { parameters: { domain: "corp", user: "CORP\\joiner" } });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.field, "domain");
  assert.equal((await join(admin, { currentPassword: "wrong" })).body.code, "reauth_failed");

  // Queued: the agent receives the parameters and the secret once.
  const queued = await join(admin);
  assert.equal(queued.status, 201, queued.raw);
  assert.ok(!queued.raw.includes(secret), "the response must not echo the password");
  assert.match(queued.body.summary, /Join domain corp\.example\.com as CORP\\joiner and restart/);

  // One change at a time.
  const second = await admin.api(commands, "POST", { commandType: "SetNla", parameters: { enabled: true }, reason: "Harden", confirmed: true, currentPassword: admin.password });
  assert.equal(second.status, 409);
  assert.equal(second.body.code, "in_progress");

  const delivered = await (await fetch(`${base}/api/agents/${enrolled.agentId}/commands`, { headers: agentHeaders })).json();
  const job = delivered.find((c) => c.commandId === queued.body.commandId);
  assert.ok(job, "the agent collects the command");
  assert.equal(job.newPassword, secret, "the agent gets the password");
  assert.deepEqual(job.parameters, { domain: "corp.example.com", user: "CORP\\joiner", ouPath: "", restart: "true" });
  assert.equal((await agentPost("/command-results", [{ commandId: job.commandId, success: true, message: "Joined corp.example.com. Restarting in 60 seconds." }])).status, 204);

  const history = await admin.api(`/api/agents/${enrolled.agentId}`);
  assert.ok(history.body.commands.some((c) => c.commandId === job.commandId && c.status === "Success"));
  assert.ok(!history.raw.includes(secret), "history never contains the password");
  const audit = await admin.api("/api/audit");
  assert.ok(!audit.raw.includes(secret), "the audit log never contains the password");
  assert.match(audit.raw, /Join domain corp\.example\.com/, "the audit says what was done");
  await sleep(1200);
  for (const file of fs.readdirSync(stateDir)) {
    const full = path.join(stateDir, file);
    if (fs.statSync(full).isFile()) {
      assert.ok(!fs.readFileSync(full, "utf8").includes(secret), `${file} must not contain the password`);
    }
  }
  assert.ok(!log.join("").includes(secret), "the service log must not contain the password");

  // The next change can go now.
  const nla = await admin.api(commands, "POST", { commandType: "SetNla", parameters: { enabled: "true" }, reason: "Harden", confirmed: true, currentPassword: admin.password });
  assert.equal(nla.status, 201, nla.raw);

  const serverPage = await mon.api("/server");
  assert.equal(serverPage.status, 200, "the portal server page renders");
  assert.match(serverPage.raw, /id="srvBody"/);
  const serverInfo = await mon.api("/api/server/info");
  assert.equal(serverInfo.status, 200);
  assert.equal(serverInfo.body.canChange, false);
  assert.equal(serverInfo.body.supported, process.platform === "linux");
  const agentPage = await admin.api(`/agents/${enrolled.displayId}`);
  assert.equal(agentPage.status, 200);
  assert.match(agentPage.raw, /\/js\/system\.js\?v=/, "the System tab script is loaded");

  // The admin snapshot.
  const snapshot = { platform: "Windows", computer: { hostname: "PC-ADMIN" }, remoteDesktop: { enabled: true, port: rdpPort, listening: true }, errors: [] };
  assert.equal((await agentPost("/inventory", { section: "admin", data: snapshot, collectedUtc: new Date().toISOString() })).status, 204);
  const viewed = await mon.api(`/api/agents/${enrolled.agentId}/inventory/admin`);
  assert.equal(viewed.status, 200, "monitors can view the snapshot");
  assert.equal(viewed.body.data.computer.hostname, "PC-ADMIN");

  if (lanIp) {
    assert.equal((await mon.api(`/api/agents/${enrolled.agentId}/rdp-probe`, "POST", {})).status, 403, "probing needs Operator");
    const open = await ops.api(`/api/agents/${enrolled.agentId}/rdp-probe`, "POST", {});
    assert.equal(open.status, 200, open.raw);
    assert.equal(open.body.port, rdpPort);
    assert.equal(open.body.reachable, true);
    listener.close();
    await sleep(100);
    const closed = await ops.api(`/api/agents/${enrolled.agentId}/rdp-probe`, "POST", {});
    assert.equal(closed.body.reachable, false);
  }

  // An agent without the feature does not offer the snapshot.
  const old = await (await fetch(`${base}/api/agents/enroll`, { method: "POST", headers: { "Content-Type": "application/json", "X-Api-Key": enrollKey },
    body: JSON.stringify({ machineName: "PC-OLD", osVersion: "Windows 10", agentVersion: "1.5.1" }) })).json();
  await fetch(`${base}/api/agents/${old.agentId}/heartbeat`, { method: "POST", headers: { "Content-Type": "application/json", "X-Api-Key": old.apiKey },
    body: JSON.stringify({ machineName: "PC-OLD", agentVersion: "1.5.1", capabilities: ["LongPoll", "Inventory"] }) });
  const unsupported = await admin.api(`/api/agents/${old.agentId}/inventory/admin`);
  assert.equal(unsupported.status, 409);
  const refused = await admin.api(`/api/agents/${old.agentId}/commands`, "POST", { commandType: "SetNla", parameters: { enabled: true }, reason: "x", confirmed: true, currentPassword: admin.password });
  assert.equal(refused.body.code, "unsupported");
});
