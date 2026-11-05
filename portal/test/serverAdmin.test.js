"use strict";

// Administration of the portal's own Linux server.
//
// What these tests are protecting:
//   * actions are validated into fixed helper arguments; nothing from the browser reaches a shell.
//   * only Administrators change anything; changes need confirmation, a reason and the password.
//   * one change at a time; every change is audited; a domain password goes to standard input only.
//   * on a platform other than Linux no server controls are offered.
//   * the root helper's parsers read real command output (run with python3 when it is available).
const test = require("node:test");
const assert = require("node:assert");
const express = require("express");
const { spawnSync } = require("child_process");
const path = require("path");
const serverAdmin = require("../lib/serverAdmin");
const serverApi = require("../routes/serverApi");
const { roleAllows } = require("../lib/commandTypes");

test("actions become fixed helper arguments", () => {
  const p = serverAdmin.prepare;
  assert.deepEqual(p("firewall-port", { op: "add", zone: "public", port: "8443/TCP" }).args, ["firewall", "port", "add", "public", "8443/tcp"]);
  assert.throws(() => p("firewall-port", { op: "add", zone: "public", port: "8443; rm -rf /" }), (e) => e.field === "port");
  assert.throws(() => p("firewall-service", { op: "drop", zone: "public", service: "ssh" }), (e) => e.field === "op");
  assert.deepEqual(p("service", { name: "httpd.service", action: "restart" }).args, ["service", "restart", "httpd.service"]);
  assert.throws(() => p("service", { name: "$(reboot)", action: "stop" }), (e) => e.field === "name");
  assert.throws(() => p("hostname", { name: "10.0.0.1" }), (e) => e.field === "name");
  assert.deepEqual(p("hostname", { name: "Portal01.Corp.Example.com" }).args, ["hostname", "set", "portal01.corp.example.com"]);
  const dns = p("dns", { connection: "0c3d1f0e-3c2b-4b4e-9f61-1234567890ab", servers: "10.0.0.10, 10.0.0.11", setSearch: true, search: "corp.example.com", test: "uagent.corp.example.com" });
  assert.deepEqual(dns.args, ["dns", "set", "0c3d1f0e-3c2b-4b4e-9f61-1234567890ab", "10.0.0.10,10.0.0.11", "--search", "corp.example.com", "--test", "uagent.corp.example.com"]);
  const join = p("domain-join", { domain: "corp.example.com", user: "joinadmin" }, "Pa55word!");
  assert.equal(join.input, "Pa55word!");
  assert.ok(!join.args.join(" ").includes("Pa55word!"), "the password is never an argument");
  assert.throws(() => p("domain-join", { domain: "corp.example.com", user: "joinadmin" }, ""), (e) => e.field === "secret");
  assert.throws(() => p("domain-join", { domain: "corp.example.com", user: "joinadmin" }, "a\nb"), (e) => e.field === "secret");
  assert.equal(p("domain-discover", { domain: "corp.example.com" }).readOnly, true);
  assert.throws(() => p("rm", {}), (e) => e instanceof serverAdmin.Invalid);
});

test("command output parsers", () => {
  const { parseDf, parseServices, parseListening, parseResolv, parseLast } = serverAdmin._parse;
  assert.deepEqual(parseDf("Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/mapper/cs-root 53660876800 5368709120 48292167680 10% /\n")[0],
    { filesystem: "/dev/mapper/cs-root", totalBytes: 53660876800, usedBytes: 5368709120, freeBytes: 48292167680, mount: "/" });
  const services = parseServices("sshd.service loaded active running OpenSSH server daemon\nxrdp.service not-found inactive dead xrdp.service\n", "sshd.service enabled\n");
  assert.equal(services[0].enabled, "enabled");
  assert.equal(services[0].description, "OpenSSH server daemon");
  assert.deepEqual(parseListening("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 511 [::]:443 [::]:*\n").map((l) => [l.address, l.port]), [["0.0.0.0", 22], ["::", 443]]);
  assert.deepEqual(parseResolv("# generated\nsearch corp.example.com\nnameserver 10.0.0.10\nnameserver 10.0.0.11\n"), { nameservers: ["10.0.0.10", "10.0.0.11"], search: ["corp.example.com"] });
  const logins = parseLast("root     pts/0        192.168.1.10     2026-11-04T10:00:00+0530 - 2026-11-04T11:00:00+0530  (01:00)\n" +
    "admin    pts/1        10.0.0.5         2026-11-04T12:00:00+0530   still logged in\n" +
    "reboot   system boot  4.18.0-553.el8.x86_64 2026-11-01T09:00:00+0530   still running\n\nwtmp begins 2026-10-01T00:00:00+0530\n");
  assert.equal(logins.length, 2);
  assert.equal(logins[0].startUtc, "2026-11-04T04:30:00.000Z");
  assert.equal(logins[1].state, "still logged in");
  assert.equal(logins[1].from, "10.0.0.5");
});

function harness(sys) {
  const audit = [];
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => {
    const role = req.get("X-Role");
    req.session = role ? { user: { name: role.toLowerCase(), role } } : {};
    next();
  });
  const auth = {
    requireApi: (req, res, next) => (req.session.user ? next() : res.status(401).json({ code: "unauthenticated" })),
    requireRole: (min) => (req, res, next) => (roleAllows(req.session.user && req.session.user.role, min) ? next() : res.status(403).json({ code: "forbidden" }))
  };
  const reauth = { verify: (req, res) => (req.body.currentPassword === "right" ? true : (res.status(403).json({ code: "reauth_failed" }), false)) };
  const store = { addAudit: (e) => audit.push(e), getAudit: () => audit.slice().reverse().map((e, i) => ({ ...e, timestampUtc: new Date(Date.now() - i).toISOString() })) };
  app.use("/api", serverApi({ store, auth, reauth, logger: () => {}, admin: sys }));
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve({ server, audit, base: `http://127.0.0.1:${server.address().port}` }));
  });
}

function fakeSystem(overrides) {
  const calls = [];
  return Object.assign({
    calls,
    HELPER: "/usr/local/sbin/uagent-sysadmin",
    LOG_SOURCES: serverAdmin.LOG_SOURCES,
    Invalid: serverAdmin.Invalid,
    prepare: serverAdmin.prepare,
    platform: () => ({ os: "linux", linux: true, helperInstalled: true }),
    collect: async () => ({ platform: { os: "linux", linux: true, helperInstalled: true }, supported: true, hostname: "portal01" }),
    runHelper: async (args, input) => {
      calls.push({ args, input });
      await new Promise((r) => setTimeout(r, 150));
      if (args[0] === "logs") { return { ok: true, text: "Nov 04 portal started\n" }; }
      return { ok: true, message: `done: ${args.join(" ")}` };
    }
  }, overrides || {});
}

const post = (base, role, url, body) => fetch(base + url, { method: "POST", headers: { "Content-Type": "application/json", "X-Role": role }, body: JSON.stringify(body) })
  .then(async (r) => ({ status: r.status, body: await r.json() }));

test("server changes: roles, confirmation, one at a time, audit and secrets", async (t) => {
  const sys = fakeSystem();
  const { server, audit, base } = await harness(sys);
  t.after(() => server.close());
  const body = { action: "service", parameters: { name: "httpd", action: "restart" }, reason: "Config reload", confirmed: true, currentPassword: "right" };

  assert.equal((await post(base, "Operator", "/api/server/actions", body)).status, 403);
  assert.equal((await post(base, "Administrator", "/api/server/actions", { ...body, confirmed: false })).body.code, "confirmation_required");
  assert.equal((await post(base, "Administrator", "/api/server/actions", { ...body, reason: "" })).body.code, "reason_required");
  assert.equal((await post(base, "Administrator", "/api/server/actions", { ...body, currentPassword: "wrong" })).body.code, "reauth_failed");
  const invalid = await post(base, "Administrator", "/api/server/actions", { ...body, parameters: { name: "a b;c", action: "stop" } });
  assert.equal(invalid.status, 400);
  assert.equal(invalid.body.field, "name");
  assert.equal(sys.calls.length, 0, "nothing reached the helper");

  const [first, second] = await Promise.all([
    post(base, "Administrator", "/api/server/actions", body),
    new Promise((r) => setTimeout(r, 30)).then(() => post(base, "Administrator", "/api/server/actions", { ...body, parameters: { name: "chronyd", action: "restart" } }))
  ]);
  assert.equal(first.status, 200);
  assert.equal(second.status, 409, "a second change waits for the first");
  assert.deepEqual(sys.calls[0].args, ["service", "restart", "httpd"]);

  const secret = "J0in-Secret!";
  const join = await post(base, "Administrator", "/api/server/actions", { action: "domain-join", parameters: { domain: "corp.example.com", user: "joinadmin" }, secret, reason: "Onboard", confirmed: true, currentPassword: "right" });
  assert.equal(join.status, 200);
  assert.equal(sys.calls[1].input, secret, "the password goes to standard input");
  assert.ok(!JSON.stringify(sys.calls[1].args).includes(secret));
  assert.ok(!JSON.stringify(audit).includes(secret), "the audit never holds the password");
  assert.ok(!JSON.stringify(join.body).includes(secret), "the response never holds the password");
  assert.ok(audit.some((e) => e.action === "Server:service" && e.result === "Success" && /Restart httpd/.test(e.details) && e.user === "administrator"));
  assert.ok(audit.some((e) => e.action === "Server:service" && e.result === "Pending" && /Reason: Config reload/.test(e.details)));

  const info = await (await fetch(`${base}/api/server/info`, { headers: { "X-Role": "Monitor" } })).json();
  assert.equal(info.canChange, false);
  assert.ok(info.portal.operations.length >= 2, "operations are listed");
  assert.equal((await fetch(`${base}/api/server/logs/auth`, { headers: { "X-Role": "Operator" } })).status, 403, "logs are for Administrators");
  const logs = await fetch(`${base}/api/server/logs/auth?lines=50`, { headers: { "X-Role": "Administrator" } });
  assert.equal(await logs.text(), "Nov 04 portal started\n");
  assert.deepEqual(sys.calls[sys.calls.length - 1].args, ["logs", "auth", "50"]);
  assert.equal((await fetch(`${base}/api/server/logs/etc-shadow`, { headers: { "X-Role": "Administrator" } })).status, 404);
});

test("no server controls on a platform other than Linux", async (t) => {
  const sys = fakeSystem({ platform: () => ({ os: "darwin", linux: false, helperInstalled: false }), collect: async () => ({ platform: { os: "darwin", linux: false }, supported: false }) });
  const { server, base } = await harness(sys);
  t.after(() => server.close());
  const info = await (await fetch(`${base}/api/server/info`, { headers: { "X-Role": "Administrator" } })).json();
  assert.equal(info.supported, false);
  const refused = await post(base, "Administrator", "/api/server/actions", { action: "power", parameters: { action: "reboot" }, reason: "x", confirmed: true, currentPassword: "right" });
  assert.equal(refused.status, 409);
  assert.equal(refused.body.code, "unsupported");
  assert.equal(sys.calls.length, 0);
  if (process.platform !== "linux") {
    assert.equal((await serverAdmin.collect()).supported, false, "the real collector also reports unsupported here");
  }
});

const python = ["python3", "/usr/libexec/platform-python"].find((p) => spawnSync(p, ["-c", "print(1)"]).status === 0);
test("the root helper parses firewalld and last output", { skip: !python && "python3 is not installed" }, () => {
  const helper = path.join(__dirname, "../../scripts/uagent-sysadmin.py");
  const script = `
import importlib.util, json
spec = importlib.util.spec_from_file_location("h", ${JSON.stringify(helper)})
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
zone = h.parse_zone("public (active)\\n  target: default\\n  interfaces: ens192\\n  services: cockpit ssh\\n  ports: 443/tcp\\n  rich rules: \\n\\trule family=\\"ipv4\\" source address=\\"10.0.0.0/8\\" accept\\n")
print(json.dumps({"zone": zone, "port": bool(h.PORT.match("70000/tcp")), "range": h.PORT.match("5000-5100/udp").groups(),
  "sshd": bool(h.PROTECTED_UNITS.match("sshd.service")), "httpd": bool(h.PROTECTED_UNITS.match("httpd.service")),
  "utc": h.iso_utc("2026-11-04T10:00:00+0530")}))
`;
  const result = spawnSync(python, ["-c", script], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const out = JSON.parse(result.stdout);
  assert.deepEqual(out.zone.services, ["cockpit", "ssh"]);
  assert.deepEqual(out.zone.richRules, ['rule family="ipv4" source address="10.0.0.0/8" accept']);
  assert.equal(out.zone.active, true);
  assert.equal(out.port, true, "the pattern matches; the range check rejects it later");
  assert.deepEqual(out.range, ["5000", "5100", "udp"]);
  assert.equal(out.sshd, true);
  assert.equal(out.httpd, false);
  assert.equal(out.utc, "2026-11-04T04:30:00Z");
  const usage = spawnSync(python, [helper, "info"], { encoding: "utf8" });
  if (process.getuid && process.getuid() !== 0) {
    assert.equal(JSON.parse(usage.stdout.trim()).error, "Run this as root.", "the helper refuses to run without root");
  }
});
