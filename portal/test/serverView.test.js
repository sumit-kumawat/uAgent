"use strict";

// The Portal server page renders a Linux snapshot without leaking bad values, reports account usage as
// unknown when the sign-in record could not be read, and states what a firewall zone does with traffic
// that is not listed.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const script = fs.readFileSync(path.join(__dirname, "../public/js/server.js"), "utf8");
const now = Date.now();
const ago = (minutes) => new Date(now - minutes * 60000).toISOString();

function snapshot(lastLoginKnown) {
  return {
    supported: true, canChange: true, collectedUtc: ago(1), hostname: "portal01", fqdn: "portal01.corp.example.com",
    platform: { os: "linux", linux: true, helperInstalled: true },
    os: { name: "CentOS Stream 8", kernel: "4.18.0", architecture: "x64" }, uptimeSeconds: 90000, bootUtc: ago(1500), loadAverage: [0.1, 0.2, 0.3],
    cpu: { model: "Xeon", count: 4 }, memory: { totalBytes: 8e9, availableBytes: 4e9, swapTotalBytes: 0, swapFreeBytes: 0 },
    disks: [{ filesystem: "/dev/sda1", totalBytes: 100e9, usedBytes: 50e9, freeBytes: 50e9, mount: "/" }],
    interfaces: [{ name: "ens192", state: "UP", mac: "00:50:56:aa:bb:cc", mtu: 1500, addresses: ["10.0.0.5/24"] }],
    gateways: [{ gateway: "10.0.0.1", device: "ens192", metric: 100 }], dns: { nameservers: ["10.0.0.10"], search: ["corp.example.com"] },
    connections: [], services: [], listening: [{ protocol: "tcp", state: "LISTEN", address: "0.0.0.0", port: 443 }],
    sessions: [{ id: "4", user: "ops", remote: true, remoteHost: "10.0.0.50", state: "active", type: "tty", service: "sshd", startedUtc: ago(30), idle: false }],
    logins: [{ user: "ops", line: "pts/0", from: "10.0.0.50", startUtc: ago(30), endUtc: null, state: "still logged in" }],
    portal: { signIns: [], lastAdministratorSignIn: null, operations: [], running: null },
    privileged: {
      ok: true, failedLogins: [], authEvents: [], adminActions: [], configChanges: [], problems: [], power: [],
      ssh: { installed: true, active: "active", enabled: "enabled", ports: [22] }, xrdp: { installed: false }, realm: { installed: false }, selinux: "Enforcing", backups: {},
      accounts: [
        { user: "root", uid: 0, shell: "/bin/bash", interactive: true, locked: false, noPassword: false, admin: true, lastLoginUtc: null, lastLoginFrom: null, lastLoginKnown },
        { user: "ops", uid: 1000, shell: "/bin/bash", interactive: true, locked: false, noPassword: false, admin: true, lastLoginUtc: ago(30), lastLoginFrom: "10.0.0.50", lastLoginKnown },
        { user: "old", uid: 1001, shell: "/bin/bash", interactive: true, locked: false, noPassword: false, admin: false, lastLoginUtc: lastLoginKnown ? ago(200 * 1440) : null, lastLoginFrom: null, lastLoginKnown }
      ],
      firewall: { installed: true, active: "active", enabled: "enabled", running: true, defaultZone: "public", panic: false, availableServices: ["ssh"], revertPending: null,
        zones: [{ name: "public", default: true, active: true, target: "default", interfaces: ["ens192"], sources: [], services: ["ssh"], ports: ["443/tcp"], richRules: [], permanentPorts: ["443/tcp"], permanentServices: ["ssh"] },
          { name: "trusted", default: false, active: false, target: "ACCEPT", interfaces: [], sources: [], services: [], ports: [], richRules: [], permanentPorts: [], permanentServices: [] }] }
    }
  };
}

function element() {
  return { innerHTML: "", textContent: "", hidden: false, disabled: false, classList: { toggle() {} }, addEventListener() {}, focus() {}, setSelectionRange() {} };
}

async function render(data, view) {
  const els = {};
  let click = null;
  const U = {
    escapeHtml: (v) => (v === null || v === undefined ? "" : String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")),
    formatDateTime: (v) => new Date(v).toISOString(),
    relativeTime: () => "5 min ago",
    formatBytes: (v) => Math.round(Number(v) / 1e9) + " GB",
    pill: (tone, label) => `<span class="pill pill-${tone}">${label}</span>`,
    statusPill: (s) => `<span class="pill">${s}</span>`,
    api: async () => data
  };
  const context = {
    window: { uAgent: U },
    document: {
      getElementById: (id) => (els[id] = els[id] || element()),
      querySelectorAll: () => [],
      addEventListener: (type, fn) => { if (type === "click") { click = fn; } }
    },
    setInterval: () => 0, setTimeout, console, Date, JSON, Math, Number, String, Array, Object, Set, Map, Promise
  };
  vm.runInNewContext(script, context);
  await new Promise((r) => setTimeout(r, 10));
  click({ target: { closest: (sel) => (sel === "[data-srv-view]" ? { getAttribute: () => view } : null) } });
  const html = els.srvBody.innerHTML;
  assert.doesNotMatch(html, /undefined|NaN|\[object Object\]/, `${view} leaks a bad value`);
  return html;
}

const row = (html, user) => html.split(`cell-primary">${user}</span>`)[1].split("</tr>")[0];

test("account usage comes from lastlog, sessions and history", async () => {
  const html = await render(snapshot(true), "access");
  assert.match(row(html, "ops"), /Session active/);
  assert.match(row(html, "ops"), /pill-success">In use/);
  assert.match(row(html, "old"), /pill-warning">Unused/);
  assert.match(row(html, "root"), /Never signed in/);
  assert.match(html, /Unused accounts<\/div><div class="value">2</);
});

test("accounts are unknown, not unused, when lastlog cannot be read", async () => {
  const html = await render(snapshot(false), "access");
  assert.match(row(html, "old"), /pill-neutral">Unknown/);
  assert.doesNotMatch(row(html, "old"), /Unused|Never signed in/);
  assert.match(row(html, "ops"), /In use/, "a live session still proves use");
  assert.match(html, /Unused accounts<\/div><div class="value">0</);
});

test("each firewall zone states what happens to unlisted traffic", async () => {
  const html = await render(snapshot(true), "firewall");
  assert.match(html.split("Zone public")[1].split("Zone trusted")[0], /Blocked \(rejected\)/);
  assert.match(html.split("Zone trusted")[1], /Allowed \(zone accepts all traffic\)/);
  assert.match(html, /443\/tcp/);
});

test("the overview shows identity, resources and gateways", async () => {
  const html = await render(snapshot(true), "overview");
  for (const p of [/portal01\.corp\.example\.com/, /CentOS Stream 8/, /4 × Xeon/, /1d 1h 0m/, /10\.0\.0\.1 via ens192/, /10\.0\.0\.10/]) {
    assert.match(html, p);
  }
});
