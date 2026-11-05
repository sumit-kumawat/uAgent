"use strict";

// The System tab script renders every view from a realistic snapshot without leaking "undefined", "NaN" or
// "[object Object]" into the page, hides controls from non-administrators, and queues the right parameters.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const script = fs.readFileSync(path.join(__dirname, "../public/js/system.js"), "utf8");
const page = fs.readFileSync(path.join(__dirname, "../views/agentDetails.ejs"), "utf8");

const now = Date.now();
const ago = (minutes) => new Date(now - minutes * 60000).toISOString();

const snapshot = {
  platform: "Windows", managerHost: "uagent.corp.example.com", collectMs: 4200, errors: ["events: The Security log is not readable."],
  computer: { hostname: "PC-01", pendingHostname: "PC-02", fqdn: "PC-01.corp.example.com", primaryDnsSuffix: "corp.example.com", configuredDnsSuffix: "corp.example.com",
    searchList: ["corp.example.com"], partOfDomain: true, domain: "corp.example.com", workgroup: null, domainRole: "MemberWorkstation", manufacturer: "VMware", model: "VM",
    osCaption: "Microsoft Windows 11 Pro", osVersion: "10.0.22631", osBuild: "22631", edition: "Professional", architecture: "64-bit", installDateUtc: ago(500000),
    lastBootUtc: ago(3000), totalMemoryBytes: 8589934592, freeMemoryBytes: 2147483648, rebootPending: true, timeZone: "India Standard Time" },
  network: [{ index: 4, name: "Ethernet0", description: "vmxnet3", type: "Ethernet", status: "Up", speedMbps: 10000, mac: "00-50-56-AA-BB-CC", dhcp: false,
    addresses: ["10.0.0.5/24"], gateways: ["10.0.0.1"], dnsServers: ["10.0.0.10"], dnsSuffix: "corp.example.com" }],
  connections: { listening: [{ protocol: "TCP", address: "0.0.0.0", port: 3389, pid: 1100, process: "svchost" }],
    established: [{ localAddress: "10.0.0.5", localPort: 50000, remoteAddress: "10.0.0.2", remotePort: 443, pid: 2200, process: "uAgent" }] },
  sessions: [{ id: 2, station: "RDP-Tcp#0", state: "Active", user: "alice", domain: "CORP", client: "LAPTOP", clientAddress: "10.0.0.50", remote: true, logonUtc: ago(90), connectUtc: ago(90), lastInputUtc: ago(2) },
    { id: 3, station: "", state: "Disconnected", user: "bob", domain: "PC-01", client: null, clientAddress: null, remote: false, logonUtc: ago(4000), lastInputUtc: ago(3000) }],
  remoteDesktop: { hostSupported: true, edition: "Professional", enabled: true, policyDenyConnections: null, nla: false, policyNla: null, securityLayer: 1, port: 3389, listening: true,
    services: [{ name: "TermService", displayName: "Remote Desktop Services", status: "Running", startType: "Manual" }] },
  localAdministrators: [{ name: "Administrator", kind: "User", enabled: false }, { name: "bob", kind: "User", enabled: true }, { name: "CORP\\Domain Admins", kind: "Group", enabled: null }],
  firewall: { profiles: [{ name: "Domain", enabled: true, defaultInbound: "Block", defaultOutbound: "Allow", allowLocalRules: "True", logAllowed: "False", logBlocked: "True", policyManaged: false },
    { name: "Public", enabled: false, defaultInbound: "Block", defaultOutbound: "Allow", allowLocalRules: "True", logAllowed: "False", logBlocked: "False", policyManaged: true }],
  networks: [{ interface: "Ethernet0", network: "corp.example.com", category: "DomainAuthenticated" }], ruleCount: 4,
  rules: [{ id: "RemoteDesktop-UserMode-In-TCP", name: "Remote Desktop - User Mode (TCP-In)", group: "Remote Desktop", enabled: true, direction: "Inbound", action: "Allow", profile: "Any", protocol: "TCP", localPort: "3389", remotePort: "Any", remoteAddress: "Any", program: "%SystemRoot%\\system32\\svchost.exe", source: "Local", portalManaged: false, protected: false },
    { id: "{abc}", name: "Web from admins", group: "uAgent portal", enabled: true, direction: "Inbound", action: "Allow", profile: "Domain", protocol: "TCP", localPort: "443", remotePort: "Any", remoteAddress: "10.0.0.0/24", program: "Any", source: "Local", portalManaged: true, protected: false },
    { id: "uAgent-out", name: "uAgent", group: "", enabled: true, direction: "Outbound", action: "Allow", profile: "Any", protocol: "TCP", localPort: "Any", remotePort: "443", remoteAddress: "Any", program: "C:\\Program Files\\uAgent\\uAgent.exe", source: "Local", portalManaged: false, protected: true },
    { id: "{def}", name: "Block SMB", group: "uAgent portal", enabled: true, direction: "Inbound", action: "Block", profile: "Any", protocol: "TCP", localPort: "445", remotePort: "Any", remoteAddress: "Any", program: "Any", source: "Local", portalManaged: true, protected: false }] },
  events: {
    logons: [{ timeUtc: ago(90), user: "alice", domain: "CORP", logonType: 10, workstation: "LAPTOP", source: "10.0.0.50" }, { timeUtc: ago(4000), user: "bob", domain: "PC-01", logonType: 2, workstation: "PC-01", source: "-" }],
    failedLogons: [{ timeUtc: ago(30), user: "alice", domain: "CORP", status: "0xC000006D", subStatus: "0xC000006A", logonType: 10, workstation: "X", source: "203.0.113.9" }],
    accountChanges: [{ timeUtc: ago(600), id: 4732, message: "A member was added to a security-enabled local group." }],
    power: [{ timeUtc: ago(3001), id: 6005, message: "The Event log service was started." }, { timeUtc: ago(3010), id: 6006, message: "The Event log service was stopped." }],
    serviceChanges: [{ timeUtc: ago(700), id: 7040, message: "The start type of the Print Spooler service was changed." }],
    firewallChanges: [{ timeUtc: ago(800), id: 2004, message: "A rule has been added to the Windows Defender Firewall exception list." }],
    problems: [{ timeUtc: ago(20), log: "System", level: "Error", id: 7000, source: "Service Control Manager", message: "The service failed to start." }],
    rdpAuthentications: [{ timeUtc: ago(91), user: "alice", domain: "CORP", source: "10.0.0.50" }],
    rdpSessions: [{ timeUtc: ago(90), id: 21, user: "CORP\\alice", session: "2", source: "10.0.0.50" }],
    rdpFailures: [{ timeUtc: ago(40), source: "203.0.113.9", message: "A connection from the client computer failed." }]
  }
};

const services = [{ name: "Spooler", displayName: "Print Spooler", status: "Running", startType: "Automatic", serviceType: "Win32OwnProcess", canStop: true },
  { name: "mpssvc", displayName: "Windows Defender Firewall", status: "Running", startType: "Automatic", canStop: false },
  { name: "wuauserv", displayName: "Windows Update", status: "Stopped", startType: "Manual", canStop: false }];

const caps = ["LongPoll", "Inventory", "SystemAdmin", "RestartComputer", "CancelRestart", "ServiceControl", "ShutdownComputer", "SetFirewallProfile", "FirewallRule",
  "SetRemoteDesktop", "SetNla", "SetHostname", "SetDns", "JoinDomain", "LeaveDomain"];

function element(id) {
  const listeners = {};
  const attrs = {};
  return {
    id, innerHTML: "", textContent: "", hidden: true, disabled: false, title: "", attrs,
    classList: { add() {}, remove() {}, toggle() {} },
    getAttribute: (name) => attrs[name] || null,
    addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
    fire: (type, event) => (listeners[type] || []).forEach((fn) => fn(event)),
    contains: () => false
  };
}

function harness(role) {
  const ids = ["agentRoot", "pane-system", "sysBody", "sysBanner", "sysCollected", "sysRefresh", "tabSystemItem"];
  const els = Object.fromEntries(ids.map((id) => [id, element(id)]));
  els.agentRoot.attrs["data-agent-key"] = "AG-0001";
  const docListeners = {};
  const actions = [];
  const U = {
    escapeHtml: (v) => (v === null || v === undefined ? "" : String(v).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")),
    text: (v) => (v === null || v === undefined || v === "" ? "\u2014" : String(v)),
    formatDateTime: (v) => (v ? new Date(v).toISOString() : "\u2014"),
    relativeTime: (v) => (v ? "5 min ago" : "Never"),
    formatUptime: (v) => (v ? "2d 1h 0m" : "\u2014"),
    formatBytes: (v) => (Number(v) > 0 ? Math.round(Number(v) / 1048576) + " MB" : "\u2014"),
    pill: (tone, label) => `<span class="pill pill-${tone}">${label}</span>`,
    statusPill: (s) => `<span class="pill">${s}</span>`,
    isTerminal: (s) => ["Success", "Failed", "TimedOut"].includes(s),
    notify: () => {},
    onChange: () => () => {},
    runAction: (opts) => actions.push(opts),
    me: { catalog: caps.map((type) => ({ type, label: type, category: ["RestartComputer", "CancelRestart"].includes(type) ? "system" : "admin", minRole: role === "Administrator" ? "Administrator" : "Administrator", allowed: role === "Administrator", sensitive: true, reauth: true })) },
    api: async (url) => {
      if (url.endsWith("/inventory/admin")) { return { data: snapshot, error: null, collectedUtc: ago(5) }; }
      if (url.endsWith("/inventory/services")) { return { data: services, collectedUtc: ago(5) }; }
      if (url.endsWith("/inventory/system")) { return { data: { logicalProcessors: 4, cpuPercent: 12, architecture: "X64", disks: [{ name: "C:\\", label: "", format: "NTFS", totalBytes: 100e9, freeBytes: 5e9 }] } }; }
      return {};
    }
  };
  const context = {
    window: { uAgent: U },
    document: {
      getElementById: (id) => els[id] || null,
      querySelectorAll: () => [],
      addEventListener: (type, fn) => { docListeners[type] = fn; },
      activeElement: null,
      body: { insertAdjacentHTML() {}, appendChild() {} }
    },
    setTimeout, clearTimeout, console, Date, JSON, Math, Number, String, Array, Object, Set, Promise
  };
  vm.runInNewContext(script, context);
  const state = {
    agent: { agentId: "a1", machineName: "PC-01", status: "Active", online: true, features: ["Inventory", "SystemAdmin"], capabilities: caps, uptime: "2.01:00:00", serviceMode: "WindowsService" },
    accounts: [{ samAccountName: "alice", source: "Domain", enabled: true, lockedOut: false, lastLogon: ago(90) },
      { samAccountName: "bob", source: "Local", enabled: true, lastLogon: ago(200 * 24 * 60) },
      { samAccountName: "Guest", source: "Local", enabled: false, lastLogon: null },
      { samAccountName: "carol", source: "Domain", enabled: true, lastLogon: null },
      { samAccountName: "dave", source: "Local", enabled: true, lastLogon: ago(200 * 24 * 60) }],
    commands: [{ commandId: "c1", commandType: "SetNla", category: "admin", label: "Configure NLA", summary: "Require NLA", status: "Success", createdUtc: ago(10), enqueuedBy: "admin", reason: "Harden", result: "Done" }]
  };
  return { els, docListeners, actions, state, U };
}

async function show(h, view) {
  h.els["pane-system"].fire("click", { target: { closest: (sel) => (sel === "[data-sys-view]" ? { getAttribute: () => view } : null) } });
  return h.els.sysBody.innerHTML;
}

function click(h, attrs) {
  const btn = { disabled: false, getAttribute: (n) => (n in attrs ? attrs[n] : null) };
  h.els["pane-system"].fire("click", { target: { closest: (sel) => (sel === "[data-sys-act]" ? btn : null) } });
}

test("every element the System tab script uses is on the agent page", () => {
  for (const id of ["tabSystemItem", "pane-system", "sysBody", "sysBanner", "sysCollected", "sysRefresh"]) {
    assert.match(page, new RegExp(`id="${id}"`), id);
  }
  for (const view of ["identity", "activity", "rdp", "firewall", "services", "events"]) {
    assert.match(page, new RegExp(`data-sys-view="${view}"`), view);
    assert.match(script, new RegExp(`${view}: ${view}View`), `${view} has a renderer`);
  }
});

test("every element the server page script uses is on the page", () => {
  const serverScript = fs.readFileSync(path.join(__dirname, "../public/js/server.js"), "utf8");
  const serverPage = fs.readFileSync(path.join(__dirname, "../views/server.ejs"), "utf8");
  const ids = new Set([...serverScript.matchAll(/\$\("(srv[A-Za-z]+)"\)/g)].map((m) => m[1]));
  assert.ok(ids.size >= 8);
  for (const id of ids) {
    if (id === "srvServiceSearch" || id === "srvServiceState") { continue; }
    assert.match(serverPage, new RegExp(`id="${id}"`), id);
  }
});

test("all views render from a realistic snapshot", async () => {
  const h = harness("Administrator");
  h.docListeners["ua:agent-loaded"]({ detail: { state: h.state, role: "Administrator" } });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(h.els.tabSystemItem.hidden, false, "the tab is shown");
  assert.match(h.els.sysBanner.innerHTML, /Security log is not readable/, "collection errors are shown");
  const expect = {
    identity: [/PC-01\.corp\.example\.com/, /Changes to PC-02 after restart/, /Ethernet0/, /10\.0\.0\.10/, /data-sys-act="dns" data-index="4"/, /Leave domain/, /95%/],
    activity: [/Active session/, /Disconnected session/, /Never signed in/, /Unused/, /Wrong password/, /Remote Desktop/, /Administrator<\/span>/],
    rdp: [/Reachable from portal/, /Not tested/, /Stop requiring NLA|Require NLA/, /Remote Desktop - User Mode/, /A connection from the client computer failed/],
    firewall: [/Group Policy/, /Turn on/, /Web from admins/, /data-sys-act="rule-edit"/, /Required/],
    services: [/Print Spooler/, /Protected/, /data-op="restart"/, /Started \(event log service started\)/],
    events: [/Require NLA/, /security-enabled local group/, /The service failed to start/]
  };
  for (const [view, patterns] of Object.entries(expect)) {
    const html = await show(h, view);
    for (const p of patterns) { assert.match(html, p, `${view}: ${p}`); }
    assert.doesNotMatch(html, /undefined|NaN|\[object Object\]/, `${view} leaks a bad value`);
  }
  const activity = await show(h, "activity");
  const carol = activity.split("carol")[1].split("</tr>")[0];
  assert.match(carol, /Unknown/, "a domain account without logon data is unknown, not unused");
  assert.doesNotMatch(carol, /Never signed in|Unused/);
  assert.match(activity, /Unused accounts<\/div><div class="value">1</, "only dave counts as unused (bob has a session, Guest is disabled, carol is unknown)");
  assert.match(activity.split("dave")[1].split("</tr>")[0], /pill-warning">Unused/);
  const firewall = await show(h, "firewall");
  const ports = firewall.split("Inbound ports")[1].split("sys-section")[0];
  assert.match(ports, /TCP 443<\/td><td><span class="pill pill-success">Allowed/);
  assert.match(ports, /TCP 445<\/td><td><span class="pill pill-danger">Blocked/);
  assert.match(ports, /Domain: Block/, "the profile default is stated for unlisted ports");
  assert.doesNotMatch(firewall.split("uAgent.exe")[1] || "", /data-sys-act="rule-toggle" data-id="uAgent-out"/, "the agent's own rule cannot be disabled");
});

test("controls queue the right parameters, and non-administrators get none", async () => {
  const h = harness("Administrator");
  h.docListeners["ua:agent-loaded"]({ detail: { state: h.state, role: "Administrator" } });
  await new Promise((r) => setTimeout(r, 20));
  click(h, { "data-sys-act": "rdp", "data-value": "false" });
  click(h, { "data-sys-act": "svc", "data-name": "Spooler", "data-op": "stop" });
  click(h, { "data-sys-act": "rule-toggle", "data-id": "{abc}", "data-value": "false" });
  click(h, { "data-sys-act": "profile", "data-profile": "Public", "data-value": "true" });
  assert.deepEqual(h.actions.map((a) => [a.control.type, JSON.parse(JSON.stringify(a.control.parameters))]), [
    ["SetRemoteDesktop", { enabled: false }],
    ["ServiceControl", { name: "Spooler", action: "stop" }],
    ["FirewallRule", { op: "disable", id: "{abc}", label: "Web from admins" }],
    ["SetFirewallProfile", { profile: "Public", enabled: true }]
  ]);
  assert.ok(h.actions.every((a) => a.control.sensitive && a.control.reauth), "every change is confirmed with the password");
  assert.match(h.actions[0].control.description, /1 active remote session/, "disabling RDP warns about active sessions");
  const adminHtml = await show(h, "firewall");
  assert.ok([...adminHtml.matchAll(/<button type="button" class="btn[^"]*"(?! disabled)[^>]*data-sys-act="(?!probe)[^"]+"/g)].length > 3, "an administrator gets enabled controls");

  const m = harness("Monitor");
  m.docListeners["ua:agent-loaded"]({ detail: { state: m.state, role: "Monitor" } });
  await new Promise((r) => setTimeout(r, 20));
  for (const view of ["identity", "rdp", "firewall", "services"]) {
    const html = await show(m, view);
    const enabled = [...html.matchAll(/<button type="button" class="btn[^"]*"(?! disabled)[^>]*data-sys-act="(?!probe)[^"]+"/g)];
    assert.equal(enabled.length, 0, `${view}: a monitor sees no enabled change buttons`);
  }
});
