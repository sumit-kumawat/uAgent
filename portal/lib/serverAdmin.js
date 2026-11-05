"use strict";

// Administration of the Linux server the portal runs on. Information any user can read is collected here;
// everything that needs root (firewall, shadow accounts, failed logins, journals, and every change) goes
// through the root-owned helper /usr/local/sbin/uagent-sysadmin via sudo, which validates its arguments
// again and refuses changes that would cut off SSH, the portal or the last local administrator.
// On other platforms (a developer's macOS or Windows machine) the page reports that it does not apply.
const { execFile, spawn } = require("child_process");
const fs = require("fs");
const os = require("os");

const HELPER = process.env.UAGENT_SYSADMIN_HELPER || "/usr/local/sbin/uagent-sysadmin";
const ENV = { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C", LC_ALL: "C" };

class Invalid extends Error {
  constructor(message, field) {
    super(message);
    this.field = field;
  }
}

function exec(file, args, timeoutMs) {
  return new Promise((resolve) => {
    execFile(file, args, { timeout: timeoutMs || 8000, maxBuffer: 8 * 1024 * 1024, env: ENV }, (error, stdout, stderr) => {
      resolve({ ok: !error, code: error ? error.code : 0, stdout: String(stdout || ""), stderr: String(stderr || "") });
    });
  });
}

function readFile(file) {
  try {
    return fs.readFileSync(file, "utf8");
  } catch (error) {
    return "";
  }
}

function osRelease() {
  const values = {};
  for (const line of readFile("/etc/os-release").split("\n")) {
    const match = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (match) {
      values[match[1]] = match[2].replace(/^"|"$/g, "");
    }
  }
  return values;
}

function platform() {
  const linux = process.platform === "linux";
  const release = linux ? osRelease() : {};
  return {
    os: process.platform,
    linux,
    distribution: release.PRETTY_NAME || null,
    distributionId: release.ID || null,
    versionId: release.VERSION_ID || null,
    helperInstalled: linux && fs.existsSync(HELPER),
    helper: HELPER
  };
}

function json(text, fallback) {
  try {
    return JSON.parse(text);
  } catch (error) {
    return fallback;
  }
}

function parseDf(text) {
  return text.split("\n").slice(1).map((line) => line.trim().split(/\s+/)).filter((p) => p.length >= 6).map((p) => ({
    filesystem: p[0], totalBytes: Number(p[1]) || 0, usedBytes: Number(p[2]) || 0, freeBytes: Number(p[3]) || 0, mount: p.slice(5).join(" ")
  }));
}

function parseServices(units, files) {
  const enabled = new Map();
  for (const line of files.split("\n")) {
    const p = line.trim().split(/\s+/);
    if (p.length >= 2 && p[0].endsWith(".service")) {
      enabled.set(p[0], p[1]);
    }
  }
  return units.split("\n").map((line) => line.trim().split(/\s+/)).filter((p) => p.length >= 4 && p[0].endsWith(".service")).map((p) => ({
    name: p[0], load: p[1], active: p[2], sub: p[3], description: p.slice(4).join(" "), enabled: enabled.get(p[0]) || null
  }));
}

function parseListening(text) {
  return text.split("\n").map((line) => line.trim().split(/\s+/)).filter((p) => p.length >= 5).map((p) => {
    const local = p[4];
    const i = local.lastIndexOf(":");
    return { protocol: p[0], state: p[1], address: local.slice(0, i).replace(/^\[|\]$/g, ""), port: Number(local.slice(i + 1)) || null };
  }).filter((l) => l.port);
}

function parseResolv(text) {
  const out = { nameservers: [], search: [] };
  for (const line of text.split("\n")) {
    const p = line.trim().split(/\s+/);
    if (p[0] === "nameserver" && p[1]) { out.nameservers.push(p[1]); }
    if ((p[0] === "search" || p[0] === "domain") && p.length > 1) { out.search.push(...p.slice(1)); }
  }
  return out;
}

async function sessions() {
  const list = await exec("loginctl", ["list-sessions", "--no-legend", "--no-pager"]);
  const ids = list.stdout.split("\n").map((l) => l.trim().split(/\s+/)[0]).filter((id) => /^[A-Za-z0-9]+$/.test(id || "")).slice(0, 50);
  if (ids.length === 0) {
    return [];
  }
  const shown = await exec("loginctl", ["show-session", ...ids, "-p", "Id", "-p", "Name", "-p", "Remote", "-p", "RemoteHost", "-p", "State",
    "-p", "Timestamp", "-p", "IdleHint", "-p", "IdleSinceHint", "-p", "Type", "-p", "TTY", "-p", "Class", "-p", "Service"]);
  return shown.stdout.split(/\n\s*\n/).map((block) => {
    const s = {};
    for (const line of block.split("\n")) {
      const i = line.indexOf("=");
      if (i > 0) { s[line.slice(0, i)] = line.slice(i + 1); }
    }
    return s;
  }).filter((s) => s.Id && s.Class !== "greeter").map((s) => ({
    id: s.Id, user: s.Name, remote: s.Remote === "yes", remoteHost: s.RemoteHost || null, state: s.State, type: s.Type, tty: s.TTY || null,
    service: s.Service || null, startedUtc: s.Timestamp ? isoOrNull(s.Timestamp) : null, idle: s.IdleHint === "yes",
    idleSinceUtc: Number(s.IdleSinceHint) > 0 ? new Date(Number(s.IdleSinceHint) / 1000).toISOString() : null
  }));
}

function isoOrNull(text) {
  const t = Date.parse(text);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

function parseLast(text) {
  const rows = [];
  for (const line of text.split("\n")) {
    const m = /^(\S+)\s+(.*?)\s+(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4})(?:\s+-\s+(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d{4}))?\s*(.*)$/.exec(line);
    if (!m || m[1] === "wtmp" || m[1] === "reboot" || m[1] === "shutdown") {
      continue;
    }
    const middle = m[2].trim().split(/\s+/);
    const iso = (v) => (v ? isoOrNull(v.replace(/([+-]\d\d)(\d\d)$/, "$1:$2")) : null);
    rows.push({ user: m[1], line: middle[0] || "", from: middle.length > 1 ? middle[middle.length - 1] : "", startUtc: iso(m[3]), endUtc: iso(m[4]), state: m[5].trim() || (m[4] ? "ended" : "") });
  }
  return rows;
}

// What any account on the server can read. Runs in parallel; a missing tool leaves its part empty.
async function collectBase() {
  const [fqdn, df, addr, route, units, files, ss, last, nm] = await Promise.all([
    exec("hostname", ["-f"], 4000),
    exec("df", ["-P", "-B1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay"]),
    exec("ip", ["-j", "addr"]),
    exec("ip", ["-j", "route"]),
    exec("systemctl", ["list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager"]),
    exec("systemctl", ["list-unit-files", "--type=service", "--no-legend", "--no-pager"]),
    exec("ss", ["-H", "-tuln"]),
    exec("last", ["-w", "-i", "--time-format", "iso", "-n", "60"]),
    exec("nmcli", ["-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show", "--active"])
  ]);
  const meminfo = {};
  for (const line of readFile("/proc/meminfo").split("\n")) {
    const m = /^(\w+):\s+(\d+)\s+kB/.exec(line);
    if (m) { meminfo[m[1]] = Number(m[2]) * 1024; }
  }
  const cpus = os.cpus();
  const connections = [];
  for (const line of nm.stdout.split("\n")) {
    const parts = line.split(":");
    if (parts.length >= 4 && /^[0-9a-f-]{36}$/i.test(parts[1])) {
      const settings = await exec("nmcli", ["-g", "ipv4.method,ipv4.dns,ipv4.dns-search,ipv4.ignore-auto-dns", "connection", "show", parts[1]]);
      const v = settings.stdout.split("\n");
      connections.push({ name: parts[0], uuid: parts[1], type: parts[2], device: parts[3], method: v[0] || "", dns: (v[1] || "").split(",").filter(Boolean),
        search: (v[2] || "").split(",").filter(Boolean), ignoreAutoDns: v[3] === "yes" });
    }
  }
  const release = osRelease();
  return {
    hostname: os.hostname(),
    fqdn: fqdn.stdout.trim() || null,
    os: { name: release.PRETTY_NAME || os.type(), id: release.ID || null, version: release.VERSION_ID || null, kernel: os.release(), architecture: os.arch() },
    uptimeSeconds: Math.round(os.uptime()),
    bootUtc: new Date(Date.now() - os.uptime() * 1000).toISOString(),
    loadAverage: os.loadavg(),
    cpu: { model: cpus[0] ? cpus[0].model : null, count: cpus.length },
    memory: { totalBytes: meminfo.MemTotal || os.totalmem(), availableBytes: meminfo.MemAvailable || os.freemem(), swapTotalBytes: meminfo.SwapTotal || 0, swapFreeBytes: meminfo.SwapFree || 0 },
    disks: parseDf(df.stdout),
    interfaces: json(addr.stdout, []).map((i) => ({
      name: i.ifname, state: i.operstate, mac: i.address || null, mtu: i.mtu,
      addresses: (i.addr_info || []).map((a) => `${a.local}/${a.prefixlen}`)
    })),
    gateways: json(route.stdout, []).filter((r) => r.dst === "default").map((r) => ({ gateway: r.gateway || null, device: r.dev, metric: r.metric || 0 })),
    dns: parseResolv(readFile("/etc/resolv.conf")),
    connections,
    services: parseServices(units.stdout, files.stdout),
    listening: parseListening(ss.stdout),
    sessions: await sessions(),
    logins: parseLast(last.stdout)
  };
}

// Runs the root helper. A password is written to its standard input and never appears in argv.
function runHelper(args, input, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn("sudo", ["-n", HELPER, ...args], { env: ENV, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs || 120000);
    child.stdout.on("data", (d) => { stdout += d; if (stdout.length > 16 * 1024 * 1024) { child.kill("SIGKILL"); } });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("error", (error) => { clearTimeout(timer); resolve({ ok: false, error: `Could not run the helper: ${error.message}` }); });
    child.on("close", (code) => {
      clearTimeout(timer);
      const lines = stdout.trim().split("\n");
      const parsed = json(lines[lines.length - 1] || "", null);
      if (parsed && typeof parsed === "object") {
        return resolve(parsed);
      }
      const denied = /sudo:|password is required|not allowed|a terminal is required/i.test(stderr);
      resolve({
        ok: false,
        error: denied
          ? `The portal is not permitted to run ${HELPER}. Re-run the installer to add its sudoers rule.`
          : (stderr.trim().split("\n").pop() || `The helper ended with code ${code}.`).slice(0, 500)
      });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input ? `${input}\n` : "");
  });
}

async function collect() {
  const info = platform();
  if (!info.linux) {
    return { platform: info, supported: false };
  }
  const [base, privileged] = await Promise.all([
    collectBase(),
    info.helperInstalled ? runHelper(["info"], null, 90000) : Promise.resolve({ ok: false, error: `${HELPER} is not installed. Re-run the installer to enable firewall, account and log details and server changes.` })
  ]);
  return { platform: info, supported: true, collectedUtc: new Date().toISOString(), ...base, privileged };
}

// --- Actions ---------------------------------------------------------------------------------------

const str = (v) => (v === undefined || v === null ? "" : String(v).trim());
const DNS_NAME = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const DOMAIN = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;
const ZONE = /^[A-Za-z0-9_-]{1,40}$/;
const need = (ok, message, field) => { if (!ok) { throw new Invalid(message, field); } };

const ACTIONS = {
  "firewall-state": {
    label: "Turn the firewall on or off",
    build: (p) => {
      const on = p.enabled === true || p.enabled === "true";
      return { args: ["firewall", on ? "enable" : "disable"], summary: `Turn the server firewall ${on ? "on" : "off"}` };
    }
  },
  "firewall-port": {
    label: "Change an open port",
    build: (p) => {
      const op = str(p.op);
      const zone = str(p.zone);
      const port = str(p.port).toLowerCase().replace(/\s/g, "");
      need(op === "add" || op === "remove", "Choose add or remove.", "op");
      need(ZONE.test(zone), "Choose the zone.", "zone");
      need(/^\d{1,5}(-\d{1,5})?\/(tcp|udp|sctp|dccp)$/.test(port), "The port must look like 8443/tcp or 5000-5100/udp.", "port");
      return { args: ["firewall", "port", op, zone, port], summary: `${op === "add" ? "Open" : "Close"} port ${port} in zone ${zone}`, pending: true };
    }
  },
  "firewall-service": {
    label: "Change an allowed service",
    build: (p) => {
      const op = str(p.op);
      const zone = str(p.zone);
      const service = str(p.service);
      need(op === "add" || op === "remove", "Choose add or remove.", "op");
      need(ZONE.test(zone), "Choose the zone.", "zone");
      need(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,60}$/.test(service), "Choose the service.", "service");
      return { args: ["firewall", "service", op, zone, service], summary: `${op === "add" ? "Allow" : "Stop allowing"} service ${service} in zone ${zone}`, pending: true };
    }
  },
  "firewall-revert": { label: "Revert firewall changes", build: () => ({ args: ["firewall", "revert"], summary: "Revert unsaved firewall changes" }) },
  service: {
    label: "Control a service",
    build: (p) => {
      const name = str(p.name);
      const action = str(p.action);
      need(["start", "stop", "restart"].includes(action), "Choose start, stop or restart.", "action");
      need(/^[A-Za-z0-9][A-Za-z0-9@._:-]{0,120}$/.test(name), "Choose the service.", "name");
      return { args: ["service", action, name], summary: `${action[0].toUpperCase()}${action.slice(1)} ${name}` };
    }
  },
  power: {
    label: "Restart or shut down the server",
    build: (p) => {
      const action = str(p.action);
      need(["reboot", "poweroff", "cancel"].includes(action), "Choose restart, shut down or cancel.", "action");
      return { args: ["power", action], summary: { reboot: "Restart the server in 1 minute", poweroff: "Shut down the server in 1 minute", cancel: "Cancel a scheduled restart or shutdown" }[action] };
    }
  },
  hostname: {
    label: "Change the host name",
    build: (p) => {
      const name = str(p.name).toLowerCase();
      need(DNS_NAME.test(name) && !/^[\d.]+$/.test(name), "Use a host name or FQDN such as portal01.corp.example.com.", "name");
      return { args: ["hostname", "set", name], summary: `Change the host name to ${name}` };
    }
  },
  "hostname-restore": { label: "Restore the host name", build: () => ({ args: ["hostname", "restore"], summary: "Restore the previous host name" }) },
  dns: {
    label: "Change DNS",
    build: (p) => {
      const uuid = str(p.connection);
      const servers = str(p.servers).replace(/\s/g, "");
      need(/^[0-9a-f-]{36}$/i.test(uuid), "Choose the connection.", "connection");
      need(/^(dhcp|[0-9A-Fa-f:.,]{2,200})$/i.test(servers), "Enter DNS server addresses separated by commas, or dhcp.", "servers");
      const args = ["dns", "set", uuid, servers];
      if (p.setSearch === true || p.setSearch === "true") {
        const search = str(p.search).replace(/\s/g, "");
        need(!search || search.split(",").every((s) => DNS_NAME.test(s)), "Search domains must be domain names separated by commas.", "search");
        args.push("--search", search);
      }
      const test = str(p.test);
      if (test) {
        need(DNS_NAME.test(test), "The test name must be a DNS name.", "test");
        args.push("--test", test);
      }
      return { args, summary: `Set DNS on ${str(p.connectionName).slice(0, 80) || uuid} to ${servers}${args.includes("--search") ? `; search ${args[args.indexOf("--search") + 1] || "none"}` : ""}` };
    }
  },
  "dns-restore": {
    label: "Restore DNS",
    build: (p) => {
      const uuid = str(p.connection);
      need(/^[0-9a-f-]{36}$/i.test(uuid), "Choose the connection.", "connection");
      return { args: ["dns", "restore", uuid], summary: `Restore the previous DNS settings of ${str(p.connectionName).slice(0, 80) || uuid}` };
    }
  },
  "domain-discover": {
    label: "Look up a domain",
    readOnly: true,
    build: (p) => {
      const name = str(p.domain).toLowerCase();
      need(DOMAIN.test(name), "Enter the domain's DNS name, for example corp.example.com.", "domain");
      return { args: ["domain", "discover", name], summary: `Look up domain ${name}` };
    }
  },
  "domain-join": {
    label: "Join a domain",
    build: (p, secret) => {
      const name = str(p.domain).toLowerCase();
      const user = str(p.user);
      const ou = str(p.ou);
      need(DOMAIN.test(name), "Enter the domain's DNS name, for example corp.example.com.", "domain");
      need(/^[A-Za-z0-9._@\\-]{1,128}$/.test(user), "Enter the domain account allowed to join computers.", "user");
      need(!ou || (/DC=/i.test(ou) && ou.length <= 512), "The OU must be a distinguished name such as OU=Servers,DC=corp,DC=example,DC=com.", "ou");
      need(typeof secret === "string" && secret.length > 0 && secret.length <= 256 && !/[\r\n]/.test(secret), "Enter the password of the domain account.", "secret");
      return { args: ["domain", "join", name, user, ...(ou ? ["--ou", ou] : [])], input: secret, summary: `Join domain ${name} as ${user}${ou ? ` in ${ou}` : ""}` };
    }
  },
  "domain-leave": { label: "Leave the domain", build: () => ({ args: ["domain", "leave"], summary: "Leave the domain" }) }
};

function prepare(action, parameters, secret) {
  const spec = ACTIONS[action];
  if (!spec) {
    throw new Invalid(`Unknown server action '${action}'.`, "action");
  }
  const built = spec.build(parameters && typeof parameters === "object" ? parameters : {}, secret);
  return { label: spec.label, readOnly: Boolean(spec.readOnly), ...built };
}

const LOG_SOURCES = ["portal", "auth", "system", "firewall", "admin"];

module.exports = { platform, collect, runHelper, prepare, Invalid, ACTIONS, LOG_SOURCES, HELPER, _parse: { parseDf, parseServices, parseListening, parseResolv, parseLast } };
