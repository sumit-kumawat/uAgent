"use strict";

// Validates a list of target systems in the background: format and duplicates, matching to enrolled
// agents, DNS resolution, network reachability and operating-system compatibility. Large lists are
// checked with bounded concurrency and report progress over the live event stream, so validating tens
// of thousands of systems never blocks a request. Results are kept in memory for review.
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");
const { fromText, fromFile } = require("./targetList");

const CONCURRENCY = 64;
const DNS_TIMEOUT_MS = 3000;
const PROBE_TIMEOUT_MS = 1500;
// SMB, RPC endpoint mapper, WinRM and RDP: a Windows host normally answers on at least one. A refused
// connection still proves the host is up.
const PROBE_PORTS = [445, 135, 5985, 3389];
const RETENTION_MS = 4 * 60 * 60 * 1000;
const VIEWS = new Set(["all", "valid", "issues", "managed", "unmanaged", "eligible", "unreachable"]);

class ValidationError extends Error {
  constructor(message, status, code) {
    super(message);
    this.status = status || 400;
    this.code = code || "invalid";
  }
}

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("timeout")), ms);
    })
  ]);
}

function probePort(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    let settled = false;
    const done = (up) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolve(up);
      }
    };
    socket.setTimeout(PROBE_TIMEOUT_MS, () => done(false));
    socket.once("connect", () => done(true));
    socket.once("error", (error) => done(error.code === "ECONNREFUSED"));
  });
}

async function probe(host) {
  const results = await Promise.all(PROBE_PORTS.map((port) => probePort(host, port)));
  return results.some(Boolean);
}

// The agent is a 64-bit .NET 8 service: Windows 10 / Server 2016 or later.
function osCompatibility(os) {
  const text = String(os || "").trim();
  if (!text) {
    return { compatible: null, note: "Operating system not known; the installer checks it." };
  }
  if (!/windows/i.test(text)) {
    return { compatible: false, note: `${text} is not Windows.` };
  }
  if (/windows\s*(xp|vista|7|8(\.1)?)\b|server\s*(2003|2008|2012)/i.test(text)) {
    return { compatible: false, note: `${text} is older than Windows 10 / Server 2016.` };
  }
  if (/\b(x86|32-bit)\b/i.test(text)) {
    return { compatible: false, note: "32-bit Windows is not supported." };
  }
  return { compatible: true, note: "" };
}

function createTargetValidation({ store, targets, agentDeployment, logger }) {
  const validations = new Map();

  function agentIndex() {
    const byName = new Map();
    const byFqdn = new Map();
    const byIp = new Map();
    for (const agent of store.agents.values()) {
      if (agent.machineName) {
        byName.set(agent.machineName.toLowerCase(), agent);
      }
      if (agent.dnsName) {
        byFqdn.set(agent.dnsName.toLowerCase(), agent);
      }
      for (const ip of agent.ipAddresses || []) {
        byIp.set(String(ip).replace(/^::ffff:/, "").toLowerCase(), agent);
      }
    }
    return { byName, byFqdn, byIp };
  }

  function matchAgent(entry, index) {
    return (entry.fqdn && index.byFqdn.get(entry.fqdn))
      || (entry.hostname && index.byName.get(entry.hostname))
      || (entry.ip && index.byIp.get(entry.ip))
      || null;
  }

  function agentSummary(agent) {
    return {
      agentId: agent.agentId,
      displayId: store.getDisplayId(agent.agentId),
      machineName: agent.machineName || "",
      version: agent.agentVersion || "",
      connection: store.isOnline(agent.agentId) ? "online" : "offline",
      os: agent.osVersion || "",
      canInstallSoftware: targets.capable(agent)
    };
  }

  function emit(v) {
    store._emit("validation", { validationId: v.id });
  }

  async function checkEntry(v, entry) {
    if (entry.agent || entry.type === "invalid" || entry.duplicateOf) {
      return;
    }
    let address = entry.ip;
    if (!address && v.options.checkDns) {
      try {
        const found = await withTimeout(dns.lookup(entry.fqdn || entry.hostname, { all: true }), DNS_TIMEOUT_MS);
        entry.addresses = found.map((a) => a.address).slice(0, 8);
        entry.dns = entry.addresses.length ? "Resolved" : "Unresolved";
        address = entry.addresses[0] || "";
      } catch {
        entry.dns = "Unresolved";
      }
      if (entry.dns === "Unresolved") {
        entry.issues.push("DNS did not resolve the name.");
      }
    }
    if (v.options.checkReachability) {
      const host = address || (!v.options.checkDns ? entry.fqdn || entry.hostname : "");
      if (!host) {
        entry.reachability = "Unreachable";
      } else {
        entry.reachability = (await probe(host)) ? "Reachable" : "Unreachable";
      }
      if (entry.reachability === "Unreachable" && entry.dns !== "Unresolved") {
        entry.issues.push("The system did not answer on SMB, RPC, WinRM or RDP from the portal.");
      }
    }
  }

  function decide(v, entry) {
    const valid = entry.type !== "invalid" && !entry.duplicateOf;
    const os = entry.agent ? entry.agent.os : entry.os;
    const compat = osCompatibility(os);
    entry.compatible = compat.compatible;
    entry.compatibility = compat.note;
    if (!valid) {
      entry.eligible = false;
      entry.reason = entry.issues[0] || "Invalid entry.";
      return;
    }
    if (v.kind === "software") {
      if (!entry.agent) {
        entry.eligible = false;
        entry.reason = "No agent is installed. Install the agent first.";
      } else if (!entry.agent.canInstallSoftware) {
        entry.eligible = false;
        entry.reason = "The agent version does not support software installation. Upgrade the agent.";
      } else if (entry.compatible === false) {
        entry.eligible = false;
        entry.reason = entry.compatibility;
      } else {
        entry.eligible = true;
        entry.reason = entry.agent.connection === "online" ? "" : "Offline; installs when it reconnects.";
      }
      return;
    }
    if (entry.compatible === false) {
      entry.eligible = false;
      entry.reason = entry.compatibility;
    } else if (entry.agent) {
      entry.eligible = true;
      entry.reason = `Agent ${entry.agent.displayId} (${entry.agent.version || "unknown version"}) is installed; upgrade or repair over the agent channel.`;
    } else if (entry.dns === "Unresolved" || entry.reachability === "Unreachable") {
      entry.eligible = false;
      entry.reason = entry.issues[entry.issues.length - 1] || "The system could not be reached.";
    } else {
      entry.eligible = true;
      entry.reason = "No agent yet; install with the enterprise deployment kit.";
    }
  }

  function summarize(v) {
    const s = { total: v.entries.length, valid: 0, invalid: 0, duplicates: 0, managed: 0, unmanaged: 0, resolved: 0, unresolved: 0, reachable: 0, unreachable: 0, incompatible: 0, eligible: 0, issues: 0 };
    for (const e of v.entries) {
      if (e.type === "invalid") { s.invalid += 1; }
      else if (e.duplicateOf) { s.duplicates += 1; }
      else { s.valid += 1; }
      if (e.agent) { s.managed += 1; } else if (e.type !== "invalid" && !e.duplicateOf) { s.unmanaged += 1; }
      if (e.dns === "Resolved") { s.resolved += 1; }
      if (e.dns === "Unresolved") { s.unresolved += 1; }
      if (e.reachability === "Reachable" || e.reachability === "ViaAgent") { s.reachable += 1; }
      if (e.reachability === "Unreachable") { s.unreachable += 1; }
      if (e.compatible === false) { s.incompatible += 1; }
      if (e.eligible) { s.eligible += 1; }
      if (e.issues.length > 0 || e.compatible === false) { s.issues += 1; }
    }
    return s;
  }

  async function run(v) {
    const index = agentIndex();
    for (const entry of v.entries) {
      const agent = entry.type === "invalid" || entry.duplicateOf ? null : matchAgent(entry, index);
      entry.agent = agent ? agentSummary(agent) : null;
      entry.addresses = entry.ip ? [entry.ip] : [];
      entry.dns = entry.agent || entry.ip ? "NotApplicable" : "NotChecked";
      entry.reachability = entry.agent ? "ViaAgent" : "NotChecked";
    }
    const pending = v.entries.filter((e) => !e.agent && e.type !== "invalid" && !e.duplicateOf && (v.options.checkDns || v.options.checkReachability));
    v.checked = v.entries.length - pending.length;
    emit(v);
    let cursor = 0;
    let lastEmit = Date.now();
    async function worker() {
      while (cursor < pending.length) {
        const entry = pending[cursor++];
        try {
          await checkEntry(v, entry);
        } catch (error) {
          entry.issues.push(`The check failed: ${error.message}`);
        }
        v.checked += 1;
        if (Date.now() - lastEmit > 500) {
          lastEmit = Date.now();
          emit(v);
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, pending.length) }, worker));
    v.entries.forEach((entry) => decide(v, entry));
    v.summary = summarize(v);
    v.status = "Completed";
    v.completedUtc = new Date().toISOString();
    emit(v);
    logger(`Target validation ${v.id}: ${v.summary.total} system(s), ${v.summary.eligible} eligible, ${v.summary.invalid + v.summary.duplicates} invalid or duplicate, ${v.summary.unreachable} unreachable.`);
  }

  function sweep() {
    const now = Date.now();
    for (const [id, v] of validations) {
      if (v.completedUtc && now - Date.parse(v.completedUtc) > RETENTION_MS) {
        validations.delete(id);
      }
    }
  }

  function view(v) {
    return {
      id: v.id,
      kind: v.kind,
      status: v.status,
      total: v.entries.length,
      checked: v.checked,
      createdBy: v.createdBy,
      createdUtc: v.createdUtc,
      completedUtc: v.completedUtc,
      options: v.options,
      summary: v.summary || summarize(v)
    };
  }

  function start(input, user) {
    sweep();
    const kind = input.kind === "agent" ? "agent" : "software";
    let entries;
    if (input.contentBase64) {
      const buffer = Buffer.from(String(input.contentBase64), "base64");
      if (buffer.length > 10 * 1024 * 1024) {
        throw new ValidationError("The file is larger than the 10 MB limit.", 413, "too_large");
      }
      entries = fromFile(buffer, input.fileName);
    } else {
      entries = fromText(input.text);
    }
    const v = {
      id: crypto.randomUUID(),
      kind,
      status: "Running",
      entries,
      checked: 0,
      createdBy: user.name,
      createdUtc: new Date().toISOString(),
      completedUtc: null,
      options: { checkDns: input.checkDns !== false, checkReachability: input.checkReachability !== false },
      summary: null
    };
    validations.set(v.id, v);
    run(v).catch((error) => {
      v.status = "Completed";
      v.completedUtc = new Date().toISOString();
      v.entries.forEach((entry) => decide(v, entry));
      v.summary = summarize(v);
      logger(`Target validation ${v.id} stopped early: ${error.message}`);
      emit(v);
    });
    return view(v);
  }

  function find(id, requireComplete) {
    const v = validations.get(id);
    if (!v) {
      throw new ValidationError("The validation was not found or has expired. Validate the list again.", 404, "not_found");
    }
    if (requireComplete && v.status !== "Completed") {
      throw new ValidationError("The validation is still running.", 409, "running");
    }
    return v;
  }

  function entryView(e) {
    return {
      row: e.row,
      input: e.input,
      type: e.type,
      hostname: e.hostname,
      fqdn: e.fqdn,
      ip: e.ip,
      site: e.site,
      group: e.group,
      os: e.os,
      issues: e.issues.concat(e.warnings || []),
      duplicateOf: e.duplicateOf,
      dns: e.dns || "NotChecked",
      addresses: e.addresses || [],
      reachability: e.reachability || "NotChecked",
      agent: e.agent || null,
      compatible: e.compatible === undefined ? null : e.compatible,
      compatibility: e.compatibility || "",
      eligible: Boolean(e.eligible),
      reason: e.reason || ""
    };
  }

  function queryEntries(id, query) {
    const v = find(id, false);
    const which = VIEWS.has(query.view) ? query.view : "all";
    const q = String(query.q || "").trim().toLowerCase();
    const page = Math.max(Number.parseInt(query.page, 10) || 1, 1);
    const pageSize = Math.min(Math.max(Number.parseInt(query.pageSize, 10) || 100, 1), 1000);
    const filters = {
      valid: (e) => e.type !== "invalid" && !e.duplicateOf,
      issues: (e) => e.issues.length > 0 || e.compatible === false,
      managed: (e) => Boolean(e.agent),
      unmanaged: (e) => !e.agent && e.type !== "invalid" && !e.duplicateOf,
      eligible: (e) => e.eligible,
      unreachable: (e) => e.reachability === "Unreachable" || e.dns === "Unresolved"
    };
    let rows = filters[which] ? v.entries.filter(filters[which]) : v.entries;
    if (q) {
      rows = rows.filter((e) => `${e.input} ${e.site} ${e.group} ${e.os} ${e.agent ? e.agent.displayId : ""}`.toLowerCase().includes(q));
    }
    return { total: rows.length, page, pageSize, rows: rows.slice((page - 1) * pageSize, page * pageSize).map(entryView) };
  }

  // Eligible enrolled agents, used by software deployments that target a validated list.
  function agentIds(id) {
    const v = find(id, true);
    return [...new Set(v.entries.filter((e) => e.eligible && e.agent).map((e) => e.agent.agentId))];
  }

  function toGroup(id, input, user) {
    const ids = agentIds(id);
    if (ids.length === 0) {
      throw new ValidationError("No eligible systems with an agent are in this list.", 400, "no_targets");
    }
    return targets.createGroup({ name: input.name, description: input.description, category: input.category, type: "static", agentIds: ids }, user);
  }

  function toImport(id, input, user) {
    const v = find(id, true);
    const rows = v.entries.filter((e) => e.type !== "invalid" && !e.duplicateOf && e.compatible !== false);
    if (rows.length === 0) {
      throw new ValidationError("No valid systems are in this list.", 400, "no_targets");
    }
    return agentDeployment.createFromEntries({
      name: input.name || `Target list ${new Date().toISOString().slice(0, 10)}`,
      source: "Validated target list",
      entries: rows.map((e) => ({
        hostname: e.hostname || (e.agent ? e.agent.machineName : ""),
        fqdn: e.fqdn,
        ip: e.ip || (e.addresses && e.addresses[0]) || "",
        site: e.site,
        group: e.group,
        os: e.os || (e.agent ? e.agent.os : ""),
        dns: e.dns === "Resolved" ? "Resolved" : e.dns === "Unresolved" ? "Unresolved" : "NotChecked"
      }))
    }, user);
  }

  const timer = setInterval(sweep, 15 * 60 * 1000);
  timer.unref();

  return { ValidationError, start, get: (id) => view(find(id, false)), queryEntries, agentIds, toGroup, toImport };
}

module.exports = { createTargetValidation, osCompatibility };
