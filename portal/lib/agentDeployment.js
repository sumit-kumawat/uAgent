"use strict";

// Centralised agent installation and upgrade. Administrators import a list of systems from CSV or Excel,
// the portal validates and de-duplicates it, matches rows to agents that have already enrolled, and plans
// each row as a fresh install, an upgrade, a repair, or no action. Upgrades and repairs run through the
// deployment engine over the authenticated agent channel; fresh installs are handled by an enterprise
// deployment kit the administrator downloads and runs through Intune, Group Policy or Configuration Manager.
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");
const { writeJson, readJson } = require("./statePath");
const { readTable } = require("./tabular");
const { fromText } = require("./targetList");
const { build } = require("./zipFile");

const MAX_RECORDS = 100000;
const PLAN_VALUES = new Set(["install", "upgrade", "repair", "none", "exclude"]);

class ImportError extends Error {
  constructor(message, status, code, field) {
    super(message);
    this.status = status || 400;
    this.code = code || "invalid";
    this.field = field;
  }
}

function hostKey(value) {
  return String(value || "").trim().toLowerCase().split(".")[0];
}

function createAgentDeployment({ store, installer, engine, targets, logger, stateFileName }) {
  const saved = readJson(stateFileName);
  const imports = new Map(saved && Array.isArray(saved.imports) ? saved.imports.map((i) => [i.id, i]) : []);

  function persist() {
    writeJson(stateFileName, { imports: [...imports.values()] });
  }

  function agentIndex() {
    const byName = new Map();
    const byFqdn = new Map();
    const byIp = new Map();
    for (const agent of store.agents.values()) {
      const summary = { agentId: agent.agentId, displayId: store.getDisplayId(agent.agentId), version: agent.agentVersion || "", connection: store.isOnline(agent.agentId) ? "online" : "offline" };
      if (agent.machineName) {
        byName.set(hostKey(agent.machineName), summary);
      }
      if (agent.dnsName) {
        byFqdn.set(agent.dnsName.toLowerCase(), summary);
      }
      for (const ip of agent.ipAddresses || []) {
        const plain = String(ip).replace(/^::ffff:/, "").toLowerCase();
        if (net.isIP(plain) !== 0) {
          byIp.set(plain, summary);
        }
      }
    }
    return { byName, byFqdn, byIp };
  }

  function normalizeRecord(raw) {
    const hostname = raw.hostname || raw.host || raw.computername || raw.name || "";
    const fqdn = raw.fqdn || raw.dnsname || raw.dns || "";
    const ip = raw.ip || raw.ipaddress || raw.address || "";
    return {
      hostname: hostname.slice(0, 200),
      fqdn: fqdn.slice(0, 253),
      ip: ip.slice(0, 45),
      site: (raw.site || raw.lab || raw.location || "").slice(0, 100),
      os: (raw.os || raw.operatingsystem || "").slice(0, 100),
      group: (raw.group || raw.deploymentgroup || "").slice(0, 100),
      requestedStatus: (raw.status || raw.installationstatus || "").slice(0, 60),
      row: raw.__row
    };
  }

  function matchAgent(record, index) {
    if (record.fqdn && index.byFqdn.has(record.fqdn.toLowerCase())) {
      return index.byFqdn.get(record.fqdn.toLowerCase());
    }
    if (record.hostname && index.byName.has(hostKey(record.hostname))) {
      return index.byName.get(hostKey(record.hostname));
    }
    if (record.fqdn && index.byName.has(hostKey(record.fqdn))) {
      return index.byName.get(hostKey(record.fqdn));
    }
    if (record.ip && index.byIp.has(record.ip)) {
      return index.byIp.get(record.ip);
    }
    return null;
  }

  function planFor(agent, targetVersion) {
    if (!agent) {
      return { plan: "install", state: "Review" };
    }
    const current = agent.version;
    if (targetVersion && current && compareVersions(current, targetVersion) >= 0) {
      return { plan: "none", state: "UpToDate" };
    }
    return { plan: "upgrade", state: "Review" };
  }

  function compareVersions(a, b) {
    const pa = String(a).split(".").map((n) => Number.parseInt(n, 10) || 0);
    const pb = String(b).split(".").map((n) => Number.parseInt(n, 10) || 0);
    for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
      if ((pa[i] || 0) !== (pb[i] || 0)) {
        return (pa[i] || 0) - (pb[i] || 0);
      }
    }
    return 0;
  }

  // Free text: one system per line or separated by commas, semicolons or spaces.
  function rowsFromText(text) {
    let entries;
    try {
      entries = fromText(text);
    } catch (error) {
      throw new ImportError(error.message, error.status, error.code, "text");
    }
    return entries.map((e) => ({ hostname: e.hostname, fqdn: e.fqdn, ip: e.ip, __row: e.row }));
  }

  function rowsFromFile(fileName, contentBase64) {
    const buffer = Buffer.from(String(contentBase64 || ""), "base64");
    if (buffer.length === 0) {
      throw new ImportError("The file is empty.", 400, "invalid", "file");
    }
    if (buffer.length > 10 * 1024 * 1024) {
      throw new ImportError("The file is larger than the 10 MB limit.", 413, "too_large", "file");
    }
    let table;
    try {
      table = readTable(buffer, fileName || "import.csv");
    } catch (error) {
      throw new ImportError(`The file could not be read: ${error.message}`, 400, "invalid", "file");
    }
    if (table.records.length === 0) {
      throw new ImportError("No rows were found. The first row must be a header with a hostname, FQDN or IP column.", 400, "no_rows");
    }
    return table.records;
  }

  async function create({ name, fileName, contentBase64, text, checkDns }, user) {
    const fromPaste = !contentBase64 && typeof text === "string";
    const rows = fromPaste ? rowsFromText(text) : rowsFromFile(fileName, contentBase64);
    return build({ name, fileName: fromPaste ? "Pasted list" : fileName, rows, checkDns }, user);
  }

  // Imports a list already validated on the Targets page; DNS results are carried over.
  function createFromEntries({ name, source, entries }, user) {
    const rows = entries.map((e, i) => ({ hostname: e.hostname, fqdn: e.fqdn, ip: e.ip, site: e.site, group: e.group, os: e.os, __row: i + 1, __dns: e.dns }));
    return build({ name, fileName: source, rows, checkDns: false }, user);
  }

  async function build({ name, fileName, rows, checkDns }, user) {
    if (rows.length > MAX_RECORDS) {
      throw new ImportError(`The list has more than ${MAX_RECORDS} systems.`, 413, "too_large");
    }
    const manifest = installer.manifest();
    const targetVersion = manifest ? manifest.version : "";
    const index = agentIndex();
    const seen = new Map();
    const records = [];
    for (const raw of rows) {
      const record = normalizeRecord(raw);
      const issues = [];
      if (!record.hostname && !record.fqdn && !record.ip) {
        issues.push("No hostname, FQDN or IP address.");
      }
      if (record.ip && net.isIP(record.ip) === 0) {
        issues.push("The IP address is not valid.");
      }
      const key = (record.fqdn || record.hostname || record.ip).toLowerCase();
      let duplicateOf = null;
      if (key) {
        if (seen.has(key)) {
          duplicateOf = seen.get(key);
          issues.push("Duplicate of an earlier row.");
        } else {
          seen.set(key, record.row);
        }
      }
      const agent = issues.length ? null : matchAgent(record, index);
      const planned = duplicateOf ? { plan: "exclude", state: "Excluded" } : issues.length ? { plan: "exclude", state: "Review" } : planFor(agent, targetVersion);
      records.push({
        ...record,
        issues,
        duplicateOf,
        dns: raw.__dns || "NotChecked",
        agent,
        plan: planned.plan,
        state: planned.state,
        message: ""
      });
    }

    if (checkDns) {
      await resolveDns(records);
    }

    const record = {
      id: crypto.randomUUID(),
      name: String(name || fileName || "Import").trim().slice(0, 120),
      fileName: String(fileName || "import.csv").slice(0, 200),
      createdBy: user.name,
      createdUtc: new Date().toISOString(),
      status: "Review",
      approvedBy: "",
      approvedUtc: null,
      targetVersion,
      jobId: null,
      records
    };
    imports.set(record.id, record);
    persist();
    store.addAudit({ user: user.name, action: "AgentImportCreated", result: "Success", details: `Imported ${records.length} system(s) from ${record.fileName}.` });
    logger(`${user.name} imported ${records.length} system(s) for agent deployment (${record.id}).`);
    return summary(record);
  }

  async function resolveDns(records) {
    const limit = 50;
    let cursor = 0;
    async function worker() {
      while (cursor < records.length) {
        const record = records[cursor++];
        const host = record.fqdn || record.hostname;
        if (!host || record.issues.length) {
          continue;
        }
        try {
          await dns.lookup(host);
          record.dns = "Resolved";
        } catch {
          record.dns = "Unresolved";
          record.issues.push("DNS did not resolve the host name.");
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(limit, records.length) }, worker));
  }

  function find(id) {
    const record = imports.get(id);
    if (!record) {
      throw new ImportError("The import was not found.", 404, "not_found");
    }
    return record;
  }

  function counts(record) {
    const c = { total: record.records.length, valid: 0, invalid: 0, duplicates: 0, unresolved: 0, install: 0, upgrade: 0, repair: 0, current: 0, excluded: 0, registered: 0, verified: 0, failed: 0 };
    for (const r of record.records) {
      if (r.issues.length) { c.invalid += 1; } else { c.valid += 1; }
      if (r.duplicateOf) { c.duplicates += 1; }
      if (r.dns === "Unresolved") { c.unresolved += 1; }
      if (r.plan === "install") { c.install += 1; }
      else if (r.plan === "upgrade") { c.upgrade += 1; }
      else if (r.plan === "repair") { c.repair += 1; }
      else if (r.plan === "exclude") { c.excluded += 1; }
      if (r.state === "UpToDate") { c.current += 1; }
      if (r.state === "Registered" || r.state === "Verified") { c.registered += 1; }
      if (r.state === "Verified") { c.verified += 1; }
      if (r.state === "Failed") { c.failed += 1; }
    }
    return c;
  }

  function summary(record) {
    return {
      id: record.id,
      name: record.name,
      fileName: record.fileName,
      createdBy: record.createdBy,
      createdUtc: record.createdUtc,
      status: record.status,
      approvedBy: record.approvedBy,
      approvedUtc: record.approvedUtc,
      targetVersion: record.targetVersion,
      jobId: record.jobId,
      counts: counts(record)
    };
  }

  function recordView(r) {
    return {
      row: r.row,
      hostname: r.hostname,
      fqdn: r.fqdn,
      ip: r.ip,
      site: r.site,
      os: r.os,
      group: r.group,
      requestedStatus: r.requestedStatus,
      issues: r.issues,
      duplicateOf: r.duplicateOf,
      dns: r.dns,
      agent: r.agent,
      plan: r.plan,
      state: r.state,
      message: r.message
    };
  }

  function queryRecords(id, query) {
    const record = find(id);
    const view = String(query.view || "all");
    const q = String(query.q || "").trim().toLowerCase();
    const page = Math.max(Number.parseInt(query.page, 10) || 1, 1);
    const pageSize = Math.min(Math.max(Number.parseInt(query.pageSize, 10) || 100, 1), 1000);
    let rows = record.records;
    const filters = {
      issues: (r) => r.issues.length > 0,
      install: (r) => r.plan === "install",
      upgrade: (r) => r.plan === "upgrade",
      repair: (r) => r.plan === "repair",
      current: (r) => r.state === "UpToDate",
      excluded: (r) => r.plan === "exclude"
    };
    if (filters[view]) {
      rows = rows.filter(filters[view]);
    }
    if (q) {
      rows = rows.filter((r) => `${r.hostname} ${r.fqdn} ${r.ip} ${r.site} ${r.os} ${r.group}`.toLowerCase().includes(q));
    }
    return { total: rows.length, page, pageSize, rows: rows.slice((page - 1) * pageSize, page * pageSize).map(recordView) };
  }

  function setPlan(id, row, plan, user) {
    const record = find(id);
    if (record.status !== "Review") {
      throw new ImportError("The import has already been approved.", 409, "approved");
    }
    if (!PLAN_VALUES.has(plan)) {
      throw new ImportError("Choose install, upgrade, repair, none or exclude.", 400, "invalid", "plan");
    }
    const target = record.records.find((r) => r.row === Number(row));
    if (!target) {
      throw new ImportError("The row was not found.", 404, "not_found");
    }
    if (plan === "upgrade" || plan === "repair") {
      if (!target.agent) {
        throw new ImportError("This system has no enrolled agent to upgrade or repair.", 400, "no_agent", "plan");
      }
    }
    target.plan = plan === "exclude" ? "exclude" : plan;
    target.state = plan === "exclude" ? "Excluded" : plan === "none" ? (target.agent ? "UpToDate" : "Review") : "Review";
    persist();
    return recordView(target);
  }

  function approve(id, options, user) {
    const record = find(id);
    if (record.status !== "Review") {
      throw new ImportError("The import has already been approved.", 409, "approved");
    }
    const upgradeAgents = record.records.filter((r) => (r.plan === "upgrade" || r.plan === "repair") && r.agent).map((r) => ({ agentId: r.agent.agentId, plan: r.plan }));
    let jobId = null;
    const upgrades = upgradeAgents.filter((a) => a.plan === "upgrade").map((a) => a.agentId);
    const repairs = upgradeAgents.filter((a) => a.plan === "repair").map((a) => a.agentId);
    if (upgrades.length) {
      const job = engine.createJob({
        kind: "agent",
        action: "upgrade",
        name: `${record.name} — agent upgrade`,
        selector: { mode: "agents", agentIds: upgrades },
        options
      }, user);
      jobId = job.id;
    }
    if (repairs.length) {
      const job = engine.createJob({
        kind: "agent",
        action: "repair",
        name: `${record.name} — agent repair`,
        selector: { mode: "agents", agentIds: repairs },
        options
      }, user);
      jobId = jobId || job.id;
    }
    for (const r of record.records) {
      if (r.plan === "install") {
        r.state = "AwaitingDeployment";
      } else if (r.plan === "upgrade") {
        r.state = "Upgrading";
      } else if (r.plan === "repair") {
        r.state = "Repairing";
      }
    }
    record.status = "Approved";
    record.approvedBy = user.name;
    record.approvedUtc = new Date().toISOString();
    record.jobId = jobId;
    persist();
    const c = counts(record);
    store.addAudit({ user: user.name, action: "AgentImportApproved", result: "Success", details: `${record.name}: ${c.install} install, ${c.upgrade} upgrade, ${c.repair} repair.` });
    return { import: summary(record), jobId };
  }

  // Reflects agent registrations and upgrade results back onto import records.
  function reconcile() {
    let changed = false;
    const index = agentIndex();
    for (const record of imports.values()) {
      if (record.status !== "Approved") {
        continue;
      }
      for (const r of record.records) {
        if (r.state === "AwaitingDeployment") {
          const agent = matchAgent(r, index);
          if (agent) {
            r.agent = agent;
            r.state = "Registered";
            r.message = `Agent ${agent.displayId} registered.`;
            changed = true;
          }
        }
      }
    }
    if (changed) {
      persist();
    }
    return changed;
  }

  function bundle(id) {
    const record = find(id);
    const installs = record.records.filter((r) => r.plan === "install");
    const manifest = installer.manifest();
    const version = manifest ? manifest.version : "the current release";
    const targetsCsv = ["hostname,fqdn,ip,site,os,group"]
      .concat(installs.map((r) => [r.hostname, r.fqdn, r.ip, r.site, r.os, r.group].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")))
      .join("\r\n");
    const files = [
      { name: "README.txt", data: readmeText(record, version, installs.length) },
      { name: "targets.csv", data: targetsCsv },
      { name: "Install-uAgent.ps1", data: installScript() },
      { name: "Intune.md", data: intuneText() },
      { name: "GroupPolicy.md", data: groupPolicyText() },
      { name: "ConfigurationManager.md", data: configMgrText() }
    ];
    return { fileName: `uAgent-deployment-kit-${record.name.replace(/[^\w.-]+/g, "_")}.zip`, data: build(files) };
  }

  function readmeText(record, version, count) {
    return [
      "uAgent agent deployment kit",
      "(c) 2026 Sumit Kumawat - Developed by Sumit Kumawat",
      "",
      `Import: ${record.name}`,
      `Generated: ${new Date().toISOString()}`,
      `Systems to install: ${count}`,
      `Agent version: ${version}`,
      "",
      "This kit installs the uAgent service on systems that do not yet have it, using your approved",
      "enterprise endpoint management tool. It does not contain any passwords or credentials.",
      "",
      "Steps:",
      "1. Download the signed installer from the portal Download page (uAgent_Version<version>.exe).",
      "2. Place the installer next to Install-uAgent.ps1.",
      "3. Deploy using one of the included guides: Intune.md, GroupPolicy.md or ConfigurationManager.md.",
      "4. targets.csv lists the systems planned for a fresh install so you can scope the deployment.",
      "",
      "Each agent registers with the portal on first start and then receives signed updates over its",
      "own authenticated channel. Review registration progress on the import page in the portal."
    ].join("\r\n");
  }

  function installScript() {
    return [
      "# Installs the uAgent service silently. Run as SYSTEM or an administrator through your",
      "# endpoint management tool. The installer carries its own manager and enrollment settings.",
      "param([string]$Installer = \"$PSScriptRoot\\uAgent-Setup.exe\")",
      "$ErrorActionPreference = 'Stop'",
      "if (-not (Test-Path $Installer)) { throw \"Installer not found: $Installer\" }",
      "$process = Start-Process -FilePath $Installer -ArgumentList '/install','/quiet' -Wait -PassThru",
      "exit $process.ExitCode"
    ].join("\r\n");
  }

  function intuneText() {
    return [
      "# Deploy with Microsoft Intune (Win32 app)",
      "",
      "1. Package the installer and Install-uAgent.ps1 with the Microsoft Win32 Content Prep Tool",
      "   (IntuneWinAppUtil.exe).",
      "2. Create a Windows app (Win32) in Intune and upload the .intunewin file.",
      "3. Install command: powershell.exe -ExecutionPolicy Bypass -File Install-uAgent.ps1",
      "4. Uninstall command: uAgent-Setup.exe /uninstall /quiet",
      "5. Install behavior: System.",
      "6. Detection rule: service 'uAgent' exists, or the file C:\\Program Files\\uAgent\\uAgent.exe exists.",
      "7. Assign to the device group that matches targets.csv."
    ].join("\r\n");
  }

  function groupPolicyText() {
    return [
      "# Deploy with Group Policy (startup script)",
      "",
      "1. Copy the installer and Install-uAgent.ps1 to a share every target can read, for example",
      "   \\\\server\\share\\uAgent.",
      "2. Create a GPO linked to the organizational unit that matches targets.csv.",
      "3. Computer Configuration > Policies > Windows Settings > Scripts (Startup) > PowerShell Scripts.",
      "4. Add Install-uAgent.ps1 with the parameter -Installer \\\\server\\share\\uAgent\\uAgent-Setup.exe.",
      "5. The script exits 0 when the agent is already installed, so it is safe to leave in place."
    ].join("\r\n");
  }

  function configMgrText() {
    return [
      "# Deploy with Microsoft Configuration Manager",
      "",
      "1. Create an Application or Package containing the installer and Install-uAgent.ps1.",
      "2. Program: powershell.exe -ExecutionPolicy Bypass -File Install-uAgent.ps1",
      "3. Run mode: Run with administrative rights (system context).",
      "4. Detection method: the file C:\\Program Files\\uAgent\\uAgent.exe exists.",
      "5. Deploy to the device collection that matches targets.csv."
    ].join("\r\n");
  }

  function exportCsv(id) {
    const record = find(id);
    const header = ["Row", "Hostname", "FQDN", "IP", "Site", "OS", "Group", "DNS", "Agent", "Agent version", "Plan", "State", "Issues"];
    const escape = (value) => {
      let s = String(value == null ? "" : value);
      if (/^[=+\-@]/.test(s)) {
        s = `'${s}`;
      }
      return `"${s.replace(/"/g, '""')}"`;
    };
    const lines = [header.map(escape).join(",")];
    for (const r of record.records) {
      lines.push([r.row, r.hostname, r.fqdn, r.ip, r.site, r.os, r.group, r.dns, r.agent ? r.agent.displayId : "", r.agent ? r.agent.version : "", r.plan, r.state, r.issues.join("; ")].map(escape).join(","));
    }
    return lines.join("\r\n");
  }

  let lastReconcile = 0;
  function safeReconcile() {
    if (Date.now() - lastReconcile < 2000) {
      return;
    }
    const waiting = [...imports.values()].some((r) => r.status === "Approved" && r.records.some((x) => x.state === "AwaitingDeployment"));
    if (!waiting) {
      return;
    }
    lastReconcile = Date.now();
    try {
      if (reconcile()) {
        for (const record of imports.values()) {
          if (record.status === "Approved") {
            store._emit("import", { importId: record.id });
          }
        }
      }
    } catch (error) {
      logger(`Agent import reconcile error: ${error.message}`);
    }
  }
  // New registrations are reflected as soon as the agent enrolls; the slow timer is a safety net.
  store.events.on("batch", (batch) => {
    if (batch.some((e) => e.type === "agent")) {
      safeReconcile();
    }
  });
  const timer = setInterval(safeReconcile, 60000);
  timer.unref();

  return {
    ImportError,
    create,
    createFromEntries,
    list: () => [...imports.values()].map(summary).sort((a, b) => b.createdUtc.localeCompare(a.createdUtc)),
    get: (id) => summary(find(id)),
    queryRecords,
    setPlan,
    approve,
    bundle,
    exportCsv
  };
}

module.exports = { createAgentDeployment };
