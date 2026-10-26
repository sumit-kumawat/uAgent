"use strict";

const crypto = require("crypto");
const { Catalog, CommandStatuses, LegacyCapabilities } = require("./commandTypes");

const DELIVERY_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_COMMUNICATION = 100;

function padNumber(n) {
  return String(n).padStart(5, "0");
}

// Per-agent credentials are random and stored only as a SHA-256 hash; the plaintext is returned once at
// enrollment (or rotation) and never persisted.
function newApiKey() {
  return "uak_" + crypto.randomBytes(30).toString("base64url");
}

function hashKey(key) {
  return crypto.createHash("sha256").update(String(key), "utf8").digest("hex");
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}

const AgentStatuses = {
  Active: "Active",
  PendingApproval: "PendingApproval",
  Revoked: "Revoked"
};

// Portal data is kept in memory and written to disk every few seconds, so a crash or reboot
// comes back with the same agents, commands, and audit log. Agents then heartbeat and sync again.
class Store {
  constructor(onlineWindowMs, options = {}) {
    this.onlineWindowMs = onlineWindowMs;
    this.requireApproval = Boolean(options.requireApproval);
    this.agents = new Map(); // agentId -> agent record
    this.reports = new Map(); // agentId -> normalized report
    this.pending = new Map(); // agentId -> [commands]
    this.history = new Map(); // agentId -> [command records]
    this.audit = []; // AuditEntry[]
    this.downloads = []; // installer downloads only — never treated as installed agents
    this.issues = []; // failed downloads, registration, or activation
    this.nextAgentNumber = 1;
    this.maxResults = 500;
    this.maxAudit = 5000;
    this._stateFile = "";
    this._dirty = false;
  }

  _mark() {
    this._dirty = true;
  }

  _getOrCreateAgent(agentId, remoteIp) {
    let agent = this.agents.get(agentId);
    if (!agent) {
      const now = new Date().toISOString();
      agent = {
        agentId,
        agentNumber: this.nextAgentNumber++,
        machineName: "",
        osVersion: "",
        domainName: "",
        dnsName: "",
        ipAddresses: [],
        uptime: "",
        agentVersion: "",
        serviceMode: "",
        capabilities: null,
        pollIntervalSeconds: null,
        commandPollSeconds: null,
        lastHeartbeatUtc: null,
        lastContactUtc: null,
        remoteIp: remoteIp || "",
        reportedDomainJoined: null,
        firstSeenUtc: now,
        communication: [],
        status: AgentStatuses.Active,
        apiKeyHash: "",
        pendingKeyHash: "",
        rotation: null,
        enrolledUtc: null
      };
      this.agents.set(agentId, agent);
      this._communicate(agent, "Registered", `Agent enrolled automatically as ${padNumber(agent.agentNumber)}.`, remoteIp);
    }
    return agent;
  }

  // Issues a unique agent id and credential. The plaintext key is returned once; only its hash is kept.
  enrollAgent(request, remoteIp) {
    const agentId = crypto.randomUUID();
    const apiKey = newApiKey();
    const agent = this._getOrCreateAgent(agentId, remoteIp);
    const req = request || {};
    agent.machineName = String(req.machineName || "").slice(0, 200);
    agent.osVersion = String(req.osVersion || "").slice(0, 200);
    agent.domainName = String(req.domainName || "").slice(0, 200);
    agent.dnsName = String(req.dnsName || "").slice(0, 253);
    agent.ipAddresses = Array.isArray(req.ipAddresses) ? req.ipAddresses.map(String).slice(0, 16) : [];
    agent.agentVersion = String(req.agentVersion || "").slice(0, 40);
    agent.serviceMode = String(req.serviceMode || "").slice(0, 40);
    agent.capabilities = Array.isArray(req.capabilities) ? req.capabilities.filter((c) => Catalog[c]) : null;
    agent.apiKeyHash = hashKey(apiKey);
    agent.status = this.requireApproval ? AgentStatuses.PendingApproval : AgentStatuses.Active;
    agent.enrolledUtc = new Date().toISOString();
    this._touch(agent, remoteIp);
    this._communicate(agent, "Enrolled", `Registered as ${padNumber(agent.agentNumber)} (${agent.status}).`, remoteIp);
    this.addAudit({
      user: "agent",
      agentId,
      action: "Enroll",
      result: agent.status,
      details: `${agent.machineName || "A new host"} registered as ${padNumber(agent.agentNumber)}.`,
      remoteIp
    });
    return {
      agentId,
      agentNumber: agent.agentNumber,
      displayId: padNumber(agent.agentNumber),
      apiKey,
      status: agent.status
    };
  }

  // Validates an agent's own credential for the agent API. Promotes a rotated key once the agent adopts it.
  authenticateAgent(agentId, providedKey) {
    const agent = this.agents.get(agentId);
    if (!agent || !agent.apiKeyHash) {
      return { ok: false, code: "unknown_agent" };
    }
    if (agent.status === AgentStatuses.Revoked) {
      return { ok: false, code: "revoked" };
    }
    const provided = hashKey(providedKey || "");
    if (timingSafeEqualHex(provided, agent.apiKeyHash)) {
      return { ok: true, agent };
    }
    if (agent.pendingKeyHash && timingSafeEqualHex(provided, agent.pendingKeyHash)) {
      // The agent has started using the rotated key; make it the active credential.
      agent.apiKeyHash = agent.pendingKeyHash;
      agent.pendingKeyHash = "";
      agent.rotation = null;
      this._communicate(agent, "KeyRotated", "Agent adopted its rotated credential.", agent.remoteIp);
      return { ok: true, agent };
    }
    return { ok: false, code: "invalid_key" };
  }

  // Returns a one-time new credential to hand to the agent in its next heartbeat response.
  _takeRotation(agent, remoteIp) {
    if (!agent.rotation || agent.rotation.delivered) {
      return null;
    }
    agent.rotation.delivered = true;
    agent.pendingKeyHash = agent.rotation.hash;
    this._communicate(agent, "KeyRotated", "Delivered a rotated credential; waiting for the agent to adopt it.", remoteIp);
    return agent.rotation.plain;
  }

  rotateKey(agentId, user) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return false;
    }
    const apiKey = newApiKey();
    agent.rotation = { plain: apiKey, hash: hashKey(apiKey), delivered: false, requestedUtc: new Date().toISOString() };
    this.addAudit({
      user: user.name,
      agentId,
      action: "RotateKey",
      result: "Pending",
      details: "Queued a credential rotation; the new key is delivered on the next heartbeat."
    });
    return true;
  }

  setAgentStatus(agentId, status, user) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return false;
    }
    agent.status = status;
    this._communicate(agent, "Status", `Status changed to ${status} by ${user.name}.`, agent.remoteIp);
    this.addAudit({
      user: user.name,
      agentId,
      action: status === AgentStatuses.Active ? "Approve" : "Revoke",
      result: status,
      details: `Agent set to ${status}.`
    });
    return true;
  }

  removeAgent(agentId, user, origin) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return false;
    }
    const displayId = padNumber(agent.agentNumber);
    const machineName = agent.machineName;
    this.agents.delete(agentId);
    this.reports.delete(agentId);
    this.pending.delete(agentId);
    this.history.delete(agentId);
    this.addAudit({
      user: user ? user.name : "agent",
      agentId: null,
      action: "Deregister",
      result: "Removed",
      details: `Agent ${displayId} (${machineName || "unknown host"}) was removed (${origin}).`
    });
    return true;
  }

  isActionable(agentId) {
    const agent = this.agents.get(agentId);
    return Boolean(agent && agent.status === AgentStatuses.Active && this._isOnline(agent));
  }

  statusOf(agentId) {
    const agent = this.agents.get(agentId);
    return agent ? agent.status : null;
  }

  _communicate(agent, kind, detail, remoteIp) {
    this._mark();
    agent.communication.unshift({
      timestampUtc: new Date().toISOString(),
      kind,
      detail,
      remoteIp: remoteIp || agent.remoteIp || ""
    });
    if (agent.communication.length > MAX_COMMUNICATION) {
      agent.communication.length = MAX_COMMUNICATION;
    }
  }

  _touch(agent, remoteIp) {
    this._mark();
    agent.lastContactUtc = new Date().toISOString();
    if (remoteIp) {
      agent.remoteIp = remoteIp;
    }
  }

  // Finds an agent by its internal id or by its zero-padded display number (e.g. "00001").
  resolveAgentId(key) {
    if (!key) {
      return null;
    }
    if (this.agents.has(key)) {
      return key;
    }
    if (/^\d{1,9}$/.test(key)) {
      const number = Number.parseInt(key, 10);
      for (const agent of this.agents.values()) {
        if (agent.agentNumber === number) {
          return agent.agentId;
        }
      }
    }
    return null;
  }

  // Auto-registers the agent on first contact (Wazuh-style enrollment) and records its system info.
  upsertHeartbeat(agentId, hb, remoteIp) {
    const agent = this._getOrCreateAgent(agentId, remoteIp);
    const wasOnline = this._isOnline(agent);
    agent.machineName = hb.machineName || agent.machineName;
    agent.osVersion = hb.osVersion || agent.osVersion;
    agent.domainName = hb.domainName || "";
    agent.dnsName = hb.dnsName || agent.dnsName || "";
    agent.ipAddresses = Array.isArray(hb.ipAddresses) ? hb.ipAddresses.map(String).slice(0, 16) : agent.ipAddresses;
    agent.uptime = hb.uptime || "";
    agent.agentVersion = hb.agentVersion || agent.agentVersion || "";
    agent.serviceMode = hb.serviceMode || agent.serviceMode || "";
    agent.capabilities = Array.isArray(hb.capabilities) ? hb.capabilities.filter((c) => Catalog[c]) : agent.capabilities;
    agent.pollIntervalSeconds = Number(hb.pollIntervalSeconds) || agent.pollIntervalSeconds;
    agent.commandPollSeconds = Number(hb.commandPollSeconds) || agent.commandPollSeconds;
    agent.lastHeartbeatUtc = new Date().toISOString();
    this._touch(agent, remoteIp);
    this._communicate(agent, "Heartbeat", wasOnline ? "Heartbeat received." : "Agent came online.", remoteIp);
    return {
      status: agent.status,
      displayId: padNumber(agent.agentNumber),
      newApiKey: this._takeRotation(agent, remoteIp)
    };
  }

  saveReport(agentId, report, remoteIp) {
    const agent = this._getOrCreateAgent(agentId, remoteIp);
    const accounts = Array.isArray(report.accounts) ? report.accounts : [];
    const normalizedAccounts = accounts
      .filter((a) => a && a.samAccountName)
      .map((a) => ({
        samAccountName: String(a.samAccountName).trim(),
        displayName: a.displayName || "",
        enabled: Boolean(a.enabled),
        lockedOut: Boolean(a.lockedOut),
        accountExpirationDate: a.accountExpirationDate || null,
        lastPasswordSet: a.lastPasswordSet || null,
        lastLogon: a.lastLogon || null,
        badLogonCount: Number(a.badLogonCount) || 0,
        source: a.source || "Local",
        passwordExpiresUtc: a.passwordExpiresUtc || null,
        passwordNeverExpires: Boolean(a.passwordNeverExpires)
      }));

    const normalized = {
      agentId,
      machineName: report.machineName || agent.machineName || "",
      isDomainJoined: Boolean(report.isDomainJoined),
      timestampUtc: new Date().toISOString(),
      accounts: normalizedAccounts
    };
    this.reports.set(agentId, normalized);

    if (normalized.machineName) {
      agent.machineName = normalized.machineName;
    }
    agent.reportedDomainJoined = normalized.isDomainJoined;
    this._touch(agent, remoteIp);
    this._communicate(agent, "Inventory", `Account inventory received (${normalizedAccounts.length} account(s)).`, remoteIp);
  }

  getReport(agentId) {
    return this.reports.get(agentId) || null;
  }

  getMachineName(agentId) {
    const agent = this.agents.get(agentId);
    return agent && agent.machineName ? agent.machineName : agentId;
  }

  getDisplayId(agentId) {
    const agent = this.agents.get(agentId);
    return agent ? padNumber(agent.agentNumber) : "";
  }

  capabilitiesOf(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return [];
    }
    return Array.isArray(agent.capabilities) ? agent.capabilities : LegacyCapabilities;
  }

  isOnline(agentId) {
    const agent = this.agents.get(agentId);
    return agent ? this._isOnline(agent) : false;
  }

  enqueue(agentId, command, user, reason) {
    this._mark();
    const queue = this.pending.get(agentId) || [];
    queue.push(command);
    this.pending.set(agentId, queue);

    const history = this.history.get(agentId) || [];
    history.push({
      command,
      status: CommandStatuses.Pending,
      deliveredUtc: null,
      executedUtc: null,
      resultMessage: null,
      enqueuedBy: user.name,
      enqueuedRole: user.role,
      reason: reason || ""
    });
    if (history.length > this.maxResults) {
      history.splice(0, history.length - this.maxResults);
    }
    this.history.set(agentId, history);

    this.addAudit({
      user: user.name,
      agentId,
      samAccountName: command.samAccountName,
      action: command.commandType,
      result: CommandStatuses.Pending,
      details: reason ? `Queued for the agent. Reason: ${reason}` : "Queued for the agent."
    });
    return command;
  }

  // Agents register through heartbeats; command polls from unknown agents must not create blank records.
  takePendingCommands(agentId, remoteIp) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return [];
    }
    this._touch(agent, remoteIp);
    if (agent.status !== AgentStatuses.Active) {
      return []; // Hold actions until an administrator approves the agent.
    }
    const queue = this.pending.get(agentId);
    if (!queue || queue.length === 0) {
      return [];
    }
    this.pending.set(agentId, []);

    const now = new Date().toISOString();
    const history = this.history.get(agentId) || [];
    const ids = new Set(queue.map((c) => c.commandId));
    for (const record of history) {
      if (ids.has(record.command.commandId) && record.status === CommandStatuses.Pending) {
        record.status = CommandStatuses.Delivered;
        record.deliveredUtc = now;
      }
    }
    this._communicate(agent, "Commands", `Delivered ${queue.length} command(s) to the agent.`, remoteIp);
    return queue;
  }

  addResults(agentId, results, remoteIp) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return;
    }
    this._touch(agent, remoteIp);
    if (!Array.isArray(results) || results.length === 0) {
      return;
    }
    const history = this.history.get(agentId) || [];
    let matched = 0;
    for (const result of results) {
      const match = [...history].reverse().find((r) => r.command.commandId === result.commandId);
      if (!match) {
        continue;
      }
      matched += 1;
      match.status = result.success ? CommandStatuses.Success : CommandStatuses.Failed;
      match.executedUtc = result.executedUtc || new Date().toISOString();
      match.resultMessage = (result.success ? result.message : result.errorMessage) || result.message || result.errorMessage || null;
      this.addAudit({
        user: match.enqueuedBy || "agent",
        agentId,
        samAccountName: match.command.samAccountName,
        action: match.command.commandType,
        result: match.status,
        details: match.resultMessage || (result.success ? "Executed by the agent." : "The agent reported a failure.")
      });
    }
    this._communicate(agent, "Results", `Received ${results.length} result(s); ${matched} matched queued actions.`, remoteIp);
  }

  _status(record) {
    if (record.status === CommandStatuses.Delivered && record.deliveredUtc &&
        Date.now() - new Date(record.deliveredUtc).getTime() > DELIVERY_TIMEOUT_MS) {
      return CommandStatuses.TimedOut;
    }
    return record.status;
  }

  _toView(agentId, record) {
    const meta = Catalog[record.command.commandType] || {};
    return {
      commandId: record.command.commandId,
      agentId,
      agentDisplayId: this.getDisplayId(agentId),
      machineName: this.getMachineName(agentId),
      samAccountName: record.command.samAccountName,
      commandType: record.command.commandType,
      label: meta.label || record.command.commandType,
      category: meta.category || "account",
      status: this._status(record),
      createdUtc: record.command.createdUtc,
      deliveredUtc: record.deliveredUtc,
      executedUtc: record.executedUtc,
      result: record.resultMessage,
      enqueuedBy: record.enqueuedBy,
      reason: record.reason
    };
  }

  getCommandHistory(agentId) {
    const history = this.history.get(agentId) || [];
    return history
      .map((record) => this._toView(agentId, record))
      .sort((a, b) => new Date(b.createdUtc) - new Date(a.createdUtc));
  }

  getCommand(agentId, commandId) {
    const record = (this.history.get(agentId) || []).find((r) => r.command.commandId === commandId);
    return record ? this._toView(agentId, record) : null;
  }

  getAllCommands() {
    const views = [];
    for (const [agentId, history] of this.history) {
      for (const record of history) {
        views.push(this._toView(agentId, record));
      }
    }
    return views.sort((a, b) => new Date(b.createdUtc) - new Date(a.createdUtc));
  }

  addAudit(entry) {
    this._mark();
    this.audit.push({
      id: crypto.randomUUID(),
      timestampUtc: new Date().toISOString(),
      user: entry.user || "system",
      agentId: entry.agentId || null,
      samAccountName: entry.samAccountName || "",
      action: entry.action,
      result: entry.result,
      details: entry.details || "",
      remoteIp: entry.remoteIp || ""
    });
    if (this.audit.length > this.maxAudit) {
      this.audit.splice(0, this.audit.length - this.maxAudit);
    }
  }

  getAudit(agentId) {
    let entries = this.audit;
    if (agentId) {
      entries = entries.filter((e) => e.agentId && e.agentId === agentId);
    }
    return [...entries]
      .sort((a, b) => new Date(b.timestampUtc) - new Date(a.timestampUtc))
      .map((e) => ({ ...e, agentDisplayId: e.agentId ? this.getDisplayId(e.agentId) : "", machineName: e.agentId ? this.getMachineName(e.agentId) : "" }));
  }

  getGlobalAccounts() {
    const views = [];
    for (const [agentId, report] of this.reports) {
      for (const account of report.accounts) {
        views.push({ agentId, agentDisplayId: this.getDisplayId(agentId), machineName: report.machineName, account });
      }
    }
    return views.sort((a, b) => {
      const byMachine = (a.machineName || "").localeCompare(b.machineName || "");
      return byMachine !== 0 ? byMachine : a.account.samAccountName.localeCompare(b.account.samAccountName);
    });
  }

  _isOnline(agent) {
    if (!agent.lastHeartbeatUtc || !agent.lastContactUtc) {
      return false;
    }
    return Date.now() - new Date(agent.lastContactUtc).getTime() <= this.onlineWindowMs;
  }

  _summary(agent) {
    const report = this.getReport(agent.agentId);
    const accounts = report ? report.accounts : [];
    return {
      agentId: agent.agentId,
      agentNumber: agent.agentNumber,
      displayId: padNumber(agent.agentNumber),
      machineName: agent.machineName,
      osVersion: agent.osVersion,
      isDomainJoined: agent.reportedDomainJoined !== null ? agent.reportedDomainJoined : Boolean(agent.domainName),
      domainName: agent.domainName,
      dnsName: agent.dnsName,
      lastSeenUtc: agent.lastContactUtc,
      lastHeartbeatUtc: agent.lastHeartbeatUtc,
      online: this._isOnline(agent),
      status: agent.status,
      accountCount: accounts.length,
      lockedCount: accounts.filter((a) => a.lockedOut).length,
      criticalCount: accounts.filter((a) => Store.isCritical(a)).length,
      ipAddresses: Array.isArray(agent.ipAddresses) ? agent.ipAddresses : [],
      agentVersion: agent.agentVersion || "",
      connection: this._connection(agent),
      enrolledUtc: agent.enrolledUtc
    };
  }

  // Active agents are split by contact: online (inside the window), disconnected (seen, then lost),
  // or offline (enrolled but never checked in). Pending and revoked are their own states.
  _connection(agent) {
    if (agent.status === AgentStatuses.PendingApproval) {
      return "pending";
    }
    if (agent.status === AgentStatuses.Revoked) {
      return "inactive";
    }
    if (!agent.lastHeartbeatUtc) {
      return "offline";
    }
    return this._isOnline(agent) ? "online" : "disconnected";
  }

  listAgents() {
    return [...this.agents.values()]
      .map((agent) => this._summary(agent))
      .sort((a, b) => a.agentNumber - b.agentNumber);
  }

  getAgentDetail(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return null;
    }
    const report = this.getReport(agentId);
    const accounts = report ? report.accounts : [];
    return {
      ...this._summary(agent),
      firstSeenUtc: agent.firstSeenUtc,
      enrolledUtc: agent.enrolledUtc,
      rotationPending: Boolean(agent.rotation && !agent.rotation.delivered) || Boolean(agent.pendingKeyHash),
      ipAddresses: agent.ipAddresses,
      remoteIp: agent.remoteIp,
      uptime: agent.uptime,
      agentVersion: agent.agentVersion,
      serviceMode: agent.serviceMode,
      capabilities: this.capabilitiesOf(agentId),
      capabilitiesReported: Array.isArray(agent.capabilities),
      pollIntervalSeconds: agent.pollIntervalSeconds,
      commandPollSeconds: agent.commandPollSeconds,
      onlineWindowSeconds: Math.round(this.onlineWindowMs / 1000),
      pendingCount: (this.pending.get(agentId) || []).length,
      inventoryUtc: report ? report.timestampUtc : null,
      accountCounts: {
        total: accounts.length,
        enabled: accounts.filter((a) => a.enabled).length,
        disabled: accounts.filter((a) => !a.enabled).length,
        locked: accounts.filter((a) => a.lockedOut).length,
        critical: accounts.filter((a) => Store.isCritical(a)).length
      },
      communication: agent.communication.slice(0, 50)
    };
  }

  getSummary() {
    const agents = this.listAgents();
    const accounts = { total: 0, enabled: 0, disabled: 0, locked: 0, expired: 0, passwordExpired: 0, passwordWarning: 0, passwordNotSet: 0, passwordUnreported: 0, passwordReported: 0 };
    for (const report of this.reports.values()) {
      for (const account of report.accounts) {
        accounts.total += 1;
        if (account.enabled) { accounts.enabled += 1; } else { accounts.disabled += 1; }
        if (account.lockedOut) { accounts.locked += 1; }
        if (Store.isAccountExpired(account)) { accounts.expired += 1; }
        if (!account.lastPasswordSet) { accounts.passwordNotSet += 1; }
        const expiry = Store.passwordExpiry(account);
        if (expiry === "unreported") { accounts.passwordUnreported += 1; }
        else { accounts.passwordReported += 1; }
        if (expiry === "expired") { accounts.passwordExpired += 1; }
        if (expiry === "warning") { accounts.passwordWarning += 1; }
      }
    }
    return {
      totalAgents: agents.length,
      activeAgents: agents.filter((a) => a.status === AgentStatuses.Active).length,
      onlineAgents: agents.filter((a) => a.connection === "online").length,
      disconnectedAgents: agents.filter((a) => a.connection === "disconnected").length,
      offlineAgents: agents.filter((a) => a.connection === "offline").length,
      pendingApproval: agents.filter((a) => a.status === AgentStatuses.PendingApproval).length,
      inactiveAgents: agents.filter((a) => a.status === AgentStatuses.Revoked).length,
      totalAccounts: accounts.total,
      criticalAccounts: accounts.locked + accounts.expired,
      accounts
    };
  }

  // Case-insensitive scan of enrolled agents. Results are capped so a large fleet stays responsive.
  searchAgents(query, limit) {
    const q = String(query || "").trim().toLowerCase();
    const cap = Math.min(Math.max(Number(limit) || 20, 1), 50);
    if (!q) {
      return { results: [], total: 0 };
    }
    const numeric = /^\d+$/.test(q) ? String(Number.parseInt(q, 10)) : "";
    const hits = [];
    for (const agent of this.agents.values()) {
      const displayId = padNumber(agent.agentNumber);
      const fields = [
        ["Agent ID", displayId],
        ["Agent ID", numeric && String(agent.agentNumber) === numeric ? displayId : ""],
        ["Hostname", agent.machineName],
        ["DNS", agent.dnsName],
        ["Domain", agent.domainName],
        ["OS", agent.osVersion],
        ["Version", agent.agentVersion],
        ["IP address", (agent.ipAddresses || []).join(" ")],
        ["Source address", agent.remoteIp],
        ["Status", agent.status]
      ];
      const matched = fields.find(([, value]) => value && String(value).toLowerCase().includes(q));
      const idMatch = agent.agentId.toLowerCase().includes(q);
      if (!matched && !idMatch) {
        continue;
      }
      const summary = this._summary(agent);
      hits.push({
        displayId: summary.displayId,
        machineName: summary.machineName || "",
        dnsName: summary.dnsName || "",
        osVersion: summary.osVersion || "",
        domainName: summary.domainName || "",
        ipAddresses: summary.ipAddresses,
        agentVersion: summary.agentVersion,
        status: summary.status,
        connection: summary.connection,
        matchedOn: matched ? matched[0] : "Agent ID",
        matchedValue: matched ? String(matched[1]) : summary.displayId
      });
    }
    hits.sort((a, b) => a.displayId.localeCompare(b.displayId));
    return { results: hits.slice(0, cap), total: hits.length };
  }

  recordDownload(entry) {
    this._mark();
    const record = {
      id: crypto.randomUUID(),
      timestampUtc: new Date().toISOString(),
      version: entry.version || "",
      fileName: entry.fileName || "",
      size: Number(entry.size) || 0,
      remoteIp: entry.remoteIp || "",
      result: entry.result === "Success" ? "Success" : "Failed",
      detail: entry.detail || ""
    };
    this.downloads.push(record);
    if (this.downloads.length > 500) {
      this.downloads.splice(0, this.downloads.length - 500);
    }
    this.addAudit({
      user: "public",
      action: "DownloadInstaller",
      result: record.result,
      details: record.result === "Success"
        ? `Downloaded ${record.fileName}${record.version ? " (" + record.version + ")" : ""}.`
        : (record.detail || "Installer download failed."),
      remoteIp: record.remoteIp
    });
    return record;
  }

  // Failed registration or activation. Identical repeats from the same address are collapsed for a minute.
  recordIssue(entry) {
    this._mark();
    const detail = entry.detail || "";
    const remoteIp = entry.remoteIp || "";
    const kind = entry.kind || "Activation";
    const recent = this.issues.slice(-40).some((item) =>
      item.kind === kind && item.remoteIp === remoteIp && item.detail === detail &&
      Date.now() - new Date(item.timestampUtc).getTime() < 60000);
    if (recent) {
      return null;
    }
    const record = {
      id: crypto.randomUUID(),
      timestampUtc: new Date().toISOString(),
      kind,
      result: "Failed",
      remoteIp,
      agentId: entry.agentId || null,
      detail
    };
    this.issues.push(record);
    if (this.issues.length > 200) {
      this.issues.splice(0, this.issues.length - 200);
    }
    this.addAudit({
      user: entry.user || "agent",
      agentId: record.agentId,
      action: kind,
      result: "Failed",
      details: detail,
      remoteIp
    });
    return record;
  }

  getDownloadReport() {
    const agents = this.listAgents();
    const versions = new Map();
    for (const agent of agents) {
      const version = agent.agentVersion || "Unknown";
      versions.set(version, (versions.get(version) || 0) + 1);
    }
    const downloads = [...this.downloads].sort((a, b) => new Date(b.timestampUtc) - new Date(a.timestampUtc));
    const issues = this.issues.map((item) => ({
      ...item,
      displayId: item.agentId ? this.getDisplayId(item.agentId) : ""
    })).sort((a, b) => new Date(b.timestampUtc) - new Date(a.timestampUtc));
    return {
      downloads: downloads.filter((d) => d.result === "Success").length,
      failedDownloads: downloads.filter((d) => d.result !== "Success").length,
      installed: agents.length,
      activated: agents.filter((a) => a.status === AgentStatuses.Active).length,
      pending: agents.filter((a) => a.status === AgentStatuses.PendingApproval).length,
      inactive: agents.filter((a) => a.status === AgentStatuses.Revoked).length,
      failed: issues.length,
      versions: [...versions.entries()].map(([version, count]) => ({ version, count })).sort((a, b) => b.count - a.count),
      history: downloads.slice(0, 100),
      activations: agents.map((agent) => ({
        displayId: agent.displayId,
        machineName: agent.machineName,
        agentVersion: agent.agentVersion,
        status: agent.status,
        connection: agent.connection,
        enrolledUtc: agent.enrolledUtc,
        lastSeenUtc: agent.lastSeenUtc,
        ipAddresses: agent.ipAddresses
      })),
      issues: issues.slice(0, 50)
    };
  }

  getRecentActivity(take) {
    const items = [];
    for (const command of this.getAllCommands()) {
      const timestamp = command.executedUtc || command.deliveredUtc || command.createdUtc;
      const target = command.samAccountName ? ` for ${command.samAccountName}` : "";
      items.push({
        timestampUtc: timestamp,
        kind: "Command",
        title: command.machineName,
        detail: `${command.label}${target} \u2014 ${command.status}`
      });
    }
    for (const agent of this.listAgents()) {
      if (agent.lastSeenUtc) {
        items.push({
          timestampUtc: agent.lastSeenUtc,
          kind: "Heartbeat",
          title: agent.machineName || agent.displayId,
          detail: agent.online ? "Online" : "Last contact"
        });
      }
    }
    return items.sort((a, b) => new Date(b.timestampUtc) - new Date(a.timestampUtc)).slice(0, take);
  }

  static isAccountExpired(account) {
    return Boolean(account.accountExpirationDate) && new Date(account.accountExpirationDate) < new Date();
  }

  // "unreported" means the agent did not send a password-expiry timestamp. Callers must not treat that as zero expired passwords.
  static passwordExpiry(account) {
    if (account.passwordNeverExpires) {
      return "never";
    }
    if (!account.passwordExpiresUtc) {
      return "unreported";
    }
    const when = new Date(account.passwordExpiresUtc).getTime();
    if (Number.isNaN(when)) {
      return "unreported";
    }
    const now = Date.now();
    if (when <= now) {
      return "expired";
    }
    if (when - now <= 14 * 24 * 60 * 60 * 1000) {
      return "warning";
    }
    return "ok";
  }

  attachPersistence(file) {
    this._stateFile = file;
    this._loadState();
    this._timer = setInterval(() => this.flush(), 2000);
    if (this._timer.unref) {
      this._timer.unref();
    }
  }

  flush() {
    if (!this._dirty || !this._stateFile) {
      return;
    }
    const { writeJson } = require("./statePath");
    const payload = {
      nextAgentNumber: this.nextAgentNumber,
      agents: [...this.agents.entries()],
      reports: [...this.reports.entries()],
      pending: [...this.pending.entries()],
      history: [...this.history.entries()],
      audit: this.audit,
      downloads: this.downloads,
      issues: this.issues
    };
    try {
      writeJson(this._stateFile, payload);
      this._dirty = false;
    } catch (error) {
      // Keep the in-memory copy. The next interval tries again.
    }
  }

  _loadState() {
    const { readJson } = require("./statePath");
    const payload = readJson(this._stateFile);
    if (!payload || !Array.isArray(payload.agents)) {
      return;
    }
    this.nextAgentNumber = Number(payload.nextAgentNumber) || 1;
    this.agents = new Map(payload.agents);
    this.reports = new Map(Array.isArray(payload.reports) ? payload.reports : []);
    this.pending = new Map(Array.isArray(payload.pending) ? payload.pending : []);
    this.history = new Map(Array.isArray(payload.history) ? payload.history : []);
    this.audit = Array.isArray(payload.audit) ? payload.audit : [];
    this.downloads = Array.isArray(payload.downloads) ? payload.downloads : [];
    this.issues = Array.isArray(payload.issues) ? payload.issues : [];
    this._dirty = false;
  }

  static isCritical(account) {
    if (account.lockedOut || !account.enabled) {
      return true;
    }
    if (account.accountExpirationDate) {
      return new Date(account.accountExpirationDate) < new Date();
    }
    return false;
  }
}

Store.AgentStatuses = AgentStatuses;

module.exports = Store;
