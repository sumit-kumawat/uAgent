"use strict";

const crypto = require("crypto");
const fs = require("fs");
const { EventEmitter } = require("events");
const { Catalog, CommandStatuses, LegacyCapabilities, Features, commandLabel, isAccountCommand } = require("./commandTypes");
const { writeJson, readJson } = require("./statePath");

const DELIVERY_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_COMMUNICATION = 100;
const EVENT_BATCH_MS = 200;
const BULK_THRESHOLD = 100;
const INVENTORY_LIMITS = { processes: 5000, services: 3000, applications: 5000, files: 2000 };
const INVENTORY_SECTIONS = ["system", "processes", "services", "applications", "files"];
// An uninstall that started but was never confirmed, and an agent that keeps running after it started.
const UNINSTALL_CONFIRM_MS = 15 * 60 * 1000;
const UNINSTALL_GRACE_MS = 2 * 60 * 1000;
const RemovalStates = { Queued: "Queued", Uninstalling: "Uninstalling", Failed: "Failed", Unverified: "Unverified" };
const INSTALL_ID_PATTERN = /^[A-Za-z0-9-]{16,64}$/;
const AGENT_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
const PRESENCE_SAVE_MS = 60 * 1000;
// 1: up to 1.4. 2: 1.5 adds agent.installId.
const STATE_SCHEMA_VERSION = 2;

function padNumber(n) {
  return String(n).padStart(5, "0");
}

function normName(value) {
  return String(value || "").trim().toLowerCase();
}

function text(value, max) {
  return value === null || value === undefined || typeof value === "object" ? "" : String(value).slice(0, max);
}

// Workgroup and a blank domain are the same "not joined" identity. A NetBIOS name copied into the
// domain field is not a domain either.
function domainKey(domainName, machineName) {
  const domain = normName(domainName);
  if (!domain || domain === "workgroup" || domain === normName(machineName)) {
    return "";
  }
  return domain;
}

// One computer is one agent. The same machine name in the same domain is the same host.
// A matching DNS name is the same host even when the domain string differs. A workgroup
// computer is not the same record as a domain computer that happens to share the name.
function sameHost(a, b) {
  const machineA = normName(a.machineName);
  const machineB = normName(b.machineName);
  if (!machineA || !machineB || machineA !== machineB) {
    return false;
  }
  const dnsA = normName(a.dnsName);
  const dnsB = normName(b.dnsName);
  if (dnsA && dnsB && dnsA === dnsB) {
    return true;
  }
  const domainA = domainKey(a.domainName, machineA);
  const domainB = domainKey(b.domainName, machineB);
  if (domainA || domainB) {
    return domainA === domainB;
  }
  return true;
}

function recentStamp(agent) {
  return Date.parse(agent.lastContactUtc || agent.enrolledUtc || agent.firstSeenUtc || "") || 0;
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
    // An agent's retry backoff tops out at 5 minutes (plus jitter), so one that went quiet more recently
    // than this is still expected back on its own.
    this.reconnectWindowMs = Math.max(6 * 60 * 1000, 2 * onlineWindowMs);
    this.staleAfterMs = Math.max(Number(options.staleAfterMs) || 24 * 60 * 60 * 1000, this.reconnectWindowMs);
    this.requireApproval = Boolean(options.requireApproval);
    this.logger = typeof options.logger === "function" ? options.logger : () => {};
    this._flushError = "";
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
    // Live state that is rebuilt after a restart, so it is never persisted.
    this.inventory = new Map(); // agentId -> { section -> { data, error, collectedUtc, receivedUtc, requestId } }
    this.requests = new Map(); // agentId -> [{ requestId, section, path, createdUtc }]
    this.waiters = new Map(); // agentId -> Set(wake functions of open long polls)
    this.connections = new Map(); // agentId -> number of open long polls
    this.presence = new Map(); // agentId -> last broadcast online state
    this.connectionStates = new Map(); // agentId -> last computed connection state
    this.events = new EventEmitter();
    this.events.setMaxListeners(0);
    this._batch = new Map();
    this._batchTimer = null;
  }

  // Change notifications for the portal's live view. Bursts are coalesced into one batch every 200 ms.
  _emit(type, data) {
    this.revision = (this.revision || 0) + 1;
    const payload = { type, ...data };
    const id = data.agentId || data.jobId || data.validationId || data.importId || "";
    this._batch.set(`${type}:${id}:${data.commandId || ""}:${data.section || ""}`, payload);
    if (!this._batchTimer) {
      this._batchTimer = setTimeout(() => {
        const batch = Store.collapseBatch([...this._batch.values()]);
        this._batch.clear();
        this._batchTimer = null;
        this.events.emit("batch", batch);
      }, EVENT_BATCH_MS);
      if (this._batchTimer.unref) {
        this._batchTimer.unref();
      }
    }
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

  // One row per computer. A later registration of the same host replaces that row and its credential
  // instead of creating another agent id, unless another installation is actively using that row.
  //
  // Two computers can share a host name (a cloned image, a re-used name in a workgroup). Replacing the
  // row would revoke the other computer's credential; it would register again, revoke this one, and the
  // two would knock each other offline indefinitely. So a row is only taken over when it belongs to the
  // same installation or is not connected; otherwise the newcomer gets its own row and the clash is
  // reported.
  enrollAgent(request, remoteIp) {
    const req = request || {};
    const incoming = {
      machineName: String(req.machineName || "").slice(0, 200),
      domainName: String(req.domainName || "").slice(0, 200),
      dnsName: String(req.dnsName || "").slice(0, 253)
    };
    const installId = INSTALL_ID_PATTERN.test(String(req.installId || "")) ? String(req.installId) : "";
    const previous = AGENT_ID_PATTERN.test(String(req.previousAgentId || "")) ? this.agents.get(String(req.previousAgentId)) : null;
    const apiKey = newApiKey();
    let agent = null;
    let conflict = null;
    if (previous && incoming.machineName && sameHost(incoming, previous) && this._claimable(previous, installId)) {
      agent = previous;
    }
    if (!agent && incoming.machineName) {
      const matches = this._agentsForHost(incoming);
      const claimable = matches.filter((match) => this._claimable(match, installId));
      if (claimable.length > 0) {
        agent = this._preferAgent(claimable);
      } else if (matches.length > 0) {
        conflict = this._preferAgent(matches);
      }
    }
    const replaced = Boolean(agent);
    if (agent) {
      agent.installId = installId || agent.installId || "";
      this._collapseHost(agent, remoteIp);
    } else {
      agent = this._getOrCreateAgent(crypto.randomUUID(), remoteIp);
      agent.installId = installId;
    }
    agent.machineName = incoming.machineName;
    agent.osVersion = String(req.osVersion || "").slice(0, 200);
    agent.domainName = incoming.domainName;
    agent.dnsName = incoming.dnsName;
    agent.ipAddresses = Array.isArray(req.ipAddresses) ? req.ipAddresses.map(String).slice(0, 16) : [];
    agent.agentVersion = String(req.agentVersion || "").slice(0, 40);
    agent.serviceMode = String(req.serviceMode || "").slice(0, 40);
    agent.capabilities = Array.isArray(req.capabilities) ? req.capabilities.filter((c) => Catalog[c]) : null;
    agent.apiKeyHash = hashKey(apiKey);
    agent.pendingKeyHash = "";
    agent.rotation = null;
    agent.status = this.requireApproval ? AgentStatuses.PendingApproval : AgentStatuses.Active;
    agent.enrolledUtc = new Date().toISOString();
    this._touch(agent, remoteIp);
    const displayId = padNumber(agent.agentNumber);
    this._communicate(
      agent,
      "Enrolled",
      replaced ? `Existing registration ${displayId} was updated (${agent.status}).` : `Registered as ${displayId} (${agent.status}).`,
      remoteIp
    );
    this.addAudit({
      user: "agent",
      agentId: agent.agentId,
      action: "Enroll",
      result: replaced ? "Updated" : agent.status,
      details: replaced
        ? `${agent.machineName} already existed as ${displayId}; that registration was updated.`
        : `${agent.machineName || "A new host"} registered as ${displayId}.`,
      remoteIp
    });
    if (conflict) {
      const other = padNumber(conflict.agentNumber);
      const detail = `Two computers named ${agent.machineName} are connected at the same time. ${displayId} was registered separately ` +
        `instead of replacing ${other}, so neither disconnects the other. Rename one of them, or remove the record that is no longer needed.`;
      this._communicate(agent, "DuplicateName", detail, remoteIp);
      this._communicate(conflict, "DuplicateName", detail, remoteIp);
      this.recordIssue({ kind: "Registration", remoteIp, agentId: agent.agentId, detail });
    }
    this._emit("agent", { agentId: agent.agentId });
    return {
      agentId: agent.agentId,
      agentNumber: agent.agentNumber,
      displayId,
      apiKey,
      status: agent.status
    };
  }

  // A row can be taken over by its own installation at any time, and by anyone once it is not connected.
  _claimable(agent, installId) {
    if (installId && agent.installId && agent.installId === installId) {
      return true;
    }
    return !this._isOnline(agent);
  }

  _agentsForHost(probe) {
    const matches = [];
    for (const agent of this.agents.values()) {
      if (sameHost(probe, agent)) {
        matches.push(agent);
      }
    }
    return matches;
  }

  _preferAgent(matches) {
    return matches.slice().sort((a, b) => {
      const seen = recentStamp(b) - recentStamp(a);
      if (seen !== 0) {
        return seen;
      }
      return b.agentNumber - a.agentNumber;
    })[0];
  }

  // Drops every other row for this computer. The caller chooses which row survives.
  _collapseHost(keep, remoteIp) {
    if (!keep || !this.agents.has(keep.agentId)) {
      return keep;
    }
    // Rows of a different installation are a different computer with the same name, not a duplicate. A row
    // that is connected right now is a live computer too, even when it is too old to report an install id.
    const extras = this._agentsForHost(keep).filter((agent) => agent.agentId !== keep.agentId &&
      !this._isOnline(agent) &&
      (!agent.installId || agent.installId === keep.installId));
    for (const extra of extras) {
      const displayId = padNumber(extra.agentNumber);
      const machineName = extra.machineName || keep.machineName || "unknown host";
      this._discardAgent(extra.agentId);
      this._emit("removed", { agentId: extra.agentId });
      this._communicate(keep, "Deduplicated", `Replaced duplicate registration ${displayId} for this host.`, remoteIp);
      this.addAudit({
        user: "agent",
        agentId: keep.agentId,
        action: "Enroll",
        result: "Updated",
        details: `Duplicate agent ${displayId} (${machineName}) was replaced by ${padNumber(keep.agentNumber)}.`,
        remoteIp
      });
    }
    if (extras.length > 0) {
      this._emit("agent", { agentId: keep.agentId });
    }
    return keep;
  }

  _collapseAll() {
    const seen = new Set();
    for (const agent of [...this.agents.values()]) {
      if (seen.has(agent.agentId) || !this.agents.has(agent.agentId)) {
        continue;
      }
      const matches = this._agentsForHost(agent);
      matches.forEach((match) => seen.add(match.agentId));
      this._collapseHost(this._preferAgent(matches), "");
    }
  }

  _discardAgent(agentId) {
    this.agents.delete(agentId);
    this.reports.delete(agentId);
    this.pending.delete(agentId);
    this.history.delete(agentId);
    this.inventory.delete(agentId);
    this.requests.delete(agentId);
    this.presence.delete(agentId);
    this.connectionStates.delete(agentId);
    this.connections.delete(agentId);
    this._wake(agentId);
    this._mark();
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

  // Proves to an agent that this manager holds its credential, without the agent sending it: an HMAC,
  // keyed by the stored hash of the agent's key, over the agent's nonce and the names this manager
  // answers to. Someone relaying the request to the real manager learns only the real manager's names.
  managerProof(agentId, nonce, hosts) {
    const agent = this.agents.get(agentId);
    if (!agent || !agent.apiKeyHash || agent.status === AgentStatuses.Revoked) {
      return null;
    }
    const message = `${nonce}\n${hosts.join(",")}`;
    const sign = (keyHash) => crypto.createHmac("sha256", Buffer.from(keyHash, "utf8")).update(message, "utf8").digest("hex");
    return [agent.apiKeyHash, agent.pendingKeyHash].filter(Boolean).map(sign);
  }

  // Returns a one-time new credential to hand to the agent in its next heartbeat response.
  _takeRotation(agent, remoteIp) {
    if (!agent.rotation || agent.rotation.delivered) {
      return null;
    }
    const plain = agent.rotation.plain;
    agent.rotation.delivered = true;
    agent.rotation.plain = null;
    agent.pendingKeyHash = agent.rotation.hash;
    this._communicate(agent, "KeyRotated", "Delivered a rotated credential; waiting for the agent to adopt it.", remoteIp);
    return plain;
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
    this._emit("agent", { agentId });
    this._wake(agentId);
    return true;
  }

  removeAgent(agentId, user, origin, outcome) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return false;
    }
    const displayId = padNumber(agent.agentNumber);
    const machineName = agent.machineName;
    const auditEntry = {
      user: user ? user.name : "agent",
      agentId: null,
      agentDisplayId: displayId,
      machineName: machineName || "",
      action: (outcome && outcome.action) || "Deregister",
      result: (outcome && outcome.result) || "Removed",
      details: (outcome && outcome.details) || `Agent ${displayId} (${machineName || "unknown host"}) was removed (${origin}).`
    };
    this._discardAgent(agentId);
    this._emit("removed", { agentId });
    this.addAudit(auditEntry);
    return true;
  }

  // --- Agent removal: uninstall on the computer, then remove from the portal once verified ------

  removalOf(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent || !agent.removal) {
      return null;
    }
    const r = agent.removal;
    const record = r.commandId ? (this.history.get(agentId) || []).find((h) => h.command.commandId === r.commandId) : null;
    return {
      state: r.state,
      detail: r.detail || "",
      requestedBy: r.requestedBy,
      requestedUtc: r.requestedUtc,
      updatedUtc: r.updatedUtc,
      reason: r.reason || "",
      commandId: r.commandId || null,
      commandStatus: record ? this._status(record) : null
    };
  }

  requestRemoval(agentId, user, reason) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return null;
    }
    const now = new Date().toISOString();
    const command = {
      commandId: crypto.randomUUID(),
      samAccountName: "",
      commandType: "UninstallAgent",
      newPassword: null,
      createdUtc: now,
      accountSource: null
    };
    const online = this._isOnline(agent);
    agent.removal = {
      state: RemovalStates.Queued,
      detail: online
        ? "The uninstall command was sent to the agent."
        : "The agent is offline. The uninstall runs when it reconnects; the agent stays listed until removal is verified.",
      requestedBy: user.name,
      requestedUtc: now,
      updatedUtc: now,
      reason: reason || "",
      commandId: command.commandId
    };
    this.enqueue(agentId, command, user, reason ? `Remove agent: ${reason}` : "Remove agent");
    this._communicate(agent, "Removal", `Removal requested by ${user.name}.`, agent.remoteIp);
    this._emit("agent", { agentId });
    return this.removalOf(agentId);
  }

  _setRemoval(agent, state, detail) {
    if (!agent.removal) {
      return;
    }
    this._mark();
    agent.removal.state = state;
    agent.removal.detail = detail;
    agent.removal.updatedUtc = new Date().toISOString();
    this._emit("agent", { agentId: agent.agentId });
  }

  // Withdraws a removal that has not started on the computer, or clears one that failed.
  cancelRemoval(agentId, user) {
    const agent = this.agents.get(agentId);
    if (!agent || !agent.removal) {
      return { ok: false, error: "No removal is in progress for this agent." };
    }
    const r = agent.removal;
    if (r.state === RemovalStates.Uninstalling) {
      return { ok: false, error: "The uninstaller is already running on the computer and cannot be cancelled." };
    }
    const queue = this.pending.get(agentId) || [];
    const stillQueued = queue.some((c) => c.commandId === r.commandId);
    const record = (this.history.get(agentId) || []).find((h) => h.command.commandId === r.commandId);
    if (r.state === RemovalStates.Queued && !stillQueued && record && record.status === CommandStatuses.Delivered) {
      return { ok: false, error: "The agent already received the uninstall command. Wait for its result." };
    }
    if (stillQueued) {
      this.pending.set(agentId, queue.filter((c) => c.commandId !== r.commandId));
    }
    if (record && (record.status === CommandStatuses.Pending || record.status === CommandStatuses.Delivered)) {
      record.status = CommandStatuses.Failed;
      record.executedUtc = new Date().toISOString();
      record.resultMessage = `Cancelled by ${user.name}.`;
      this._emit("command", { agentId, commandId: r.commandId });
    }
    agent.removal = null;
    this._mark();
    this.addAudit({ user: user.name, agentId, action: "RemoveAgent", result: "Cancelled", details: "Agent removal was cancelled." });
    this._emit("agent", { agentId });
    return { ok: true };
  }

  _onUninstallResult(agent, result, success, message) {
    if (!agent.removal || agent.removal.commandId !== result.commandId) {
      return;
    }
    if (success) {
      this._setRemoval(agent, RemovalStates.Uninstalling, "The uninstaller is running on the computer. The agent is removed from the portal when it reports the verified result.");
    } else {
      this._setRemoval(agent, RemovalStates.Failed, `The agent could not start the uninstall: ${message || "no detail reported"}.`);
      this.addAudit({ user: agent.removal.requestedBy, agentId: agent.agentId, action: "RemoveAgent", result: "Failed", details: agent.removal.detail });
    }
  }

  // Called by the uninstaller on the computer once the service and files are gone.
  completeRemoval(agentId, report) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return false;
    }
    const body = report && typeof report === "object" ? report : {};
    const list = (v) => (Array.isArray(v) ? v.map((x) => text(x, 300)).filter(Boolean).slice(0, 20) : []);
    const removed = list(body.removed);
    const issues = list(body.issues);
    const requested = agent.removal;
    const by = requested ? `requested by ${requested.requestedBy}` : "started on the computer";
    let outcome;
    if (body.verified === true) {
      outcome = { action: "AgentUninstalled", result: "Succeeded", details: `Agent ${padNumber(agent.agentNumber)} (${agent.machineName || "unknown host"}) was uninstalled and verified (${by}). Removed: ${removed.join(", ") || "agent components"}.` };
    } else if (body.verified === false) {
      outcome = { action: "AgentUninstalled", result: "Warning", details: `Agent ${padNumber(agent.agentNumber)} (${agent.machineName || "unknown host"}) was uninstalled with warnings (${by}): ${issues.join(" ") || "no detail"}` };
    } else {
      outcome = { action: "Deregister", result: "Removed", details: `Agent ${padNumber(agent.agentNumber)} (${agent.machineName || "unknown host"}) deregistered during uninstall (${by}). This agent version does not report verification.` };
    }
    return this.removeAgent(agentId, requested ? { name: requested.requestedBy } : null, "agent uninstall", outcome);
  }

  _checkRemoval(agent) {
    const r = agent.removal;
    if (!r) {
      return;
    }
    const age = Date.now() - new Date(r.updatedUtc).getTime();
    if (r.state === RemovalStates.Uninstalling && age > UNINSTALL_CONFIRM_MS) {
      this._setRemoval(agent, RemovalStates.Unverified, "The uninstaller started but never reported a verified result. Check the computer, then remove the record or try again.");
      this.addAudit({ user: r.requestedBy, agentId: agent.agentId, action: "RemoveAgent", result: "Warning", details: r.detail });
    } else if (r.state === RemovalStates.Queued) {
      const record = (this.history.get(agent.agentId) || []).find((h) => h.command.commandId === r.commandId);
      if (record && this._status(record) === CommandStatuses.TimedOut) {
        this._setRemoval(agent, RemovalStates.Unverified, "The agent received the uninstall command but never reported a result.");
      }
    }
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
    this._touchPresence(agent, remoteIp);
  }

  // Contact time and source address only. These change on every heartbeat and poll and are re-learned
  // within seconds of a restart, so they are saved at most once a minute (PRESENCE_SAVE_MS) instead of
  // forcing a rewrite of the whole state file every few seconds.
  _touchPresence(agent, remoteIp) {
    this._presenceDirty = true;
    agent.lastContactUtc = new Date().toISOString();
    if (remoteIp) {
      agent.remoteIp = remoteIp;
    }
    this._checkPresence(agent);
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

  // Records an enrolled agent's heartbeat and system info.
  upsertHeartbeat(agentId, hb, remoteIp) {
    const agent = this._getOrCreateAgent(agentId, remoteIp);
    const wasOnline = this._isOnline(agent);
    const before = Store.heartbeatSignature(agent);
    agent.machineName = text(hb.machineName, 200) || agent.machineName;
    agent.osVersion = text(hb.osVersion, 200) || agent.osVersion;
    agent.domainName = text(hb.domainName, 200);
    agent.dnsName = text(hb.dnsName, 253) || agent.dnsName || "";
    agent.ipAddresses = Array.isArray(hb.ipAddresses) ? hb.ipAddresses.slice(0, 16).map((ip) => text(ip, 64)) : agent.ipAddresses;
    agent.uptime = text(hb.uptime, 100);
    agent.agentVersion = text(hb.agentVersion, 40) || agent.agentVersion || "";
    agent.serviceMode = text(hb.serviceMode, 40) || agent.serviceMode || "";
    agent.capabilities = Array.isArray(hb.capabilities) ? hb.capabilities.filter((c) => Catalog[c]) : agent.capabilities;
    agent.features = Array.isArray(hb.capabilities) ? hb.capabilities.filter((c) => Features.includes(c)) : (agent.features || []);
    agent.pollIntervalSeconds = Number(hb.pollIntervalSeconds) || agent.pollIntervalSeconds;
    agent.commandPollSeconds = Number(hb.commandPollSeconds) || 0;
    agent.heartbeatSeconds = Number(hb.heartbeatSeconds) || agent.heartbeatSeconds || null;
    agent.integrity = Store.normalizeIntegrity(hb.integrity) || agent.integrity || null;
    // The address the agent is really using, so a certificate or host change can be checked against the
    // fleet instead of against what the portal assumes they use.
    agent.managerUrl = text(hb.managerUrl, 300) || agent.managerUrl || "";
    // Agents from before 1.5 registered without an installation id; they report it from their first
    // heartbeat after the upgrade.
    if (!agent.installId && INSTALL_ID_PATTERN.test(text(hb.installId, 64))) {
      agent.installId = hb.installId;
    }
    agent.lastHeartbeatUtc = new Date().toISOString();
    const wasStopped = Boolean(agent.serviceStoppedUtc);
    agent.serviceStoppedUtc = null;
    agent.serviceStopDetail = "";
    if (hb.metrics && typeof hb.metrics === "object") {
      this._setInventory(agentId, "system", Store.normalizeMetrics(hb.metrics), null, null);
    }
    this._touchPresence(agent, remoteIp);
    // A steady heartbeat repeats what is already stored; only a real change is worth an immediate save
    // and a scan of the fleet for duplicate rows of this host.
    if (Store.heartbeatSignature(agent) !== before || wasStopped) {
      this._mark();
      this._collapseHost(agent, remoteIp);
    }
    if (agent.removal && agent.removal.state === RemovalStates.Uninstalling &&
        Date.now() - new Date(agent.removal.updatedUtc).getTime() > UNINSTALL_GRACE_MS) {
      this._setRemoval(agent, RemovalStates.Failed, "The agent is still running after the uninstaller started, so the uninstall did not complete. Check the computer or try again.");
      this.addAudit({ user: agent.removal.requestedBy, agentId, action: "RemoveAgent", result: "Failed", details: agent.removal.detail });
    }
    if (!wasOnline || wasStopped) {
      this._communicate(agent, "Heartbeat", wasStopped ? "The uAgent service started again." : "Agent came online.", remoteIp);
    }
    this._emit("agent", { agentId });
    return {
      status: agent.status,
      displayId: padNumber(agent.agentNumber),
      newApiKey: this._takeRotation(agent, remoteIp)
    };
  }

  static heartbeatSignature(agent) {
    return JSON.stringify([
      agent.machineName, agent.osVersion, agent.domainName, agent.dnsName, agent.ipAddresses, agent.agentVersion,
      agent.serviceMode, agent.capabilities, agent.pollIntervalSeconds, agent.commandPollSeconds, agent.heartbeatSeconds,
      agent.integrity, agent.managerUrl, agent.installId, agent.serviceStoppedUtc
    ]);
  }

  saveReport(agentId, report, remoteIp) {
    const agent = this._getOrCreateAgent(agentId, remoteIp);
    const accounts = Array.isArray(report.accounts) ? report.accounts : [];
    const normalizedAccounts = accounts
      .filter((a) => a && text(a.samAccountName, 256).trim())
      .map((a) => Store.normalizeAccount(a));

    const normalized = {
      agentId,
      machineName: text(report.machineName, 200) || agent.machineName || "",
      isDomainJoined: Boolean(report.isDomainJoined),
      timestampUtc: new Date().toISOString(),
      accounts: normalizedAccounts
    };
    this.reports.set(agentId, normalized);

    if (normalized.machineName) {
      agent.machineName = normalized.machineName;
      this._collapseHost(agent, remoteIp);
    }
    agent.reportedDomainJoined = normalized.isDomainJoined;
    this._touch(agent, remoteIp);
    const previous = agent.lastAccountCount;
    agent.lastAccountCount = normalizedAccounts.length;
    if (previous !== normalizedAccounts.length) {
      this._communicate(agent, "Inventory", `Account inventory received (${normalizedAccounts.length} account(s)).`, remoteIp);
    }
    this._emit("accounts", { agentId });
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

  getFeatures(agentId) {
    const agent = this.agents.get(agentId);
    return agent && Array.isArray(agent.features) ? agent.features : [];
  }

  // The newest queued or running action of a type (and account) on an agent; used to refuse duplicates.
  findActiveCommand(agentId, commandType, samAccountName) {
    const history = this.history.get(agentId) || [];
    const name = normName(samAccountName);
    for (let i = history.length - 1; i >= 0; i--) {
      const record = history[i];
      const status = this._status(record);
      if (status !== CommandStatuses.Pending && status !== CommandStatuses.Delivered) {
        continue;
      }
      if (samAccountName !== undefined && normName(record.command.samAccountName) !== name) {
        continue;
      }
      if (commandType && record.command.commandType !== commandType) {
        continue;
      }
      return this._toView(agentId, record);
    }
    return null;
  }

  activeCommands(agentId) {
    return (this.history.get(agentId) || [])
      .filter((r) => {
        const status = this._status(r);
        return status === CommandStatuses.Pending || status === CommandStatuses.Delivered;
      })
      .map((r) => this._toView(agentId, r));
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

  // Lets the deployment engine receive agent results and route command delivery without flooding the
  // per-agent action history or the audit log, which deployments record at the job level instead.
  setDeploymentHandler(handler) {
    this._deploymentHandler = handler;
  }

  // Queues a deployment command (e.g. InstallSoftware or an agent action issued by a job). Unlike
  // enqueue, it does not write an audit entry or an action-history record per target.
  enqueueDeploymentCommand(agentId, command) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return null;
    }
    this._mark();
    const queue = this.pending.get(agentId) || [];
    queue.push(command);
    this.pending.set(agentId, queue);
    this._emit("command", { agentId, commandId: command.commandId });
    this._wake(agentId);
    return command;
  }

  enqueue(agentId, command, user, reason) {
    this._mark();
    const queue = this.pending.get(agentId) || [];
    queue.push(command);
    this.pending.set(agentId, queue);

    const history = this.history.get(agentId) || [];
    history.push({
      command: { ...command, newPassword: null },
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
    this._emit("command", { agentId, commandId: command.commandId });
    this._wake(agentId);
    return command;
  }

  // Agents register through heartbeats; command polls from unknown agents must not create blank records.
  takePendingCommands(agentId, remoteIp) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return [];
    }
    this._touchPresence(agent, remoteIp);
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
    for (const command of queue) {
      this._emit("command", { agentId, commandId: command.commandId });
    }
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
      if (!result || typeof result !== "object") {
        continue;
      }
      const match = [...history].reverse().find((r) => r.command.commandId === result.commandId);
      if (!match) {
        // Deployment commands are not kept in the per-agent history; hand their results to the engine.
        if (this._deploymentHandler && this._deploymentHandler.onResult(agentId, result)) {
          matched += 1;
        }
        continue;
      }
      matched += 1;
      const message = text(result.message, 4000);
      const errorMessage = text(result.errorMessage, 4000);
      match.status = result.success ? CommandStatuses.Success : CommandStatuses.Failed;
      match.executedUtc = text(result.executedUtc, 40) || new Date().toISOString();
      match.resultMessage = (result.success ? message : errorMessage) || message || errorMessage || null;
      if (result.account && typeof result.account === "object" && isAccountCommand(match.command.commandType)) {
        this._applyAccountSnapshot(agentId, match.command, result.account);
      }
      if (match.command.commandType === "UninstallAgent") {
        this._onUninstallResult(agent, result, Boolean(result.success), match.resultMessage);
      }
      this.addAudit({
        user: match.enqueuedBy || "agent",
        agentId,
        samAccountName: match.command.samAccountName,
        action: match.command.commandType,
        result: match.status,
        details: match.resultMessage || (result.success ? "Executed by the agent." : "The agent reported a failure.")
      });
      this._emit("command", { agentId, commandId: match.command.commandId });
    }
    this._communicate(agent, "Results", `Received ${results.length} result(s); ${matched} matched queued actions.`, remoteIp);
  }

  // The agent re-reads the account after a change; the verified state replaces the inventory entry right away
  // so the portal does not wait for the next inventory cycle. Group membership is not part of the snapshot.
  _applyAccountSnapshot(agentId, command, raw) {
    const report = this.reports.get(agentId);
    if (!report || !text(raw.samAccountName, 256).trim()) {
      return;
    }
    const fresh = Store.normalizeAccount(raw);
    const name = normName(fresh.samAccountName);
    const index = report.accounts.findIndex((a) => normName(a.samAccountName) === name &&
      (!command.accountSource || a.source === command.accountSource || a.source === fresh.source));
    if (index < 0) {
      return;
    }
    const current = report.accounts[index];
    report.accounts[index] = {
      ...current,
      displayName: fresh.displayName || current.displayName,
      enabled: fresh.enabled,
      lockedOut: fresh.lockedOut,
      accountExpirationDate: fresh.accountExpirationDate,
      lastPasswordSet: fresh.lastPasswordSet,
      lastLogon: fresh.lastLogon || current.lastLogon,
      badLogonCount: fresh.badLogonCount,
      passwordExpiresUtc: fresh.passwordExpiresUtc,
      passwordNeverExpires: fresh.passwordNeverExpires,
      userCannotChangePassword: fresh.userCannotChangePassword !== null ? fresh.userCannotChangePassword : current.userCannotChangePassword,
      verifiedUtc: new Date().toISOString()
    };
    this._mark();
    this._emit("accounts", { agentId });
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
      accountSource: record.command.accountSource || null,
      commandType: record.command.commandType,
      value: typeof record.command.value === "boolean" ? record.command.value : null,
      label: commandLabel(record.command.commandType, record.command.value),
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
      agentDisplayId: entry.agentDisplayId || (entry.agentId ? this.getDisplayId(entry.agentId) : ""),
      machineName: entry.machineName || (entry.agentId && this.agents.has(entry.agentId) ? this.agents.get(entry.agentId).machineName || "" : ""),
      samAccountName: entry.samAccountName || "",
      action: entry.action,
      result: entry.result,
      details: entry.details || "",
      remoteIp: entry.remoteIp || ""
    });
    if (this.audit.length > this.maxAudit) {
      this.audit.splice(0, this.audit.length - this.maxAudit);
    }
    this._emit("audit", {});
  }

  getAudit(agentId) {
    let entries = this.audit;
    if (agentId) {
      entries = entries.filter((e) => e.agentId && e.agentId === agentId);
    }
    return [...entries]
      .sort((a, b) => new Date(b.timestampUtc) - new Date(a.timestampUtc))
      .map((e) => ({
        ...e,
        agentDisplayId: (e.agentId && this.getDisplayId(e.agentId)) || e.agentDisplayId || "",
        machineName: (e.agentId && this.agents.has(e.agentId) ? this.getMachineName(e.agentId) : "") || e.machineName || ""
      }));
  }

  // Online while a long poll is open, or while the last contact is inside the online window.
  // A reported service stop takes the agent offline immediately.
  _isOnline(agent) {
    if (!agent.lastHeartbeatUtc || !agent.lastContactUtc || agent.serviceStoppedUtc) {
      return false;
    }
    if ((this.connections.get(agent.agentId) || 0) > 0) {
      return true;
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
      passwordExpiredCount: accounts.filter((a) => Store.passwordExpiry(a) === "expired").length,
      criticalCount: accounts.filter((a) => Store.isCritical(a)).length,
      ipAddresses: Array.isArray(agent.ipAddresses) ? agent.ipAddresses : [],
      agentVersion: agent.agentVersion || "",
      managerUrl: agent.managerUrl || "",
      connection: this._connection(agent),
      enrolledUtc: agent.enrolledUtc,
      serviceStopped: Boolean(agent.serviceStoppedUtc),
      integrityOk: agent.integrity ? agent.integrity.healthy : null,
      liveChannel: (this.connections.get(agent.agentId) || 0) > 0,
      removalState: agent.removal ? agent.removal.state : null,
      cpuPercent: this._metric(agent.agentId, "cpuPercent"),
      memoryPercent: this._memoryPercent(agent.agentId)
    };
  }

  _metric(agentId, key) {
    const entry = (this.inventory.get(agentId) || {}).system;
    return entry && entry.data && typeof entry.data[key] === "number" ? entry.data[key] : null;
  }

  _memoryPercent(agentId) {
    const entry = (this.inventory.get(agentId) || {}).system;
    if (!entry || !entry.data || !entry.data.memoryTotalBytes) {
      return null;
    }
    const used = entry.data.memoryTotalBytes - entry.data.memoryAvailableBytes;
    return Math.round((used / entry.data.memoryTotalBytes) * 1000) / 10;
  }

  // Active agents are split by contact:
  //   online        a long poll is open or the agent was heard from inside the online window;
  //   reconnecting  quiet for less than the longest retry backoff, so it is expected back by itself;
  //   disconnected  quiet for longer than that, or its service was reported stopped;
  //   stale         not heard from for staleAfterMs (retired, powered off, or removed locally);
  //   offline       enrolled but never checked in.
  // Pending and revoked are their own states.
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
    if (this._isOnline(agent)) {
      return "online";
    }
    const quiet = Date.now() - (Date.parse(agent.lastContactUtc || agent.lastHeartbeatUtc) || 0);
    if (quiet > this.staleAfterMs) {
      return "stale";
    }
    if (!agent.serviceStoppedUtc && quiet <= this.reconnectWindowMs) {
      return "reconnecting";
    }
    return "disconnected";
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
        passwordExpired: accounts.filter((a) => Store.passwordExpiry(a) === "expired").length,
        critical: accounts.filter((a) => Store.isCritical(a)).length
      },
      communication: agent.communication.slice(0, 50),
      heartbeatSeconds: agent.heartbeatSeconds || null,
      features: Array.isArray(agent.features) ? agent.features : [],
      integrity: agent.integrity || null,
      serviceStoppedUtc: agent.serviceStoppedUtc || null,
      serviceStopDetail: agent.serviceStopDetail || "",
      openPolls: this.connections.get(agentId) || 0,
      removal: this.removalOf(agentId),
      inventoryStatus: this.inventoryStatus(agentId)
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
        else if (expiry !== "disabled") { accounts.passwordReported += 1; }
        if (expiry === "expired") { accounts.passwordExpired += 1; }
        if (expiry === "warning") { accounts.passwordWarning += 1; }
      }
    }
    return {
      totalAgents: agents.length,
      activeAgents: agents.filter((a) => a.status === AgentStatuses.Active).length,
      onlineAgents: agents.filter((a) => a.connection === "online").length,
      reconnectingAgents: agents.filter((a) => a.connection === "reconnecting").length,
      disconnectedAgents: agents.filter((a) => a.connection === "disconnected").length,
      staleAgents: agents.filter((a) => a.connection === "stale").length,
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

  // --- Long-poll delivery ---------------------------------------------------------------------

  _wake(agentId) {
    const set = this.waiters.get(agentId);
    if (set) {
      for (const wake of [...set]) {
        wake();
      }
    }
  }

  // Resolves as soon as work is queued for the agent, or after waitMs. cancel() releases it early.
  waitForWork(agentId, waitMs) {
    let wake;
    let timer;
    const promise = new Promise((resolve) => {
      wake = () => resolve(true);
      timer = setTimeout(() => resolve(false), waitMs);
    });
    const set = this.waiters.get(agentId) || new Set();
    set.add(wake);
    this.waiters.set(agentId, set);
    const cleanup = () => {
      clearTimeout(timer);
      set.delete(wake);
      if (set.size === 0) {
        this.waiters.delete(agentId);
      }
    };
    return { promise: promise.finally(cleanup), cancel: () => { wake(); } };
  }

  hasWork(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent || agent.status !== AgentStatuses.Active) {
      return false;
    }
    return (this.pending.get(agentId) || []).length > 0 || (this.requests.get(agentId) || []).length > 0;
  }

  pollOpened(agentId, remoteIp) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return;
    }
    this.connections.set(agentId, (this.connections.get(agentId) || 0) + 1);
    this._touchPresence(agent, remoteIp);
    this._checkPresence(agent);
  }

  pollClosed(agentId) {
    const open = (this.connections.get(agentId) || 1) - 1;
    if (open <= 0) {
      this.connections.delete(agentId);
    } else {
      this.connections.set(agentId, open);
    }
    const agent = this.agents.get(agentId);
    if (agent) {
      agent.lastContactUtc = new Date().toISOString();
    }
  }

  // Hands queued actions and inventory requests to the agent. Nothing is released before approval.
  takeWork(agentId, remoteIp) {
    const agent = this.agents.get(agentId);
    if (!agent || agent.status !== AgentStatuses.Active) {
      return { commands: [], requests: [] };
    }
    const commands = this.takePendingCommands(agentId, remoteIp);
    const requests = this.requests.get(agentId) || [];
    this.requests.set(agentId, []);
    return {
      commands,
      requests: requests.map((r) => ({ requestId: r.requestId, section: r.section, path: r.path || null }))
    };
  }

  // Asks the agent for a fresh copy of one inventory section. Identical outstanding requests are reused.
  requestInventory(agentId, section, requestPath) {
    if (!INVENTORY_SECTIONS.includes(section)) {
      return null;
    }
    const queue = this.requests.get(agentId) || [];
    const pathKey = requestPath || null;
    const existing = queue.find((r) => r.section === section && (r.path || null) === pathKey);
    if (existing) {
      return existing.requestId;
    }
    const request = { requestId: crypto.randomUUID(), section, path: pathKey, createdUtc: new Date().toISOString() };
    queue.push(request);
    this.requests.set(agentId, queue.slice(-20));
    this._wake(agentId);
    return request.requestId;
  }

  _setInventory(agentId, section, data, error, requestId, collectedUtc) {
    const sections = this.inventory.get(agentId) || {};
    sections[section] = {
      data,
      error: error || null,
      requestId: requestId || null,
      collectedUtc: collectedUtc || new Date().toISOString(),
      receivedUtc: new Date().toISOString()
    };
    this.inventory.set(agentId, sections);
    this._emit("inventory", { agentId, section, requestId: requestId || null });
  }

  saveInventory(agentId, upload, remoteIp) {
    const agent = this.agents.get(agentId);
    if (!agent || !upload || !INVENTORY_SECTIONS.includes(upload.section)) {
      return false;
    }
    this._touch(agent, remoteIp);
    const section = upload.section;
    const error = upload.error ? String(upload.error).slice(0, 500) : null;
    const data = error ? null : Store.normalizeSection(section, upload.data);
    this._setInventory(agentId, section, data, error, upload.requestId ? String(upload.requestId) : null, upload.collectedUtc);
    return true;
  }

  getInventory(agentId, section) {
    const entry = (this.inventory.get(agentId) || {})[section];
    return entry || null;
  }

  inventoryStatus(agentId) {
    const sections = this.inventory.get(agentId) || {};
    const status = {};
    for (const name of INVENTORY_SECTIONS) {
      const entry = sections[name];
      status[name] = entry ? { receivedUtc: entry.receivedUtc, error: entry.error } : null;
    }
    return status;
  }

  // --- Agent lifecycle events -----------------------------------------------------------------

  recordAgentEvent(agentId, event, remoteIp) {
    const agent = this.agents.get(agentId);
    if (!agent || !event) {
      return;
    }
    const kind = String(event.kind || "");
    const detail = String(event.detail || "").slice(0, 2000);
    this._touch(agent, remoteIp);
    if (kind === "ServiceStopping") {
      agent.serviceStoppedUtc = new Date().toISOString();
      agent.serviceStopDetail = detail;
      this.connections.delete(agentId);
      this._communicate(agent, "Stopped", detail || "The uAgent service stopped.", remoteIp);
      this.addAudit({ user: "agent", agentId, action: "ServiceStopped", result: "Stopped", details: detail, remoteIp });
    } else if (kind === "TamperDetected") {
      agent.lastTamperUtc = new Date().toISOString();
      this._communicate(agent, "Integrity", detail, remoteIp);
      this.addAudit({ user: "agent", agentId, action: "TamperDetected", result: "Warning", details: detail, remoteIp });
    } else if (kind === "ManagerAddressChanged") {
      agent.managerUrl = detail;
      this._communicate(agent, "Address", detail, remoteIp);
      this.addAudit({ user: "agent", agentId, action: "AgentAddressChanged", result: "Success", details: detail, remoteIp });
    } else if (kind === "Uninstalling") {
      this._communicate(agent, "Uninstall", detail || "The agent is uninstalling.", remoteIp);
      this.addAudit({ user: "agent", agentId, action: "Uninstalling", result: "Pending", details: detail, remoteIp });
    } else if (kind === "UninstallFailed") {
      this._communicate(agent, "Uninstall", detail || "The uninstall failed.", remoteIp);
      if (agent.removal) {
        this._setRemoval(agent, RemovalStates.Failed, detail || "The uninstaller reported a failure.");
      }
      this.addAudit({ user: "agent", agentId, action: "AgentUninstalled", result: "Failed", details: detail || "The uninstaller reported a failure.", remoteIp });
    } else {
      return;
    }
    this._checkPresence(agent);
    this._emit("agent", { agentId });
  }

  _checkPresence(agent) {
    const online = this._isOnline(agent);
    const before = this.presence.get(agent.agentId);
    const state = this._connection(agent);
    const stateBefore = this.connectionStates.get(agent.agentId);
    this.connectionStates.set(agent.agentId, state);
    if (before === online) {
      // Reconnecting, disconnected and stale are reached by time alone; the live view still needs them.
      if (stateBefore !== undefined && stateBefore !== state) {
        this._emit("agent", { agentId: agent.agentId });
      }
      return;
    }
    this.presence.set(agent.agentId, online);
    if (before !== undefined) {
      if (!online && !agent.serviceStoppedUtc) {
        this._communicate(agent, "Disconnected", "The agent stopped communicating.", agent.remoteIp);
      }
      this._emit("agent", { agentId: agent.agentId });
    }
  }

  // Called every few seconds so the live view learns about agents that went silent.
  sweepPresence() {
    for (const agent of this.agents.values()) {
      this._checkPresence(agent);
      this._checkRemoval(agent);
    }
  }

  // --- Account search -------------------------------------------------------------------------

  // Server-side filtering and paging across every agent's latest inventory.
  queryAccounts(options) {
    const opts = options || {};
    const q = String(opts.q || "").trim().toLowerCase();
    const state = String(opts.state || "");
    const agentFilter = opts.agent ? this.resolveAgentId(String(opts.agent)) || String(opts.agent) : "";
    const source = opts.source === "Local" || opts.source === "Domain" ? opts.source : "";
    const pageSize = Math.min(Math.max(Number.parseInt(opts.pageSize, 10) || 50, 10), 500);
    const sort = ["machine", "account", "lastLogon", "passwordSet", "badLogons"].includes(opts.sort) ? opts.sort : "machine";
    const dir = opts.dir === "desc" ? -1 : 1;

    const counts = { total: 0, attention: 0, locked: 0, disabled: 0, local: 0, domain: 0 };
    const agents = [];
    const rows = [];
    for (const [agentId, report] of this.reports) {
      const agent = this.agents.get(agentId);
      if (!agent) {
        continue;
      }
      const displayId = padNumber(agent.agentNumber);
      const online = this._isOnline(agent) && agent.status === AgentStatuses.Active;
      agents.push({ agentId, displayId, machineName: report.machineName || agent.machineName || "", accountCount: report.accounts.length });
      if (agentFilter && agentId !== agentFilter) {
        continue;
      }
      for (const account of report.accounts) {
        counts.total += 1;
        if (Store.isCritical(account)) { counts.attention += 1; }
        if (account.lockedOut) { counts.locked += 1; }
        if (!account.enabled) { counts.disabled += 1; }
        if (account.source === "Domain") { counts.domain += 1; } else { counts.local += 1; }
        if (source && account.source !== source) {
          continue;
        }
        if (q && ![account.samAccountName, account.displayName, account.description, (account.groups || []).join(" "), report.machineName]
          .some((value) => value && String(value).toLowerCase().includes(q))) {
          continue;
        }
        if (!Store.matchesState(account, state)) {
          continue;
        }
        rows.push({ agentId, agentDisplayId: displayId, machineName: report.machineName || agent.machineName || "", online, inventoryUtc: report.timestampUtc, account });
      }
    }

    const key = {
      machine: (r) => `${(r.machineName || "").toLowerCase()}\u0000${r.account.samAccountName.toLowerCase()}`,
      account: (r) => `${r.account.samAccountName.toLowerCase()}\u0000${(r.machineName || "").toLowerCase()}`,
      lastLogon: (r) => r.account.lastLogon ? new Date(r.account.lastLogon).getTime() : 0,
      passwordSet: (r) => r.account.lastPasswordSet ? new Date(r.account.lastPasswordSet).getTime() : 0,
      badLogons: (r) => r.account.badLogonCount || 0
    }[sort];
    rows.sort((a, b) => {
      const ka = key(a);
      const kb = key(b);
      return (ka < kb ? -1 : ka > kb ? 1 : 0) * dir;
    });

    const total = rows.length;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    const page = Math.min(Math.max(Number.parseInt(opts.page, 10) || 1, 1), pages);
    agents.sort((a, b) => a.displayId.localeCompare(b.displayId));
    return {
      items: rows.slice((page - 1) * pageSize, page * pageSize).map((r) => ({ ...r, account: Store.accountView(r.account), removalState: this.agents.get(r.agentId).removal ? this.agents.get(r.agentId).removal.state : null })),
      total,
      page,
      pageSize,
      pages,
      counts,
      agents
    };
  }

  // Backpressure for large fleets: when one burst carries many changes of the same type, browsers get a
  // single bulk marker instead of thousands of entries and simply refresh what they display.
  static collapseBatch(batch) {
    const byType = new Map();
    for (const event of batch) {
      byType.set(event.type, (byType.get(event.type) || 0) + 1);
    }
    const out = [];
    const bulked = new Set();
    for (const event of batch) {
      if (byType.get(event.type) > BULK_THRESHOLD) {
        if (!bulked.has(event.type)) {
          bulked.add(event.type);
          out.push({ type: event.type, bulk: true, count: byType.get(event.type) });
        }
      } else {
        out.push(event);
      }
    }
    return out;
  }

  static matchesState(account, state) {
    switch (state) {
      case "Attention": return Store.isCritical(account);
      case "Enabled": return account.enabled;
      case "Disabled": return !account.enabled;
      case "Locked": return account.lockedOut;
      case "Expired": return Store.isAccountExpired(account);
      case "PasswordExpired": return Store.passwordExpiry(account) === "expired";
      case "PasswordWarning": return Store.passwordExpiry(account) === "warning";
      case "PasswordUnset": return !account.lastPasswordSet;
      case "Protected": return Boolean(account.isProtected);
      case "Admins": return (account.groups || []).some((g) => /^administrators$/i.test(g));
      default: return true;
    }
  }

  // --- Payload normalisation ------------------------------------------------------------------

  static normalizeIntegrity(value) {
    if (!value || typeof value !== "object") {
      return null;
    }
    const list = (items) => Array.isArray(items) ? items.map((i) => String(i).slice(0, 500)).slice(0, 20) : [];
    return {
      healthy: Boolean(value.healthy),
      executableSha256: String(value.executableSha256 || "").slice(0, 64),
      expectedSha256: String(value.expectedSha256 || "").slice(0, 64),
      signed: Boolean(value.signed),
      startType: String(value.startType || "").slice(0, 40),
      permissionsLocked: Boolean(value.permissionsLocked),
      recoveryConfigured: Boolean(value.recoveryConfigured),
      issues: list(value.issues),
      repaired: list(value.repaired),
      checkedUtc: value.checkedUtc || null
    };
  }

  static normalizeMetrics(m) {
    const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : 0);
    return {
      cpuPercent: num(m.cpuPercent),
      memoryTotalBytes: num(m.memoryTotalBytes),
      memoryAvailableBytes: num(m.memoryAvailableBytes),
      processCount: num(m.processCount),
      threadCount: num(m.threadCount),
      handleCount: num(m.handleCount),
      uptime: String(m.uptime || ""),
      logicalProcessors: num(m.logicalProcessors),
      architecture: String(m.architecture || ""),
      osVersion: String(m.osVersion || ""),
      manufacturer: String(m.manufacturer || ""),
      model: String(m.model || ""),
      collectedUtc: m.collectedUtc || new Date().toISOString(),
      disks: Array.isArray(m.disks) ? m.disks.slice(0, 26).map((d) => ({
        name: String(d.name || ""),
        label: String(d.label || ""),
        format: String(d.format || ""),
        totalBytes: num(d.totalBytes),
        freeBytes: num(d.freeBytes)
      })) : []
    };
  }

  static normalizeSection(section, data) {
    const str = (v, max) => (v === null || v === undefined ? null : String(v).slice(0, max || 500));
    const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
    const limit = INVENTORY_LIMITS[section] || 5000;
    switch (section) {
      case "system":
        return Store.normalizeMetrics(data || {});
      case "processes":
        return (Array.isArray(data) ? data : []).slice(0, limit).map((p) => ({
          pid: num(p.pid), name: str(p.name, 260), cpuPercent: num(p.cpuPercent) || 0,
          workingSetBytes: num(p.workingSetBytes) || 0, privateBytes: num(p.privateBytes) || 0,
          threads: num(p.threads) || 0, handles: num(p.handles) || 0, sessionId: num(p.sessionId) || 0,
          startedUtc: str(p.startedUtc, 40), path: str(p.path, 1024)
        }));
      case "services":
        return (Array.isArray(data) ? data : []).slice(0, limit).map((s) => ({
          name: str(s.name, 256), displayName: str(s.displayName, 256), status: str(s.status, 40),
          startType: str(s.startType, 40), serviceType: str(s.serviceType, 80), canStop: Boolean(s.canStop)
        }));
      case "applications":
        return (Array.isArray(data) ? data : []).slice(0, limit).map((a) => ({
          name: str(a.name, 300), version: str(a.version, 100), publisher: str(a.publisher, 300),
          installDate: str(a.installDate, 40), sizeBytes: num(a.sizeBytes), scope: str(a.scope, 40),
          installLocation: str(a.installLocation, 1024)
        }));
      case "files": {
        const d = data || {};
        return {
          path: str(d.path, 2048) || "",
          parent: str(d.parent, 2048),
          truncated: Boolean(d.truncated),
          roots: Array.isArray(d.roots) ? d.roots.map((r) => String(r).slice(0, 260)).slice(0, 50) : [],
          entries: (Array.isArray(d.entries) ? d.entries : []).slice(0, limit).map((e) => ({
            name: str(e.name, 260), isDirectory: Boolean(e.isDirectory), sizeBytes: num(e.sizeBytes),
            modifiedUtc: str(e.modifiedUtc, 40), attributes: str(e.attributes, 200)
          }))
        };
      }
      default:
        return null;
    }
  }

  static normalizeAccount(a) {
    return {
      samAccountName: text(a.samAccountName, 256).trim(),
      displayName: text(a.displayName, 256),
      enabled: Boolean(a.enabled),
      lockedOut: Boolean(a.lockedOut),
      accountExpirationDate: a.accountExpirationDate || null,
      lastPasswordSet: a.lastPasswordSet || null,
      lastLogon: a.lastLogon || null,
      badLogonCount: Number(a.badLogonCount) || 0,
      source: a.source === "Domain" ? "Domain" : "Local",
      passwordExpiresUtc: a.passwordExpiresUtc || null,
      passwordNeverExpires: Boolean(a.passwordNeverExpires),
      userCannotChangePassword: typeof a.userCannotChangePassword === "boolean" ? a.userCannotChangePassword : null,
      sid: a.sid ? String(a.sid).slice(0, 200) : "",
      description: a.description ? String(a.description).slice(0, 500) : "",
      groups: Array.isArray(a.groups) ? a.groups.map(String).slice(0, 50) : [],
      isProtected: Boolean(a.isProtected)
    };
  }

  // The derived states every page shows, computed once here so lists, filters, counts and exports agree.
  static accountView(account) {
    return {
      ...account,
      passwordState: Store.passwordExpiry(account),
      accountExpired: Store.isAccountExpired(account),
      critical: Store.isCritical(account)
    };
  }

  static isAccountExpired(account) {
    return Boolean(account.accountExpirationDate) && new Date(account.accountExpirationDate) < new Date();
  }

  // "unreported" means the agent did not send a password-expiry timestamp. Callers must not treat that as zero expired passwords.
  // A disabled account cannot sign in, so its password is never reported as expired or expiring.
  static passwordExpiry(account) {
    if (!account.enabled) {
      return "disabled";
    }
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
    this._timer = setInterval(() => this.flush(), 3000);
    if (this._timer.unref) {
      this._timer.unref();
    }
  }

  /**
   * Clears the records the portal holds in memory as well as on disk.
   *
   * Deleting the state file alone is not a reset: this store flushes every few seconds, so the file comes
   * straight back. The caller has already taken a verified backup.
   *
   * @param {object} options `{ keepAudit }` keeps the audit log, which is the default everywhere in the
   *                         Danger Zone because it is security evidence.
   */
  // options.keepAudit (default true): keep the audit log and download history.
  // options.keepAgents: clear only the audit log; agent records stay.
  // options.keepRemovals: agents with an uninstall on its way keep their record, queue and history, so
  //   the uninstall still reaches them and is verified; everything else is cleared.
  resetData(options) {
    const opts = options || {};
    const keepAudit = opts.keepAudit !== false;
    const audit = keepAudit ? this.audit : [];
    const downloads = keepAudit ? this.downloads : [];
    if (opts.keepAgents) {
      this.audit = audit;
      this.downloads = downloads;
      this._dirty = true;
      this.flush();
      return { keptAudit: keepAudit, auditEntries: this.audit.length, keptAgents: this.agents.size };
    }
    const kept = new Set(opts.keepRemovals
      ? [...this.agents.values()].filter((agent) => agent.removal && agent.removal.state !== "Failed").map((agent) => agent.agentId)
      : []);
    for (const agentId of [...this.waiters.keys()]) {
      if (!kept.has(agentId)) {
        this._wake(agentId);
      }
    }
    for (const map of [this.agents, this.reports, this.pending, this.history, this.connections, this.presence, this.connectionStates, this.inventory, this.requests]) {
      for (const key of [...map.keys()]) {
        if (!kept.has(key)) {
          map.delete(key);
        }
      }
    }
    if (kept.size === 0) {
      this.nextAgentNumber = 1;
    }
    this.audit = audit;
    this.downloads = downloads;
    this.issues = [];
    this._dirty = true;
    this.flush();
    this._emit("agent", {});
    return { keptAudit: keepAudit, auditEntries: this.audit.length };
  }

  // Stops saving for good, for when the state files have been replaced underneath the running portal.
  detachPersistence() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    this._stateFile = "";
  }

  flush(force) {
    if (!this._stateFile) {
      return;
    }
    const presenceDue = this._presenceDirty && (force || Date.now() - (this._savedAt || 0) >= PRESENCE_SAVE_MS);
    if (!this._dirty && !presenceDue) {
      return;
    }
    const payload = {
      schemaVersion: STATE_SCHEMA_VERSION,
      nextAgentNumber: this.nextAgentNumber,
      // An undelivered rotated credential is plaintext; it is kept in memory only.
      agents: [...this.agents.entries()].map(([id, agent]) => [id, agent.rotation
        ? { ...agent, rotation: { ...agent.rotation, plain: null } }
        : agent]),
      reports: [...this.reports.entries()],
      // Queued password resets carry the new password; they are kept in memory only.
      pending: [...this.pending.entries()].map(([id, queue]) => [id, queue.filter((c) => !c.newPassword)]),
      history: [...this.history.entries()],
      audit: this.audit,
      downloads: this.downloads,
      issues: this.issues
    };
    try {
      writeJson(this._stateFile, payload);
      this._dirty = false;
      this._presenceDirty = false;
      this._savedAt = Date.now();
      if (this._flushError) {
        this.logger(`Portal state is being saved to ${this._stateFile} again.`);
        this._flushError = "";
      }
    } catch (error) {
      // Keep the in-memory copy; the next interval tries again. Log each distinct failure once.
      if (this._flushError !== error.message) {
        this._flushError = error.message;
        this.logger(`Could not save portal state to ${this._stateFile}: ${error.message}`);
      }
    }
  }

  _loadState() {
    const payload = readJson(this._stateFile);
    if (!payload || !Array.isArray(payload.agents)) {
      return;
    }
    // Every schema change so far only adds fields, so an older portal can still read this file after a
    // rollback. Before the first save in a new schema the original is copied aside all the same.
    const version = Number(payload.schemaVersion) || 1;
    if (version !== STATE_SCHEMA_VERSION) {
      const copy = `${this._stateFile}.schema${version}-${new Date().toISOString().replace(/[:.]/g, "-")}.bak`;
      try {
        fs.copyFileSync(this._stateFile, copy);
        fs.chmodSync(copy, 0o600);
        this.logger(version > STATE_SCHEMA_VERSION
          ? `The portal state was written by a newer portal (schema ${version}); a copy was kept at ${copy} before this version saves it.`
          : `Upgrading the portal state from schema ${version} to ${STATE_SCHEMA_VERSION}; the original was kept at ${copy}.`);
      } catch (error) {
        this.logger(`Could not keep a copy of the portal state before upgrading it: ${error.message}`);
      }
    }
    this.agents = new Map(payload.agents.filter((entry) => Array.isArray(entry) && entry[1] && typeof entry[1] === "object"));
    const highest = Math.max(0, ...[...this.agents.values()].map((agent) => Number(agent.agentNumber) || 0));
    this.nextAgentNumber = Math.max(Number(payload.nextAgentNumber) || 1, highest + 1);
    this.reports = new Map(Array.isArray(payload.reports) ? payload.reports : []);
    this.pending = new Map(Array.isArray(payload.pending) ? payload.pending : []);
    this.history = new Map(Array.isArray(payload.history) ? payload.history : []);
    this.audit = Array.isArray(payload.audit) ? payload.audit : [];
    this.downloads = Array.isArray(payload.downloads) ? payload.downloads : [];
    this.issues = Array.isArray(payload.issues) ? payload.issues : [];
    const queued = new Set();
    for (const [agentId, queue] of this.pending) {
      const commands = Array.isArray(queue) ? queue.filter((c) => c && c.commandId) : [];
      this.pending.set(agentId, commands);
      commands.forEach((c) => queued.add(c.commandId));
    }
    let changed = false;
    for (const [agentId, history] of this.history) {
      const records = Array.isArray(history) ? history.filter((record) => record && record.command) : [];
      this.history.set(agentId, records);
      for (const record of records) {
        record.command.newPassword = null;
        if (record.status === CommandStatuses.Pending && !queued.has(record.command.commandId)) {
          record.status = CommandStatuses.Failed;
          record.resultMessage = "The portal restarted before the agent collected this action. Queue it again.";
          changed = true;
        }
      }
    }
    for (const agent of this.agents.values()) {
      if (!Array.isArray(agent.communication)) {
        agent.communication = [];
      }
      if (typeof agent.installId !== "string") {
        agent.installId = "";
      }
      if (agent.rotation && !agent.rotation.delivered && !agent.rotation.plain) {
        agent.rotation = null;
        this._communicate(agent, "KeyRotated", "The portal restarted before the rotated credential was delivered. Rotate the key again.", agent.remoteIp);
        changed = true;
      }
    }
    const before = this.agents.size;
    this._collapseAll();
    this._dirty = changed || this.agents.size !== before || version !== STATE_SCHEMA_VERSION;
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
