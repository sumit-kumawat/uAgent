"use strict";

// Operator-facing JSON API used by the portal pages. Requires the session cookie.
const express = require("express");
const crypto = require("crypto");
const Store = require("../lib/store");
const { Catalog, Roles, roleAllows, isKnown, requiresNewPassword, isAccountCommand } = require("../lib/commandTypes");

module.exports = function portalApi(store, auth, config, urlCatalog, logger, installer, hostSettings) {
  const router = express.Router();
  router.use(auth.requireApi);
  router.use((req, res, next) => {
    if (req.session.user && req.session.user.mustChangePassword) {
      return res.status(403).json({ error: "Change the initial password before using the portal.", code: "password_change_required" });
    }
    return next();
  });

  function resolve(req, res) {
    const agentId = store.resolveAgentId(req.params.agentId);
    if (!agentId) {
      res.status(404).json({ error: "No agent with that id has enrolled with this portal.", code: "not_found" });
      return null;
    }
    return agentId;
  }

  // Per-control availability for the signed-in user on one agent, with the reason when unavailable.
  function controlsFor(agentId, role) {
    const capabilities = new Set(store.capabilitiesOf(agentId));
    const online = store.isOnline(agentId);
    return Object.keys(Catalog).map((type) => {
      const meta = Catalog[type];
      let state = "available";
      let reason = "";
      if (!roleAllows(role, meta.minRole)) {
        state = "forbidden";
        reason = `Requires the ${meta.minRole} role.`;
      } else if (!capabilities.has(type)) {
        state = "unsupported";
        reason = "This agent does not support this action on its operating system or run mode.";
      } else if (!online) {
        state = "offline";
        reason = "The agent is offline. Actions are available again when it reconnects.";
      }
      return { type, ...meta, state, reason };
    });
  }

  router.get("/me", (req, res) => {
    const user = req.session.user;
    res.json({
      name: user.name,
      role: user.role,
      catalog: Object.keys(Catalog).map((type) => ({ type, ...Catalog[type], allowed: roleAllows(user.role, Catalog[type].minRole) }))
    });
  });

  router.get("/agents", (req, res) => {
    res.json(store.listAgents());
  });

  router.get("/agents/:agentId", (req, res) => {
    const agentId = resolve(req, res);
    if (!agentId) {
      return;
    }
    const report = store.getReport(agentId);
    res.json({
      agent: store.getAgentDetail(agentId),
      accounts: report ? report.accounts : [],
      controls: controlsFor(agentId, req.session.user.role),
      commands: store.getCommandHistory(agentId).slice(0, 200),
      audit: store.getAudit(agentId).slice(0, 200)
    });
  });

  router.get("/agents/:agentId/accounts", (req, res) => {
    const agentId = resolve(req, res);
    if (!agentId) {
      return;
    }
    const report = store.getReport(agentId);
    if (!report) {
      return res.status(404).json({ error: "No account report has been received for this agent." });
    }
    res.json(report);
  });

  router.get("/agents/:agentId/commands-history", (req, res) => {
    const agentId = resolve(req, res);
    if (agentId) {
      res.json(store.getCommandHistory(agentId));
    }
  });

  router.get("/agents/:agentId/commands/:commandId", (req, res) => {
    const agentId = resolve(req, res);
    if (!agentId) {
      return;
    }
    const command = store.getCommand(agentId, req.params.commandId);
    if (!command) {
      return res.status(404).json({ error: "Command not found." });
    }
    res.json(command);
  });

  router.get("/agents/:agentId/audit", (req, res) => {
    const agentId = resolve(req, res);
    if (agentId) {
      res.json(store.getAudit(agentId));
    }
  });

  // Role checks happen inside the handler (every action needs at least Operator) so denials are audited.
  router.post("/agents/:agentId/commands", (req, res) => {
    const agentId = resolve(req, res);
    if (!agentId) {
      return;
    }
    const user = req.session.user;
    const body = req.body || {};
    const commandType = String(body.commandType || "").trim();
    const samAccountName = String(body.samAccountName || "").trim();
    const reason = String(body.reason || "").trim().slice(0, 500);

    function reject(status, code, error, auditResult) {
      store.addAudit({
        user: user.name,
        agentId,
        samAccountName,
        action: commandType || "Unknown",
        result: auditResult,
        details: error,
        remoteIp: req.ip
      });
      return res.status(status).json({ error, code });
    }

    if (!isKnown(commandType)) {
      return res.status(400).json({ error: `Unknown action '${commandType}'.`, code: "invalid" });
    }
    const meta = Catalog[commandType];
    if (!roleAllows(user.role, meta.minRole)) {
      return reject(403, "forbidden", `${meta.label} requires the ${meta.minRole} role. You are signed in as ${user.role}.`, "Denied");
    }
    if (isAccountCommand(commandType)) {
      if (!samAccountName) {
        return res.status(400).json({ error: "Choose the account this action applies to.", code: "invalid" });
      }
      if (samAccountName.length > 256) {
        return res.status(400).json({ error: "Account name is too long.", code: "invalid" });
      }
    }
    if (requiresNewPassword(commandType)) {
      if (!body.newPassword) {
        return res.status(400).json({ error: "A new password is required.", code: "invalid" });
      }
      if (String(body.newPassword).length > 256) {
        return res.status(400).json({ error: "The new password must be 256 characters or fewer.", code: "invalid" });
      }
    }
    if (meta.sensitive && body.confirmed !== true) {
      return res.status(400).json({ error: `${meta.label} is a sensitive action and must be confirmed.`, code: "confirmation_required" });
    }
    if (!store.capabilitiesOf(agentId).includes(commandType)) {
      return reject(409, "unsupported", `${meta.label} is not supported by this agent.`, "Unavailable");
    }
    const status = store.statusOf(agentId);
    if (status !== Store.AgentStatuses.Active) {
      return reject(409, "not_active", `${store.getMachineName(agentId)} is ${status === Store.AgentStatuses.PendingApproval ? "awaiting approval" : "revoked"}. ${meta.label} was not queued.`, "Unavailable");
    }
    if (!store.isOnline(agentId)) {
      return reject(409, "offline", `${store.getMachineName(agentId)} is offline. ${meta.label} was not queued.`, "Unavailable");
    }

    const command = {
      commandId: crypto.randomUUID(),
      samAccountName: isAccountCommand(commandType) ? samAccountName : "",
      commandType,
      newPassword: requiresNewPassword(commandType) ? String(body.newPassword) : null,
      createdUtc: new Date().toISOString()
    };
    store.enqueue(agentId, command, user, reason);
    logger(`${user.name} (${user.role}) queued ${commandType} on agent ${store.getDisplayId(agentId)} (${command.commandId}).`);
    res.status(201).json(store.getCommand(agentId, command.commandId));
  });

  // --- Agent lifecycle management (Administrator only) ---
  function manage(action, auditVerb) {
    return [auth.requireRole(Roles.Administrator), (req, res) => {
      const agentId = resolve(req, res);
      if (!agentId) {
        return;
      }
      if (!action(agentId, req.session.user)) {
        return res.status(404).json({ error: "Agent not found.", code: "not_found" });
      }
      logger(`${req.session.user.name} ${auditVerb} agent ${store.getDisplayId(agentId) || agentId}.`);
      res.json({ ok: true, agent: store.getAgentDetail(agentId) });
    }];
  }

  router.post("/agents/:agentId/approve", ...manage((id, user) => store.setAgentStatus(id, Store.AgentStatuses.Active, user), "approved"));
  router.post("/agents/:agentId/revoke", ...manage((id, user) => store.setAgentStatus(id, Store.AgentStatuses.Revoked, user), "revoked"));
  router.post("/agents/:agentId/rotate-key", ...manage((id, user) => store.rotateKey(id, user), "rotated the credential for"));

  router.delete("/agents/:agentId", auth.requireRole(Roles.Administrator), (req, res) => {
    const agentId = resolve(req, res);
    if (!agentId) {
      return;
    }
    store.removeAgent(agentId, req.session.user, "removed in portal");
    logger(`${req.session.user.name} removed agent ${agentId}.`);
    res.json({ ok: true });
  });

  router.get("/accounts", (req, res) => {
    res.json(store.getGlobalAccounts());
  });

  router.get("/commands", (req, res) => {
    res.json(store.getAllCommands());
  });

  router.get("/audit", (req, res) => {
    res.json(store.getAudit());
  });

  router.get("/search", (req, res) => {
    const query = String(req.query.q || "").slice(0, 200);
    res.json(store.searchAgents(query, 20));
  });

  router.get("/downloads", (req, res) => {
    const manifest = installer ? installer.manifest() : null;
    res.json({
      report: store.getDownloadReport(),
      installer: manifest ? {
        available: true,
        fileName: installer.fileName,
        version: manifest.version,
        size: manifest.size,
        signed: manifest.signed,
        sha256: manifest.sha256
      } : { available: false, fileName: installer ? installer.fileName : "", version: null, size: null, signed: false, sha256: null },
      downloadPath: "/download/agent",
      downloadUrl: `${hostSettings.managerUrl(req)}/download/agent`
    });
  });

  router.get("/dashboard/summary", (req, res) => {
    res.json({
      summary: store.getSummary(),
      agents: store.listAgents()
    });
  });

  router.get("/dashboard/urls", (req, res) => {
    const access = hostSettings.describe(req);
    res.json({ publicHost: access.host, source: access.source, managerUrl: access.managerUrl, urls: urlCatalog.urls, localIpAddress: urlCatalog.localIp });
  });

  return router;
};
