"use strict";

// Operator-facing JSON API used by the portal pages. Requires the session cookie.
const express = require("express");
const crypto = require("crypto");
const Store = require("../lib/store");
const { Catalog, Roles, roleAllows, isKnown, requiresNewPassword, isAccountCommand, requiresReauth, ToggleLabels, commandLabel } = require("../lib/commandTypes");
const { buildPanel, checkAccountChange, findAccount } = require("../lib/controlPanel");

const INVENTORY_VIEW_SECTIONS = ["system", "processes", "services", "applications", "files"];

module.exports = function portalApi(store, auth, config, urlCatalog, logger, installer, hostSettings, operators, tlsManager, hostChange, reauth) {
  const router = express.Router();
  router.use(auth.requireApi);

  // Reachable while a password change is pending, so the forced-change dialog can complete it.
  router.post("/account/password", (req, res) => {
    const user = req.session.user;
    const body = req.body || {};
    const next = typeof body.newPassword === "string" ? body.newPassword : "";
    if (next !== body.confirmPassword) {
      return res.status(400).json({ error: "The new password and confirmation do not match.", field: "confirmPassword" });
    }
    try {
      operators.changePassword(user.name, body.currentPassword, next);
    } catch (error) {
      store.addAudit({ user: user.name, action: "ChangePassword", result: "Failed", details: error.message, remoteIp: req.ip });
      return res.status(400).json({ error: error.message, field: error.field || "newPassword" });
    }
    const wasForced = Boolean(user.mustChangePassword);
    user.mustChangePassword = false;
    store.addAudit({ user: user.name, action: "ChangePassword", result: "Success", details: wasForced ? "Replaced the initial password." : "Changed the portal password.", remoteIp: req.ip });
    logger(`${user.name} changed the portal password.`);
    res.json({ ok: true });
  });
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

  const verifyReauth = reauth.verify;

  // Change detection for fleet-wide lists: the store revision advances on every change, so a refresh
  // with nothing new is answered with 304 before any payload is built.
  function notModified(req, res, view) {
    const etag = `W/"${view}-${store.revision || 0}"`;
    res.set("Cache-Control", "private, no-cache");
    res.set("ETag", etag);
    if (req.get("If-None-Match") === etag) {
      res.status(304).end();
      return true;
    }
    return false;
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
    if (notModified(req, res, "agents")) {
      return;
    }
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
      accounts: report ? report.accounts.map((a) => Store.accountView(a)) : [],
      commands: store.getCommandHistory(agentId).slice(0, 200),
      audit: store.getAudit(agentId).slice(0, 200)
    });
  });

  // The one control panel for an agent, optionally focused on one account. Actions follow the current state.
  router.get("/agents/:agentId/panel", (req, res) => {
    const agentId = resolve(req, res);
    if (!agentId) {
      return;
    }
    const source = req.query.source === "Domain" || req.query.source === "Local" ? req.query.source : "";
    res.set("Cache-Control", "no-store");
    res.json(buildPanel(store, agentId, req.session.user.role, { account: String(req.query.account || "").slice(0, 256), source }));
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
    const accountSource = body.accountSource === "Domain" || body.accountSource === "Local" ? body.accountSource : null;
    const reason = String(body.reason || "").trim().slice(0, 500);
    const value = ToggleLabels[commandType] ? body.value !== false : null;

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
    if (commandType === "UninstallAgent") {
      return res.status(400).json({ error: "Use Remove agent in the control panel. It uninstalls the agent, verifies the result and then removes it from the portal.", code: "use_remove" });
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
    if (meta.sensitive && !reason) {
      return res.status(400).json({ error: `Give a reason for ${meta.label.toLowerCase()}; it is recorded in the audit log.`, code: "reason_required" });
    }
    if (requiresReauth(commandType) && !verifyReauth(req, res, commandType, agentId)) {
      return;
    }
    if (!store.capabilitiesOf(agentId).includes(commandType)) {
      return reject(409, "unsupported", `${meta.label} is not supported by this agent.`, "Unavailable");
    }
    const status = store.statusOf(agentId);
    if (status !== Store.AgentStatuses.Active) {
      return reject(409, "not_active", `${store.getMachineName(agentId)} is ${status === Store.AgentStatuses.PendingApproval ? "awaiting approval" : "revoked"}. ${meta.label} was not queued.`, "Unavailable");
    }
    if (store.removalOf(agentId)) {
      return reject(409, "removal_pending", `${store.getMachineName(agentId)} is being removed. ${meta.label} was not queued.`, "Unavailable");
    }
    if (!store.isOnline(agentId)) {
      return reject(409, "offline", `${store.getMachineName(agentId)} is offline. ${meta.label} was not queued.`, "Unavailable");
    }
    if (isAccountCommand(commandType)) {
      const busy = store.findActiveCommand(agentId, null, samAccountName);
      if (busy) {
        return res.status(409).json({ error: `${busy.label} is already ${busy.status === "Pending" ? "queued" : "running"} for ${samAccountName}. Wait for it to finish.`, code: "in_progress", command: busy });
      }
      const report = store.getReport(agentId);
      const problem = checkAccountChange({
        report,
        account: findAccount(report, samAccountName, accountSource),
        commandType,
        value,
        features: store.getFeatures(agentId),
        agent: store.getAgentDetail(agentId)
      });
      if (problem) {
        return res.status(problem.status).json({ error: problem.error, code: problem.code });
      }
    } else {
      const busy = store.findActiveCommand(agentId, commandType, "");
      if (busy) {
        return res.status(409).json({ error: `${busy.label} is already ${busy.status === "Pending" ? "queued" : "running"} on this agent.`, code: "in_progress", command: busy });
      }
    }

    const command = {
      commandId: crypto.randomUUID(),
      samAccountName: isAccountCommand(commandType) ? samAccountName : "",
      commandType,
      newPassword: requiresNewPassword(commandType) ? String(body.newPassword) : null,
      createdUtc: new Date().toISOString(),
      accountSource: isAccountCommand(commandType) ? accountSource : null
    };
    if (value !== null) {
      command.value = value;
    }
    store.enqueue(agentId, command, user, reason);
    logger(`${user.name} (${user.role}) queued ${commandLabel(commandType, value)} on agent ${store.getDisplayId(agentId)} (${command.commandId}).`);
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
      logger(`${req.session.user.name} ${auditVerb} agent ${store.getDisplayId(agentId)}.`);
      res.json({ ok: true, agent: store.getAgentDetail(agentId) });
    }];
  }

  router.post("/agents/:agentId/approve", ...manage((id, user) => store.setAgentStatus(id, Store.AgentStatuses.Active, user), "approved"));
  router.post("/agents/:agentId/revoke", ...manage((id, user) => store.setAgentStatus(id, Store.AgentStatuses.Revoked, user), "revoked"));
  router.post("/agents/:agentId/rotate-key", ...manage((id, user) => store.rotateKey(id, user), "rotated the credential for"));

  // mode "uninstall" (default) queues a verified uninstall; the agent leaves the inventory only when the
  // uninstaller confirms. mode "record" removes the portal record alone, for computers that are gone.
  router.delete("/agents/:agentId", auth.requireRole(Roles.Administrator), (req, res) => {
    const agentId = resolve(req, res);
    if (!agentId) {
      return;
    }
    const body = req.body || {};
    if (body.confirmed !== true) {
      return res.status(400).json({ error: "Removing an agent must be confirmed.", code: "confirmation_required" });
    }
    const mode = body.mode === "record" ? "record" : "uninstall";
    const reason = String(body.reason || "").trim().slice(0, 500);
    if (!reason) {
      return res.status(400).json({ error: "Give a reason for removing the agent; it is recorded in the audit log.", code: "reason_required" });
    }
    if (!verifyReauth(req, res, "RemoveAgent", agentId)) {
      return;
    }
    const user = req.session.user;
    const displayId = store.getDisplayId(agentId);
    if (mode === "record") {
      store.removeAgent(agentId, user, `record removed in portal without uninstalling: ${reason}`);
      logger(`${user.name} removed the record of agent ${displayId} without uninstalling.`);
      return res.json({ ok: true, removed: true });
    }
    if (store.removalOf(agentId)) {
      return res.status(409).json({ error: "Removal is already in progress for this agent.", code: "in_progress", removal: store.removalOf(agentId) });
    }
    if (store.statusOf(agentId) !== Store.AgentStatuses.Active) {
      return res.status(409).json({ error: "Only an active agent can receive the uninstall command. Remove the record instead and uninstall it on the computer.", code: "not_active" });
    }
    if (!store.capabilitiesOf(agentId).includes("UninstallAgent")) {
      return res.status(409).json({ error: "This agent cannot uninstall itself (it is not running as the Windows service or is an older version). Remove the record instead and uninstall it on the computer.", code: "unsupported" });
    }
    const removal = store.requestRemoval(agentId, user, reason);
    logger(`${user.name} requested removal of agent ${displayId} (${removal.commandId}).`);
    res.status(202).json({ ok: true, removed: false, removal });
  });

  router.post("/agents/:agentId/removal/cancel", auth.requireRole(Roles.Administrator), (req, res) => {
    const agentId = resolve(req, res);
    if (!agentId) {
      return;
    }
    const result = store.cancelRemoval(agentId, req.session.user);
    if (!result.ok) {
      return res.status(409).json({ error: result.error, code: "not_cancellable" });
    }
    logger(`${req.session.user.name} cancelled removal of agent ${store.getDisplayId(agentId)}.`);
    res.json({ ok: true });
  });

  // Paged, filtered and sorted on the server so large fleets stay fast in the browser.
  router.get("/accounts", (req, res) => {
    res.json(store.queryAccounts({
      q: String(req.query.q || "").slice(0, 200),
      state: String(req.query.state || ""),
      agent: String(req.query.agent || ""),
      source: String(req.query.source || ""),
      page: req.query.page,
      pageSize: req.query.pageSize,
      sort: String(req.query.sort || ""),
      dir: String(req.query.dir || "")
    }));
  });

  // --- Remote monitoring ------------------------------------------------------------------
  // Read access for every role; folder listings need Administrator and are audited.
  function inventoryAccess(req, res, agentId, section) {
    if (!INVENTORY_VIEW_SECTIONS.includes(section)) {
      res.status(404).json({ error: "Unknown inventory view.", code: "not_found" });
      return false;
    }
    const detail = store.getAgentDetail(agentId);
    const features = detail.features || [];
    if (!features.includes("Inventory")) {
      const [major, minor] = String(detail.agentVersion || "0.0").split(".").map((part) => parseInt(part, 10) || 0);
      const current = major > 1 || (major === 1 && minor >= 3);
      const error = current
        ? "This agent does not collect monitoring data on its platform. Inventory is available from agents running on Windows."
        : "This agent does not report monitoring data. Update it to version 1.3 or later.";
      res.status(409).json({ error, code: "unsupported" });
      return false;
    }
    if (section === "files") {
      if (!roleAllows(req.session.user.role, Roles.Administrator)) {
        res.status(403).json({ error: "Browsing folders requires the Administrator role.", code: "forbidden" });
        return false;
      }
      if (!features.includes("FileBrowse")) {
        res.status(409).json({ error: "Folder browsing is disabled in this agent's configuration.", code: "unsupported" });
        return false;
      }
    }
    return true;
  }

  router.get("/agents/:agentId/inventory/:section", (req, res) => {
    const agentId = resolve(req, res);
    if (!agentId || !inventoryAccess(req, res, agentId, req.params.section)) {
      return;
    }
    const entry = store.getInventory(agentId, req.params.section);
    res.json(entry || { data: null, error: null, receivedUtc: null, collectedUtc: null, requestId: null });
  });

  router.post("/agents/:agentId/inventory/:section/refresh", (req, res) => {
    const agentId = resolve(req, res);
    const section = req.params.section;
    if (!agentId || !inventoryAccess(req, res, agentId, section)) {
      return;
    }
    if (store.statusOf(agentId) !== Store.AgentStatuses.Active || !store.isOnline(agentId)) {
      return res.status(409).json({ error: `${store.getMachineName(agentId)} is offline; showing the last data received.`, code: "offline" });
    }
    let requestPath = null;
    if (section === "files") {
      requestPath = String((req.body && req.body.path) || "").slice(0, 2048);
      store.addAudit({
        user: req.session.user.name,
        agentId,
        action: "BrowseFiles",
        result: "Requested",
        details: requestPath ? `Listed ${requestPath}` : "Listed the allowed drives.",
        remoteIp: req.ip
      });
    }
    const requestId = store.requestInventory(agentId, section, requestPath);
    res.status(202).json({ requestId });
  });

  // Server-sent events: one batched message per change burst. The browser reconnects automatically.
  router.get("/events", (req, res) => {
    res.set({
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no"
    });
    res.flushHeaders();
    res.write("retry: 3000\n\n");
    // A slow browser does not queue unbounded data: while its socket is backed up, batches are dropped
    // and a single resync marker is sent once it drains, so the page refetches what it shows.
    let behind = false;
    const send = (batch) => {
      if (res.writableNeedDrain) {
        if (!behind) {
          behind = true;
          res.once("drain", () => {
            behind = false;
            res.write(`event: change\ndata: ${JSON.stringify([{ type: "resync" }])}\n\n`);
          });
        }
        return;
      }
      res.write(`event: change\ndata: ${JSON.stringify(batch)}\n\n`);
    };
    // A visible heartbeat lets the browser tell a quiet stream from a dead one and mark data as stale.
    res.write(`event: ping\ndata: ${Date.now()}\n\n`);
    const ping = setInterval(() => res.write(`event: ping\ndata: ${Date.now()}\n\n`), 15000);
    store.events.on("batch", send);
    req.on("close", () => {
      clearInterval(ping);
      store.events.off("batch", send);
    });
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
    const manifest = installer.manifest();
    res.json({
      report: store.getDownloadReport(),
      installer: manifest ? {
        available: true,
        fileName: installer.fileName,
        version: manifest.version,
        size: manifest.size,
        signed: manifest.signed,
        sha256: manifest.sha256
      } : { available: false, fileName: installer.fileName, version: null, size: null, signed: false, sha256: null },
      downloadPath: "/download/agent",
      downloadUrl: `${hostSettings.managerUrl()}/download/agent`
    });
  });

  // Connection settings for a signed installer, which is served unmodified. Contains the enrollment key,
  // so only Administrators can fetch it, and each fetch is audited.
  router.get("/installer/config", auth.requireRole(Roles.Administrator), (req, res) => {
    const settings = installer.connectionConfig(hostSettings.managerUrl(), config.enrollmentKey, tlsManager.agentTrust());
    store.addAudit({ user: req.session.user.name, action: "DownloadInstallerConfig", result: "Success", details: `uagent-install.json for ${settings.managerUrl}`, remoteIp: req.ip });
    res.setHeader("Content-Disposition", 'attachment; filename="uagent-install.json"');
    res.setHeader("Cache-Control", "no-store");
    res.type("application/json").send(JSON.stringify(settings, null, 2) + "\n");
  });

  router.get("/dashboard/summary", (req, res) => {
    if (notModified(req, res, "dashboard")) {
      return;
    }
    res.json({
      summary: store.getSummary(),
      agents: store.listAgents()
    });
  });

  // --- Agent host (DNS/FQDN) ------------------------------------------------------------------
  router.get("/settings/host", (req, res) => {
    res.json({ access: hostSettings.describe(), certificate: tlsManager.describe(), canConfigure: roleAllows(req.session.user.role, Roles.Administrator) });
  });

  router.post("/settings/host/preview", auth.requireRole(Roles.Administrator), async (req, res) => {
    try {
      res.json(await hostChange.preview((req.body || {}).host));
    } catch (error) {
      res.status(400).json({ error: error.message, field: "host" });
    }
  });

  router.post("/settings/host", auth.requireRole(Roles.Administrator), async (req, res) => {
    const body = req.body || {};
    try {
      if (body.action === "detect") {
        return res.json(Object.assign({ ok: true }, hostChange.clear(req.session.user.name, req.ip), { access: hostSettings.describe() }));
      }
      if (body.confirm !== true) {
        return res.status(400).json({ error: "Confirm the change before saving.", field: "confirm" });
      }
      const result = await hostChange.apply(body.host, req.session.user.name, req.ip);
      res.json({ ok: true, managerUrl: result.managerUrl, certificate: result.certificate, preview: result.preview, access: hostSettings.describe() });
    } catch (error) {
      res.status(error.status || 400).json({ error: error.message, field: "host", preview: error.preview || null });
    }
  });

  router.get("/dashboard/urls", (req, res) => {
    const access = hostSettings.describe();
    res.json({ publicHost: access.host, source: access.source, managerUrl: access.managerUrl, urls: urlCatalog.urls, localIpAddress: urlCatalog.localIp });
  });

  return router;
};
