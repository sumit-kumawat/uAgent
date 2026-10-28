"use strict";

// Danger Zone endpoints. Everything here is Administrator-only, and anything destructive additionally
// requires the operator's password and a typed confirmation phrase, so neither an unattended session nor
// an ordinary API call can trigger a reset. Preflight is always available, because reading what an
// operation would do is how an administrator decides whether to run it.
const express = require("express");
const { Roles } = require("../lib/commandTypes");

module.exports = function maintenanceApi(context) {
  const { store, auth, maintenance, reauth, uninstallKeys, connectivity, tlsManager, hostSettings, config, logger } = context;
  const router = express.Router();
  const admin = auth.requireRole(Roles.Administrator);

  function reason(req) {
    return String((req.body || {}).reason || "").trim();
  }

  // The checks every destructive operation has to pass before it is allowed to start.
  function authorise(req, res, action, phrase) {
    const text = reason(req);
    if (text.length < 5) {
      res.status(400).json({ error: "Give a reason of at least 5 characters. It is recorded in the audit log.", field: "reason" });
      return false;
    }
    if (phrase) {
      if (String((req.body || {}).confirm || "") !== phrase) {
        res.status(400).json({ error: `Type ${phrase} exactly to confirm.`, field: "confirm" });
        return false;
      }
      if ((req.body || {}).acknowledge !== true) {
        res.status(400).json({ error: "Confirm that you have read what this will affect.", field: "acknowledge" });
        return false;
      }
    }
    return reauth.verify(req, res, action);
  }

  router.get("/maintenance", admin, (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
      res.json({
        operations: maintenance.operations(),
        resetScopes: maintenance.resetScopes(),
        current: maintenance.current(),
        history: maintenance.history().slice(0, 15),
        backups: maintenance.backups(),
        state: require("../lib/backup").describeState(),
        setupRequired: maintenance.setupRequired(),
        restartRequired: maintenance.restartRequired()
      });
    } catch (error) {
      res.status(500).json({ error: `The maintenance overview could not be read: ${error.message}` });
    }
  });

  router.get("/maintenance/connectivity", admin, async (req, res) => {
    res.set("Cache-Control", "no-store");
    try {
      res.json(await connectivity.report({ tlsManager, store, hostSettings, config }));
    } catch (error) {
      res.status(500).json({ error: `The connectivity report could not be produced: ${error.message}` });
    }
  });

  router.post("/maintenance/:type/preflight", admin, async (req, res) => {
    try {
      res.json(await maintenance.preflight(req.params.type, { scope: (req.body || {}).scope }));
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  // Declared before /maintenance/:type, which would otherwise swallow "backups" as an operation name.
  router.post("/maintenance/backups", admin, (req, res) => {
    try {
      const made = maintenance.createBackup({ user: req.session.user.name, remoteIp: req.ip, reason: reason(req), label: "manual" });
      res.status(201).json({
        backup: { name: require("path").basename(made.file), sizeBytes: made.sizeBytes, createdUtc: made.createdUtc, sha256: made.sha256, contents: made.contents.length }
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  router.post("/maintenance/:type", admin, async (req, res) => {
    const type = req.params.type;
    const definition = maintenance.Operations[type];
    if (!definition) {
      return res.status(404).json({ error: "Unknown operation." });
    }
    // Repair and resynchronise is the only operation that changes nothing and so needs no password:
    // everything else reaches an endpoint, replaces code or clears records.
    if (type !== "repair" && !authorise(req, res, `Maintenance:${type}`, definition.confirmPhrase)) {
      return;
    }
    // Operations that uninstall agents need the uninstall verification key, like removing one agent.
    const scope = (req.body || {}).scope || {};
    if (type === "agent-removal" || (type === "destroy" && scope.agents)) {
      const keyCheck = uninstallKeys.verify((req.body || {}).uninstallKey, req.session.user.name, req.ip);
      if (!keyCheck.ok) {
        return res.status(keyCheck.status).json({ error: keyCheck.error, code: keyCheck.code, field: "uninstallKey" });
      }
    }
    try {
      const job = await maintenance.start(type, {
        user: req.session.user.name,
        remoteIp: req.ip,
        reason: reason(req),
        scope: (req.body || {}).scope
      });
      res.status(202).json({ job });
    } catch (error) {
      res.status(error.code === "busy" ? 409 : 400).json({ error: error.message, code: error.code || "failed", blockers: error.blockers || [] });
    }
  });

  router.get("/maintenance/jobs/:id", admin, (req, res) => {
    res.set("Cache-Control", "no-store");
    const job = maintenance.job(req.params.id);
    if (!job) {
      return res.status(404).json({ error: "That operation is not on record." });
    }
    res.json({ job });
  });

  router.post("/maintenance/backups/:name/verify", admin, (req, res) => {
    try {
      const result = maintenance.verifyBackup(req.params.name);
      res.json({ ok: result.ok, problems: result.problems, sizeBytes: result.sizeBytes, sha256: result.sha256, manifest: result.manifest });
    } catch (error) {
      res.status(404).json({ error: error.message });
    }
  });

  router.post("/maintenance/backups/:name/restore", admin, (req, res) => {
    if (!authorise(req, res, "Maintenance:restore", "RESTORE")) {
      return;
    }
    try {
      const result = maintenance.restoreBackup(req.params.name, { user: req.session.user.name, remoteIp: req.ip, reason: reason(req) });
      res.json({
        restored: result.restored,
        safety: result.safety ? require("path").basename(result.safety) : "",
        restarting: result.restarting,
        note: result.restarting
          ? "The portal is restarting to load the restored records. Sign in again in a few seconds."
          : "Restart the portal to load the restored records."
      });
    } catch (error) {
      res.status(error.code === "busy" ? 409 : 400).json({ error: error.message, code: error.code || "failed" });
    }
  });

  return router;
};

// Setup is mounted separately: it must be reachable with no session, but only while the portal has no
// account at all. Once an administrator exists it refuses, so it cannot be used to add one later.
module.exports.setupApi = function setupApi(context) {
  const { operators, maintenance, store, auth, logger } = context;
  const router = express.Router();

  router.get("/setup", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.json({ required: maintenance.setupRequired() });
  });

  router.post("/setup", (req, res) => {
    if (!maintenance.setupRequired()) {
      return res.status(409).json({ error: "This portal is already set up. Sign in instead.", code: "already_setup" });
    }
    const body = req.body || {};
    const ip = req.ip || "unknown";
    const remaining = auth.throttle.lockoutRemaining(ip);
    if (remaining > 0) {
      return res.status(429).json({ error: `Too many failed attempts. Try again in ${Math.ceil(remaining / 1000)} seconds.`, field: "setupCode" });
    }
    let user;
    try {
      user = operators.createFirstAdministrator(body.username, body.password, body.confirmPassword, body.setupCode);
    } catch (error) {
      if (error.field === "setupCode") {
        auth.throttle.registerFailure(ip);
        store.addAudit({ user: String(body.username || "(blank)").slice(0, 64), action: "SetupCompleted", result: "Denied", details: "The setup code was missing or wrong.", remoteIp: ip });
      }
      return res.status(400).json({ error: error.message, field: error.field || "" });
    }
    auth.throttle.reset(ip);
    maintenance.clearSetupRequired();
    store.addAudit({
      user: user.name,
      action: "SetupCompleted",
      result: "Success",
      details: `The administrator account "${user.name}" was created through the setup wizard.`,
      remoteIp: ip
    });
    logger(`Setup completed: administrator "${user.name}" created from ${ip}.`);
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: "The account was created, but a session could not be started. Sign in.", code: "session" });
      }
      req.session.user = user;
      req.session.epoch = operators.sessionEpoch();
      res.status(201).json({ ok: true, user: { name: user.name, role: user.role } });
    });
  });

  return router;
};
