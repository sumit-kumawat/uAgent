"use strict";

// Agent-facing API.
//   POST /enroll                 registers a new agent using the enrollment key; returns a unique credential.
//   /:agentId/*                  authenticated with that agent's own credential (X-Api-Key).
// Enrollment is the only endpoint that accepts the shared enrollment key.
const express = require("express");

const AGENT_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

module.exports = function agentApi(store, auth, config, installer, logger) {
  const router = express.Router();

  function validId(req, res, next) {
    if (!AGENT_ID_PATTERN.test(req.params.agentId)) {
      return res.status(400).json({ error: "Agent id is malformed.", code: "invalid" });
    }
    next();
  }

  // Authenticates /:agentId/* with the agent's own credential and attaches req.agent.
  function agentAuth(req, res, next) {
    const result = store.authenticateAgent(req.params.agentId, req.get("X-Api-Key") || "");
    if (!result.ok) {
      const status = result.code === "revoked" ? 403 : 401;
      store.recordIssue({
        kind: result.code === "revoked" ? "Activation" : "Registration",
        remoteIp: req.ip,
        agentId: req.params.agentId,
        detail: result.code === "revoked"
          ? "A revoked agent tried to connect and was refused."
          : result.code === "unknown_agent"
            ? "A connection used an agent id this manager does not have."
            : "An agent credential was rejected."
      });
      return res.status(status).json({ error: `Agent credential rejected (${result.code}).`, code: result.code });
    }
    req.agent = result.agent;
    next();
  }

  router.post("/enroll", (req, res) => {
    const provided = req.get("X-Api-Key") || "";
    if (!provided || !auth.safeEqual(provided, config.enrollmentKey)) {
      store.recordIssue({
        kind: "Enrollment",
        remoteIp: req.ip,
        detail: provided ? "Enrollment was rejected: the enrollment key did not match." : "Enrollment was rejected: the enrollment key was missing."
      });
      return res.status(401).json({ error: "Invalid or missing enrollment key.", code: "invalid_key" });
    }
    const enrollment = store.enrollAgent(req.body || {}, req.ip);
    logger(`Agent ${enrollment.displayId} enrolled from ${req.ip} (${enrollment.status}).`);
    res.status(201).json({
      agentId: enrollment.agentId,
      agentNumber: enrollment.agentNumber,
      displayId: enrollment.displayId,
      apiKey: enrollment.apiKey,
      status: enrollment.status,
      dashboardUrl: config.publicDashboardUrl ? `${config.publicDashboardUrl}/agents/${enrollment.displayId}` : null
    });
  });

  router.post("/:agentId/heartbeat", validId, agentAuth, (req, res) => {
    const outcome = store.upsertHeartbeat(req.params.agentId, req.body || {}, req.ip);
    res.json({
      status: outcome.status,
      displayId: outcome.displayId,
      newApiKey: outcome.newApiKey,
      dashboardUrl: config.publicDashboardUrl ? `${config.publicDashboardUrl}/agents/${outcome.displayId}` : null
    });
  });

  router.post("/:agentId/report", validId, agentAuth, (req, res) => {
    store.saveReport(req.params.agentId, req.body || {}, req.ip);
    res.status(204).end();
  });

  router.get("/:agentId/commands", validId, agentAuth, (req, res) => {
    res.json(store.takePendingCommands(req.params.agentId, req.ip));
  });

  router.post("/:agentId/command-results", validId, agentAuth, (req, res) => {
    const results = Array.isArray(req.body) ? req.body : [];
    store.addResults(req.params.agentId, results, req.ip);
    res.status(204).end();
  });

  // Current validated build for self-update. packageUrl points to the raw, signed base installer.
  router.get("/:agentId/update/manifest", validId, agentAuth, (req, res) => {
    const manifest = installer.manifest();
    if (!manifest) {
      return res.status(404).json({ error: "No agent build is published.", code: "no_build" });
    }
    res.json({
      version: manifest.version,
      sha256: manifest.sha256,
      size: manifest.size,
      signed: manifest.signed,
      packageUrl: `api/agents/${req.params.agentId}/update/package`
    });
  });

  router.get("/:agentId/update/package", validId, agentAuth, (req, res) => {
    const stream = installer.baseStream();
    if (!stream) {
      return res.status(404).json({ error: "No agent build is published.", code: "no_build" });
    }
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${installer.fileName}"`);
    stream.on("error", () => res.destroy());
    stream.pipe(res);
  });

  // Agent-initiated removal during uninstall.
  router.post("/:agentId/deregister", validId, agentAuth, (req, res) => {
    store.removeAgent(req.params.agentId, null, "agent uninstall");
    logger(`Agent ${req.params.agentId} deregistered from ${req.ip}.`);
    res.status(204).end();
  });

  return router;
};
