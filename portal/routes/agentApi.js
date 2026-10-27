"use strict";

// Agent-facing API.
//   POST /enroll                 registers a new agent using the enrollment key; returns a unique credential.
//   /:agentId/*                  authenticated with that agent's own credential (X-Api-Key).
// Enrollment is the only endpoint that accepts the shared enrollment key.
const express = require("express");
const fs = require("fs");

const AGENT_ID_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

module.exports = function agentApi(store, auth, config, installer, logger, hostSettings, deploy) {
  const router = express.Router();
  const engine = deploy && deploy.engine;
  const library = deploy && deploy.library;

  function dashboardUrl(displayId) {
    return `${hostSettings.managerUrl()}/agents/${displayId}`;
  }

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
      dashboardUrl: dashboardUrl(enrollment.displayId),
      managerUrl: hostSettings.managerUrl()
    });
  });

  router.post("/:agentId/heartbeat", validId, agentAuth, (req, res) => {
    const outcome = store.upsertHeartbeat(req.params.agentId, req.body || {}, req.ip);
    res.json({
      status: outcome.status,
      displayId: outcome.displayId,
      newApiKey: outcome.newApiKey,
      dashboardUrl: dashboardUrl(outcome.displayId),
      managerUrl: hostSettings.managerUrl()
    });
  });

  // Lets an agent confirm that a new manager address still accepts its credential before switching.
  router.get("/:agentId/whoami", validId, agentAuth, (req, res) => {
    res.json({ agentId: req.params.agentId, displayId: store.getDisplayId(req.params.agentId) });
  });

  router.post("/:agentId/report", validId, agentAuth, (req, res) => {
    store.saveReport(req.params.agentId, req.body || {}, req.ip);
    res.status(204).end();
  });

  router.get("/:agentId/commands", validId, agentAuth, (req, res) => {
    res.json(store.takePendingCommands(req.params.agentId, req.ip));
  });

  // Long poll: answers immediately when work is queued, otherwise holds the request until work arrives
  // or the wait (max 55 s) expires. An open poll also marks the agent as connected in real time.
  router.get("/:agentId/poll", validId, agentAuth, async (req, res, next) => {
    const agentId = req.params.agentId;
    const waitMs = Math.min(Math.max(Number.parseInt(req.query.wait, 10) || 25, 0), 55) * 1000;
    let closed = false;
    let waiter = null;
    store.pollOpened(agentId, req.ip);
    res.on("close", () => {
      closed = true;
      if (waiter) {
        waiter.cancel();
      }
    });
    try {
      try {
        if (!store.hasWork(agentId) && waitMs > 0) {
          waiter = store.waitForWork(agentId, waitMs);
          await waiter.promise;
        }
      } finally {
        store.pollClosed(agentId);
      }
      // A disconnected or removed agent leaves queued work for its next poll.
      if (closed || !store.agents.has(agentId)) {
        return;
      }
      const work = store.takeWork(agentId, req.ip);
      res.json({ commands: work.commands, requests: work.requests, status: store.statusOf(agentId) });
    } catch (error) {
      next(error);
    }
  });

  router.post("/:agentId/inventory", validId, agentAuth, (req, res) => {
    if (!store.saveInventory(req.params.agentId, req.body || {}, req.ip)) {
      return res.status(400).json({ error: "Unknown inventory section.", code: "invalid" });
    }
    res.status(204).end();
  });

  router.post("/:agentId/events", validId, agentAuth, (req, res) => {
    const event = req.body || {};
    store.recordAgentEvent(req.params.agentId, event, req.ip);
    if (event.kind === "ServiceStopping" || event.kind === "TamperDetected" || event.kind === "Uninstalling") {
      const detail = String(event.detail || "").replace(/[\r\n]+/g, " ").slice(0, 300);
      logger(`Agent ${store.getDisplayId(req.params.agentId)} reported ${event.kind}: ${detail}`);
    }
    res.status(204).end();
  });

  router.post("/:agentId/command-results", validId, agentAuth, (req, res) => {
    const results = Array.isArray(req.body) ? req.body : [];
    store.addResults(req.params.agentId, results, req.ip);
    res.status(204).end();
  });

  // Progress updates for an in-flight software deployment. Advisory only: the authoritative outcome
  // arrives through command-results.
  router.post("/:agentId/deployments/progress", validId, agentAuth, (req, res) => {
    const body = req.body || {};
    if (engine && typeof body.commandId === "string") {
      engine.onProgress(req.params.agentId, body.commandId, {
        stage: body.stage,
        percent: typeof body.percent === "number" ? body.percent : Number.parseFloat(body.percent),
        message: body.message
      });
    }
    res.status(204).end();
  });

  // Downloads a deployment package. Authorized only while this agent has an active software job for the
  // package, so installers are never a general download. Supports Range so an interrupted download resumes.
  router.get("/:agentId/packages/:packageId", validId, agentAuth, (req, res) => {
    const { agentId, packageId } = req.params;
    if (!engine || !library || !engine.agentHasActiveSoftwareJob(agentId, packageId)) {
      return res.status(403).json({ error: "This agent is not assigned to install this package.", code: "forbidden" });
    }
    const pkg = library.raw(packageId);
    if (!pkg || !pkg.stored || !pkg.path) {
      return res.status(404).json({ error: "The package file is not available.", code: "not_found" });
    }
    let stat;
    try {
      stat = fs.statSync(pkg.path);
    } catch {
      return res.status(404).json({ error: "The package file is not available.", code: "not_found" });
    }
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename="${pkg.fileName}"`);
    res.setHeader("X-Package-Sha256", pkg.sha256);
    res.setHeader("Accept-Ranges", "bytes");
    const range = /^bytes=(\d*)-(\d*)$/.exec(req.get("Range") || "");
    let start = 0;
    let end = stat.size - 1;
    if (range) {
      if (range[1]) {
        start = Number.parseInt(range[1], 10);
      }
      if (range[2]) {
        end = Number.parseInt(range[2], 10);
      }
      if (!range[1] && range[2]) {
        start = stat.size - Number.parseInt(range[2], 10);
        end = stat.size - 1;
      }
      if (Number.isNaN(start) || Number.isNaN(end) || start > end || start < 0 || end >= stat.size) {
        res.setHeader("Content-Range", `bytes */${stat.size}`);
        return res.status(416).end();
      }
      res.status(206);
      res.setHeader("Content-Range", `bytes ${start}-${end}/${stat.size}`);
    }
    res.setHeader("Content-Length", end - start + 1);
    const stream = fs.createReadStream(pkg.path, { start, end });
    stream.on("error", () => res.destroy());
    stream.pipe(res);
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
    const displayId = store.getDisplayId(req.params.agentId);
    store.removeAgent(req.params.agentId, null, "agent uninstall");
    logger(`Agent ${displayId} deregistered from ${req.ip}.`);
    res.status(204).end();
  });

  return router;
};
