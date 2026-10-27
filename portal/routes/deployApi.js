"use strict";

// Operator API for software deployment and centralised agent deployment. Mounted under /api. Every
// route requires a session (the parent router enforces that); mutations require the Administrator role
// and, where marked, the operator's portal password.
const express = require("express");
const { Roles } = require("../lib/commandTypes");

module.exports = function deployApi(context) {
  const { store, auth, logger, uploads, library, targets, engine, vault, agentDeployment, agentReleases, scanner, reauth } = context;
  const router = express.Router();
  router.use(auth.requireApi);
  router.use((req, res, next) => {
    if (req.session.user && req.session.user.mustChangePassword) {
      return res.status(403).json({ error: "Change the initial password before using the portal.", code: "password_change_required" });
    }
    return next();
  });
  const admin = auth.requireRole(Roles.Administrator);

  function fail(res, error) {
    const status = error.status || 500;
    if (status >= 500) {
      logger(`Deployment API error: ${error.message}`);
      return res.status(500).json({ error: "The portal could not complete the request.", code: "server_error" });
    }
    return res.status(status).json({ error: error.message, code: error.code || "invalid", field: error.field });
  }

  function requireReauth(req, res, action) {
    return reauth.verify(req, res, action, null);
  }

  // --- Uploads (chunked, resumable) -----------------------------------------------------------

  router.post("/uploads", admin, (req, res) => {
    try {
      res.status(201).json(uploads.start(req.body || {}, req.session.user));
    } catch (error) {
      fail(res, error);
    }
  });

  router.put("/uploads/:id", admin, express.raw({ type: "application/octet-stream", limit: uploads.CHUNK_SIZE + 1024 }), (req, res) => {
    const offset = Number.parseInt(req.query.offset, 10);
    if (!Number.isInteger(offset) || offset < 0) {
      return res.status(400).json({ error: "A valid chunk offset is required.", code: "invalid" });
    }
    uploads.writeChunk(req.params.id, req.session.user, offset, streamFromBody(req))
      .then((result) => res.json(result))
      .catch((error) => res.status(error.status || 500).json({ error: error.message, code: error.code || "server_error", ...error.extra }));
  });

  router.get("/uploads/:id", admin, (req, res) => {
    try {
      res.json(uploads.describe(req.params.id, req.session.user));
    } catch (error) {
      fail(res, error);
    }
  });

  router.delete("/uploads/:id", admin, (req, res) => {
    uploads.discard(req.params.id, req.session.user);
    res.json({ ok: true });
  });

  // The raw body parser buffers the chunk; replay it as a stream for the uploads library.
  function streamFromBody(req) {
    const { Readable } = require("stream");
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const stream = Readable.from(body);
    stream.on("newListener", (event) => {
      if (event === "aborted") {
        req.on("aborted", () => stream.emit("aborted"));
      }
    });
    return stream;
  }

  // --- Software library -----------------------------------------------------------------------

  router.get("/software/packages", (req, res) => res.json({ packages: library.list() }));

  router.post("/software/packages", admin, async (req, res) => {
    try {
      const upload = uploads.take(req.body.uploadId, req.session.user, "software");
      const pkg = await library.addFromUpload(upload, req.body, req.session.user);
      res.status(201).json({ package: pkg });
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/software/packages/:id", (req, res) => {
    const pkg = library.get(req.params.id);
    if (!pkg) {
      return res.status(404).json({ error: "The package was not found.", code: "not_found" });
    }
    res.json({ package: pkg, deployments: engine.list({ kind: "software" }).filter((j) => j.packageId === req.params.id) });
  });

  router.patch("/software/packages/:id", admin, (req, res) => {
    try {
      res.json({ package: library.update(req.params.id, req.body || {}, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.post("/software/packages/:id/approve", admin, (req, res) => {
    if (!requireReauth(req, res, "ApprovePackage")) {
      return;
    }
    try {
      res.json({ package: library.approve(req.params.id, req.body || {}, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.post("/software/packages/:id/reject", admin, (req, res) => {
    try {
      res.json({ package: library.reject(req.params.id, req.body && req.body.reason, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.delete("/software/packages/:id", admin, (req, res) => {
    if (!requireReauth(req, res, "DeletePackage")) {
      return;
    }
    try {
      library.remove(req.params.id, req.session.user);
      res.json({ ok: true });
    } catch (error) {
      fail(res, error);
    }
  });

  // --- Target selection -----------------------------------------------------------------------

  router.get("/deploy/agents", (req, res) => res.json(targets.queryAgents(req.query)));

  router.post("/deploy/preview", (req, res) => {
    try {
      const resolved = targets.resolve((req.body || {}).selector);
      const kind = req.body.kind === "agent" ? "agent" : "software";
      const pkg = kind === "software" ? library.raw(req.body.packageId) : null;
      const force = Boolean(req.body.options && req.body.options.force);
      const skipped = {};
      const sample = [];
      let eligible = 0;
      for (const agentId of resolved.agentIds) {
        const agent = store.agents.get(agentId);
        let reason = "";
        if (!agent || agent.status !== "Active") {
          reason = "The agent is not approved.";
        } else if (kind === "software" && !targets.capable(agent)) {
          reason = "The agent version does not support software installation.";
        }
        if (reason) {
          skipped[reason] = (skipped[reason] || 0) + 1;
        } else {
          eligible += 1;
        }
        if (sample.length < 50) {
          sample.push({ displayId: store.getDisplayId(agentId), machineName: agent ? agent.machineName : "", site: agent ? targets.siteOf(agent) : "", eligible: !reason, reason });
        }
      }
      res.json({ total: resolved.agentIds.length, eligible, skipped, sample, package: pkg ? { name: pkg.name, version: pkg.version, status: pkg.status } : null });
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/deploy/groups", (req, res) => res.json({ groups: targets.listGroups() }));
  router.post("/deploy/groups", admin, (req, res) => {
    try {
      res.status(201).json({ group: targets.createGroup(req.body || {}, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });
  router.patch("/deploy/groups/:id", admin, (req, res) => {
    try {
      res.json({ group: targets.updateGroup(req.params.id, req.body || {}, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });
  router.delete("/deploy/groups/:id", admin, (req, res) => {
    try {
      targets.deleteGroup(req.params.id, req.session.user);
      res.json({ ok: true });
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/deploy/settings", (req, res) => {
    const limits = context.limits.describe();
    res.json({ ...targets.getSettings(), scanner: scanner.describe(), limits });
  });
  router.put("/deploy/settings", admin, (req, res) => {
    try {
      res.json(targets.updateSettings(req.body || {}, req.session.user));
    } catch (error) {
      fail(res, error);
    }
  });

  // --- Secrets vault --------------------------------------------------------------------------

  router.get("/deploy/secrets", admin, (req, res) => res.json({ secrets: vault.list() }));
  router.post("/deploy/secrets", admin, (req, res) => {
    if (!requireReauth(req, res, "CreateSecret")) {
      return;
    }
    try {
      res.status(201).json({ secret: vault.create(req.body || {}, req.session.user) });
    } catch (error) {
      res.status(400).json({ error: error.message, code: "invalid", field: error.field });
    }
  });
  router.put("/deploy/secrets/:name", admin, (req, res) => {
    if (!requireReauth(req, res, "RotateSecret")) {
      return;
    }
    try {
      const secret = vault.rotate(req.params.name, (req.body || {}).value, req.session.user);
      if (!secret) {
        return res.status(404).json({ error: "The secret was not found.", code: "not_found" });
      }
      res.json({ secret });
    } catch (error) {
      res.status(400).json({ error: error.message, code: "invalid", field: error.field });
    }
  });
  router.delete("/deploy/secrets/:name", admin, (req, res) => {
    if (!requireReauth(req, res, "DeleteSecret")) {
      return;
    }
    res.json({ ok: vault.remove(req.params.name, req.session.user) });
  });

  // --- Deployments ----------------------------------------------------------------------------

  router.get("/deployments", (req, res) => {
    res.json({ jobs: engine.list({ kind: req.query.kind, status: req.query.status }) });
  });

  router.post("/deployments", admin, (req, res) => {
    const body = req.body || {};
    if (body.confirmed !== true) {
      return res.status(400).json({ error: "Confirm the deployment before starting it.", code: "confirmation_required" });
    }
    if (String(body.confirmText || "").trim() !== String(body.name || "").trim()) {
      return res.status(400).json({ error: "Type the deployment name to confirm.", code: "confirmation_required", field: "confirmText" });
    }
    if (!requireReauth(req, res, "CreateDeployment")) {
      return;
    }
    try {
      res.status(201).json({ job: engine.createJob(body, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/deployments/:id", (req, res) => {
    try {
      res.json({ job: engine.get(req.params.id) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/deployments/:id/targets", (req, res) => {
    try {
      res.json(engine.queryTargets(req.params.id, req.query));
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/deployments/:id/targets/:agentId", (req, res) => {
    try {
      res.json(engine.targetDetail(req.params.id, store.resolveAgentId(req.params.agentId) || req.params.agentId));
    } catch (error) {
      fail(res, error);
    }
  });

  for (const action of ["pause", "resume", "cancel", "advance"]) {
    router.post(`/deployments/:id/${action}`, admin, (req, res) => {
      if (!requireReauth(req, res, `Deployment:${action}`)) {
        return;
      }
      try {
        res.json({ job: engine[action](req.params.id, req.session.user, (req.body || {}).reason) });
      } catch (error) {
        fail(res, error);
      }
    });
  }

  router.post("/deployments/:id/retry", admin, (req, res) => {
    if (!requireReauth(req, res, "Deployment:retry")) {
      return;
    }
    try {
      const body = req.body || {};
      res.json(engine.retry(req.params.id, req.session.user, { agentIds: body.agentIds, scope: body.scope }));
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/deployments/:id/export.csv", (req, res) => {
    try {
      const csv = engine.exportCsv(req.params.id);
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="deployment-${req.params.id}.csv"`);
      res.send(csv);
    } catch (error) {
      fail(res, error);
    }
  });

  // --- Agent deployment -----------------------------------------------------------------------

  router.get("/agent-deployment/releases", (req, res) => res.json(agentReleases.describe()));

  router.post("/agent-deployment/releases", admin, async (req, res) => {
    try {
      const upload = uploads.take((req.body || {}).uploadId, req.session.user, "agent-release");
      res.status(201).json({ release: await agentReleases.addFromUpload(upload, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.post("/agent-deployment/releases/:id/publish", admin, (req, res) => {
    if (!requireReauth(req, res, "PublishAgentRelease")) {
      return;
    }
    try {
      res.json({ release: agentReleases.publish(req.params.id, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.delete("/agent-deployment/releases/:id", admin, (req, res) => {
    if (!requireReauth(req, res, "DeleteAgentRelease")) {
      return;
    }
    try {
      agentReleases.remove(req.params.id, req.session.user);
      res.json({ ok: true });
    } catch (error) {
      fail(res, error);
    }
  });

  router.post("/agent-deployment/imports", admin, async (req, res) => {
    try {
      res.status(201).json({ import: await agentDeployment.create(req.body || {}, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/agent-deployment/imports", (req, res) => res.json({ imports: agentDeployment.list() }));

  router.get("/agent-deployment/imports/:id", (req, res) => {
    try {
      res.json({ import: agentDeployment.get(req.params.id) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/agent-deployment/imports/:id/records", (req, res) => {
    try {
      res.json(agentDeployment.queryRecords(req.params.id, req.query));
    } catch (error) {
      fail(res, error);
    }
  });

  router.patch("/agent-deployment/imports/:id/records/:row", admin, (req, res) => {
    try {
      res.json({ record: agentDeployment.setPlan(req.params.id, req.params.row, (req.body || {}).plan, req.session.user) });
    } catch (error) {
      fail(res, error);
    }
  });

  router.post("/agent-deployment/imports/:id/approve", admin, (req, res) => {
    const body = req.body || {};
    if (body.confirmed !== true) {
      return res.status(400).json({ error: "Confirm the deployment before approving it.", code: "confirmation_required" });
    }
    if (!requireReauth(req, res, "ApproveAgentImport")) {
      return;
    }
    try {
      res.json(agentDeployment.approve(req.params.id, body.options || {}, req.session.user));
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/agent-deployment/imports/:id/bundle", (req, res) => {
    try {
      const bundle = agentDeployment.bundle(req.params.id);
      res.setHeader("Content-Type", "application/zip");
      res.setHeader("Content-Disposition", `attachment; filename="${bundle.fileName}"`);
      res.send(bundle.data);
    } catch (error) {
      fail(res, error);
    }
  });

  router.get("/agent-deployment/imports/:id/export.csv", (req, res) => {
    try {
      const csv = agentDeployment.exportCsv(req.params.id);
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="agent-import-${req.params.id}.csv"`);
      res.send(csv);
    } catch (error) {
      fail(res, error);
    }
  });

  return router;
};
