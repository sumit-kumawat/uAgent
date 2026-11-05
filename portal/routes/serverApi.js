"use strict";

// The portal server's own administration (Linux only). Every role may view it; changes are for
// Administrators, need a reason, confirmation and the portal password, run one at a time, and are audited
// with who, when, what and the result. A domain password goes to the helper's standard input only.
const express = require("express");
const { Roles } = require("../lib/commandTypes");
const serverAdmin = require("../lib/serverAdmin");

module.exports = function serverApi({ store, auth, reauth, logger, admin }) {
  const router = express.Router();
  const sys = admin || serverAdmin;
  let running = null;

  router.use("/server", auth.requireApi);

  function audit(req, action, result, details) {
    store.addAudit({ user: req.session.user.name, action, result, details, remoteIp: req.ip, machineName: "Portal server" });
  }

  function portalSignIns() {
    return store.getAudit().filter((e) => e.action === "SignIn").slice(0, 30)
      .map((e) => ({ timeUtc: e.timestampUtc, user: e.user, result: e.result, details: e.details, remoteIp: e.remoteIp }));
  }

  function operations() {
    return store.getAudit().filter((e) => /^Server/.test(e.action)).slice(0, 200)
      .map((e) => ({ timeUtc: e.timestampUtc, user: e.user, action: e.action, result: e.result, details: e.details, remoteIp: e.remoteIp }));
  }

  router.get("/server/info", async (req, res, next) => {
    try {
      const info = await sys.collect();
      const signIns = portalSignIns();
      const lastAdmin = signIns.find((e) => e.result === "Success" && /as Administrator/.test(e.details || ""));
      res.set("Cache-Control", "no-store").json({
        ...info,
        portal: { signIns, lastAdministratorSignIn: lastAdmin || null, operations: operations(), running: running ? { summary: running.summary, startedUtc: running.startedUtc, user: running.user } : null },
        canChange: req.session.user.role === Roles.Administrator
      });
    } catch (error) {
      next(error);
    }
  });

  router.post("/server/actions", auth.requireRole(Roles.Administrator), async (req, res) => {
    const body = req.body || {};
    const info = sys.platform();
    if (!info.linux) {
      return res.status(409).json({ error: `Server administration is available on Linux. This portal runs on ${info.os}.`, code: "unsupported" });
    }
    if (!info.helperInstalled) {
      return res.status(409).json({ error: `${sys.HELPER} is not installed. Re-run the installer on the server.`, code: "unsupported" });
    }
    let plan;
    try {
      plan = sys.prepare(String(body.action || ""), body.parameters, typeof body.secret === "string" ? body.secret : "");
    } catch (error) {
      if (error instanceof sys.Invalid) {
        return res.status(400).json({ error: error.message, code: "invalid", field: error.field || null });
      }
      throw error;
    }
    const reason = String(body.reason || "").trim().slice(0, 500);
    if (!plan.readOnly) {
      if (body.confirmed !== true) {
        return res.status(400).json({ error: `${plan.label} must be confirmed.`, code: "confirmation_required" });
      }
      if (!reason) {
        return res.status(400).json({ error: `Give a reason for ${plan.label.toLowerCase()}; it is recorded in the audit log.`, code: "reason_required" });
      }
      if (!reauth.verify(req, res, "ServerAdministration", null)) {
        return;
      }
    }
    if (running) {
      return res.status(409).json({ error: `${running.summary} is still running (started by ${running.user}). Wait for it to finish.`, code: "in_progress" });
    }
    const action = `Server:${body.action}`;
    running = { summary: plan.summary, startedUtc: new Date().toISOString(), user: req.session.user.name };
    if (!plan.readOnly) {
      audit(req, action, "Pending", `${plan.summary}. Reason: ${reason}`);
    }
    try {
      const result = await sys.runHelper(plan.args, plan.input || null, 240000);
      plan.input = null;
      const message = String(result.message || result.error || "").slice(0, 3000);
      if (!plan.readOnly || !result.ok) {
        audit(req, action, result.ok ? "Success" : "Failed", `${plan.summary}: ${message}`);
      }
      logger(`${req.session.user.name} ran server action ${body.action}: ${result.ok ? "succeeded" : "failed"}.`);
      if (!result.ok) {
        return res.status(result.field ? 400 : 502).json({ error: result.error || "The change failed.", code: "failed", field: result.field || null });
      }
      res.json({ ok: true, summary: plan.summary, message, pending: Boolean(result.pending), revertSeconds: result.revertSeconds || null });
    } finally {
      running = null;
    }
  });

  // The browser calls this after a firewall change if it can still reach the portal. If it cannot, the
  // change is undone by the helper's timer.
  router.post("/server/firewall/confirm", auth.requireRole(Roles.Administrator), async (req, res) => {
    const result = await sys.runHelper(["firewall", "confirm"], null, 60000);
    audit(req, "Server:firewall-confirm", result.ok ? "Success" : "Failed", String(result.message || result.error || ""));
    if (!result.ok) {
      return res.status(409).json({ error: result.error, code: "failed" });
    }
    res.json({ ok: true, message: result.message });
  });

  router.get("/server/logs/:source", auth.requireRole(Roles.Administrator), async (req, res) => {
    const source = req.params.source;
    if (!sys.LOG_SOURCES.includes(source)) {
      return res.status(404).json({ error: "Unknown log.", code: "not_found" });
    }
    if (!sys.platform().helperInstalled) {
      return res.status(409).json({ error: "Server logs need the uagent-sysadmin helper. Re-run the installer on the server.", code: "unsupported" });
    }
    const lines = Math.min(Math.max(Number.parseInt(req.query.lines, 10) || 1000, 1), 10000);
    const result = await sys.runHelper(["logs", source, String(lines)], null, 90000);
    if (!result.ok) {
      return res.status(502).json({ error: result.error, code: "failed" });
    }
    audit(req, "Server:logs", "Success", `Viewed the last ${lines} lines of the ${source} log.`);
    res.set("Cache-Control", "no-store").type("text/plain").send(result.text || "");
  });

  return router;
};
