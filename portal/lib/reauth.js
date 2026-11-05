"use strict";

const MAX_FAILURES = 3;
const WINDOW_MS = 15 * 60 * 1000;

// Sensitive actions require the operator's current password, so a stolen or unattended session
// cannot use them. Repeated failures end the session. Shared by every router so the failure count
// cannot be reset by switching endpoints.
function createReauth(auth, store, logger) {
  const failures = new Map();

  // Checks the password in body.currentPassword and records a failure. Returns { ok, lockout, password };
  // on lockout the session has already been destroyed. The caller sends the response.
  function check(req, action, agentId) {
    const user = req.session.user;
    const password = typeof req.body?.currentPassword === "string" ? req.body.currentPassword : "";
    if (password && auth.validate(user.name, password)) {
      failures.delete(user.name);
      return { ok: true, lockout: false, password };
    }
    const now = Date.now();
    const recent = (failures.get(user.name) || []).filter((t) => now - t < WINDOW_MS);
    recent.push(now);
    failures.set(user.name, recent);
    const lockout = recent.length >= MAX_FAILURES;
    store.addAudit({
      user: user.name,
      agentId: agentId || null,
      action,
      result: "Denied",
      details: lockout
        ? `Password confirmation failed ${recent.length} times; the session was signed out.`
        : "Password confirmation failed.",
      remoteIp: req.ip
    });
    if (lockout) {
      failures.delete(user.name);
      logger(`Signed out ${user.name} after ${MAX_FAILURES} failed password confirmations for ${action}.`);
      req.session.destroy(() => {});
    }
    return { ok: false, lockout, password };
  }

  function verify(req, res, action, agentId) {
    const result = check(req, action, agentId);
    if (result.ok) {
      return true;
    }
    if (result.lockout) {
      res.status(401).json({ error: "Too many failed password confirmations. You have been signed out.", code: "unauthenticated" });
      return false;
    }
    res.status(403).json({
      error: result.password ? "The password is incorrect." : "Enter your portal password to confirm this action.",
      code: "reauth_failed",
      field: "currentPassword"
    });
    return false;
  }

  return { check, verify };
}

module.exports = { createReauth };
