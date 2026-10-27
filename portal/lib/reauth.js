"use strict";

const MAX_FAILURES = 3;
const WINDOW_MS = 15 * 60 * 1000;

// Sensitive actions require the operator's current password, so a stolen or unattended session
// cannot use them. Repeated failures end the session. Shared by every router so the failure count
// cannot be reset by switching endpoints.
function createReauth(auth, store, logger) {
  const failures = new Map();

  function verify(req, res, action, agentId) {
    const user = req.session.user;
    const password = typeof req.body?.currentPassword === "string" ? req.body.currentPassword : "";
    if (password && auth.validate(user.name, password)) {
      failures.delete(user.name);
      return true;
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
      res.status(401).json({ error: "Too many failed password confirmations. You have been signed out.", code: "unauthenticated" });
      return false;
    }
    res.status(403).json({ error: password ? "The password is incorrect." : "Enter your portal password to confirm this action.", code: "reauth_failed" });
    return false;
  }

  return { verify };
}

module.exports = { createReauth };
