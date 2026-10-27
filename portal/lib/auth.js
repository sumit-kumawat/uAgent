"use strict";

const crypto = require("crypto");
const { roleAllows } = require("./commandTypes");

// Fixed-time string comparison to avoid leaking content timing on credentials and API keys.
function safeEqual(a, b) {
  const hashA = crypto.createHash("sha256").update(String(a), "utf8").digest();
  const hashB = crypto.createHash("sha256").update(String(b), "utf8").digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

// Per-IP login throttle: 5 failures within 15 minutes triggers a 5-second lockout.
class LoginThrottle {
  constructor() {
    this.attempts = new Map();
    this.maxFailures = 5;
    this.lockoutMs = 5000;
    this.windowMs = 15 * 60 * 1000;
    this.maxTracked = 10000;
  }

  lockoutRemaining(ip) {
    const entry = this.attempts.get(ip);
    if (entry && entry.lockedUntil) {
      const remaining = entry.lockedUntil - Date.now();
      if (remaining > 0) {
        return remaining;
      }
    }
    return 0;
  }

  registerFailure(ip) {
    const now = Date.now();
    if (!this.attempts.has(ip) && this.attempts.size >= this.maxTracked) {
      this._prune(now);
    }
    let entry = this.attempts.get(ip);
    if (!entry || (now - entry.lastFailure > this.windowMs && entry.lockedUntil <= now)) {
      entry = { failures: 0, lockedUntil: 0, lastFailure: now };
    }
    entry.lastFailure = now;
    entry.failures += 1;
    if (entry.failures >= this.maxFailures) {
      entry.lockedUntil = Date.now() + this.lockoutMs;
      entry.failures = 0;
    }
    this.attempts.set(ip, entry);
  }

  reset(ip) {
    this.attempts.delete(ip);
  }

  _prune(now) {
    for (const [ip, entry] of this.attempts) {
      if (now - entry.lastFailure > this.windowMs && entry.lockedUntil <= now) {
        this.attempts.delete(ip);
      }
    }
    if (this.attempts.size >= this.maxTracked) {
      this.attempts.delete(this.attempts.keys().next().value);
    }
  }
}

function createAuth(operators) {
  const throttle = new LoginThrottle();

  // Validates portal sign-in credentials. Returns { name, role, mustChangePassword } or null.
  function validate(username, password) {
    return operators.validate(username, password);
  }

  // Guards portal pages: redirect browsers to the login page (relative, so host and protocol are preserved).
  function requirePage(req, res, next) {
    if (req.session && req.session.user) {
      return next();
    }
    const returnUrl = encodeURIComponent(req.originalUrl);
    return res.redirect(`/login?returnUrl=${returnUrl}`);
  }

  // Guards operator JSON APIs: 401 instead of a redirect.
  function requireApi(req, res, next) {
    if (req.session && req.session.user) {
      return next();
    }
    return res.status(401).json({ error: "Your session has expired. Sign in again.", code: "unauthenticated" });
  }

  function requireRole(minRole) {
    return function (req, res, next) {
      const role = req.session && req.session.user ? req.session.user.role : "";
      if (roleAllows(role, minRole)) {
        return next();
      }
      return res.status(403).json({
        error: `This action requires the ${minRole} role. You are signed in as ${role || "unknown"}.`,
        code: "forbidden"
      });
    };
  }

  return { validate, requirePage, requireApi, requireRole, safeEqual, throttle };
}

module.exports = { createAuth, safeEqual };
