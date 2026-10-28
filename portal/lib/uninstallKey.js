"use strict";

// Portal-specific uninstall verification key.
//
// Removing an agent (uninstalling it, or deleting its record) needs an Administrator, their password,
// and this key. The key is 25 characters, uppercase letters and digits, drawn from the operating system's
// CSPRNG. It is shown once when it is generated; the portal keeps only a salted scrypt hash of
// "<portal id>:<key>", so a key issued by another portal can never match here, and the file is useless
// to anyone who copies it. Rotation replaces the key; revocation leaves none, which blocks removals until
// a new one is generated. Failed attempts are rate limited per user and per portal and every outcome is
// audited, without the key.
const crypto = require("crypto");
const fs = require("fs");
const { stateFile, writeJson, readJson } = require("./statePath");

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const KEY_LENGTH = 25;
const SCRYPT = { N: 16384, r: 8, p: 1 };
const WINDOW_MS = 15 * 60 * 1000;
const MAX_USER_FAILURES = 5;
const MAX_PORTAL_FAILURES = 20;

function generateKey() {
  let key = "";
  for (let i = 0; i < KEY_LENGTH; i++) {
    key += ALPHABET[crypto.randomInt(ALPHABET.length)];
  }
  return key;
}

// Accepts the key as shown (five groups of five) or typed without separators, in any case.
function normalize(value) {
  return String(value || "").toUpperCase().replace(/[\s-]/g, "");
}

function format(key) {
  return key.match(/.{1,5}/g).join("-");
}

function hash(portalId, key, salt) {
  return crypto.scryptSync(`${portalId}:${key}`, Buffer.from(salt, "hex"), 32, SCRYPT).toString("hex");
}

function createUninstallKeys(options) {
  const { store, logger } = options;
  const file = options.file || stateFile("uninstall-key.json");
  const failures = { users: new Map(), portal: [] };
  let data = load();

  function load() {
    const existing = readJson(file);
    if (existing && typeof existing.portalId === "string" && existing.portalId) {
      return existing;
    }
    const fresh = { portalId: crypto.randomUUID(), key: null, revoked: null, history: [] };
    save(fresh);
    return fresh;
  }

  function save(next) {
    writeJson(file, next);
    fs.chmodSync(file, 0o600);
  }

  function status() {
    const key = data.key;
    return {
      portalId: data.portalId,
      configured: Boolean(key),
      revoked: data.revoked ? { utc: data.revoked.utc, by: data.revoked.by } : null,
      keyId: key ? key.id : null,
      hint: key ? key.hint : null,
      createdUtc: key ? key.createdUtc : null,
      createdBy: key ? key.createdBy : null,
      length: KEY_LENGTH
    };
  }

  function retire(reason, user) {
    if (data.key) {
      data.history.unshift({ id: data.key.id, createdUtc: data.key.createdUtc, createdBy: data.key.createdBy, retiredUtc: new Date().toISOString(), retiredBy: user, reason });
      data.history = data.history.slice(0, 20);
    }
  }

  // Creates the first key or replaces the current one. Returns the plaintext once.
  function issue(user, remoteIp, reason) {
    const rotating = Boolean(data.key);
    const key = generateKey();
    const salt = crypto.randomBytes(16).toString("hex");
    retire(rotating ? "rotated" : "replaced", user);
    data.key = {
      id: crypto.randomBytes(4).toString("hex").toUpperCase(),
      salt,
      hash: hash(data.portalId, key, salt),
      hint: key.slice(-4),
      createdUtc: new Date().toISOString(),
      createdBy: user
    };
    data.revoked = null;
    save(data);
    failures.users.clear();
    failures.portal = [];
    store.addAudit({
      user, agentId: null, action: rotating ? "UninstallKeyRotated" : "UninstallKeyGenerated", result: "Succeeded",
      details: `Uninstall verification key ${data.key.id} (ending ${data.key.hint}) ${rotating ? "replaced the previous key" : "was generated"}. Reason: ${reason}`,
      remoteIp
    });
    logger(`${user} ${rotating ? "rotated" : "generated"} the uninstall verification key (${data.key.id}).`);
    return { key: format(key), ...status() };
  }

  function revoke(user, remoteIp, reason) {
    if (!data.key) {
      return { ok: false, error: "There is no uninstall verification key to revoke." };
    }
    const id = data.key.id;
    retire("revoked", user);
    data.key = null;
    data.revoked = { utc: new Date().toISOString(), by: user };
    save(data);
    store.addAudit({
      user, agentId: null, action: "UninstallKeyRevoked", result: "Succeeded",
      details: `Uninstall verification key ${id} was revoked. Agents cannot be removed until a new key is generated. Reason: ${reason}`,
      remoteIp
    });
    logger(`${user} revoked the uninstall verification key (${id}).`);
    return { ok: true, ...status() };
  }

  function recent(list, now) {
    return list.filter((t) => now - t < WINDOW_MS);
  }

  /**
   * Checks a key for a removal. Audits refusals; the caller audits the removal itself.
   * @returns {{ ok: true } | { ok: false, status: number, code: string, error: string }}
   */
  function verify(candidate, user, remoteIp, agentId) {
    const now = Date.now();
    const userFailures = recent(failures.users.get(user) || [], now);
    failures.portal = recent(failures.portal, now);
    if (userFailures.length >= MAX_USER_FAILURES || failures.portal.length >= MAX_PORTAL_FAILURES) {
      const oldest = Math.min(...(userFailures.length >= MAX_USER_FAILURES ? userFailures : failures.portal));
      const minutes = Math.max(1, Math.ceil((oldest + WINDOW_MS - now) / 60000));
      store.addAudit({ user, agentId: agentId || null, action: "UninstallKeyCheck", result: "Denied", details: "Refused without checking: too many incorrect uninstall verification keys.", remoteIp });
      return { ok: false, status: 429, code: "rate_limited", error: `Too many incorrect uninstall verification keys. Try again in ${minutes} minute(s).` };
    }
    if (!data.key) {
      return {
        ok: false, status: 409, code: data.revoked ? "uninstall_key_revoked" : "uninstall_key_missing",
        error: data.revoked
          ? "The uninstall verification key was revoked. An Administrator must generate a new one in Settings before agents can be removed."
          : "No uninstall verification key has been generated for this portal. Generate one in Settings before removing agents."
      };
    }
    const value = normalize(candidate);
    const wellFormed = value.length === KEY_LENGTH && /^[A-Z0-9]+$/.test(value);
    const expected = Buffer.from(data.key.hash, "hex");
    const actual = Buffer.from(hash(data.portalId, wellFormed ? value : "-", data.key.salt), "hex");
    if (wellFormed && crypto.timingSafeEqual(expected, actual)) {
      failures.users.delete(user);
      return { ok: true, keyId: data.key.id };
    }
    userFailures.push(now);
    failures.users.set(user, userFailures);
    failures.portal.push(now);
    store.addAudit({
      user, agentId: agentId || null, action: "UninstallKeyCheck", result: "Denied",
      details: value ? `An incorrect uninstall verification key was entered (attempt ${userFailures.length} of ${MAX_USER_FAILURES}).` : "No uninstall verification key was entered.",
      remoteIp
    });
    return {
      ok: false, status: 403, code: "uninstall_key_invalid",
      error: value ? "The uninstall verification key is not correct for this portal." : "Enter this portal's uninstall verification key."
    };
  }

  return { status, issue, revoke, verify, KEY_LENGTH };
}

module.exports = { createUninstallKeys, generateKey, normalize, format, KEY_LENGTH, ALPHABET };
