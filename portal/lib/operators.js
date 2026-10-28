"use strict";

const crypto = require("crypto");
const fs = require("fs");
const { stateFile, writeJson, readJson } = require("./statePath");

const MIN_PASSWORD_LENGTH = 6;

// Written by a reset that clears portal accounts; removed when setup creates the new administrator.
function setupMarker() {
  return stateFile("setup-required");
}

function setupCodeFile() {
  return stateFile("setup-code");
}

function fieldError(message, field) {
  const error = new Error(message);
  error.field = field;
  return error;
}

// Portal sign-in accounts. The first start copies the environment password and requires a change
// before the rest of the dashboard can be used. Later passwords are stored only as scrypt hashes.
function createOperators(config, logger) {
  const file = stateFile("operators.json");
  let users = load(file, config);
  let epoch = 1;

  function validate(username, password) {
    if (password === undefined || password === null) {
      return null;
    }
    const user = find(username);
    // Unknown users still pay for a hash so response timing does not reveal which usernames exist.
    const ok = verifyPassword(String(password), user ? user.password : UNKNOWN_USER_HASH);
    if (!user || !ok) {
      return null;
    }
    return { name: user.username, role: user.role, mustChangePassword: Boolean(user.mustChangePassword) };
  }

  function changePassword(username, currentPassword, nextPassword) {
    const user = find(username);
    if (!user || !verifyPassword(String(currentPassword || ""), user.password)) {
      throw fieldError("The current password is not correct.", "currentPassword");
    }
    const next = String(nextPassword || "");
    if (next.length < MIN_PASSWORD_LENGTH) {
      throw fieldError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`, "newPassword");
    }
    if (next.length > 256) {
      throw fieldError("Use at most 256 characters.", "newPassword");
    }
    if (verifyPassword(next, user.password)) {
      throw fieldError("Choose a password that is different from the current one.", "newPassword");
    }
    if (next.toLowerCase() === user.username.toLowerCase()) {
      throw fieldError("The password cannot match the username.", "newPassword");
    }
    user.password = hashPassword(next);
    user.mustChangePassword = false;
    save();
  }

  function find(username) {
    const wanted = String(username || "").trim().toLowerCase();
    return users.find((user) => user.username.toLowerCase() === wanted) || null;
  }

  function save() {
    writeJson(file, users.map((user) => ({
      username: user.username,
      password: user.password,
      role: user.role,
      mustChangePassword: Boolean(user.mustChangePassword)
    })));
  }

  function mustChange(username) {
    const user = find(username);
    return Boolean(user && user.mustChangePassword);
  }

  function hasAccounts() {
    return users.length > 0;
  }

  function accounts() {
    return users.map((user) => ({ username: user.username, role: user.role, mustChangePassword: Boolean(user.mustChangePassword) }));
  }

  /**
   * Creates the first administrator during setup. It is refused once any account exists, so this can
   * never be used to add an account to a running installation.
   */
  function createFirstAdministrator(username, password, confirm, code) {
    if (users.length > 0) {
      throw fieldError("This portal already has an account, so setup is finished. Sign in instead.", "username");
    }
    const expected = Buffer.from(setupCode(), "utf8");
    const given = Buffer.from(String(code || "").toUpperCase().replace(/[\s-]/g, ""), "utf8");
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
      throw fieldError(`Enter the setup code from the server: sudo cat ${setupCodeFile()}`, "setupCode");
    }
    const name = String(username || "").trim();
    if (!/^[a-zA-Z0-9._-]{3,64}$/.test(name)) {
      throw fieldError("Use 3 to 64 characters: letters, numbers, dots, hyphens or underscores.", "username");
    }
    const next = String(password || "");
    if (next.length < MIN_PASSWORD_LENGTH) {
      throw fieldError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`, "password");
    }
    if (next.length > 256) {
      throw fieldError("Use at most 256 characters.", "password");
    }
    if (next !== String(confirm || "")) {
      throw fieldError("The passwords do not match.", "confirmPassword");
    }
    if (next.toLowerCase() === name.toLowerCase()) {
      throw fieldError("The password cannot match the username.", "password");
    }
    users.push({ username: name, password: hashPassword(next), role: "Administrator", mustChangePassword: false });
    save();
    fs.rmSync(setupMarker(), { force: true });
    fs.rmSync(setupCodeFile(), { force: true });
    return { name, role: "Administrator", mustChangePassword: false };
  }

  // Clears every account. Sessions signed in before this are no longer accepted (see sessionEpoch).
  function requireSetup() {
    fs.mkdirSync(require("path").dirname(setupMarker()), { recursive: true });
    fs.writeFileSync(setupMarker(), `${new Date().toISOString()}\n`, { mode: 0o600 });
    users = [];
    epoch += 1;
    fs.rmSync(setupCodeFile(), { force: true });
    setupCode();
  }

  // A one-time code that only someone with access to the server can read, so whoever happens to reach
  // the setup page first after a reset cannot claim the portal.
  function setupCode() {
    const existing = fs.existsSync(setupCodeFile()) ? fs.readFileSync(setupCodeFile(), "utf8").trim() : "";
    if (/^[A-Z0-9]{12}$/.test(existing)) {
      return existing;
    }
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let fresh = "";
    for (let i = 0; i < 12; i++) {
      fresh += alphabet[crypto.randomInt(alphabet.length)];
    }
    fs.mkdirSync(require("path").dirname(setupCodeFile()), { recursive: true });
    fs.writeFileSync(setupCodeFile(), `${fresh}\n`, { mode: 0o600 });
    if (typeof logger === "function") {
      logger(`Setup is required. The one-time setup code is in ${setupCodeFile()} (readable by root and the service account).`);
    }
    return fresh;
  }

  function sessionEpoch() {
    return epoch;
  }

  // The marker only stops the environment password being seeded again; accounts restored from a backup
  // end setup, so a restore can never leave the portal pointing at a setup page that refuses to run.
  function setupPending() {
    return users.length === 0;
  }

  return {
    validate, changePassword, mustChange, hasAccounts, accounts, createFirstAdministrator, requireSetup, setupPending,
    setupCode, setupCodeFile, sessionEpoch,
    minPasswordLength: MIN_PASSWORD_LENGTH
  };

  function load(target, source) {
    const existing = readJson(target);
    const valid = Array.isArray(existing)
      ? existing.filter((user) => user && typeof user.username === "string" && typeof user.password === "string" && user.role)
      : [];
    if (valid.length > 0) {
      fs.rmSync(setupMarker(), { force: true });
      return valid;
    }
    // A reset leaves this marker so the environment password is not seeded again behind the
    // administrator's back: the portal must go through setup and have an account created deliberately.
    if (fs.existsSync(setupMarker())) {
      return [];
    }
    const seeded = source.users.map((user) => ({
      username: user.username,
      password: hashPassword(user.password || oneTimePassword(user.username)),
      role: user.role,
      mustChangePassword: true
    }));
    writeJson(target, seeded);
    return seeded;
  }
}

function oneTimePassword(username) {
  const password = crypto.randomBytes(12).toString("base64url");
  console.log(`[${new Date().toISOString()}] First sign-in: user "${username}", one-time password ${password} (must be changed at sign-in).`);
  return password;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(password), salt, 32).toString("hex");
  return `scrypt$${salt}$${hash}`;
}

const UNKNOWN_USER_HASH = hashPassword(crypto.randomBytes(16).toString("hex"));

function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") {
    return false;
  }
  const got = crypto.scryptSync(password, parts[1], 32);
  const expected = Buffer.from(parts[2], "hex");
  if (got.length !== expected.length) {
    return false;
  }
  return crypto.timingSafeEqual(got, expected);
}

module.exports = { createOperators };
