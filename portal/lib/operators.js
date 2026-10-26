"use strict";

const crypto = require("crypto");
const { stateFile, writeJson, readJson } = require("./statePath");

const MIN_PASSWORD_LENGTH = 6;

function fieldError(message, field) {
  const error = new Error(message);
  error.field = field;
  return error;
}

// Portal sign-in accounts. The first start copies the environment password and requires a change
// before the rest of the dashboard can be used. Later passwords are stored only as scrypt hashes.
function createOperators(config) {
  const file = stateFile("operators.json");
  let users = load(file, config);

  function validate(username, password) {
    const user = find(username);
    if (!user || password === undefined || password === null || !verifyPassword(String(password), user.password)) {
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

  return { validate, changePassword, mustChange, file };

  function load(target, source) {
    const existing = readJson(target);
    if (Array.isArray(existing) && existing.length > 0) {
      return existing.filter((user) => user && user.username && user.password && user.role);
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
