"use strict";

const crypto = require("crypto");
const { stateFile, writeJson, readJson } = require("./statePath");

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
      throw new Error("The current password is not correct.");
    }
    const next = String(nextPassword || "");
    if (next.length < 12) {
      throw new Error("Use at least 12 characters.");
    }
    if (verifyPassword(next, user.password)) {
      throw new Error("Choose a password that is different from the one printed at install.");
    }
    if (next.toLowerCase() === user.username.toLowerCase()) {
      throw new Error("The password cannot match the username.");
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
      password: hashPassword(user.password),
      role: user.role,
      mustChangePassword: true
    }));
    writeJson(target, seeded);
    return seeded;
  }
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
