"use strict";

// Encrypted store for values that installer arguments need, such as license keys. Values are sealed
// with AES-256-GCM under a key file readable only by the portal service, are never returned by the API,
// and are resolved only when a command is dispatched to an authenticated agent. Every change is audited.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { writeJson, readJson } = require("./statePath");

const NAME_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const REFERENCE_PATTERN = /\{\{secret:([A-Za-z][A-Za-z0-9_.-]{0,63})\}\}/g;

function loadKey(keyFile) {
  try {
    const key = Buffer.from(fs.readFileSync(keyFile, "utf8").trim(), "base64");
    if (key.length === 32) {
      return key;
    }
  } catch {
    // Created below.
  }
  if (fs.existsSync(keyFile)) {
    throw new Error(`The vault key in ${keyFile} is not a 32-byte base64 value. Restore it from backup; secrets sealed with it cannot be read otherwise.`);
  }
  const key = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(keyFile), { recursive: true });
  fs.writeFileSync(keyFile, key.toString("base64") + "\n", { mode: 0o600 });
  return key;
}

function createSecretVault(file, keyFile, store) {
  const key = loadKey(keyFile);
  const saved = readJson(file);
  const secrets = new Map(saved && Array.isArray(saved.secrets) ? saved.secrets.map((s) => [s.name, s]) : []);

  function persist() {
    writeJson(file, { secrets: [...secrets.values()] });
  }

  function seal(value) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const data = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
    return { iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") };
  }

  function open(sealed) {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(sealed.iv, "base64"));
    decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(sealed.data, "base64")), decipher.final()]).toString("utf8");
  }

  function view(s) {
    return { name: s.name, description: s.description, createdBy: s.createdBy, createdUtc: s.createdUtc, rotatedUtc: s.rotatedUtc, lastUsedUtc: s.lastUsedUtc, useCount: s.useCount || 0 };
  }

  function validateValue(value) {
    if (typeof value !== "string" || value.length === 0 || value.length > 4096) {
      const error = new Error("Enter a value between 1 and 4096 characters.");
      error.field = "value";
      throw error;
    }
  }

  function create({ name, value, description }, user) {
    if (!NAME_PATTERN.test(String(name || ""))) {
      const error = new Error("Use 1-64 letters, digits, '.', '_' or '-', starting with a letter.");
      error.field = "name";
      throw error;
    }
    if (secrets.has(name)) {
      const error = new Error(`A secret named ${name} already exists. Rotate it instead.`);
      error.field = "name";
      throw error;
    }
    validateValue(value);
    const now = new Date().toISOString();
    secrets.set(name, { name, description: String(description || "").slice(0, 300), sealed: seal(value), createdBy: user.name, createdUtc: now, rotatedUtc: null, lastUsedUtc: null, useCount: 0 });
    persist();
    store.addAudit({ user: user.name, action: "SecretCreated", result: "Success", details: `Created vault secret ${name}.` });
    return view(secrets.get(name));
  }

  function rotate(name, value, user) {
    const secret = secrets.get(name);
    if (!secret) {
      return null;
    }
    validateValue(value);
    secret.sealed = seal(value);
    secret.rotatedUtc = new Date().toISOString();
    persist();
    store.addAudit({ user: user.name, action: "SecretRotated", result: "Success", details: `Rotated vault secret ${name}.` });
    return view(secret);
  }

  function remove(name, user) {
    if (!secrets.delete(name)) {
      return false;
    }
    persist();
    store.addAudit({ user: user.name, action: "SecretDeleted", result: "Success", details: `Deleted vault secret ${name}.` });
    return true;
  }

  function references(text) {
    return [...new Set([...String(text || "").matchAll(REFERENCE_PATTERN)].map((m) => m[1]))];
  }

  function missing(text) {
    return references(text).filter((name) => !secrets.has(name));
  }

  // Replaces {{secret:NAME}} with the plaintext for dispatch and returns the values to redact.
  function resolve(text) {
    const values = [];
    const names = references(text);
    const now = new Date().toISOString();
    const resolved = String(text || "").replace(REFERENCE_PATTERN, (match, name) => {
      const secret = secrets.get(name);
      if (!secret) {
        throw new Error(`The vault secret ${name} referenced by the install arguments no longer exists.`);
      }
      const value = open(secret.sealed);
      values.push(value);
      return value;
    });
    for (const name of names) {
      const secret = secrets.get(name);
      secret.lastUsedUtc = now;
      secret.useCount = (secret.useCount || 0) + 1;
    }
    if (names.length) {
      persist();
    }
    return { text: resolved, redactions: values };
  }

  return {
    list: () => [...secrets.values()].map(view).sort((a, b) => a.name.localeCompare(b.name)),
    create,
    rotate,
    remove,
    references,
    missing,
    resolve
  };
}

function redact(text, values) {
  let out = String(text == null ? "" : text);
  for (const value of values || []) {
    if (value && value.length >= 3) {
      out = out.split(value).join("********");
    }
  }
  return out;
}

module.exports = { createSecretVault, redact };
