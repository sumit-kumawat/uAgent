"use strict";

// The portal-specific uninstall verification key.
//
// What these tests are protecting:
//   * the key is 25 uppercase letters and digits, random, and shown only once; the file holds a hash.
//   * a key from another portal never matches, even with an identical key file layout.
//   * rotation retires the old key at once, and revocation blocks removal until a new key exists.
//   * wrong keys are rate limited per user, every refusal is audited, and no audit entry holds the key.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { createUninstallKeys, generateKey, normalize, ALPHABET } = require("../lib/uninstallKey");

function harness(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `uagent-ukey-${name}-`));
  const audit = [];
  const store = { addAudit: (entry) => audit.push(entry) };
  const keys = createUninstallKeys({ store, logger: () => {}, file: path.join(dir, "uninstall-key.json") });
  return { dir, audit, keys, file: path.join(dir, "uninstall-key.json") };
}

test("keys are 25 random uppercase alphanumerics", () => {
  const seen = new Set();
  const counts = new Map();
  for (let i = 0; i < 400; i++) {
    const key = generateKey();
    assert.match(key, /^[A-Z0-9]{25}$/);
    seen.add(key);
    for (const ch of key) { counts.set(ch, (counts.get(ch) || 0) + 1); }
  }
  assert.equal(seen.size, 400, "keys must not repeat");
  assert.equal(counts.size, ALPHABET.length, "every letter and digit should appear");
  // 10,000 characters over 36 symbols: about 278 each. A broken generator is far outside this band.
  for (const [ch, n] of counts) { assert.ok(n > 180 && n < 380, `${ch} appeared ${n} times`); }
  assert.equal(normalize("abcde-fghij klmno-pqrst-uvw12"), "ABCDEFGHIJKLMNOPQRSTUVW12");
});

test("issue shows the key once and stores only a hash", () => {
  const { keys, file, audit, dir } = harness("issue");
  try {
    assert.equal(keys.verify("", "admin", "192.0.2.1").code, "uninstall_key_missing");
    const issued = keys.issue("admin", "192.0.2.1", "First key");
    assert.match(issued.key, /^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$/);
    const plain = issued.key.replace(/-/g, "");
    const saved = fs.readFileSync(file, "utf8");
    assert.ok(!saved.includes(plain), "the key file must not contain the key");
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(keys.status().key, undefined, "status never returns the key");
    assert.equal(keys.status().hint, plain.slice(-4));
    assert.ok(keys.verify(issued.key, "admin", "192.0.2.1").ok);
    assert.ok(keys.verify(plain.toLowerCase(), "admin", "192.0.2.1").ok, "case and separators do not matter");
    assert.ok(audit.some((entry) => entry.action === "UninstallKeyGenerated"));
    assert.ok(!JSON.stringify(audit).includes(plain), "audit entries must not contain the key");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a key from another portal does not match", () => {
  const a = harness("a");
  const b = harness("b");
  try {
    const issued = a.keys.issue("admin", "192.0.2.1", "Portal A key");
    b.keys.issue("admin", "192.0.2.1", "Portal B key");
    assert.notEqual(a.keys.status().portalId, b.keys.status().portalId);
    assert.equal(b.keys.verify(issued.key, "admin", "192.0.2.1").code, "uninstall_key_invalid");

    // Even with portal B's file carrying portal A's salt and hash, the portal identity is part of the hash.
    const fileA = JSON.parse(fs.readFileSync(a.file, "utf8"));
    const fileB = JSON.parse(fs.readFileSync(b.file, "utf8"));
    fileB.key = fileA.key;
    fs.writeFileSync(b.file, JSON.stringify(fileB));
    const reloaded = createUninstallKeys({ store: { addAudit() {} }, logger: () => {}, file: b.file });
    assert.equal(reloaded.verify(issued.key, "admin", "192.0.2.1").code, "uninstall_key_invalid");
  } finally {
    fs.rmSync(a.dir, { recursive: true, force: true });
    fs.rmSync(b.dir, { recursive: true, force: true });
  }
});

test("rotation retires the old key and revocation blocks removal", () => {
  const { keys, audit, dir } = harness("rotate");
  try {
    const first = keys.issue("admin", "192.0.2.1", "First key");
    const second = keys.issue("admin", "192.0.2.1", "Scheduled rotation");
    assert.notEqual(first.key, second.key);
    assert.equal(keys.verify(first.key, "admin", "192.0.2.1").code, "uninstall_key_invalid");
    assert.ok(keys.verify(second.key, "admin", "192.0.2.1").ok);
    assert.ok(audit.some((entry) => entry.action === "UninstallKeyRotated"));

    assert.ok(keys.revoke("admin", "192.0.2.1", "Key exposed").ok);
    const refused = keys.verify(second.key, "admin", "192.0.2.1");
    assert.equal(refused.status, 409);
    assert.equal(refused.code, "uninstall_key_revoked");
    assert.equal(keys.status().configured, false);
    assert.ok(keys.status().revoked);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("wrong keys are rate limited per user and audited", () => {
  const { keys, audit, dir } = harness("rate");
  try {
    const issued = keys.issue("admin", "192.0.2.1", "First key");
    for (let i = 0; i < 5; i++) {
      assert.equal(keys.verify("AAAAAAAAAAAAAAAAAAAAAAAAA", "mallory", "192.0.2.9").status, 403);
    }
    const limited = keys.verify(issued.key, "mallory", "192.0.2.9");
    assert.equal(limited.status, 429, "even the right key is refused once the limit is reached");
    assert.ok(keys.verify(issued.key, "admin", "192.0.2.1").ok, "other users are not locked out by one user");
    const denials = audit.filter((entry) => entry.action === "UninstallKeyCheck" && entry.result === "Denied");
    assert.equal(denials.length, 6);
    assert.ok(denials.every((entry) => entry.user === "mallory"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
