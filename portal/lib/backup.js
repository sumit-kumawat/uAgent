"use strict";

// Backups exist so that a repair, an update or a reset can be undone. Every destructive operation takes one
// first, verifies it can be read back, and refuses to continue if it cannot.
//
// A backup is an ordinary ZIP holding the portal's state files plus a manifest with a SHA-256 for each one.
// Nothing proprietary is needed to open it, and verification re-reads the archive from disk rather than
// trusting what was just written in memory.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { stateFile } = require("./statePath");
const zipFile = require("./zipFile");

const MANIFEST = "manifest.json";
const FORMAT = 1;

// Everything the portal keeps. Each entry says what it holds, so an administrator can see what a backup
// covers and what a reset would clear, rather than being asked to trust one word like "data".
const STATE_FILES = [
  { name: "portal-store.json", holds: "agents, inventory, action history and the audit log" },
  { name: "operators.json", holds: "portal sign-in accounts and password hashes" },
  { name: "portal-host.json", holds: "the address agents are told to contact" },
  { name: "vault-secrets.json", holds: "stored deployment secrets (encrypted)" },
  { name: "vault.key", holds: "the key that decrypts stored secrets" },
  { name: "software-library.json", holds: "the software package library and approvals" },
  { name: "deployments.json", holds: "deployment jobs and their history" },
  { name: "deploy-targets.json", holds: "saved target groups and validation results" },
  { name: "agent-releases.json", holds: "agent releases offered for upgrade" },
  { name: "agent-imports.json", holds: "imported installation plans" },
  { name: "maintenance.json", holds: "the record of repair, update and reset operations" },
  { name: "uninstall-key.json", holds: "this portal's identity and the hash of its uninstall verification key" }
];

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function backupDirectory() {
  return path.dirname(stateFile("backups/.keep"));
}

function describeState() {
  return STATE_FILES.map((entry) => {
    const file = stateFile(entry.name);
    let bytes = null;
    let modifiedUtc = null;
    try {
      const stat = fs.statSync(file);
      bytes = stat.size;
      modifiedUtc = stat.mtime.toISOString();
    } catch (error) {
      // Not every file exists on every installation.
    }
    return Object.assign({}, entry, { present: bytes !== null, bytes, modifiedUtc });
  });
}

/**
 * Writes a backup and verifies it by reading it back.
 *
 * @param {object} options `{ user, reason, label, extra }`. `extra` adds files from outside the state
 *                         directory, such as the TLS certificate, as `{ name, file }`.
 * @returns the manifest, including the archive's own SHA-256.
 */
function create(options) {
  const user = (options && options.user) || "system";
  const reason = (options && options.reason) || "";
  const label = ((options && options.label) || "backup").replace(/[^a-z0-9-]/gi, "-").toLowerCase();
  const createdUtc = new Date().toISOString();
  const id = `${createdUtc.replace(/[:.]/g, "-")}-${label}`;
  const directory = backupDirectory();
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });

  const files = [];
  const contents = [];
  for (const entry of STATE_FILES) {
    const source = stateFile(entry.name);
    if (!fs.existsSync(source)) {
      continue;
    }
    const data = fs.readFileSync(source);
    files.push({ name: `state/${entry.name}`, data });
    contents.push({ name: `state/${entry.name}`, bytes: data.length, sha256: sha256(data), holds: entry.holds });
  }
  for (const entry of (options && options.extra) || []) {
    if (!entry.file || !fs.existsSync(entry.file)) {
      continue;
    }
    const data = fs.readFileSync(entry.file);
    files.push({ name: entry.name, data });
    contents.push({ name: entry.name, bytes: data.length, sha256: sha256(data), holds: entry.holds || "" });
  }
  if (!contents.length) {
    throw new Error("There is nothing to back up: no portal state files exist yet.");
  }

  const manifest = { format: FORMAT, id, createdUtc, user, reason, label, contents };
  files.unshift({ name: MANIFEST, data: Buffer.from(JSON.stringify(manifest, null, 2)) });

  const file = path.join(directory, `${id}.zip`);
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, zipFile.build(files), { mode: 0o600 });
  fs.renameSync(tmp, file);

  const check = verify(file);
  if (!check.ok) {
    throw new Error(`The backup was written to ${file} but could not be verified (${check.problems.join("; ")}), so the operation was stopped.`);
  }
  return Object.assign({}, manifest, { file, sizeBytes: check.sizeBytes, sha256: check.sha256, verified: true });
}

/** Reads a backup from disk and checks every file against the manifest. */
function verify(file) {
  const problems = [];
  let manifest = null;
  let entries = null;
  let archive = null;
  try {
    archive = fs.readFileSync(file);
    entries = zipFile.readEntries(archive);
  } catch (error) {
    return { ok: false, file, problems: [`The backup could not be read: ${error.message}`] };
  }
  try {
    manifest = JSON.parse(entries.get(MANIFEST).toString("utf8"));
  } catch (error) {
    return { ok: false, file, problems: ["The backup has no readable manifest."] };
  }
  for (const item of manifest.contents || []) {
    const data = entries.get(item.name);
    if (!data) {
      problems.push(`${item.name} is missing from the backup.`);
    } else if (sha256(data) !== item.sha256) {
      problems.push(`${item.name} does not match its recorded checksum.`);
    }
  }
  return {
    ok: problems.length === 0,
    file,
    manifest,
    sizeBytes: archive.length,
    sha256: sha256(archive),
    problems
  };
}

function list() {
  const directory = backupDirectory();
  let names = [];
  try {
    names = fs.readdirSync(directory).filter((name) => name.endsWith(".zip"));
  } catch (error) {
    return [];
  }
  return names.map((name) => {
    const file = path.join(directory, name);
    const stat = fs.statSync(file);
    let manifest = null;
    try {
      manifest = JSON.parse(zipFile.readEntries(fs.readFileSync(file)).get(MANIFEST).toString("utf8"));
    } catch (error) {
      manifest = null;
    }
    return {
      id: manifest ? manifest.id : name.replace(/\.zip$/, ""),
      file,
      name,
      sizeBytes: stat.size,
      createdUtc: manifest ? manifest.createdUtc : stat.mtime.toISOString(),
      user: manifest ? manifest.user : "",
      reason: manifest ? manifest.reason : "",
      label: manifest ? manifest.label : "",
      readable: Boolean(manifest),
      contents: manifest && Array.isArray(manifest.contents) ? manifest.contents.map((item) => item && item.name).filter(Boolean) : []
    };
  }).sort((a, b) => String(b.createdUtc).localeCompare(String(a.createdUtc)));
}

/**
 * Puts the state files from a backup back in place.
 *
 * A safety backup of the current state is taken first, so a restore can itself be undone. Files are written
 * to temporary names and then renamed, so an interruption leaves either the old file or the new one, never
 * a half-written one. The caller must restart the portal afterwards: the modules hold their state in memory.
 */
function restore(file, options) {
  const check = verify(file);
  if (!check.ok) {
    throw new Error(`This backup cannot be restored: ${check.problems.join("; ")}`);
  }
  const safety = (options && options.skipSafetyBackup)
    ? null
    : create({ user: (options && options.user) || "system", label: "before-restore", reason: `Taken automatically before restoring ${path.basename(file)}.` });

  const entries = zipFile.readEntries(fs.readFileSync(file));
  const restored = [];
  const staged = [];
  try {
    for (const item of check.manifest.contents) {
      if (!item.name.startsWith("state/")) {
        continue;
      }
      const target = stateFile(item.name.slice("state/".length));
      const tmp = `${target}.restore.tmp`;
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(tmp, entries.get(item.name), { mode: 0o600 });
      staged.push({ tmp, target });
    }
    for (const item of staged) {
      fs.renameSync(item.tmp, item.target);
      restored.push(path.basename(item.target));
    }
  } finally {
    staged.forEach((item) => fs.rmSync(item.tmp, { force: true }));
  }
  return { restored, safety: safety ? safety.file : null, from: file, manifest: check.manifest };
}

/** Removes the state files listed in `names`, keeping a verified backup first. */
function clearState(names, options) {
  const backup = create({
    user: (options && options.user) || "system",
    label: (options && options.label) || "before-reset",
    reason: (options && options.reason) || ""
  });
  const removed = [];
  for (const name of names) {
    const file = stateFile(name);
    if (fs.existsSync(file)) {
      fs.rmSync(file, { force: true });
      removed.push(name);
    }
  }
  return { removed, backup };
}

module.exports = { create, verify, list, restore, clearState, describeState, backupDirectory, STATE_FILES };
