"use strict";

// Repository of uAgent installer builds. Administrators upload signed releases; publishing one makes it
// the installer served on the Download page and the build enrolled agents pull for self-update. The
// currently published build is the authoritative source for upgrade jobs.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { writeJson, readJson } = require("./statePath");
const { detectType, inspectPe } = require("./binaryInspect");
const { hashFile, numericVersion } = require("./softwareLibrary");

class ReleaseError extends Error {
  constructor(message, status, code) {
    super(message);
    this.status = status || 400;
    this.code = code || "invalid";
  }
}

function createAgentReleases({ dir, installerDir, stateFileName, scanner, store, installer, logger }) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(installerDir, { recursive: true });
  const saved = readJson(stateFileName);
  const releases = new Map(saved && Array.isArray(saved.releases) ? saved.releases.map((r) => [r.id, r]) : []);

  function persist() {
    writeJson(stateFileName, { releases: [...releases.values()] });
  }

  function view(r) {
    return {
      id: r.id,
      version: r.version,
      fileName: r.fileName,
      size: r.size,
      sha256: r.sha256,
      signature: r.signature,
      uploadedBy: r.uploadedBy,
      uploadedUtc: r.uploadedUtc,
      published: r.published
    };
  }

  async function addFromUpload(upload, user) {
    if (detectType(upload.file) !== "exe") {
      fs.rmSync(upload.file, { force: true });
      throw new ReleaseError("An agent release must be a Windows executable installer.", 400, "invalid");
    }
    let pe;
    try {
      pe = inspectPe(upload.file);
    } catch (error) {
      fs.rmSync(upload.file, { force: true });
      throw new ReleaseError(`The installer could not be read: ${error.message}`, 400, "invalid");
    }
    const version = numericVersion(pe.fileVersion) || numericVersion(pe.productVersion);
    if (!version) {
      fs.rmSync(upload.file, { force: true });
      throw new ReleaseError("The installer does not report a version. Build it with scripts/build-agent.sh.", 400, "invalid");
    }
    const sha256 = await hashFile(upload.file);
    if ([...releases.values()].some((r) => r.sha256 === sha256)) {
      fs.rmSync(upload.file, { force: true });
      throw new ReleaseError("This build is already in the release repository.", 409, "duplicate");
    }
    const signature = await scanner.verifySignature(upload.file, pe.hasSignature);
    const id = crypto.randomUUID();
    const stored = path.join(dir, `${id}.exe`);
    fs.renameSync(upload.file, stored);
    fs.chmodSync(stored, 0o600);
    const release = {
      id,
      version,
      fileName: upload.fileName,
      size: upload.size,
      sha256,
      signed: signature.status === "Valid",
      signature,
      path: stored,
      uploadedBy: user.name,
      uploadedUtc: new Date().toISOString(),
      published: false
    };
    releases.set(id, release);
    persist();
    store.addAudit({ user: user.name, action: "AgentReleaseUploaded", result: "Success", details: `Uploaded agent build ${version} (${signature.status}, SHA-256 ${sha256.slice(0, 16)}…).` });
    logger(`${user.name} uploaded agent release ${version} (${sha256}).`);
    return view(release);
  }

  function publish(id, user) {
    const release = releases.get(id);
    if (!release) {
      throw new ReleaseError("The release was not found.", 404, "not_found");
    }
    if (release.signature.status === "Invalid") {
      throw new ReleaseError("A build with an invalid digital signature cannot be published.", 409, "invalid_signature");
    }
    const target = path.join(installerDir, "uAgent-Setup.exe");
    const tmp = `${target}.publishing`;
    fs.copyFileSync(release.path, tmp);
    fs.renameSync(tmp, target);
    writeJson(path.join(installerDir, "manifest.json"), {
      version: release.version,
      sha256: release.sha256,
      size: release.size,
      signed: release.signed,
      builtUtc: release.uploadedUtc
    });
    for (const r of releases.values()) {
      r.published = r.id === id;
    }
    persist();
    store.addAudit({ user: user.name, action: "AgentReleasePublished", result: "Success", details: `Published agent build ${release.version} to the Download page and self-update.` });
    logger(`${user.name} published agent release ${release.version}.`);
    return view(release);
  }

  function remove(id, user) {
    const release = releases.get(id);
    if (!release) {
      throw new ReleaseError("The release was not found.", 404, "not_found");
    }
    if (release.published) {
      throw new ReleaseError("The published release cannot be deleted. Publish another build first.", 409, "published");
    }
    fs.rmSync(release.path, { force: true });
    releases.delete(id);
    persist();
    store.addAudit({ user: user.name, action: "AgentReleaseDeleted", result: "Success", details: `Deleted agent build ${release.version}.` });
  }

  function describe() {
    const manifest = installer.manifest();
    const published = [...releases.values()].find((r) => r.published);
    return {
      current: manifest
        ? { version: manifest.version, sha256: manifest.sha256, size: manifest.size, signed: manifest.signed, source: published ? "repository" : "build" }
        : null,
      releases: [...releases.values()].map(view).sort((a, b) => b.uploadedUtc.localeCompare(a.uploadedUtc))
    };
  }

  return { ReleaseError, addFromUpload, publish, remove, describe };
}

module.exports = { createAgentReleases };
