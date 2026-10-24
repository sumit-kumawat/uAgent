"use strict";

// Serves the downloadable Windows installer and the self-update package.
//
// - The human installer is personalised: the base uAgent.exe with a small config block appended
//   (manager URL, enrollment key, certificate pin) so installation needs no manual entry. The block
//   format matches EmbeddedConfig.cs in the agent.
// - The self-update package is the untouched base uAgent.exe, so its Authenticode signature (when the
//   build is signed) stays valid. The agent validates that signature and the SHA-256 before installing.
//
// scripts/build-agent.sh writes uAgent-Setup.exe and manifest.json into the installer directory.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const BEGIN_MARKER = "#UAGENT-CONFIG-V1:";
const END_MARKER = ":UAGENT-CONFIG-END#";
const INSTALLER_NAME = "uAgent-Setup.exe";
const MANIFEST_NAME = "manifest.json";

class InstallerPackage {
  constructor(dir) {
    this.dir = dir;
    this.installerPath = path.join(dir, INSTALLER_NAME);
    this.manifestPath = path.join(dir, MANIFEST_NAME);
  }

  // On-disk build name. The file a person downloads is named from the published version.
  get storedName() {
    return INSTALLER_NAME;
  }

  // Public download name, e.g. uAgent_Version1.2.0.exe. The version comes from manifest.json.
  get fileName() {
    return `uAgent_Version${this.versionLabel()}.exe`;
  }

  versionLabel() {
    try {
      if (fs.existsSync(this.manifestPath)) {
        const parsed = JSON.parse(fs.readFileSync(this.manifestPath, "utf8"));
        const version = String(parsed.version || "").trim();
        if (/^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$/.test(version)) {
          return version;
        }
      }
    } catch {
      // A missing or unreadable manifest still produces a safe filename.
    }
    return "0.0.0";
  }

  // The installer is "available" only when the file exists and is a real Windows PE image
  // (starts with the "MZ" signature) of plausible size, so a truncated or corrupt build is
  // never advertised as downloadable.
  isAvailable() {
    try {
      const stat = fs.statSync(this.installerPath);
      if (!stat.isFile() || stat.size < 65536) {
        return false;
      }
      const fd = fs.openSync(this.installerPath, "r");
      try {
        const head = Buffer.alloc(2);
        fs.readSync(fd, head, 0, 2, 0);
        return head[0] === 0x4d && head[1] === 0x5a; // "MZ"
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      return false;
    }
  }

  // { version, sha256, size, signed, builtUtc } describing the base build, or null when not built yet.
  manifest() {
    try {
      const base = fs.existsSync(this.manifestPath)
        ? JSON.parse(fs.readFileSync(this.manifestPath, "utf8"))
        : {};
      if (!this.isAvailable()) {
        return null;
      }
      const stat = fs.statSync(this.installerPath);
      const sha256 = base.sha256 || this._hashFile(this.installerPath);
      return {
        version: base.version || "0.0.0",
        sha256,
        size: stat.size,
        signed: Boolean(base.signed),
        builtUtc: base.builtUtc || stat.mtime.toISOString()
      };
    } catch {
      return null;
    }
  }

  // Raw base installer for the self-update path (signature intact). Returns a readable stream or null.
  baseStream() {
    return this.isAvailable() ? fs.createReadStream(this.installerPath) : null;
  }

  // Base installer plus the appended connection block, as a Buffer, for the human download.
  personalized(configBlock) {
    if (!this.isAvailable()) {
      return null;
    }
    const base = fs.readFileSync(this.installerPath);
    const json = Buffer.from(JSON.stringify(configBlock), "utf8");
    const block = Buffer.concat([
      Buffer.from(BEGIN_MARKER, "ascii"),
      Buffer.from(json.toString("base64"), "ascii"),
      Buffer.from(END_MARKER, "ascii")
    ]);
    return Buffer.concat([base, block]);
  }

  _hashFile(file) {
    return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  }
}

module.exports = InstallerPackage;
