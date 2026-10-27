"use strict";

// Central software library. Each package is stored once under the state directory, identified by its
// SHA-256, inspected for metadata and signatures, optionally malware-scanned, and must be approved by an
// administrator before it can be deployed. Changing how a package installs requires approval again.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { writeJson, readJson } = require("./statePath");
const { detectType, inspectPe, inspectMsi } = require("./binaryInspect");

const DETECTION_TYPES = new Set(["none", "msiProductCode", "registry", "file"]);
const ARCHITECTURES = new Set(["any", "x64", "x86"]);
const RESTART = new Set(["never", "ifRequired"]);
const GUID = /^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$/;

class LibraryError extends Error {
  constructor(message, status, code, field) {
    super(message);
    this.status = status || 400;
    this.code = code || "invalid";
    this.field = field;
  }
}

function hashFile(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    fs.createReadStream(file)
      .on("data", (chunk) => hash.update(chunk))
      .on("error", reject)
      .on("end", () => resolve(hash.digest("hex")));
  });
}

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? Math.min(Math.max(n, min), max) : fallback;
}

function exitCodes(value, fallback) {
  const list = Array.isArray(value) ? value : String(value == null ? "" : value).split(/[\s,;]+/);
  const codes = [...new Set(list.map((v) => Number.parseInt(v, 10)).filter((n) => Number.isInteger(n) && n >= -2147483648 && n <= 4294967295))];
  return codes.length ? codes.slice(0, 32) : fallback;
}

function str(value, max) {
  return String(value == null ? "" : value).trim().slice(0, max);
}

function numericVersion(value) {
  const match = /\d+(\.\d+){1,3}/.exec(String(value || ""));
  return match ? match[0] : "";
}

function defaultInstall(type, metadata, signature) {
  const signed = signature.status === "Valid" || signature.status === "Present";
  const base = {
    arguments: "",
    allowEmptyArguments: false,
    timeoutMinutes: 60,
    successExitCodes: [0],
    rebootExitCodes: [3010, 1641],
    retryExitCodes: [1618],
    requireSignature: signed,
    expectedSigner: signed ? signature.subject || "" : "",
    scanWithDefender: true,
    prerequisites: {
      minOsBuild: 0,
      architecture: metadata.architecture === "x64" ? "x64" : "any",
      minFreeDiskMb: 1024,
      blockOnPendingReboot: false
    },
    restartBehavior: "never",
    restartDelayMinutes: 15
  };
  if (type === "msi") {
    base.detection = metadata.productCode
      ? { type: "msiProductCode", productCode: metadata.productCode, displayName: "", minVersion: "", path: "" }
      : { type: "registry", productCode: "", displayName: metadata.productName || "", minVersion: numericVersion(metadata.productVersion), path: "" };
  } else {
    base.detection = metadata.productName
      ? { type: "registry", productCode: "", displayName: metadata.productName, minVersion: numericVersion(metadata.productVersion), path: "" }
      : { type: "none", productCode: "", displayName: "", minVersion: "", path: "" };
  }
  return base;
}

function normalizeInstall(input, current) {
  const src = input || {};
  const detection = src.detection || current.detection || {};
  const prereq = src.prerequisites || current.prerequisites || {};
  const out = {
    arguments: str(src.arguments !== undefined ? src.arguments : current.arguments, 4000),
    allowEmptyArguments: Boolean(src.allowEmptyArguments !== undefined ? src.allowEmptyArguments : current.allowEmptyArguments),
    timeoutMinutes: clampInt(src.timeoutMinutes !== undefined ? src.timeoutMinutes : current.timeoutMinutes, 1, 720, 60),
    successExitCodes: exitCodes(src.successExitCodes !== undefined ? src.successExitCodes : current.successExitCodes, [0]),
    rebootExitCodes: exitCodes(src.rebootExitCodes !== undefined ? src.rebootExitCodes : current.rebootExitCodes, []),
    retryExitCodes: exitCodes(src.retryExitCodes !== undefined ? src.retryExitCodes : current.retryExitCodes, []),
    requireSignature: Boolean(src.requireSignature !== undefined ? src.requireSignature : current.requireSignature),
    expectedSigner: str(src.expectedSigner !== undefined ? src.expectedSigner : current.expectedSigner, 200),
    scanWithDefender: Boolean(src.scanWithDefender !== undefined ? src.scanWithDefender : current.scanWithDefender),
    detection: {
      type: DETECTION_TYPES.has(detection.type) ? detection.type : "none",
      productCode: str(detection.productCode, 40),
      displayName: str(detection.displayName, 200),
      minVersion: str(detection.minVersion, 40),
      path: str(detection.path, 400)
    },
    prerequisites: {
      minOsBuild: clampInt(prereq.minOsBuild, 0, 99999, 0),
      architecture: ARCHITECTURES.has(prereq.architecture) ? prereq.architecture : "any",
      minFreeDiskMb: clampInt(prereq.minFreeDiskMb, 0, 1000000, 0),
      blockOnPendingReboot: Boolean(prereq.blockOnPendingReboot)
    },
    restartBehavior: RESTART.has(src.restartBehavior !== undefined ? src.restartBehavior : current.restartBehavior) ? (src.restartBehavior !== undefined ? src.restartBehavior : current.restartBehavior) : "never",
    restartDelayMinutes: clampInt(src.restartDelayMinutes !== undefined ? src.restartDelayMinutes : current.restartDelayMinutes, 1, 1440, 15)
  };
  const d = out.detection;
  if (d.type === "msiProductCode" && !GUID.test(d.productCode)) {
    throw new LibraryError("Enter the MSI product code as a GUID in braces, for example {12345678-1234-1234-1234-123456789ABC}.", 400, "invalid", "detection.productCode");
  }
  if (d.type === "registry" && !d.displayName) {
    throw new LibraryError("Enter the display name shown in Programs and Features for registry detection.", 400, "invalid", "detection.displayName");
  }
  if (d.type === "file" && !/^([A-Za-z]:\\|%[A-Za-z_]+%\\)/.test(d.path)) {
    throw new LibraryError("Enter an absolute file path, for example %ProgramFiles%\\Vendor\\app.exe.", 400, "invalid", "detection.path");
  }
  if (d.minVersion && !/^\d+(\.\d+){0,3}$/.test(d.minVersion)) {
    throw new LibraryError("The minimum version must look like 1.2.3.4.", 400, "invalid", "detection.minVersion");
  }
  return out;
}

function createSoftwareLibrary({ dir, stateFileName, scanner, vault, store, logger, limits }) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const saved = readJson(stateFileName);
  const packages = new Map(saved && Array.isArray(saved.packages) ? saved.packages.map((p) => [p.id, p]) : []);
  let usage = () => ({ deploymentCount: 0, activeDeployments: 0, lastDeployedUtc: null });

  function persist() {
    writeJson(stateFileName, { packages: [...packages.values()] });
  }

  function usedBytes() {
    let total = 0;
    for (const p of packages.values()) {
      if (p.stored) {
        total += p.size;
      }
    }
    return total;
  }

  function view(p) {
    const stats = usage(p.id);
    return {
      id: p.id,
      name: p.name,
      version: p.version,
      publisher: p.publisher,
      fileName: p.fileName,
      installerType: p.installerType,
      size: p.size,
      sha256: p.sha256,
      uploadedUtc: p.uploadedUtc,
      uploadedBy: p.uploadedBy,
      status: p.status,
      statusReason: p.statusReason || "",
      approvedBy: p.approvedBy || "",
      approvedUtc: p.approvedUtc || null,
      notes: p.notes || "",
      signature: p.signature,
      scan: p.scan,
      metadata: p.metadata,
      install: p.install,
      secretsUsed: vault.references(p.install.arguments),
      deploymentCount: stats.deploymentCount,
      activeDeployments: stats.activeDeployments,
      lastDeployedUtc: stats.lastDeployedUtc
    };
  }

  async function addFromUpload(upload, fields, user) {
    const type = detectType(upload.file);
    const extension = path.extname(upload.fileName).toLowerCase();
    if (!type || (type === "msi" && extension !== ".msi") || (type === "exe" && extension !== ".exe")) {
      fs.rmSync(upload.file, { force: true });
      throw new LibraryError("The file is not a valid Windows Installer (.msi) or Windows executable (.exe) package.", 400, "invalid_package");
    }
    let inspected;
    try {
      inspected = type === "msi" ? inspectMsi(upload.file) : inspectPe(upload.file);
    } catch (error) {
      fs.rmSync(upload.file, { force: true });
      throw new LibraryError(`The package could not be read: ${error.message}`, 400, "invalid_package");
    }
    const sha256 = await hashFile(upload.file);
    const duplicate = [...packages.values()].find((p) => p.sha256 === sha256 && p.stored);
    if (duplicate) {
      fs.rmSync(upload.file, { force: true });
      throw new LibraryError(`This file is already in the library as ${duplicate.name} ${duplicate.version}.`, 409, "duplicate");
    }
    const [signature, scan] = await Promise.all([scanner.verifySignature(upload.file, inspected.hasSignature), scanner.scan(upload.file)]);

    const metadata = {
      productName: inspected.productName || "",
      productVersion: inspected.productVersion || "",
      manufacturer: inspected.manufacturer || inspected.companyName || "",
      productCode: inspected.productCode || "",
      upgradeCode: inspected.upgradeCode || "",
      fileDescription: inspected.fileDescription || "",
      companyName: inspected.companyName || "",
      fileVersion: inspected.fileVersion || "",
      architecture: inspected.architecture || "unknown"
    };
    const id = crypto.randomUUID();
    const packageDir = path.join(dir, id);
    fs.mkdirSync(packageDir, { recursive: true, mode: 0o700 });
    const storedPath = path.join(packageDir, upload.fileName);
    fs.renameSync(upload.file, storedPath);
    fs.chmodSync(storedPath, 0o600);

    let status = "PendingReview";
    let statusReason = "";
    let stored = true;
    if (scan.status === "Infected") {
      fs.rmSync(packageDir, { recursive: true, force: true });
      stored = false;
      status = "Quarantined";
      statusReason = `${scan.detail} The file was deleted.`;
    } else if (scanner.describe().mode === "required" && scan.status !== "Clean") {
      status = "Quarantined";
      statusReason = "Malware scanning is required on this server and the package was not confirmed clean.";
    } else if (signature.status === "Invalid") {
      statusReason = signature.detail;
    }

    const pkg = {
      id,
      name: str(fields.name, 200) || metadata.productName || path.basename(upload.fileName, extension),
      version: str(fields.version, 60) || numericVersion(metadata.productVersion) || metadata.productVersion.slice(0, 60),
      publisher: str(fields.publisher, 200) || metadata.manufacturer || signature.subject || "",
      fileName: upload.fileName,
      installerType: type,
      size: upload.size,
      sha256,
      uploadedUtc: new Date().toISOString(),
      uploadedBy: user.name,
      status,
      statusReason,
      notes: "",
      signature,
      scan,
      metadata,
      install: defaultInstall(type, metadata, signature),
      stored,
      path: stored ? storedPath : ""
    };
    packages.set(id, pkg);
    persist();
    store.addAudit({
      user: user.name,
      action: "PackageUploaded",
      result: status === "Quarantined" ? "Failed" : "Success",
      details: `${pkg.name} ${pkg.version} (${type.toUpperCase()}, ${(pkg.size / 1048576).toFixed(1)} MB, SHA-256 ${sha256.slice(0, 16)}…). Signature: ${signature.status}. Scan: ${scan.status}.${statusReason ? ` ${statusReason}` : ""}`
    });
    logger(`${user.name} uploaded package ${pkg.name} ${pkg.version} (${sha256}).`);
    return view(pkg);
  }

  function find(id) {
    const pkg = packages.get(id);
    if (!pkg) {
      throw new LibraryError("The package was not found.", 404, "not_found");
    }
    return pkg;
  }

  function update(id, fields, user) {
    const pkg = find(id);
    if (pkg.status === "Quarantined" && !pkg.stored) {
      throw new LibraryError("A quarantined package cannot be changed.", 409, "quarantined");
    }
    const changes = [];
    for (const key of ["name", "version", "publisher"]) {
      if (fields[key] !== undefined) {
        const value = str(fields[key], key === "version" ? 60 : 200);
        if (!value) {
          throw new LibraryError(`The ${key} cannot be empty.`, 400, "invalid", key);
        }
        if (value !== pkg[key]) {
          pkg[key] = value;
          changes.push(key);
        }
      }
    }
    if (fields.notes !== undefined) {
      pkg.notes = str(fields.notes, 2000);
    }
    if (fields.install !== undefined) {
      const next = normalizeInstall(fields.install, pkg.install);
      const missing = vault.missing(next.arguments);
      if (missing.length) {
        throw new LibraryError(`These vault secrets do not exist: ${missing.join(", ")}.`, 400, "invalid", "install.arguments");
      }
      if (JSON.stringify(next) !== JSON.stringify(pkg.install)) {
        pkg.install = next;
        changes.push("installation settings");
        if (pkg.status === "Approved") {
          pkg.status = "PendingReview";
          pkg.statusReason = "The installation settings changed and must be approved again.";
        }
      }
    }
    persist();
    if (changes.length) {
      store.addAudit({ user: user.name, action: "PackageUpdated", result: "Success", details: `${pkg.name} ${pkg.version}: changed ${changes.join(", ")}.` });
    }
    return view(pkg);
  }

  function approve(id, { acknowledgeUnscanned, acknowledgeUnsigned }, user) {
    const pkg = find(id);
    if (pkg.status === "Quarantined") {
      throw new LibraryError(pkg.statusReason || "A quarantined package cannot be approved.", 409, "quarantined");
    }
    if (pkg.signature.status === "Invalid") {
      throw new LibraryError("A package with an invalid digital signature cannot be approved.", 409, "invalid_signature");
    }
    if (pkg.scan.status !== "Clean" && !acknowledgeUnscanned) {
      throw new LibraryError("The package was not confirmed clean by a malware scanner. Confirm that you have verified its source before approving.", 400, "acknowledge_unscanned", "acknowledgeUnscanned");
    }
    if (pkg.signature.status === "Unsigned") {
      if (!acknowledgeUnsigned) {
        throw new LibraryError("The package is not digitally signed. Confirm that you trust its source before approving.", 400, "acknowledge_unsigned", "acknowledgeUnsigned");
      }
      if (pkg.install.requireSignature) {
        throw new LibraryError("Turn off 'Require a valid signature' for an unsigned package, or upload a signed build.", 400, "invalid", "install.requireSignature");
      }
    }
    if (pkg.installerType === "exe" && !pkg.install.arguments && !pkg.install.allowEmptyArguments) {
      throw new LibraryError("Enter the vendor's silent-install arguments for this EXE. EXE installers do not share common switches.", 400, "invalid", "install.arguments");
    }
    const missing = vault.missing(pkg.install.arguments);
    if (missing.length) {
      throw new LibraryError(`These vault secrets do not exist: ${missing.join(", ")}.`, 400, "invalid", "install.arguments");
    }
    pkg.status = "Approved";
    pkg.statusReason = "";
    pkg.approvedBy = user.name;
    pkg.approvedUtc = new Date().toISOString();
    persist();
    const acknowledgements = [
      pkg.scan.status !== "Clean" ? `scan status ${pkg.scan.status} acknowledged` : "",
      pkg.signature.status === "Unsigned" ? "unsigned package acknowledged" : ""
    ].filter(Boolean);
    store.addAudit({ user: user.name, action: "PackageApproved", result: "Success", details: `Approved ${pkg.name} ${pkg.version} (SHA-256 ${pkg.sha256.slice(0, 16)}…)${acknowledgements.length ? `; ${acknowledgements.join("; ")}` : ""}.` });
    return view(pkg);
  }

  function reject(id, reason, user) {
    const pkg = find(id);
    pkg.status = "Rejected";
    pkg.statusReason = str(reason, 500) || "Rejected by an administrator.";
    persist();
    store.addAudit({ user: user.name, action: "PackageRejected", result: "Success", details: `Rejected ${pkg.name} ${pkg.version}: ${pkg.statusReason}` });
    return view(pkg);
  }

  function remove(id, user) {
    const pkg = find(id);
    if (usage(id).activeDeployments > 0) {
      throw new LibraryError("The package is used by an active deployment. Cancel or finish it first.", 409, "in_use");
    }
    fs.rmSync(path.join(dir, id), { recursive: true, force: true });
    packages.delete(id);
    persist();
    store.addAudit({ user: user.name, action: "PackageDeleted", result: "Success", details: `Deleted ${pkg.name} ${pkg.version} from the software library.` });
  }

  function get(id) {
    const pkg = packages.get(id);
    return pkg ? view(pkg) : null;
  }

  return {
    LibraryError,
    list: () => [...packages.values()].map(view).sort((a, b) => b.uploadedUtc.localeCompare(a.uploadedUtc)),
    get,
    raw: (id) => packages.get(id) || null,
    addFromUpload,
    update,
    approve,
    reject,
    remove,
    usedBytes,
    setUsage: (fn) => { usage = fn; },
    limits
  };
}

module.exports = { createSoftwareLibrary, LibraryError, hashFile, numericVersion };
