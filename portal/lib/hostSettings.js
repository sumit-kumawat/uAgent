"use strict";

// The host agents call after they are downloaded. An administrator can set it on the Settings page.
// Until then, each download uses the host name or IP the browser used to reach the portal.
const fs = require("fs");
const path = require("path");
const net = require("net");
const { execFileSync } = require("child_process");

function createHostSettings(config) {
  const stateFile = pickStateFile();
  let saved = readState(stateFile);
  let certificateReissued = false;

  function configuredHost() {
    return saved.host || "";
  }

  function detectedHost(req) {
    const host = String((req && req.hostname) || "").trim().toLowerCase().replace(/\.$/, "");
    if (!host || host === "localhost" || host.endsWith(".localhost")) {
      return "";
    }
    return isValidHost(host) ? host : "";
  }

  function effectiveHost(req) {
    return configuredHost() || detectedHost(req) || config.publicHost;
  }

  function originFor(host, protocol) {
    const port = protocol === "https" ? config.publicHttpsPort : config.publicHttpPort;
    const standard = (protocol === "http" && port === 80) || (protocol === "https" && port === 443);
    return `${protocol}://${host}${standard ? "" : `:${port}`}`;
  }

  function managerUrl(req) {
    const protocol = config.httpsEnabled ? "https" : "http";
    return originFor(effectiveHost(req), protocol);
  }

  function describe(req) {
    const configured = configuredHost();
    const detected = detectedHost(req);
    const host = configured || detected || config.publicHost;
    let source = "default";
    if (configured) {
      source = "configured";
    } else if (detected) {
      source = "detected";
    }
    return {
      host,
      configured,
      detected,
      source,
      managerUrl: originFor(host, config.httpsEnabled ? "https" : "http"),
      updatedUtc: saved.updatedUtc || "",
      updatedBy: saved.updatedBy || "",
      certificateReissued
    };
  }

  function setHost(input, user) {
    const host = normalize(input);
    saved = {
      host,
      updatedUtc: new Date().toISOString(),
      updatedBy: user || ""
    };
    writeState(stateFile, saved);
    return saved;
  }

  function clearHost(user) {
    saved = {
      host: "",
      updatedUtc: new Date().toISOString(),
      updatedBy: user || ""
    };
    writeState(stateFile, saved);
    return saved;
  }

  function reissueCertificate(host) {
    const names = [`DNS:localhost`, `IP:127.0.0.1`];
    if (net.isIP(host) === 4) {
      names.push(`IP:${host}`);
    } else {
      names.push(`DNS:${host}`);
    }
    if (config.publicIp && net.isIP(config.publicIp) === 4 && !names.includes(`IP:${config.publicIp}`)) {
      names.push(`IP:${config.publicIp}`);
    }
    if (config.publicHost && net.isIP(config.publicHost) === 0 && !names.includes(`DNS:${config.publicHost}`)) {
      names.push(`DNS:${config.publicHost}`);
    }
    const cn = net.isIP(host) === 4 ? host : host;
    fs.mkdirSync(path.dirname(config.certFile), { recursive: true });
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes",
      "-keyout", config.keyFile,
      "-out", config.certFile,
      "-days", "825",
      "-subj", `/CN=${cn}`,
      "-addext", `subjectAltName=${names.join(",")}`
    ], { stdio: "pipe" });
    fs.chmodSync(config.keyFile, 0o600);
    certificateReissued = true;
  }

  function covers(host) {
    if (!host || !fs.existsSync(config.certFile)) {
      return false;
    }
    try {
      const { X509Certificate } = require("crypto");
      const certificate = new X509Certificate(fs.readFileSync(config.certFile));
      if (net.isIP(host) === 4) {
        return certificate.checkIP(host);
      }
      return Boolean(certificate.checkHost(host));
    } catch (error) {
      return false;
    }
  }

  return { configuredHost, detectedHost, effectiveHost, managerUrl, describe, setHost, clearHost, reissueCertificate, covers, stateFile };

  function normalize(input) {
    let raw = String(input || "").trim();
    if (!raw) {
      throw new Error("Enter the DNS name or IP address agents should contact.");
    }
    raw = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    raw = raw.split(/[/?#]/)[0];
    if (raw.startsWith("[") && raw.includes("]")) {
      raw = raw.slice(1, raw.indexOf("]"));
    } else if (net.isIP(raw) === 0) {
      raw = raw.replace(/:\d+$/, "");
    }
    const host = raw.toLowerCase().replace(/\.$/, "");
    if (!isValidHost(host) || host === "localhost" || host.endsWith(".localhost")) {
      throw new Error("Enter a DNS name or an IPv4 address that agents can reach.");
    }
    return host;
  }
}

function isValidHost(host) {
  if (net.isIP(host) === 4) {
    return true;
  }
  if (!host || host.length > 253) {
    return false;
  }
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(host) ||
    /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(host);
}

function pickStateFile() {
  if (process.env.PORTAL_STATE_FILE) {
    return process.env.PORTAL_STATE_FILE;
  }
  const preferred = path.join(process.env.PORTAL_STATE_DIR || "/var/lib/uagent", "portal-host.json");
  if (canWrite(path.dirname(preferred))) {
    return preferred;
  }
  return path.join(__dirname, "..", "data", "portal-host.json");
}

function canWrite(directory) {
  try {
    fs.mkdirSync(directory, { recursive: true });
    fs.accessSync(directory, fs.constants.W_OK);
    return true;
  } catch (error) {
    return false;
  }
}

function readState(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    const host = typeof parsed.host === "string" ? parsed.host.trim().toLowerCase() : "";
    return {
      host: host && isValidHost(host) ? host : "",
      updatedUtc: parsed.updatedUtc || "",
      updatedBy: parsed.updatedBy || ""
    };
  } catch (error) {
    return { host: "", updatedUtc: "", updatedBy: "" };
  }
}

function writeState(file, state) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file);
  fs.chmodSync(file, 0o600);
}

module.exports = { createHostSettings };
