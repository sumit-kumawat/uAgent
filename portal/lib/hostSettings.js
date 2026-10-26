"use strict";

// The host agents call after they are downloaded. The first run uses this machine's IP address.
// An administrator then saves a DNS name or FQDN on the Settings page, and later downloads use that name.
const fs = require("fs");
const os = require("os");
const net = require("net");
const { stateFile: statePath, writeJson } = require("./statePath");

function systemIp() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const entry of ifaces[name] || []) {
      const family = entry.family === 4 || entry.family === "IPv4";
      if (family && !entry.internal) {
        return entry.address;
      }
    }
  }
  return "";
}

function createHostSettings(config) {
  const stateFile = statePath("portal-host.json");
  let saved = readState(stateFile);

  function configuredHost() {
    return saved.host || "";
  }

  function needsDns() {
    const saved = configuredHost();
    return !saved || net.isIP(saved) !== 0;
  }

  function effectiveHost() {
    const saved = configuredHost();
    if (saved) {
      return saved;
    }
    return systemIp() || config.publicHost;
  }

  function originFor(host, protocol) {
    const port = protocol === "https" ? config.publicHttpsPort : config.publicHttpPort;
    const standard = (protocol === "http" && port === 80) || (protocol === "https" && port === 443);
    return `${protocol}://${host}${standard ? "" : `:${port}`}`;
  }

  function managerUrl() {
    const protocol = config.httpsEnabled ? "https" : "http";
    return originFor(effectiveHost(), protocol);
  }

  function describe() {
    const configured = configuredHost();
    const host = effectiveHost();
    let source = "default";
    if (configured && net.isIP(configured) === 0) {
      source = "configured";
    } else if (host && net.isIP(host) === 4) {
      source = "system";
    }
    return {
      host,
      configured,
      systemIp: systemIp(),
      source,
      needsDns: needsDns(),
      managerUrl: originFor(host, config.httpsEnabled ? "https" : "http"),
      updatedUtc: saved.updatedUtc || "",
      updatedBy: saved.updatedBy || ""
    };
  }

  function setHost(input, user) {
    const host = normalize(input);
    saved = {
      host,
      updatedUtc: new Date().toISOString(),
      updatedBy: user || ""
    };
    writeJson(stateFile, saved);
    return saved;
  }

  function clearHost(user) {
    saved = {
      host: "",
      updatedUtc: new Date().toISOString(),
      updatedBy: user || ""
    };
    writeJson(stateFile, saved);
    return saved;
  }

  function addresses() {
    return [systemIp(), config.publicIp].filter((ip, index, all) => ip && net.isIP(ip) === 4 && all.indexOf(ip) === index);
  }

  return { configuredHost, effectiveHost, managerUrl, originFor, describe, needsDns, setHost, clearHost, addresses, normalize, stateFile, systemIp };

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

module.exports = { createHostSettings, systemIp };
