"use strict";

// Changing the host agents contact touches three things that must stay consistent: the saved setting,
// the TLS certificate (its SAN must contain the host or agents refuse the connection), and agents that
// are already installed (they learn the new address from their next heartbeat). The Settings form and
// the setup wizard both go through here.
const dns = require("dns").promises;
const net = require("net");

function createHostChange({ hostSettings, tlsManager, store, logger, config }) {
  async function resolve(host) {
    if (net.isIP(host) !== 0) {
      return { addresses: [host], error: "" };
    }
    try {
      const records = await dns.lookup(host, { all: true, verbatim: true });
      return { addresses: records.map((r) => r.address), error: "" };
    } catch (error) {
      return { addresses: [], error: error.code === "ENOTFOUND" ? `${host} does not resolve in DNS from this server.` : `DNS lookup failed: ${error.code || error.message}` };
    }
  }

  // Validation result shown in the wizard before anything is saved.
  async function preview(input) {
    const host = hostSettings.normalize(input);
    const lookup = await resolve(host);
    const own = hostSettings.addresses();
    const warnings = [];
    if (lookup.error) {
      warnings.push(`${lookup.error} Create an A record pointing to ${own[0] || "this server"} before installing agents, or agents will fail to register.`);
    } else if (own.length && !lookup.addresses.some((address) => own.includes(address))) {
      warnings.push(`${host} resolves to ${lookup.addresses.join(", ")}, not to this server (${own.join(", ")}). Agents will contact that address.`);
    }
    const cert = tlsManager.describe();
    const covered = cert ? tlsManager.covers(host) : false;
    let certificate = "none";
    if (cert && covered) {
      certificate = "covered";
    } else if (cert && cert.managed) {
      certificate = "reissue";
    } else if (cert) {
      certificate = "missing";
      warnings.push(`The installed ${cert.mode} certificate does not include ${host}. Install a certificate whose SAN contains ${host} before saving, or agents will refuse the connection.`);
    }
    return {
      host,
      managerUrl: hostSettings.originFor(host, config.httpsEnabled ? "https" : "http"),
      resolvesTo: lookup.addresses,
      serverAddresses: own,
      certificate,
      certificateMode: cert ? cert.mode : "",
      isIp: net.isIP(host) !== 0,
      warnings,
      blocking: certificate === "missing"
    };
  }

  async function apply(input, user, remoteIp) {
    const check = await preview(input);
    if (check.blocking) {
      const error = new Error(check.warnings[check.warnings.length - 1]);
      error.preview = check;
      throw error;
    }
    const before = hostSettings.managerUrl();
    let certificate = { issued: false, reason: "" };
    if (check.certificate === "reissue") {
      try {
        certificate = tlsManager.issue(check.host, hostSettings.addresses());
      } catch (cause) {
        logger(`Could not reissue the TLS certificate for ${check.host}: ${cause.message}`);
        const error = new Error(`The certificate could not be reissued for ${check.host}, so the host was not changed. See the portal log for details.`);
        error.preview = check;
        error.status = 500;
        throw error;
      }
    }
    hostSettings.setHost(check.host, user);
    const managerUrl = hostSettings.managerUrl();
    store.addAudit({
      user,
      action: "SetAgentHost",
      result: "Success",
      details: `Agents contact ${managerUrl} (was ${before}).${certificate.issued ? ` Certificate reissued for ${check.host}.` : ""}`,
      remoteIp
    });
    logger(`Agent host set to ${check.host} by ${user}. New downloads and existing agents now use ${managerUrl}.`);
    return { preview: check, certificate, managerUrl };
  }

  function clear(user, remoteIp) {
    hostSettings.clearHost(user);
    const managerUrl = hostSettings.managerUrl();
    store.addAudit({ user, action: "SetAgentHost", result: "Success", details: `Cleared the DNS name. Agents contact ${managerUrl}.`, remoteIp });
    logger(`Agent host cleared by ${user}. Downloads use this server: ${managerUrl}.`);
    return { managerUrl };
  }

  return { preview, apply, clear };
}

module.exports = { createHostChange };
