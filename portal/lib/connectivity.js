"use strict";

// Answers one question for an administrator: can the agents reach this portal, and would a change stop
// them? Installing a certificate that does not cover the address a fleet is already using is what takes
// agents offline, and because the new address is delivered over that same broken connection, they cannot
// be told to move. So coverage is checked against the addresses agents report, not against the address the
// portal would like them to use.
const dns = require("dns").promises;
const net = require("net");
const tls = require("tls");

// Agents are grouped by the address they last reported, newest first within each group.
function agentAddresses(store) {
  const groups = new Map();
  for (const agent of store.listAgents()) {
    if (agent.status === "Inactive") {
      continue;
    }
    const url = agent.managerUrl || "";
    const key = url || "(not reported)";
    if (!groups.has(key)) {
      groups.set(key, { managerUrl: url, host: hostOf(url), agents: 0, online: 0, examples: [] });
    }
    const group = groups.get(key);
    group.agents += 1;
    group.online += agent.online ? 1 : 0;
    if (group.examples.length < 5) {
      group.examples.push({ displayId: agent.displayId, machineName: agent.machineName, online: Boolean(agent.online) });
    }
  }
  return [...groups.values()].sort((a, b) => b.agents - a.agents);
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (error) {
    return "";
  }
}

/**
 * Checks a certificate against every address in use.
 *
 * @param {object} tlsManager  the portal's TLS manager.
 * @param {object} store       the agent store.
 * @param {string} host        the address the portal tells agents to use.
 */
function coverage(tlsManager, store, host) {
  const certificate = tlsManager.describe();
  const groups = agentAddresses(store);
  const covered = [];
  const stranded = [];
  const unknown = [];
  for (const group of groups) {
    if (!group.host) {
      unknown.push(group);
    } else if (tlsManager.covers(group.host)) {
      covered.push(group);
    } else {
      stranded.push(group);
    }
  }
  const strandedAgents = stranded.reduce((total, group) => total + group.agents, 0);
  return {
    certificate,
    host,
    hostCovered: host ? tlsManager.covers(host) : false,
    covered,
    stranded,
    unknown,
    strandedAgents,
    // Agents on an older build do not report their address; they are assumed to use the advertised one.
    unknownAgents: unknown.reduce((total, group) => total + group.agents, 0)
  };
}

// Resolves the host and opens a TLS connection to the portal's own listener, so the report reflects what
// an agent would actually get rather than what the files on disk say.
async function probe(host, port, options) {
  const result = { host, port, dns: { ok: false, detail: "" }, tcp: { ok: false, detail: "" }, tls: { ok: false, detail: "" } };
  if (!host) {
    result.dns.detail = "No host name is configured.";
    return result;
  }
  if (net.isIP(host) !== 0) {
    result.dns = { ok: true, detail: `${host} is an IP address; no lookup needed.`, addresses: [host] };
  } else {
    try {
      const records = await dns.lookup(host, { all: true, verbatim: true });
      const addresses = records.map((record) => record.address);
      result.dns = { ok: addresses.length > 0, detail: addresses.join(", "), addresses };
      const own = (options && options.serverAddresses) || [];
      if (own.length && !addresses.some((address) => own.includes(address))) {
        result.dns.detail += ` (this server is ${own.join(", ")})`;
        result.dns.warning = `${host} does not resolve to this server. Agents will contact whatever is at ${addresses.join(", ")}.`;
      }
    } catch (error) {
      result.dns.detail = error.code === "ENOTFOUND"
        ? `${host} does not resolve in DNS from this server.`
        : `DNS lookup failed: ${error.code || error.message}`;
      return result;
    }
  }

  const target = (result.dns.addresses || [host])[0];
  await new Promise((resolve) => {
    const socket = net.connect({ host: target, port, timeout: 5000 });
    socket.once("connect", () => { result.tcp = { ok: true, detail: `Connected to ${target}:${port}.` }; socket.destroy(); resolve(); });
    socket.once("timeout", () => { result.tcp.detail = `No answer from ${target}:${port} within 5 seconds.`; socket.destroy(); resolve(); });
    socket.once("error", (error) => { result.tcp.detail = `${target}:${port} refused the connection (${error.code || error.message}).`; resolve(); });
  });
  if (!result.tcp.ok) {
    return result;
  }

  await new Promise((resolve) => {
    // The handshake is verified the way an agent verifies it: the chain must lead to a trusted root and
    // the name must match, with an internal root supplied explicitly exactly as it is to agents.
    //
    // The connection is opened without rejecting on failure so the result can be *reported* rather than
    // thrown away as a generic socket error; the verdict below is still Node's own verification, and a
    // failure is reported as a failure. Pinning is accepted only when the portal is serving a self-signed
    // certificate and agents were given that pin, which is how an evaluation install is meant to work.
    const ca = (options && options.caRootPem) ? [options.caRootPem] : undefined;
    const pin = ((options && options.pin) || "").replace(/:/g, "").toUpperCase();
    const socket = tls.connect({ host: target, port, servername: host, ca, timeout: 8000, rejectUnauthorized: false }, () => {
      const peer = socket.getPeerCertificate(true);
      const fingerprint = String(peer.fingerprint256 || "").replace(/:/g, "").toUpperCase();
      const pinned = Boolean(pin) && fingerprint === pin;
      result.tls = {
        ok: socket.authorized || pinned,
        verifiedBy: socket.authorized ? (ca ? "internal root" : "system trust store") : (pinned ? "pinned certificate" : ""),
        detail: socket.authorized
          ? `Verified ${peer.subject && peer.subject.CN ? peer.subject.CN : host} against ${ca ? "the internal root supplied to agents" : "the system trust store"}.`
          : pinned
            ? `The chain is not trusted (${socket.authorizationError}), but the certificate matches the pin embedded in agent downloads. This works for evaluation only; browsers still warn.`
            : `The certificate was refused: ${socket.authorizationError}.`,
        chainLength: countChain(peer)
      };
      socket.destroy();
      resolve();
    });
    socket.once("timeout", () => { result.tls.detail = "The TLS handshake did not finish within 8 seconds."; socket.destroy(); resolve(); });
    socket.once("error", (error) => { result.tls.detail = `The TLS handshake failed: ${error.message}`; resolve(); });
  });
  return result;
}

function countChain(peer) {
  let count = 0;
  let node = peer;
  const seen = new Set();
  while (node && node.fingerprint256 && !seen.has(node.fingerprint256)) {
    seen.add(node.fingerprint256);
    count += 1;
    node = node.issuerCertificate;
  }
  return count;
}

/**
 * The full manager-connectivity report used by Settings and by Repair in the Danger Zone.
 * It never changes anything; it only says what an agent would experience right now.
 */
async function report(context) {
  const { tlsManager, store, hostSettings, config } = context;
  const host = hostSettings.describe().host;
  const port = config.publicHttpsPort || config.httpsPort || 443;
  const cover = coverage(tlsManager, store, host);
  const trust = tlsManager.agentTrust();
  const live = await probe(host, port, {
    serverAddresses: hostSettings.addresses(),
    caRootPem: trust.caCertificate || undefined,
    pin: trust.certificatePin || ""
  });

  const problems = [];
  const warnings = [];
  const certificate = cover.certificate;
  if (!certificate) {
    problems.push("No TLS certificate is installed, so agents cannot connect at all.");
  } else {
    certificate.problems.forEach((problem) => problems.push(problem));
    certificate.warnings.forEach((warning) => warnings.push(warning));
    if (host && !cover.hostCovered) {
      problems.push(`The certificate does not cover ${host}, the address agents are told to use. It covers ${certificate.names.join(", ") || "no names"}.`);
    }
  }
  if (!live.dns.ok) {
    problems.push(live.dns.detail);
  } else if (live.dns.warning) {
    warnings.push(live.dns.warning);
  }
  if (live.dns.ok && !live.tcp.ok) {
    problems.push(`${live.tcp.detail} Check that the portal is running and that the firewall allows TCP ${port}.`);
  }
  if (live.tcp.ok && !live.tls.ok) {
    problems.push(`${live.tls.detail} This is what every agent sees.`);
  }
  if (cover.strandedAgents > 0) {
    problems.push(`${cover.strandedAgents} agent(s) are using an address the certificate does not cover: ${cover.stranded.map((group) => group.managerUrl).join(", ")}. They will reconnect on their own once they see a certificate that names ${host || "this portal"}, but only if that name resolves and is reachable from the endpoint.`);
  }
  if (cover.unknownAgents > 0) {
    warnings.push(`${cover.unknownAgents} agent(s) have not reported which address they use; they are running a build older than 1.5.0.`);
  }

  return {
    checkedUtc: new Date().toISOString(),
    host,
    port,
    managerUrl: hostSettings.managerUrl(),
    certificate,
    coverage: { covered: cover.covered, stranded: cover.stranded, unknown: cover.unknown },
    live,
    problems,
    warnings,
    ok: problems.length === 0
  };
}

module.exports = { report, coverage, agentAddresses, probe };
