"use strict";

// Turns whatever a certificate authority hands an administrator into the two files the portal serves:
// a certificate file holding the leaf, its intermediates and (for an internal CA) the root, and a key file.
//
// Accepted inputs: PEM or DER certificates, a PKCS#7 bundle (`.p7b`, what Windows CA web enrollment calls
// "certificate chain"), and PKCS#12 (`.pfx`/`.p12`, which carries the key as well). Order does not matter
// and duplicates are ignored: the leaf is found by matching the private key, and the chain is built from
// the issuer links. The result is validated before anything is written, so a bad import cannot take the
// portal off the air.
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const net = require("net");
const { execFileSync } = require("child_process");

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
const PEM_KEY = /-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/g;

function openssl(args, input, env) {
  return execFileSync("openssl", args, { input, stdio: ["pipe", "pipe", "pipe"], env: env ? { ...process.env, ...env } : process.env }).toString();
}

function withTempFile(buffer, run) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "uagent-tls-")), "input");
  try {
    fs.writeFileSync(file, buffer, { mode: 0o600 });
    return run(file);
  } finally {
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
}

function parses(pem) {
  try {
    new crypto.X509Certificate(pem);
    return true;
  } catch (error) {
    return false;
  }
}

// Pull every certificate out of one uploaded file, whatever container it came in.
function readCertificates(buffer, passphrase) {
  const text = buffer.toString("utf8");
  const blocks = text.match(PEM_CERT) || [];
  const readable = blocks.filter(parses).map((pem) => pem.trim());
  const unreadable = blocks.filter((pem) => !parses(pem));
  if (readable.length && !unreadable.length) {
    return { certificates: readable, keys: text.match(PEM_KEY) || [], format: "PEM" };
  }
  // Windows CA web enrollment writes its PKCS#7 chain under a CERTIFICATE header, so a block that is not
  // a certificate is decoded and offered to the container parsers.
  const candidates = unreadable.length
    ? unreadable.map((pem) => Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64"))
    : [buffer];
  const attempts = [
    { format: "DER certificate", args: ["x509", "-inform", "DER", "-outform", "PEM"] },
    { format: "PKCS#7 bundle", args: ["pkcs7", "-inform", "DER", "-print_certs"] },
    { format: "PKCS#7 bundle", args: ["pkcs7", "-inform", "PEM", "-print_certs"] }
  ];
  for (const candidate of candidates) {
    for (const attempt of attempts) {
      try {
        const found = (openssl(attempt.args, candidate).match(PEM_CERT) || []).filter(parses);
        if (found.length) {
          return {
            certificates: readable.concat(found.map((pem) => pem.trim())),
            keys: text.match(PEM_KEY) || [],
            format: attempt.format
          };
        }
      } catch (error) {
        // Try the next container format.
      }
    }
  }
  try {
    return withTempFile(buffer, (file) => {
      // The passphrase goes through the environment; on the command line any local user could read it.
      const env = { UAGENT_PFX_PASS: passphrase || "" };
      const certs = openssl(["pkcs12", "-in", file, "-clcerts", "-nokeys", "-passin", "env:UAGENT_PFX_PASS"], undefined, env);
      const chain = openssl(["pkcs12", "-in", file, "-cacerts", "-nokeys", "-passin", "env:UAGENT_PFX_PASS"], undefined, env);
      const key = openssl(["pkcs12", "-in", file, "-nocerts", "-nodes", "-passin", "env:UAGENT_PFX_PASS"], undefined, env);
      const certificates = `${certs}\n${chain}`.match(PEM_CERT) || [];
      if (!certificates.length) {
        throw new Error("no certificates");
      }
      return { certificates: certificates.map((pem) => pem.trim()), keys: key.match(PEM_KEY) || [], format: "PKCS#12" };
    });
  } catch (error) {
    throw new Error("The file is not a certificate the portal recognises. Supply PEM, DER, PKCS#7 (.p7b) or PKCS#12 (.pfx). A PKCS#12 file needs its password.");
  }
}

function parse(pem) {
  try {
    return new crypto.X509Certificate(pem);
  } catch (error) {
    throw new Error(`A certificate in the import could not be read: ${error.message}`);
  }
}

function isSelfIssued(cert) {
  try {
    return cert.subject === cert.issuer && cert.verify(cert.publicKey);
  } catch (error) {
    return false;
  }
}

function issuedBy(child, parent) {
  try {
    return child.checkIssued(parent) && child.verify(parent.publicKey);
  } catch (error) {
    return false;
  }
}

function describe(cert) {
  return cert.subject.replace(/\n/g, ", ");
}

function sanNames(cert) {
  return String(cert.subjectAltName || "").split(",").map((part) => part.trim()).filter(Boolean);
}

function covers(cert, host) {
  try {
    return net.isIP(host) !== 0 ? Boolean(cert.checkIP(host)) : Boolean(cert.checkHost(host));
  } catch (error) {
    return false;
  }
}

// Builds the ordered chain (leaf first) for the certificate matching `key`, and keeps the self-signed root
// aside: it is stored so agent installers can embed it, but it is not served.
function buildChain(certificates, key) {
  const unique = [];
  for (const pem of certificates) {
    const cert = parse(pem);
    if (!unique.some((entry) => entry.cert.fingerprint256 === cert.fingerprint256)) {
      unique.push({ pem, cert });
    }
  }
  const leaf = unique.find((entry) => {
    try {
      return entry.cert.checkPrivateKey(key);
    } catch (error) {
      return false;
    }
  });
  if (!leaf) {
    throw new Error("None of the certificates in the import belongs to the private key. Export the certificate that was issued for this server's key, or supply the matching key.");
  }
  // A lone self-signed certificate is marked CA:TRUE by openssl and is allowed for evaluation; a CA
  // certificate alongside others means the wrong key was supplied, usually the issuing CA's own key.
  if (leaf.cert.ca && !(unique.length === 1 && isSelfIssued(leaf.cert))) {
    throw new Error(`The certificate that belongs to the private key is a certificate authority (${describe(leaf.cert)}), not a server certificate. Supply this server's own key and certificate.`);
  }
  const ordered = [leaf];
  const rest = unique.filter((entry) => entry !== leaf);
  for (;;) {
    const top = ordered[ordered.length - 1].cert;
    if (isSelfIssued(top)) {
      break;
    }
    const next = rest.findIndex((entry) => issuedBy(top, entry.cert));
    if (next < 0) {
      break;
    }
    ordered.push(rest.splice(next, 1)[0]);
  }
  const top = ordered[ordered.length - 1].cert;
  const root = ordered.length > 1 && isSelfIssued(top) ? ordered[ordered.length - 1] : null;
  return { ordered, root, unused: rest, complete: isSelfIssued(top) };
}

/**
 * Validates an import and reports exactly what it would change, without writing anything.
 *
 * @param {object} input            `{ certificate, chain, key, passphrase }` of file buffers.
 * @param {object} context          `{ host, agentUrls }`: the host agents are told to contact, and the
 *                                  manager URLs installed agents are actually using.
 */
function plan(input, context) {
  const sources = [input.certificate, input.chain].filter(Boolean);
  if (!sources.length) {
    throw new Error("Supply at least a certificate file.");
  }
  const certificates = [];
  const keys = [];
  const formats = [];
  for (const buffer of sources) {
    const read = readCertificates(buffer, input.passphrase);
    certificates.push(...read.certificates);
    keys.push(...read.keys);
    formats.push(read.format);
  }
  if (input.key) {
    keys.push(...(input.key.toString("utf8").match(PEM_KEY) || []));
  }
  if (!keys.length) {
    throw new Error("The import contains no private key. Supply the key file, or export the certificate and key together as PKCS#12 (.pfx).");
  }

  let key = null;
  let keyPem = "";
  for (const candidate of keys) {
    try {
      key = crypto.createPrivateKey(input.passphrase ? { key: candidate, passphrase: input.passphrase } : candidate);
      keyPem = candidate;
      break;
    } catch (error) {
      // Try the next key in the bundle.
    }
  }
  if (!key) {
    throw new Error("The private key could not be read. If it is encrypted, supply its password.");
  }

  const { ordered, root, unused, complete } = buildChain(certificates, key);
  const leaf = ordered[0].cert;
  const problems = [];
  const warnings = [];

  const now = Date.now();
  if (new Date(leaf.validTo).getTime() <= now) {
    problems.push(`The certificate expired on ${new Date(leaf.validTo).toISOString()}.`);
  } else if (new Date(leaf.validFrom).getTime() > now) {
    problems.push(`The certificate is not valid until ${new Date(leaf.validFrom).toISOString()}.`);
  } else if (new Date(leaf.validTo).getTime() - now < 30 * 86400000) {
    warnings.push(`The certificate expires on ${new Date(leaf.validTo).toISOString().slice(0, 10)}, in under 30 days.`);
  }

  const eku = String(leaf.infoAccess || "");
  if (ordered.length === 1 && !isSelfIssued(leaf)) {
    problems.push(`Only the server certificate was supplied. Add the issuing chain: ${describe(leaf)} was issued by ${leaf.issuer.replace(/\n/g, ", ")}. A Windows CA provides it as certnew.p7b.`);
  }
  if (!complete && ordered.length > 1) {
    warnings.push(`The chain stops at ${describe(ordered[ordered.length - 1].cert)} without reaching a self-signed root. Agent installers can only embed a root, so include it, or deploy it to endpoints with Group Policy or Intune.`);
  }
  if (unused.length) {
    warnings.push(`${unused.length} certificate(s) in the import were not part of this chain and were ignored: ${unused.map((entry) => describe(entry.cert)).join("; ")}.`);
  }

  // The names clients use must be in the certificate, or the handshake fails on the name check. This is
  // the check that prevents an import from stranding the agents that are already deployed.
  const host = (context && context.host) || "";
  const names = sanNames(leaf);
  if (host && !covers(leaf, host)) {
    problems.push(`The certificate does not cover ${host}, the address agents are told to contact. It covers ${names.join(", ") || "no names"}.`);
  }
  const stranded = [];
  for (const entry of (context && context.agentUrls) || []) {
    let target = "";
    try {
      target = new URL(entry.managerUrl).hostname;
    } catch (error) {
      continue;
    }
    if (target && !covers(leaf, target)) {
      stranded.push({ managerUrl: entry.managerUrl, host: target, agents: entry.agents });
    }
  }

  return {
    format: [...new Set(formats)].join(" + "),
    subject: describe(leaf),
    issuer: leaf.issuer.replace(/\n/g, ", "),
    names,
    validFrom: new Date(leaf.validFrom).toISOString(),
    validTo: new Date(leaf.validTo).toISOString(),
    fingerprint: leaf.fingerprint256,
    serves: ordered.filter((entry) => entry !== root).map((entry) => describe(entry.cert)),
    rootSubject: root ? describe(root.cert) : "",
    hasRoot: Boolean(root),
    selfSigned: ordered.length === 1 && isSelfIssued(leaf),
    eku,
    problems,
    warnings,
    stranded,
    ok: problems.length === 0,
    // What would be written. The root is kept at the end of the certificate file: the portal recognises it
    // as the anchor, serves only what precedes it, and embeds it in agent installers.
    files: {
      certificate: `${ordered.map((entry) => entry.pem.trim()).join("\n")}\n`,
      key: `${keyPem.trim()}\n`,
      caRoot: root ? `${root.pem.trim()}\n` : ""
    }
  };
}

module.exports = { plan, readCertificates };
