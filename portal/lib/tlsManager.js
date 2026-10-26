"use strict";

// Owns the portal's TLS certificate: loads the leaf and its chain, classifies how clients can trust it,
// reloads it into the running HTTPS server when the files change (renewals, host changes), and reissues
// certificates the portal manages itself. Certificates from a public or enterprise CA are never rewritten.
//
// Trust modes, from most to least preferred:
//   public      chains to a root in the Mozilla/OS trust store; browsers and agents trust it as is.
//   private-ca  chains to TLS_CA_FILE (an internal root). Browsers trust it once the root is deployed by
//               GPO/Intune; agents receive the root in their installer and validate chain + hostname.
//   self-signed lab only. Agents can pin the public key; browsers always warn.
//   untrusted   the chain is incomplete or the key does not match. Agents will refuse to connect.
const fs = require("fs");
const path = require("path");
const net = require("net");
const crypto = require("crypto");
const tls = require("tls");
const { execFileSync } = require("child_process");

const RENEW_BEFORE_DAYS = 30;
const LEAF_DAYS = 397;
const WATCH_INTERVAL_MS = 30 * 1000;
const RENEW_CHECK_MS = 12 * 60 * 60 * 1000;

function splitPem(text) {
  return String(text).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
}

function spkiSha256(certificate) {
  const der = certificate.publicKey.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex").toUpperCase();
}

function isSelfIssued(certificate) {
  try {
    return certificate.subject === certificate.issuer && certificate.verify(certificate.publicKey);
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

let publicRoots = null;
function publicRootCertificates() {
  if (!publicRoots) {
    publicRoots = tls.rootCertificates.map((pem) => {
      try {
        return new crypto.X509Certificate(pem);
      } catch (error) {
        return null;
      }
    }).filter(Boolean);
  }
  return publicRoots;
}

function sanList(certificate) {
  return String(certificate.subjectAltName || "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function normalizePem(text) {
  return splitPem(text).map((pem) => pem.trim()).join("\n");
}

// The certificate that matches the private key is the leaf. Issuers follow it, so a file saved
// root-then-leaf is served leaf-then-root.
function orderChain(entries, key) {
  const leaf = entries.find((entry) => {
    try {
      return Boolean(key) && entry.cert.checkPrivateKey(key);
    } catch (error) {
      return false;
    }
  }) || entries[0];
  const ordered = [leaf];
  const rest = entries.filter((entry) => entry !== leaf);
  while (rest.length) {
    const current = ordered[ordered.length - 1].cert;
    const next = rest.findIndex((entry) => issuedBy(current, entry.cert));
    if (next < 0) {
      break;
    }
    ordered.push(rest.splice(next, 1)[0]);
  }
  return ordered.concat(rest);
}

function createTlsManager(config, logger) {
  const servers = [];
  let current = null;
  let lastMtime = "";

  function readCaRoot() {
    if (!config.caFile || !fs.existsSync(config.caFile)) {
      return null;
    }
    try {
      const pems = splitPem(fs.readFileSync(config.caFile, "utf8"));
      return pems.length ? { pem: pems[pems.length - 1], cert: new crypto.X509Certificate(pems[pems.length - 1]) } : null;
    } catch (error) {
      logger(`Could not read the private CA certificate ${config.caFile}: ${error.message}`);
      return null;
    }
  }

  function inspect() {
    if (!fs.existsSync(config.certFile) || !fs.existsSync(config.keyFile)) {
      return null;
    }
    const certText = fs.readFileSync(config.certFile, "utf8");
    const keyText = fs.readFileSync(config.keyFile);
    const pems = splitPem(certText);
    if (!pems.length) {
      throw new Error(`${config.certFile} does not contain a PEM certificate.`);
    }
    const entries = pems.map((pem) => ({ pem: pem.trim(), cert: new crypto.X509Certificate(pem) }));
    let key = null;
    try {
      key = crypto.createPrivateKey(keyText);
    } catch (error) {
      // Reported below when the leaf cannot be matched to the key.
    }
    const ordered = orderChain(entries, key);
    const chain = ordered.map((entry) => entry.cert);
    const leaf = chain[0];
    const problems = [];
    const corrected = `${ordered.map((entry) => entry.pem).join("\n")}\n`;

    let keyMatches = false;
    try {
      keyMatches = Boolean(key) && leaf.checkPrivateKey(key);
    } catch (error) {
      problems.push(`The private key could not be read: ${error.message}`);
    }
    if (!keyMatches) {
      problems.push("The private key does not belong to the certificate.");
    }
    let linked = true;
    for (let i = 0; i < chain.length - 1; i += 1) {
      if (!issuedBy(chain[i], chain[i + 1])) {
        linked = false;
        problems.push(`Certificate ${i + 1} in ${path.basename(config.certFile)} was not issued by certificate ${i + 2}; the chain is out of order.`);
      }
    }
    // openssl req -x509 marks self-signed certificates as CA:TRUE, so only flag a CA leaf inside a chain.
    const singleSelfSigned = chain.length === 1 && isSelfIssued(leaf);
    if (leaf.ca && !singleSelfSigned) {
      problems.push("The first certificate is a CA certificate. Put the server certificate first, then intermediates.");
    }

    const last = chain[chain.length - 1];
    const caRoot = readCaRoot();
    let mode = "untrusted";
    let anchor = "";
    if (singleSelfSigned) {
      mode = "self-signed";
      anchor = leaf.subject;
    } else if (caRoot && (issuedBy(last, caRoot.cert) || last.fingerprint256 === caRoot.cert.fingerprint256)) {
      mode = "private-ca";
      anchor = caRoot.cert.subject;
    } else {
      const root = isSelfIssued(last) ? last : publicRootCertificates().find((candidate) => issuedBy(last, candidate));
      if (root && publicRootCertificates().some((candidate) => candidate.fingerprint256 === root.fingerprint256)) {
        mode = "public";
        anchor = root.subject;
      } else if (isSelfIssued(last)) {
        problems.push("The chain ends at a root that is neither public nor configured as TLS_CA_FILE.");
      } else {
        problems.push("The chain is incomplete: an intermediate certificate is missing, or the issuing CA is not trusted. Include the full chain in the certificate file.");
      }
    }

    const validTo = new Date(leaf.validTo);
    const validFrom = new Date(leaf.validFrom);
    if (validTo.getTime() <= Date.now()) {
      problems.push(`The certificate expired on ${validTo.toISOString()}.`);
    }
    if (validFrom.getTime() > Date.now()) {
      problems.push(`The certificate is not valid until ${validFrom.toISOString()}.`);
    }

    return {
      cert: linked ? corrected : certText,
      key: keyText,
      rewrite: linked && normalizePem(certText) !== normalizePem(corrected),
      leaf,
      chainLength: chain.length,
      mode: problems.some((p) => /private key|chain|out of order|CA certificate/.test(p)) ? "untrusted" : mode,
      anchor: anchor.replace(/\n/g, ", "),
      caRootPem: mode === "private-ca" && caRoot ? caRoot.pem : "",
      fingerprint: leaf.fingerprint256,
      spki: spkiSha256(leaf),
      subject: leaf.subject.replace(/\n/g, ", "),
      issuer: leaf.issuer.replace(/\n/g, ", "),
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      names: sanList(leaf),
      problems,
      healthy: problems.length === 0,
      managed: isManaged(mode)
    };
  }

  // The portal rewrites only certificates it created: its own self-signed lab certificate, or leaves signed
  // by the private CA whose key it holds. Anything else belongs to the administrator's PKI.
  function isManaged(mode) {
    if (mode === "self-signed") {
      return config.manageSelfSigned;
    }
    return mode === "private-ca" && Boolean(config.caKeyFile) && fs.existsSync(config.caKeyFile);
  }

  function mtimeKey() {
    try {
      return [config.certFile, config.keyFile].map((file) => fs.statSync(file).mtimeMs).join(":");
    } catch (error) {
      return "";
    }
  }

  function load() {
    try {
      current = inspect();
      if (current && current.rewrite) {
        writeAtomic(config.certFile, current.cert);
        current.rewrite = false;
        logger(`TLS certificate chain in ${config.certFile} was out of order. It was rewritten with the server certificate first.`);
      }
      lastMtime = mtimeKey();
      if (current) {
        current.problems.forEach((problem) => logger(`TLS: ${problem}`));
      }
    } catch (error) {
      logger(`Could not read the TLS certificate: ${error.message}`);
      current = null;
    }
    return current;
  }

  function apply() {
    if (!current) {
      return;
    }
    for (const server of servers) {
      try {
        server.setSecureContext({ cert: current.cert, key: current.key });
      } catch (error) {
        logger(`Could not load the new TLS certificate into the HTTPS listener: ${error.message}`);
      }
    }
  }

  function reload(reason) {
    const before = current ? current.fingerprint : "";
    load();
    if (current && current.fingerprint !== before) {
      apply();
      logger(`TLS certificate loaded (${reason}): ${current.subject}, ${current.mode}, valid to ${current.validTo}, SHA-256 ${current.fingerprint}.`);
    }
    return current;
  }

  function attach(server) {
    servers.push(server);
  }

  function covers(host) {
    if (!current || !host) {
      return false;
    }
    try {
      return net.isIP(host) !== 0 ? Boolean(current.leaf.checkIP(host)) : Boolean(current.leaf.checkHost(host));
    } catch (error) {
      return false;
    }
  }

  function altNames(host, extraIps) {
    const names = new Set();
    const add = (value) => {
      if (!value) {
        return;
      }
      names.add(net.isIP(value) !== 0 ? `IP:${value}` : `DNS:${value}`);
    };
    add(host);
    (extraIps || []).forEach(add);
    if (config.publicHost && net.isIP(config.publicHost) === 0 && config.publicHost !== "uagent.example.com") {
      add(config.publicHost);
    }
    add("localhost");
    add("127.0.0.1");
    return [...names];
  }

  // Issue a leaf for `host`. The existing private key is reused so agents that pin the public key, and
  // anything else keyed to it, keep working after the host name changes or the certificate is renewed.
  function issue(host, extraIps) {
    const mode = current ? current.mode : (config.caKeyFile && fs.existsSync(config.caKeyFile) ? "private-ca" : "self-signed");
    if (current && !current.managed) {
      return { issued: false, reason: `The installed certificate (${current.mode}) is managed outside the portal. Install a certificate whose SAN includes ${host}.` };
    }
    const dir = path.dirname(config.certFile);
    fs.mkdirSync(dir, { recursive: true });
    if (!fs.existsSync(config.keyFile)) {
      execFileSync("openssl", ["genrsa", "-out", config.keyFile, "2048"], { stdio: "pipe" });
    }
    fs.chmodSync(config.keyFile, 0o600);
    const names = altNames(host, extraIps).join(",");
    const subject = `/CN=${host}`;
    const tmp = fs.mkdtempSync(path.join(dir, ".issue-"));
    try {
      const ext = path.join(tmp, "ext.cnf");
      fs.writeFileSync(ext, [
        "basicConstraints=critical,CA:FALSE",
        "keyUsage=critical,digitalSignature,keyEncipherment",
        "extendedKeyUsage=serverAuth",
        `subjectAltName=${names}`,
        "subjectKeyIdentifier=hash",
        "authorityKeyIdentifier=keyid,issuer"
      ].join("\n") + "\n");
      const csr = path.join(tmp, "leaf.csr");
      const leaf = path.join(tmp, "leaf.crt");
      execFileSync("openssl", ["req", "-new", "-key", config.keyFile, "-subj", subject, "-out", csr], { stdio: "pipe" });
      if (mode === "private-ca") {
        execFileSync("openssl", ["x509", "-req", "-in", csr, "-CA", config.caFile, "-CAkey", config.caKeyFile,
          "-set_serial", `0x${crypto.randomBytes(16).toString("hex")}`, "-days", String(LEAF_DAYS), "-sha256",
          "-extfile", ext, "-out", leaf], { stdio: "pipe" });
        const root = splitPem(fs.readFileSync(config.caFile, "utf8")).pop();
        writeAtomic(config.certFile, fs.readFileSync(leaf, "utf8").trim() + "\n" + root.trim() + "\n");
      } else {
        fs.writeFileSync(ext, fs.readFileSync(ext, "utf8").replace("authorityKeyIdentifier=keyid,issuer\n", ""));
        execFileSync("openssl", ["x509", "-req", "-in", csr, "-signkey", config.keyFile,
          "-set_serial", `0x${crypto.randomBytes(16).toString("hex")}`, "-days", String(LEAF_DAYS), "-sha256",
          "-extfile", ext, "-out", leaf], { stdio: "pipe" });
        writeAtomic(config.certFile, fs.readFileSync(leaf, "utf8"));
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
    reload(`issued for ${host}`);
    return { issued: true, mode, names };
  }

  function writeAtomic(file, contents) {
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, contents, { mode: 0o644 });
    fs.renameSync(tmp, file);
  }

  function renewIfDue(hostProvider) {
    if (!current || !current.managed) {
      return;
    }
    const remainingDays = (new Date(current.validTo).getTime() - Date.now()) / 86400000;
    const host = hostProvider();
    if (remainingDays > RENEW_BEFORE_DAYS && covers(host)) {
      return;
    }
    try {
      const result = issue(host, hostProvider.ips ? hostProvider.ips() : []);
      if (result.issued) {
        logger(`TLS certificate renewed for ${host} (${result.mode}).`);
      }
    } catch (error) {
      logger(`TLS certificate renewal failed: ${error.message}`);
    }
  }

  function start(hostProvider) {
    const watch = setInterval(() => {
      if (mtimeKey() !== lastMtime) {
        reload("file changed");
      }
    }, WATCH_INTERVAL_MS);
    watch.unref();
    const renew = setInterval(() => renewIfDue(hostProvider), RENEW_CHECK_MS);
    renew.unref();
    renewIfDue(hostProvider);
  }

  // What the installer embeds so the agent can verify the portal. Public certificates need nothing.
  function agentTrust() {
    if (!current) {
      return { certificatePin: "", spkiPin: "", caCertificate: "" };
    }
    if (current.mode === "private-ca") {
      return { certificatePin: "", spkiPin: "", caCertificate: current.caRootPem };
    }
    if (current.mode === "self-signed" && config.embedCertPin) {
      return { certificatePin: current.fingerprint, spkiPin: current.spki, caCertificate: "" };
    }
    return { certificatePin: "", spkiPin: "", caCertificate: "" };
  }

  function describe() {
    if (!current) {
      return null;
    }
    const { cert, key, leaf, caRootPem, rewrite, ...rest } = current;
    return Object.assign(rest, { hasCaRoot: Boolean(caRootPem) });
  }

  function caRootPem() {
    return current && current.caRootPem ? current.caRootPem : (readCaRoot() || {}).pem || "";
  }

  load();
  return { load, reload, attach, start, covers, issue, agentTrust, describe, caRootPem, get current() { return current; } };
}

module.exports = { createTlsManager, splitPem, spkiSha256 };
