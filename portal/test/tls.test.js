"use strict";

// Regression tests for the outage where agents stopped connecting after an enterprise certificate was
// installed. Each case here maps to one of the faults that caused it:
//   * only the server certificate was installed, so the chain could not be verified;
//   * a valid internal root was classified as untrusted, so agent installers embedded no trust material;
//   * the new certificate did not cover the address installed agents were still using.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { buildPki } = require("./helpers/pki");
const tlsImport = require("../lib/tlsImport");
const { createTlsManager } = require("../lib/tlsManager");

const pki = buildPki({ host: "uagent.corp.example.com" });
test.after(() => pki.cleanup());

function manager(certPems, options) {
  const dir = fs.mkdtempSync(path.join(pki.dir, "srv-"));
  const certFile = path.join(dir, "portal.crt");
  const keyFile = path.join(dir, "portal.key");
  fs.writeFileSync(certFile, `${certPems.join("\n")}\n`);
  fs.copyFileSync(pki.file((options && options.key) || "leaf.key"), keyFile);
  const config = Object.assign({
    certFile,
    keyFile,
    caFile: "",
    caKeyFile: "",
    manageSelfSigned: true,
    embedCertPin: true,
    publicHost: "uagent.example.com"
  }, (options && options.config) || {});
  const logs = [];
  return { tls: createTlsManager(config, (line) => logs.push(line)), logs, certFile };
}

test("a Windows CA chain file armoured as a CERTIFICATE block is read as PKCS#7", () => {
  const read = tlsImport.readCertificates(pki.read("chain.p7b"));
  assert.equal(read.format, "PKCS#7 bundle");
  assert.equal(read.certificates.length, 3);
});

test("installing only the server certificate is refused and names the missing issuer", () => {
  const result = manager([pki.pem("leaf.crt")]);
  const state = result.tls.current;
  assert.equal(state.mode, "untrusted");
  assert.equal(state.healthy, false);
  assert.match(state.problems.join(" "), /Only the server certificate is installed/);
  assert.match(state.problems.join(" "), /TEST Issuing CA/);
  assert.deepEqual(result.tls.agentTrust(), { certificatePin: "", spkiPin: "", caCertificate: "" });
});

test("a chain without its root serves, but warns that installers cannot embed trust", () => {
  const result = manager([pki.pem("leaf.crt"), pki.pem("issuing.crt")]);
  const state = result.tls.current;
  assert.equal(state.mode, "enterprise-ca");
  assert.equal(state.healthy, true);
  assert.match(state.warnings.join(" "), /issuing root is not available/);
  assert.equal(result.tls.agentTrust().caCertificate, "");
});

test("an internal root in the certificate file becomes the trust anchor and is not served", () => {
  const result = manager([pki.pem("leaf.crt"), pki.pem("issuing.crt"), pki.pem("root.crt")]);
  const state = result.tls.current;
  assert.equal(state.mode, "enterprise-ca");
  assert.equal(state.healthy, true);
  assert.deepEqual(state.warnings, []);
  assert.equal(state.chainLength, 3);
  assert.equal(state.servedLength, 2, "the root is an anchor, not something to transmit");
  assert.match(state.cert, /BEGIN CERTIFICATE/);
  assert.equal(state.cert.match(/BEGIN CERTIFICATE/g).length, 2);
  assert.equal(result.tls.agentTrust().caCertificate.trim(), pki.pem("root.crt"));
  assert.equal(state.managed, false, "a certificate from the corporate CA is never rewritten");
});

test("the root may instead be configured as TLS_CA_FILE", () => {
  const result = manager([pki.pem("leaf.crt"), pki.pem("issuing.crt")], {
    config: { caFile: pki.file("root.crt") }
  });
  assert.equal(result.tls.current.mode, "enterprise-ca");
  assert.equal(result.tls.agentTrust().caCertificate.trim(), pki.pem("root.crt"));
});

test("holding the CA key makes the certificate renewable by the portal", () => {
  const result = manager([pki.pem("leaf-from-root.crt"), pki.pem("root.crt")], {
    config: { caFile: pki.file("root.crt"), caKeyFile: pki.file("root.key") }
  });
  assert.equal(result.tls.current.mode, "private-ca");
  assert.equal(result.tls.current.managed, true);
});

test("host coverage is reported per name, so an IP-addressed agent is not assumed to work", () => {
  const result = manager([pki.pem("leaf.crt"), pki.pem("issuing.crt"), pki.pem("root.crt")]);
  assert.equal(result.tls.covers("uagent.corp.example.com"), true);
  assert.equal(result.tls.covers("192.0.2.25"), false);
});

test("an import plan reports what will be served and keeps the root aside", () => {
  const plan = tlsImport.plan({
    certificate: pki.read("leaf.crt"),
    chain: pki.read("chain.p7b"),
    key: pki.read("leaf.key")
  }, { host: pki.host });
  assert.equal(plan.ok, true);
  assert.deepEqual(plan.problems, []);
  assert.equal(plan.serves.length, 2);
  assert.equal(plan.hasRoot, true);
  assert.match(plan.rootSubject, /TEST Root CA/);
  assert.equal(plan.files.certificate.match(/BEGIN CERTIFICATE/g).length, 3);
});

test("an import of the leaf alone is refused and points at the chain file", () => {
  const plan = tlsImport.plan({ certificate: pki.read("leaf.crt"), key: pki.read("leaf.key") }, { host: pki.host });
  assert.equal(plan.ok, false);
  assert.match(plan.problems.join(" "), /Only the server certificate was supplied/);
  assert.match(plan.problems.join(" "), /certnew\.p7b/);
});

test("an import that does not cover the configured host is refused", () => {
  const plan = tlsImport.plan({
    certificate: pki.read("leaf.crt"),
    chain: pki.read("chain.p7b"),
    key: pki.read("leaf.key")
  }, { host: "uagent.other.example.com" });
  assert.equal(plan.ok, false);
  assert.match(plan.problems.join(" "), /does not cover uagent\.other\.example\.com/);
});

test("an import lists the agents it would strand before anything is written", () => {
  const plan = tlsImport.plan({
    certificate: pki.read("leaf.crt"),
    chain: pki.read("chain.p7b"),
    key: pki.read("leaf.key")
  }, {
    host: pki.host,
    agentUrls: [
      { managerUrl: "https://192.0.2.25:443", agents: 12 },
      { managerUrl: `https://${pki.host}:443`, agents: 3 }
    ]
  });
  assert.equal(plan.ok, true, "stranding is reported, not a validation failure");
  assert.equal(plan.stranded.length, 1);
  assert.equal(plan.stranded[0].host, "192.0.2.25");
  assert.equal(plan.stranded[0].agents, 12);
});

test("a key that belongs to no supplied certificate is refused", () => {
  assert.throws(() => tlsImport.plan({
    certificate: pki.read("leaf.crt"),
    key: pki.read("root.key")
  }, { host: pki.host }), /belongs to the private key/);
});

test("supplying the issuing CA's own key instead of the server's is refused", () => {
  assert.throws(() => tlsImport.plan({
    certificate: pki.read("leaf.crt"),
    chain: pki.read("chain.p7b"),
    key: pki.read("issuing.key")
  }, { host: pki.host }), /is a certificate authority/);
});

test("a certificate with no private key is refused", () => {
  assert.throws(() => tlsImport.plan({ certificate: pki.read("leaf.crt") }, { host: pki.host }),
    /contains no private key/);
});

test("a self-signed certificate still offers a pin for evaluation", () => {
  const result = manager([pki.pem("leaf.crt")], {
    config: { caFile: "", caKeyFile: "" }
  });
  assert.equal(result.tls.current.mode, "untrusted");
  const selfSigned = manager([fs.readFileSync(pki.file("root.crt"), "utf8").trim()], { key: "root.key" });
  assert.equal(selfSigned.tls.current.mode, "self-signed");
  assert.equal(selfSigned.tls.agentTrust().spkiPin.length, 64);
});
