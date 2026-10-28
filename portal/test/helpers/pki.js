"use strict";

// Builds a three-tier PKI (root -> issuing CA -> server certificate) in a temporary directory, so the TLS
// tests exercise the same shape as a corporate Windows CA rather than a self-signed shortcut.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

function openssl(args, options) {
  return execFileSync("openssl", args, Object.assign({ stdio: ["pipe", "pipe", "pipe"] }, options));
}

function serial() {
  return `0x${require("crypto").randomBytes(16).toString("hex")}`;
}

function buildPki(options) {
  const host = (options && options.host) || "uagent.corp.example.com";
  const names = (options && options.names) || [`DNS:${host}`];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "uagent-pki-"));
  const file = (name) => path.join(dir, name);
  const ext = (name, lines) => {
    fs.writeFileSync(file(name), `${lines.join("\n")}\n`);
    return file(name);
  };

  openssl(["genrsa", "-out", file("root.key"), "2048"]);
  openssl(["req", "-x509", "-new", "-key", file("root.key"), "-sha256", "-days", "3650",
    "-subj", "/CN=TEST Root CA", "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", file("root.crt")]);

  openssl(["genrsa", "-out", file("issuing.key"), "2048"]);
  openssl(["req", "-new", "-key", file("issuing.key"), "-subj", "/CN=TEST Issuing CA", "-out", file("issuing.csr")]);
  openssl(["x509", "-req", "-in", file("issuing.csr"), "-CA", file("root.crt"), "-CAkey", file("root.key"),
    "-set_serial", serial(), "-days", "1800", "-sha256", "-out", file("issuing.crt"),
    "-extfile", ext("issuing.cnf", [
      "basicConstraints=critical,CA:TRUE,pathlen:0",
      "keyUsage=critical,keyCertSign,cRLSign",
      "subjectKeyIdentifier=hash"
    ])]);

  openssl(["genrsa", "-out", file("leaf.key"), "2048"]);
  openssl(["req", "-new", "-key", file("leaf.key"), "-subj", `/CN=${host}`, "-out", file("leaf.csr")]);
  openssl(["x509", "-req", "-in", file("leaf.csr"), "-CA", file("issuing.crt"), "-CAkey", file("issuing.key"),
    "-set_serial", serial(), "-days", "397", "-sha256", "-out", file("leaf.crt"),
    "-extfile", ext("leaf.cnf", [
      "basicConstraints=critical,CA:FALSE",
      "keyUsage=critical,digitalSignature,keyEncipherment",
      "extendedKeyUsage=serverAuth",
      `subjectAltName=${names.join(",")}`,
      "authorityKeyIdentifier=keyid,issuer"
    ])]);

  // A leaf signed straight off the root, for the case where the portal owns the CA key.
  openssl(["x509", "-req", "-in", file("leaf.csr"), "-CA", file("root.crt"), "-CAkey", file("root.key"),
    "-set_serial", serial(), "-days", "397", "-sha256", "-out", file("leaf-from-root.crt"),
    "-extfile", file("leaf.cnf")]);

  // Windows CA web enrollment hands out the chain as PKCS#7 but armours it as a CERTIFICATE block.
  const p7 = openssl(["crl2pkcs7", "-nocrl", "-certfile", file("leaf.crt"), "-certfile", file("issuing.crt"),
    "-certfile", file("root.crt"), "-outform", "DER"]);
  const body = p7.toString("base64").replace(/(.{64})/g, "$1\n").trim();
  fs.writeFileSync(file("chain.p7b"), `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`);

  const read = (name) => fs.readFileSync(file(name));
  return {
    dir,
    host,
    file,
    read,
    pem: (name) => read(name).toString("utf8").trim(),
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true })
  };
}

module.exports = { buildPki };
