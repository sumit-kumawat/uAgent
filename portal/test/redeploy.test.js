"use strict";

// Certificate validation in scripts/redeploy-centos.sh (run with --check-cert, which changes nothing).
//
// What these tests are protecting:
//   * a CA-issued bundle (leaf as CRLF PEM, chain as DER PKCS#7, like the AD CS download) is split into
//     server certificate, intermediates and root, and the chain verifies.
//   * the redeploy refuses a certificate whose SAN does not cover the host, a key that does not belong to
//     the certificate, and an HTML page saved as a ZIP.
//   * the bundled uagent.corp.helixops.ai.zip is recognised, and the private key is never in it.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const repo = path.resolve(__dirname, "..", "..");
const script = path.join(repo, "scripts", "redeploy-centos.sh");
const haveTools = ["openssl", "unzip", "zip"].every(t => spawnSync("sh", ["-c", `command -v ${t}`]).status === 0);

function sh(cwd, cmd) {
  const r = spawnSync("sh", ["-c", cmd], { cwd, encoding: "utf8" });
  assert.strictEqual(r.status, 0, `${cmd}\n${r.stderr}`);
}

function check(host, zip, key) {
  const r = spawnSync("bash", [script, "--check-cert", "--host", host, "--cert-zip", zip, "--key", key], { encoding: "utf8" });
  return { status: r.status, out: r.stdout + r.stderr };
}

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "uagent-redeploy-"));
  sh(dir, [
    "printf 'basicConstraints=critical,CA:TRUE\\nkeyUsage=keyCertSign,cRLSign\\n' > ca.ext",
    'openssl req -newkey rsa:2048 -nodes -keyout root.key -out root.csr -subj "/CN=Test Root"',
    "openssl x509 -req -in root.csr -signkey root.key -out root.crt -days 90 -extfile ca.ext",
    'openssl req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/CN=Test Issuing"',
    "openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 90 -extfile ca.ext",
    'openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=portal.test.local"',
    "printf 'basicConstraints=CA:FALSE\\nsubjectAltName=DNS:portal.test.local\\nextendedKeyUsage=serverAuth,clientAuth\\nkeyUsage=digitalSignature,keyEncipherment\\n' > leaf.ext",
    "openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -out leaf.crt -days 90 -extfile leaf.ext",
    "openssl genrsa -out other.key 2048",
    "mkdir -p z/portal && sed 's/$/\\r/' leaf.crt > z/portal/certnew.cer",
    "cat leaf.crt int.crt root.crt > all.pem && openssl crl2pkcs7 -nocrl -certfile all.pem -outform DER -out z/portal/certnew.p7b",
    "echo '<!DOCTYPE html><html></html>' > page.zip",
    "cd z && zip -qr ../bundle.zip portal",
  ].join(" && "));
  return dir;
}

test("redeploy certificate check", { skip: !haveTools && "openssl, zip or unzip is not installed" }, async t => {
  const dir = fixture();
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const f = name => path.join(dir, name);

  await t.test("a valid bundle and matching key pass", () => {
    const r = check("portal.test.local", f("bundle.zip"), f("leaf.key"));
    assert.strictEqual(r.status, 0, r.out);
    assert.match(r.out, /Server: +CN=portal\.test\.local/);
    assert.match(r.out, /Intermediate: CN=Test Issuing/);
    assert.match(r.out, /Root CA: +CN=Test Root/);
    assert.match(r.out, /Chain verified/);
    assert.match(r.out, /matches the certificate/);
    assert.doesNotMatch(r.out, /BEGIN .*PRIVATE KEY/);
  });

  await t.test("a host outside the SAN is refused", () => {
    const r = check("other.test.local", f("bundle.zip"), f("leaf.key"));
    assert.notStrictEqual(r.status, 0);
    assert.match(r.out, /No certificate in the ZIP is valid for other\.test\.local/);
  });

  await t.test("a key that does not belong to the certificate is refused", () => {
    const r = check("portal.test.local", f("bundle.zip"), f("other.key"));
    assert.notStrictEqual(r.status, 0);
    assert.match(r.out, /is not the private key of this certificate/);
  });

  await t.test("an HTML page instead of a ZIP is refused", () => {
    const r = check("portal.test.local", f("page.zip"), f("leaf.key"));
    assert.notStrictEqual(r.status, 0);
    assert.match(r.out, /not a ZIP file/);
  });

  await t.test("the bundled corporate certificate is recognised and holds no key", () => {
    const zip = path.join(repo, "uagent.corp.helixops.ai.zip");
    if (!fs.existsSync(zip)) return;
    const r = check("uagent.corp.helixops.ai", zip, f("leaf.key"));
    assert.match(r.out, /Server: +CN=uagent\.corp\.helixops\.ai/, r.out);
    assert.match(r.out, /Chain verified/);
    assert.match(r.out, /is not the private key of this certificate/);
    const listing = spawnSync("unzip", ["-l", zip], { encoding: "utf8" }).stdout;
    assert.doesNotMatch(listing, /\.(key|pfx|p12)\b/i);
  });
});
