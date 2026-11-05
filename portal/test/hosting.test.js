"use strict";

// Hosting: the portal answers on localhost, 127.0.0.1 and the server's LAN address on any port, can be
// limited to loopback with PORTAL_BIND_ADDRESS, refuses state-changing requests from another origin, and
// never accepts registrations under a publicly known enrollment key.
const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { lanIpv4Addresses } = require("../lib/network");

const ROOT = path.resolve(__dirname, "../..");
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

function startPortal(port, extraEnv) {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "uagent-hosting-"));
  const env = Object.assign({}, process.env, {
    PORTAL_STATE_DIR: stateDir,
    PORTAL_HTTP_PORT: String(port),
    PORTAL_HTTPS_PORT: "0",
    FORCE_HTTPS: "false",
    CANONICAL_REDIRECT: "false",
    TLS_MANAGE_SELF_SIGNED: "false",
    PORTAL_PASS: "Hostingpass123!",
    PORTAL_ENV_FILE: path.join(stateDir, "none.env")
  }, extraEnv || {});
  delete env.ENROLLMENT_KEY;
  delete env.AGENT_API_KEY;
  const portal = spawn("node", ["server.js"], { cwd: path.join(ROOT, "portal"), env, stdio: ["ignore", "pipe", "pipe"] });
  const log = [];
  portal.stdout.on("data", (d) => log.push(d.toString()));
  portal.stderr.on("data", (d) => log.push(d.toString()));
  return { portal, log, stateDir };
}

async function reachable(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
    return res.status === 200;
  } catch (error) {
    return false;
  }
}

async function waitFor(url) {
  for (let i = 0; i < 80; i++) {
    if (await reachable(url)) { return true; }
    await sleep(250);
  }
  return false;
}

function stop(instance) {
  instance.portal.kill("SIGKILL");
  fs.rmSync(instance.stateDir, { recursive: true, force: true });
}

const lanIp = lanIpv4Addresses()[0];

test("the portal answers on localhost, 127.0.0.1 and the server IP", async (t) => {
  const port = 18561;
  const instance = startPortal(port);
  t.after(() => stop(instance));
  assert.ok(await waitFor(`http://127.0.0.1:${port}/healthz`), instance.log.join("").slice(-600));
  assert.ok(await reachable(`http://localhost:${port}/healthz`), "localhost");
  if (lanIp) {
    assert.ok(await reachable(`http://${lanIp}:${port}/healthz`), `server IP ${lanIp}`);
    const health = await (await fetch(`http://127.0.0.1:${port}/healthz`)).json();
    assert.equal(health.agentUrl, `http://${lanIp}:${port}`, "agents are given the server IP, not localhost");
  }
  assert.match(instance.log.join(""), new RegExp(`http://127\\.0\\.0\\.1:${port}`), "127.0.0.1 is listed among the reachable URLs");
});

test("PORTAL_BIND_ADDRESS=127.0.0.1 keeps the portal off the network", { skip: !lanIp && "no LAN address" }, async (t) => {
  const port = 18562;
  const instance = startPortal(port, { PORTAL_BIND_ADDRESS: "127.0.0.1" });
  t.after(() => stop(instance));
  assert.ok(await waitFor(`http://127.0.0.1:${port}/healthz`), instance.log.join("").slice(-600));
  assert.equal(await reachable(`http://${lanIp}:${port}/healthz`), false, "the LAN address must not answer");
  // Agents may still be given the LAN address, which a reverse proxy on this server answers; the portal
  // itself only lists the loopback URLs as reachable.
  const reachableList = instance.log.join("").split("Reachable URLs:")[1] || "";
  assert.match(reachableList, new RegExp(`http://127\\.0\\.0\\.1:${port}`));
  assert.doesNotMatch(reachableList.split("Portal accounts")[0], new RegExp(`http://${lanIp.replace(/\./g, "\\.")}:${port}`), "no LAN URL is listed as reachable");
});

test("state-changing requests from another origin are refused; same-origin ones are not", async (t) => {
  const port = 18563;
  const instance = startPortal(port);
  t.after(() => stop(instance));
  const base = `http://127.0.0.1:${port}`;
  assert.ok(await waitFor(`${base}/healthz`), instance.log.join("").slice(-600));
  const post = (headers) => fetch(`${base}/login`, {
    method: "POST",
    redirect: "manual",
    headers: Object.assign({ "Content-Type": "application/x-www-form-urlencoded" }, headers),
    body: "username=admin&password=Hostingpass123!"
  });
  assert.equal((await post({ Origin: "http://evil.example" })).status, 403);
  assert.equal((await post({ Origin: `http://127.0.0.1:${port + 1}` })).status, 403, "another port on the same host is another origin");
  assert.equal((await post({ "Sec-Fetch-Site": "cross-site" })).status, 403);
  assert.equal((await post({ Origin: "null" })).status, 403);
  const same = await post({ Origin: base, "Sec-Fetch-Site": "same-origin" });
  assert.equal(same.status, 302, "a same-origin sign-in is accepted");
  const cli = await post({});
  assert.equal(cli.status, 302, "clients that send no Origin (agents, scripts) are not affected");
});

test("PORTAL_HTTPS_PORT=0 serves HTTP even when a certificate is present", async (t) => {
  const port = 18565;
  const certDir = fs.mkdtempSync(path.join(os.tmpdir(), "uagent-hosting-cert-"));
  const cert = path.join(certDir, "portal.crt");
  const key = path.join(certDir, "portal.key");
  require("child_process").execFileSync("bash", [path.join(ROOT, "portal/scripts/gencert.sh")], {
    env: Object.assign({}, process.env, { TLS_CERT_FILE: cert, TLS_KEY_FILE: key }),
    stdio: "ignore"
  });
  const instance = startPortal(port, { TLS_CERT_FILE: cert, TLS_KEY_FILE: key, FORCE_HTTPS: "true" });
  t.after(() => { stop(instance); fs.rmSync(certDir, { recursive: true, force: true }); });
  assert.ok(await waitFor(`http://127.0.0.1:${port}/healthz`), instance.log.join("").slice(-600));
  const res = await fetch(`http://127.0.0.1:${port}/login`, { redirect: "manual" });
  assert.equal(res.status, 200, `no redirect to an HTTPS port that is not served (${res.headers.get("location")})`);
  assert.match(instance.log.join(""), /HTTPS disabled \(PORTAL_HTTPS_PORT=0\)/);
});

test("without ENROLLMENT_KEY a private key is generated, kept, and the old default is refused", async (t) => {
  const port = 18564;
  const instance = startPortal(port);
  t.after(() => stop(instance));
  const base = `http://127.0.0.1:${port}`;
  assert.ok(await waitFor(`${base}/healthz`), instance.log.join("").slice(-600));
  const file = path.join(instance.stateDir, "enrollment-key");
  assert.ok(fs.existsSync(file), "the generated key is saved");
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  const key = fs.readFileSync(file, "utf8").trim();
  assert.match(key, /^[0-9a-f]{48}$/);
  const enroll = (apiKey) => fetch(`${base}/api/agents/enroll`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Api-Key": apiKey },
    body: JSON.stringify({ machineName: "pc-hosting", osVersion: "Windows 11", agentVersion: "1.5.1" })
  });
  assert.equal((await enroll("change-me-enroll")).status, 401);
  assert.equal((await enroll(key)).status, 201);
});
