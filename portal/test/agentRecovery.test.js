"use strict";

// Reproduces the production outage end to end with the real agent binary, then proves the fix.
//
//   The portal serves a certificate from a three-tier internal CA whose only name is "localhost".
//   The agent is configured, as the deployed fleet was, with the server's IP address.
//   Every request therefore fails the certificate host name check, including the heartbeat that would
//   have carried the corrected address, so the agent cannot be told where to go.
//
// Expected: the agent notices the certificate vouches for "localhost", verifies DNS, TCP, TLS and its own
// credential against that address, switches to it and reconnects, with no manual step on the endpoint.
const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const https = require("https");
const os = require("os");
const { buildPki } = require("./helpers/pki");

const ROOT = path.resolve(__dirname, "../..");
const PORT = 18443;
const STATE = path.join(os.tmpdir(), "uagent-recovery-state");
const AGENT_DIR = path.join(ROOT, "uAgent.Agent/bin/Release/net8.0");
const AGENT_DLL = path.join(AGENT_DIR, "uAgent.dll");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let passed = 0;
let failed = 0;
const check = (name, ok, detail) => {
  if (ok) { passed++; console.log("PASS ", name, detail ? "— " + detail : ""); }
  else { failed++; console.log("FAIL ", name, detail ? "— " + detail : ""); }
};

function run() {
const pki = buildPki({ host: "localhost", names: ["DNS:localhost"] });
fs.rmSync(STATE, { recursive: true, force: true });
fs.mkdirSync(STATE, { recursive: true });
const certFile = path.join(STATE, "portal.crt");
const keyFile = path.join(STATE, "portal.key");
fs.writeFileSync(certFile, [pki.pem("leaf.crt"), pki.pem("issuing.crt"), pki.pem("root.crt")].join("\n") + "\n");
fs.copyFileSync(pki.file("leaf.key"), keyFile);
const ca = pki.pem("root.crt");

function request(method, url, body, headers) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const payload = body === undefined ? null : JSON.stringify(body);
    const req = https.request({
      hostname: target.hostname,
      port: target.port,
      path: target.pathname + target.search,
      method,
      ca,
      servername: "localhost",
      headers: Object.assign({ Accept: "application/json" },
        payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {},
        headers || {})
    }, (res) => {
      let data = "";
      res.on("data", (c) => { data += c; });
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(data); } catch { json = data; }
        resolve({ status: res.statusCode, body: json });
      });
    });
    req.on("error", reject);
    if (payload) { req.write(payload); }
    req.end();
  });
}

return (async () => {
  const portal = spawn("node", ["server.js"], {
    cwd: path.join(ROOT, "portal"),
    env: Object.assign({}, process.env, {
      PORTAL_STATE_DIR: path.join(STATE, "portal"),
      PORTAL_HTTP_PORT: "0",
      PORTAL_HTTPS_PORT: String(PORT),
      TLS_CERT_FILE: certFile,
      TLS_KEY_FILE: keyFile,
      TLS_MANAGE_SELF_SIGNED: "false",
      FORCE_HTTPS: "false",
      PUBLIC_HOST: "localhost",
      ONLINE_WINDOW_MS: "15000",
      ENROLLMENT_KEY: "test-enroll-key",
      PORTAL_USERS: JSON.stringify([{ username: "admin", password: "testpass123", role: "Administrator" }])
    }),
    stdio: ["ignore", "pipe", "pipe"]
  });
  const portalLog = [];
  portal.stdout.on("data", (d) => portalLog.push(d.toString()));
  portal.stderr.on("data", (d) => portalLog.push(d.toString()));

  let agent = null;
  const agentLog = [];
  try {
    for (let i = 0; i < 60; i++) {
      try { await request("GET", `https://localhost:${PORT}/healthz`); break; } catch { await sleep(250); }
    }
    const health = await request("GET", `https://localhost:${PORT}/healthz`);
    check("portal serves the internal-CA certificate and verifies against its root", health.status === 200);
    check("portal reports the enterprise trust mode",
      /enterprise-ca/.test(portalLog.join("")), (portalLog.join("").match(/TLS certificate loaded[^\n]*/) || [""])[0].slice(0, 110));

    // Enrol the agent the way the installer does, then point it at the IP address, as the fleet was.
    const enroll = await request("POST", `https://localhost:${PORT}/api/agents/enroll`, {
      machineName: "PC-RECOVER", dnsName: "pc-recover.corp.example.com", domainName: "corp.example.com",
      osVersion: "Microsoft Windows 11 Enterprise", ipAddresses: ["192.0.2.77"], agentVersion: "1.5.0"
    }, { "X-Api-Key": "test-enroll-key" });
    check("agent enrols over the new certificate", enroll.status < 300 && Boolean(enroll.body.agentId),
      `status ${enroll.status} ${JSON.stringify(enroll.body).slice(0, 160)}`);
    if (!enroll.body || !enroll.body.agentId) { throw new Error("enrolment did not return an agent"); }

    const dataDir = path.join(AGENT_DIR, "data");
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "agent-state.json"), JSON.stringify({
      AgentId: enroll.body.agentId,
      DisplayId: enroll.body.displayId,
      ProtectedApiKey: "plain:" + Buffer.from(enroll.body.apiKey).toString("base64"),
      ManagerUrl: `https://127.0.0.1:${PORT}`,
      CaCertificate: ca,
      Status: "Active"
    }, null, 2));

    agent = spawn("dotnet", [AGENT_DLL, "/run"], {
      cwd: AGENT_DIR,
      env: Object.assign({}, process.env, { DOTNET_ENVIRONMENT: "Production", DOTNET_ROLL_FORWARD: "LatestMajor" }),
      stdio: ["ignore", "pipe", "pipe"]
    });
    agent.stdout.on("data", (d) => agentLog.push(d.toString()));
    agent.stderr.on("data", (d) => agentLog.push(d.toString()));

    const waitFor = async (pattern, ms) => {
      const end = Date.now() + ms;
      while (Date.now() < end) {
        if (pattern.test(agentLog.join(""))) { return true; }
        await sleep(300);
      }
      return false;
    };

    check("agent is refused at the IP address because the certificate does not cover it",
      await waitFor(/does not cover the manager host name/, 30000),
      (agentLog.join("").match(/does not cover the manager host name[^\n]*/) || [""])[0].slice(0, 90));

    check("agent corrects its own address using the name in the certificate",
      await waitFor(/manager address was corrected to/, 90000),
      (agentLog.join("").match(/The manager address was corrected to [^\s]+/) || [""])[0]);

    check("agent reconnects without touching the endpoint",
      await waitFor(/Connected|heartbeat|started as/i, 30000));

    // The portal must agree: the agent is online and the change is on the record.
    let session = "";
    const login = await new Promise((resolve, reject) => {
      const payload = "username=admin&password=testpass123";
      const req = https.request({
        hostname: "localhost", port: PORT, path: "/login", method: "POST", ca, servername: "localhost",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": payload.length }
      }, (res) => { session = (res.headers["set-cookie"] || []).map((c) => c.split(";")[0]).join("; "); res.resume(); res.on("end", () => resolve(res.statusCode)); });
      req.on("error", reject); req.write(payload); req.end();
    });
    check("portal sign-in works over the internal-CA certificate", login === 302);
    await request("POST", `https://localhost:${PORT}/api/account/password`,
      { currentPassword: "testpass123", newPassword: "newpass12345", confirmPassword: "newpass12345" }, { Cookie: session });

    let online = false;
    let detail = "";
    for (let i = 0; i < 40 && !online; i++) {
      const list = await request("GET", `https://localhost:${PORT}/api/agents`, undefined, { Cookie: session });
      const found = (Array.isArray(list.body) ? list.body : list.body.agents || []).find((a) => a.agentId === enroll.body.agentId || a.displayId === enroll.body.displayId);
      online = Boolean(found && found.online);
      detail = found ? `${found.machineName} ${found.online ? "online" : "offline"}` : "not listed";
      if (!online) { await sleep(1000); }
    }
    check("portal shows the recovered agent as online", online, detail);

    const audit = await request("GET", `https://localhost:${PORT}/api/audit`, undefined, { Cookie: session });
    const entries = Array.isArray(audit.body) ? audit.body : (audit.body.items || []);
    const recorded = entries.find((e) => /ManagerAddressChanged/i.test(e.action || "") || /corrected the manager address/i.test(e.details || ""));
    check("the address correction is recorded for the administrator", Boolean(recorded),
      recorded ? String(recorded.details).slice(0, 100) : entries.map((e) => e.action).join(","));
  } catch (error) {
    check("test ran without crashing", false, error.message);
  } finally {
    if (agent) { agent.kill("SIGKILL"); }
    portal.kill("SIGKILL");
    if (failed || process.argv.includes("--logs")) {
      console.log("\n--- agent ---\n" + agentLog.join("").slice(-4000));
      console.log("\n--- portal ---\n" + portalLog.join("").slice(-3000));
    }
    pki.cleanup();
    console.log(`\n${passed}/${passed + failed} passed`);
  }
})();
}

// Needs the agent build (`dotnet build -c Release`); skipped when it is not present.
test("a stranded agent recovers its manager address from the certificate", {
  skip: fs.existsSync(AGENT_DLL) ? false : "uAgent.dll has not been built",
  timeout: 240000
}, async () => {
  await run();
  assert.equal(failed, 0, `${failed} of ${passed + failed} connectivity checks failed`);
});
