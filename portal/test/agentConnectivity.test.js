"use strict";

// Connection stability with the real agent binary.
//
//   1. The agent connects and stays connected: it keeps one registration and is shown online.
//   2. The manager is restarted. The agent must reconnect by itself, with backoff, using its existing
//      credential: no new enrolment, no second record, no loss of identity.
//   3. While the manager is away the dashboard must say "reconnecting", not "disconnected".
const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const https = require("https");
const os = require("os");
const { buildPki } = require("./helpers/pki");

const ROOT = path.resolve(__dirname, "../..");
const PORT = 18445;
const STATE = path.join(os.tmpdir(), "uagent-connectivity-state");
const BUILD_DIR = path.join(ROOT, "uAgent.Agent/bin/Release/net8.0");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function run() {
  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok, detail });
    console.log(ok ? "PASS " : "FAIL ", name, detail ? "— " + detail : "");
  };
  const pki = buildPki({ host: "localhost", names: ["DNS:localhost"] });
  fs.rmSync(STATE, { recursive: true, force: true });
  fs.mkdirSync(STATE, { recursive: true });
  // The agent keeps its state next to the binary when it is not installed, so it runs from its own copy.
  const agentDir = path.join(STATE, "agent");
  fs.cpSync(BUILD_DIR, agentDir, { recursive: true, filter: (src) => path.basename(src) !== "data" });
  const certFile = path.join(STATE, "portal.crt");
  const keyFile = path.join(STATE, "portal.key");
  fs.writeFileSync(certFile, [pki.pem("leaf.crt"), pki.pem("issuing.crt"), pki.pem("root.crt")].join("\n") + "\n");
  fs.copyFileSync(pki.file("leaf.key"), keyFile);
  const ca = pki.pem("root.crt");

  function request(method, url, body, headers) {
    return new Promise((resolve, reject) => {
      const target = new URL(url);
      const payload = body === undefined ? null : (typeof body === "string" ? body : JSON.stringify(body));
      const req = https.request({
        hostname: target.hostname, port: target.port, path: target.pathname + target.search, method, ca, servername: "localhost",
        headers: Object.assign({ Accept: "application/json" },
          payload ? { "Content-Type": typeof body === "string" ? "application/x-www-form-urlencoded" : "application/json", "Content-Length": Buffer.byteLength(payload) } : {},
          headers || {})
      }, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; });
        res.on("end", () => {
          let json = null;
          try { json = JSON.parse(data); } catch { json = data; }
          resolve({ status: res.statusCode, body: json, headers: res.headers });
        });
      });
      req.on("error", reject);
      if (payload) { req.write(payload); }
      req.end();
    });
  }

  const portalLog = [];
  function startPortal() {
    const child = spawn("node", ["server.js"], {
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
        AGENT_HEARTBEAT_SECONDS: "5",
        ENROLLMENT_KEY: "test-enroll-key",
        PORTAL_USERS: JSON.stringify([{ username: "admin", password: "testpass123", role: "Administrator" }])
      }),
      stdio: ["ignore", "pipe", "pipe"]
    });
    child.stdout.on("data", (d) => portalLog.push(d.toString()));
    child.stderr.on("data", (d) => portalLog.push(d.toString()));
    return child;
  }
  async function waitForPortal() {
    for (let i = 0; i < 80; i++) {
      try { if ((await request("GET", `https://localhost:${PORT}/healthz`)).status === 200) { return true; } } catch { /* starting */ }
      await sleep(250);
    }
    return false;
  }
  async function signIn() {
    const login = await request("POST", `https://localhost:${PORT}/login`, "username=admin&password=testpass123");
    const cookie = (login.headers["set-cookie"] || []).map((c) => c.split(";")[0]).join("; ");
    await request("POST", `https://localhost:${PORT}/api/account/password`,
      { currentPassword: "testpass123", newPassword: "newpass12345", confirmPassword: "newpass12345" }, { Cookie: cookie });
    return cookie;
  }
  async function signInAgain() {
    const login = await request("POST", `https://localhost:${PORT}/login`, "username=admin&password=newpass12345");
    return (login.headers["set-cookie"] || []).map((c) => c.split(";")[0]).join("; ");
  }
  async function agents(cookie) {
    const list = await request("GET", `https://localhost:${PORT}/api/agents`, undefined, { Cookie: cookie });
    return Array.isArray(list.body) ? list.body : (list.body.agents || []);
  }
  async function waitOnline(cookie, agentId, ms) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const found = (await agents(cookie)).find((a) => a.agentId === agentId);
      if (found && found.connection === "online") { return found; }
      await sleep(1000);
    }
    return null;
  }

  let portal = startPortal();
  let agent = null;
  const agentLog = [];
  try {
    check("portal starts", await waitForPortal());
    let cookie = await signIn();

    const enroll = await request("POST", `https://localhost:${PORT}/api/agents/enroll`, {
      machineName: "PC-0142", dnsName: "pc-0142.corp.example.com", domainName: "corp.example.com",
      osVersion: "Microsoft Windows 11 Enterprise", ipAddresses: ["192.0.2.42"], agentVersion: "1.5.0"
    }, { "X-Api-Key": "test-enroll-key" });
    if (!enroll.body || !enroll.body.agentId) { throw new Error(`enrolment failed: ${JSON.stringify(enroll.body).slice(0, 200)}`); }
    const agentId = enroll.body.agentId;

    const dataDir = path.join(agentDir, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(path.join(dataDir, "agent-state.json"), JSON.stringify({
      AgentId: agentId,
      DisplayId: enroll.body.displayId,
      ProtectedApiKey: "plain:" + Buffer.from(enroll.body.apiKey).toString("base64"),
      ManagerUrl: `https://localhost:${PORT}`,
      CaCertificate: ca,
      Status: "Active"
    }, null, 2));

    agent = spawn("dotnet", [path.join(agentDir, "uAgent.dll"), "/run"], {
      cwd: agentDir,
      env: Object.assign({}, process.env, { DOTNET_ENVIRONMENT: "Production", DOTNET_ROLL_FORWARD: "LatestMajor" }),
      stdio: ["ignore", "pipe", "pipe"]
    });
    agent.stdout.on("data", (d) => agentLog.push(d.toString()));
    agent.stderr.on("data", (d) => agentLog.push(d.toString()));

    const first = await waitOnline(cookie, agentId, 60000);
    check("agent connects and is shown online", Boolean(first), first ? first.connection : "not online");

    // Stay connected across several long polls: no flapping to another state.
    const seen = new Set();
    for (let i = 0; i < 12; i++) {
      const found = (await agents(cookie)).find((a) => a.agentId === agentId);
      seen.add(found ? found.connection : "missing");
      await sleep(1000);
    }
    check("agent stays online while idle", seen.size === 1 && seen.has("online"), [...seen].join(","));

    const saved = JSON.parse(fs.readFileSync(path.join(dataDir, "agent-state.json"), "utf8"));
    check("agent has a per-install identity", /^[a-f0-9]{32}$/.test(saved.InstallId || ""), saved.InstallId);

    // Restart the manager the way systemd does.
    portal.kill("SIGTERM");
    await new Promise((done) => portal.once("exit", done));
    await sleep(4000);
    portal = startPortal();
    check("portal restarts", await waitForPortal());
    cookie = await signInAgain();

    const during = (await agents(cookie)).find((a) => a.agentId === agentId);
    check("dashboard says reconnecting, not disconnected, right after the restart",
      Boolean(during) && ["reconnecting", "online"].includes(during.connection), during ? during.connection : "missing");

    const back = await waitOnline(cookie, agentId, 90000);
    check("agent reconnects by itself after the manager restart", Boolean(back), back ? back.connection : "still offline");

    const list = await agents(cookie);
    check("no duplicate registration after reconnecting", list.length === 1 && list[0].agentId === agentId, `${list.length} record(s)`);
    const after = JSON.parse(fs.readFileSync(path.join(dataDir, "agent-state.json"), "utf8"));
    check("agent kept its identity and credential", after.AgentId === agentId && after.InstallId === saved.InstallId && after.ProtectedApiKey === saved.ProtectedApiKey);
    check("agent did not enrol again", !/Registered as agent/.test(agentLog.join("")));
  } catch (error) {
    check("test ran without crashing", false, error.message);
  } finally {
    if (agent) { agent.kill("SIGKILL"); }
    portal.kill("SIGKILL");
    const failed = results.filter((r) => !r.ok).length;
    if (failed || process.argv.includes("--logs")) {
      console.log("\n--- agent ---\n" + agentLog.join("").slice(-4000));
      console.log("\n--- portal ---\n" + portalLog.join("").slice(-3000));
    }
    pki.cleanup();
    fs.rmSync(STATE, { recursive: true, force: true });
  }
  return results;
}

// Needs the agent build (`dotnet build -c Release`); skipped when it is not present.
test("the real agent stays connected and recovers from a manager restart without re-registering", {
  skip: fs.existsSync(path.join(BUILD_DIR, "uAgent.dll")) ? false : "uAgent.dll has not been built",
  timeout: 300000
}, async () => {
  const results = await run();
  const failed = results.filter((r) => !r.ok);
  assert.equal(failed.length, 0, failed.map((r) => `${r.name}: ${r.detail || ""}`).join("; "));
});
