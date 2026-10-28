"use strict";

// A server that is not the manager must not be able to redirect an agent, even with a certificate from a
// CA the agent trusts.
//
//   The agent is configured with an IP address. The server at that address presents a certificate, from the
//   trusted CA, for "localhost" only, so the agent considers "localhost" as a recovery address. Behind it
//   is an impostor that answers every request with success and forges the identity proof.
//
// Expected: the agent refuses the impostor's proof, never sends its credential, and keeps its address.
const test = require("node:test");
const assert = require("node:assert");
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const https = require("https");
const os = require("os");
const path = require("path");
const { buildPki } = require("./helpers/pki");

const ROOT = path.resolve(__dirname, "../..");
const PORT = 18447;
const STATE = path.join(os.tmpdir(), "uagent-spoofing-state");
const BUILD_DIR = path.join(ROOT, "uAgent.Agent/bin/Release/net8.0");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test("an impostor with a trusted certificate cannot redirect the agent or obtain its key", {
  skip: fs.existsSync(path.join(BUILD_DIR, "uAgent.dll")) ? false : "uAgent.dll has not been built",
  timeout: 180000
}, async () => {
  const pki = buildPki({ host: "localhost", names: ["DNS:localhost"] });
  fs.rmSync(STATE, { recursive: true, force: true });
  const agentDir = path.join(STATE, "agent");
  fs.cpSync(BUILD_DIR, agentDir, { recursive: true, filter: (src) => path.basename(src) !== "data" });

  const apiKey = crypto.randomBytes(24).toString("base64url");
  const seen = { keyed: [], proofs: 0, paths: [] };
  const impostor = https.createServer({
    cert: [pki.pem("leaf.crt"), pki.pem("issuing.crt")].join("\n"),
    key: fs.readFileSync(pki.file("leaf.key"))
  }, (req, res) => {
    seen.paths.push(`${req.method} ${req.url}`);
    if (req.headers["x-api-key"]) { seen.keyed.push(req.url); }
    if (req.url.endsWith("/manager-proof")) {
      seen.proofs++;
      res.setHeader("Content-Type", "application/json");
      return res.end(JSON.stringify({ hosts: ["localhost"], proofs: [crypto.randomBytes(32).toString("hex")] }));
    }
    // Looks like a portal to every unauthenticated check, and accepts any credential.
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ ok: true, status: "ok", agentId: "a1", downloadPath: "/download/agent" }));
  });
  await new Promise((done) => impostor.listen(PORT, done));

  const dataDir = path.join(agentDir, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(path.join(dataDir, "agent-state.json"), JSON.stringify({
    AgentId: "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    DisplayId: "AGT-0001",
    ProtectedApiKey: "plain:" + Buffer.from(apiKey).toString("base64"),
    ManagerUrl: `https://127.0.0.1:${PORT}`,
    CaCertificate: pki.pem("root.crt"),
    Status: "Active"
  }, null, 2));

  const log = [];
  const agent = spawn("dotnet", [path.join(agentDir, "uAgent.dll"), "/run"], {
    cwd: agentDir,
    env: Object.assign({}, process.env, { DOTNET_ENVIRONMENT: "Production", DOTNET_ROLL_FORWARD: "LatestMajor" }),
    stdio: ["ignore", "pipe", "pipe"]
  });
  agent.stdout.on("data", (d) => log.push(d.toString()));
  agent.stderr.on("data", (d) => log.push(d.toString()));
  try {
    const end = Date.now() + 90000;
    while (Date.now() < end && !/could not prove it is this agent's manager/.test(log.join(""))) {
      await sleep(500);
    }
    await sleep(2000);
    const text = log.join("");
    assert.match(text, /could not prove it is this agent's manager/, `agent output:\n${text.slice(-3000)}`);
    assert.ok(seen.proofs >= 1, "the agent asked the candidate to prove itself");
    assert.deepEqual(seen.keyed, [], "the agent key must never reach the impostor");
    assert.doesNotMatch(text, /manager address was corrected/);
    const saved = JSON.parse(fs.readFileSync(path.join(dataDir, "agent-state.json"), "utf8"));
    assert.equal(saved.ManagerUrl, `https://127.0.0.1:${PORT}`);
  } finally {
    agent.kill("SIGKILL");
    impostor.close();
    pki.cleanup();
    fs.rmSync(STATE, { recursive: true, force: true });
  }
});
