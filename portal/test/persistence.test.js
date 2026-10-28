"use strict";

// Portal state on disk: schema upgrade from 1.4 with a copy kept for rollback, and steady heartbeats
// that no longer rewrite the whole state file every few seconds.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const Store = require("../lib/store");

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "uagent-persist-"));
}

test("a 1.4 state file is upgraded, the original is kept, and nothing is lost", () => {
  const dir = tempDir();
  const file = path.join(dir, "state.json");
  const legacyAgent = {
    agentId: "legacy-1", agentNumber: 7, machineName: "PC-0142", domainName: "corp.example.com", dnsName: "pc-0142.corp.example.com",
    apiKeyHash: "0".repeat(64), status: "Active", communication: [], lastHeartbeatUtc: new Date().toISOString(), lastContactUtc: new Date().toISOString()
  };
  const audit = [{ id: "x", timestampUtc: new Date().toISOString(), user: "admin", agentId: "legacy-1", action: "Enroll", result: "Active", details: "", remoteIp: "" }];
  fs.writeFileSync(file, JSON.stringify({ nextAgentNumber: 8, agents: [["legacy-1", legacyAgent]], reports: [], pending: [], history: [], audit, downloads: [], issues: [] }));

  const store = new Store(60000);
  store.attachPersistence(file);
  clearInterval(store._timer);
  assert.strictEqual(store.agents.get("legacy-1").installId, "", "new field defaulted");
  assert.strictEqual(store.nextAgentNumber, 8);
  assert.strictEqual(store.audit.length, 1, "audit kept");
  store.flush();
  const saved = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.strictEqual(saved.schemaVersion, 2);
  const copies = fs.readdirSync(dir).filter((name) => /schema1-.*\.bak$/.test(name));
  assert.strictEqual(copies.length, 1, "the 1.4 file was copied aside before the upgrade");
  assert.ok(!("schemaVersion" in JSON.parse(fs.readFileSync(path.join(dir, copies[0]), "utf8"))), "the copy is the untouched original");

  // Loading the upgraded file again changes nothing and makes no further copies.
  const again = new Store(60000);
  again.attachPersistence(file);
  clearInterval(again._timer);
  assert.strictEqual(again.agents.size, 1);
  assert.strictEqual(fs.readdirSync(dir).filter((name) => name.endsWith(".bak")).length, 1);
});

test("steady heartbeats do not rewrite the state file; real changes and shutdown do", () => {
  const dir = tempDir();
  const store = new Store(60000);
  store.attachPersistence(path.join(dir, "state.json"));
  clearInterval(store._timer);
  const agent = store.enrollAgent({ machineName: "PC-0142", installId: "a".repeat(32) }, "192.0.2.10");
  store.upsertHeartbeat(agent.agentId, { machineName: "PC-0142", agentVersion: "1.5.0" }, "192.0.2.10");
  store.flush();
  const mtime = () => fs.statSync(path.join(dir, "state.json")).mtimeMs;
  const first = mtime();
  for (let i = 0; i < 10; i++) {
    store.upsertHeartbeat(agent.agentId, { machineName: "PC-0142", agentVersion: "1.5.0" }, "192.0.2.10");
    store.flush();
  }
  assert.strictEqual(mtime(), first, "no rewrite for heartbeats that repeat stored values");
  store.upsertHeartbeat(agent.agentId, { machineName: "PC-0142", agentVersion: "1.5.1" }, "192.0.2.10");
  store.flush();
  assert.ok(JSON.parse(fs.readFileSync(path.join(dir, "state.json"), "utf8")).agents[0][1].agentVersion === "1.5.1", "a version change is saved at once");
  store.upsertHeartbeat(agent.agentId, { machineName: "PC-0142", agentVersion: "1.5.1" }, "192.0.2.10");
  const contact = store.agents.get(agent.agentId).lastContactUtc;
  store.flush(true);
  assert.strictEqual(JSON.parse(fs.readFileSync(path.join(dir, "state.json"), "utf8")).agents[0][1].lastContactUtc, contact, "shutdown saves the latest contact time");
});
