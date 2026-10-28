"use strict";

// Registration identity. Two computers with the same host name used to take each other's registration
// over on every enrollment, revoking the other's credential, so both disconnected continuously.
const test = require("node:test");
const assert = require("node:assert");
const Store = require("../lib/store");

const WINDOW = 60000;
const host = { machineName: "PC-0142", domainName: "corp.example.com", dnsName: "pc-0142.corp.example.com", osVersion: "Windows 11", agentVersion: "1.5.0" };
const A = "a".repeat(32);
const B = "b".repeat(32);

function enroll(store, extra) {
  return store.enrollAgent(Object.assign({}, host, extra), "192.0.2.10");
}

function heartbeat(store, enrollment, extra) {
  assert.ok(store.authenticateAgent(enrollment.agentId, enrollment.apiKey).ok, "credential accepted");
  store.upsertHeartbeat(enrollment.agentId, Object.assign({ machineName: host.machineName, agentVersion: "1.5.0" }, extra), "192.0.2.10");
}

test("two connected computers with the same name keep separate registrations", () => {
  const store = new Store(WINDOW);
  const first = enroll(store, { installId: A });
  heartbeat(store, first);
  const second = enroll(store, { installId: B });
  assert.notStrictEqual(second.agentId, first.agentId, "the second computer gets its own record");
  assert.ok(store.authenticateAgent(first.agentId, first.apiKey).ok, "the first computer's credential still works");
  heartbeat(store, second);

  // The old behaviour: each re-registration revoked the other. Neither may happen now.
  for (let i = 0; i < 5; i++) {
    assert.ok(store.authenticateAgent(first.agentId, first.apiKey).ok);
    assert.ok(store.authenticateAgent(second.agentId, second.apiKey).ok);
  }
  assert.strictEqual(store.listAgents().length, 2);
  assert.ok(store.issues.some((issue) => /Two computers named PC-0142/.test(issue.detail)), "the clash is reported");
});

test("the same installation re-registering keeps its record", () => {
  const store = new Store(WINDOW);
  const first = enroll(store, { installId: A });
  heartbeat(store, first);
  const again = enroll(store, { installId: A, previousAgentId: first.agentId });
  assert.strictEqual(again.agentId, first.agentId);
  assert.strictEqual(again.displayId, first.displayId);
  assert.ok(!store.authenticateAgent(first.agentId, first.apiKey).ok, "the old credential is replaced");
  assert.ok(store.authenticateAgent(again.agentId, again.apiKey).ok);
  assert.strictEqual(store.listAgents().length, 1);
});

test("a re-imaged computer takes over its old record once that record is no longer connected", () => {
  const store = new Store(WINDOW);
  const old = enroll(store, { installId: A });
  heartbeat(store, old);
  const record = store.agents.get(old.agentId);
  record.lastContactUtc = new Date(Date.now() - 10 * 60000).toISOString();
  const fresh = enroll(store, { installId: B });
  assert.strictEqual(fresh.agentId, old.agentId, "the stale record is reused");
  assert.strictEqual(store.agents.get(fresh.agentId).installId, B);
  assert.strictEqual(store.listAgents().length, 1);
});

test("an agent from before 1.5 learns its installation id from the heartbeat", () => {
  const store = new Store(WINDOW);
  const legacy = enroll(store, {});
  heartbeat(store, legacy, { installId: A });
  assert.strictEqual(store.agents.get(legacy.agentId).installId, A);
  // A legacy duplicate that is not connected is still collapsed into one row, as before.
  store.agents.get(legacy.agentId).lastContactUtc = new Date(Date.now() - 10 * 60000).toISOString();
  const again = enroll(store, {});
  assert.strictEqual(again.agentId, legacy.agentId);
});

test("a connected record without an installation id is not taken over by another computer", () => {
  const store = new Store(WINDOW);
  const legacy = enroll(store, {});
  heartbeat(store, legacy);
  const other = enroll(store, {});
  assert.notStrictEqual(other.agentId, legacy.agentId);
  assert.ok(store.authenticateAgent(legacy.agentId, legacy.apiKey).ok);
});

test("connection state distinguishes online, reconnecting, disconnected and stale", () => {
  const store = new Store(WINDOW, { staleAfterMs: 24 * 3600000 });
  const agent = enroll(store, { installId: A });
  heartbeat(store, agent);
  const record = store.agents.get(agent.agentId);
  const ago = (ms) => { record.lastContactUtc = new Date(Date.now() - ms).toISOString(); return store._connection(record); };
  assert.strictEqual(ago(10000), "online");
  assert.strictEqual(ago(2 * 60000), "reconnecting", "inside the longest retry backoff");
  assert.strictEqual(ago(30 * 60000), "disconnected");
  assert.strictEqual(ago(25 * 3600000), "stale");
  store.pollOpened(agent.agentId, "192.0.2.10");
  ago(30 * 60000);
  assert.strictEqual(store._connection(record), "online", "an open long poll is online whatever the last contact");
  store.pollClosed(agent.agentId);
  record.lastContactUtc = new Date(Date.now() - 2 * 60000).toISOString();
  record.serviceStoppedUtc = new Date().toISOString();
  assert.strictEqual(store._connection(record), "disconnected", "a reported service stop is not reconnecting");
  const summary = store.getSummary();
  assert.strictEqual(summary.disconnectedAgents, 1);
  assert.ok("reconnectingAgents" in summary && "staleAgents" in summary);
});

test("moving between states by time alone is broadcast to the live view", async () => {
  const store = new Store(WINDOW);
  const agent = enroll(store, { installId: A });
  heartbeat(store, agent);
  store.sweepPresence();
  const record = store.agents.get(agent.agentId);
  record.lastContactUtc = new Date(Date.now() - 2 * 60000).toISOString();
  store.sweepPresence();
  const batches = [];
  store.events.on("batch", (batch) => batches.push(batch));
  record.lastContactUtc = new Date(Date.now() - 30 * 60000).toISOString();
  store.sweepPresence();
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.ok(batches.flat().some((event) => event.type === "agent" && event.agentId === agent.agentId), "reconnecting to disconnected emits an update");
});

test("restart de-duplication keeps different installations apart", () => {
  const store = new Store(WINDOW);
  const first = enroll(store, { installId: A });
  heartbeat(store, first);
  enroll(store, { installId: B });
  store._collapseAll();
  assert.strictEqual(store.listAgents().length, 2);
});

test("a newer computer's heartbeat does not delete a connected older computer with the same name", () => {
  const store = new Store(WINDOW);
  const legacy = enroll(store, { agentVersion: "1.4.0" });
  heartbeat(store, legacy, { agentVersion: "1.4.0" });
  const modern = enroll(store, { installId: B });
  assert.notStrictEqual(modern.agentId, legacy.agentId);
  heartbeat(store, modern, { installId: B, osVersion: "Windows 11 24H2" });
  heartbeat(store, legacy, { agentVersion: "1.4.0", osVersion: "Windows 10" });
  heartbeat(store, modern, { installId: B, osVersion: "Windows 11 25H2" });
  assert.strictEqual(store.listAgents().length, 2, "both records survive");
  assert.ok(store.authenticateAgent(legacy.agentId, legacy.apiKey).ok);
  assert.ok(store.authenticateAgent(modern.agentId, modern.apiKey).ok);
});

test("clearing records keeps agents whose uninstall is on its way, and an audit-only clear keeps agents", () => {
  const store = new Store(WINDOW);
  const leaving = enroll(store, { installId: A, machineName: "PC-0150" });
  const staying = enroll(store, { installId: B, machineName: "PC-0151" });
  store.requestRemoval(leaving.agentId, { name: "admin", role: "Administrator" }, "Destroy");
  store.addAudit({ user: "admin", action: "Test", result: "Success", details: "x" });

  store.resetData({ keepAudit: false, keepAgents: true });
  assert.strictEqual(store.listAgents().length, 2, "an audit-only clear leaves agents alone");
  assert.strictEqual(store.audit.length, 0);

  store.resetData({ keepAudit: true, keepRemovals: true });
  const left = store.listAgents();
  assert.deepStrictEqual(left.map((agent) => agent.agentId), [leaving.agentId], "only the agent being uninstalled is kept");
  assert.ok(!store.agents.has(staying.agentId));
  const queued = store.takePendingCommands(leaving.agentId, "192.0.2.10");
  const list = Array.isArray(queued) ? queued : (queued.commands || []);
  assert.ok(list.some((command) => command.commandType === "UninstallAgent"), "the uninstall still reaches the computer");
});
