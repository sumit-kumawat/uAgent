"use strict";

// Deployment engine: turns a job (a package or an agent action plus a target list) into per-system
// work, dispatched through the existing authenticated agent command channel. It enforces staged waves,
// global and per-site concurrency, scheduling, maintenance windows, failure thresholds, bounded retries
// and offline deadlines. A single scheduler tick decides what to dispatch next, so the same logic scales
// from one system to tens of thousands without a thread per target.
const crypto = require("crypto");
const { writeJson, readJson } = require("./statePath");

const TERMINAL_JOB = new Set(["Completed", "Cancelled"]);
const TERMINAL_TARGET = new Set(["Succeeded", "Failed", "Skipped", "Cancelled"]);
const DONE_OUTCOMES = new Set(["Installed", "AlreadyInstalled", "UpToDate", "Verified"]);
const RETRYABLE_OUTCOMES = new Set(["Busy", "DownloadFailed"]);

class EngineError extends Error {
  constructor(message, status, code, field) {
    super(message);
    this.status = status || 400;
    this.code = code || "invalid";
    this.field = field;
  }
}

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? Math.min(Math.max(n, min), max) : fallback;
}

function normalizeOptions(input, defaults) {
  const o = input || {};
  const window = o.maintenanceWindow || {};
  const days = Array.isArray(window.days) ? [...new Set(window.days.map((d) => Number.parseInt(d, 10)).filter((d) => d >= 0 && d <= 6))] : [];
  const time = (value, fallback) => (/^([01]\d|2[0-3]):[0-5]\d$/.test(String(value)) ? String(value) : fallback);
  let startAt = null;
  if (o.startAt) {
    const when = new Date(o.startAt);
    if (Number.isNaN(when.getTime())) {
      throw new EngineError("The scheduled start time is not a valid date.", 400, "invalid", "options.startAt");
    }
    startAt = when.toISOString();
  }
  return {
    pilotCount: clampInt(o.pilotCount, 0, 1000000, 0),
    waveSize: clampInt(o.waveSize, 0, 1000000, 0),
    autoAdvance: o.autoAdvance !== false,
    waveDelayMinutes: clampInt(o.waveDelayMinutes, 0, 10080, 0),
    maxConcurrent: clampInt(o.maxConcurrent, 1, 5000, defaults.maxConcurrent),
    perSiteConcurrent: clampInt(o.perSiteConcurrent, 1, 5000, defaults.perSiteConcurrent),
    failureThresholdPercent: clampInt(o.failureThresholdPercent, 0, 100, 0),
    failureMinSample: clampInt(o.failureMinSample, 1, 1000000, 10),
    onThreshold: o.onThreshold === "cancel" ? "cancel" : "pause",
    maxAttempts: clampInt(o.maxAttempts, 1, 10, defaults.defaultMaxAttempts),
    retryDelayMinutes: clampInt(o.retryDelayMinutes, 0, 10080, 10),
    startAt,
    maintenanceWindow: { enabled: Boolean(window.enabled), days, start: time(window.start, "00:00"), end: time(window.end, "06:00") },
    offlineDeadlineHours: clampInt(o.offlineDeadlineHours, 0, 8760, 72),
    restartBehavior: ["never", "ifRequired"].includes(o.restartBehavior) ? o.restartBehavior : "package",
    force: Boolean(o.force)
  };
}

function inMaintenanceWindow(window, now) {
  if (!window.enabled) {
    return true;
  }
  const day = now.getDay();
  if (window.days.length && !window.days.includes(day)) {
    return false;
  }
  const minutes = now.getHours() * 60 + now.getMinutes();
  const [sh, sm] = window.start.split(":").map(Number);
  const [eh, em] = window.end.split(":").map(Number);
  const start = sh * 60 + sm;
  const end = eh * 60 + em;
  return start <= end ? minutes >= start && minutes < end : minutes >= start || minutes < end;
}

function versionAtLeast(current, target) {
  const a = String(current || "").split(".").map((n) => Number.parseInt(n, 10) || 0);
  const b = String(target || "").split(".").map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    if ((a[i] || 0) !== (b[i] || 0)) {
      return (a[i] || 0) > (b[i] || 0);
    }
  }
  return true;
}

function createDeploymentEngine({ store, targets, library, vault, logger, stateFileName, onDispatch, agentVersion }) {
  const jobs = new Map();
  const saved = readJson(stateFileName);
  if (saved && Array.isArray(saved.jobs)) {
    for (const job of saved.jobs) {
      jobs.set(job.id, job);
    }
  }
  // commandId -> { jobId, agentId } for routing agent results and progress back to a target.
  const commandIndex = new Map();
  rebuildIndex();
  let dirty = false;

  function rebuildIndex() {
    commandIndex.clear();
    for (const job of jobs.values()) {
      for (const target of job.targets) {
        if (target.commandId) {
          commandIndex.set(target.commandId, { jobId: job.id, agentId: target.agentId });
        }
      }
    }
  }

  const changed = new Set();
  let lastWrite = 0;

  function mark(job) {
    dirty = true;
    if (job) {
      changed.add(job.id);
    }
  }

  // Browsers hear about changed jobs immediately; the state file is rewritten at most once a second
  // so a burst of agent progress updates does not turn into a burst of disk writes.
  function persist(force) {
    for (const jobId of changed) {
      store._emit("deployment", { jobId });
    }
    changed.clear();
    if (!dirty || (!force && Date.now() - lastWrite < 1000)) {
      return;
    }
    writeJson(stateFileName, { jobs: [...jobs.values()] });
    dirty = false;
    lastWrite = Date.now();
  }

  // --- Job creation ---------------------------------------------------------------------------

  function assignWaves(targetIds, options) {
    const waves = [];
    let index = 0;
    if (options.pilotCount > 0) {
      waves.push(targetIds.slice(0, options.pilotCount));
      index = options.pilotCount;
    }
    const size = options.waveSize > 0 ? options.waveSize : targetIds.length - index;
    while (index < targetIds.length) {
      waves.push(targetIds.slice(index, index + (size || targetIds.length)));
      index += size || targetIds.length;
    }
    return waves.length ? waves : [[]];
  }

  function eligibility(kind, agent, packageRecord, action, force) {
    if (!agent) {
      return { ok: false, reason: "The agent is no longer registered." };
    }
    if (agent.status !== "Active") {
      return { ok: false, reason: "The agent is not approved." };
    }
    if (kind === "software") {
      if (!targets.capable(agent)) {
        return { ok: false, reason: "The agent version does not support software installation." };
      }
      return { ok: true };
    }
    if (action === "upgrade" || action === "repair") {
      return { ok: true };
    }
    return { ok: false, reason: "Unsupported agent action." };
  }

  function createJob(input, user) {
    const kind = input.kind === "agent" ? "agent" : "software";
    const defaults = targets.getSettings();
    const options = normalizeOptions(input.options, defaults);
    const name = String(input.name || "").trim().slice(0, 120);
    if (!name) {
      throw new EngineError("Enter a name for this deployment.", 400, "invalid", "name");
    }
    let packageRecord = null;
    let action = null;
    if (kind === "software") {
      packageRecord = library.raw(input.packageId);
      if (!packageRecord) {
        throw new EngineError("Select a package to deploy.", 400, "invalid", "packageId");
      }
      if (packageRecord.status !== "Approved") {
        throw new EngineError("Only an approved package can be deployed.", 409, "not_approved");
      }
      const missing = vault.missing(packageRecord.install.arguments);
      if (missing.length) {
        throw new EngineError(`The package references vault secrets that no longer exist: ${missing.join(", ")}.`, 400, "invalid");
      }
    } else {
      action = input.action === "repair" ? "repair" : "upgrade";
    }

    const resolved = targets.resolve(input.selector);
    const targetRows = [];
    const skipped = {};
    for (const agentId of resolved.agentIds) {
      const agent = store.agents.get(agentId);
      const check = eligibility(kind, agent, packageRecord, action, options.force);
      if (!check.ok) {
        skipped[check.reason] = (skipped[check.reason] || 0) + 1;
        continue;
      }
      const row = {
        agentId,
        displayId: store.getDisplayId(agentId),
        machineName: agent.machineName || "",
        site: targets.siteOf(agent),
        wave: 0,
        state: "Pending",
        stage: "",
        percent: null,
        attempts: 0,
        exitCode: null,
        rebootRequired: false,
        outcome: "",
        message: "",
        commandId: null,
        updatedUtc: new Date().toISOString(),
        nextAttemptUtc: null,
        dispatchedUtc: null,
        history: []
      };
      // An agent already on the published build needs no upgrade; record it instead of reinstalling.
      const published = action === "upgrade" && typeof agentVersion === "function" ? agentVersion() : "";
      if (published && !options.force && agent.agentVersion && versionAtLeast(agent.agentVersion, published)) {
        row.state = "Skipped";
        row.outcome = "UpToDate";
        row.message = `Already on version ${agent.agentVersion}.`;
        row.history.push({ utc: row.updatedUtc, state: "Skipped", message: row.message });
      }
      targetRows.push(row);
    }
    if (targetRows.length === 0) {
      throw new EngineError("No eligible systems are in the selected targets.", 400, "no_targets");
    }

    const waves = assignWaves(targetRows.map((t) => t.agentId), options);
    const waveByAgent = new Map();
    waves.forEach((wave, index) => wave.forEach((agentId) => waveByAgent.set(agentId, index)));
    for (const target of targetRows) {
      target.wave = waveByAgent.get(target.agentId) || 0;
    }

    const now = new Date().toISOString();
    const job = {
      id: crypto.randomUUID(),
      kind,
      name,
      packageId: packageRecord ? packageRecord.id : null,
      packageName: packageRecord ? packageRecord.name : "",
      packageVersion: packageRecord ? packageRecord.version : "",
      action,
      status: options.startAt ? "Scheduled" : "Running",
      statusReason: "",
      createdBy: user.name,
      createdUtc: now,
      startedUtc: options.startAt ? null : now,
      completedUtc: null,
      startAt: options.startAt,
      currentWave: 0,
      waveCount: waves.length,
      nextWaveAtUtc: null,
      options,
      targets: targetRows,
      timeline: []
    };
    addEvent(job, user.name, "Created", `${targetRows.length} target(s) in ${waves.length} wave(s).${Object.keys(skipped).length ? ` Skipped ${Object.values(skipped).reduce((a, b) => a + b, 0)} at creation.` : ""}`);
    jobs.set(job.id, job);
    mark(job);
    store.addAudit({
      user: user.name,
      action: kind === "software" ? "SoftwareDeployment" : "AgentDeployment",
      result: "Pending",
      details: `${name}: ${kind === "software" ? `${job.packageName} ${job.packageVersion}` : action} to ${targetRows.length} system(s)${options.startAt ? `, scheduled for ${options.startAt}` : ""}.`
    });
    logger(`${user.name} created ${kind} deployment "${name}" (${job.id}) for ${targetRows.length} system(s).`);
    persist();
    tick();
    return summary(job);
  }

  function addEvent(job, user, event, detail) {
    job.timeline.unshift({ utc: new Date().toISOString(), user, event, detail });
    if (job.timeline.length > 500) {
      job.timeline.length = 500;
    }
  }

  // --- Scheduler ------------------------------------------------------------------------------

  function activeCount(job) {
    let total = 0;
    const perSite = new Map();
    for (const target of job.targets) {
      if (target.state === "Dispatched" || target.state === "Running") {
        total += 1;
        perSite.set(target.site, (perSite.get(target.site) || 0) + 1);
      }
    }
    return { total, perSite };
  }

  function globalActive() {
    let total = 0;
    const perSite = new Map();
    for (const job of jobs.values()) {
      if (TERMINAL_JOB.has(job.status)) {
        continue;
      }
      for (const target of job.targets) {
        if (target.state === "Dispatched" || target.state === "Running") {
          total += 1;
          perSite.set(target.site, (perSite.get(target.site) || 0) + 1);
        }
      }
    }
    return { total, perSite };
  }

  function waveComplete(job, wave) {
    return job.targets.every((t) => t.wave !== wave || TERMINAL_TARGET.has(t.state) || t.state === "Offline" && isOfflineExpired(job, t));
  }

  function waveSettled(job, wave) {
    return job.targets.every((t) => t.wave !== wave || TERMINAL_TARGET.has(t.state));
  }

  function isOfflineExpired(job, target) {
    if (!job.options.offlineDeadlineHours) {
      return false;
    }
    const since = Date.parse(target.firstOfflineUtc || target.updatedUtc);
    return Date.now() - since > job.options.offlineDeadlineHours * 3600 * 1000;
  }

  function checkThreshold(job) {
    if (!job.options.failureThresholdPercent) {
      return;
    }
    let failed = 0;
    let settled = 0;
    for (const target of job.targets) {
      if (TERMINAL_TARGET.has(target.state)) {
        settled += 1;
        if (target.state === "Failed") {
          failed += 1;
        }
      }
    }
    if (settled >= job.options.failureMinSample && (failed / settled) * 100 >= job.options.failureThresholdPercent) {
      const reason = `Failure rate ${Math.round((failed / settled) * 100)}% reached the ${job.options.failureThresholdPercent}% threshold after ${settled} result(s).`;
      if (job.options.onThreshold === "cancel") {
        cancelInternal(job, "system", reason);
      } else if (job.status === "Running") {
        job.status = "Paused";
        job.statusReason = reason;
        addEvent(job, "system", "Paused", reason);
        store.addAudit({ user: "system", action: "DeploymentPaused", result: "Paused", details: `${job.name}: ${reason}` });
        logger(`Deployment "${job.name}" paused automatically: ${reason}`);
      }
      mark(job);
    }
  }

  function buildDeploymentSpec(job, packageRecord, target) {
    const resolved = vault.resolve(packageRecord.install.arguments);
    const install = packageRecord.install;
    return {
      spec: {
        deploymentId: job.id,
        packageId: packageRecord.id,
        packageName: packageRecord.name,
        packageVersion: packageRecord.version,
        installerType: packageRecord.installerType,
        fileName: packageRecord.fileName,
        sha256: packageRecord.sha256,
        size: packageRecord.size,
        downloadUrl: `api/agents/${target.agentId}/packages/${packageRecord.id}`,
        arguments: resolved.text,
        timeoutSeconds: install.timeoutMinutes * 60,
        successExitCodes: install.successExitCodes,
        rebootExitCodes: install.rebootExitCodes,
        retryExitCodes: install.retryExitCodes,
        requireSignature: install.requireSignature,
        expectedSigner: install.expectedSigner,
        scanWithDefender: install.scanWithDefender,
        detection: install.detection,
        prerequisites: install.prerequisites,
        restartBehavior: job.options.restartBehavior && job.options.restartBehavior !== "package" ? job.options.restartBehavior : install.restartBehavior,
        restartDelayMinutes: install.restartDelayMinutes,
        attempt: target.attempts + 1,
        force: Boolean(job.options.force),
        redactions: resolved.redactions
      },
      redactions: resolved.redactions
    };
  }

  function dispatch(job, target) {
    const agent = store.agents.get(target.agentId);
    if (!agent) {
      finishTarget(job, target, "Skipped", "", "The agent is no longer registered.", { success: false });
      return;
    }
    target.attempts += 1;
    const online = store.isOnline(target.agentId);
    try {
      if (job.kind === "software") {
        const packageRecord = library.raw(job.packageId);
        if (!packageRecord) {
          finishTarget(job, target, "Skipped", "", "The package was removed from the library.", { success: false });
          return;
        }
        const built = buildDeploymentSpec(job, packageRecord, target);
        const command = onDispatch.software(target.agentId, built.spec, { jobId: job.id, name: job.name, user: job.createdBy });
        target.commandId = command.commandId;
        target.redactions = built.redactions;
      } else {
        const command = onDispatch.agentAction(target.agentId, job.action, { jobId: job.id, name: job.name, user: job.createdBy });
        target.commandId = command.commandId;
      }
    } catch (error) {
      target.attempts -= 1;
      logger(`Could not dispatch deployment "${job.name}" to ${target.displayId}: ${error.message}`);
      scheduleRetry(job, target, `The portal could not queue the command: ${error.message}`);
      return;
    }
    commandIndex.set(target.commandId, { jobId: job.id, agentId: target.agentId });
    target.state = online ? "Dispatched" : "Offline";
    target.stage = online ? "Queued" : "";
    target.percent = null;
    target.dispatchedUtc = new Date().toISOString();
    if (!online && !target.firstOfflineUtc) {
      target.firstOfflineUtc = target.dispatchedUtc;
    }
    target.updatedUtc = target.dispatchedUtc;
    pushHistory(target, target.state, online ? "Queued for the agent." : "Queued; the agent is offline and will run it when it reconnects.");
    mark(job);
  }

  function pushHistory(target, state, message) {
    target.history.unshift({ utc: new Date().toISOString(), state, message });
    if (target.history.length > 60) {
      target.history.length = 60;
    }
  }

  function scheduleRetry(job, target, message) {
    if (target.attempts >= job.options.maxAttempts) {
      finishTarget(job, target, "Failed", target.outcome || "Failed", message, { success: false });
      return;
    }
    target.state = "Waiting";
    target.stage = "";
    target.commandId = null;
    target.nextAttemptUtc = new Date(Date.now() + job.options.retryDelayMinutes * 60 * 1000).toISOString();
    target.updatedUtc = new Date().toISOString();
    pushHistory(target, "Waiting", `${message} Retrying attempt ${target.attempts + 1} of ${job.options.maxAttempts} after ${job.options.retryDelayMinutes} minute(s).`);
    mark(job);
  }

  function finishTarget(job, target, state, outcome, message, result) {
    target.state = state;
    target.outcome = outcome || target.outcome;
    target.message = message || target.message;
    if (target.commandId) {
      commandIndex.delete(target.commandId);
    }
    target.commandId = null;
    target.stage = state === "Succeeded" ? "Completed" : "";
    target.percent = state === "Succeeded" ? 100 : target.percent;
    target.nextAttemptUtc = null;
    target.updatedUtc = new Date().toISOString();
    pushHistory(target, state, message || state);
    mark(job);
    checkThreshold(job);
  }

  function readyForWork(job, now) {
    if (job.status === "Scheduled" && job.startAt && Date.parse(job.startAt) <= now.getTime()) {
      job.status = "Running";
      job.startedUtc = new Date().toISOString();
      addEvent(job, "system", "Started", "The scheduled start time was reached.");
      mark(job);
    }
    return job.status === "Running";
  }

  function tick() {
    const now = new Date();
    const global = globalActive();
    const defaults = targets.getSettings();
    const globalLimit = defaults.maxConcurrent;

    for (const job of jobs.values()) {
      if (TERMINAL_JOB.has(job.status)) {
        continue;
      }
      if (!readyForWork(job, now)) {
        continue;
      }
      if (job.nextWaveAtUtc && Date.parse(job.nextWaveAtUtc) <= now.getTime()) {
        job.nextWaveAtUtc = null;
      }

      // Re-evaluate offline targets: expire past the deadline, or dispatch nothing until they return.
      for (const target of job.targets) {
        if (target.state === "Offline") {
          if (isOfflineExpired(job, target)) {
            finishTarget(job, target, "Skipped", "Offline", "The system did not reconnect before the offline deadline.", { success: false });
          } else if (store.isOnline(target.agentId) && !target.commandId) {
            target.state = "Waiting";
            target.updatedUtc = new Date().toISOString();
          }
        }
      }

      const inMaintenance = inMaintenanceWindow(job.options.maintenanceWindow, now);
      const local = activeCount(job);
      let roomGlobal = Math.min(globalLimit, job.options.maxConcurrent) - Math.max(global.total, local.total);

      if (inMaintenance && !job.nextWaveAtUtc) {
        const wave = job.currentWave;
        const candidates = job.targets
          .filter((t) => t.wave === wave && (t.state === "Pending" || t.state === "Waiting"))
          .filter((t) => !t.nextAttemptUtc || Date.parse(t.nextAttemptUtc) <= now.getTime());
        for (const target of candidates) {
          if (roomGlobal <= 0) {
            break;
          }
          const siteActive = local.perSite.get(target.site) || 0;
          const siteGlobal = global.perSite.get(target.site) || 0;
          if (Math.max(siteActive, siteGlobal) >= job.options.perSiteConcurrent) {
            continue;
          }
          if (target.state === "Pending") {
            target.state = "Waiting";
          }
          dispatch(job, target);
          if (target.state === "Dispatched" || target.state === "Running") {
            roomGlobal -= 1;
            local.perSite.set(target.site, (local.perSite.get(target.site) || 0) + 1);
            global.perSite.set(target.site, (global.perSite.get(target.site) || 0) + 1);
            global.total += 1;
          }
        }
      }

      advanceWaves(job, now);
      finalize(job);
    }
    persist();
  }

  function advanceWaves(job, now) {
    if (job.status !== "Running") {
      return;
    }
    if (!waveSettled(job, job.currentWave)) {
      return;
    }
    if (job.currentWave >= job.waveCount - 1) {
      return;
    }
    if (!job.options.autoAdvance) {
      if (job.statusReason !== "Waiting for an administrator to advance to the next wave.") {
        job.statusReason = "Waiting for an administrator to advance to the next wave.";
        addEvent(job, "system", "WavePaused", `Wave ${job.currentWave + 1} finished. Waiting to advance.`);
        mark(job);
      }
      return;
    }
    if (!job.nextWaveAtUtc && job.options.waveDelayMinutes > 0) {
      job.nextWaveAtUtc = new Date(now.getTime() + job.options.waveDelayMinutes * 60 * 1000).toISOString();
      addEvent(job, "system", "WaveDelay", `Wave ${job.currentWave + 1} finished. Next wave starts in ${job.options.waveDelayMinutes} minute(s).`);
      mark(job);
      return;
    }
    if (job.nextWaveAtUtc && Date.parse(job.nextWaveAtUtc) > now.getTime()) {
      return;
    }
    job.currentWave += 1;
    job.nextWaveAtUtc = null;
    addEvent(job, "system", "WaveStarted", `Wave ${job.currentWave + 1} of ${job.waveCount} started.`);
    mark(job);
  }

  function finalize(job) {
    if (TERMINAL_JOB.has(job.status)) {
      return;
    }
    const allSettled = job.targets.every((t) => TERMINAL_TARGET.has(t.state));
    const lastWave = job.currentWave >= job.waveCount - 1;
    if (allSettled && lastWave) {
      job.status = "Completed";
      job.completedUtc = new Date().toISOString();
      job.statusReason = "";
      const c = counts(job);
      addEvent(job, "system", "Completed", `${c.succeeded} succeeded, ${c.failed} failed, ${c.skipped} skipped.`);
      store.addAudit({ user: job.createdBy, action: job.kind === "software" ? "SoftwareDeployment" : "AgentDeployment", result: c.failed ? "Failed" : "Succeeded", details: `${job.name} finished: ${c.succeeded} succeeded, ${c.failed} failed, ${c.skipped} skipped of ${c.total}.` });
      logger(`Deployment "${job.name}" (${job.id}) completed: ${c.succeeded}/${c.total} succeeded, ${c.failed} failed, ${c.skipped} skipped.`);
      mark(job);
    }
  }

  // --- Agent feedback -------------------------------------------------------------------------

  function onProgress(agentId, commandId, progress) {
    const route = commandIndex.get(commandId);
    if (!route || route.agentId !== agentId) {
      return;
    }
    const job = jobs.get(route.jobId);
    const target = job && job.targets.find((t) => t.commandId === commandId);
    if (!target) {
      return;
    }
    if (target.state === "Dispatched" || target.state === "Offline") {
      target.state = "Running";
    }
    target.stage = String(progress.stage || target.stage || "").slice(0, 40);
    target.percent = typeof progress.percent === "number" ? Math.min(Math.max(Math.round(progress.percent), 0), 100) : target.percent;
    if (progress.message) {
      target.message = String(progress.message).slice(0, 500);
    }
    target.updatedUtc = new Date().toISOString();
    mark(job);
    persist();
  }

  function onResult(agentId, result) {
    const route = commandIndex.get(result.commandId);
    if (!route || route.agentId !== agentId) {
      return false;
    }
    const job = jobs.get(route.jobId);
    const target = job && job.targets.find((t) => t.commandId === result.commandId);
    if (!target) {
      return false;
    }
    const outcome = String(result.outcome || (result.success ? "Installed" : "Failed")).slice(0, 40);
    target.outcome = outcome;
    target.exitCode = Number.isInteger(result.exitCode) ? result.exitCode : target.exitCode;
    target.rebootRequired = Boolean(result.rebootRequired);
    const message = String((result.success ? result.message : result.errorMessage) || result.message || result.errorMessage || "").slice(0, 2000);
    target.message = message;
    if (result.log) {
      target.log = String(result.log).slice(0, 16000);
    }
    if (Number.isInteger(result.durationSeconds)) {
      target.durationSeconds = result.durationSeconds;
    }
    target.commandId = null;
    commandIndex.delete(result.commandId);

    if (result.success || DONE_OUTCOMES.has(outcome)) {
      finishTarget(job, target, "Succeeded", outcome, message || "Completed.", result);
    } else if (RETRYABLE_OUTCOMES.has(outcome)) {
      scheduleRetry(job, target, message || `The system reported ${outcome}.`);
    } else {
      finishTarget(job, target, "Failed", outcome, message || "The system reported a failure.", result);
    }
    mark(job);
    persist();
    tick();
    return true;
  }

  // An agent that drops before reporting leaves a Dispatched/Running target; the next tick re-queues it
  // after the delivery times out, bounded by maxAttempts.
  function reclaimStalled() {
    const now = Date.now();
    for (const job of jobs.values()) {
      if (TERMINAL_JOB.has(job.status)) {
        continue;
      }
      for (const target of job.targets) {
        if ((target.state === "Dispatched" || target.state === "Running") && target.dispatchedUtc) {
          const stalledMs = now - Date.parse(target.dispatchedUtc);
          const budget = (job.kind === "software" ? (library.raw(job.packageId)?.install.timeoutMinutes || 60) : 15) * 60 * 1000 + 10 * 60 * 1000;
          if (stalledMs > budget && !store.isOnline(target.agentId)) {
            if (target.commandId) {
              commandIndex.delete(target.commandId);
            }
            scheduleRetry(job, target, "The agent did not report a result in time.");
          }
        }
      }
    }
  }

  // --- Controls -------------------------------------------------------------------------------

  function get(id) {
    const job = jobs.get(id);
    if (!job) {
      throw new EngineError("The deployment was not found.", 404, "not_found");
    }
    return job;
  }

  function pause(id, user, reason) {
    const job = get(id);
    if (TERMINAL_JOB.has(job.status)) {
      throw new EngineError("The deployment has already finished.", 409, "finished");
    }
    job.status = "Paused";
    job.statusReason = String(reason || "").slice(0, 300) || "Paused by an administrator.";
    addEvent(job, user.name, "Paused", job.statusReason);
    store.addAudit({ user: user.name, action: "DeploymentPaused", result: "Paused", details: `${job.name}: ${job.statusReason}` });
    mark(job);
    persist();
    return summary(job);
  }

  function resume(id, user) {
    const job = get(id);
    if (job.status !== "Paused") {
      throw new EngineError("The deployment is not paused.", 409, "not_paused");
    }
    job.status = "Running";
    job.statusReason = "";
    addEvent(job, user.name, "Resumed", "Resumed by an administrator.");
    store.addAudit({ user: user.name, action: "DeploymentResumed", result: "Running", details: `${job.name} resumed.` });
    mark(job);
    tick();
    return summary(get(id));
  }

  function cancelInternal(job, user, reason) {
    job.status = "Cancelled";
    job.statusReason = String(reason || "").slice(0, 300) || "Cancelled.";
    job.completedUtc = new Date().toISOString();
    for (const target of job.targets) {
      if (!TERMINAL_TARGET.has(target.state)) {
        if (target.commandId) {
          commandIndex.delete(target.commandId);
          target.commandId = null;
        }
        target.state = "Cancelled";
        target.updatedUtc = job.completedUtc;
        pushHistory(target, "Cancelled", "The deployment was cancelled.");
      }
    }
    addEvent(job, user, "Cancelled", job.statusReason);
    mark(job);
  }

  function cancel(id, user, reason) {
    const job = get(id);
    if (TERMINAL_JOB.has(job.status)) {
      throw new EngineError("The deployment has already finished.", 409, "finished");
    }
    cancelInternal(job, user.name, reason || "Cancelled by an administrator.");
    store.addAudit({ user: user.name, action: "DeploymentCancelled", result: "Cancelled", details: `${job.name}: ${job.statusReason}` });
    logger(`${user.name} cancelled deployment "${job.name}" (${job.id}).`);
    persist();
    return summary(job);
  }

  function advance(id, user) {
    const job = get(id);
    if (job.status === "Paused") {
      job.status = "Running";
      job.statusReason = "";
    }
    if (job.status !== "Running") {
      throw new EngineError("The deployment is not running.", 409, "not_running");
    }
    if (!waveSettled(job, job.currentWave)) {
      throw new EngineError("The current wave is still running.", 409, "wave_active");
    }
    if (job.currentWave >= job.waveCount - 1) {
      throw new EngineError("This is the last wave.", 409, "last_wave");
    }
    job.currentWave += 1;
    job.nextWaveAtUtc = null;
    addEvent(job, user.name, "WaveStarted", `Wave ${job.currentWave + 1} of ${job.waveCount} started by an administrator.`);
    store.addAudit({ user: user.name, action: "DeploymentAdvanced", result: "Running", details: `${job.name}: advanced to wave ${job.currentWave + 1}.` });
    mark(job);
    tick();
    return summary(get(id));
  }

  function retry(id, user, { agentIds, scope }) {
    const job = get(id);
    if (TERMINAL_JOB.has(job.status) && job.status === "Cancelled") {
      throw new EngineError("A cancelled deployment cannot be retried.", 409, "cancelled");
    }
    const ids = new Set(Array.isArray(agentIds) ? agentIds.map(String) : []);
    let retried = 0;
    for (const target of job.targets) {
      const chosen = scope === "failed" ? target.state === "Failed" : ids.has(target.agentId);
      if (chosen && (target.state === "Failed" || target.state === "Skipped")) {
        target.state = "Waiting";
        target.attempts = 0;
        target.outcome = "";
        target.message = "";
        target.exitCode = null;
        target.nextAttemptUtc = null;
        target.firstOfflineUtc = null;
        pushHistory(target, "Waiting", "Queued again for retry by an administrator.");
        retried += 1;
      }
    }
    if (retried === 0) {
      throw new EngineError("No matching failed systems to retry.", 400, "nothing_to_retry");
    }
    if (TERMINAL_JOB.has(job.status)) {
      job.status = "Running";
      job.completedUtc = null;
      job.statusReason = "";
    }
    addEvent(job, user.name, "Retry", `Re-queued ${retried} system(s).`);
    store.addAudit({ user: user.name, action: "DeploymentRetried", result: "Running", details: `${job.name}: re-queued ${retried} system(s).` });
    mark(job);
    tick();
    return { job: summary(get(id)), retried };
  }

  // --- Views ----------------------------------------------------------------------------------

  function counts(job) {
    const c = { total: job.targets.length, pending: 0, waiting: 0, offline: 0, running: 0, succeeded: 0, failed: 0, skipped: 0, cancelled: 0, rebootRequired: 0 };
    for (const t of job.targets) {
      if (t.state === "Pending") { c.pending += 1; }
      else if (t.state === "Waiting") { c.waiting += 1; }
      else if (t.state === "Offline") { c.offline += 1; }
      else if (t.state === "Dispatched" || t.state === "Running") { c.running += 1; }
      else if (t.state === "Succeeded") { c.succeeded += 1; }
      else if (t.state === "Failed") { c.failed += 1; }
      else if (t.state === "Skipped") { c.skipped += 1; }
      else if (t.state === "Cancelled") { c.cancelled += 1; }
      if (t.rebootRequired) { c.rebootRequired += 1; }
    }
    return c;
  }

  function summary(job) {
    return {
      id: job.id,
      kind: job.kind,
      name: job.name,
      packageId: job.packageId,
      packageName: job.packageName,
      packageVersion: job.packageVersion,
      action: job.action,
      status: job.status,
      statusReason: job.statusReason,
      createdBy: job.createdBy,
      createdUtc: job.createdUtc,
      startedUtc: job.startedUtc,
      completedUtc: job.completedUtc,
      startAt: job.startAt,
      currentWave: job.currentWave,
      waveCount: job.waveCount,
      nextWaveAtUtc: job.nextWaveAtUtc,
      options: job.options,
      counts: counts(job)
    };
  }

  function detail(job) {
    const waves = [];
    for (let i = 0; i < job.waveCount; i += 1) {
      const members = job.targets.filter((t) => t.wave === i);
      waves.push({
        index: i,
        total: members.length,
        succeeded: members.filter((t) => t.state === "Succeeded").length,
        failed: members.filter((t) => t.state === "Failed").length,
        skipped: members.filter((t) => t.state === "Skipped" || t.state === "Cancelled").length,
        active: i === job.currentWave && !TERMINAL_JOB.has(job.status)
      });
    }
    return { ...summary(job), waves, timeline: job.timeline.slice(0, 200) };
  }

  function targetView(t) {
    return {
      agentId: t.agentId,
      displayId: t.displayId,
      machineName: t.machineName,
      site: t.site,
      wave: t.wave,
      state: t.state,
      stage: t.stage,
      percent: t.percent,
      attempts: t.attempts,
      exitCode: t.exitCode,
      rebootRequired: t.rebootRequired,
      outcome: t.outcome,
      message: t.message,
      updatedUtc: t.updatedUtc,
      nextAttemptUtc: t.nextAttemptUtc
    };
  }

  function queryTargets(id, query) {
    const job = get(id);
    const state = String(query.state || "").trim();
    const q = String(query.q || "").trim().toLowerCase();
    const page = Math.max(Number.parseInt(query.page, 10) || 1, 1);
    const pageSize = Math.min(Math.max(Number.parseInt(query.pageSize, 10) || 100, 1), 1000);
    let rows = job.targets;
    if (state && state !== "all") {
      rows = rows.filter((t) => t.state === state || (state === "Running" && (t.state === "Dispatched" || t.state === "Running")));
    }
    if (q) {
      rows = rows.filter((t) => `${t.displayId} ${t.machineName} ${t.site} ${t.message}`.toLowerCase().includes(q));
    }
    return { total: rows.length, page, pageSize, rows: rows.slice((page - 1) * pageSize, page * pageSize).map(targetView) };
  }

  function targetDetail(id, agentId) {
    const job = get(id);
    const target = job.targets.find((t) => t.agentId === agentId);
    if (!target) {
      throw new EngineError("The system is not part of this deployment.", 404, "not_found");
    }
    return { target: { ...targetView(target), history: target.history.slice(0, 60), log: target.log || "" } };
  }

  function setLog(commandId, log) {
    const route = commandIndex.get(commandId);
    if (!route) {
      return;
    }
    const job = jobs.get(route.jobId);
    const target = job && job.targets.find((t) => t.commandId === commandId || t.agentId === route.agentId);
    if (target) {
      target.log = String(log || "").slice(0, 16000);
      mark(job);
    }
  }

  function list(filter) {
    const kind = filter && filter.kind;
    const status = filter && filter.status;
    const q = String((filter && filter.q) || "").trim().toLowerCase();
    return [...jobs.values()]
      .filter((job) => (!kind || job.kind === kind) && (!status || job.status === status))
      .filter((job) => !q || `${job.name} ${job.packageName} ${job.packageVersion} ${job.action || ""} ${job.createdBy}`.toLowerCase().includes(q))
      .sort((a, b) => b.createdUtc.localeCompare(a.createdUtc))
      .map(summary);
  }

  function usageForPackage(packageId) {
    let deploymentCount = 0;
    let activeDeployments = 0;
    let lastDeployedUtc = null;
    for (const job of jobs.values()) {
      if (job.packageId === packageId) {
        deploymentCount += 1;
        if (!TERMINAL_JOB.has(job.status)) {
          activeDeployments += 1;
        }
        if (!lastDeployedUtc || job.createdUtc > lastDeployedUtc) {
          lastDeployedUtc = job.createdUtc;
        }
      }
    }
    return { deploymentCount, activeDeployments, lastDeployedUtc };
  }

  function exportCsv(id) {
    const job = get(id);
    const header = ["Agent ID", "Machine", "Site", "Wave", "State", "Outcome", "Attempts", "Exit code", "Reboot required", "Updated", "Message"];
    const escape = (value) => {
      let s = String(value == null ? "" : value);
      if (/^[=+\-@]/.test(s)) {
        s = `'${s}`;
      }
      return `"${s.replace(/"/g, '""')}"`;
    };
    const lines = [header.map(escape).join(",")];
    for (const t of job.targets) {
      lines.push([t.displayId, t.machineName, t.site, t.wave + 1, t.state, t.outcome, t.attempts, t.exitCode == null ? "" : t.exitCode, t.rebootRequired ? "yes" : "no", t.updatedUtc, t.message].map(escape).join(","));
    }
    return lines.join("\r\n");
  }

  function agentHasActiveSoftwareJob(agentId, packageId) {
    for (const job of jobs.values()) {
      if (job.kind !== "software" || job.packageId !== packageId || TERMINAL_JOB.has(job.status)) {
        continue;
      }
      if (job.targets.some((t) => t.agentId === agentId && !TERMINAL_TARGET.has(t.state))) {
        return true;
      }
    }
    return false;
  }

  // A one-second tick keeps dispatch latency low; stalled-delivery reclamation is far less urgent.
  let ticks = 0;
  const timer = setInterval(() => {
    try {
      ticks += 1;
      if (ticks % 30 === 0) {
        reclaimStalled();
      }
      if ([...jobs.values()].some((job) => !TERMINAL_JOB.has(job.status))) {
        tick();
      } else {
        persist();
      }
    } catch (error) {
      logger(`Deployment scheduler error: ${error.message}`);
    }
  }, 1000);
  timer.unref();

  return {
    EngineError,
    createJob,
    list,
    get: (id) => detail(get(id)),
    summary: (id) => summary(get(id)),
    queryTargets,
    targetDetail,
    pause,
    resume,
    cancel,
    advance,
    retry,
    onProgress,
    onResult,
    setLog,
    usageForPackage,
    exportCsv,
    agentHasActiveSoftwareJob,
    normalizeOptions: (opts) => normalizeOptions(opts, targets.getSettings()),
    flush: () => persist(true),
    tick
  };
}

module.exports = { createDeploymentEngine, EngineError, normalizeOptions };
