"use strict";

// Repair, update, reset and removal, run as staged jobs.
//
// Rules that apply to every operation here, because these are the ones that can break an installation:
//   * one at a time. A lock is held in the state file, so a second request is refused rather than queued,
//     and a job left behind by a crash or a restart is visible instead of blocking forever.
//   * preflight first. Each stage is listed before anything runs, with what it will touch; destructive
//     stages do not start unless the checks pass.
//   * a verified backup before anything destructive, and the job stops if it cannot be verified.
//   * progress is written to disk after every stage, so an interrupted job can be reported and resumed
//     instead of leaving the installation in an unknown state.
//   * every stage transition is audited with the operator, the reason and the outcome.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { stateFile, writeJson, readJson } = require("./statePath");
const backup = require("./backup");
const connectivity = require("./connectivity");
const { Roles } = require("./commandTypes");

const STATE = () => stateFile("maintenance.json");
// Store calls take the acting user as { name, role }; maintenance jobs record only the name.
const operator = (job) => ({ name: job.user, role: Roles.Administrator });
// Written by uagent-maintenance (root-owned directory, readable by the service).
const RELEASE_RECORD = () => process.env.UAGENT_RELEASE_RECORD || "/etc/uagent/last-release.json";
// Not part of any backup, so it survives the restore it describes.
const RESTORE_NOTE = () => stateFile("restore-pending.json");
const HISTORY_LIMIT = 50;
// A job whose heartbeat is older than this was interrupted, almost always by the service restarting.
const STALE_MS = 10 * 60 * 1000;

const JobStates = {
  Running: "Running",
  Succeeded: "Succeeded",
  Failed: "Failed",
  Interrupted: "Interrupted",
  NeedsAttention: "NeedsAttention"
};

// `destructive` marks the operations that require a verified backup and a typed confirmation phrase.
// Everything here also requires the Administrator role, a reason and the operator's own password.
const Operations = {
  repair: {
    title: "Repair and resynchronise",
    destructive: false,
    confirmPhrase: "",
    summary: "Revalidates the manager address, certificate and connectivity, reconciles agent records and reports what it corrected. Customer records, credentials, agent registrations and audit history are left alone.",
    stages: ["inspect-state", "check-certificate", "check-connectivity", "reconcile-agents", "verify"]
  },
  refresh: {
    title: "Refresh the application",
    destructive: false,
    confirmPhrase: "",
    summary: "Takes a verified backup, fetches the configured release, checks its integrity, applies it, restarts the service and verifies health. If the new version does not come up, it is rolled back.",
    stages: ["preflight", "backup", "fetch-release", "verify-release", "apply-release", "verify-health"]
  },
  "agent-repair": {
    title: "Repair the selected agents",
    destructive: false,
    confirmPhrase: "",
    selectsAgents: true,
    summary: "Sends an authenticated repair to the agents you choose: each re-applies its service start type, recovery settings, permissions and firewall rule, and reports every step. Nothing is uninstalled and no records are removed.",
    stages: ["preflight", "dispatch-agents", "verify"]
  },
  "agent-removal": {
    title: "Uninstall the selected agents",
    destructive: true,
    confirmPhrase: "UNINSTALL",
    selectsAgents: true,
    summary: "Sends an authenticated uninstall to the agents you choose. Each is removed from the portal only after its uninstaller reports success, so a failed removal stays visible instead of disappearing. The portal's own configuration and the audit log are untouched.",
    stages: ["preflight", "backup", "remove-agents", "verify"]
  },
  reset: {
    title: "Reset the installation",
    destructive: true,
    confirmPhrase: "RESET",
    summary: "Returns the portal to a fresh installation and the setup wizard. The selected records are cleared after a verified backup is taken. Installed agents are not touched and keep running until they are removed separately.",
    stages: ["preflight", "backup", "clear-state", "verify"]
  },
  destroy: {
    title: "Destroy the environment",
    destructive: true,
    confirmPhrase: "DESTROY",
    summary: "Removes the selected parts of the deployment. Each part is chosen explicitly; nothing is included by default.",
    stages: ["preflight", "backup", "remove-agents", "clear-state", "remove-files", "verify"]
  }
};

// The reset form offers these groups rather than one switch, so an administrator chooses what goes.
const ResetScopes = {
  operational: {
    title: "Agents, inventory and action history",
    // Handled by clearing the store rather than deleting its file, because the audit log shares that file
    // and is kept. Installed agents are not touched and re-register when they next check in.
    files: [],
    detail: "Agent registrations, inventory and action history. The audit log is kept. Agents still installed on computers re-register when they next check in, so remove them first if they are not wanted back."
  },
  deployment: {
    title: "Deployment Center data",
    files: ["software-library.json", "deployments.json", "deploy-targets.json", "agent-releases.json", "agent-imports.json"],
    detail: "The package library, deployment jobs and history, saved target groups and agent releases."
  },
  secrets: {
    title: "Stored deployment secrets",
    files: ["vault-secrets.json", "vault.key"],
    detail: "Secrets saved for deployments, and the key that decrypts them."
  },
  accounts: {
    title: "Portal accounts and the manager address",
    files: ["operators.json", "portal-host.json"],
    detail: "Portal sign-in accounts and the configured agent address. Clearing this returns the portal to the setup wizard, where a new administrator account is created."
  }
};

// Destruction offers everything a reset offers, plus the parts a reset deliberately keeps: the agents
// themselves, generated files, the backups and the audit history. None of it is selected by default.
const DestroyExtras = {
  agents: {
    title: "Windows agents on remote computers",
    detail: "Each selected agent is sent an authenticated uninstall and removed from the portal only after it reports success."
  },
  installerFiles: {
    title: "Generated installer files and caches",
    detail: "Built agent installers and uploaded packages. Source files and certificates are not touched."
  },
  backups: {
    title: "Backups and recovery material",
    detail: "Every backup in the backup directory. After this there is nothing left to restore from."
  },
  auditHistory: {
    title: "Security audit history",
    detail: "The audit log is security evidence. It is kept unless this is selected, and the removal is itself recorded."
  }
};

// Agents first and the audit history last, so the form reads from "what is still out there" down to
// "what is left to investigate with".
function destroyScopeList() {
  return [
    { key: "agents", ...DestroyExtras.agents },
    ...Object.entries(ResetScopes).map(([key, group]) => ({ key, title: group.title, detail: group.detail, files: group.files })),
    { key: "installerFiles", ...DestroyExtras.installerFiles },
    { key: "backups", ...DestroyExtras.backups },
    { key: "auditHistory", ...DestroyExtras.auditHistory }
  ];
}

function newId() {
  return crypto.randomBytes(8).toString("hex");
}

function load() {
  const saved = readJson(STATE());
  return {
    current: (saved && saved.current) || null,
    history: (saved && Array.isArray(saved.history)) ? saved.history : [],
    setupRequired: Boolean(saved && saved.setupRequired),
    restartRequired: (saved && saved.restartRequired) || null
  };
}

function createMaintenance(context) {
  const { store, tlsManager, hostSettings, config, logger, operators } = context;
  let state = load();
  const runtime = { save: null, freeze: null, restart: null, frozen: false };

  function persist() {
    if (!runtime.frozen) {
      writeJson(STATE(), state);
    }
  }

  // State lives in memory and is saved periodically, so it is saved now: a backup read from disk would
  // otherwise miss the latest changes.
  function saveNow() {
    if (runtime.save) {
      runtime.save();
    } else {
      store.flush(true);
    }
  }

  function takeBackup(options) {
    saveNow();
    return backup.create(options);
  }

  function audit(job, action, result, details) {
    store.addAudit({
      user: job.user,
      action,
      result,
      details: `[${Operations[job.type].title}] ${details}`,
      remoteIp: job.remoteIp || ""
    });
  }

  function view(job) {
    if (!job) {
      return null;
    }
    const definition = Operations[job.type];
    return {
      id: job.id,
      type: job.type,
      title: definition.title,
      state: job.state,
      user: job.user,
      reason: job.reason,
      startedUtc: job.startedUtc,
      endedUtc: job.endedUtc || null,
      stages: job.stages,
      findings: job.findings || [],
      corrections: job.corrections || [],
      error: job.error || "",
      backupFile: job.backupFile ? path.basename(job.backupFile) : "",
      scope: job.scope || null,
      resumable: Boolean(job.state === JobStates.Interrupted && definition.destructive)
    };
  }

  // A job still marked running after a restart was interrupted. It is recorded as such and the lock is
  // released, so the installation is never stuck waiting for a job that is no longer going to finish.
  // A restart was outstanding and this is a new process, so by definition it has happened. The modules
  // that hold deployment data in memory have now reloaded from the cleared files, which is what finishes
  // a reset of those groups.
  function clearRestartFlagOnStart() {
    if (state.restartRequired) {
      logger(`The restart needed to finish ${state.restartRequired.operation} has happened; the cleared records are no longer in memory.`);
      state.restartRequired = null;
      persist();
    }
  }

  function reconcileOnStart() {
    const job = state.current;
    if (!job) {
      return;
    }
    if (job.state !== JobStates.Running) {
      finish(job, job.state);
      return;
    }
    // Applying a release restarts this process, so the helper's own record says how it ended.
    const release = job.type === "refresh" && job.target ? readJson(RELEASE_RECORD()) : null;
    if (release && release.target === job.target && (release.outcome === "applied" || release.outcome === "rolled-back")) {
      const applied = release.outcome === "applied";
      for (const stage of job.stages) {
        if (stage.state === "running" || stage.state === "pending") {
          stage.state = applied ? "done" : (stage.key === "apply-release" ? "failed" : "skipped");
          stage.detail = applied
            ? "The portal restarted on the new release and answered /healthz."
            : `The new release did not answer /healthz; ${String(release.previous || "").slice(0, 12)} was restored.`;
        }
      }
      if (applied) {
        corrected(job, `Applied release ${job.target}.`);
      } else {
        finding(job, "problem", "The new version did not come up, so the previous one was restored.");
      }
      audit(job, applied ? "MaintenanceCompleted" : "MaintenanceFailed", applied ? "Success" : "Failed", applied ? `Release ${job.target} is running.` : `Release ${job.target} was rolled back.`);
      finish(job, applied ? JobStates.Succeeded : JobStates.Failed);
      return;
    }
    const age = Date.now() - new Date(job.heartbeatUtc || job.startedUtc).getTime();
    if (age < STALE_MS) {
      return;
    }
    job.state = JobStates.Interrupted;
    const pending = job.stages.filter((stage) => stage.state === "pending" || stage.state === "running");
    pending.forEach((stage) => { if (stage.state === "running") { stage.state = "interrupted"; } });
    job.error = `The operation stopped before it finished, most likely because the portal restarted. ${pending.length} stage(s) did not complete.`;
    logger(`Maintenance job ${job.id} (${job.type}) was interrupted; it is recorded for review.`);
    audit(job, "MaintenanceInterrupted", "Warning", job.error);
    finish(job, JobStates.Interrupted);
  }

  function finish(job, finalState) {
    job.state = finalState;
    job.endedUtc = job.endedUtc || new Date().toISOString();
    state.history.unshift(job);
    state.history = state.history.slice(0, HISTORY_LIMIT);
    state.current = null;
    persist();
  }

  function busy() {
    const job = state.current;
    if (!job) {
      return null;
    }
    if (job.state === JobStates.Running &&
        Date.now() - new Date(job.heartbeatUtc || job.startedUtc).getTime() > STALE_MS) {
      reconcileOnStart();
      return state.current;
    }
    return job;
  }

  /** What an operation would do, with the checks that gate it. Nothing is changed. */
  async function preflight(type, options) {
    const definition = Operations[type];
    if (!definition) {
      throw new Error(`Unknown operation: ${type}`);
    }
    const scope = normalizeScope(type, options && options.scope);
    const report = await connectivity.report({ tlsManager, store, hostSettings, config });
    const agents = store.listAgents();
    const blockers = [];
    const notes = [];

    // The job being started holds the lock while its own preflight runs, so it is not its own blocker.
    const running = busy();
    if (running && running.id !== (options && options.jobId)) {
      blockers.push(`${Operations[running.type].title} is already running (started ${running.startedUtc} by ${running.user}). Wait for it to finish.`);
    }
    if (definition.destructive) {
      const space = freeSpace();
      if (space !== null && space < 64 * 1024 * 1024) {
        blockers.push(`There is only ${Math.round(space / 1048576)} MB free where backups are written; a verified backup is required before this runs.`);
      }
      notes.push("A backup is taken and verified before anything is removed. The operation stops if it cannot be read back.");
    }
    if (type === "refresh") {
      const source = releaseSource();
      if (!source.ok) {
        blockers.push(source.detail);
      } else {
        notes.push(source.detail);
      }
    }
    if ((type === "reset" || type === "destroy") && !Object.values(scope).some(Boolean)) {
      blockers.push("Select at least one group of records to clear.");
    }
    if (definition.selectsAgents) {
      const chosen = selectedAgents(scope);
      if (!chosen.length) {
        blockers.push("Choose at least one agent.");
      } else {
        const offline = chosen.filter((agent) => !agent.online);
        notes.push(`${chosen.length} agent(s) selected: ${chosen.filter((agent) => agent.online).length} online, ${offline.length} offline.`);
        if (offline.length) {
          notes.push(`The ${offline.length} offline agent(s) keep the command queued and run it when they next connect, so this may complete over hours rather than minutes.`);
        }
        const busyAgents = chosen.filter((agent) => agent.removalState && agent.removalState !== "Failed");
        if (busyAgents.length) {
          notes.push(`${busyAgents.length} of them are already being removed and are skipped.`);
        }
      }
    }
    if (type === "destroy" && scope.agents) {
      const removable = agents.filter((agent) => agent.status === "Active");
      notes.push(`${removable.length} agent(s) will be sent an uninstall. Each is removed from the portal only after its uninstaller reports success; the rest stay listed as failed or unverified.`);
      const offline = removable.filter((agent) => !agent.online).length;
      if (offline) {
        notes.push(`${offline} of them are offline, so their uninstall is queued and runs when they next connect.`);
      }
    }

    return {
      type,
      title: definition.title,
      summary: definition.summary,
      destructive: definition.destructive,
      stages: definition.stages.map((key) => ({ key, title: stageTitle(key) })),
      scope,
      // The chosen agents, named, so the confirmation shows exactly which computers are affected.
      selection: definition.selectsAgents
        ? selectedAgents(scope).map((agent) => ({
          agentId: agent.agentId,
          displayId: agent.displayId,
          machineName: agent.machineName,
          online: Boolean(agent.online),
          status: agent.status,
          agentVersion: agent.agentVersion || ""
        }))
        : [],
      scopes: type === "reset"
        ? Object.entries(ResetScopes).map(([key, group]) => ({ key, title: group.title, detail: group.detail }))
        : (type === "destroy" ? destroyScopeList() : []),
      affects: (type === "reset" || type === "destroy") ? describeScope(scope) : [],
      state: backup.describeState(),
      connectivity: report,
      agents: { total: agents.length, online: agents.filter((a) => a.online).length, active: agents.filter((a) => a.status === "Active").length },
      backups: backup.list().slice(0, 5),
      confirmPhrase: definition.confirmPhrase || "",
      selectsAgents: Boolean(definition.selectsAgents),
      requiresUninstallKey: type === "agent-removal" || (type === "destroy" && Boolean(scope.agents)),
      blockers,
      notes,
      ready: blockers.length === 0
    };
  }

  function freeSpace() {
    try {
      const stat = fs.statfsSync(backup.backupDirectory());
      return stat.bsize * stat.bavail;
    } catch (error) {
      return null;
    }
  }

  function normalizeScope(type, scope) {
    const input = scope || {};
    if (Operations[type] && Operations[type].selectsAgents) {
      const known = new Set(store.listAgents().map((agent) => agent.agentId));
      return {
        agentIds: (Array.isArray(input.agentIds) ? input.agentIds : []).filter((id) => known.has(id)),
        includeOffline: input.includeOffline !== false
      };
    }
    if (type === "reset") {
      const chosen = {};
      for (const key of Object.keys(ResetScopes)) {
        chosen[key] = Boolean(input[key]);
      }
      return chosen;
    }
    if (type === "destroy") {
      // Audit history is included only when it is explicitly released, and even then the removal is recorded.
      const chosen = {};
      for (const group of destroyScopeList()) {
        chosen[group.key] = Boolean(input[group.key]);
      }
      return chosen;
    }
    return {};
  }

  function filesFor(scope) {
    const files = [];
    for (const [key, group] of Object.entries(ResetScopes)) {
      if (scope[key]) {
        files.push(...group.files);
      }
    }
    return [...new Set(files)];
  }

  // The agents an operation will act on: the ones chosen, still registered, and reachable in the sense
  // that an offline agent is only included when the operator said to include them.
  function selectedAgents(scope) {
    const wanted = new Set((scope && scope.agentIds) || []);
    return store.listAgents().filter((agent) => wanted.has(agent.agentId) && (agent.online || scope.includeOffline));
  }

  function describeScope(scope) {
    const items = [];
    for (const [key, group] of Object.entries(ResetScopes)) {
      if (scope[key]) {
        items.push({ key, title: group.title, detail: group.detail, files: group.files });
      }
    }
    for (const [key, group] of Object.entries(DestroyExtras)) {
      if (scope[key]) {
        items.push({ key, ...group });
      }
    }
    return items;
  }

  function stageTitle(key) {
    return {
      "inspect-state": "Check configuration and stored records",
      "check-certificate": "Check the TLS certificate and trust",
      "check-connectivity": "Check DNS, the port and the handshake",
      "reconcile-agents": "Reconcile agent registrations and inventory",
      preflight: "Run preflight checks",
      "dispatch-agents": "Send the repair to each selected agent",
      backup: "Create and verify a backup",
      "fetch-release": "Fetch the configured release",
      "verify-release": "Verify the release integrity",
      "apply-release": "Apply the release and restart",
      "verify-health": "Verify service health",
      "clear-state": "Clear the selected records",
      "remove-agents": "Uninstall the selected agents",
      "remove-files": "Remove generated files",
      verify: "Verify the result"
    }[key] || key;
  }

  // Updates are applied by a root-owned helper, never by this process. The installed copy at
  // /usr/local/sbin is the one used: the checkout belongs to the service account, so a copy inside it
  // must not be what sudo executes. Without the installed copy the update is refused rather than run
  // from a path the portal itself could rewrite.
  function releaseSource() {
    const directory = path.resolve(__dirname, "../..");
    const helper = "/usr/local/sbin/uagent-maintenance";
    if (!fs.existsSync(path.join(directory, ".git"))) {
      return { ok: false, detail: `This installation is not a tracked checkout (${directory} has no .git), so the portal cannot fetch a release itself. Update it the way it was installed.` };
    }
    if (!fs.existsSync(helper)) {
      return {
        ok: false,
        detail: `The update helper is not installed at ${helper}, so the portal cannot apply a release. Re-run the installer, or update this server the way it was installed.`
      };
    }
    return {
      ok: true,
      directory,
      helper,
      detail: `Releases come from the checkout at ${directory}. ${path.basename(helper)} applies them as root, verifies the new version answers, and restores the previous one if it does not. Configuration, certificates and agent records are not part of a release.`
    };
  }

  /**
   * Starts an operation. The caller must already have checked the role, the typed confirmation and the
   * operator's password; this records who asked and why, and runs the stages.
   */
  async function start(type, options) {
    const definition = Operations[type];
    if (!definition) {
      throw new Error(`Unknown operation: ${type}`);
    }
    const running = busy();
    if (running) {
      const error = new Error(`${Operations[running.type].title} is already running. Wait for it to finish.`);
      error.code = "busy";
      throw error;
    }
    const job = {
      id: newId(),
      type,
      state: JobStates.Running,
      user: options.user,
      remoteIp: options.remoteIp || "",
      reason: options.reason || "",
      scope: normalizeScope(type, options.scope),
      startedUtc: new Date().toISOString(),
      heartbeatUtc: new Date().toISOString(),
      stages: definition.stages.map((key) => ({ key, title: stageTitle(key), state: "pending", detail: "" })),
      findings: [],
      corrections: []
    };

    // The lock is claimed before the preflight is awaited. Preflight opens a connection to the portal's
    // own listener, so two requests that arrived together would both pass the check above, and the second
    // would overwrite the first job and run alongside it. A job that fails preflight releases the lock
    // again without being recorded, because it never started.
    state.current = job;
    persist();
    let check;
    try {
      check = await preflight(type, Object.assign({}, options, { jobId: job.id }));
    } catch (error) {
      state.current = null;
      persist();
      throw error;
    }
    if (!check.ready) {
      state.current = null;
      persist();
      const error = new Error(check.blockers[0]);
      error.code = "not_ready";
      error.blockers = check.blockers;
      throw error;
    }
    job.scope = check.scope;
    persist();
    logger(`${definition.title} started by ${job.user}${job.reason ? ` (${job.reason})` : ""}.`);
    audit(job, "MaintenanceStarted", "Success", `Started by ${job.user}. Reason: ${job.reason || "not given"}.`);

    // Deliberately not awaited: the caller gets the job id immediately and polls for progress.
    run(job).catch((error) => {
      job.error = error.message;
      audit(job, "MaintenanceFailed", "Failed", error.message);
      finish(job, JobStates.Failed);
    });
    return view(job);
  }

  async function run(job) {
    const handlers = {
      repair: repairStages,
      refresh: refreshStages,
      "agent-repair": agentStages,
      "agent-removal": agentStages,
      reset: resetStages,
      destroy: destroyStages
    };
    const steps = handlers[job.type]();
    for (const stage of job.stages) {
      const handler = steps[stage.key];
      stage.state = "running";
      stage.startedUtc = new Date().toISOString();
      job.heartbeatUtc = stage.startedUtc;
      persist();
      try {
        const result = (handler ? await handler(job) : null) || {};
        stage.state = result.state || "done";
        stage.detail = result.detail || "";
        stage.endedUtc = new Date().toISOString();
        job.heartbeatUtc = stage.endedUtc;
        persist();
        if (stage.state === "failed") {
          throw new Error(result.detail || `${stage.title} failed.`);
        }
      } catch (error) {
        stage.state = "failed";
        stage.detail = error.message;
        stage.endedUtc = new Date().toISOString();
        job.error = error.message;
        persist();
        audit(job, "MaintenanceFailed", "Failed", `${stage.title}: ${error.message}`);
        finish(job, JobStates.Failed);
        return;
      }
    }
    const attention = job.findings.some((finding) => finding.severity === "problem");
    audit(job, "MaintenanceCompleted", attention ? "Warning" : "Success",
      `${job.corrections.length} correction(s), ${job.findings.length} finding(s).${job.backupFile ? ` Backup: ${path.basename(job.backupFile)}.` : ""}`);
    finish(job, attention ? JobStates.NeedsAttention : JobStates.Succeeded);
  }

  function finding(job, severity, message) {
    job.findings.push({ severity, message });
  }

  function corrected(job, message) {
    job.corrections.push(message);
  }

  // ---- Agent maintenance and removal ---------------------------------------------------------------
  //
  // Both operations act on named agents only, and both are attributable: each command carries the
  // operator, the reason and its own id, and lands in that agent's action history and in the audit log.
  // Nothing happens silently on an endpoint and nothing is removed from the portal before the endpoint
  // confirms it, so a failed removal stays visible instead of disappearing from the fleet list.

  function agentStages() {
    const describe = (agentId) => {
      const agent = store.listAgents().find((entry) => entry.agentId === agentId);
      return agent ? `${agent.displayId} (${agent.machineName})` : agentId;
    };

    return {
      preflight: async (job) => {
        const chosen = selectedAgents(job.scope);
        if (!chosen.length) {
          return { state: "failed", detail: "None of the selected agents are still registered." };
        }
        job.targets = chosen.map((agent) => agent.agentId);
        return { detail: `${chosen.length} agent(s): ${chosen.map((agent) => agent.displayId).join(", ")}.` };
      },
      backup: async (job) => {
        const made = takeBackup({
          user: job.user,
          label: "before-agent-removal",
          reason: job.reason || "Taken before uninstalling agents."
        });
        job.backupFile = made.file;
        return { detail: `${path.basename(made.file)} (${Math.round(made.sizeBytes / 1024)} KB), verified. The agent records can be restored even though the software cannot.` };
      },
      "dispatch-agents": async (job) => {
        let sent = 0;
        for (const agentId of job.targets) {
          const label = describe(agentId);
          try {
            store.enqueue(agentId, {
              commandId: crypto.randomUUID(),
              samAccountName: "",
              commandType: "RepairAgent",
              newPassword: null,
              createdUtc: new Date().toISOString(),
              accountSource: null
            }, operator(job), job.reason || "Agent repair from Reset & Recovery");
            sent += 1;
          } catch (error) {
            finding(job, "warning", `${label} could not be sent a repair: ${error.message}`);
          }
        }
        if (!sent) {
          return { state: "failed", detail: "No repair could be sent to any of the selected agents." };
        }
        corrected(job, `Sent an authenticated repair to ${sent} agent(s). Each reports its steps in its own action history.`);
        return { detail: `${sent} of ${job.targets.length} agent(s) were sent a repair.` };
      },
      "remove-agents": async (job) => {
        let requested = 0;
        for (const agentId of job.targets) {
          const label = describe(agentId);
          try {
            store.requestRemoval(agentId, operator(job), job.reason || "Agent removal from Reset & Recovery");
            requested += 1;
          } catch (error) {
            finding(job, "warning", `${label} could not be sent an uninstall: ${error.message}`);
          }
        }
        if (!requested) {
          return { state: "failed", detail: "No uninstall could be sent to any of the selected agents." };
        }
        corrected(job, `Sent an authenticated uninstall to ${requested} agent(s).`);
        return { detail: `${requested} of ${job.targets.length} agent(s) were sent an uninstall.` };
      },
      verify: async (job) => {
        const live = store.listAgents().filter((agent) => job.targets.includes(agent.agentId));
        if (job.type === "agent-removal") {
          const pending = live.filter((agent) => agent.removalState && agent.removalState !== "Removed");
          const done = job.targets.length - live.length;
          if (pending.length) {
            finding(job, "warning", `${pending.length} agent(s) are still being removed. They stay listed until their uninstaller reports success; offline ones finish when they reconnect.`);
          }
          return {
            state: pending.length ? "warning" : "done",
            detail: `${done} agent(s) removed so far, ${pending.length} still to confirm. Watch the Agents page for the rest.`
          };
        }
        const queued = live.filter((agent) => store.findActiveCommand && store.findActiveCommand(agent.agentId, "RepairAgent", "")).length;
        return {
          detail: queued
            ? `${queued} repair(s) are queued or running. Each agent's result appears in its action history.`
            : "Every repair has been delivered. Each agent's result appears in its action history."
        };
      }
    };
  }

  // ---- Repair and resynchronise -------------------------------------------------------------------

  function repairStages() {
    return {
      "inspect-state": async (job) => {
        const files = backup.describeState();
        const missing = files.filter((file) => !file.present).map((file) => file.name);
        const unreadable = [];
        for (const file of files.filter((entry) => entry.present && entry.name.endsWith(".json"))) {
          if (readJson(stateFile(file.name)) === null) {
            unreadable.push(file.name);
            finding(job, "problem", `${file.name} could not be read as JSON. Restore it from a backup; the portal is using what it loaded at startup.`);
          }
        }
        return {
          state: unreadable.length ? "warning" : "done",
          detail: `${files.filter((f) => f.present).length} state file(s) present${missing.length ? `, ${missing.length} not yet created` : ""}${unreadable.length ? `, ${unreadable.length} unreadable` : ""}.`
        };
      },
      "check-certificate": async (job) => {
        const reloaded = tlsManager.reload("repair");
        const certificate = tlsManager.describe();
        if (!certificate) {
          finding(job, "problem", "No TLS certificate is installed. Agents cannot connect until one is.");
          return { state: "failed", detail: "No certificate is installed." };
        }
        certificate.problems.forEach((problem) => finding(job, "problem", problem));
        certificate.warnings.forEach((warning) => finding(job, "warning", warning));
        if (reloaded) {
          corrected(job, "Reloaded the certificate from disk, so a renewal or replacement is now in use.");
        }
        return {
          state: certificate.problems.length ? "warning" : "done",
          detail: `${certificate.subject} (${certificate.mode}), serving ${certificate.servedLength} certificate(s), valid to ${String(certificate.validTo).slice(0, 10)}.`
        };
      },
      "check-connectivity": async (job) => {
        const report = await connectivity.report({ tlsManager, store, hostSettings, config });
        report.problems.forEach((problem) => finding(job, "problem", problem));
        report.warnings.forEach((warning) => finding(job, "warning", warning));
        job.connectivity = report;
        const steps = [report.live.dns, report.live.tcp, report.live.tls];
        return {
          state: report.ok ? "done" : "warning",
          detail: `DNS ${steps[0].ok ? "OK" : "failed"}, TCP ${steps[1].ok ? "OK" : "failed"}, TLS ${steps[2].ok ? "OK" : "failed"} for ${report.host}:${report.port}.`
        };
      },
      "reconcile-agents": async (job) => {
        // Presence is recomputed and stuck removals are re-evaluated, so the portal's view matches reality.
        store.sweepPresence();
        const agents = store.listAgents();
        const stale = agents.filter((agent) => agent.status === "Active" && !agent.online);
        const pendingRemoval = agents.filter((agent) => agent.removalState);
        if (stale.length) {
          finding(job, "warning", `${stale.length} active agent(s) have not checked in recently. They retry on their own; if they stay offline, run diagnostics on the endpoint.`);
        }
        if (pendingRemoval.length) {
          finding(job, "warning", `${pendingRemoval.length} agent(s) have a removal in progress or unverified.`);
        }
        return { detail: `${agents.length} agent(s): ${agents.filter((a) => a.online).length} online, ${stale.length} not checked in, ${pendingRemoval.length} being removed.` };
      },
      verify: async (job) => {
        const problems = job.findings.filter((entry) => entry.severity === "problem").length;
        return {
          state: problems ? "warning" : "done",
          detail: problems
            ? `${problems} problem(s) need attention; nothing was removed or overwritten.`
            : "The manager configuration, certificate, connectivity and agent records are consistent."
        };
      }
    };
  }

  // ---- Refresh the application --------------------------------------------------------------------

  function refreshStages() {
    return {
      preflight: async (job) => {
        const source = releaseSource();
        if (!source.ok) {
          return { state: "failed", detail: source.detail };
        }
        job.release = source;
        return { detail: source.detail };
      },
      backup: async (job) => {
        const made = takeBackup({
          user: job.user,
          label: "before-refresh",
          reason: job.reason || "Taken before refreshing the application.",
          extra: certificateFiles()
        });
        job.backupFile = made.file;
        return { detail: `${path.basename(made.file)} (${Math.round(made.sizeBytes / 1024)} KB), verified, covering ${made.contents.length} file(s).` };
      },
      "fetch-release": async (job) => {
        const result = await helper(job, ["fetch"]);
        job.target = (result.stdout.match(/target=([0-9a-f]{7,40})/) || [])[1] || "";
        return { detail: result.summary || "Fetched the configured release." };
      },
      "verify-release": async (job) => {
        const result = await helper(job, ["verify", job.target || ""]);
        return { detail: result.summary || "The release was verified." };
      },
      "apply-release": async (job) => {
        // The helper restarts the service, which ends this process. It records its own progress, and the
        // portal reports the job as interrupted on startup if the restart happened mid-stage.
        let result;
        try {
          result = await helper(job, ["apply", job.target || ""]);
        } catch (error) {
          // The helper restores the previous version itself when the new one does not answer. That is a
          // failed update on a working installation, not an unknown state, and is reported as such.
          if (/rolled back/i.test(error.message)) {
            finding(job, "problem", error.message);
            return { state: "failed", detail: error.message };
          }
          throw error;
        }
        if (result.rolledBack) {
          finding(job, "problem", "The new version did not come up, so the previous one was restored.");
          return { state: "failed", detail: result.summary };
        }
        corrected(job, `Applied release ${job.target || "(latest)"}.`);
        return { detail: result.summary || "The release was applied." };
      },
      "verify-health": async (job) => {
        const report = await connectivity.report({ tlsManager, store, hostSettings, config });
        report.problems.forEach((problem) => finding(job, "problem", problem));
        return {
          state: report.ok ? "done" : "warning",
          detail: report.ok
            ? "The portal answers over TLS and the agent records loaded."
            : `The portal is running, but ${report.problems.length} connectivity problem(s) remain.`
        };
      }
    };
  }

  function certificateFiles() {
    const certificate = tlsManager.describe();
    if (!certificate) {
      return [];
    }
    return [
      { name: "tls/portal.crt", file: config.certFile, holds: "the TLS certificate chain" },
      { name: "tls/ca.crt", file: config.caFile, holds: "the internal root CA certificate" }
    ].filter((entry) => entry.file);
  }

  function helper(job, args) {
    const source = job.release || releaseSource();
    if (!source.ok) {
      return Promise.reject(new Error(source.detail));
    }
    return new Promise((resolve, reject) => {
      execFile("sudo", ["-n", source.helper, ...args], { timeout: 15 * 60 * 1000, maxBuffer: 4 * 1024 * 1024 },
        (error, stdout, stderr) => {
          const output = `${stdout || ""}${stderr || ""}`.trim();
          if (error) {
            const denied = /sudo:|password is required|not allowed/i.test(output);
            reject(new Error(denied
              ? `The portal is not permitted to run ${path.basename(source.helper)}. Run "sudo ${source.helper} ${args.join(" ")}" on the server, or re-run the installer to add the sudoers rule.`
              : `${path.basename(source.helper)} ${args[0]} failed: ${output.split("\n").slice(-3).join(" ") || error.message}`));
            return;
          }
          resolve({
            stdout: output,
            summary: (output.split("\n").filter(Boolean).pop() || "").slice(0, 300),
            rolledBack: /rolled back/i.test(output)
          });
        });
    });
  }

  // ---- Reset the installation ---------------------------------------------------------------------

  function resetStages() {
    return {
      preflight: async (job) => {
        const items = describeScope(job.scope);
        if (!items.length) {
          return { state: "failed", detail: "No records were selected." };
        }
        return { detail: `${items.length} group(s) selected: ${items.map((item) => item.title).join("; ")}.` };
      },
      backup: async (job) => {
        const made = takeBackup({
          user: job.user,
          label: "before-reset",
          reason: job.reason || "Taken before resetting the installation.",
          extra: certificateFiles()
        });
        job.backupFile = made.file;
        return { detail: `${path.basename(made.file)} (${Math.round(made.sizeBytes / 1024)} KB), verified. Restore with: Danger Zone, Backups, Restore.` };
      },
      "clear-state": async (job) => {
        const files = filesFor(job.scope);
        const removed = [];
        // Agent records live in this store, which flushes to disk every few seconds, so clearing memory
        // has to come first or the file simply reappears. The audit log is kept: it is security evidence.
        if (job.scope.operational) {
          const result = store.resetData({ keepAudit: true });
          corrected(job, `Cleared agent registrations, inventory and action history. ${result.auditEntries} audit entr(ies) were kept.`);
        }
        for (const name of files) {
          const file = stateFile(name);
          if (fs.existsSync(file)) {
            fs.rmSync(file, { force: true });
            removed.push(name);
          }
        }
        if (job.scope.accounts) {
          // Drops the accounts the portal is holding in memory as well, so the old credentials stop
          // working immediately rather than at the next restart, and setup cannot be skipped.
          operators.requireSetup();
          state.setupRequired = true;
        }
        // Deployment data and secrets are held in memory by the modules that own them, so those groups are
        // only finished by a restart. This is recorded, shown in the Danger Zone, and cleared on startup.
        if (job.scope.deployment || job.scope.secrets) {
          state.restartRequired = {
            sinceUtc: new Date().toISOString(),
            operation: Operations[job.type].title,
            detail: "Deployment Center data and stored secrets were cleared on disk. Restart the portal to drop the copies it is still holding in memory."
          };
        }
        persist();
        if (removed.length) {
          corrected(job, `Cleared ${removed.length} state file(s): ${removed.join(", ")}.`);
        }
        return {
          detail: [
            removed.length ? `${removed.length} file(s) cleared.` : "",
            job.scope.operational ? "Agent records were cleared immediately." : "",
            job.scope.accounts ? "Portal sign-in now goes to the setup wizard." : "",
            state.restartRequired ? "A restart is needed to finish clearing Deployment Center data." : ""
          ].filter(Boolean).join(" ")
        };
      },
      verify: async (job) => {
        const remaining = filesFor(job.scope).filter((name) => fs.existsSync(stateFile(name)));
        if (remaining.length) {
          return { state: "failed", detail: `${remaining.join(", ")} could not be removed. Check the file permissions on the state directory.` };
        }
        if (job.scope.operational && store.listAgents().length) {
          return { state: "failed", detail: `${store.listAgents().length} agent record(s) are still present. Nothing further was removed; restore the backup if the portal is in an unexpected state.` };
        }
        const outstanding = [
          state.setupRequired ? "sign in to create the new administrator account" : "",
          state.restartRequired ? "restart the portal to finish clearing Deployment Center data" : ""
        ].filter(Boolean);
        return {
          state: outstanding.length ? "warning" : "done",
          detail: outstanding.length
            ? `The selected records were cleared. Still to do: ${outstanding.join("; ")}.`
            : "The selected records were cleared and the portal is consistent. Nothing else is needed."
        };
      }
    };
  }

  // ---- Destroy the environment --------------------------------------------------------------------

  function destroyStages() {
    return {
      preflight: async (job) => {
        const items = describeScope(job.scope);
        if (!items.length) {
          return { state: "failed", detail: "Nothing was selected." };
        }
        if (!job.scope.auditHistory) {
          corrected(job, "Audit history is kept.");
        }
        return { detail: `${items.length} part(s) selected: ${items.map((item) => item.title).join("; ")}.` };
      },
      backup: async (job) => {
        const made = takeBackup({
          user: job.user,
          label: "before-destroy",
          reason: job.reason || "Taken before destroying the environment.",
          extra: certificateFiles()
        });
        job.backupFile = made.file;
        if (job.scope.backups) {
          finding(job, "warning", `Backups were selected for removal. This backup (${path.basename(made.file)}) is kept and must be copied off this server to be of any use.`);
        }
        return { detail: `${path.basename(made.file)}, verified.` };
      },
      "remove-agents": async (job) => {
        if (!job.scope.agents) {
          return { state: "skipped", detail: "Agents on remote computers were not selected and are left installed." };
        }
        const agents = store.listAgents().filter((agent) => agent.status === "Active" && !agent.removalState);
        let requested = 0;
        for (const agent of agents) {
          try {
            store.requestRemoval(agent.agentId, operator(job), job.reason || "Environment removal");
            requested += 1;
          } catch (error) {
            finding(job, "warning", `${agent.displayId} (${agent.machineName}) could not be sent an uninstall: ${error.message}`);
          }
        }
        finding(job, "warning", `${requested} uninstall(s) were sent. Each agent is removed from the portal only when its uninstaller reports success, so watch the Agents page until they clear.`);
        return { detail: `${requested} of ${agents.length} agent(s) were sent an authenticated uninstall.` };
      },
      "clear-state": async (job) => {
        const names = filesFor(job.scope);
        if (job.scope.operational || job.scope.auditHistory) {
          // Agents that were just sent an uninstall keep their records until it is verified; clearing them
          // here would drop the command before it reached them and they would simply register again.
          const result = store.resetData({
            keepAudit: !job.scope.auditHistory,
            keepAgents: !job.scope.operational,
            keepRemovals: Boolean(job.scope.agents)
          });
          if (job.scope.operational) {
            const awaiting = store.listAgents().length;
            corrected(job, awaiting
              ? `Agent records were cleared, except ${awaiting} agent(s) whose uninstall is still on its way; each leaves the list when its uninstall is verified.`
              : "Agent records were cleared.");
          }
          if (result.keptAudit) {
            corrected(job, `${result.auditEntries} audit entr(ies) were kept as security evidence.`);
          } else {
            finding(job, "warning", "The audit log was released as well, so there is no record left in the portal of what happened before this operation. This operation itself is recorded.");
          }
          if (job.scope.auditHistory) {
            fs.rmSync(stateFile("portal-store.json"), { force: true });
            names.push("portal-store.json");
          }
        }
        const removed = [];
        for (const name of names) {
          const file = stateFile(name);
          if (fs.existsSync(file)) {
            fs.rmSync(file, { force: true });
            removed.push(name);
          }
        }
        if (job.scope.accounts) {
          operators.requireSetup();
          state.setupRequired = true;
          persist();
        }
        return { detail: removed.length ? `${removed.join(", ")} removed.` : "No state files needed removing." };
      },
      "remove-files": async (job) => {
        const removed = [];
        if (job.scope.installerFiles) {
          for (const directory of [config.installerDir, stateFile("uploads"), stateFile("packages")].filter(Boolean)) {
            if (fs.existsSync(directory)) {
              fs.rmSync(directory, { recursive: true, force: true });
              removed.push(directory);
            }
          }
        }
        if (job.scope.backups) {
          const keep = job.backupFile ? path.basename(job.backupFile) : "";
          for (const entry of backup.list()) {
            if (entry.name !== keep) {
              fs.rmSync(entry.file, { force: true });
              removed.push(entry.name);
            }
          }
        }
        return {
          state: removed.length ? "done" : "skipped",
          detail: removed.length ? `${removed.length} item(s) removed.` : "No generated files or backups were selected."
        };
      },
      verify: async (job) => {
        const items = describeScope(job.scope);
        return {
          detail: `${items.length} part(s) processed. ${job.scope.agents ? "Agent uninstalls are verified per computer and may still be in progress. " : ""}Application files, certificates and the service itself are untouched; remove those on the server if the deployment is being retired.`
        };
      }
    };
  }

  // ---- Backups -------------------------------------------------------------------------------------

  function createBackup(options) {
    const made = takeBackup({
      user: options.user,
      label: options.label || "manual",
      reason: options.reason || "",
      extra: certificateFiles()
    });
    store.addAudit({
      user: options.user,
      action: "BackupCreated",
      result: "Success",
      details: `${path.basename(made.file)} (${Math.round(made.sizeBytes / 1024)} KB), verified, covering ${made.contents.length} file(s). Reason: ${options.reason || "not given"}.`,
      remoteIp: options.remoteIp || ""
    });
    return made;
  }

  function restoreBackup(name, options) {
    const entry = backup.list().find((item) => item.name === name || item.id === name);
    if (!entry) {
      throw new Error("That backup no longer exists.");
    }
    const running = busy();
    if (running) {
      const error = new Error(`${Operations[running.type].title} is running. Wait for it to finish before restoring.`);
      error.code = "busy";
      throw error;
    }
    // Everything in memory is saved into the safety backup, then nothing may write state again: the
    // restored files would otherwise be overwritten by the next periodic save. The portal restarts on the
    // restored state, and records the restore in the restored audit log when it comes back.
    saveNow();
    runtime.frozen = true;
    if (runtime.freeze) {
      runtime.freeze();
    }
    const result = backup.restore(entry.file, { user: options.user });
    const details = `Restored ${result.restored.length} file(s) from ${entry.name} (taken ${entry.createdUtc} by ${entry.user || "unknown"}). The state before the restore was saved as ${result.safety ? path.basename(result.safety) : "no safety backup"}. Reason: ${options.reason || "not given"}.`;
    writeJson(RESTORE_NOTE(), { user: options.user, remoteIp: options.remoteIp || "", details, utc: new Date().toISOString() });
    logger(`${options.user} restored portal state from ${entry.name}. The portal restarts now to load it.`);
    if (runtime.restart) {
      setTimeout(runtime.restart, 750).unref();
    }
    return { ...result, restarting: Boolean(runtime.restart) };
  }

  // A restore is recorded after the restart, in the audit log that was restored.
  function recordRestoreOnStart() {
    const note = readJson(RESTORE_NOTE());
    if (!note) {
      return;
    }
    fs.rmSync(RESTORE_NOTE(), { force: true });
    store.addAudit({ user: note.user, action: "BackupRestored", result: "Success", details: note.details, remoteIp: note.remoteIp });
    logger(`Portal state restored by ${note.user} at ${note.utc} is loaded.`);
  }

  clearRestartFlagOnStart();
  reconcileOnStart();
  recordRestoreOnStart();

  return {
    // freeze: stop every periodic save. restart: exit without saving so the service manager restarts it.
    setRuntime: (hooks) => Object.assign(runtime, hooks),
    restartRequired: () => state.restartRequired,
    preflight,
    start,
    operations: () => Object.entries(Operations).map(([type, definition]) => ({
      type,
      title: definition.title,
      summary: definition.summary,
      destructive: definition.destructive,
      selectsAgents: Boolean(definition.selectsAgents)
    })),
    resetScopes: () => Object.entries(ResetScopes).map(([key, group]) => ({ key, ...group })),
    current: () => view(busy()),
    history: () => state.history.map(view),
    job: (id) => view(state.current && state.current.id === id ? state.current : state.history.find((entry) => entry.id === id)),
    backups: backup.list,
    createBackup,
    restoreBackup,
    verifyBackup: (name) => {
      const entry = backup.list().find((item) => item.name === name || item.id === name);
      if (!entry) {
        throw new Error("That backup no longer exists.");
      }
      return backup.verify(entry.file);
    },
    setupRequired: () => operators.setupPending(),
    clearSetupRequired: () => { state.setupRequired = false; persist(); },
    Operations,
    JobStates
  };
}

module.exports = { createMaintenance, Operations, ResetScopes, JobStates };
