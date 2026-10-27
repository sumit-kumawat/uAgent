"use strict";

const { Catalog, Roles, roleAllows, ToggleLabels, commandLabel } = require("./commandTypes");

// Account inventory older than this is shown as stale; the agent still verifies the real state before changing it.
const MIN_STALE_MS = 5 * 60 * 1000;

const Icons = {
  UnlockAccount: "bi-unlock",
  EnableAccount: "bi-person-check",
  DisableAccount: "bi-person-slash",
  ResetPassword: "bi-key",
  PasswordNeverExpires: "bi-calendar-x",
  CannotChangePassword: "bi-shield-lock",
  Ping: "bi-broadcast",
  RefreshInventory: "bi-arrow-repeat",
  CollectDiagnostics: "bi-clipboard2-pulse",
  RestartAgent: "bi-bootstrap-reboot",
  RestartComputer: "bi-power",
  CancelRestart: "bi-x-octagon",
  UpdateAgent: "bi-arrow-up-circle",
  StopAgent: "bi-stop-circle",
  RepairAgent: "bi-tools"
};

const SystemOrder = ["Ping", "RefreshInventory", "CollectDiagnostics", "CancelRestart", "RestartComputer", "RestartAgent", "UpdateAgent", "RepairAgent", "StopAgent"];

function sameName(a, b) {
  return String(a || "").trim().toLowerCase() === String(b || "").trim().toLowerCase();
}

function findAccount(report, samAccountName, source) {
  if (!report || !samAccountName) {
    return null;
  }
  const matches = report.accounts.filter((a) => sameName(a.samAccountName, samAccountName));
  return matches.find((a) => !source || a.source === source) || matches[0] || null;
}

function staleAfterMs(agent) {
  const poll = Number(agent && agent.pollIntervalSeconds) || 0;
  return Math.max(MIN_STALE_MS, poll * 3 * 1000);
}

// How old the account data is: the newer of the last inventory and the last verified change.
function accountAge(report, account) {
  const times = [report && report.timestampUtc, account && account.verifiedUtc]
    .filter(Boolean)
    .map((t) => new Date(t).getTime())
    .filter((t) => !Number.isNaN(t));
  return times.length ? Date.now() - Math.max(...times) : Infinity;
}

// The account actions that make sense for the account's current state. Toggles carry the value to apply.
function accountActionsFor(account, features) {
  const toggles = features.includes("AccountToggles");
  const actions = [];
  if (account.lockedOut) {
    actions.push({ type: "UnlockAccount" });
  }
  actions.push({ type: account.enabled ? "DisableAccount" : "EnableAccount" });
  actions.push({ type: "ResetPassword" });

  if (!account.passwordNeverExpires) {
    actions.push({ type: "PasswordNeverExpires", value: true });
  } else if (toggles) {
    actions.push({ type: "PasswordNeverExpires", value: false });
  } else {
    actions.push({ type: "PasswordNeverExpires", value: false, unsupported: "Update the agent to turn this setting off." });
  }

  if (account.userCannotChangePassword === true) {
    actions.push(toggles
      ? { type: "CannotChangePassword", value: false }
      : { type: "CannotChangePassword", value: false, unsupported: "Update the agent to turn this setting off." });
  } else {
    actions.push({ type: "CannotChangePassword", value: true });
  }
  return actions;
}

// Server-side guard for a requested account change. Returns null when it may be queued.
// With stale data the state checks are skipped: the agent verifies the real state and reports "no change".
function checkAccountChange({ report, account, commandType, value, features, agent }) {
  if (!report) {
    return { status: 409, code: "no_inventory", error: "No account inventory has been received from this agent yet. Refresh the inventory first." };
  }
  if (!account) {
    return { status: 409, code: "unknown_account", error: "That account is not in the agent's latest inventory. Refresh the inventory and try again." };
  }
  const toggle = Boolean(ToggleLabels[commandType]);
  if (toggle && value === false && !features.includes("AccountToggles")) {
    return { status: 409, code: "unsupported", error: "This agent version can only turn the setting on. Update the agent to turn it off." };
  }
  if (accountAge(report, account) > staleAfterMs(agent)) {
    return null;
  }
  const name = account.samAccountName;
  const noChange = (what) => ({ status: 409, code: "no_change", error: `'${name}' ${what}. Nothing to change.` });
  switch (commandType) {
    case "UnlockAccount": return account.lockedOut ? null : noChange("is not locked out");
    case "EnableAccount": return account.enabled ? noChange("is already enabled") : null;
    case "DisableAccount": return account.enabled ? null : noChange("is already disabled");
    case "PasswordNeverExpires":
      return account.passwordNeverExpires === (value !== false)
        ? noChange(value !== false ? "already has a password that never expires" : "already has a password that expires")
        : null;
    case "CannotChangePassword":
      return account.userCannotChangePassword !== null && account.userCannotChangePassword === (value !== false)
        ? noChange(value !== false ? "already cannot change its password" : "can already change its password")
        : null;
    default:
      return null;
  }
}

function describe(type, value) {
  const toggle = ToggleLabels[type];
  const meta = Catalog[type];
  const text = toggle ? toggle[value === false ? "false" : "true"] : { label: meta.label, description: meta.description };
  return {
    type,
    value: toggle ? value !== false : null,
    label: text.label,
    description: text.description,
    icon: Icons[type] || "bi-lightning",
    sensitive: Boolean(meta.sensitive),
    reauth: Boolean(meta.reauth),
    needsPassword: Boolean(meta.needsPassword),
    minRole: meta.minRole
  };
}

// Builds the single control panel for one agent and, optionally, one of its accounts. Only actions the
// signed-in user may run and the agent supports are listed; each carries its availability and reason.
function buildPanel(store, agentId, role, options) {
  const opts = options || {};
  const detail = store.getAgentDetail(agentId);
  const report = store.getReport(agentId);
  const capabilities = new Set(store.capabilitiesOf(agentId));
  const features = store.getFeatures(agentId);
  const active = store.activeCommands(agentId);
  const removal = detail.removal;
  const isActive = detail.status === "Active";
  const online = detail.online && isActive;

  function availability(action, accountName) {
    if (removal) {
      return { state: "blocked", reason: "The agent is being removed." };
    }
    if (!isActive) {
      return { state: "blocked", reason: detail.status === "PendingApproval" ? "Approve the agent first." : "The agent's credential is revoked." };
    }
    const running = active.find((c) => c.commandType === action.type &&
      (accountName === undefined ? !c.samAccountName : sameName(c.samAccountName, accountName)));
    if (running) {
      return { state: "running", reason: `${running.label} is ${running.status === "Pending" ? "queued" : "running on the computer"}.`, commandId: running.commandId };
    }
    if (accountName !== undefined) {
      const other = active.find((c) => c.samAccountName && sameName(c.samAccountName, accountName));
      if (other) {
        return { state: "blocked", reason: `Wait for ${other.label.toLowerCase()} to finish on this account.` };
      }
    }
    if (action.unsupported) {
      return { state: "unsupported", reason: action.unsupported };
    }
    if (!online) {
      return { state: "offline", reason: "The agent is offline. Actions are available again when it reconnects." };
    }
    return { state: "available", reason: "" };
  }

  let account = null;
  let accountActions = [];
  if (opts.account) {
    const found = findAccount(report, opts.account, opts.source);
    if (found) {
      const age = accountAge(report, found);
      account = {
        ...store.constructor.accountView(found),
        dataAgeMs: Number.isFinite(age) ? age : null,
        stale: age > staleAfterMs(detail),
        verifiedUtc: found.verifiedUtc || null
      };
      accountActions = accountActionsFor(found, features)
        .filter((a) => capabilities.has(a.type) && roleAllows(role, Catalog[a.type].minRole))
        .map((a) => ({ ...describe(a.type, a.value), ...availability(a, found.samAccountName) }));
    }
  }

  const system = SystemOrder
    .filter((type) => capabilities.has(type) && roleAllows(role, Catalog[type].minRole))
    .map((type) => ({ ...describe(type), category: Catalog[type].category, ...availability({ type }) }));

  const admin = [];
  if (role === Roles.Administrator) {
    if (detail.status === "PendingApproval") {
      admin.push({ action: "approve", label: "Approve agent", icon: "bi-check2-circle", description: "Lets this agent receive actions." });
    }
    if (detail.status === "Revoked") {
      admin.push({ action: "approve", label: "Reinstate agent", icon: "bi-check2-circle", description: "Restores the agent's credential." });
    } else {
      admin.push({ action: "revoke", label: "Revoke credential", icon: "bi-slash-circle", danger: true, description: "Stops the agent communicating until it is reinstated." });
    }
    admin.push({ action: "rotate-key", label: "Rotate credential", icon: "bi-key", description: "Issues a new agent key at the next check-in." });
    const canUninstall = capabilities.has("UninstallAgent") && isActive;
    if (!removal) {
      admin.push(canUninstall
        ? { action: "remove", label: "Remove agent", icon: "bi-trash3", danger: true, description: "Uninstalls the agent from the computer, verifies it, then removes it from the portal." }
        : { action: "remove-record", label: "Remove record", icon: "bi-trash3", danger: true, description: detail.status !== "Active"
          ? "This agent cannot receive an uninstall command. Removes the record only; uninstall it on the computer."
          : "This agent cannot uninstall itself (it is not running as the Windows service or is an older version). Removes the record only." });
    } else {
      if (removal.state !== "Uninstalling") {
        admin.push({ action: "cancel-removal", label: removal.state === "Queued" ? "Cancel removal" : "Clear removal", icon: "bi-arrow-counterclockwise", description: "Keeps the agent." });
      }
      if (removal.state === "Failed" || removal.state === "Unverified") {
        admin.push({ action: "remove-record", label: "Remove record", icon: "bi-trash3", danger: true, description: "Removes the record without confirmation from the computer. The agent re-registers if it is still installed." });
      }
    }
  }

  const accounts = report ? report.accounts.map((a) => ({ samAccountName: a.samAccountName, source: a.source, enabled: a.enabled, lockedOut: a.lockedOut })) : [];

  return {
    agent: {
      agentId: detail.agentId,
      displayId: detail.displayId,
      machineName: detail.machineName,
      online: detail.online,
      connection: detail.connection,
      status: detail.status,
      lastSeenUtc: detail.lastSeenUtc,
      inventoryUtc: detail.inventoryUtc,
      agentVersion: detail.agentVersion,
      removal
    },
    role,
    accounts,
    account,
    accountMissing: Boolean(opts.account) && !account,
    accountActions,
    system,
    admin,
    active: active.map((c) => ({ commandId: c.commandId, label: c.label, samAccountName: c.samAccountName, status: c.status, createdUtc: c.createdUtc })),
    staleAfterSeconds: Math.round(staleAfterMs(detail) / 1000)
  };
}

module.exports = { buildPanel, checkAccountChange, findAccount, commandLabel };
