"use strict";

// Every remote action the portal can send to an agent. The agent reports which of these it
// supports (capabilities); the portal enforces the minimum role and confirmation rules.
const Roles = {
  Monitor: "Monitor",
  Operator: "Operator",
  Administrator: "Administrator"
};

const roleRank = { Monitor: 1, Operator: 2, Administrator: 3 };

function roleAllows(role, minRole) {
  return (roleRank[role] || 0) >= (roleRank[minRole] || Infinity);
}

const Catalog = {
  UnlockAccount: {
    label: "Unlock account",
    category: "account",
    minRole: Roles.Operator,
    sensitive: false,
    needsPassword: false,
    description: "Clears the lockout on the account."
  },
  EnableAccount: {
    label: "Enable account",
    category: "account",
    minRole: Roles.Operator,
    sensitive: false,
    needsPassword: false,
    description: "Re-enables a disabled account."
  },
  DisableAccount: {
    label: "Disable account",
    category: "account",
    minRole: Roles.Administrator,
    sensitive: true,
    needsPassword: false,
    description: "Disables the account so it can no longer sign in."
  },
  ResetPassword: {
    label: "Reset password",
    category: "account",
    minRole: Roles.Administrator,
    sensitive: true,
    needsPassword: true,
    description: "Sets a new password for the account."
  },
  PasswordNeverExpires: {
    label: "Set password never expires",
    category: "account",
    minRole: Roles.Administrator,
    sensitive: false,
    needsPassword: false,
    description: "Marks the password as non-expiring."
  },
  CannotChangePassword: {
    label: "Set user cannot change password",
    category: "account",
    minRole: Roles.Administrator,
    sensitive: false,
    needsPassword: false,
    description: "Prevents the user from changing their own password."
  },
  Ping: {
    label: "Test connection",
    category: "system",
    minRole: Roles.Operator,
    sensitive: false,
    needsPassword: false,
    description: "Round-trips a request through the agent and returns its response."
  },
  RefreshInventory: {
    label: "Refresh inventory",
    category: "system",
    minRole: Roles.Operator,
    sensitive: false,
    needsPassword: false,
    description: "Re-collects system details and the account inventory immediately."
  },
  CollectDiagnostics: {
    label: "Collect diagnostics",
    category: "system",
    minRole: Roles.Operator,
    sensitive: false,
    needsPassword: false,
    description: "Gathers OS, network, runtime, memory and disk details from the host."
  },
  RestartAgent: {
    label: "Restart agent service",
    category: "system",
    minRole: Roles.Administrator,
    sensitive: true,
    needsPassword: false,
    description: "Exits the uAgent service so Windows service recovery restarts it."
  },
  RestartComputer: {
    label: "Restart computer",
    category: "system",
    minRole: Roles.Administrator,
    sensitive: true,
    needsPassword: false,
    description: "Schedules a Windows restart in 60 seconds."
  },
  CancelRestart: {
    label: "Cancel restart",
    category: "system",
    minRole: Roles.Operator,
    sensitive: false,
    needsPassword: false,
    description: "Aborts a pending restart on the host."
  },
  UpdateAgent: {
    label: "Update agent",
    category: "system",
    minRole: Roles.Administrator,
    sensitive: true,
    needsPassword: false,
    description: "Downloads the current validated agent build and upgrades the service in place."
  },
  StopAgent: {
    label: "Stop agent service",
    category: "lifecycle",
    minRole: Roles.Administrator,
    sensitive: true,
    reauth: true,
    needsPassword: false,
    description: "Stops the uAgent service cleanly. It stays stopped until started on the host or Windows restarts."
  },
  RepairAgent: {
    label: "Repair agent",
    category: "lifecycle",
    minRole: Roles.Administrator,
    sensitive: true,
    reauth: true,
    needsPassword: false,
    description: "Re-applies the service start type, failure recovery, service and folder permissions and the firewall rule, and reports each step."
  },
  UninstallAgent: {
    label: "Uninstall agent",
    category: "lifecycle",
    minRole: Roles.Administrator,
    sensitive: true,
    reauth: true,
    needsPassword: false,
    description: "Deregisters the agent and removes the service, program files and credentials from the host."
  }
};

// Capability names that are not actions: they tell the portal which monitoring views an agent can serve.
const Features = ["LongPoll", "Inventory", "FileBrowse", "Integrity"];

const CommandTypes = Object.freeze(Object.keys(Catalog).reduce((acc, key) => {
  acc[key] = key;
  return acc;
}, {}));

// Agents older than 1.1 do not report capabilities; they only understand account commands.
const LegacyCapabilities = Object.keys(Catalog).filter((key) => Catalog[key].category === "account");

const CommandStatuses = {
  Pending: "Pending",
  Delivered: "Delivered",
  Success: "Success",
  Failed: "Failed",
  TimedOut: "TimedOut"
};

function isKnown(type) {
  return Object.prototype.hasOwnProperty.call(Catalog, type);
}

function requiresNewPassword(type) {
  return isKnown(type) && Catalog[type].needsPassword;
}

function isAccountCommand(type) {
  return isKnown(type) && Catalog[type].category === "account";
}

function requiresReauth(type) {
  return isKnown(type) && Boolean(Catalog[type].reauth);
}

module.exports = {
  Roles,
  roleAllows,
  Catalog,
  CommandTypes,
  CommandStatuses,
  LegacyCapabilities,
  Features,
  requiresReauth,
  isKnown,
  requiresNewPassword,
  isAccountCommand
};
