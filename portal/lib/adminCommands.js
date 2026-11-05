"use strict";

// Validates system administration commands before they are queued. The agent checks everything again;
// checking here gives the operator an immediate, specific error and keeps malformed requests off the queue.
// Every value becomes a string parameter. A domain password is returned separately as `secret`, which the
// store keeps only in memory and never returns or writes to disk.

const NETBIOS = /^(?![0-9]+$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$/;
const DNS_NAME = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;
const DNS_SUFFIX = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const SERVICE = /^[A-Za-z0-9_.\-$ ]{1,256}$/;
const PORTS = /^(?:Any|\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*)$/;
const ADDRESSES = /^(?:Any|LocalSubnet|[0-9A-Fa-f:./-]{2,49}(?:,[0-9A-Fa-f:./-]{2,49})*)$/;
const WORKGROUP = /^[A-Za-z0-9_-]{1,15}$/;
const PRINTABLE = /^[^\x00-\x1f\x7f]+$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9A-Fa-f:]{2,39}$/;

const PROTECTED_SERVICES = new Set(["uagent", "rpcss", "rpceptmapper", "dcomlaunch", "lsm", "samss", "bfe", "mpssvc", "nsi",
  "eventlog", "plugplay", "power", "gpsvc", "brokerinfrastructure", "systemeventsbroker", "coremessagingregistrar"]);

class Invalid extends Error {
  constructor(message, field) {
    super(message);
    this.field = field;
  }
}

const str = (v) => (v === undefined || v === null ? "" : String(v).trim());
const flag = (v) => v === true || v === "true";

function need(condition, message, field) {
  if (!condition) {
    throw new Invalid(message, field);
  }
}

function validPorts(value) {
  if (!PORTS.test(value)) {
    return false;
  }
  if (value === "Any") {
    return true;
  }
  return value.split(",").every((part) => {
    const [a, b] = part.split("-").map(Number);
    return a >= 1 && a <= 65535 && (b === undefined || (b >= a && b <= 65535));
  });
}

function credentials(p, secret, required) {
  const user = str(p.user);
  if (!required && !user && !secret) {
    return { user: "" };
  }
  need(user && user.length <= 256 && PRINTABLE.test(user), "Enter the domain account (DOMAIN\\user or user@domain).", "user");
  need(secret && secret.length <= 256, "Enter the password of the domain account.", "secret");
  return { user };
}

const validators = {
  ServiceControl(p) {
    const name = str(p.name);
    const action = str(p.action).toLowerCase();
    need(SERVICE.test(name), "Enter the service name (not the display name).", "name");
    need(["start", "stop", "restart"].includes(action), "The action must be start, stop or restart.", "action");
    need(action === "start" || !PROTECTED_SERVICES.has(name.toLowerCase()),
      `${name} is essential to Windows or to remote management and cannot be stopped from the portal.`, "name");
    return { parameters: { name, action }, summary: `${action[0].toUpperCase()}${action.slice(1)} service ${name}` };
  },

  ShutdownComputer() {
    return { parameters: {}, summary: "Shut down in 60 seconds" };
  },

  SetFirewallProfile(p) {
    const profile = str(p.profile);
    need(["Domain", "Private", "Public"].includes(profile), "The profile must be Domain, Private or Public.", "profile");
    const enabled = flag(p.enabled);
    return { parameters: { profile, enabled: String(enabled) }, summary: `Turn ${enabled ? "on" : "off"} the ${profile} firewall profile` };
  },

  FirewallRule(p) {
    const op = str(p.op).toLowerCase();
    need(["add", "update", "remove", "enable", "disable"].includes(op), "The operation must be add, update, remove, enable or disable.", "op");
    const parameters = { op };
    if (op !== "add") {
      const id = str(p.id);
      need(id && id.length <= 300 && PRINTABLE.test(id), "Choose the firewall rule.", "id");
      parameters.id = id;
    }
    if (op === "add" || op === "update") {
      const name = str(p.name);
      need(name && name.length <= 200 && PRINTABLE.test(name), "Give the rule a name of up to 200 characters.", "name");
      const direction = str(p.direction);
      const action = str(p.action);
      const protocol = str(p.protocol);
      need(["Inbound", "Outbound"].includes(direction), "Direction must be Inbound or Outbound.", "direction");
      need(["Allow", "Block"].includes(action), "Action must be Allow or Block.", "action");
      need(["TCP", "UDP", "Any", "ICMPv4", "ICMPv6"].includes(protocol), "Protocol must be TCP, UDP, ICMPv4, ICMPv6 or Any.", "protocol");
      const profiles = str(p.profile || "Any").split(",").map((s) => s.trim()).filter(Boolean);
      need(profiles.length > 0 && profiles.every((x) => ["Any", "Domain", "Private", "Public"].includes(x)) && !(profiles.includes("Any") && profiles.length > 1),
        "Profile must be Any, or one or more of Domain, Private and Public.", "profile");
      const ports = protocol === "TCP" || protocol === "UDP";
      const localPort = str(p.localPort).replace(/\s/g, "") || "Any";
      const remotePort = str(p.remotePort).replace(/\s/g, "") || "Any";
      if (ports) {
        need(validPorts(localPort), "Local port must be Any, a port (443), a range (5000-5100) or a list of those.", "localPort");
        need(validPorts(remotePort), "Remote port must be Any, a port, a range or a list of those.", "remotePort");
      } else {
        need(localPort === "Any" && remotePort === "Any", "Ports apply only to TCP and UDP rules.", "localPort");
      }
      const remoteAddress = str(p.remoteAddress).replace(/\s/g, "") || "Any";
      need(ADDRESSES.test(remoteAddress), "Remote address must be Any, LocalSubnet, or IP addresses, ranges or subnets, comma-separated.", "remoteAddress");
      const program = str(p.program);
      need(!program || (program.length <= 400 && PRINTABLE.test(program) && /^[A-Za-z]:\\/.test(program)), "The program must be a full path, for example C:\\Program Files\\App\\app.exe.", "program");
      Object.assign(parameters, { name, direction, action, protocol, profile: profiles.join(","), localPort, remotePort, remoteAddress, program });
      const what = `${action} ${direction.toLowerCase()} ${protocol}${ports && localPort !== "Any" ? ` ${localPort}` : ""}${remoteAddress !== "Any" ? ` from ${remoteAddress}` : ""}`;
      return { parameters, summary: `${op === "add" ? "Add" : "Update"} firewall rule "${name}" (${what})` };
    }
    const label = str(p.label).slice(0, 200) || parameters.id;
    return { parameters, summary: `${op[0].toUpperCase()}${op.slice(1)} firewall rule "${label}"` };
  },

  SetRemoteDesktop(p) {
    const enabled = flag(p.enabled);
    return { parameters: { enabled: String(enabled) }, summary: `${enabled ? "Enable" : "Disable"} Remote Desktop` };
  },

  SetNla(p) {
    const enabled = flag(p.enabled);
    return { parameters: { enabled: String(enabled) }, summary: `${enabled ? "Require" : "Stop requiring"} Network Level Authentication` };
  },

  SetHostname(p, secret) {
    const name = str(p.name);
    const dnsSuffix = str(p.dnsSuffix);
    need(NETBIOS.test(name), "The computer name must be 1-15 letters, digits or hyphens, not only digits, and must not start or end with a hyphen.", "name");
    need(!dnsSuffix || DNS_SUFFIX.test(dnsSuffix), "The DNS suffix must be a domain name such as corp.example.com.", "dnsSuffix");
    const { user } = credentials(p, secret, false);
    const restart = flag(p.restart);
    return {
      parameters: { name, dnsSuffix, user, restart: String(restart) },
      secret: user ? secret : null,
      summary: `Rename the computer to ${name}${dnsSuffix ? ` with DNS suffix ${dnsSuffix}` : ""}${restart ? " and restart" : ""}`
    };
  },

  SetDns(p) {
    const interfaceIndex = str(p.interfaceIndex);
    need(/^[1-9]\d{0,6}$/.test(interfaceIndex), "Choose the network adapter.", "interfaceIndex");
    const raw = str(p.servers);
    const list = raw.split(",").map((s) => s.trim()).filter(Boolean);
    const dhcp = list.length === 1 && list[0].toLowerCase() === "dhcp";
    need(dhcp || (list.length >= 1 && list.length <= 6 && list.every((s) => IPV4.test(s) || (s.includes(":") && IPV6.test(s)))),
      "Enter one to six DNS server IP addresses separated by commas, or \"dhcp\".", "servers");
    const setSearchList = flag(p.setSearchList);
    const suffixes = str(p.searchList).split(",").map((s) => s.trim()).filter(Boolean);
    need(!setSearchList || (suffixes.length <= 20 && suffixes.every((s) => DNS_SUFFIX.test(s))), "Search domains must be domain names separated by commas.", "searchList");
    const testHost = str(p.testHost);
    need(!testHost || DNS_NAME.test(testHost), "The test name must be a DNS name such as uagent.corp.example.com.", "testHost");
    return {
      parameters: { interfaceIndex, servers: dhcp ? "dhcp" : list.join(","), setSearchList: String(setSearchList), searchList: suffixes.join(","), testHost },
      summary: `Set DNS servers on adapter ${str(p.adapterName).slice(0, 100) || interfaceIndex} to ${dhcp ? "automatic (DHCP)" : list.join(", ")}${setSearchList ? `; search domains ${suffixes.join(", ") || "cleared"}` : ""}`
    };
  },

  JoinDomain(p, secret) {
    const domain = str(p.domain);
    need(DNS_NAME.test(domain), "Enter the domain's DNS name, for example corp.example.com.", "domain");
    const ouPath = str(p.ouPath);
    need(!ouPath || (ouPath.length <= 1024 && PRINTABLE.test(ouPath) && /DC=/i.test(ouPath)), "The OU must be a distinguished name such as OU=Workstations,DC=corp,DC=example,DC=com.", "ouPath");
    const { user } = credentials(p, secret, true);
    const restart = flag(p.restart);
    return {
      parameters: { domain, user, ouPath, restart: String(restart) },
      secret,
      summary: `Join domain ${domain} as ${user}${ouPath ? ` in ${ouPath}` : ""}${restart ? " and restart" : ""}`
    };
  },

  LeaveDomain(p, secret) {
    const workgroup = str(p.workgroup) || "WORKGROUP";
    need(WORKGROUP.test(workgroup), "The workgroup name must be 1-15 letters, digits, hyphens or underscores.", "workgroup");
    const { user } = credentials(p, secret, true);
    const restart = flag(p.restart);
    return {
      parameters: { user, workgroup, restart: String(restart) },
      secret,
      summary: `Leave the domain for workgroup ${workgroup}${restart ? " and restart" : ""}`
    };
  }
};

// Returns { parameters, secret, summary } or throws Invalid with a field name for the form.
function validate(commandType, params, secret) {
  const fn = validators[commandType];
  if (!fn) {
    throw new Invalid(`'${commandType}' is not a system administration command.`);
  }
  const result = fn(params && typeof params === "object" ? params : {}, typeof secret === "string" ? secret : "");
  return { parameters: result.parameters, secret: result.secret || null, summary: result.summary };
}

module.exports = { validate, Invalid, isAdminCommand: (type) => Object.prototype.hasOwnProperty.call(validators, type) };
