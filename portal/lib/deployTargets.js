"use strict";

// Target selection for deployments: sites (named IPv4 ranges used for per-site limits), saved groups
// (static lists or dynamic filters, also used as exclusion lists), and selector resolution. Rows are
// built from the raw agent records so paging through tens of thousands of agents stays cheap.
const crypto = require("crypto");
const net = require("net");
const { writeJson, readJson } = require("./statePath");

const CAPABILITY = "InstallSoftware";
const DEFAULT_SITE = "Default";

function parseCidr(text) {
  const [ip, bitsText] = String(text || "").trim().split("/");
  const bits = bitsText === undefined ? 32 : Number.parseInt(bitsText, 10);
  if (net.isIP(ip) !== 4 || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return null;
  }
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (ipToInt(ip) & mask) >>> 0, mask, text: `${intToIp((ipToInt(ip) & mask) >>> 0)}/${bits}` };
}

function ipToInt(ip) {
  return ip.split(".").reduce((acc, part) => ((acc << 8) + Number(part)) >>> 0, 0);
}

function intToIp(n) {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
}

function plainIp(value) {
  const ip = String(value || "").replace(/^::ffff:/, "");
  return net.isIP(ip) === 4 ? ip : "";
}

class TargetError extends Error {
  constructor(message, status, field) {
    super(message);
    this.status = status || 400;
    this.code = status === 404 ? "not_found" : "invalid";
    this.field = field;
  }
}

const CATEGORIES = new Set(["site", "lab", "environment", "department", "other"]);

function createDeployTargets(store, stateFileName, defaultHeartbeatSeconds) {
  const saved = readJson(stateFileName) || {};
  const settings = {
    sites: Array.isArray(saved.sites) ? saved.sites : [],
    maxConcurrent: saved.maxConcurrent || 50,
    perSiteConcurrent: saved.perSiteConcurrent || 20,
    defaultMaxAttempts: saved.defaultMaxAttempts || 3,
    agentHeartbeatSeconds: saved.agentHeartbeatSeconds || defaultHeartbeatSeconds || 15
  };
  let validationResolver = null;
  const groups = new Map(Array.isArray(saved.groups) ? saved.groups.map((g) => [g.id, g]) : []);
  let compiledSites = compileSites(settings.sites);

  function compileSites(sites) {
    return sites.map((s) => ({ name: s.name, ranges: s.cidrs.map(parseCidr).filter(Boolean) }));
  }

  function persist() {
    writeJson(stateFileName, { ...settings, groups: [...groups.values()] });
  }

  function siteOf(agent) {
    const ips = (agent.ipAddresses || []).map(plainIp).filter(Boolean);
    const remote = plainIp(agent.remoteIp);
    if (remote) {
      ips.push(remote);
    }
    for (const site of compiledSites) {
      for (const ip of ips) {
        const value = ipToInt(ip);
        if (site.ranges.some((r) => ((value & r.mask) >>> 0) === r.base)) {
          return site.name;
        }
      }
    }
    return DEFAULT_SITE;
  }

  function capable(agent) {
    return Array.isArray(agent.features) && agent.features.includes(CAPABILITY);
  }

  function row(agent) {
    return {
      agentId: agent.agentId,
      displayId: store.getDisplayId(agent.agentId),
      machineName: agent.machineName || "",
      dnsName: agent.dnsName || "",
      domainName: agent.domainName || "",
      osVersion: agent.osVersion || "",
      ipAddresses: Array.isArray(agent.ipAddresses) ? agent.ipAddresses : [],
      site: siteOf(agent),
      connection: store.isOnline(agent.agentId) ? "online" : "offline",
      agentVersion: agent.agentVersion || "",
      status: agent.status,
      canInstallSoftware: capable(agent)
    };
  }

  function normalizeFilter(filter) {
    const f = filter || {};
    return {
      q: String(f.q || "").trim().toLowerCase().slice(0, 200),
      domain: String(f.domain || "").trim().toLowerCase().slice(0, 200),
      os: String(f.os || "").trim().toLowerCase().slice(0, 200),
      site: String(f.site || "").trim().slice(0, 100),
      connection: ["online", "offline"].includes(f.connection) ? f.connection : "all",
      capable: Boolean(f.capable)
    };
  }

  function matches(agent, f) {
    if (f.domain && String(agent.domainName || "").toLowerCase() !== f.domain) {
      return false;
    }
    if (f.os && !String(agent.osVersion || "").toLowerCase().includes(f.os)) {
      return false;
    }
    if (f.site && siteOf(agent) !== f.site) {
      return false;
    }
    if (f.connection !== "all" && (store.isOnline(agent.agentId) ? "online" : "offline") !== f.connection) {
      return false;
    }
    if (f.capable && !capable(agent)) {
      return false;
    }
    if (f.q) {
      const haystack = [store.getDisplayId(agent.agentId), agent.machineName, agent.dnsName, agent.domainName, agent.osVersion, (agent.ipAddresses || []).join(" ")]
        .join(" ").toLowerCase();
      if (!haystack.includes(f.q)) {
        return false;
      }
    }
    return true;
  }

  function queryAgents(query) {
    const f = normalizeFilter(query);
    const page = Math.max(Number.parseInt(query.page, 10) || 1, 1);
    const pageSize = Math.min(Math.max(Number.parseInt(query.pageSize, 10) || 50, 1), 500);
    const domains = new Set();
    const sites = new Set(settings.sites.map((s) => s.name).concat(DEFAULT_SITE));
    const os = new Set();
    const hits = [];
    for (const agent of store.agents.values()) {
      if (agent.domainName) {
        domains.add(agent.domainName.toLowerCase());
      }
      if (agent.osVersion) {
        os.add(agent.osVersion);
      }
      if (matches(agent, f)) {
        hits.push(agent);
      }
    }
    hits.sort((a, b) => a.agentNumber - b.agentNumber);
    return {
      total: hits.length,
      page,
      pageSize,
      rows: hits.slice((page - 1) * pageSize, page * pageSize).map(row),
      facets: { domains: [...domains].sort(), sites: [...sites].sort(), os: [...os].sort() }
    };
  }

  function groupMembers(group) {
    if (group.type === "static") {
      return group.agentIds.filter((id) => store.agents.has(id));
    }
    const f = normalizeFilter(group.filter);
    const ids = [];
    for (const agent of store.agents.values()) {
      if (matches(agent, f)) {
        ids.push(agent.agentId);
      }
    }
    return ids;
  }

  // Resolves a selector to a de-duplicated list of agent ids, in agent number order.
  function resolve(selector) {
    const s = selector || {};
    const chosen = new Set();
    const addAll = (ids) => ids.forEach((id) => { if (store.agents.has(id)) { chosen.add(id); } });
    switch (s.mode) {
      case "all":
        addAll([...store.agents.keys()]);
        break;
      case "filter": {
        const f = normalizeFilter(s.filter);
        addAll([...store.agents.values()].filter((a) => matches(a, f)).map((a) => a.agentId));
        break;
      }
      case "agents":
        addAll(Array.isArray(s.agentIds) ? s.agentIds.map(String) : []);
        break;
      case "validation":
        if (!validationResolver) {
          throw new TargetError("Target validation is not available.", 400, "selector.validationId");
        }
        try {
          addAll(validationResolver(String(s.validationId || "")));
        } catch (error) {
          throw new TargetError(error.message, error.status === 404 ? 400 : error.status || 400, "selector.validationId");
        }
        break;
      case "groups":
        for (const id of Array.isArray(s.groupIds) ? s.groupIds : []) {
          const group = groups.get(id);
          if (!group) {
            throw new TargetError("A selected group no longer exists.", 400, "selector.groupIds");
          }
          addAll(groupMembers(group));
        }
        break;
      default:
        throw new TargetError("Choose how to select target systems.", 400, "selector.mode");
    }
    const excluded = new Set(Array.isArray(s.excludeAgentIds) ? s.excludeAgentIds.map(String) : []);
    for (const id of Array.isArray(s.excludeGroupIds) ? s.excludeGroupIds : []) {
      const group = groups.get(id);
      if (group) {
        groupMembers(group).forEach((member) => excluded.add(member));
      }
    }
    const result = [...chosen].filter((id) => !excluded.has(id));
    result.sort((a, b) => store.agents.get(a).agentNumber - store.agents.get(b).agentNumber);
    return { agentIds: result, excludedCount: chosen.size - result.length };
  }

  function groupView(g) {
    return { id: g.id, name: g.name, description: g.description, category: g.category || "other", type: g.type, agentIds: g.type === "static" ? g.agentIds : [], filter: g.type === "dynamic" ? g.filter : null, memberCount: groupMembers(g).length, createdBy: g.createdBy, updatedUtc: g.updatedUtc };
  }

  function validateGroup(input, existing) {
    const name = String(input.name !== undefined ? input.name : existing && existing.name || "").trim().slice(0, 100);
    if (!name) {
      throw new TargetError("Enter a group name.", 400, "name");
    }
    const duplicate = [...groups.values()].find((g) => g.name.toLowerCase() === name.toLowerCase() && (!existing || g.id !== existing.id));
    if (duplicate) {
      throw new TargetError(`A group named ${name} already exists.`, 400, "name");
    }
    const type = input.type || (existing && existing.type);
    if (type !== "static" && type !== "dynamic") {
      throw new TargetError("Choose a static or dynamic group.", 400, "type");
    }
    const agentIds = type === "static"
      ? [...new Set((Array.isArray(input.agentIds) ? input.agentIds : existing ? existing.agentIds : []).map(String))].filter((id) => store.agents.has(id)).slice(0, 100000)
      : [];
    if (type === "static" && agentIds.length === 0) {
      throw new TargetError("Select at least one agent for a static group.", 400, "agentIds");
    }
    const filter = type === "dynamic" ? normalizeFilter(input.filter !== undefined ? input.filter : existing && existing.filter) : null;
    const requested = input.category !== undefined ? input.category : existing && existing.category;
    const category = CATEGORIES.has(requested) ? requested : "other";
    return { name, category, description: String(input.description !== undefined ? input.description : existing && existing.description || "").trim().slice(0, 300), type, agentIds, filter };
  }

  function createGroup(input, user) {
    const fields = validateGroup(input || {}, null);
    const group = { id: crypto.randomUUID(), ...fields, createdBy: user.name, updatedUtc: new Date().toISOString() };
    groups.set(group.id, group);
    persist();
    store.addAudit({ user: user.name, action: "TargetGroupCreated", result: "Success", details: `Created ${group.type} group ${group.name}.` });
    return groupView(group);
  }

  function updateGroup(id, input, user) {
    const group = groups.get(id);
    if (!group) {
      throw new TargetError("The group was not found.", 404);
    }
    Object.assign(group, validateGroup(input || {}, group), { updatedUtc: new Date().toISOString() });
    persist();
    store.addAudit({ user: user.name, action: "TargetGroupUpdated", result: "Success", details: `Updated group ${group.name}.` });
    return groupView(group);
  }

  function deleteGroup(id, user) {
    const group = groups.get(id);
    if (!group) {
      throw new TargetError("The group was not found.", 404);
    }
    groups.delete(id);
    persist();
    store.addAudit({ user: user.name, action: "TargetGroupDeleted", result: "Success", details: `Deleted group ${group.name}.` });
  }

  function updateSettings(input, user) {
    const sites = [];
    const names = new Set();
    for (const raw of Array.isArray(input.sites) ? input.sites.slice(0, 500) : []) {
      const name = String(raw.name || "").trim().slice(0, 100);
      if (!name) {
        continue;
      }
      if (name === DEFAULT_SITE || names.has(name.toLowerCase())) {
        throw new TargetError(`Site names must be unique and cannot be "${DEFAULT_SITE}".`, 400, "sites");
      }
      const cidrs = (Array.isArray(raw.cidrs) ? raw.cidrs : String(raw.cidrs || "").split(/[\s,;]+/)).map((c) => String(c).trim()).filter(Boolean);
      const parsed = cidrs.map(parseCidr);
      const bad = cidrs.filter((c, i) => !parsed[i]);
      if (bad.length || cidrs.length === 0) {
        throw new TargetError(`Site ${name} needs IPv4 ranges such as 10.20.0.0/16${bad.length ? `; not valid: ${bad.join(", ")}` : ""}.`, 400, "sites");
      }
      names.add(name.toLowerCase());
      sites.push({ name, cidrs: parsed.map((p) => p.text) });
    }
    const clamp = (v, min, max, d) => {
      const n = Number.parseInt(v, 10);
      return Number.isFinite(n) ? Math.min(Math.max(n, min), max) : d;
    };
    settings.sites = sites;
    settings.maxConcurrent = clamp(input.maxConcurrent, 1, 5000, settings.maxConcurrent);
    settings.perSiteConcurrent = clamp(input.perSiteConcurrent, 1, 5000, settings.perSiteConcurrent);
    settings.defaultMaxAttempts = clamp(input.defaultMaxAttempts, 1, 10, settings.defaultMaxAttempts);
    settings.agentHeartbeatSeconds = clamp(input.agentHeartbeatSeconds, 5, 300, settings.agentHeartbeatSeconds);
    compiledSites = compileSites(sites);
    persist();
    store.addAudit({ user: user.name, action: "DeploymentSettingsUpdated", result: "Success", details: `${sites.length} site(s); ${settings.maxConcurrent} concurrent installs, ${settings.perSiteConcurrent} per site; ${settings.defaultMaxAttempts} attempt(s); agent heartbeat ${settings.agentHeartbeatSeconds}s.` });
    return getSettings();
  }

  function getSettings() {
    return { sites: settings.sites, maxConcurrent: settings.maxConcurrent, perSiteConcurrent: settings.perSiteConcurrent, defaultMaxAttempts: settings.defaultMaxAttempts, agentHeartbeatSeconds: settings.agentHeartbeatSeconds };
  }

  return {
    TargetError,
    CAPABILITY,
    siteOf,
    capable,
    row,
    queryAgents,
    resolve,
    listGroups: () => [...groups.values()].map(groupView).sort((a, b) => a.name.localeCompare(b.name)),
    createGroup,
    updateGroup,
    deleteGroup,
    getSettings,
    updateSettings,
    setValidationResolver: (fn) => { validationResolver = fn; }
  };
}

module.exports = { createDeployTargets, parseCidr };
