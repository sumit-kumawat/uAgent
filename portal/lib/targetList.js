"use strict";

// Parses target systems entered as free text or imported from CSV/Excel into classified entries:
// hostname, FQDN, IPv4 or IPv6. Free text accepts one entry per line or entries separated by commas,
// semicolons or whitespace. Duplicates are flagged against the first occurrence, never dropped.
const net = require("net");
const { readTable } = require("./tabular");

const MAX_ENTRIES = 50000;
const HOSTNAME = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;
const LABEL = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;

class TargetListError extends Error {
  constructor(message, status, field) {
    super(message);
    this.status = status || 400;
    this.code = status === 413 ? "too_large" : "invalid";
    this.field = field;
  }
}

function classify(value) {
  const input = String(value || "").trim().replace(/^\[|\]$/g, "");
  if (!input) {
    return { type: "invalid", issue: "Empty entry." };
  }
  const ipVersion = net.isIP(input);
  if (ipVersion === 4) {
    return { type: "ipv4", ip: input };
  }
  if (ipVersion === 6) {
    return { type: "ipv6", ip: input.toLowerCase() };
  }
  if (/^\d+(\.\d+){1,3}$/.test(input)) {
    return { type: "invalid", issue: "Not a valid IPv4 address." };
  }
  const name = input.replace(/\.$/, "").toLowerCase();
  if (name.length > 253) {
    return { type: "invalid", issue: "The name is longer than 253 characters." };
  }
  if (!name.includes(".")) {
    if (name.length > 15) {
      return HOSTNAME.test(name)
        ? { type: "hostname", hostname: name, warning: "Longer than 15 characters; Windows computer names are limited to 15." }
        : { type: "invalid", issue: "Not a valid host name." };
    }
    return HOSTNAME.test(name) ? { type: "hostname", hostname: name } : { type: "invalid", issue: "Not a valid host name." };
  }
  const labels = name.split(".");
  if (labels.every((l) => LABEL.test(l)) && !/^\d+$/.test(labels[labels.length - 1])) {
    return { type: "fqdn", fqdn: name, hostname: labels[0] };
  }
  return { type: "invalid", issue: "Not a valid FQDN." };
}

function entryKey(entry) {
  return entry.fqdn || entry.ip || entry.hostname || entry.input.toLowerCase();
}

function finish(raw) {
  if (raw.length > MAX_ENTRIES) {
    throw new TargetListError(`The list has more than ${MAX_ENTRIES} systems. Split it into smaller lists.`, 413);
  }
  const seen = new Map();
  return raw.map((item, index) => {
    const c = classify(item.value);
    const entry = {
      row: item.row || index + 1,
      input: String(item.value || "").trim().slice(0, 300),
      type: c.type,
      hostname: c.hostname || "",
      fqdn: c.fqdn || "",
      ip: c.ip || "",
      site: String(item.site || "").slice(0, 100),
      group: String(item.group || "").slice(0, 100),
      os: String(item.os || "").slice(0, 100),
      issues: c.issue ? [c.issue] : [],
      warnings: c.warning ? [c.warning] : [],
      duplicateOf: null
    };
    if (entry.type !== "invalid") {
      const key = entryKey(entry);
      if (seen.has(key)) {
        entry.duplicateOf = seen.get(key);
        entry.issues.push(`Duplicate of entry ${entry.duplicateOf}.`);
      } else {
        seen.set(key, entry.row);
      }
    }
    return entry;
  });
}

function fromText(text) {
  const values = String(text || "")
    .split(/[\s,;]+/)
    .map((v) => v.trim())
    .filter(Boolean);
  if (values.length === 0) {
    throw new TargetListError("Enter at least one host name, FQDN or IP address.", 400, "text");
  }
  return finish(values.map((value, i) => ({ value, row: i + 1 })));
}

// Each row may carry hostname, FQDN and IP columns; the most specific available value is the target.
function fromFile(buffer, fileName) {
  let table;
  try {
    table = readTable(buffer, fileName || "targets.csv");
  } catch (error) {
    throw new TargetListError(`The file could not be read: ${error.message}`, 400, "file");
  }
  if (table.records.length === 0) {
    throw new TargetListError("No rows were found. The first row must be a header with a hostname, FQDN or IP column.", 400, "file");
  }
  const raw = table.records.map((r) => {
    const fqdn = r.fqdn || r.dnsname || r.dns || "";
    const hostname = r.hostname || r.host || r.computername || r.computer || r.name || r.system || r.target || "";
    const ip = r.ip || r.ipaddress || r.address || r.ipv4 || r.ipv6 || "";
    return {
      value: fqdn || hostname || ip,
      ip,
      row: r.__row,
      site: r.site || r.lab || r.location || "",
      group: r.group || r.environment || r.department || "",
      os: r.os || r.operatingsystem || ""
    };
  });
  const entries = finish(raw);
  entries.forEach((entry, i) => {
    const extraIp = String(raw[i].ip || "").trim();
    if (!entry.ip && net.isIP(extraIp)) {
      entry.ip = extraIp;
    }
  });
  return entries;
}

module.exports = { fromText, fromFile, classify, TargetListError, MAX_ENTRIES };
