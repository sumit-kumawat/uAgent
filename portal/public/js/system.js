// System tab on the agent page: identity, network, sessions and logins, Remote Desktop, firewall, services,
// power and events, with administrator controls. Every change is confirmed in the shared action dialog
// (reason, typed computer name, the administrator's password) and is tracked until the agent reports back.
(function () {
  "use strict";
  const U = window.uAgent;
  const root = document.getElementById("agentRoot");
  if (!root || !document.getElementById("pane-system")) {
    return;
  }
  const agentKey = root.getAttribute("data-agent-key");
  const $ = function (id) { return document.getElementById(id); };
  const esc = U.escapeHtml;

  const PROTECTED_SERVICES = ["uagent", "rpcss", "rpceptmapper", "dcomlaunch", "lsm", "samss", "bfe", "mpssvc", "nsi",
    "eventlog", "plugplay", "power", "gpsvc", "brokerinfrastructure", "systemeventsbroker", "coremessagingregistrar"];
  const UNUSED_DAYS = 90;
  const LOGON_TYPES = { 2: "Console", 3: "Network", 7: "Unlock", 10: "Remote Desktop", 11: "Cached credentials" };
  const FAILURE_REASONS = {
    "0xC000006A": "Wrong password", "0xC0000064": "Unknown user name", "0xC000006D": "Bad user name or password",
    "0xC0000234": "Account locked out", "0xC0000072": "Account disabled", "0xC000006F": "Outside allowed hours",
    "0xC0000070": "Workstation not allowed", "0xC0000071": "Password expired", "0xC0000193": "Account expired",
    "0xC0000133": "Clock out of sync with the domain controller", "0xC0000224": "Password must be changed",
    "0xC000015B": "Logon type not granted", "0xC000005E": "No logon server available"
  };
  const POWER_EVENTS = {
    41: "Restarted without a clean shutdown (power loss, crash or hang)", 1074: "Shutdown or restart requested",
    1076: "Reason given for an unexpected shutdown", 6005: "Started (event log service started)",
    6006: "Clean shutdown (event log service stopped)", 6008: "Previous shutdown was unexpected"
  };

  let agentState = null;
  let role = "";
  let entry = null;
  let services = null;
  let metrics = null;
  let view = "identity";
  let requested = false;
  let collecting = false;
  let probe = null;
  let loadedOnce = false;
  let fetching = false;
  const filters = { rules: "", ruleDirection: "", ruleShow: "all", services: "", serviceStatus: "" };

  function agent() { return agentState ? agentState.agent : null; }
  function snap() { return entry && entry.data ? entry.data : null; }
  function supported() { const a = agent(); return Boolean(a && (a.features || []).includes("SystemAdmin")); }
  function list(v) { return Array.isArray(v) ? v : []; }
  function dash(v) { return v === null || v === undefined || v === "" ? '<span class="subtle">\u2014</span>' : esc(String(v)); }
  function when(v) { return v ? esc(U.formatDateTime(v)) + ' <span class="subtle">(' + esc(U.relativeTime(v)) + ")</span>" : '<span class="subtle">Never</span>'; }
  function pill(tone, label) { return U.pill(tone, label, true); }
  function ms(v) { const t = v ? Date.parse(v) : NaN; return Number.isFinite(t) ? t : 0; }
  function shortName(user) { return String(user || "").split("\\").pop().split("@")[0].toLowerCase(); }
  function catalog(type) {
    const found = U.me && Array.isArray(U.me.catalog) ? U.me.catalog.find(function (c) { return c.type === type; }) : null;
    return found || { type: type, label: type, description: "", category: "admin", minRole: "Administrator", sensitive: true, reauth: true, needsPassword: false };
  }

  function activeAdmin() {
    return agentState ? agentState.commands.find(function (c) { return c.category === "admin" && (c.status === "Pending" || c.status === "Delivered"); }) : null;
  }

  // Why a control is unavailable, or "" when it can be used.
  function blocked(type) {
    const a = agent();
    const meta = catalog(type);
    if (meta.allowed === false || (meta.category === "admin" && role !== "Administrator")) { return "This action requires the " + (meta.minRole || "Administrator") + " role."; }
    if (!a || a.status !== "Active") { return "The agent is not approved."; }
    if (!a.online) { return "The agent is offline."; }
    if (!(a.capabilities || []).includes(type)) { return "This agent version does not support this action."; }
    const busy = activeAdmin();
    if (busy && type !== "RestartComputer" && type !== "CancelRestart") { return (busy.summary || busy.label) + " is still running."; }
    return "";
  }

  function button(type, label, attrs, tone) {
    const why = blocked(type);
    return '<button type="button" class="btn btn-sm ' + (tone || "btn-outline-secondary") + '"' + (why ? ' disabled title="' + esc(why) + '"' : "") +
      " " + attrs + ">" + label + "</button>";
  }

  // --- Data -------------------------------------------------------------------------------------
  async function fetchSection(section) {
    try {
      return await U.api("/api/agents/" + encodeURIComponent(agentKey) + "/inventory/" + section);
    } catch (error) {
      return { data: null, error: error.message, receivedUtc: null };
    }
  }

  async function load() {
    if (fetching || !supported()) {
      return;
    }
    fetching = true;
    try {
      const results = await Promise.all([fetchSection("admin"), fetchSection("services"), fetchSection("system")]);
      entry = results[0];
      services = results[1];
      metrics = results[2];
      if (entry && entry.data) {
        collecting = false;
      }
      if (!entry.data && !requested && agent() && agent().online) {
        requested = true;
        collect(true);
      }
    } finally {
      fetching = false;
    }
    render();
  }

  async function collect(quiet) {
    const base = "/api/agents/" + encodeURIComponent(agentKey) + "/inventory/";
    collecting = true;
    renderHeader();
    try {
      await U.api(base + "admin/refresh", { method: "POST", body: {} });
      U.api(base + "services/refresh", { method: "POST", body: {} }).catch(function () {});
      if (!quiet) { U.notify("Collecting system information from " + (agent().machineName || agentKey) + "\u2026", "info"); }
    } catch (error) {
      collecting = false;
      if (!quiet) { U.notify(error.message || "Could not request the information.", "danger"); }
      renderHeader();
    }
  }

  // --- Running a change -------------------------------------------------------------------------
  function run(type, parameters, summary, warning, secret) {
    const meta = catalog(type);
    const description = summary + "." + (warning ? " " + warning : "");
    U.runAction({
      agentKey: agentKey,
      machineName: agent().machineName || agentKey,
      control: {
        type: type, label: meta.label, description: description, sensitive: true, reauth: true,
        needsPassword: false, category: "admin", parameters: parameters, secret: secret || null
      },
      onQueued: function () { render(); },
      onUpdate: function (latest) { if (U.isTerminal(latest.status)) { load(); } }
    });
  }

  function runExisting(type) {
    const meta = catalog(type);
    U.runAction({
      agentKey: agentKey,
      machineName: agent().machineName || agentKey,
      control: meta,
      onQueued: function () { render(); }
    });
  }

  function form(def) { U.formDialog(def); }

  // --- Rendering --------------------------------------------------------------------------------
  function renderTab() {
    const a = agent();
    const item = $("tabSystemItem");
    if (!a || !item) {
      return;
    }
    // Shown for every agent that reports inventory, so an outdated agent explains what is missing.
    item.hidden = !((a.features || []).includes("Inventory") || supported());
  }

  function renderHeader() {
    const s = snap();
    let text = collecting ? "Collecting\u2026" : "Not collected yet";
    if (s && entry.collectedUtc && !collecting) {
      text = "Collected " + U.relativeTime(entry.collectedUtc).toLowerCase() + (s.collectMs ? " in " + (s.collectMs / 1000).toFixed(1) + " s" : "");
    }
    $("sysCollected").textContent = text;
    const a = agent();
    const refresh = $("sysRefresh");
    refresh.disabled = collecting || !a || !a.online || !supported();
    refresh.title = a && !a.online ? "The agent is offline; showing the last data received." : "";
  }

  function renderBanners() {
    const items = [];
    const a = agent();
    const busy = activeAdmin();
    if (busy) {
      items.push('<div class="banner banner-info"><span class="spinner-border spinner-border-sm" aria-hidden="true"></span><div><strong>' + esc(busy.label) + "</strong> " +
        esc(busy.summary || "") + " \u2014 " + (busy.status === "Pending" ? "waiting for the agent to collect it." : "running on the computer.") +
        " Other system changes are held until it finishes.</div></div>");
    }
    if (entry && entry.error) {
      items.push('<div class="banner banner-warning"><i class="bi bi-exclamation-triangle"></i><div>The last collection failed: ' + esc(entry.error) + "</div></div>");
    }
    const s = snap();
    if (s && list(s.errors).length) {
      items.push('<div class="banner banner-warning"><i class="bi bi-exclamation-triangle"></i><div>Some information could not be read: ' +
        esc(list(s.errors).map(function (e) { return typeof e === "string" ? e : (e.part || "") + ": " + (e.error || e.message || ""); }).join("; ")) + "</div></div>");
    }
    if (a && !a.online && s) {
      items.push('<div class="banner banner-info"><i class="bi bi-wifi-off"></i><div>The agent is offline. This is the information received ' + esc(U.relativeTime(entry.collectedUtc).toLowerCase()) + "; changes are unavailable.</div></div>");
    }
    if (role && role !== "Administrator" && s) {
      items.push('<div class="banner banner-info"><i class="bi bi-eye"></i><div>System changes require the Administrator role. You can view this information.</div></div>');
    }
    $("sysBanner").innerHTML = items.join("");
  }

  function render() {
    renderTab();
    if (!agent()) {
      return;
    }
    renderHeader();
    document.querySelectorAll("[data-sys-view]").forEach(function (b) { b.classList.toggle("active", b.getAttribute("data-sys-view") === view); });
    const body = $("sysBody");
    if (!supported()) {
      const a = agent();
      $("sysBanner").innerHTML = "";
      body.innerHTML = '<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>' +
        (a.serviceMode === "Console"
          ? "System administration is available when the agent runs as the uAgent Windows service. It is running in a console session."
          : "This agent does not report system administration data. Update it to version 1.6 or later from the <strong>Control panel</strong> to see sessions, firewall, Remote Desktop, DNS and domain settings.") +
        "</div></div>";
      return;
    }
    renderBanners();
    if (!snap()) {
      body.innerHTML = '<p class="subtle mb-0">' + (collecting ? "Collecting system information from the computer\u2026 this takes up to a minute."
        : agent().online ? "No system information has been received yet. Select <strong>Collect now</strong>." : "No system information has been received and the agent is offline.") + "</p>";
      return;
    }
    const scroll = body.scrollTop;
    const focus = document.activeElement && document.activeElement.id;
    body.innerHTML = ({ identity: identityView, activity: activityView, rdp: rdpView, firewall: firewallView, services: servicesView, events: eventsView }[view] || identityView)();
    body.scrollTop = scroll;
    if (focus && $(focus) && body.contains($(focus))) {
      const input = $(focus);
      input.focus();
      if (typeof input.value === "string" && input.setSelectionRange) { input.setSelectionRange(input.value.length, input.value.length); }
    }
  }

  function table(headers, rows, empty) {
    return '<div class="table-responsive"><table class="data-table"><thead><tr>' + headers.map(function (h) { return "<th>" + h + "</th>"; }).join("") +
      "</tr></thead><tbody>" + (rows.length ? rows.join("") : '<tr><td colspan="' + headers.length + '" class="empty">' + empty + "</td></tr>") + "</tbody></table></div>";
  }

  function panel(title, inner, actions) {
    return '<div class="info-panel"><h3>' + title + (actions ? '<span class="sys-actions">' + actions + "</span>" : "") + "</h3>" + inner + "</div>";
  }

  function kv(pairs) {
    return '<dl class="kv">' + pairs.filter(Boolean).map(function (p) { return "<dt>" + p[0] + "</dt><dd>" + p[1] + "</dd>"; }).join("") + "</dl>";
  }

  function section(title, inner, actions) {
    return '<div class="sys-section"><div class="sys-section-head"><h3 class="section-title mb-0">' + title + "</h3>" + (actions || "") + "</div>" + inner + "</div>";
  }

  // Identity, operating system, hardware, network and DNS.
  function identityView() {
    const s = snap();
    const c = s.computer || {};
    const a = agent();
    const m = metrics && metrics.data ? metrics.data : {};
    const memUsed = c.totalMemoryBytes ? c.totalMemoryBytes - (c.freeMemoryBytes || 0) : null;
    const pending = c.pendingHostname && c.hostname && c.pendingHostname.toLowerCase() !== c.hostname.toLowerCase();
    const membership = c.partOfDomain
      ? pill("info", "Domain") + " " + esc(c.domain || "")
      : pill("neutral", "Workgroup") + " " + esc(c.workgroup || "");
    const identityActions = button("SetHostname", '<i class="bi bi-pencil me-1"></i>Rename', 'data-sys-act="rename"') + " " +
      (c.partOfDomain
        ? button("LeaveDomain", '<i class="bi bi-box-arrow-left me-1"></i>Leave domain', 'data-sys-act="leave"')
        : button("JoinDomain", '<i class="bi bi-diagram-3 me-1"></i>Join domain', 'data-sys-act="join"'));

    let html = '<div class="info-grid">';
    html += panel("Identity", kv([
      ["Hostname", dash(c.hostname) + (pending ? " " + pill("warning", "Changes to " + c.pendingHostname + " after restart") : "")],
      ["FQDN", '<span class="mono">' + dash(c.fqdn) + "</span>"],
      ["Primary DNS suffix", dash(c.primaryDnsSuffix) + (c.configuredDnsSuffix && c.configuredDnsSuffix !== c.primaryDnsSuffix ? " " + pill("warning", "Changes to " + c.configuredDnsSuffix + " after restart") : "")],
      ["Membership", membership],
      ["Role", dash(c.domainRole)],
      ["DNS search domains", list(c.searchList).length ? esc(list(c.searchList).join(", ")) : '<span class="subtle">None (uses the adapter suffixes)</span>'],
      ["Time zone", dash(c.timeZone)],
      ["Manager address", '<span class="mono">' + dash(s.managerHost) + "</span>"]
    ]), identityActions);
    html += panel("Operating system and hardware", kv([
      ["Operating system", dash(c.osCaption) + (c.edition ? ' <span class="subtle">(' + esc(c.edition) + ")</span>" : "")],
      ["Version", dash([c.osVersion, c.osBuild ? "build " + c.osBuild : ""].filter(Boolean).join(", "))],
      ["Architecture", dash(c.architecture || m.architecture)],
      ["Hardware", dash([c.manufacturer, c.model].filter(Boolean).join(" "))],
      ["Processors", m.logicalProcessors ? esc(m.logicalProcessors + " logical") + (m.cpuPercent ? ' <span class="subtle">(' + Math.round(m.cpuPercent) + "% busy)</span>" : "") : dash(null)],
      ["Memory", c.totalMemoryBytes ? esc(U.formatBytes(memUsed) + " used of " + U.formatBytes(c.totalMemoryBytes)) + ' <span class="subtle">(' + Math.round(memUsed / c.totalMemoryBytes * 100) + "%)</span>" : dash(null)],
      ["Installed", when(c.installDateUtc)],
      ["Last boot", when(c.lastBootUtc)],
      ["Uptime", dash(U.formatUptime(a.uptime))],
      ["Restart pending", c.rebootPending ? pill("warning", "Yes, a restart is required") : pill("success", "No")]
    ]));
    html += "</div>";

    const disks = list(m.disks);
    if (disks.length) {
      html += section("Disks", table(["Drive", "Label", "Format", "Used", "Free", "Size"], disks.map(function (d) {
        const used = d.totalBytes - d.freeBytes;
        const pct = d.totalBytes ? Math.round(used / d.totalBytes * 100) : 0;
        return "<tr><td class=\"mono\">" + esc(d.name) + "</td><td>" + dash(d.label) + "</td><td>" + dash(d.format) + "</td><td>" +
          (pct >= 90 ? pill("danger", pct + "%") : pct >= 80 ? pill("warning", pct + "%") : esc(pct + "%")) + "</td><td>" + esc(U.formatBytes(d.freeBytes)) + "</td><td>" + esc(U.formatBytes(d.totalBytes)) + "</td></tr>";
      }), "No disks reported."));
    }

    html += section("Network adapters", table(["Adapter", "Status", "Addresses", "Gateway", "DNS servers", "DNS suffix", ""], list(s.network).map(function (n) {
      const up = n.status === "Up";
      return "<tr><td><span class=\"cell-primary\">" + esc(n.name) + '</span><div class="subtle small">' + esc(n.description || "") + (n.mac ? " \u00B7 " + esc(n.mac) : "") +
        (n.speedMbps ? " \u00B7 " + esc(n.speedMbps >= 1000 ? n.speedMbps / 1000 + " Gbps" : n.speedMbps + " Mbps") : "") + "</div></td>" +
        "<td>" + (up ? pill("success", "Up") : pill("neutral", n.status || "Unknown")) + (n.dhcp === true ? ' <span class="subtle small">DHCP</span>' : n.dhcp === false ? ' <span class="subtle small">Static</span>' : "") + "</td>" +
        '<td class="mono small">' + (list(n.addresses).map(esc).join("<br>") || dash(null)) + "</td>" +
        '<td class="mono small">' + (list(n.gateways).map(esc).join("<br>") || dash(null)) + "</td>" +
        '<td class="mono small">' + (list(n.dnsServers).map(esc).join("<br>") || dash(null)) + "</td>" +
        "<td>" + dash(n.dnsSuffix) + "</td>" +
        "<td>" + (n.index ? button("SetDns", "Change DNS", 'data-sys-act="dns" data-index="' + esc(n.index) + '"') : "") + "</td></tr>";
    }), "No network adapters reported."));

    const conn = s.connections || {};
    const listening = list(conn.listening).slice().sort(function (x, y) { return x.port - y.port; });
    html += section("Listening ports <span class=\"subtle small\">(" + listening.length + ")</span>",
      table(["Protocol", "Address", "Port", "Process"], listening.slice(0, 200).map(function (l) {
        return "<tr><td>" + esc(l.protocol) + '</td><td class="mono">' + esc(l.address) + '</td><td class="mono">' + esc(l.port) + "</td><td>" + dash(l.process) + (l.pid ? ' <span class="subtle small">PID ' + esc(l.pid) + "</span>" : "") + "</td></tr>";
      }), "No listening ports reported."));
    const est = list(conn.established);
    html += section("Established connections <span class=\"subtle small\">(" + est.length + ")</span>",
      table(["Local", "Remote", "Process"], est.slice(0, 200).map(function (e) {
        return '<tr><td class="mono small">' + esc(e.localAddress + ":" + e.localPort) + '</td><td class="mono small">' + esc(e.remoteAddress + ":" + e.remotePort) + "</td><td>" + dash(e.process) + "</td></tr>";
      }), "No established connections."));
    return html;
  }

  function admins() {
    return new Set(list(snap().localAdministrators).map(function (m) { return shortName(m.name); }));
  }

  // Joins the account report, live sessions and logon events into one view per account.
  function accountActivity() {
    const s = snap();
    const sessions = list(s.sessions).filter(function (x) { return x.user; });
    const logons = list((s.events || {}).logons);
    const failed = list((s.events || {}).failedLogons);
    const adminSet = admins();
    const now = Date.now();
    return (agentState.accounts || []).map(function (acct) {
      const key = shortName(acct.samAccountName);
      const own = sessions.filter(function (x) { return shortName(x.user) === key; });
      const active = own.some(function (x) { return x.state === "Active"; });
      const lastEvent = logons.filter(function (l) { return shortName(l.user) === key; }).reduce(function (t, l) { return Math.max(t, ms(l.timeUtc)); }, 0);
      const lastInput = own.reduce(function (t, x) { return Math.max(t, ms(x.lastInputUtc), ms(x.logonUtc)); }, 0);
      const lastLogon = Math.max(ms(acct.lastLogon), lastEvent);
      const lastActivity = Math.max(lastLogon, lastInput);
      // Local accounts record their last logon in the SAM; a domain account's lastLogon is kept per domain
      // controller, so its absence is not proof the account was never used.
      const domainAccount = acct.source === "Domain";
      const usage = own.length || (lastLogon && now - lastLogon <= UNUSED_DAYS * 86400000) ? "In use"
        : lastLogon ? "Unused" : domainAccount ? "Unknown" : "Never signed in";
      return {
        account: acct.samAccountName, source: acct.source || "Local", enabled: Boolean(acct.enabled), lockedOut: Boolean(acct.lockedOut),
        session: active ? "Active" : own.length ? "Disconnected" : "None", sessions: own.length,
        usage: usage,
        lastLogonUtc: lastLogon ? new Date(lastLogon).toISOString() : null,
        lastActivityUtc: lastActivity ? new Date(lastActivity).toISOString() : null,
        failed7d: failed.filter(function (f) { return shortName(f.user) === key; }).length,
        admin: adminSet.has(key)
      };
    });
  }

  function activityView() {
    const s = snap();
    const ev = s.events || {};
    const sessions = list(s.sessions).filter(function (x) { return x.user; });
    const logons = list(ev.logons).slice().sort(function (x, y) { return ms(y.timeUtc) - ms(x.timeUtc); });
    const failed = list(ev.failedLogons).slice().sort(function (x, y) { return ms(y.timeUtc) - ms(x.timeUtc); });
    const adminSet = admins();
    const rows = accountActivity();
    const lastLogon = logons[0];
    const lastAdmin = logons.find(function (l) { return adminSet.has(shortName(l.user)); });
    const active = sessions.filter(function (x) { return x.state === "Active"; }).length;

    let html = '<div class="stat-strip">' +
      "<div><div class=\"label\">Active sessions</div><div class=\"value\">" + active + "</div></div>" +
      "<div><div class=\"label\">Disconnected sessions</div><div class=\"value\">" + (sessions.length - active) + "</div></div>" +
      "<div><div class=\"label\">Sign-ins (30 days)</div><div class=\"value\">" + logons.length + "</div></div>" +
      "<div><div class=\"label\">Failed sign-ins (7 days)</div><div class=\"value\">" + failed.length + "</div></div>" +
      "<div><div class=\"label\">Unused accounts</div><div class=\"value\">" + rows.filter(function (r) { return r.enabled && (r.usage === "Unused" || r.usage === "Never signed in"); }).length + "</div></div></div>";

    html += '<div class="info-grid">' + panel("Last sign-in", kv([
      ["Any user", lastLogon ? esc((lastLogon.domain ? lastLogon.domain + "\\" : "") + lastLogon.user) + " \u00B7 " + esc(LOGON_TYPES[lastLogon.logonType] || "Type " + lastLogon.logonType) + "<br>" + when(lastLogon.timeUtc) : '<span class="subtle">None in 30 days</span>'],
      ["Administrator", lastAdmin ? esc((lastAdmin.domain ? lastAdmin.domain + "\\" : "") + lastAdmin.user) + " \u00B7 " + esc(LOGON_TYPES[lastAdmin.logonType] || "Type " + lastAdmin.logonType) + "<br>" + when(lastAdmin.timeUtc) : '<span class="subtle">None in 30 days</span>'],
      ["Last boot", when((s.computer || {}).lastBootUtc)]
    ])) + panel("Local Administrators group", list(s.localAdministrators).length
      ? '<ul class="sys-list">' + list(s.localAdministrators).map(function (m) {
        return "<li>" + esc(m.name) + ' <span class="subtle small">' + esc(m.kind || "") + "</span>" + (m.enabled === false ? " " + pill("neutral", "Disabled") : "") + "</li>";
      }).join("") + "</ul>"
      : '<p class="subtle small p-3 mb-0">Not reported.</p>') + "</div>";

    html += section("Signed-in sessions", table(["User", "Session", "State", "Connected from", "Signed in", "Last input"], sessions.map(function (x) {
      const idle = ms(x.lastInputUtc) ? Date.now() - ms(x.lastInputUtc) : 0;
      return "<tr><td><span class=\"cell-primary\">" + esc((x.domain ? x.domain + "\\" : "") + x.user) + "</span></td><td>" + esc(x.station || "") + ' <span class="subtle small">#' + esc(x.id) + "</span></td>" +
        "<td>" + (x.state === "Active" ? pill("success", "Active") : pill("neutral", x.state || "Unknown")) + "</td>" +
        "<td>" + (x.remote ? esc(x.client || "") + ' <span class="mono small">' + esc(x.clientAddress || "") + "</span>" : '<span class="subtle">This computer</span>') + "</td>" +
        "<td>" + when(x.logonUtc) + "</td><td>" + (ms(x.lastInputUtc) ? esc(U.relativeTime(x.lastInputUtc)) + (idle > 3600000 ? " " + pill("neutral", "Idle") : "") : dash(null)) + "</td></tr>";
    }), "Nobody is signed in."));

    html += section("Account activity", '<p class="subtle small">Three separate facts per account: whether it is <strong>enabled</strong> (it may sign in), whether it has a <strong>session</strong> now, and whether it has been <strong>used</strong> in the last ' + UNUSED_DAYS + " days. An enabled account with no sign-in for " + UNUSED_DAYS + " days is listed as unused. A domain account with no recorded sign-in is shown as unknown, because its last logon is kept by each domain controller.</p>" +
      table(["Account", "Enabled", "Session", "Usage", "Last sign-in", "Last activity", "Failed (7 days)"], rows.map(function (r) {
        return "<tr><td><span class=\"cell-primary\">" + esc(r.account) + "</span> <span class=\"subtle small\">" + esc(r.source) + "</span>" + (r.admin ? " " + pill("info", "Administrator") : "") + "</td>" +
          "<td>" + (r.lockedOut ? pill("danger", "Locked out") : r.enabled ? pill("success", "Enabled") : pill("neutral", "Disabled")) + "</td>" +
          "<td>" + (r.session === "Active" ? pill("success", "Active session") : r.session === "Disconnected" ? pill("warning", "Disconnected session") : '<span class="subtle">No session</span>') + "</td>" +
          "<td>" + (r.usage === "In use" ? pill("success", "In use") : r.usage === "Unknown" ? pill("neutral", "Unknown") : r.enabled ? pill("warning", r.usage) : pill("neutral", r.usage)) + "</td>" +
          "<td>" + (r.usage === "Unknown" ? '<span class="subtle" title="No sign-in on this computer in 30 days and no last-logon time from the domain controller.">Not recorded</span>' : when(r.lastLogonUtc)) + "</td>" +
          "<td>" + (r.usage === "Unknown" && !r.lastActivityUtc ? '<span class="subtle">Not recorded</span>' : when(r.lastActivityUtc)) + '</td><td class="num">' + (r.failed7d ? '<span class="text-danger">' + r.failed7d + "</span>" : "0") + "</td></tr>";
      }), "No accounts reported."));

    html += section("Recent sign-ins <span class=\"subtle small\">(30 days)</span>", table(["Time", "User", "Type", "From"], logons.slice(0, 100).map(function (l) {
      return "<tr><td class=\"text-nowrap\">" + esc(U.formatDateTime(l.timeUtc)) + "</td><td>" + esc((l.domain ? l.domain + "\\" : "") + l.user) + (adminSet.has(shortName(l.user)) ? " " + pill("info", "Admin") : "") + "</td>" +
        "<td>" + esc(LOGON_TYPES[l.logonType] || "Type " + l.logonType) + '</td><td class="mono small">' + dash(l.source && l.source !== "-" ? l.source : l.workstation) + "</td></tr>";
    }), "No interactive or remote sign-ins in 30 days (or the Security log is not available)."));

    html += section("Failed sign-ins <span class=\"subtle small\">(7 days)</span>", table(["Time", "User", "Reason", "Type", "From"], failed.slice(0, 100).map(function (f) {
      return "<tr><td class=\"text-nowrap\">" + esc(U.formatDateTime(f.timeUtc)) + "</td><td>" + esc((f.domain ? f.domain + "\\" : "") + (f.user || "?")) + "</td>" +
        "<td>" + esc(FAILURE_REASONS[String(f.subStatus).toUpperCase().replace("0X", "0x")] || FAILURE_REASONS[String(f.status).toUpperCase().replace("0X", "0x")] || "Status " + (f.subStatus || f.status)) + "</td>" +
        "<td>" + esc(LOGON_TYPES[f.logonType] || "Type " + f.logonType) + '</td><td class="mono small">' + dash(f.source && f.source !== "-" ? f.source : f.workstation) + "</td></tr>";
    }), "No failed sign-ins in 7 days."));
    return html;
  }

  function rdpRules() {
    const fw = snap().firewall || {};
    const port = String((snap().remoteDesktop || {}).port || 3389);
    return list(fw.rules).filter(function (r) {
      return r.direction === "Inbound" && (/remote desktop/i.test(r.group || "") || String(r.localPort || "").split(",").includes(port));
    });
  }

  function rdpView() {
    const s = snap();
    const r = s.remoteDesktop || {};
    const term = list(r.services).find(function (x) { return x.name === "TermService"; }) || {};
    const rules = rdpRules();
    const allowed = rules.some(function (x) { return x.enabled && x.action === "Allow"; });
    const ev = s.events || {};
    const policyEnabled = r.policyDenyConnections === 0;
    const policyDisabled = r.policyDenyConnections === 1;

    function state(label, ok, detail, unknown) {
      return '<div class="sys-state"><div class="label">' + label + "</div><div>" + (unknown ? pill("neutral", "Unknown") : ok ? pill("success", "Yes") : pill("danger", "No")) + "</div>" +
        (detail ? '<div class="subtle small">' + detail + "</div>" : "") + "</div>";
    }

    let html = "";
    if (!r.hostSupported) {
      html += '<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>' + esc(r.edition || "This edition") + " of Windows cannot accept Remote Desktop connections. It can still connect to other computers.</div></div>";
    }
    html += '<div class="sys-states">' +
      state("Enabled", r.enabled, policyEnabled ? "Enforced on by Group Policy" : policyDisabled ? "Enforced off by Group Policy" : "Connections " + (r.enabled ? "allowed" : "refused") + " in system settings") +
      state("Service running", term.status === "Running", "Remote Desktop Services: " + esc(term.status || "unknown") + (term.startType ? ", " + esc(term.startType) : "")) +
      state("Listening", r.listening, "TCP port " + esc(r.port || 3389)) +
      state("Allowed by firewall", allowed, rules.length ? rules.filter(function (x) { return x.enabled; }).length + " of " + rules.length + " inbound rules enabled" : "No inbound rule found for the port") +
      state("Reachable from portal", probe && probe.reachable, probe ? (probe.reachable ? "Port accepted a connection " : "No connection ") + esc(U.relativeTime(probe.testedUtc).toLowerCase()) : "Not tested", !probe) +
      state("Network Level Authentication", r.nla, r.policyNla === 1 ? "Required by Group Policy" : r.policyNla === 0 ? "Turned off by Group Policy" : "Security layer " + esc(r.securityLayer === 2 ? "TLS" : r.securityLayer === 1 ? "Negotiate" : r.securityLayer === 0 ? "RDP (legacy)" : "default")) +
      "</div>";

    html += '<div class="sys-toolbar">' +
      (r.enabled
        ? button("SetRemoteDesktop", '<i class="bi bi-display me-1"></i>Disable Remote Desktop', 'data-sys-act="rdp" data-value="false"', "btn-outline-danger")
        : button("SetRemoteDesktop", '<i class="bi bi-display me-1"></i>Enable Remote Desktop', 'data-sys-act="rdp" data-value="true"', "btn-primary")) + " " +
      (r.nla
        ? button("SetNla", '<i class="bi bi-shield-slash me-1"></i>Stop requiring NLA', 'data-sys-act="nla" data-value="false"', "btn-outline-danger")
        : button("SetNla", '<i class="bi bi-shield-check me-1"></i>Require NLA', 'data-sys-act="nla" data-value="true"')) + " " +
      '<button type="button" class="btn btn-sm btn-outline-secondary" data-sys-act="probe"' + (role === "Monitor" ? ' disabled title="Requires the Operator role."' : "") + '><i class="bi bi-broadcast me-1"></i>Test reachability</button></div>';

    if (probe && probe.results) {
      html += '<p class="subtle small">' + probe.results.map(function (x) {
        return esc(x.address + ":" + probe.port) + " \u2014 " + (x.open ? "open (" + x.ms + " ms)" : esc(x.error || "closed"));
      }).join("<br>") + "</p>";
    }

    const remote = list(s.sessions).filter(function (x) { return x.remote && x.user; });
    html += section("Remote Desktop sessions", table(["User", "State", "Client", "Signed in"], remote.map(function (x) {
      return "<tr><td>" + esc((x.domain ? x.domain + "\\" : "") + x.user) + "</td><td>" + (x.state === "Active" ? pill("success", "Active") : pill("neutral", x.state)) + "</td><td>" +
        esc(x.client || "") + ' <span class="mono small">' + esc(x.clientAddress || "") + "</span></td><td>" + when(x.logonUtc) + "</td></tr>";
    }), "No Remote Desktop sessions."));

    html += section("Firewall rules for Remote Desktop", table(["Rule", "Enabled", "Action", "Profile", "Port", "Remote address"], rules.map(function (x) {
      return "<tr><td>" + esc(x.name) + "</td><td>" + (x.enabled ? pill("success", "Yes") : pill("neutral", "No")) + "</td><td>" + esc(x.action) + "</td><td>" + esc(x.profile) + '</td><td class="mono">' + esc(x.localPort || "Any") + '</td><td class="mono small">' + esc(x.remoteAddress || "Any") + "</td></tr>";
    }), "No inbound rules found."));

    html += section("Successful Remote Desktop authentications <span class=\"subtle small\">(30 days)</span>", table(["Time", "User", "From"], list(ev.rdpAuthentications).slice(0, 50).map(function (x) {
      return "<tr><td class=\"text-nowrap\">" + esc(U.formatDateTime(x.timeUtc)) + "</td><td>" + esc((x.domain ? x.domain + "\\" : "") + x.user) + '</td><td class="mono small">' + dash(x.source) + "</td></tr>";
    }), "None recorded."));
    const sessionNames = { 21: "Signed in", 23: "Signed out", 24: "Disconnected", 25: "Reconnected" };
    html += section("Session history <span class=\"subtle small\">(30 days)</span>", table(["Time", "Event", "User", "From"], list(ev.rdpSessions).slice(0, 60).map(function (x) {
      return "<tr><td class=\"text-nowrap\">" + esc(U.formatDateTime(x.timeUtc)) + "</td><td>" + esc(sessionNames[x.id] || "Event " + x.id) + "</td><td>" + esc(x.user) + '</td><td class="mono small">' + dash(x.source === "LOCAL" ? "This computer" : x.source) + "</td></tr>";
    }), "None recorded."));
    const failures = list(ev.rdpFailures).concat(list(ev.failedLogons).filter(function (f) { return f.logonType === 10; }).map(function (f) {
      return { timeUtc: f.timeUtc, source: f.source, message: (FAILURE_REASONS[f.subStatus] || "Failed sign-in") + " for " + f.user };
    })).sort(function (x, y) { return ms(y.timeUtc) - ms(x.timeUtc); });
    html += section("Connection and authentication failures <span class=\"subtle small\">(7 days)</span>", table(["Time", "From", "Detail"], failures.slice(0, 60).map(function (x) {
      return "<tr><td class=\"text-nowrap\">" + esc(U.formatDateTime(x.timeUtc)) + '</td><td class="mono small">' + dash(x.source) + "</td><td>" + esc(x.message || "") + "</td></tr>";
    }), "No failures recorded."));
    return html;
  }

  // Ports named by enabled inbound rules. A block rule wins over an allow rule for the same port and profile.
  function inboundPorts(fw) {
    const ports = new Map();
    list(fw.rules).forEach(function (r) {
      if (!r.enabled || r.direction !== "Inbound" || !r.localPort || /^any$/i.test(r.localPort) || !/^(TCP|UDP)$/i.test(r.protocol || "")) { return; }
      r.localPort.split(",").forEach(function (port) {
        const key = r.protocol.toUpperCase() + " " + port.trim();
        const e = ports.get(key) || { key: key, allow: [], block: [] };
        (r.action === "Block" ? e.block : e.allow).push(r);
        ports.set(key, e);
      });
    });
    const rows = Array.from(ports.values()).sort(function (a, b) { return (parseInt(a.key.split(" ")[1], 10) || 0) - (parseInt(b.key.split(" ")[1], 10) || 0) || a.key.localeCompare(b.key); });
    const defaults = list(fw.profiles).map(function (p) { return esc(p.name) + ": " + (p.enabled ? esc(p.defaultInbound === "NotConfigured" ? "Block" : p.defaultInbound) : "firewall off, everything allowed"); }).join(" \u00B7 ");
    const names = function (rs) { return rs.slice(0, 3).map(function (r) { return esc(r.name) + ' <span class="subtle small">(' + esc(r.profile) + ")</span>"; }).join("<br>") + (rs.length > 3 ? '<br><span class="subtle small">+' + (rs.length - 3) + " more</span>" : ""); };
    return section("Inbound ports <span class=\"subtle small\">(" + rows.length + ")</span>",
      '<p class="subtle small">Ports named by enabled inbound TCP and UDP rules. A blocking rule overrides an allowing rule for the same profile. Ports not listed follow the profile default \u2014 ' + (defaults || "not reported") + ".</p>" +
      table(["Port", "Result", "Allowed by", "Blocked by"], rows.slice(0, 300).map(function (e) {
        return '<tr><td class="mono">' + esc(e.key) + "</td><td>" + (e.block.length && e.allow.length ? pill("warning", "Allow and block rules \u2014 check profiles") : e.block.length ? pill("danger", "Blocked") : pill("success", "Allowed")) + "</td>" +
          "<td>" + (e.allow.length ? names(e.allow) : dash(null)) + "</td><td>" + (e.block.length ? names(e.block) : dash(null)) + "</td></tr>";
      }), "No enabled inbound rule names a specific port."));
  }

  function firewallView() {
    const fw = snap().firewall || {};
    const networks = list(fw.networks);
    let html = section("Profiles", table(["Profile", "State", "Inbound default", "Outbound default", "Local rules", "Logging", "Active on", ""], list(fw.profiles).map(function (p) {
      const nets = networks.filter(function (n) { return n.category === p.name || (p.name === "Domain" && n.category === "DomainAuthenticated"); });
      return "<tr><td><span class=\"cell-primary\">" + esc(p.name) + "</span>" + (p.policyManaged ? " " + pill("info", "Group Policy") : "") + "</td>" +
        "<td>" + (p.enabled ? pill("success", "On") : pill("danger", "Off")) + "</td><td>" + esc(p.defaultInbound) + "</td><td>" + esc(p.defaultOutbound) + "</td>" +
        "<td>" + esc(p.allowLocalRules === "False" ? "Ignored (policy)" : "Applied") + "</td><td class=\"small\">" + esc([p.logAllowed === "True" ? "allowed" : "", p.logBlocked === "True" ? "blocked" : ""].filter(Boolean).join(", ") || "Off") + "</td>" +
        "<td>" + (nets.length ? nets.map(function (n) { return esc(n.network + " (" + n.interface + ")"); }).join("<br>") : '<span class="subtle">No network</span>') + "</td>" +
        "<td>" + (p.enabled
          ? button("SetFirewallProfile", "Turn off", 'data-sys-act="profile" data-profile="' + esc(p.name) + '" data-value="false"', "btn-outline-danger")
          : button("SetFirewallProfile", "Turn on", 'data-sys-act="profile" data-profile="' + esc(p.name) + '" data-value="true"')) + "</td></tr>";
    }), "Firewall profiles were not reported."));

    html += inboundPorts(fw);

    const q = filters.rules.toLowerCase();
    const rules = list(fw.rules).filter(function (r) {
      if (filters.ruleDirection && r.direction !== filters.ruleDirection) { return false; }
      if (filters.ruleShow === "portal" && !r.portalManaged) { return false; }
      if (filters.ruleShow === "enabled" && !r.enabled) { return false; }
      if (filters.ruleShow === "block" && r.action !== "Block") { return false; }
      return !q || [r.name, r.group, r.localPort, r.remoteAddress, r.program, r.protocol].join(" ").toLowerCase().includes(q);
    });
    const shown = rules.slice(0, 300);
    html += '<div class="sys-section"><div class="sys-section-head"><h3 class="section-title mb-0">Rules</h3>' + button("FirewallRule", '<i class="bi bi-plus-lg me-1"></i>Add rule', 'data-sys-act="rule-add"', "btn-primary") + "</div>" +
      '<div class="toolbar px-0"><div class="search"><i class="bi bi-search" aria-hidden="true"></i><input class="form-control form-control-sm" id="sysRuleSearch" placeholder="Search name, group, port, address or program" value="' + esc(filters.rules) + '"></div>' +
      '<select class="form-select form-select-sm" id="sysRuleDirection"><option value="">Both directions</option><option value="Inbound"' + (filters.ruleDirection === "Inbound" ? " selected" : "") + '>Inbound</option><option value="Outbound"' + (filters.ruleDirection === "Outbound" ? " selected" : "") + ">Outbound</option></select>" +
      '<select class="form-select form-select-sm" id="sysRuleShow">' + [["all", "All rules"], ["enabled", "Enabled only"], ["block", "Blocking rules"], ["portal", "Added from the portal"]].map(function (o) {
        return '<option value="' + o[0] + '"' + (filters.ruleShow === o[0] ? " selected" : "") + ">" + o[1] + "</option>";
      }).join("") + '</select><span class="count">' + (rules.length > shown.length ? "Showing " + shown.length + " of " : "") + rules.length + " of " + (fw.ruleCount || list(fw.rules).length) + " rules</span></div>" +
      table(["Name", "Direction", "Action", "Protocol", "Local port", "Remote address", "Profile", "Enabled", ""], shown.map(function (r) {
        const policy = r.source && r.source !== "Local" && r.source !== "None" && r.source !== "";
        let actions = "";
        if (!policy) {
          actions += r.enabled
            ? (r.protected ? '<span class="subtle small" title="The agent needs this rule to reach the portal.">Required</span>' : button("FirewallRule", "Disable", 'data-sys-act="rule-toggle" data-id="' + esc(r.id) + '" data-value="false"'))
            : button("FirewallRule", "Enable", 'data-sys-act="rule-toggle" data-id="' + esc(r.id) + '" data-value="true"');
          if (r.portalManaged) {
            actions += " " + button("FirewallRule", "Edit", 'data-sys-act="rule-edit" data-id="' + esc(r.id) + '"') + " " +
              button("FirewallRule", "Remove", 'data-sys-act="rule-remove" data-id="' + esc(r.id) + '"', "btn-outline-danger");
          }
        } else {
          actions = '<span class="subtle small" title="Change it in the Group Policy that sets it.">Managed by policy</span>';
        }
        return "<tr><td><span class=\"cell-primary\">" + esc(r.name) + "</span>" + (r.portalManaged ? " " + pill("info", "Portal") : "") + '<div class="subtle small">' + esc(r.group || "") + (r.program && r.program !== "Any" ? " \u00B7 " + esc(r.program) : "") + "</div></td>" +
          "<td>" + esc(r.direction) + "</td><td>" + (r.action === "Block" ? pill("danger", "Block") : pill("success", "Allow")) + "</td><td>" + esc(r.protocol || "Any") + '</td><td class="mono small">' + esc(r.localPort || "Any") +
          '</td><td class="mono small">' + esc(r.remoteAddress || "Any") + "</td><td>" + esc(r.profile) + "</td><td>" + (r.enabled ? pill("success", "Yes") : pill("neutral", "No")) + '</td><td class="text-nowrap">' + actions + "</td></tr>";
      }), "No rules match.") + "</div>";

    const changes = list((snap().events || {}).firewallChanges);
    html += section("Recent firewall changes <span class=\"subtle small\">(30 days)</span>", table(["Time", "Event", "Detail"], changes.slice(0, 60).map(function (e) {
      return "<tr><td class=\"text-nowrap\">" + esc(U.formatDateTime(e.timeUtc)) + "</td><td>" + esc(e.id) + "</td><td>" + esc(e.message) + "</td></tr>";
    }), "No changes recorded (or the firewall log is not available)."));
    return html;
  }

  function servicesView() {
    const all = services && Array.isArray(services.data) ? services.data : [];
    const q = filters.services.toLowerCase();
    const rows = all.filter(function (s) {
      if (filters.serviceStatus && s.status !== filters.serviceStatus) { return false; }
      return !q || (s.name + " " + s.displayName).toLowerCase().includes(q);
    }).sort(function (a, b) { return String(a.displayName).localeCompare(String(b.displayName)); });
    const ev = snap().events || {};
    const power = list(ev.power).slice().sort(function (x, y) { return ms(y.timeUtc) - ms(x.timeUtc); });
    const lastShutdown = power.find(function (e) { return e.id === 6006 || e.id === 6008 || e.id === 41; });
    const c = snap().computer || {};

    let html = '<div class="info-grid">' + panel("Power", kv([
      ["Last boot", when(c.lastBootUtc)],
      ["Last shutdown", lastShutdown ? when(lastShutdown.timeUtc) + (lastShutdown.id === 6006 ? "" : " " + pill("warning", "Unexpected")) : '<span class="subtle">None in 90 days</span>'],
      ["Restart pending", c.rebootPending ? pill("warning", "Yes") : pill("success", "No")]
    ]) + '<div class="sys-toolbar px-3 pb-3">' +
      button("RestartComputer", '<i class="bi bi-arrow-repeat me-1"></i>Restart', 'data-sys-act="restart"') + " " +
      button("CancelRestart", "Cancel restart or shutdown", 'data-sys-act="cancel-restart"') + " " +
      button("ShutdownComputer", '<i class="bi bi-power me-1"></i>Shut down', 'data-sys-act="shutdown"', "btn-outline-danger") + "</div>") +
      panel("Power history <span class=\"subtle small\">(90 days)</span>", power.length ? '<ul class="sys-list">' + power.slice(0, 12).map(function (e) {
        return "<li>" + esc(U.formatDateTime(e.timeUtc)) + " \u2014 " + esc(POWER_EVENTS[e.id] || "Event " + e.id) + (e.id === 1074 && e.message ? '<div class="subtle small">' + esc(e.message) + "</div>" : "") + "</li>";
      }).join("") + "</ul>" : '<p class="subtle small p-3 mb-0">No power events recorded.</p>') + "</div>";

    const statuses = Array.from(new Set(all.map(function (s) { return s.status; }))).sort();
    html += '<div class="sys-section"><div class="sys-section-head"><h3 class="section-title mb-0">Services</h3><span class="subtle small">' +
      (services && services.collectedUtc ? "Collected " + esc(U.relativeTime(services.collectedUtc).toLowerCase()) : "") + "</span></div>" +
      '<div class="toolbar px-0"><div class="search"><i class="bi bi-search" aria-hidden="true"></i><input class="form-control form-control-sm" id="sysServiceSearch" placeholder="Search services" value="' + esc(filters.services) + '"></div>' +
      '<select class="form-select form-select-sm" id="sysServiceStatus"><option value="">Any status</option>' + statuses.map(function (s) {
        return '<option value="' + esc(s) + '"' + (filters.serviceStatus === s ? " selected" : "") + ">" + esc(s) + "</option>";
      }).join("") + '</select><span class="count">' + rows.length + " of " + all.length + "</span></div>" +
      table(["Service", "Status", "Start type", ""], rows.slice(0, 400).map(function (s) {
        const prot = PROTECTED_SERVICES.includes(String(s.name).toLowerCase());
        const running = s.status === "Running";
        let actions = "";
        if (!running) {
          actions = s.startType === "Disabled" ? '<span class="subtle small">Disabled</span>' : button("ServiceControl", "Start", 'data-sys-act="svc" data-name="' + esc(s.name) + '" data-op="start"');
        } else if (prot) {
          actions = '<span class="subtle small" title="Essential to Windows or remote management.">Protected</span>';
        } else {
          actions = button("ServiceControl", "Restart", 'data-sys-act="svc" data-name="' + esc(s.name) + '" data-op="restart"') + " " +
            (s.canStop ? button("ServiceControl", "Stop", 'data-sys-act="svc" data-name="' + esc(s.name) + '" data-op="stop"', "btn-outline-danger") : "");
        }
        return "<tr><td><span class=\"cell-primary\">" + esc(s.displayName || s.name) + '</span><div class="subtle small mono">' + esc(s.name) + "</div></td>" +
          "<td>" + (running ? pill("success", "Running") : s.status === "Stopped" ? pill("neutral", "Stopped") : pill("warning", s.status)) + "</td><td>" + esc(s.startType) + '</td><td class="text-nowrap">' + actions + "</td></tr>";
      }), services && services.data ? "No services match." : "The service list has not been received yet.") + "</div>";
    return html;
  }

  function changeEvents() {
    const ev = snap().events || {};
    function tag(items, category) { return list(items).map(function (e) { return Object.assign({ category: category }, e); }); }
    return tag(ev.accountChanges, "Accounts").concat(tag(ev.serviceChanges, "Services"), tag(ev.firewallChanges, "Firewall"), tag(ev.power, "Power"))
      .sort(function (x, y) { return ms(y.timeUtc) - ms(x.timeUtc); });
  }

  function operations() {
    return (agentState.commands || []).filter(function (c) { return c.category === "admin" || ["RestartComputer", "CancelRestart"].includes(c.commandType); });
  }

  function eventsView() {
    const ev = snap().events || {};
    const ops = operations();
    let html = section("Administration operations from this portal", table(["Requested", "Operation", "Status", "Result", "By"], ops.slice(0, 100).map(function (c) {
      return '<tr><td class="text-nowrap">' + esc(U.formatDateTime(c.createdUtc)) + "</td><td>" + esc(c.label) + (c.summary ? '<div class="subtle small">' + esc(c.summary) + "</div>" : "") + "</td>" +
        "<td>" + U.statusPill(c.status) + "</td><td>" + (c.result ? '<div class="result-text">' + esc(c.result) + "</div>" : '<span class="subtle">\u2014</span>') + "</td>" +
        "<td>" + esc(c.enqueuedBy) + (c.reason ? '<div class="subtle small">' + esc(c.reason) + "</div>" : "") + "</td></tr>";
    }), "No administration operations have been run on this computer."));
    html += section("Configuration changes on the computer <span class=\"subtle small\">(accounts, services and firewall: 30 days; power: 90 days)</span>", table(["Time", "Area", "Event", "Detail"], changeEvents().slice(0, 150).map(function (e) {
      return '<tr><td class="text-nowrap">' + esc(U.formatDateTime(e.timeUtc)) + "</td><td>" + esc(e.category) + "</td><td>" + esc(e.id) + "</td><td>" + esc(e.category === "Power" ? POWER_EVENTS[e.id] || e.message : e.message) + "</td></tr>";
    }), "No changes recorded."));
    html += section("Errors and warnings <span class=\"subtle small\">(24 hours)</span>", table(["Time", "Log", "Level", "Source", "Event", "Message"], list(ev.problems).slice(0, 120).map(function (e) {
      return '<tr><td class="text-nowrap">' + esc(U.formatDateTime(e.timeUtc)) + "</td><td>" + esc(e.log) + "</td><td>" + (/error|critical/i.test(e.level) ? pill("danger", e.level) : pill("warning", e.level || "Warning")) + "</td><td>" + esc(e.source) + "</td><td>" + esc(e.id) + "</td><td>" + esc(e.message) + "</td></tr>";
    }), "No errors or warnings in the last 24 hours."));
    return html;
  }

  // --- Export -----------------------------------------------------------------------------------
  function csvCell(v) {
    let s = v === null || v === undefined ? "" : String(v);
    if (/^[=+\-@\t\r]/.test(s)) { s = "'" + s; }
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function download(name, type, content) {
    const blob = new Blob([content], { type: type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function exportData(kind) {
    if (!snap()) {
      U.notify("No system information has been received yet.", "warning");
      return;
    }
    const host = (agent().machineName || agentKey).replace(/[^A-Za-z0-9_.-]/g, "_");
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const csv = function (headers, rows) { return [headers].concat(rows).map(function (r) { return r.map(csvCell).join(","); }).join("\r\n") + "\r\n"; };
    if (kind === "json") {
      download(host + "-system-" + stamp + ".json", "application/json", JSON.stringify({ machineName: agent().machineName, collectedUtc: entry.collectedUtc, snapshot: snap(), services: services && services.data }, null, 2));
    } else if (kind === "events") {
      const ev = snap().events || {};
      const rows = changeEvents().map(function (e) { return [e.timeUtc, e.category, e.id, "", e.message]; })
        .concat(list(ev.logons).map(function (e) { return [e.timeUtc, "Sign-in", 4624, (e.domain ? e.domain + "\\" : "") + e.user, (LOGON_TYPES[e.logonType] || e.logonType) + " from " + (e.source || e.workstation || "")]; }))
        .concat(list(ev.failedLogons).map(function (e) { return [e.timeUtc, "Failed sign-in", 4625, (e.domain ? e.domain + "\\" : "") + e.user, (FAILURE_REASONS[e.subStatus] || e.subStatus) + " from " + (e.source || e.workstation || "")]; }))
        .concat(list(ev.problems).map(function (e) { return [e.timeUtc, e.log + " " + e.level, e.id, e.source, e.message]; }))
        .sort(function (x, y) { return ms(y[0]) - ms(x[0]); });
      download(host + "-events-" + stamp + ".csv", "text/csv", csv(["TimeUtc", "Category", "EventId", "Subject", "Detail"], rows));
    } else if (kind === "firewall") {
      download(host + "-firewall-" + stamp + ".csv", "text/csv", csv(["Name", "Group", "Direction", "Action", "Protocol", "LocalPort", "RemotePort", "RemoteAddress", "Program", "Profile", "Enabled", "Source", "PortalManaged"],
        list((snap().firewall || {}).rules).map(function (r) { return [r.name, r.group, r.direction, r.action, r.protocol, r.localPort, r.remotePort, r.remoteAddress, r.program, r.profile, r.enabled, r.source, r.portalManaged]; })));
    } else if (kind === "activity") {
      download(host + "-account-activity-" + stamp + ".csv", "text/csv", csv(["Account", "Source", "Administrator", "Enabled", "LockedOut", "Session", "Usage", "LastSignInUtc", "LastActivityUtc", "FailedSignIns7Days"],
        accountActivity().map(function (r) { return [r.account, r.source, r.admin, r.enabled, r.lockedOut, r.session, r.usage, r.lastLogonUtc, r.lastActivityUtc, r.failed7d]; })));
    } else if (kind === "operations") {
      download(host + "-admin-operations-" + stamp + ".csv", "text/csv", csv(["RequestedUtc", "Operation", "Summary", "Status", "Result", "RequestedBy", "Reason", "CompletedUtc"],
        operations().map(function (c) { return [c.createdUtc, c.label, c.summary, c.status, c.result, c.enqueuedBy, c.reason, c.executedUtc]; })));
    }
  }

  // --- Actions ----------------------------------------------------------------------------------
  function findRule(id) { return list((snap().firewall || {}).rules).find(function (r) { return r.id === id; }); }

  function ruleForm(existing) {
    form({
      title: existing ? "Edit firewall rule" : "Add firewall rule",
      intro: "The rule is created in the <strong>uAgent portal</strong> group so it can be told apart from the computer's own rules. Ports apply only to TCP and UDP.",
      fields: [
        { name: "name", label: "Name", value: existing ? existing.name : "", placeholder: "Allow HTTPS from the admin subnet" },
        { name: "direction", label: "Direction", type: "select", value: existing ? existing.direction : "Inbound", options: [{ value: "Inbound", label: "Inbound" }, { value: "Outbound", label: "Outbound" }] },
        { name: "action", label: "Action", type: "select", value: existing ? existing.action : "Allow", options: [{ value: "Allow", label: "Allow" }, { value: "Block", label: "Block" }] },
        { name: "protocol", label: "Protocol", type: "select", value: existing ? existing.protocol || "TCP" : "TCP", options: ["TCP", "UDP", "Any", "ICMPv4", "ICMPv6"].map(function (p) { return { value: p, label: p }; }) },
        { name: "localPort", label: "Local port", value: existing ? existing.localPort : "", placeholder: "443, 5000-5100 or Any", help: "For inbound rules, the port on this computer." },
        { name: "remotePort", label: "Remote port", value: existing ? existing.remotePort : "", placeholder: "Any" },
        { name: "remoteAddress", label: "Remote address", value: existing ? existing.remoteAddress : "", placeholder: "Any, LocalSubnet, 10.0.0.0/24 or 10.0.0.5", help: "Comma-separated." },
        { name: "profile", label: "Profiles", value: existing ? existing.profile : "Any", placeholder: "Any, or Domain,Private,Public" },
        { name: "program", label: "Program (optional)", value: existing && existing.program !== "Any" ? existing.program : "", placeholder: "C:\\Program Files\\App\\app.exe" }
      ],
      check: function (v) { return v.name ? "" : "Give the rule a name."; },
      submit: function (v) {
        const params = Object.assign({ op: existing ? "update" : "add" }, v, existing ? { id: existing.id } : {});
        const blocksAll = v.action === "Block" && v.direction === "Inbound" && (!v.remoteAddress || v.remoteAddress === "Any") && (!v.localPort || v.localPort === "Any") && v.protocol === "Any";
        const outboundBlock = v.action === "Block" && v.direction === "Outbound";
        run("FirewallRule", params, (existing ? "Update" : "Add") + " firewall rule \"" + v.name + "\": " + v.action + " " + v.direction.toLowerCase() + " " + v.protocol + (v.localPort ? " port " + v.localPort : "") + (v.remoteAddress ? " from " + v.remoteAddress : ""),
          blocksAll ? "This blocks all inbound traffic, including Remote Desktop and file sharing." : outboundBlock ? "Outbound block rules can stop the agent reaching the portal if they match its address; the agent's own rule does not override a block." : "");
      }
    });
  }

  function onAction(btn) {
    const act = btn.getAttribute("data-sys-act");
    const s = snap();
    const c = (s && s.computer) || {};
    const machine = agent().machineName || agentKey;
    if (act === "probe") {
      btn.disabled = true;
      U.api("/api/agents/" + encodeURIComponent(agentKey) + "/rdp-probe", { method: "POST", body: {} })
        .then(function (result) { probe = result; render(); })
        .catch(function (error) { U.notify(error.message || "The test failed.", "danger"); btn.disabled = false; });
      return;
    }
    if (act === "restart") { runExisting("RestartComputer"); return; }
    if (act === "cancel-restart") { runExisting("CancelRestart"); return; }
    if (act === "shutdown") {
      run("ShutdownComputer", {}, "Shut down " + machine + " in 60 seconds", "The computer stays off, and the agent offline, until someone powers it on. Signed-in users lose unsaved work. Cancel within 60 seconds with \u201CCancel restart or shutdown\u201D.");
      return;
    }
    if (act === "svc") {
      const name = btn.getAttribute("data-name");
      const op = btn.getAttribute("data-op");
      run("ServiceControl", { name: name, action: op }, op[0].toUpperCase() + op.slice(1) + " service " + name, op === "start" ? "" : "Dependent services are stopped too and are restarted afterwards where possible.");
      return;
    }
    if (act === "profile") {
      const profile = btn.getAttribute("data-profile");
      const on = btn.getAttribute("data-value") === "true";
      run("SetFirewallProfile", { profile: profile, enabled: on }, "Turn " + (on ? "on" : "off") + " the " + profile + " firewall profile",
        on ? "Inbound connections without an allow rule are blocked. The agent connects outbound, so it stays in contact." : "The computer accepts every inbound connection on networks of this type. Group Policy may turn it back on.");
      return;
    }
    if (act === "rule-add") { ruleForm(null); return; }
    if (act === "rule-edit") { const r = findRule(btn.getAttribute("data-id")); if (r) { ruleForm(r); } return; }
    if (act === "rule-toggle" || act === "rule-remove") {
      const r = findRule(btn.getAttribute("data-id"));
      if (!r) { return; }
      const op = act === "rule-remove" ? "remove" : btn.getAttribute("data-value") === "true" ? "enable" : "disable";
      const rdpRisk = op !== "enable" && r.direction === "Inbound" && /remote desktop/i.test(r.group || "");
      run("FirewallRule", { op: op, id: r.id, label: r.name }, op[0].toUpperCase() + op.slice(1) + " firewall rule \"" + r.name + "\"",
        rdpRisk ? "Remote Desktop connections to this computer will be refused." : "");
      return;
    }
    if (act === "rdp") {
      const on = btn.getAttribute("data-value") === "true";
      const remote = list(s.sessions).filter(function (x) { return x.remote && x.state === "Active"; }).length;
      run("SetRemoteDesktop", { enabled: on }, (on ? "Enable" : "Disable") + " Remote Desktop on " + machine,
        on ? "The Remote Desktop firewall rules are enabled too." + ((s.remoteDesktop || {}).nla ? "" : " Network Level Authentication is off; consider requiring it.")
          : "New connections are refused" + (remote ? " and " + remote + " active remote session(s) may be disconnected" : "") + ". The agent is not affected.");
      return;
    }
    if (act === "nla") {
      const on = btn.getAttribute("data-value") === "true";
      run("SetNla", { enabled: on }, (on ? "Require" : "Stop requiring") + " Network Level Authentication",
        on ? "Clients must authenticate before a session is created. Very old clients cannot connect." : "Anyone who can reach the port gets a sign-in screen before authenticating. This is less secure.");
      return;
    }
    if (act === "rename") {
      form({
        title: "Rename computer",
        intro: "The new name applies after a restart. " + (c.partOfDomain ? "The computer is in <strong>" + esc(c.domain) + "</strong>: give a domain account that may rename it, so its account in the directory is renamed too." : ""),
        fields: [
          { name: "name", label: "New computer name", value: c.hostname || "", help: "Up to 15 letters, digits and hyphens." },
          { name: "dnsSuffix", label: "Primary DNS suffix (optional)", value: c.configuredDnsSuffix || c.primaryDnsSuffix || "", placeholder: "corp.example.com" },
          { name: "user", label: c.partOfDomain ? "Domain account" : "Domain account (only for domain computers)", value: "", placeholder: "CORP\\admin" },
          { name: "secret", label: "Domain account password", type: "password", help: "Sent once to the agent over HTTPS. It is not stored, logged or shown again." },
          { name: "restart", label: "Restart in 60 seconds to apply the name", type: "checkbox", value: false }
        ],
        check: function (v) {
          if (!v.name) { return "Enter the new computer name."; }
          if (c.partOfDomain && (!v.user || !v.secret)) { return "Enter the domain account and its password."; }
          if (!!v.user !== !!v.secret) { return "Enter both the domain account and its password, or neither."; }
          return "";
        },
        submit: function (v) {
          const secret = v.secret;
          run("SetHostname", { name: v.name, dnsSuffix: v.dnsSuffix, user: v.user, restart: v.restart }, "Rename " + machine + " to " + v.name + (v.dnsSuffix ? " with DNS suffix " + v.dnsSuffix : "") + (v.restart ? " and restart" : ""),
            "The agent keeps its identity; the portal shows the new name after the restart. Update DNS records or certificates that use the old name.", secret);
        }
      });
      return;
    }
    if (act === "join") {
      form({
        title: "Join domain",
        intro: "The computer must resolve the domain's DNS name; point its DNS servers at the domain controllers first. It joins after a restart.",
        fields: [
          { name: "domain", label: "Domain DNS name", placeholder: "corp.example.com" },
          { name: "ouPath", label: "Organizational unit (optional)", placeholder: "OU=Workstations,DC=corp,DC=example,DC=com" },
          { name: "user", label: "Domain account allowed to join computers", placeholder: "CORP\\joinadmin" },
          { name: "secret", label: "Password", type: "password", help: "Sent once to the agent over HTTPS. It is not stored, logged or shown again." },
          { name: "restart", label: "Restart in 60 seconds to complete the join", type: "checkbox", value: true }
        ],
        check: function (v) { return !v.domain ? "Enter the domain name." : !v.user || !v.secret ? "Enter the domain account and its password." : ""; },
        submit: function (v) {
          const secret = v.secret;
          run("JoinDomain", { domain: v.domain, ouPath: v.ouPath, user: v.user, restart: v.restart }, "Join " + machine + " to " + v.domain + (v.ouPath ? " in " + v.ouPath : "") + (v.restart ? " and restart" : ""),
            "Domain policies apply after the restart and may change the firewall, Remote Desktop and local administrators.", secret);
        }
      });
      return;
    }
    if (act === "leave") {
      const localAdmins = list(s.localAdministrators).filter(function (m) { return m.kind === "User" && m.enabled !== false && m.name.indexOf("\\") < 0; });
      form({
        title: "Leave domain",
        intro: "Domain accounts can no longer sign in afterwards. " + (localAdmins.length
          ? "Enabled local administrators: <strong>" + esc(localAdmins.map(function (m) { return m.name; }).join(", ")) + "</strong>. Make sure you know one of their passwords."
          : '<span class="text-danger">No enabled local administrator account was found; the agent refuses to leave the domain until one exists.</span>'),
        fields: [
          { name: "workgroup", label: "Workgroup", value: "WORKGROUP" },
          { name: "user", label: "Domain account allowed to remove the computer", placeholder: "CORP\\admin" },
          { name: "secret", label: "Password", type: "password", help: "Sent once to the agent over HTTPS. It is not stored, logged or shown again." },
          { name: "restart", label: "Restart in 60 seconds to complete", type: "checkbox", value: true }
        ],
        check: function (v) { return !v.user || !v.secret ? "Enter the domain account and its password." : ""; },
        submit: function (v) {
          const secret = v.secret;
          run("LeaveDomain", { workgroup: v.workgroup, user: v.user, restart: v.restart }, "Remove " + machine + " from " + (c.domain || "the domain") + " into workgroup " + (v.workgroup || "WORKGROUP") + (v.restart ? " and restart" : ""),
            "Only local accounts can sign in afterwards. Rejoining needs a domain account.", secret);
        }
      });
      return;
    }
    if (act === "dns") {
      const index = Number(btn.getAttribute("data-index"));
      const nic = list(s.network).find(function (n) { return n.index === index; }) || {};
      form({
        title: "Change DNS servers: " + (nic.name || "adapter " + index),
        intro: "After the change the agent resolves <strong>" + esc(s.managerHost || "the portal") + "</strong> (or the name below). If that fails, the previous DNS servers are restored automatically.",
        fields: [
          { name: "servers", label: "DNS servers", value: list(nic.dnsServers).filter(function (d) { return d.indexOf(":") < 0; }).join(", "), placeholder: "10.0.0.10, 10.0.0.11 or dhcp", help: "IP addresses separated by commas, or <strong>dhcp</strong> to use the servers from DHCP." },
          { name: "setSearchList", label: "Also set the DNS search domains for the computer", type: "checkbox", value: false },
          { name: "searchList", label: "Search domains", value: list(c.searchList).join(", "), placeholder: "corp.example.com, example.com", help: "Comma-separated. Leave empty to clear the list." },
          { name: "testHost", label: "Name to test after the change (optional)", placeholder: s.managerHost || "uagent.corp.example.com" }
        ],
        check: function (v) { return v.servers ? "" : "Enter at least one DNS server, or dhcp."; },
        submit: function (v) {
          run("SetDns", { interfaceIndex: index, adapterName: nic.name, servers: v.servers, setSearchList: v.setSearchList, searchList: v.searchList, testHost: v.testHost },
            "Set the DNS servers of " + (nic.name || "adapter " + index) + " to " + v.servers + (v.setSearchList ? "; search domains " + (v.searchList || "cleared") : ""),
            "Wrong servers can stop the computer finding the domain and the portal; the agent reverts the change if the test name does not resolve.");
        }
      });
    }
  }

  // --- Wiring -----------------------------------------------------------------------------------
  document.addEventListener("ua:agent-loaded", function (event) {
    agentState = event.detail.state;
    role = event.detail.role;
    if (!loadedOnce && supported()) {
      loadedOnce = true;
      load();
      return;
    }
    render();
  });

  $("pane-system").addEventListener("click", function (event) {
    const nav = event.target.closest("[data-sys-view]");
    if (nav) {
      view = nav.getAttribute("data-sys-view");
      render();
      return;
    }
    const exp = event.target.closest("[data-sys-export]");
    if (exp) {
      exportData(exp.getAttribute("data-sys-export"));
      return;
    }
    const act = event.target.closest("[data-sys-act]");
    if (act && !act.disabled) {
      onAction(act);
    }
  });

  $("sysRefresh").addEventListener("click", function () { collect(false); });

  $("pane-system").addEventListener("input", function (event) {
    const id = event.target.id;
    if (id === "sysRuleSearch") { filters.rules = event.target.value; render(); }
    if (id === "sysServiceSearch") { filters.services = event.target.value; render(); }
  });
  $("pane-system").addEventListener("change", function (event) {
    const id = event.target.id;
    if (id === "sysRuleDirection") { filters.ruleDirection = event.target.value; render(); }
    if (id === "sysRuleShow") { filters.ruleShow = event.target.value; render(); }
    if (id === "sysServiceStatus") { filters.serviceStatus = event.target.value; render(); }
  });

  U.onChange(function (batch) {
    if (!agentState) {
      return;
    }
    const id = agentState.agent.agentId;
    if (batch.some(function (e) { return e.type === "inventory" && e.agentId === id && (e.section === "admin" || e.section === "services"); })) {
      load();
    }
  });
})();
