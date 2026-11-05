// Portal server page: the Linux host the portal runs on. Controls appear only for what this platform
// supports, only for Administrators, and only when the root helper is installed. Every change goes through
// the shared confirmation dialog (reason, typed host name, portal password).
(function () {
  "use strict";
  const U = window.uAgent;
  const $ = function (id) { return document.getElementById(id); };
  const esc = U.escapeHtml;
  const UNUSED_DAYS = 90;

  let data = null;
  let view = "overview";
  let loading = false;
  let logText = "";
  let logName = "";
  const filters = { services: "", serviceState: "" };

  function list(v) { return Array.isArray(v) ? v : []; }
  function dash(v) { return v === null || v === undefined || v === "" ? '<span class="subtle">\u2014</span>' : esc(String(v)); }
  function when(v) { return v ? esc(U.formatDateTime(v)) + ' <span class="subtle">(' + esc(U.relativeTime(v)) + ")</span>" : '<span class="subtle">Never</span>'; }
  function pill(tone, label) { return U.pill(tone, label, true); }
  function ms(v) { const t = v ? Date.parse(v) : NaN; return Number.isFinite(t) ? t : 0; }
  function priv() { return data && data.privileged && data.privileged.ok ? data.privileged : null; }
  function uptime(seconds) {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return (d ? d + "d " : "") + h + "h " + m + "m";
  }

  function blocked() {
    if (!data || !data.canChange) { return "Server changes require the Administrator role."; }
    if (!data.platform.helperInstalled) { return "The uagent-sysadmin helper is not installed on this server."; }
    if (data.portal.running) { return data.portal.running.summary + " is still running."; }
    return "";
  }

  function button(label, attrs, tone) {
    const why = blocked();
    return '<button type="button" class="btn btn-sm ' + (tone || "btn-outline-secondary") + '"' + (why ? ' disabled title="' + esc(why) + '"' : "") + " " + attrs + ">" + label + "</button>";
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

  // --- Data -------------------------------------------------------------------------------------
  async function load() {
    if (loading) { return; }
    loading = true;
    $("srvRefresh").disabled = true;
    $("srvCollected").textContent = "Collecting\u2026";
    try {
      data = await U.api("/api/server/info");
    } catch (error) {
      $("srvBanners").innerHTML = '<div class="banner banner-danger"><i class="bi bi-exclamation-octagon"></i><div>' + esc(error.message || "Could not read the server.") + "</div></div>";
    }
    loading = false;
    $("srvRefresh").disabled = false;
    render();
  }

  function act(action, parameters, summary, warning, secret) {
    const host = data.hostname || "server";
    U.runAction({
      agentKey: "",
      machineName: host,
      control: { type: action, label: summary, description: warning || "", sensitive: true, reauth: true, needsPassword: false },
      submit: async function (values) {
        const result = await U.api("/api/server/actions", {
          method: "POST",
          body: { action: action, parameters: parameters, secret: secret || undefined, reason: values.reason, currentPassword: values.currentPassword, confirmed: true }
        });
        secret = null;
        U.notify(result.message || summary + " done.", "success");
        load();
      }
    });
  }

  async function lookup(domain) {
    try {
      const result = await U.api("/api/server/actions", { method: "POST", body: { action: "domain-discover", parameters: { domain: domain } } });
      showLog("Domain " + domain, result.message || "");
    } catch (error) {
      U.notify(error.message, "danger");
    }
  }

  async function confirmFirewall(keep) {
    try {
      const result = keep
        ? await U.api("/api/server/firewall/confirm", { method: "POST", body: {} })
        : await U.api("/api/server/actions", { method: "POST", body: { action: "firewall-revert", parameters: {}, reason: "Revert the unconfirmed firewall change", confirmed: true, currentPassword: await askPassword() } });
      U.notify(result.message, "success");
    } catch (error) {
      if (error && error.message) { U.notify(error.message, "danger"); }
    }
    load();
  }

  function askPassword() {
    return new Promise(function (resolve, reject) {
      U.formDialog({
        title: "Revert firewall change",
        intro: "Enter your portal password to undo the change now.",
        fields: [{ name: "password", label: "Your portal password", type: "password" }],
        check: function (v) { return v.password ? "" : "Enter your password."; },
        submit: function (v) { resolve(v.password); }
      });
      setTimeout(function () { reject(new Error("")); }, 5 * 60 * 1000);
    });
  }

  function showLog(title, text) {
    logText = text;
    logName = title.replace(/[^A-Za-z0-9_.-]+/g, "-").toLowerCase();
    $("srvLogTitle").textContent = title;
    $("srvLogText").textContent = text || "(empty)";
    bootstrap.Modal.getOrCreateInstance($("srvLogModal")).show();
  }

  async function openLog(source) {
    try {
      const res = await fetch("/api/server/logs/" + encodeURIComponent(source) + "?lines=2000", { credentials: "same-origin", headers: { Accept: "text/plain" } });
      const text = await res.text();
      if (!res.ok) {
        let message = text;
        try { message = JSON.parse(text).error; } catch (e) { /* plain text */ }
        throw new Error(message);
      }
      showLog((data.hostname || "server") + " " + source + " log", text);
    } catch (error) {
      U.notify(error.message || "Could not read the log.", "danger");
    }
  }

  function download(name, type, content) {
    const url = URL.createObjectURL(new Blob([content], { type: type }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function csvCell(v) {
    let s = v === null || v === undefined ? "" : String(v);
    if (/^[=+\-@\t\r]/.test(s)) { s = "'" + s; }
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  // --- Rendering --------------------------------------------------------------------------------
  function renderBanners() {
    const items = [];
    if (!data.supported) {
      items.push('<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>Server administration covers Linux servers. This portal runs on <strong>' + esc(data.platform.os) +
        "</strong>, so no server controls are offered here. Windows computers are administered from their agent page (System tab).</div></div>");
      return items.join("");
    }
    const p = data.privileged || {};
    if (!data.platform.helperInstalled || !p.ok) {
      items.push('<div class="banner banner-warning"><i class="bi bi-exclamation-triangle"></i><div>' +
        esc(p.error || "The root helper is not available.") + " Basic information is shown; firewall, account and log details and all changes need the helper.</div></div>");
    }
    const pending = priv() && priv().firewall && priv().firewall.revertPending;
    if (pending) {
      const left = Math.max(0, Math.round((ms(pending.armedUtc) + pending.revertSeconds * 1000 - Date.now()) / 1000));
      items.push('<div class="banner banner-warning"><i class="bi bi-hourglass-split"></i><div><strong>Firewall change not yet kept:</strong> ' + esc(pending.description) +
        ". It is undone automatically in about " + left + " seconds. Keep it if SSH and the portal still work." +
        (data.canChange ? ' <button type="button" class="btn btn-sm btn-primary ms-2" data-srv-act="fw-keep">Keep change</button> <button type="button" class="btn btn-sm btn-outline-secondary" data-srv-act="fw-revert">Revert now</button>' : "") +
        "</div></div>");
    }
    if (data.portal.running) {
      items.push('<div class="banner banner-info"><span class="spinner-border spinner-border-sm"></span><div>' + esc(data.portal.running.summary) + " is running (started by " + esc(data.portal.running.user) + ").</div></div>");
    }
    if (!data.canChange) {
      items.push('<div class="banner banner-info"><i class="bi bi-eye"></i><div>Server changes require the Administrator role. You can view this information.</div></div>');
    }
    return items.join("");
  }

  function render() {
    if (!data) { return; }
    document.querySelectorAll("[data-srv-view]").forEach(function (b) { b.classList.toggle("active", b.getAttribute("data-srv-view") === view); });
    $("srvHost").textContent = data.hostname || "Portal server";
    $("srvFqdn").textContent = data.fqdn && data.fqdn !== data.hostname ? data.fqdn : "";
    $("srvPlatform").innerHTML = data.supported ? pill("info", (data.os && data.os.name) || "Linux") : pill("neutral", data.platform.os);
    $("srvCollected").textContent = data.collectedUtc ? "Collected " + U.relativeTime(data.collectedUtc).toLowerCase() : "";
    $("srvLogsMenu").hidden = !(data.canChange && data.supported);
    $("srvBanners").innerHTML = renderBanners();
    const body = $("srvBody");
    if (!data.supported) {
      body.innerHTML = '<p class="subtle mb-0">Nothing to show on this platform.</p>';
      return;
    }
    body.innerHTML = ({ overview: overviewView, access: accessView, firewall: firewallView, services: servicesView, domain: domainView, events: eventsView }[view] || overviewView)();
  }

  function overviewView() {
    const d = data;
    const mem = d.memory || {};
    const used = mem.totalBytes - mem.availableBytes;
    const backups = (priv() && priv().backups) || {};
    let html = '<div class="info-grid">' + panel("Identity", kv([
      ["Host name", dash(d.hostname)],
      ["FQDN", '<span class="mono">' + dash(d.fqdn) + "</span>"],
      ["DNS servers", d.dns.nameservers.length ? '<span class="mono">' + esc(d.dns.nameservers.join(", ")) + "</span>" : dash(null)],
      ["Search domains", d.dns.search.length ? esc(d.dns.search.join(", ")) : dash(null)],
      ["Domain", realmText()],
      ["SELinux", dash(priv() && priv().selinux)]
    ]), button('<i class="bi bi-pencil me-1"></i>Change host name', 'data-srv-act="hostname"') + (backups.hostname ? " " + button("Restore " + esc(backups.hostname.previous), 'data-srv-act="hostname-restore"') : "")) +
      panel("Operating system and resources", kv([
        ["Operating system", dash(d.os.name)],
        ["Kernel", '<span class="mono">' + dash(d.os.kernel) + "</span>"],
        ["Architecture", dash(d.os.architecture)],
        ["Processors", esc(d.cpu.count + " \u00D7 " + (d.cpu.model || "CPU")) + ' <span class="subtle">(load ' + esc(d.loadAverage.map(function (x) { return x.toFixed(2); }).join(", ")) + ")</span>"],
        ["Memory", esc(U.formatBytes(used) + " used of " + U.formatBytes(mem.totalBytes)) + ' <span class="subtle">(' + Math.round(used / mem.totalBytes * 100) + "%)</span>"],
        ["Swap", mem.swapTotalBytes ? esc(U.formatBytes(mem.swapTotalBytes - mem.swapFreeBytes) + " used of " + U.formatBytes(mem.swapTotalBytes)) : dash("None")],
        ["Last boot", when(d.bootUtc)],
        ["Uptime", esc(uptime(d.uptimeSeconds))]
      ])) + "</div>";

    html += section("Disks", table(["Mount", "Filesystem", "Used", "Free", "Size"], d.disks.map(function (x) {
      const pct = x.totalBytes ? Math.round(x.usedBytes / x.totalBytes * 100) : 0;
      return '<tr><td class="mono">' + esc(x.mount) + '</td><td class="mono small">' + esc(x.filesystem) + "</td><td>" + (pct >= 90 ? pill("danger", pct + "%") : pct >= 80 ? pill("warning", pct + "%") : esc(pct + "%")) +
        "</td><td>" + esc(U.formatBytes(x.freeBytes)) + "</td><td>" + esc(U.formatBytes(x.totalBytes)) + "</td></tr>";
    }), "No disks reported."));

    html += section("Network interfaces", table(["Interface", "State", "Addresses", "MAC"], d.interfaces.filter(function (i) { return i.name !== "lo"; }).map(function (i) {
      return "<tr><td>" + esc(i.name) + "</td><td>" + (i.state === "UP" ? pill("success", "Up") : pill("neutral", i.state || "Unknown")) + '</td><td class="mono small">' + (i.addresses.map(esc).join("<br>") || dash(null)) +
        '</td><td class="mono small">' + dash(i.mac) + "</td></tr>";
    }), "No interfaces reported.") + '<p class="subtle small mt-2 mb-0">Default gateway: <span class="mono">' + esc(d.gateways.map(function (g) { return g.gateway + " via " + g.device; }).join(", ") || "none") + "</span></p>");

    html += section("Connections and DNS (NetworkManager)", table(["Connection", "Device", "Method", "DNS servers", "Search domains", ""], d.connections.map(function (c) {
      const hasBackup = list(backups.dns).indexOf("dns-" + c.uuid + ".json") >= 0;
      return "<tr><td>" + esc(c.name) + '</td><td class="mono">' + esc(c.device) + "</td><td>" + esc(c.method) + '</td><td class="mono small">' + (c.dns.length ? esc(c.dns.join(", ")) : '<span class="subtle">From DHCP</span>') +
        "</td><td>" + (c.search.length ? esc(c.search.join(", ")) : dash(null)) + '</td><td class="text-nowrap">' + button("Change DNS", 'data-srv-act="dns" data-uuid="' + esc(c.uuid) + '"') +
        (hasBackup ? " " + button("Restore", 'data-srv-act="dns-restore" data-uuid="' + esc(c.uuid) + '"') : "") + "</td></tr>";
    }), "NetworkManager reports no active connections, so DNS is not managed from here."));

    html += section("Listening ports <span class=\"subtle small\">(" + d.listening.length + ")</span>", table(["Protocol", "Address", "Port"], d.listening.slice().sort(function (a, b) { return a.port - b.port; }).map(function (l) {
      return "<tr><td>" + esc(l.protocol) + '</td><td class="mono">' + esc(l.address) + '</td><td class="mono">' + esc(l.port) + "</td></tr>";
    }), "No listening ports."));
    return html;
  }

  function realmText() {
    const realm = priv() && priv().realm;
    if (!realm) { return dash(null); }
    if (!realm.installed) { return '<span class="subtle">Not joined (realmd not installed)</span>'; }
    const joined = list(realm.realms).filter(function (r) { return r.configured && r.configured !== "no"; });
    return joined.length ? pill("info", "Domain") + " " + esc(joined.map(function (r) { return r.name; }).join(", ")) : '<span class="subtle">Not joined</span>';
  }

  function accessView() {
    const p = priv() || {};
    const sessions = list(data.sessions);
    const logins = list(data.logins).slice().sort(function (a, b) { return ms(b.startUtc) - ms(a.startUtc); });
    const failed = list(p.failedLogins).slice().sort(function (a, b) { return ms(b.startUtc) - ms(a.startUtc); });
    const accounts = list(p.accounts);
    const admins = new Set(accounts.filter(function (a) { return a.admin; }).map(function (a) { return a.user; }));
    const lastAdmin = logins.find(function (l) { return admins.has(l.user); });
    const portal = data.portal;
    const ssh = p.ssh || {};
    const xrdp = p.xrdp || {};
    const activity = accounts.map(function (a) {
      const own = sessions.filter(function (s) { return s.user === a.user; });
      const history = logins.filter(function (l) { return l.user === a.user; });
      const lastLogin = Math.max(ms(a.lastLoginUtc), history.reduce(function (t, l) { return Math.max(t, ms(l.startUtc)); }, 0));
      const lastActivity = Math.max(lastLogin, own.reduce(function (t, s) { return Math.max(t, s.idle ? ms(s.idleSinceUtc) : Date.now()); }, 0),
        history.reduce(function (t, l) { return Math.max(t, ms(l.endUtc)); }, 0));
      const can = a.interactive && !a.locked;
      const usage = own.length || (lastLogin && Date.now() - lastLogin <= UNUSED_DAYS * 86400000) ? "In use"
        : lastLogin ? "Unused" : a.lastLoginKnown === false ? "Unknown" : "Never signed in";
      return { a: a, can: can, sessions: own.length, usage: usage, lastLoginUtc: lastLogin ? new Date(lastLogin).toISOString() : null, lastActivityUtc: lastActivity ? new Date(lastActivity).toISOString() : null };
    });

    let html = '<div class="stat-strip">' +
      "<div><div class=\"label\">Sessions now</div><div class=\"value\">" + sessions.length + "</div></div>" +
      "<div><div class=\"label\">Remote sessions</div><div class=\"value\">" + sessions.filter(function (s) { return s.remote; }).length + "</div></div>" +
      "<div><div class=\"label\">Recent sign-ins</div><div class=\"value\">" + logins.length + "</div></div>" +
      "<div><div class=\"label\">Failed sign-ins</div><div class=\"value\">" + failed.length + "</div></div>" +
      "<div><div class=\"label\">Unused accounts</div><div class=\"value\">" + activity.filter(function (r) { return r.can && (r.usage === "Unused" || r.usage === "Never signed in"); }).length + "</div></div></div>";

    html += '<div class="info-grid">' + panel("Last sign-in", kv([
      ["Server, any user", logins[0] ? esc(logins[0].user) + " from " + esc(logins[0].from || "console") + "<br>" + when(logins[0].startUtc) : '<span class="subtle">None recorded</span>'],
      ["Server, administrator", lastAdmin ? esc(lastAdmin.user) + " from " + esc(lastAdmin.from || "console") + "<br>" + when(lastAdmin.startUtc) : '<span class="subtle">None recorded</span>'],
      ["Portal, administrator", portal.lastAdministratorSignIn ? esc(portal.lastAdministratorSignIn.user) + " from " + esc(portal.lastAdministratorSignIn.remoteIp) + "<br>" + when(portal.lastAdministratorSignIn.timeUtc) : '<span class="subtle">None recorded</span>']
    ])) + panel("Remote access", kv([
      ["SSH", ssh.installed ? (ssh.active === "active" ? pill("success", "Running") : pill("danger", ssh.active || "Stopped")) + ' <span class="subtle">port ' + esc(list(ssh.ports).join(", ")) + ", " + esc(ssh.enabled) + "</span>" : dash("Not installed")],
      ["Remote Desktop", xrdp.installed ? "xrdp " + (xrdp.active === "active" ? pill("success", "Running") : pill("neutral", xrdp.active)) : '<span class="subtle">Not applicable. Windows Remote Desktop and NLA do not exist on Linux; xrdp is not installed.</span>']
    ])) + "</div>";

    html += section("Sessions now", table(["User", "Type", "From", "Started", "State"], sessions.map(function (s) {
      return "<tr><td>" + esc(s.user) + "</td><td>" + esc(s.service || s.type || "") + (s.tty ? ' <span class="mono small">' + esc(s.tty) + "</span>" : "") + "</td><td>" + (s.remote ? '<span class="mono">' + esc(s.remoteHost || "") + "</span>" : '<span class="subtle">Console</span>') +
        "</td><td>" + when(s.startedUtc) + "</td><td>" + (s.idle ? pill("neutral", "Idle") : pill("success", s.state || "Active")) + "</td></tr>";
    }), "Nobody is signed in."));

    html += section("Accounts", '<p class="subtle small">Separate facts per account: whether it <strong>can sign in</strong> (shell and unlocked password), whether it has a <strong>session now</strong>, and whether it was <strong>used</strong> in the last ' + UNUSED_DAYS + " days. When the sign-in record cannot be read, usage is shown as unknown rather than unused.</p>" +
      table(["Account", "Can sign in", "Session", "Usage", "Last sign-in", "Last activity", "Password changed", "Expires"], activity.map(function (r) {
        const a = r.a;
        const unknownWhen = r.usage === "Unknown" ? '<span class="subtle">Unknown</span>' : when(r.lastLoginUtc);
        return "<tr><td><span class=\"cell-primary\">" + esc(a.user) + '</span> <span class="subtle small">uid ' + esc(a.uid) + "</span>" + (a.admin ? " " + pill("info", "Administrator") : "") + "</td>" +
          "<td>" + (r.can ? pill("success", a.noPassword ? "Yes (no password)" : "Yes") : pill("neutral", a.locked ? "Locked" : "No shell")) + "</td>" +
          "<td>" + (r.sessions ? pill("success", r.sessions > 1 ? r.sessions + " sessions" : "Session active") : '<span class="subtle">No session</span>') + "</td>" +
          "<td>" + (r.usage === "In use" ? pill("success", "In use") : r.usage === "Unknown" ? pill("neutral", "Unknown") : pill(r.can ? "warning" : "neutral", r.usage)) + "</td>" +
          "<td>" + unknownWhen + (a.lastLoginFrom ? ' <span class="mono small">' + esc(a.lastLoginFrom) + "</span>" : "") + "</td><td>" + (r.usage === "Unknown" && !r.lastActivityUtc ? '<span class="subtle">Unknown</span>' : when(r.lastActivityUtc)) + "</td>" +
          "<td>" + dash(a.passwordChanged) + "</td><td>" + dash(a.expires || "Never") + "</td></tr>";
      }), p.ok ? "No accounts." : "Account details need the helper."));

    html += section("Recent sign-ins", table(["Time", "User", "Line", "From", "Ended"], logins.slice(0, 60).map(function (l) {
      return '<tr><td class="text-nowrap">' + esc(U.formatDateTime(l.startUtc)) + "</td><td>" + esc(l.user) + (admins.has(l.user) ? " " + pill("info", "Admin") : "") + '</td><td class="mono small">' + esc(l.line) + '</td><td class="mono small">' + dash(l.from) + "</td><td>" + (l.endUtc ? esc(U.formatDateTime(l.endUtc)) : esc(l.state)) + "</td></tr>";
    }), "No sign-ins recorded."));
    html += section("Failed sign-ins", table(["Time", "User", "Line", "From"], failed.slice(0, 100).map(function (l) {
      return '<tr><td class="text-nowrap">' + esc(U.formatDateTime(l.startUtc)) + "</td><td>" + esc(l.user) + '</td><td class="mono small">' + esc(l.line) + '</td><td class="mono small">' + dash(l.from) + "</td></tr>";
    }), p.ok ? "No failed sign-ins recorded." : "Failed sign-ins need the helper."));
    html += section("Portal sign-ins", table(["Time", "User", "Result", "From", "Detail"], list(portal.signIns).map(function (e) {
      return '<tr><td class="text-nowrap">' + esc(U.formatDateTime(e.timeUtc)) + "</td><td>" + esc(e.user) + "</td><td>" + U.statusPill(e.result) + '</td><td class="mono small">' + esc(e.remoteIp) + "</td><td>" + esc(e.details) + "</td></tr>";
    }), "No portal sign-ins recorded."));
    return html;
  }

  function firewallView() {
    const p = priv();
    if (!p) { return '<p class="subtle">Firewall details need the helper.</p>'; }
    const fw = p.firewall || {};
    if (!fw.installed) { return '<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>firewalld is not installed on this server.</div></div>'; }
    let html = '<div class="sys-states">' +
      '<div class="sys-state"><div class="label">Firewall</div><div>' + (fw.running ? pill("success", "On") : pill("danger", "Off")) + '</div><div class="subtle small">firewalld ' + esc(fw.active) + ", " + esc(fw.enabled) + " at boot</div></div>" +
      (fw.running ? '<div class="sys-state"><div class="label">Default zone</div><div>' + esc(fw.defaultZone) + "</div></div>" +
        '<div class="sys-state"><div class="label">Panic mode</div><div>' + (fw.panic ? pill("danger", "On (all traffic dropped)") : pill("success", "Off")) + "</div></div>" : "") + "</div>";
    html += '<div class="sys-toolbar">' + (fw.running
      ? button('<i class="bi bi-shield-slash me-1"></i>Turn firewall off', 'data-srv-act="fw-state" data-value="false"', "btn-outline-danger")
      : button('<i class="bi bi-shield-check me-1"></i>Turn firewall on', 'data-srv-act="fw-state" data-value="true"', "btn-primary")) + "</div>";
    if (!fw.running) { return html; }
    list(fw.zones).forEach(function (z) {
      const unsaved = function (items, saved) { return items.filter(function (x) { return saved.indexOf(x) < 0; }); };
      const pendingPorts = unsaved(list(z.ports), list(z.permanentPorts));
      const pendingServices = unsaved(list(z.services), list(z.permanentServices));
      html += section("Zone " + esc(z.name) + (z.default ? " " + pill("info", "Default") : "") + (z.active ? " " + pill("success", "Active") : ""),
        kv([
          ["Interfaces", z.interfaces.length ? '<span class="mono">' + esc(z.interfaces.join(", ")) + "</span>" : dash(null)],
          ["Sources", z.sources.length ? '<span class="mono">' + esc(z.sources.join(", ")) + "</span>" : dash(null)],
          ["Target", dash(z.target)],
          ["Everything else", z.target === "ACCEPT" ? pill("danger", "Allowed (zone accepts all traffic)") : z.target === "DROP" ? pill("success", "Blocked (dropped silently)")
            : z.target ? pill("success", "Blocked (rejected)") : dash(null)]
        ]) +
        table(["Allowed", "Kind", "Saved", ""], list(z.services).map(function (s) {
          return "<tr><td>" + esc(s) + "</td><td>Service</td><td>" + (pendingServices.indexOf(s) >= 0 ? pill("warning", "Not saved") : pill("success", "Yes")) + "</td><td>" + button("Remove", 'data-srv-act="fw-remove" data-kind="service" data-zone="' + esc(z.name) + '" data-value="' + esc(s) + '"', "btn-outline-danger") + "</td></tr>";
        }).concat(list(z.ports).map(function (port) {
          return '<tr><td class="mono">' + esc(port) + "</td><td>Port</td><td>" + (pendingPorts.indexOf(port) >= 0 ? pill("warning", "Not saved") : pill("success", "Yes")) + "</td><td>" + button("Remove", 'data-srv-act="fw-remove" data-kind="port" data-zone="' + esc(z.name) + '" data-value="' + esc(port) + '"', "btn-outline-danger") + "</td></tr>";
        })), "Nothing is allowed in this zone.") +
        (list(z.richRules).length ? '<p class="subtle small mt-2 mb-1">Rich rules (change them with firewall-cmd on the server):</p><pre class="mono small mb-0">' + esc(z.richRules.join("\n")) + "</pre>" : ""),
        button('<i class="bi bi-plus-lg me-1"></i>Allow port or service', 'data-srv-act="fw-add" data-zone="' + esc(z.name) + '"', "btn-primary"));
    });
    return html;
  }

  function servicesView() {
    const q = filters.services.toLowerCase();
    const services = list(data.services).filter(function (s) {
      if (filters.serviceState && s.active !== filters.serviceState) { return false; }
      return !q || (s.name + " " + s.description).toLowerCase().includes(q);
    });
    const power = list((priv() || {}).power);
    const lastBoot = power.find(function (e) { return e.user === "reboot"; });
    const lastShutdown = power.find(function (e) { return e.user === "shutdown"; });
    let html = '<div class="info-grid">' + panel("Power", kv([
      ["Last boot", when(lastBoot ? lastBoot.startUtc : data.bootUtc)],
      ["Last shutdown", lastShutdown ? when(lastShutdown.startUtc) : '<span class="subtle">Not recorded</span>']
    ]) + '<div class="sys-toolbar px-3 pb-3">' + button('<i class="bi bi-arrow-repeat me-1"></i>Restart', 'data-srv-act="power" data-value="reboot"') + " " +
      button("Cancel restart or shutdown", 'data-srv-act="power" data-value="cancel"') + " " +
      button('<i class="bi bi-power me-1"></i>Shut down', 'data-srv-act="power" data-value="poweroff"', "btn-outline-danger") + "</div>") +
      panel("Boot history", power.length ? '<ul class="sys-list">' + power.slice(0, 12).map(function (e) {
        return "<li>" + esc(U.formatDateTime(e.startUtc)) + " \u2014 " + (e.user === "reboot" ? "Started (kernel " + esc(e.from) + ")" : "Shut down") + "</li>";
      }).join("") + "</ul>" : '<p class="subtle small p-3 mb-0">Not recorded.</p>') + "</div>";
    const states = Array.from(new Set(list(data.services).map(function (s) { return s.active; }))).sort();
    html += '<div class="sys-section"><div class="sys-section-head"><h3 class="section-title mb-0">Services</h3></div>' +
      '<div class="toolbar px-0"><div class="search"><i class="bi bi-search"></i><input class="form-control form-control-sm" id="srvServiceSearch" placeholder="Search services" value="' + esc(filters.services) + '"></div>' +
      '<select class="form-select form-select-sm" id="srvServiceState"><option value="">Any state</option>' + states.map(function (s) { return '<option value="' + esc(s) + '"' + (filters.serviceState === s ? " selected" : "") + ">" + esc(s) + "</option>"; }).join("") +
      '</select><span class="count">' + services.length + " of " + list(data.services).length + "</span></div>" +
      table(["Service", "State", "At boot", ""], services.slice(0, 400).map(function (s) {
        const protectedUnit = /^(sshd|NetworkManager|network|dbus|dbus-broker|polkit|systemd-.*|firewalld|auditd|getty@.*|serial-getty@.*|uagent-portal)\.service$/.test(s.name);
        const restartable = ["uagent-portal.service", "sshd.service", "NetworkManager.service", "firewalld.service"].indexOf(s.name) >= 0;
        let actions = "";
        if (s.load !== "loaded") {
          actions = '<span class="subtle small">' + esc(s.load) + "</span>";
        } else if (s.active !== "active") {
          actions = button("Start", 'data-srv-act="svc" data-name="' + esc(s.name) + '" data-op="start"');
        } else {
          actions = (!protectedUnit || restartable ? button("Restart", 'data-srv-act="svc" data-name="' + esc(s.name) + '" data-op="restart"') : "") +
            (protectedUnit ? ' <span class="subtle small" title="Needed to reach or manage the server.">Protected</span>' : " " + button("Stop", 'data-srv-act="svc" data-name="' + esc(s.name) + '" data-op="stop"', "btn-outline-danger"));
        }
        return "<tr><td><span class=\"cell-primary\">" + esc(s.name) + '</span><div class="subtle small">' + esc(s.description) + "</div></td><td>" +
          (s.active === "active" ? pill("success", s.sub) : s.active === "failed" ? pill("danger", "failed") : pill("neutral", s.sub || s.active)) + "</td><td>" + dash(s.enabled) + '</td><td class="text-nowrap">' + actions + "</td></tr>";
      }), "No services match.") + "</div>";
    return html;
  }

  function domainView() {
    const realm = (priv() || {}).realm;
    if (!priv()) { return '<p class="subtle">Domain details need the helper.</p>'; }
    if (!realm || !realm.installed) {
      return '<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>Joining an Active Directory or IdM domain uses realmd, which is not installed. Install it on the server with <span class="mono">dnf install realmd sssd adcli oddjob oddjob-mkhomedir samba-common-tools</span>, then refresh.</div></div>';
    }
    const joined = list(realm.realms).filter(function (r) { return r.configured && r.configured !== "no"; });
    let html = '<div class="sys-toolbar">' + (joined.length
      ? button('<i class="bi bi-box-arrow-left me-1"></i>Leave domain', 'data-srv-act="domain-leave"', "btn-outline-danger")
      : button('<i class="bi bi-diagram-3 me-1"></i>Join domain', 'data-srv-act="domain-join"', "btn-primary")) + " " +
      (data.canChange ? '<button type="button" class="btn btn-sm btn-outline-secondary" data-srv-act="domain-discover"><i class="bi bi-search me-1"></i>Look up a domain</button>' : "") + "</div>";
    html += table(["Realm", "Type", "Configured", "Login formats", "Permitted logins"], list(realm.realms).map(function (r) {
      return "<tr><td>" + esc(r.name) + "</td><td>" + dash(r.server_software || r.type) + "</td><td>" + (r.configured && r.configured !== "no" ? pill("success", r.configured) : pill("neutral", "No")) + "</td><td>" + dash(r.login_formats) + "</td><td>" + dash(r.permitted_logins || r.login_policy) + "</td></tr>";
    }), "This server is not in a domain.");
    return html;
  }

  function eventsView() {
    const p = priv() || {};
    const ops = list(data.portal.operations);
    let html = section("Server operations from this portal", table(["Time", "User", "Operation", "Result", "Detail"], ops.map(function (e) {
      return '<tr><td class="text-nowrap">' + esc(U.formatDateTime(e.timeUtc)) + "</td><td>" + esc(e.user) + "</td><td>" + esc(e.action.replace(/^Server:/, "")) + "</td><td>" + U.statusPill(e.result) + '</td><td><div class="result-text">' + esc(e.details) + "</div></td></tr>";
    }), "No server operations have been run from the portal."));
    const journalTable = function (rows, empty) {
      return table(["Time", "Source", "Message"], list(rows).slice(0, 150).map(function (e) {
        return '<tr><td class="text-nowrap">' + esc(U.formatDateTime(e.timeUtc)) + "</td><td>" + esc(e.source) + "</td><td>" + (e.priority <= 3 ? pill("danger", "Error") + " " : "") + esc(e.message) + "</td></tr>";
      }), empty);
    };
    html += section("Administrative actions <span class=\"subtle small\">(sudo and this helper, 30 days)</span>", journalTable(list(p.adminActions).slice().reverse(), p.ok ? "None recorded." : "Needs the helper."));
    html += section("Configuration changes <span class=\"subtle small\">(host name, firewall, domain, packages, 30 days)</span>", journalTable(list(p.configChanges).slice().reverse(), p.ok ? "None recorded." : "Needs the helper."));
    html += section("Authentication events <span class=\"subtle small\">(7 days)</span>", journalTable(list(p.authEvents).slice().reverse(), p.ok ? "None recorded." : "Needs the helper."));
    html += section("Errors <span class=\"subtle small\">(24 hours)</span>", journalTable(list(p.problems).slice().reverse(), p.ok ? "No errors." : "Needs the helper."));
    return html;
  }

  // --- Actions ----------------------------------------------------------------------------------
  function onAction(btn) {
    const a = btn.getAttribute("data-srv-act");
    const host = data.hostname;
    if (a === "fw-keep") { confirmFirewall(true); return; }
    if (a === "fw-revert") { confirmFirewall(false); return; }
    if (a === "fw-state") {
      const on = btn.getAttribute("data-value") === "true";
      act("firewall-state", { enabled: on }, "Turn the server firewall " + (on ? "on" : "off"),
        on ? "SSH and the portal ports are opened in the default zone first, so access is kept." : "Every listening port on " + host + " becomes reachable from the network.");
      return;
    }
    if (a === "fw-remove") {
      const kind = btn.getAttribute("data-kind");
      const zone = btn.getAttribute("data-zone");
      const value = btn.getAttribute("data-value");
      act(kind === "port" ? "firewall-port" : "firewall-service", kind === "port" ? { op: "remove", zone: zone, port: value } : { op: "remove", zone: zone, service: value },
        (kind === "port" ? "Close port " : "Stop allowing service ") + value + " in zone " + zone,
        "The change is undone automatically after 2 minutes unless you keep it. SSH and the portal ports cannot be closed from here.");
      return;
    }
    if (a === "fw-add") {
      const zone = btn.getAttribute("data-zone");
      const services = list(((priv() || {}).firewall || {}).availableServices);
      U.formDialog({
        title: "Allow in zone " + zone,
        intro: "The change is active at once and undone after 2 minutes unless you keep it.",
        fields: [
          { name: "kind", label: "Allow", type: "select", value: "port", options: [{ value: "port", label: "A port" }, { value: "service", label: "A predefined service" }] },
          { name: "port", label: "Port", placeholder: "8443/tcp or 5000-5100/udp" },
          { name: "service", label: "Service", type: "select", value: "", options: [{ value: "", label: "Choose\u2026" }].concat(services.map(function (s) { return { value: s, label: s }; })) }
        ],
        check: function (v) { return v.kind === "port" ? (/^\d{1,5}(-\d{1,5})?\/(tcp|udp|sctp|dccp)$/i.test(v.port) ? "" : "Enter a port such as 8443/tcp.") : (v.service ? "" : "Choose a service."); },
        submit: function (v) {
          if (v.kind === "port") {
            act("firewall-port", { op: "add", zone: zone, port: v.port.toLowerCase() }, "Open port " + v.port + " in zone " + zone, "Undone after 2 minutes unless kept.");
          } else {
            act("firewall-service", { op: "add", zone: zone, service: v.service }, "Allow service " + v.service + " in zone " + zone, "Undone after 2 minutes unless kept.");
          }
        }
      });
      return;
    }
    if (a === "svc") {
      const name = btn.getAttribute("data-name");
      const op = btn.getAttribute("data-op");
      act("service", { name: name, action: op }, op[0].toUpperCase() + op.slice(1) + " " + name,
        name === "uagent-portal.service" ? "The portal restarts; this page reconnects in a few seconds." : op === "stop" ? "Anything that depends on it stops too." : "");
      return;
    }
    if (a === "power") {
      const op = btn.getAttribute("data-value");
      act("power", { action: op }, { reboot: "Restart " + host + " in 1 minute", poweroff: "Shut down " + host + " in 1 minute", cancel: "Cancel the scheduled restart or shutdown" }[op],
        op === "poweroff" ? "The portal and every agent connection stay down until someone powers the server on." : op === "reboot" ? "The portal is unavailable for a few minutes. Agents reconnect by themselves." : "");
      return;
    }
    if (a === "hostname") {
      U.formDialog({
        title: "Change host name",
        intro: "Agents and browsers keep using the portal address in Settings (PUBLIC_HOST), so they are not affected. Update DNS records and the certificate if you also change that address.",
        fields: [{ name: "name", label: "New host name or FQDN", value: data.fqdn || data.hostname }],
        check: function (v) { return v.name ? "" : "Enter the host name."; },
        submit: function (v) { act("hostname", { name: v.name }, "Change the host name of " + host + " to " + v.name, "The previous name is recorded and can be restored from this page."); }
      });
      return;
    }
    if (a === "hostname-restore") {
      act("hostname-restore", {}, "Restore the previous host name", "");
      return;
    }
    if (a === "dns" || a === "dns-restore") {
      const uuid = btn.getAttribute("data-uuid");
      const c = data.connections.find(function (x) { return x.uuid === uuid; }) || {};
      if (a === "dns-restore") {
        act("dns-restore", { connection: uuid, connectionName: c.name }, "Restore the previous DNS settings of " + c.name, "");
        return;
      }
      U.formDialog({
        title: "Change DNS: " + c.name,
        intro: "Applied without taking the connection down. If the test name stops resolving, the previous settings are restored automatically.",
        fields: [
          { name: "servers", label: "DNS servers", value: c.dns.join(", "), placeholder: "10.0.0.10, 10.0.0.11 or dhcp", help: "Up to three addresses separated by commas, or <strong>dhcp</strong>." },
          { name: "setSearch", label: "Also set the search domains", type: "checkbox", value: false },
          { name: "search", label: "Search domains", value: c.search.join(", "), placeholder: "corp.example.com" },
          { name: "test", label: "Name to test afterwards", placeholder: "the portal's own DNS name", help: "Leave empty to test the portal's address." }
        ],
        check: function (v) { return v.servers ? "" : "Enter DNS servers or dhcp."; },
        submit: function (v) {
          act("dns", { connection: uuid, connectionName: c.name, servers: v.servers.replace(/\s/g, ""), setSearch: v.setSearch, search: v.search.replace(/\s/g, ""), test: v.test },
            "Set DNS on " + c.name + " to " + v.servers, "Wrong servers stop the server resolving the domain, package mirrors and agents' names; the change reverts if the test fails.");
        }
      });
      return;
    }
    if (a === "domain-discover") {
      U.formDialog({
        title: "Look up a domain",
        fields: [{ name: "domain", label: "Domain DNS name", placeholder: "corp.example.com" }],
        check: function (v) { return v.domain ? "" : "Enter the domain."; },
        submit: function (v) { lookup(v.domain); }
      });
      return;
    }
    if (a === "domain-join") {
      U.formDialog({
        title: "Join domain",
        intro: "The server's DNS must resolve the domain. A local administrator with a password must exist so the server stays manageable if the domain is unreachable.",
        fields: [
          { name: "domain", label: "Domain DNS name", placeholder: "corp.example.com" },
          { name: "user", label: "Account allowed to join computers", placeholder: "joinadmin" },
          { name: "secret", label: "Password", type: "password", help: "Passed once to realm join on standard input. It is not stored, logged or shown again." },
          { name: "ou", label: "Organizational unit (optional)", placeholder: "OU=Servers,DC=corp,DC=example,DC=com" }
        ],
        check: function (v) { return !v.domain ? "Enter the domain." : !v.user || !v.secret ? "Enter the account and its password." : ""; },
        submit: function (v) {
          act("domain-join", { domain: v.domain, user: v.user, ou: v.ou }, "Join " + host + " to " + v.domain, "Domain users may then sign in to this server according to the realm's login policy.", v.secret);
        }
      });
      return;
    }
    if (a === "domain-leave") {
      act("domain-leave", {}, "Remove " + host + " from the domain", "Domain users can no longer sign in to this server. Local accounts are unaffected.");
    }
  }

  // --- Wiring -----------------------------------------------------------------------------------
  document.addEventListener("click", function (event) {
    const nav = event.target.closest("[data-srv-view]");
    if (nav) { view = nav.getAttribute("data-srv-view"); render(); return; }
    const log = event.target.closest("[data-srv-log]");
    if (log) { openLog(log.getAttribute("data-srv-log")); return; }
    const exp = event.target.closest("[data-srv-export]");
    if (exp && data) {
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
      if (exp.getAttribute("data-srv-export") === "json") {
        download((data.hostname || "server") + "-snapshot-" + stamp + ".json", "application/json", JSON.stringify(data, null, 2));
      } else {
        download((data.hostname || "server") + "-operations-" + stamp + ".csv", "text/csv", [["TimeUtc", "User", "Operation", "Result", "Detail", "SourceAddress"]]
          .concat(list(data.portal.operations).map(function (e) { return [e.timeUtc, e.user, e.action, e.result, e.details, e.remoteIp]; }))
          .map(function (r) { return r.map(csvCell).join(","); }).join("\r\n") + "\r\n");
      }
      return;
    }
    const btn = event.target.closest("[data-srv-act]");
    if (btn && !btn.disabled && data) { onAction(btn); }
  });
  $("srvLogDownload").addEventListener("click", function () { download(logName + ".txt", "text/plain", logText); });
  $("srvRefresh").addEventListener("click", load);
  document.addEventListener("input", function (e) { if (e.target.id === "srvServiceSearch") { filters.services = e.target.value; render(); const i = $("srvServiceSearch"); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } });
  document.addEventListener("change", function (e) { if (e.target.id === "srvServiceState") { filters.serviceState = e.target.value; render(); } });
  setInterval(function () { if (data && priv() && priv().firewall && priv().firewall.revertPending) { $("srvBanners").innerHTML = renderBanners(); } }, 5000);

  load();
})();
