(function () {
  "use strict";
  const U = window.uAgent;
  const agentKey = document.getElementById("agentRoot").getAttribute("data-agent-key");
  const $ = function (id) { return document.getElementById(id); };

  let state = null;
  let lastAccountsKey = "";
  let failures = 0;
  let loading = false;

  function set(id, html) {
    const el = $(id);
    if (el && el.innerHTML !== html) {
      el.innerHTML = html;
    }
  }

  function setText(id, value) {
    const el = $(id);
    const text = U.text(value);
    if (el && el.textContent !== text) {
      el.textContent = text;
    }
  }

  function when(value) {
    if (!value) {
      return '<span class="subtle">Never</span>';
    }
    return U.escapeHtml(U.relativeTime(value)) + ' <span class="subtle">(' + U.escapeHtml(U.formatDateTime(value)) + ")</span>";
  }

  function renderHeader(agent) {
    setText("hdrMachine", agent.machineName || agentKey);
    set("hdrConnection", U.connectionPill(agent.online));
    setText("hdrDns", agent.dnsName);
    set("hdrHeartbeat", '<i class="bi bi-heart-pulse me-1" aria-hidden="true"></i>' + U.escapeHtml(U.relativeTime(agent.lastSeenUtc)));
    document.title = (agent.machineName || agentKey) + " (" + agentKey + ") \u00B7 uAgent";
  }

  function openPanel(account, source) {
    U.controlPanel.open({
      agentKey: agentKey,
      account: account || "",
      source: source || "",
      onRemoved: function () {
        setTimeout(function () { window.location.href = "/agents"; }, 2500);
      }
    });
  }

  function renderBanners(agent, role) {
    const items = [];
    if (agent.removal) {
      const r = agent.removal;
      const tone = r.state === "Failed" ? "danger" : r.state === "Unverified" ? "warning" : "info";
      const title = { Queued: "Removal pending.", Uninstalling: "Uninstalling.", Failed: "Removal failed.", Unverified: "Removal not verified." }[r.state] || "Removal in progress.";
      items.push('<div class="banner banner-' + tone + '"><i class="bi bi-trash3"></i><div><strong>' + title + "</strong> " + U.escapeHtml(r.detail) +
        ' <button type="button" class="btn btn-link btn-sm p-0 align-baseline" data-open-panel>Open control panel</button></div></div>');
    }
    if (agent.status === "PendingApproval") {
      items.push('<div class="banner banner-warning"><i class="bi bi-hourglass-split"></i><div><strong>Awaiting approval.</strong> This agent does not receive actions until an administrator approves it' +
        (role === "Administrator" ? " from the <strong>Control panel</strong>." : ".") + "</div></div>");
    }
    if (agent.status === "Revoked") {
      items.push('<div class="banner banner-danger"><i class="bi bi-slash-circle"></i><div><strong>Credential revoked.</strong> This agent cannot communicate until it is reinstated or reinstalled.</div></div>');
    }
    if (agent.rotationPending) {
      items.push('<div class="banner banner-info"><i class="bi bi-key"></i><div>Credential rotation is in progress. It completes at the agent\'s next check-in.</div></div>');
    }
    if (!agent.online && agent.status === "Active") {
      items.push('<div class="banner banner-warning"><i class="bi bi-wifi-off"></i><div><strong>Agent offline.</strong> ' +
        U.escapeHtml(agent.machineName || agentKey) +
        (agent.lastSeenUtc ? " last checked in " + U.escapeHtml(U.relativeTime(agent.lastSeenUtc).toLowerCase()) : " has not checked in yet") +
        ". Remote actions are unavailable until it reconnects.</div></div>");
    }
    if (!agent.capabilitiesReported) {
      items.push('<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>This agent version supports account actions only. Update the agent to enable system controls.</div></div>');
    }
    if (role === "Monitor") {
      items.push('<div class="banner banner-info"><i class="bi bi-eye"></i><div>You have read-only access. Remote actions require the Operator or Administrator role.</div></div>');
    }
    if (failures > 0) {
      items.push('<div class="banner banner-danger"><i class="bi bi-exclamation-octagon"></i><div>Could not refresh this page. Retrying automatically\u2026</div></div>');
    }
    set("banners", items.join(""));
  }

  function renderOverview(agent) {
    const counts = agent.accountCounts;
    set("stConnection", agent.online ? '<span class="text-online">Online</span>' : '<span class="text-muted">Offline</span>');
    setText("stAccounts", String(counts.total));
    setText("stCritical", String(counts.critical));
    setText("stPending", String(state.commands.filter(function (c) { return c.status === "Pending" || c.status === "Delivered"; }).length));
    setText("stVersion", agent.agentVersion || "Unknown");

    setText("ovHostname", agent.machineName);
    setText("ovEnrollment", agent.agentId);
    setText("ovOs", agent.osVersion);
    set("ovDomain", agent.isDomainJoined && agent.domainName ? U.escapeHtml(agent.domainName) : '<span class="subtle">Workgroup (not domain joined)</span>');
    setText("ovDns", agent.dnsName);
    setText("ovIps", (agent.ipAddresses || []).join(", "));
    setText("ovUptime", U.formatUptime(agent.uptime));
    set("ovSystemStatus", agent.online
      ? (counts.critical > 0 ? U.pill("warning", counts.critical === 1 ? "1 account needs attention" : counts.critical + " accounts need attention", true) : U.pill("success", "Healthy", true))
      : U.pill("neutral", "Unknown while offline", true));

    set("ovConnection", U.connectionPill(agent.online));
    set("ovHeartbeat", when(agent.lastHeartbeatUtc));
    set("ovContact", when(agent.lastSeenUtc));
    setText("ovVersion", agent.agentVersion || "Unknown");
    let service;
    if (agent.serviceMode === "WindowsService") {
      service = agent.online ? U.pill("success", "Running as a Windows service", true) : U.pill("danger", "Not responding", true);
    } else if (agent.serviceMode === "Console") {
      service = agent.online ? U.pill("warning", "Running outside the Windows service", true) : U.pill("neutral", "Stopped", true);
    } else {
      service = U.pill("neutral", "Not reported", true);
    }
    set("ovService", service);
    setText("ovPolling", agent.pollIntervalSeconds
      ? "Inventory every " + agent.pollIntervalSeconds + "s, actions every " + (agent.commandPollSeconds || agent.pollIntervalSeconds) + "s"
      : "Not reported");
    setText("ovRemoteIp", agent.remoteIp);
    set("ovFirstSeen", when(agent.firstSeenUtc));
    set("ovInventory", when(agent.inventoryUtc));
  }

  function renderAccounts(agent) {
    const counts = agent.accountCounts;
    setText("cntAccounts", String(counts.total));
    setText("acTotal", String(counts.total));
    setText("acEnabled", String(counts.enabled));
    setText("acDisabled", String(counts.disabled));
    setText("acLocked", String(counts.locked));
    setText("acCritical", String(counts.critical));

    const key = JSON.stringify([state.accounts, agent.online, agent.removal]);
    if (key === lastAccountsKey) {
      return;
    }
    lastAccountsKey = key;

    const body = $("accountsBody");
    if (state.accounts.length === 0) {
      body.innerHTML = '<tr><td colspan="10" class="empty">' +
        (agent.inventoryUtc ? "The agent reported no monitored accounts." : "No account inventory has been received from this agent yet.") + "</td></tr>";
      return;
    }
    body.innerHTML = state.accounts.map(function (a) {
      return "<tr>" +
        '<td><span class="cell-primary">' + U.escapeHtml(a.samAccountName) + "</span></td>" +
        "<td>" + U.escapeHtml(U.text(a.displayName)) + "</td>" +
        "<td>" + U.escapeHtml(a.source || "Local") + "</td>" +
        "<td>" + U.booleanPill(a.enabled, "Enabled", "Disabled", "success", "danger") + "</td>" +
        "<td>" + U.booleanPill(a.lockedOut, "Locked", "No", "danger", "neutral") + "</td>" +
        "<td>" + U.passwordStatePill(a.passwordState) + (a.accountExpired ? " " + U.pill("danger", "Account expired") : "") + "</td>" +
        "<td>" + U.escapeHtml(U.formatDateTime(a.lastPasswordSet)) + "</td>" +
        "<td>" + U.escapeHtml(U.formatDateTime(a.lastLogon)) + "</td>" +
        '<td class="num">' + (Number(a.badLogonCount) || 0) + "</td>" +
        '<td><button class="btn btn-sm btn-outline-secondary" type="button" data-panel-account="' + U.escapeHtml(a.samAccountName) + '" data-source="' + U.escapeHtml(a.source || "") +
        '" aria-label="Manage ' + U.escapeHtml(a.samAccountName) + '" aria-controls="ua-control-panel"><i class="bi bi-sliders me-1" aria-hidden="true"></i>Manage</button></td>' +
        "</tr>";
    }).join("");
  }

  function statusHint(c) {
    if (c.status === "Pending") { return '<span class="subtle">Waiting for the agent to collect it</span>'; }
    if (c.status === "Delivered") { return '<span class="subtle">Running on the host</span>'; }
    if (c.status === "TimedOut") { return '<span class="subtle">No result reported within 10 minutes</span>'; }
    return '<span class="subtle">\u2014</span>';
  }

  function renderHistory() {
    setText("cntHistory", String(state.commands.length));
    set("historyBody", state.commands.length === 0
      ? '<tr><td colspan="7" class="empty">No actions have been run on this agent.</td></tr>'
      : state.commands.map(function (c) {
        return "<tr>" +
          '<td class="text-nowrap">' + U.escapeHtml(U.formatDateTime(c.createdUtc)) + "</td>" +
          "<td>" + U.escapeHtml(c.label) + "</td>" +
          "<td>" + (c.samAccountName ? U.escapeHtml(c.samAccountName) : '<span class="subtle">System</span>') + "</td>" +
          "<td>" + U.statusPill(c.status) + "</td>" +
          "<td>" + (c.result ? '<div class="result-text">' + U.escapeHtml(c.result) + "</div>" : statusHint(c)) + "</td>" +
          "<td>" + U.escapeHtml(c.enqueuedBy) + (c.reason ? '<div class="subtle">' + U.escapeHtml(c.reason) + "</div>" : "") + "</td>" +
          '<td class="text-nowrap">' + U.escapeHtml(U.formatDateTime(c.executedUtc)) + "</td>" +
          "</tr>";
      }).join(""));

    set("auditBody", state.audit.length === 0
      ? '<tr><td colspan="6" class="empty">No audit entries for this agent.</td></tr>'
      : state.audit.map(function (e) {
        return "<tr>" +
          '<td class="text-nowrap">' + U.escapeHtml(U.formatDateTime(e.timestampUtc)) + "</td>" +
          "<td>" + U.escapeHtml(e.user) + "</td>" +
          "<td>" + U.escapeHtml(e.action) + "</td>" +
          "<td>" + (e.samAccountName ? U.escapeHtml(e.samAccountName) : '<span class="subtle">System</span>') + "</td>" +
          "<td>" + U.statusPill(e.result) + "</td>" +
          "<td>" + U.escapeHtml(e.details) + "</td>" +
          "</tr>";
      }).join(""));
  }

  function renderCommunication(agent) {
    set("commBody", agent.communication.length === 0
      ? '<tr><td colspan="4" class="empty">No communication recorded.</td></tr>'
      : agent.communication.map(function (c) {
        return "<tr>" +
          '<td class="text-nowrap">' + U.escapeHtml(U.formatDateTime(c.timestampUtc)) + "</td>" +
          "<td>" + U.escapeHtml(c.kind) + "</td>" +
          "<td>" + U.escapeHtml(c.detail) + "</td>" +
          '<td class="mono">' + U.escapeHtml(U.text(c.remoteIp)) + "</td>" +
          "</tr>";
      }).join(""));
  }

  async function load() {
    if (loading) {
      return;
    }
    loading = true;
    const indicator = $("liveIndicator");
    try {
      const me = await U.loadMe();
      state = await U.api("/api/agents/" + encodeURIComponent(agentKey));
      failures = 0;
      const agent = state.agent;
      renderHeader(agent);
      renderBanners(agent, me.role);
      renderOverview(agent);
      renderAccounts(agent);
      renderHistory();
      renderCommunication(agent);
      indicator.classList.remove("paused");
      $("liveText").textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (error) {
      if (error.status === 404) {
        set("banners", '<div class="banner banner-danger"><i class="bi bi-x-octagon"></i><div>' + U.escapeHtml(error.message) + ' <a href="/agents">Back to agents</a></div></div>');
        indicator.classList.add("paused");
        $("liveText").textContent = "Not available";
        loading = false;
        return;
      }
      failures += 1;
      indicator.classList.add("paused");
      $("liveText").textContent = "Reconnecting\u2026";
      if (state) {
        renderBanners(state.agent, (U.me && U.me.role) || "");
      } else {
        set("banners", '<div class="banner banner-danger"><i class="bi bi-exclamation-octagon"></i><div>' + U.escapeHtml(error.message || "Could not load this agent.") + "</div></div>");
      }
    }
    loading = false;
  }

  document.addEventListener("click", function (event) {
    const accountBtn = event.target.closest("[data-panel-account]");
    if (accountBtn) {
      openPanel(accountBtn.getAttribute("data-panel-account"), accountBtn.getAttribute("data-source"));
      return;
    }
    if (event.target.closest("[data-open-panel]")) {
      openPanel();
    }
  });

  $("openPanel").addEventListener("click", function () { openPanel(); });
  $("refreshBtn").addEventListener("click", function () { load(); });
  const liveTypes = new Set(["agent", "command", "accounts", "removed"]);
  U.liveRefresh(load, {
    types: ["agent", "command", "accounts", "removed"],
    match: function (e) { return liveTypes.has(e.type) && (!state || e.agentId === state.agent.agentId); }
  });

  load();
})();
