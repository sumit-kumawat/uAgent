(function () {
  "use strict";
  const U = window.uAgent;
  const agentKey = document.getElementById("agentRoot").getAttribute("data-agent-key");
  const $ = function (id) { return document.getElementById(id); };

  const controlIcons = {
    Ping: "bi-broadcast",
    RefreshInventory: "bi-arrow-repeat",
    CollectDiagnostics: "bi-clipboard2-pulse",
    RestartAgent: "bi-bootstrap-reboot",
    RestartComputer: "bi-power",
    CancelRestart: "bi-x-octagon",
    UpdateAgent: "bi-arrow-up-circle",
    StopAgent: "bi-stop-circle",
    RepairAgent: "bi-tools",
    UninstallAgent: "bi-trash3"
  };

  let state = null;
  let timer = null;
  let lastAccountsKey = "";
  let failures = 0;

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

  function controlsByCategory(category) {
    return state.controls.filter(function (c) { return c.category === category; });
  }

  function stateReasonPill(control) {
    if (control.state === "forbidden") { return U.pill("neutral", "Requires " + control.minRole); }
    if (control.state === "unsupported") { return U.pill("neutral", "Not supported"); }
    if (control.state === "offline") { return U.pill("warning", "Agent offline"); }
    return control.sensitive ? U.pill("danger", "Sensitive") : U.pill("info", control.minRole + "+");
  }

  function run(control, samAccountName, accountSource) {
    if (control.state !== "available") {
      U.notify(control.reason, "warning");
      return;
    }
    U.runAction({
      agentKey: agentKey,
      machineName: state.agent.machineName || agentKey,
      control: control,
      samAccountName: samAccountName,
      accountSource: accountSource || null,
      onQueued: function () { load(); },
      onUpdate: function (cmd) { if (U.isTerminal(cmd.status)) { load(); } }
    });
  }

  function renderHeader(agent) {
    setText("hdrMachine", agent.machineName || agentKey);
    set("hdrConnection", U.connectionPill(agent.online));
    setText("hdrDns", agent.dnsName);
    set("hdrHeartbeat", '<i class="bi bi-heart-pulse me-1"></i>' + U.escapeHtml(U.relativeTime(agent.lastSeenUtc)));
    document.title = (agent.machineName || agentKey) + " (" + agentKey + ") \u00B7 uAgent";

    const quick = controlsByCategory("system");
    set("quickActions", '<li><h6 class="dropdown-header">System</h6></li>' + quick.map(function (c) {
      const disabled = c.state !== "available";
      return '<li><button type="button" class="dropdown-item' + (disabled ? " disabled" : "") + (c.sensitive && !disabled ? " text-danger" : "") +
        '" data-control="' + c.type + '" title="' + U.escapeHtml(disabled ? c.reason : c.description) + '">' +
        '<i class="bi ' + (controlIcons[c.type] || "bi-lightning") + ' me-2"></i>' + U.escapeHtml(c.label) + "</button></li>";
    }).join(""));
  }

  function renderManage(agent, role) {
    const wrap = $("manageWrap");
    if (role !== "Administrator") {
      wrap.hidden = true;
      return;
    }
    wrap.hidden = false;
    const items = [];
    if (agent.status === "PendingApproval") {
      items.push(manageItem("approve", "bi-check2-circle", "Approve agent", false));
    }
    if (agent.status === "Revoked") {
      items.push(manageItem("approve", "bi-check2-circle", "Reinstate agent", false));
    } else {
      items.push(manageItem("revoke", "bi-slash-circle", "Revoke credential", true));
    }
    items.push(manageItem("rotate-key", "bi-key", "Rotate credential", false));
    items.push('<li><hr class="dropdown-divider"></li>');
    items.push(manageItem("remove", "bi-trash", "Remove agent", true));
    set("manageMenu", items.join(""));
  }

  function manageItem(action, icon, label, danger) {
    return '<li><button type="button" class="dropdown-item' + (danger ? " text-danger" : "") +
      '" data-manage="' + action + '"><i class="bi ' + icon + ' me-2"></i>' + label + "</button></li>";
  }

  async function manage(action) {
    const confirmText = {
      revoke: "Revoke this agent's credential? It will stop receiving actions until reinstated or reinstalled.",
      remove: "Remove this agent from the portal? It will re-register on its next heartbeat unless uninstalled.",
      "rotate-key": "Rotate this agent's credential? The new key is delivered on its next heartbeat."
    }[action];
    if (confirmText && !window.confirm(confirmText)) {
      return;
    }
    try {
      if (action === "remove") {
        await U.api("/api/agents/" + encodeURIComponent(agentKey), { method: "DELETE" });
        U.notify("Agent removed.", "success");
        window.location.href = "/agents";
        return;
      }
      await U.api("/api/agents/" + encodeURIComponent(agentKey) + "/" + action, { method: "POST" });
      U.notify({ approve: "Agent approved.", revoke: "Agent revoked.", "rotate-key": "Credential rotation queued." }[action], "success");
      load();
    } catch (error) {
      U.notify(error.message || "The action failed.", "danger");
    }
  }

  function renderBanners(agent, role) {
    const items = [];
    if (agent.status === "PendingApproval") {
      items.push('<div class="banner banner-warning"><i class="bi bi-hourglass-split"></i><div><strong>Awaiting approval.</strong> This agent is registered but will not receive actions until an administrator approves it' +
        (role === "Administrator" ? ' (use <strong>Manage agent → Approve</strong>).' : ".") + "</div></div>");
    }
    if (agent.status === "Revoked") {
      items.push('<div class="banner banner-danger"><i class="bi bi-slash-circle"></i><div><strong>Credential revoked.</strong> This agent cannot communicate until it is reinstated or reinstalled.</div></div>');
    }
    if (agent.rotationPending) {
      items.push('<div class="banner banner-info"><i class="bi bi-key"></i><div>A credential rotation is in progress; it completes when the agent next checks in with the new key.</div></div>');
    }
    if (!agent.online && agent.status === "Active") {
      items.push('<div class="banner banner-warning"><i class="bi bi-wifi-off"></i><div><strong>Agent offline.</strong> ' +
        U.escapeHtml(agent.machineName || agentKey) + " last communicated " + U.escapeHtml(U.relativeTime(agent.lastSeenUtc)) +
        ". Remote actions are unavailable until the uAgent service reconnects.</div></div>");
    }
    if (!agent.capabilitiesReported) {
      items.push('<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>This agent does not report its capabilities (agent version earlier than 1.1). Only account actions are offered; upgrade the agent to enable system controls.</div></div>');
    }
    if (role === "Monitor") {
      items.push('<div class="banner banner-info"><i class="bi bi-eye"></i><div>You have read-only access. Remote actions require the Operator or Administrator role.</div></div>');
    }
    if (failures > 0) {
      items.push('<div class="banner banner-danger"><i class="bi bi-exclamation-octagon"></i><div>Live updates are failing. Retrying automatically\u2026</div></div>');
    }
    set("banners", items.join(""));
  }

  function renderOverview(agent) {
    const counts = agent.accountCounts;
    set("stConnection", agent.online ? '<span style="color:var(--ua-good)">Online</span>' : '<span class="text-muted">Offline</span>');
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
      ? (counts.critical > 0 ? U.pill("warning", counts.critical + " account(s) need attention", true) : U.pill("success", "Healthy", true))
      : U.pill("neutral", "Unknown (agent offline)", true));

    set("ovConnection", U.connectionPill(agent.online) + ' <span class="subtle ms-1">online window ' + agent.onlineWindowSeconds + "s</span>");
    set("ovHeartbeat", when(agent.lastHeartbeatUtc));
    set("ovContact", when(agent.lastSeenUtc));
    setText("ovVersion", agent.agentVersion || "Unknown");
    let service;
    if (agent.serviceMode === "WindowsService") {
      service = agent.online ? U.pill("success", "Running \u2014 Windows service (uAgent)", true) : U.pill("danger", "Not responding \u2014 Windows service", true);
    } else if (agent.serviceMode === "Console") {
      service = agent.online ? U.pill("warning", "Running in console (not installed as a service)", true) : U.pill("neutral", "Stopped (console)", true);
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

    const accountControls = controlsByCategory("account");
    const key = JSON.stringify([state.accounts, accountControls.map(function (c) { return c.state; })]);
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
    const anyAvailable = accountControls.some(function (c) { return c.state === "available"; });
    body.innerHTML = state.accounts.map(function (a) {
      const expired = a.accountExpirationDate && new Date(a.accountExpirationDate) < new Date();
      const items = accountControls.map(function (c) {
        const disabled = c.state !== "available";
        return '<li><button type="button" class="dropdown-item' + (disabled ? " disabled" : "") + (c.sensitive && !disabled ? " text-danger" : "") +
          '" data-control="' + c.type + '" data-account="' + U.escapeHtml(a.samAccountName) + '" data-source="' + U.escapeHtml(a.source || "") + '" title="' + U.escapeHtml(disabled ? c.reason : c.description) + '">' +
          U.escapeHtml(c.label) + "</button></li>";
      }).join("");
      return "<tr>" +
        '<td><span class="cell-primary">' + U.escapeHtml(a.samAccountName) + "</span></td>" +
        "<td>" + U.escapeHtml(U.text(a.displayName)) + "</td>" +
        "<td>" + U.escapeHtml(a.source) + "</td>" +
        "<td>" + U.booleanPill(a.enabled, "Enabled", "Disabled", "success", "danger") + "</td>" +
        "<td>" + U.booleanPill(a.lockedOut, "Locked", "No", "danger", "neutral") + "</td>" +
        "<td>" + U.booleanPill(expired, "Expired", "No", "danger", "neutral") + "</td>" +
        "<td>" + U.escapeHtml(U.formatDateTime(a.lastPasswordSet)) + "</td>" +
        "<td>" + U.escapeHtml(U.formatDateTime(a.lastLogon)) + "</td>" +
        '<td class="num">' + a.badLogonCount + "</td>" +
        '<td><div class="dropdown">' +
        '<button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown"' +
        (anyAvailable ? "" : ' title="No account actions are available"') + ">Manage</button>" +
        '<ul class="dropdown-menu dropdown-menu-end">' + items + "</ul></div></td>" +
        "</tr>";
    }).join("");
  }

  function controlCards(category) {
    return controlsByCategory(category).map(function (c) {
      const disabled = c.state !== "available";
      return '<div class="control-card' + (disabled ? " is-disabled" : "") + '">' +
        '<div class="head"><span class="title"><i class="bi ' + (controlIcons[c.type] || "bi-lightning") + '"></i>' + U.escapeHtml(c.label) + "</span>" + stateReasonPill(c) + "</div>" +
        '<div class="desc">' + U.escapeHtml(c.description) + "</div>" +
        '<div class="foot"><span class="reason">' + U.escapeHtml(disabled ? c.reason : "") + "</span>" +
        '<button type="button" class="btn btn-sm ' + (c.sensitive ? "btn-outline-danger" : "btn-outline-secondary") + '" data-control="' + c.type + '"' +
        (disabled ? ' disabled aria-disabled="true"' : "") + ">Run</button></div></div>";
    }).join("");
  }

  function renderControls() {
    set("controlsGrid", controlCards("system"));
    set("lifecycleGrid", controlCards("lifecycle"));

    const system = state.commands.filter(function (c) { return c.category === "system" || c.category === "lifecycle"; }).slice(0, 15);
    set("controlResults", system.length === 0
      ? '<tr><td colspan="5" class="empty">No remote actions yet.</td></tr>'
      : system.map(function (c) {
        return "<tr>" +
          '<td class="text-nowrap">' + U.escapeHtml(U.formatDateTime(c.createdUtc)) + "</td>" +
          "<td>" + U.escapeHtml(c.label) + "</td>" +
          "<td>" + U.statusPill(c.status) + "</td>" +
          "<td>" + (c.result ? '<div class="result-text">' + U.escapeHtml(c.result) + "</div>" : statusHint(c)) + "</td>" +
          "<td>" + U.escapeHtml(c.enqueuedBy) + "</td>" +
          "</tr>";
      }).join(""));
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

  function schedule() {
    clearTimeout(timer);
    if (document.hidden) {
      return;
    }
    const active = state && state.commands.some(function (c) { return c.status === "Pending" || c.status === "Delivered"; });
    timer = setTimeout(load, active ? 5000 : 10000);
  }

  async function load() {
    const indicator = $("liveIndicator");
    try {
      const me = await U.loadMe();
      state = await U.api("/api/agents/" + encodeURIComponent(agentKey));
      failures = 0;
      const agent = state.agent;
      renderHeader(agent);
      renderManage(agent, me.role);
      renderBanners(agent, me.role);
      renderOverview(agent);
      renderAccounts(agent);
      renderControls();
      renderHistory();
      renderCommunication(agent);
      indicator.classList.remove("paused");
      $("liveText").textContent = "Live \u00B7 updated " + new Date().toLocaleTimeString();
    } catch (error) {
      if (error.status === 404) {
        set("banners", '<div class="banner banner-danger"><i class="bi bi-x-octagon"></i><div>' + U.escapeHtml(error.message) + ' <a href="/agents">Back to agents</a></div></div>');
        indicator.classList.add("paused");
        $("liveText").textContent = "Stopped";
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
    schedule();
  }

  document.addEventListener("click", function (event) {
    const manageBtn = event.target.closest("[data-manage]");
    if (manageBtn) {
      manage(manageBtn.getAttribute("data-manage"));
      return;
    }
    const button = event.target.closest("[data-control]");
    if (!button || !state || button.classList.contains("disabled") || button.disabled) {
      return;
    }
    const control = state.controls.find(function (c) { return c.type === button.getAttribute("data-control"); });
    if (control) {
      run(control, button.getAttribute("data-account") || "", button.getAttribute("data-source") || "");
    }
  });

  $("refreshBtn").addEventListener("click", function () { load(); });
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) {
      load();
    } else {
      clearTimeout(timer);
    }
  });

  load();
})();
