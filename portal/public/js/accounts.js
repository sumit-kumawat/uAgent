(function () {
  "use strict";
  const U = window.uAgent;
  const body = document.getElementById("accountsBody");
  let rows = [];
  let onlineByAgent = {};
  let accountControls = [];

  function isExpired(account) {
    return account.accountExpirationDate && new Date(account.accountExpirationDate) < new Date();
  }

  function passwordState(account) {
    if (account.passwordNeverExpires) { return "never"; }
    if (!account.passwordExpiresUtc) { return "unreported"; }
    const when = new Date(account.passwordExpiresUtc).getTime();
    if (Number.isNaN(when)) { return "unreported"; }
    if (when <= Date.now()) { return "expired"; }
    if (when - Date.now() <= 14 * 24 * 60 * 60 * 1000) { return "warning"; }
    return "ok";
  }

  function needsAttention(account) {
    return account.lockedOut || !account.enabled || isExpired(account);
  }

  function actionsMenu(row) {
    const online = onlineByAgent[row.agentId];
    const items = accountControls.map(function (c) {
      let reason = "";
      if (!c.allowed) {
        reason = "Requires the " + c.minRole + " role.";
      } else if (!online) {
        reason = "The agent is offline.";
      }
      const disabled = Boolean(reason);
      return '<li><button type="button" class="dropdown-item' + (disabled ? " disabled" : "") + (c.sensitive && !disabled ? " text-danger" : "") +
        '" data-control="' + c.type + '" data-agent="' + U.escapeHtml(row.agentDisplayId) + '" data-machine="' + U.escapeHtml(row.machineName) +
        '" data-account="' + U.escapeHtml(row.account.samAccountName) + '" title="' + U.escapeHtml(reason || c.description) + '">' + U.escapeHtml(c.label) + "</button></li>";
    }).join("");
    return '<div class="dropdown"><button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">Manage</button>' +
      '<ul class="dropdown-menu dropdown-menu-end">' + items + "</ul></div>";
  }

  function populateAgentFilter() {
    const select = document.getElementById("agentFilter");
    const current = select.value;
    const seen = {};
    const options = ['<option value="">All agents</option>'];
    rows.forEach(function (row) {
      if (!seen[row.agentId]) {
        seen[row.agentId] = true;
        options.push('<option value="' + U.escapeHtml(row.agentId) + '">' + U.escapeHtml(row.agentDisplayId + " \u00B7 " + (row.machineName || "")) + "</option>");
      }
    });
    select.innerHTML = options.join("");
    select.value = current;
  }

  function render() {
    const agent = document.getElementById("agentFilter").value;
    const name = document.getElementById("nameFilter").value.trim().toLowerCase();
    const stateFilter = document.getElementById("stateFilter").value;
    const filtered = rows.filter(function (row) {
      const a = row.account;
      if (agent && row.agentId !== agent) { return false; }
      if (name && a.samAccountName.toLowerCase().indexOf(name) < 0) { return false; }
      if (stateFilter === "Attention" && !needsAttention(a)) { return false; }
      if (stateFilter === "Enabled" && !a.enabled) { return false; }
      if (stateFilter === "Disabled" && a.enabled) { return false; }
      if (stateFilter === "Locked" && !a.lockedOut) { return false; }
      if (stateFilter === "Expired" && !isExpired(a)) { return false; }
      if (stateFilter === "PasswordExpired" && passwordState(a) !== "expired") { return false; }
      if (stateFilter === "PasswordWarning" && passwordState(a) !== "warning") { return false; }
      if (stateFilter === "PasswordUnset" && a.lastPasswordSet) { return false; }
      return true;
    });
    document.getElementById("accountCount").textContent = filtered.length + " of " + rows.length + " accounts";
    if (filtered.length === 0) {
      const passwordFilter = stateFilter === "PasswordExpired" || stateFilter === "PasswordWarning";
      const note = !rows.length
        ? "No account inventory has been reported yet."
        : passwordFilter
          ? "No accounts match. Password expiry is shown only when an agent reports it."
          : "No accounts match the current filters.";
      body.innerHTML = '<tr><td colspan="8" class="empty">' + note + "</td></tr>";
      return;
    }
    body.innerHTML = filtered.map(function (row) {
      const a = row.account;
      return "<tr>" +
        '<td><a class="id-chip" href="/agents/' + encodeURIComponent(row.agentDisplayId) + '">' + U.escapeHtml(row.agentDisplayId) + "</a></td>" +
        "<td>" + U.escapeHtml(U.text(row.machineName)) + "</td>" +
        '<td><span class="cell-primary">' + U.escapeHtml(a.samAccountName) + "</span></td>" +
        "<td>" + U.booleanPill(a.enabled, "Enabled", "Disabled", "success", "danger") + "</td>" +
        "<td>" + U.booleanPill(a.lockedOut, "Locked", "No", "danger", "neutral") + "</td>" +
        "<td>" + U.booleanPill(isExpired(a), "Expired", "No", "danger", "neutral") + "</td>" +
        "<td>" + U.escapeHtml(U.formatDateTime(a.lastPasswordSet)) + "</td>" +
        "<td>" + actionsMenu(row) + "</td>" +
        "</tr>";
    }).join("");
  }

  async function refresh() {
    try {
      const me = await U.loadMe();
      accountControls = me.catalog.filter(function (c) { return c.category === "account"; });
      const results = await Promise.all([U.api("/api/accounts"), U.api("/api/agents")]);
      rows = results[0];
      onlineByAgent = {};
      results[1].forEach(function (a) { onlineByAgent[a.agentId] = a.online; });
      populateAgentFilter();
      const params = new URLSearchParams(window.location.search);
      const state = params.get("state") || "";
      const agentPreset = params.get("agent") || "";
      const stateSelect = document.getElementById("stateFilter");
      const agentSelect = document.getElementById("agentFilter");
      if (state && Array.from(stateSelect.options).some(function (option) { return option.value === state; })) {
        stateSelect.value = state;
      }
      if (agentPreset && Array.from(agentSelect.options).some(function (option) { return option.value === agentPreset; })) {
        agentSelect.value = agentPreset;
      }
      render();
      document.getElementById("lastUpdated").textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (error) {
      U.notify(error.message || "Could not load accounts.", "danger");
    }
  }

  body.addEventListener("click", function (event) {
    const button = event.target.closest("[data-control]");
    if (!button || button.classList.contains("disabled")) {
      return;
    }
    const control = accountControls.find(function (c) { return c.type === button.getAttribute("data-control"); });
    U.runAction({
      agentKey: button.getAttribute("data-agent"),
      machineName: button.getAttribute("data-machine"),
      control: control,
      samAccountName: button.getAttribute("data-account"),
      onUpdate: function (cmd) { if (U.isTerminal(cmd.status)) { refresh(); } }
    });
  });
  function rememberFilters() {
    const url = new URL(window.location.href);
    const state = document.getElementById("stateFilter").value;
    const agent = document.getElementById("agentFilter").value;
    if (!state || state === "All") { url.searchParams.delete("state"); } else { url.searchParams.set("state", state); }
    if (!agent) { url.searchParams.delete("agent"); } else { url.searchParams.set("agent", agent); }
    window.history.replaceState(null, "", url);
    render();
  }
  document.getElementById("agentFilter").addEventListener("change", rememberFilters);
  document.getElementById("nameFilter").addEventListener("input", render);
  document.getElementById("stateFilter").addEventListener("change", rememberFilters);
  refresh();
  setInterval(refresh, 30000);
})();
