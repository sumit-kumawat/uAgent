(function () {
  "use strict";
  const U = window.uAgent;
  let rows = [];

  function render() {
    const body = document.getElementById("commandsBody");
    const status = document.getElementById("statusFilter").value;
    const type = document.getElementById("typeFilter").value;
    const filtered = rows.filter(function (c) {
      if (status !== "All" && c.status !== status) { return false; }
      if (type !== "All" && c.commandType !== type) { return false; }
      return true;
    });
    document.getElementById("commandCount").textContent = filtered.length + " of " + rows.length + " actions";
    if (filtered.length === 0) {
      body.innerHTML = '<tr><td colspan="9" class="empty">' + (rows.length ? "No actions match the current filters." : "No remote actions have been run yet.") + "</td></tr>";
      return;
    }
    body.innerHTML = filtered.map(function (c) {
      return "<tr>" +
        '<td class="text-nowrap">' + U.escapeHtml(U.formatDateTime(c.createdUtc)) + "</td>" +
        '<td><a class="id-chip" href="/agents/' + encodeURIComponent(c.agentDisplayId) + '">' + U.escapeHtml(c.agentDisplayId) + "</a></td>" +
        "<td>" + U.escapeHtml(U.text(c.machineName)) + "</td>" +
        "<td>" + U.escapeHtml(c.label) + "</td>" +
        "<td>" + (c.samAccountName ? U.escapeHtml(c.samAccountName) : '<span class="subtle">System</span>') + "</td>" +
        "<td>" + U.statusPill(c.status) + "</td>" +
        "<td>" + (c.result ? '<div class="result-text">' + U.escapeHtml(c.result) + "</div>" : '<span class="subtle">\u2014</span>') + "</td>" +
        "<td>" + U.escapeHtml(c.enqueuedBy) + "</td>" +
        '<td class="text-nowrap">' + U.escapeHtml(U.formatDateTime(c.executedUtc)) + "</td>" +
        "</tr>";
    }).join("");
  }

  async function refresh() {
    try {
      const me = await U.loadMe();
      const typeSelect = document.getElementById("typeFilter");
      if (typeSelect.options.length === 1) {
        typeSelect.innerHTML += me.catalog.map(function (c) {
          return '<option value="' + c.type + '">' + U.escapeHtml(c.label) + "</option>";
        }).join("");
      }
      rows = await U.api("/api/commands");
      render();
      document.getElementById("lastUpdated").textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (error) {
      U.notify(error.message || "Could not load actions.", "danger");
    }
  }

  document.getElementById("statusFilter").addEventListener("change", render);
  document.getElementById("typeFilter").addEventListener("change", render);
  refresh();
  setInterval(refresh, 15000);
})();
