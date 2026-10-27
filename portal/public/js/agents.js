(function () {
  "use strict";
  const U = window.uAgent;
  const body = document.getElementById("agentsBody");
  let agents = [];

  function matches(agent, term, filter) {
    if (filter === "Active" && agent.status !== "Active") { return false; }
    if (filter === "Online" && agent.connection !== "online") { return false; }
    if (filter === "Disconnected" && agent.connection !== "disconnected") { return false; }
    if (filter === "Offline" && agent.connection !== "offline") { return false; }
    if (filter === "Pending" && agent.status !== "PendingApproval") { return false; }
    if (filter === "Revoked" && agent.status !== "Revoked") { return false; }
    if (filter === "Domain" && !agent.isDomainJoined) { return false; }
    if (filter === "Workgroup" && agent.isDomainJoined) { return false; }
    if (!term) { return true; }
    return [agent.displayId, agent.machineName, agent.dnsName, agent.domainName, agent.osVersion]
      .some(function (v) { return v && String(v).toLowerCase().indexOf(term) >= 0; });
  }

  function render() {
    const term = document.getElementById("searchBox").value.trim().toLowerCase();
    const filter = document.getElementById("filterSelect").value;
    const shown = agents.filter(function (a) { return matches(a, term, filter); });
    document.getElementById("agentCount").textContent = shown.length + " of " + agents.length + " agents";
    if (agents.length === 0) {
      body.innerHTML = '<tr><td colspan="7" class="empty">No agents have enrolled yet. Install uAgent on a Windows computer and it appears here after it first checks in.</td></tr>';
      return;
    }
    if (shown.length === 0) {
      body.innerHTML = '<tr><td colspan="7" class="empty">No agents match the current filters.</td></tr>';
      return;
    }
    body.innerHTML = U.agentRows(shown);
  }

  async function refresh() {
    try {
      agents = await U.api("/api/agents");
      render();
      document.getElementById("lastUpdated").textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (error) {
      U.notify(error.message || "Could not load agents.", "danger");
    }
  }

  U.bindRowLinks(body);
  const filterSelect = document.getElementById("filterSelect");
  const preset = new URLSearchParams(window.location.search).get("filter") || "";
  if (preset && Array.from(filterSelect.options).some(function (option) { return option.value === preset; })) {
    filterSelect.value = preset;
  }
  document.getElementById("searchBox").addEventListener("input", render);
  filterSelect.addEventListener("change", function () {
    const url = new URL(window.location.href);
    if (filterSelect.value === "All") { url.searchParams.delete("filter"); }
    else { url.searchParams.set("filter", filterSelect.value); }
    window.history.replaceState(null, "", url);
    render();
  });
  U.liveRefresh(refresh, { types: ["agent", "accounts", "removed"], minGapMs: function () { return agents.length > 2000 ? 5000 : 1000; } });
  refresh();
})();
