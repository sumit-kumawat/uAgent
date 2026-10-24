(function () {
  "use strict";
  const U = window.uAgent;

  function connectionCell(agent) {
    if (agent.connection === "pending") {
      return '<span class="pill pill-warning"><span class="dot"></span>Awaiting approval</span>';
    }
    if (agent.connection === "inactive") {
      return '<span class="pill pill-danger"><span class="dot"></span>Inactive</span>';
    }
    if (agent.connection === "online") {
      return '<span class="pill pill-success"><span class="dot"></span>Online</span>';
    }
    if (agent.connection === "disconnected") {
      return '<span class="pill pill-warning"><span class="dot"></span>Disconnected</span>';
    }
    return '<span class="pill pill-neutral"><span class="dot"></span>Offline</span>';
  }

  function rows(agents) {
    return agents.map(function (agent) {
      const address = agent.ipAddresses && agent.ipAddresses.length ? agent.ipAddresses[0] : "";
      const locked = agent.lockedCount || 0;
      const lockedCell = locked
        ? '<a href="/accounts?state=Locked&agent=' + encodeURIComponent(agent.agentId) + '">' + locked + "</a>"
        : "0";
      return '<tr class="row-link" tabindex="0" data-href="/agents/' + encodeURIComponent(agent.displayId) + '">' +
        '<td><span class="id-chip">' + U.escapeHtml(agent.displayId) + "</span></td>" +
        '<td><span class="cell-primary">' + U.escapeHtml(U.text(agent.machineName)) + "</span></td>" +
        '<td class="mono">' + U.escapeHtml(U.text(address)) + "</td>" +
        '<td class="mono">' + U.escapeHtml(U.text(agent.dnsName)) + "</td>" +
        "<td>" + U.escapeHtml(U.text(agent.osVersion)) + "</td>" +
        '<td class="num">' + agent.accountCount + "</td>" +
        '<td class="num">' + lockedCell + "</td>" +
        "<td>" + connectionCell(agent) + "</td>" +
        "</tr>";
    }).join("");
  }

  function countOrDash(value, reported) {
    return reported ? String(value || 0) : "\u2014";
  }

  function renderStats(summary) {
    const accounts = summary.accounts || {};
    document.getElementById("statTotal").textContent = summary.totalAgents || 0;
    document.getElementById("statActive").textContent = summary.activeAgents || 0;
    document.getElementById("statOnline").textContent = summary.onlineAgents || 0;
    document.getElementById("statOffline").textContent = summary.offlineAgents || 0;
    document.getElementById("statDisconnected").textContent = summary.disconnectedAgents || 0;
    document.getElementById("statAccounts").textContent = accounts.total || 0;
    document.getElementById("hintAccounts").textContent = (accounts.enabled || 0) + " enabled · " + (accounts.disabled || 0) + " disabled";
    document.getElementById("statLocked").textContent = accounts.locked || 0;
    document.getElementById("statAcctExpired").textContent = accounts.expired || 0;
    const reported = (accounts.passwordReported || 0) > 0;
    document.getElementById("statPassExpired").textContent = countOrDash(accounts.passwordExpired, reported);
    document.getElementById("statPassSoon").textContent = countOrDash(accounts.passwordWarning, reported);
    document.getElementById("hintPassExpired").textContent = !reported
      ? "Not reported by agents yet"
      : accounts.passwordUnreported
        ? accounts.passwordUnreported + " accounts have no expiry time"
        : "Reported by agents";
  }

  async function refresh() {
    try {
      const data = await U.api("/api/dashboard/summary");
      renderStats(data.summary);
      const body = document.getElementById("agentsBody");
      body.innerHTML = data.agents.length
        ? rows(data.agents)
        : '<tr><td colspan="8" class="empty">No agents have registered yet.</td></tr>';
      document.getElementById("lastUpdated").textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (error) {
      U.notify(error.message || "Could not load the dashboard.", "danger");
    }
  }

  U.bindRowLinks(document.getElementById("agentsBody"));
  refresh();
  setInterval(refresh, 15000);
})();
