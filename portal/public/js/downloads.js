(function () {
  "use strict";
  const U = window.uAgent;

  function statusCell(agent) {
    if (agent.status === "PendingApproval") { return U.pill("warning", "Pending", true); }
    if (agent.status === "Revoked") { return U.pill("danger", "Inactive", true); }
    if (agent.connection === "online") { return U.pill("success", "Activated", true); }
    if (agent.connection === "disconnected") { return U.pill("warning", "Disconnected", true); }
    return U.pill("neutral", "Activated", true);
  }

  function sizeLabel(bytes) {
    if (!bytes) { return "\u2014"; }
    return (bytes / 1048576).toFixed(1) + " MB";
  }

  function render(data) {
    const report = data.report;
    const info = data.installer;
    document.getElementById("dlCount").textContent = report.downloads;
    document.getElementById("dlInstalled").textContent = report.installed;
    document.getElementById("dlActivated").textContent = report.activated;
    document.getElementById("dlPending").textContent = report.pending;
    document.getElementById("dlInactive").textContent = report.inactive;

    const fileName = info.fileName || "uAgent.exe";
    document.getElementById("dlFileName").textContent = info.available ? fileName : "Installer not published";
    document.getElementById("dlFileMeta").textContent = info.available
      ? "Version " + info.version + " · " + sizeLabel(info.size) + (info.signed ? " · signed" : " · unsigned")
      : "Build it with scripts/build-agent.sh before downloading.";
    const canonicalUrl = data.downloadUrl || (location.origin + data.downloadPath);
    document.getElementById("dlLink").value = canonicalUrl;
    const btn = document.getElementById("dlBtn");
    if (info.available) {
      btn.href = canonicalUrl;
      btn.classList.remove("disabled");
      btn.removeAttribute("aria-disabled");
      btn.setAttribute("download", fileName);
      btn.innerHTML = '<i class="bi bi-download me-1"></i>' + U.escapeHtml(fileName);
    } else {
      btn.classList.add("disabled");
      btn.setAttribute("aria-disabled", "true");
      btn.removeAttribute("download");
    }

    document.getElementById("verInstaller").textContent = info.available ? info.version : "Not published";
    document.getElementById("verPackage").textContent = info.available ? fileName + " · " + sizeLabel(info.size) : "\u2014";
    document.getElementById("verSigned").textContent = info.available ? (info.signed ? "Authenticode signed, served unmodified" : "Unsigned lab build, personalised for this portal") : "\u2014";
    document.getElementById("verSha").textContent = info.available && info.sha256 ? info.sha256 + (info.signed ? "" : " (base build)") : "\u2014";
    document.getElementById("dlSignedNote").hidden = !(info.available && info.signed);
    document.getElementById("verAgents").textContent = report.versions.length
      ? report.versions.map(function (v) { return v.version + " (" + v.count + ")"; }).join(", ")
      : "No agents registered";

    const history = document.getElementById("dlHistory");
    history.innerHTML = report.history.length
      ? report.history.map(function (row) {
        return "<tr>" +
          '<td class="nowrap">' + U.escapeHtml(U.formatDateTime(row.timestampUtc)) + "</td>" +
          "<td class=\"mono\">" + U.escapeHtml(U.text(row.fileName)) + "</td>" +
          "<td class=\"mono\">" + U.escapeHtml(U.text(row.version)) + "</td>" +
          '<td class="num">' + sizeLabel(row.size) + "</td>" +
          "<td>" + U.statusPill(row.result) + "</td>" +
          '<td class="mono">' + U.escapeHtml(U.text(row.remoteIp)) + "</td>" +
          "</tr>";
      }).join("")
      : '<tr><td colspan="6" class="empty">No downloads have been recorded yet.</td></tr>';

    const activations = document.getElementById("dlActivations");
    activations.innerHTML = report.activations.length
      ? report.activations.map(function (agent) {
        return "<tr>" +
          '<td><a class="id-chip" href="/agents/' + encodeURIComponent(agent.displayId) + '">' + U.escapeHtml(agent.displayId) + "</a></td>" +
          "<td>" + U.escapeHtml(U.text(agent.machineName)) + "</td>" +
          '<td class="mono">' + U.escapeHtml(U.text(agent.agentVersion)) + "</td>" +
          '<td class="nowrap">' + U.escapeHtml(U.formatDateTime(agent.enrolledUtc)) + "</td>" +
          "<td>" + statusCell(agent) + "</td>" +
          '<td class="nowrap">' + U.escapeHtml(agent.lastSeenUtc ? U.relativeTime(agent.lastSeenUtc) : "Never") + "</td>" +
          "</tr>";
      }).join("")
      : '<tr><td colspan="6" class="empty">No agents have registered. A download does not appear here.</td></tr>';

    const issues = document.getElementById("dlIssues");
    const failedDownloads = report.history.filter(function (row) { return row.result !== "Success"; }).map(function (row) {
      return { timestampUtc: row.timestampUtc, kind: "Download", detail: row.detail || "The installer could not be downloaded.", remoteIp: row.remoteIp };
    });
    const problems = failedDownloads.concat(report.issues).sort(function (a, b) {
      return new Date(b.timestampUtc) - new Date(a.timestampUtc);
    }).slice(0, 30);
    issues.innerHTML = problems.length
      ? problems.map(function (item) {
        const who = item.displayId ? " · " + item.displayId : "";
        return '<li><span class="activity-icon crit"><i class="bi bi-exclamation-octagon"></i></span>' +
          '<div class="activity-text"><div class="title">' + U.escapeHtml(item.kind) + U.escapeHtml(who) + "</div>" +
          '<div class="text-muted">' + U.escapeHtml(item.detail || "Failed") + (item.remoteIp ? " · " + item.remoteIp : "") + "</div></div>" +
          '<span class="subtle nowrap">' + U.escapeHtml(U.relativeTime(item.timestampUtc)) + "</span></li>";
      }).join("")
      : '<li class="empty text-muted" style="padding:20px 16px;">No failed downloads, registrations, or activations.</li>';

    document.getElementById("dlUpdated").textContent = "Updated " + new Date().toLocaleTimeString();
  }

  async function refresh() {
    try {
      render(await U.api("/api/downloads"));
    } catch (error) {
      U.notify(error.message || "Could not load download information.", "danger");
    }
  }

  document.getElementById("dlCopy").addEventListener("click", async function () {
    const input = document.getElementById("dlLink");
    const btn = document.getElementById("dlCopy");
    if (!input.value) { return; }
    try {
      await navigator.clipboard.writeText(input.value);
    } catch (error) {
      input.select();
      document.execCommand("copy");
    }
    btn.innerHTML = '<i class="bi bi-check2"></i>';
    U.notify("Download link copied.", "success");
    setTimeout(function () { btn.innerHTML = '<i class="bi bi-clipboard"></i>'; }, 1500);
  });

  document.getElementById("dlBtn").addEventListener("click", function (event) {
    if (event.currentTarget.classList.contains("disabled")) {
      event.preventDefault();
    }
  });

  refresh();
  setInterval(refresh, 20000);
})();
