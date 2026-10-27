(function () {
  "use strict";
  const U = window.uAgent;
  const $ = function (id) { return document.getElementById(id); };
  const importId = $("importRoot").dataset.importId;
  const base = "/api/agent-deployment/imports/" + encodeURIComponent(importId);
  const isAdmin = document.body.dataset.role === "Administrator";

  const importStatus = { Review: ["warning", "In review"], Approved: ["success", "Approved"] };
  const recordState = {
    Review: ["neutral", "In review"], Excluded: ["neutral", "Excluded"], AwaitingDeployment: ["warning", "Awaiting install"],
    Registered: ["info", "Registered"], Upgrading: ["info", "Upgrading"], Repairing: ["info", "Repairing"],
    Verified: ["success", "Verified"], UpToDate: ["success", "Up to date"], Failed: ["danger", "Failed"]
  };
  const dnsState = { Resolved: ["success", "Resolved"], Unresolved: ["warning", "Unresolved"], NotChecked: ["neutral", "Not checked"] };
  const plans = [["install", "Install (kit)"], ["upgrade", "Upgrade"], ["repair", "Repair"], ["none", "No action"], ["exclude", "Exclude"]];
  const tiles = [
    { key: "total", label: "Total" },
    { key: "valid", label: "Valid", tone: "good" },
    { key: "invalid", label: "Invalid", tone: "crit" },
    { key: "duplicates", label: "Duplicates", tone: "warn" },
    { key: "unresolved", label: "DNS unresolved", tone: "warn" },
    { key: "install", label: "Install" },
    { key: "upgrade", label: "Upgrade" },
    { key: "repair", label: "Repair" },
    { key: "current", label: "Current", tone: "good" },
    { key: "excluded", label: "Excluded" },
    { key: "registered", label: "Registered", tone: "info" },
    { key: "verified", label: "Verified", tone: "good" },
    { key: "failed", label: "Failed", tone: "crit" }
  ];

  let summary = null;
  let view = "all";
  let page = 1;
  let request = 0;

  function num(value) {
    return Number(value) || 0;
  }

  function mapPill(map, value, withDot) {
    const style = map[value] || ["neutral", value || "Unknown"];
    return U.pill(style[0], style[1], withDot);
  }

  function plain(value) {
    return U.escapeHtml(U.text(value));
  }

  function kv(rows) {
    return rows.map(function (r) { return "<dt>" + U.escapeHtml(r[0]) + "</dt><dd>" + r[1] + "</dd>"; }).join("");
  }

  function canEditPlan() {
    return isAdmin && summary && summary.status === "Review";
  }

  // ---------- Summary ----------
  function renderSummary() {
    const s = summary;
    const c = s.counts || {};
    document.title = (s.name || "Agent import") + " \u00b7 uAgent";
    $("hdrName").textContent = s.name || "Agent import";
    $("hdrStatus").innerHTML = mapPill(importStatus, s.status, true);
    $("hdrFile").textContent = s.fileName || "";
    $("hdrCreated").innerHTML = "Imported by " + plain(s.createdBy) + ' <span title="' + U.escapeHtml(U.formatDateTime(s.createdUtc)) + '">' + U.escapeHtml(U.relativeTime(s.createdUtc)) + "</span>";
    $("hdrVersion").innerHTML = s.targetVersion ? 'Target version <span class="mono">' + U.escapeHtml(s.targetVersion) + "</span>" : "";
    $("approveBtn").hidden = !(isAdmin && s.status === "Review");
    $("jobLink").hidden = !s.jobId;
    if (s.jobId) {
      $("jobLink").href = "/deployment-center/jobs/" + encodeURIComponent(s.jobId);
    }
    $("kitCard").hidden = s.status !== "Approved" || !num(c.install);
    $("kitCount").textContent = num(c.install);

    const banners = [];
    if (s.status === "Review") {
      banners.push('<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>Review the plan for each system' +
        (isAdmin ? ", change it where needed, then approve. Approval starts upgrade and repair through the installed agents." : ". An administrator approves the import to start the deployment.") + "</div></div>");
      if (num(c.invalid) || num(c.duplicates)) {
        banners.push('<div class="banner banner-warning"><i class="bi bi-exclamation-triangle"></i><div>' + num(c.invalid) + " invalid and " + num(c.duplicates) +
          " duplicate rows are not deployed. Open the Issues view for details.</div></div>");
      }
    } else if (s.status === "Approved") {
      banners.push('<div class="banner banner-success"><i class="bi bi-check-circle"></i><div>Approved by ' + plain(s.approvedBy) + " on " + U.escapeHtml(U.formatDateTime(s.approvedUtc)) + "." +
        (s.jobId ? ' <a href="/deployment-center/jobs/' + encodeURIComponent(s.jobId) + '">Follow the upgrade job</a>.' : "") + "</div></div>");
    }
    $("banners").innerHTML = banners.join("");

    const html = tiles.map(function (t) {
      return '<div class="tile' + (t.tone ? " tone-" + t.tone : "") + '"><div class="label">' + U.escapeHtml(t.label) + '</div><div class="value">' + num(c[t.key]) + "</div></div>";
    }).join("");
    if ($("tiles").innerHTML !== html) {
      $("tiles").innerHTML = html;
    }
  }

  async function loadSummary() {
    const data = await U.api(base);
    summary = data.import;
    renderSummary();
  }

  // ---------- Records ----------
  function issuesHtml(r) {
    const items = (r.issues || []).slice();
    if (r.duplicateOf) {
      items.push("Duplicate of row " + r.duplicateOf);
    }
    return items.length
      ? '<span class="text-danger small">' + items.map(U.escapeHtml).join("<br />") + "</span>"
      : '<span class="subtle">\u2014</span>';
  }

  function agentHtml(agent) {
    if (!agent) {
      return '<span class="subtle">No agent</span>';
    }
    return (agent.displayId ? '<a class="id-chip" href="/agents/' + encodeURIComponent(agent.displayId) + '">' + U.escapeHtml(agent.displayId) + "</a> " : "") +
      '<span class="mono">' + plain(agent.version) + "</span> " + U.connectionStatePill(agent.connection);
  }

  function planHtml(r) {
    if (!canEditPlan()) {
      const label = plans.find(function (p) { return p[0] === r.plan; });
      return '<span class="tag">' + U.escapeHtml(label ? label[1] : U.text(r.plan)) + "</span>";
    }
    return '<select class="form-select form-select-sm plan-select" data-row="' + U.escapeHtml(r.row) + '" aria-label="Plan for row ' + U.escapeHtml(r.row) + '">' +
      plans.map(function (p) {
        return '<option value="' + p[0] + '"' + (p[0] === r.plan ? " selected" : "") + ">" + U.escapeHtml(p[1]) + "</option>";
      }).join("") + "</select>";
  }

  function recordRow(r) {
    return '<tr data-row="' + U.escapeHtml(r.row) + '">' +
      '<td class="num">' + plain(r.row) + "</td>" +
      '<td><span class="cell-primary">' + plain(r.hostname) + "</span></td>" +
      '<td class="mono">' + plain(r.fqdn) + "</td>" +
      '<td class="mono">' + plain(r.ip) + "</td>" +
      "<td>" + plain(r.site) + "</td>" +
      "<td>" + plain(r.os) + "</td>" +
      "<td>" + plain(r.group) + "</td>" +
      '<td class="cell-wrap">' + issuesHtml(r) + "</td>" +
      "<td>" + mapPill(dnsState, r.dns) + "</td>" +
      '<td class="nowrap">' + agentHtml(r.agent) + "</td>" +
      "<td>" + planHtml(r) + "</td>" +
      "<td>" + mapPill(recordState, r.state, true) + "</td>" +
      '<td><span class="truncate d-inline-block" title="' + U.escapeHtml(r.message || "") + '">' + plain(r.message) + "</span></td>" +
      "</tr>";
  }

  function renderPager(total, pageSize) {
    const pager = $("recordPager");
    if (!total) {
      pager.hidden = true;
      return;
    }
    pager.hidden = false;
    const pageCount = Math.max(1, Math.ceil(total / pageSize));
    $("pageInfo").textContent = "Showing " + ((page - 1) * pageSize + 1) + "\u2013" + Math.min(page * pageSize, total) + " of " + total;
    const btns = [];
    const add = function (label, target, disabled, active) {
      btns.push('<button type="button" data-page="' + target + '"' + (disabled ? " disabled" : "") + (active ? ' class="active"' : "") + ">" + label + "</button>");
    };
    add("\u2039", page - 1, page <= 1, false);
    let prev = 0;
    for (let p = 1; p <= pageCount; p++) {
      if (p === 1 || p === pageCount || Math.abs(p - page) <= 1) {
        if (p - prev > 1) {
          btns.push('<span class="subtle px-1">\u2026</span>');
        }
        add(String(p), p, false, p === page);
        prev = p;
      }
    }
    add("\u203a", page + 1, page >= pageCount, false);
    $("pageButtons").innerHTML = btns.join("");
  }

  async function loadRecords() {
    const mine = ++request;
    const pageSize = parseInt($("pageSize").value, 10) || 50;
    const params = new URLSearchParams({ view: view, q: $("recordSearch").value.trim(), page: String(page), pageSize: String(pageSize) });
    try {
      const data = await U.api(base + "/records?" + params.toString());
      if (mine !== request) {
        return;
      }
      const total = num(data.total);
      const rows = data.rows || [];
      if (!rows.length && total && page > 1) {
        page = Math.max(1, Math.ceil(total / pageSize));
        loadRecords();
        return;
      }
      $("recordCount").textContent = total + (total === 1 ? " system" : " systems");
      $("recordBody").innerHTML = rows.length ? rows.map(recordRow).join("") : '<tr><td colspan="13" class="empty">No systems in this view.</td></tr>';
      renderPager(total, pageSize);
    } catch (error) {
      if (mine === request) {
        $("recordBody").innerHTML = '<tr><td colspan="13" class="empty">' + U.escapeHtml(error.message || "Records could not be loaded.") + "</td></tr>";
      }
    }
  }

  async function changePlan(select) {
    const row = select.dataset.row;
    select.disabled = true;
    try {
      const data = await U.api(base + "/records/" + encodeURIComponent(row), { method: "PATCH", body: { plan: select.value } });
      const tr = select.closest("tr");
      if (data && data.record && tr) {
        tr.outerHTML = recordRow(data.record);
      }
      loadSummary().catch(function () {});
    } catch (error) {
      U.notify(error.message || "The plan could not be changed.", "danger");
      loadRecords();
    }
  }

  // ---------- Approve ----------
  async function openApprove() {
    const c = summary.counts || {};
    $("approveSummary").innerHTML = kv([
      ["Upgrade", String(num(c.upgrade))],
      ["Repair", String(num(c.repair))],
      ["Install with the kit", String(num(c.install))],
      ["Already current", String(num(c.current))],
      ["Excluded", String(num(c.excluded))],
      ["Target version", '<span class="mono">' + plain(summary.targetVersion) + "</span>"]
    ]);
    $("apReauth").value = "";
    $("approveError").hidden = true;
    try {
      const settings = await U.api("/api/deploy/settings");
      $("apMaxConc").value = settings.maxConcurrent || "";
      $("apPerSite").value = settings.perSiteConcurrent || "";
      $("apAttempts").value = settings.defaultMaxAttempts || 3;
    } catch (error) {
      U.notify("Default limits could not be loaded. Enter them manually.", "warning");
    }
    bootstrap.Modal.getOrCreateInstance($("approveModal")).show();
  }

  function readInt(id, label, min, max) {
    const input = $(id);
    const value = Number(input.value.trim());
    if (input.value.trim() === "" || !Number.isInteger(value) || value < min || (max !== undefined && value > max)) {
      const error = new Error(label + " must be a whole number" + (max !== undefined ? " from " + min + " to " + max : " of at least " + min) + ".");
      error.input = input;
      throw error;
    }
    return value;
  }

  async function submitApprove() {
    const box = $("approveError");
    box.hidden = true;
    let options;
    try {
      options = {
        maxConcurrent: readInt("apMaxConc", "Maximum concurrent", 1),
        perSiteConcurrent: readInt("apPerSite", "Maximum concurrent per site", 1),
        maxAttempts: readInt("apAttempts", "Maximum attempts", 1, 10),
        pilotCount: readInt("apPilot", "Pilot systems", 0),
        waveSize: readInt("apWave", "Wave size", 0),
        autoAdvance: $("apAutoAdvance").checked
      };
      if (!$("apReauth").value) {
        const error = new Error("Enter your portal password.");
        error.input = $("apReauth");
        throw error;
      }
    } catch (error) {
      box.textContent = error.message;
      box.hidden = false;
      if (error.input) {
        error.input.focus();
      }
      return;
    }
    $("approveSubmit").disabled = true;
    try {
      const data = await U.api(base + "/approve", { method: "POST", body: { confirmed: true, currentPassword: $("apReauth").value, options: options } });
      bootstrap.Modal.getOrCreateInstance($("approveModal")).hide();
      U.notify(data && data.jobId ? "Import approved. The upgrade job has started." : "Import approved.", "success");
      await refresh();
    } catch (error) {
      box.textContent = error.message || "The import could not be approved.";
      box.hidden = false;
    } finally {
      $("apReauth").value = "";
      $("approveSubmit").disabled = false;
    }
  }

  // ---------- Refresh ----------
  async function refresh() {
    try {
      await loadSummary();
    } catch (error) {
      if (error.status === 404) {
        $("banners").innerHTML = '<div class="banner banner-danger"><i class="bi bi-exclamation-circle"></i><div>This import does not exist or was removed.</div></div>';
        $("recordBody").innerHTML = '<tr><td colspan="13" class="empty">No records.</td></tr>';
        return;
      }
      U.notify(error.message || "The import could not be loaded.", "danger");
    }
    await loadRecords();
  }

  $("refreshBtn").addEventListener("click", refresh);
  $("approveBtn").addEventListener("click", openApprove);
  $("approveForm").addEventListener("submit", function (event) { event.preventDefault(); submitApprove(); });
  $("approveModal").addEventListener("hidden.bs.modal", function () { $("apReauth").value = ""; });
  $("viewTabs").addEventListener("click", function (event) {
    const btn = event.target.closest("button[data-view]");
    if (!btn) {
      return;
    }
    view = btn.dataset.view;
    $("viewTabs").querySelectorAll("button[data-view]").forEach(function (b) {
      b.classList.toggle("active", b === btn);
      b.setAttribute("aria-pressed", String(b === btn));
    });
    page = 1;
    loadRecords();
  });
  $("recordSearch").addEventListener("input", U.debounce(function () { page = 1; loadRecords(); }, 250));
  $("pageSize").addEventListener("change", function () { page = 1; loadRecords(); });
  $("pageButtons").addEventListener("click", function (event) {
    const btn = event.target.closest("button[data-page]");
    if (btn && !btn.disabled) {
      page = parseInt(btn.dataset.page, 10) || 1;
      loadRecords();
    }
  });
  $("recordBody").addEventListener("change", function (event) {
    const select = event.target.closest("select.plan-select");
    if (select) {
      changePlan(select);
    }
  });

  U.liveRefresh(refresh, {
    types: ["deployment", "agent"],
    fallbackMs: 10000,
    match: function (e) { return (e.type === "deployment" && summary && e.jobId === summary.jobId) || (e.type === "agent" && summary && summary.status === "Approved"); }
  });
  refresh();
})();
