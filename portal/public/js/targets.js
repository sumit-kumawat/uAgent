(function () {
  "use strict";
  const U = window.uAgent;
  const $ = function (id) { return document.getElementById(id); };
  const isAdmin = document.body.dataset.role === "Administrator";
  const MAX_FILE_BYTES = 10 * 1024 * 1024;

  const dnsState = { Resolved: ["success", "Resolved"], Unresolved: ["warning", "Unresolved"], NotChecked: ["neutral", "Not checked"], NotApplicable: ["neutral", "N/A"] };
  const reachState = { Reachable: ["success", "Reachable"], Unreachable: ["warning", "Unreachable"], NotChecked: ["neutral", "Not checked"], ViaAgent: ["info", "Via agent"] };
  const typeLabels = { hostname: "Host name", fqdn: "FQDN", ipv4: "IPv4", ipv6: "IPv6", invalid: "Invalid" };
  const views = [
    { key: "all", label: "All", count: function (s) { return s.total; } },
    { key: "valid", label: "Valid", count: function (s) { return s.valid; }, tone: "good" },
    { key: "issues", label: "Issues", count: function (s) { return s.issues; }, tone: "crit" },
    { key: "managed", label: "Managed", count: function (s) { return s.managed; }, tone: "info" },
    { key: "unmanaged", label: "Unmanaged", count: function (s) { return s.unmanaged; } },
    { key: "eligible", label: "Eligible", count: function (s) { return s.eligible; }, tone: "good" },
    { key: "unreachable", label: "Unreachable", count: function (s) { return s.unreachable; }, tone: "warn" }
  ];

  let currentId = null;
  let currentValidation = null;
  let view = "all";
  let page = 1;
  let request = 0;

  function num(value) {
    return Number(value) || 0;
  }

  function plain(value) {
    return U.escapeHtml(U.text(value));
  }

  function mapPill(map, value, withDot) {
    const style = map[value] || ["neutral", value || "Unknown"];
    return U.pill(style[0], style[1], withDot);
  }

  function kv(rows) {
    return rows.map(function (r) { return "<dt>" + U.escapeHtml(r[0]) + "</dt><dd>" + r[1] + "</dd>"; }).join("");
  }

  function emptyRow(colspan, message) {
    return '<tr><td colspan="' + colspan + '" class="empty">' + U.escapeHtml(message) + "</td></tr>";
  }

  function showError(box, error) {
    box.textContent = error.message || "Something went wrong.";
    box.hidden = false;
  }

  // ---------- Validate form ----------
  function valSource() {
    return document.querySelector('input[name="valSource"]:checked').value;
  }

  function syncValSource() {
    const file = valSource() === "file";
    $("valTextWrap").hidden = file;
    $("valFileWrap").hidden = !file;
  }

  function readBase64(file) {
    return new Promise(function (resolve, reject) {
      const reader = new FileReader();
      reader.onload = function () {
        const result = String(reader.result || "");
        resolve(result.slice(result.indexOf(",") + 1));
      };
      reader.onerror = function () { reject(new Error("The file could not be read.")); };
      reader.readAsDataURL(file);
    });
  }

  async function submitValidate() {
    const box = $("valError");
    box.hidden = true;
    const kind = $("valKind").value;
    const file = valSource() === "file";
    const body = { kind: kind, checkDns: $("valDns").checked, checkReachability: $("valReach").checked };
    if (file) {
      const input = $("valFile").files && $("valFile").files[0];
      if (!input) {
        showError(box, { input: $("valFile"), message: "Choose a CSV or Excel file." });
        return;
      }
      if (!/\.(csv|xlsx)$/i.test(input.name)) {
        showError(box, { message: "Only .csv and .xlsx files are supported." });
        return;
      }
      if (input.size > MAX_FILE_BYTES) {
        showError(box, { message: "The file is larger than 10 MB." });
        return;
      }
      body.fileName = input.name;
      body.contentBase64 = await readBase64(input);
    } else {
      const text = $("valText").value.trim();
      if (!text) {
        showError(box, { message: "Enter at least one host name, FQDN or IP address." });
        return;
      }
      body.text = text;
    }
    $("valSubmit").disabled = true;
    $("valProgress").hidden = false;
    $("valProgressLabel").textContent = "Starting\u2026";
    $("valProgressStatus").textContent = "";
    $("valBar").style.width = "0%";
    try {
      const data = await U.api("/api/deploy/targets/validate", { method: "POST", body: body });
      currentId = data.validation.id;
      currentValidation = data.validation;
      renderValidation();
    } catch (error) {
      showError(box, error);
      $("valProgress").hidden = true;
      $("valSubmit").disabled = false;
    }
  }

  function resetValidation() {
    currentId = null;
    currentValidation = null;
    view = "all";
    page = 1;
    $("resultsCard").hidden = true;
    $("formCard").hidden = false;
    $("valSubmit").disabled = false;
    $("valProgress").hidden = true;
    $("valError").hidden = true;
  }

  // ---------- Validation progress / summary ----------
  function renderValidation() {
    const v = currentValidation;
    if (!v) {
      return;
    }
    if (v.status !== "Completed") {
      $("valProgressLabel").textContent = "Checking systems\u2026";
      $("valProgressStatus").textContent = num(v.checked) + " of " + num(v.total) + " checked";
      const pct = num(v.total) ? Math.min(100, Math.floor(num(v.checked) * 100 / num(v.total))) : 0;
      $("valBar").style.width = pct + "%";
      return;
    }
    $("valSubmit").disabled = false;
    $("valProgress").hidden = true;
    $("formCard").hidden = true;
    $("resultsCard").hidden = false;
    $("resultsMeta").textContent = num(v.total) + (num(v.total) === 1 ? " system" : " systems") + " \u00b7 " + (v.kind === "agent" ? "Agent installation" : "Software deployment") + " \u00b7 by " + U.text(v.createdBy);
    renderSummary();
    renderActions();
    loadEntries();
  }

  function renderSummary() {
    const s = currentValidation.summary || {};
    $("sumTiles").innerHTML = views.map(function (v) {
      const cls = "tile" + (v.tone ? " tone-" + v.tone : "") + (v.key === view ? " active" : "");
      return '<button type="button" class="' + cls + '" data-view="' + v.key + '" aria-pressed="' + (v.key === view) + '">' +
        '<div class="label">' + U.escapeHtml(v.label) + '</div><div class="value">' + num(v.count(s)) + "</div></button>";
    }).join("");
  }

  function renderActions() {
    const s = currentValidation.summary || {};
    const admin = isAdmin;
    $("actGroup").hidden = !admin || !num(s.eligible);
    $("actDeploy").hidden = !admin || currentValidation.kind !== "software" || !num(s.eligible);
    $("actImport").hidden = !admin || !num(s.valid);
  }

  // ---------- Entries ----------
  function systemHtml(e) {
    const label = e.fqdn || e.hostname || e.ip || e.input;
    return '<span class="cell-primary">' + plain(label) + '</span><div class="subtle">' + U.escapeHtml(typeLabels[e.type] || e.type) + "</div>";
  }

  function issuesHtml(e) {
    const items = (e.issues || []).slice();
    if (e.compatible === false && e.compatibility) {
      items.push(e.compatibility);
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
      U.connectionStatePill(agent.connection);
  }

  function entryRow(e) {
    return "<tr>" +
      '<td class="num">' + plain(e.row) + "</td>" +
      "<td>" + systemHtml(e) + "</td>" +
      "<td>" + plain(e.site) + "</td>" +
      "<td>" + plain(e.group) + "</td>" +
      "<td>" + plain(e.os) + "</td>" +
      '<td class="cell-wrap">' + issuesHtml(e) + "</td>" +
      "<td>" + mapPill(dnsState, e.dns) + "</td>" +
      "<td>" + mapPill(reachState, e.reachability) + "</td>" +
      '<td class="nowrap">' + agentHtml(e.agent) + "</td>" +
      "<td>" + (e.eligible ? U.pill("success", "Yes") : U.pill("neutral", "No")) + "</td>" +
      '<td><span class="truncate d-inline-block" title="' + U.escapeHtml(e.reason || "") + '">' + plain(e.reason) + "</span></td>" +
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

  async function loadEntries() {
    if (!currentId) {
      return;
    }
    const mine = ++request;
    const pageSize = parseInt($("pageSize").value, 10) || 50;
    const params = new URLSearchParams({ view: view, q: $("recordSearch").value.trim(), page: String(page), pageSize: String(pageSize) });
    try {
      const data = await U.api("/api/deploy/targets/validations/" + encodeURIComponent(currentId) + "/entries?" + params.toString());
      if (mine !== request) {
        return;
      }
      const total = num(data.total);
      const rows = data.rows || [];
      if (!rows.length && total && page > 1) {
        page = Math.max(1, Math.ceil(total / pageSize));
        loadEntries();
        return;
      }
      $("recordCount").textContent = total + (total === 1 ? " system" : " systems");
      $("recordBody").innerHTML = rows.length ? rows.map(entryRow).join("") : emptyRow(11, "No systems in this view.");
      renderPager(total, pageSize);
    } catch (error) {
      if (mine === request) {
        $("recordBody").innerHTML = emptyRow(11, error.message || "Records could not be loaded.");
      }
    }
  }

  // ---------- Live refresh while running ----------
  const live = U.liveRefresh(function () {
    if (!currentId || (currentValidation && currentValidation.status === "Completed")) {
      return Promise.resolve();
    }
    return U.api("/api/deploy/targets/validations/" + encodeURIComponent(currentId)).then(function (data) {
      currentValidation = data.validation;
      renderValidation();
    }).catch(function () { /* keep the last known state */ });
  }, {
    types: ["validation"],
    fallbackMs: 2000,
    match: function (e) { return e.type === "validation" && e.validationId === currentId; }
  });

  // ---------- Save as target group ----------
  function openGroupModal() {
    $("grpName").value = "";
    $("grpCategory").value = "other";
    $("grpDesc").value = "";
    $("grpError").hidden = true;
    bootstrap.Modal.getOrCreateInstance($("groupModal")).show();
  }

  async function saveGroup() {
    const box = $("grpError");
    box.hidden = true;
    const name = $("grpName").value.trim();
    if (!name) {
      showError(box, { input: $("grpName"), message: "Enter a group name." });
      $("grpName").focus();
      return;
    }
    $("grpSave").disabled = true;
    try {
      await U.api("/api/deploy/targets/validations/" + encodeURIComponent(currentId) + "/group", {
        method: "POST",
        body: { name: name, category: $("grpCategory").value, description: $("grpDesc").value.trim() }
      });
      bootstrap.Modal.getOrCreateInstance($("groupModal")).hide();
      U.notify("Target group created.", "success");
    } catch (error) {
      showError(box, error);
    } finally {
      $("grpSave").disabled = false;
    }
  }

  // ---------- Create agent installation plan ----------
  function openImportModal() {
    $("impName").value = "Target list " + new Date().toISOString().slice(0, 10);
    $("impError").hidden = true;
    bootstrap.Modal.getOrCreateInstance($("importModal")).show();
  }

  async function saveImport() {
    const box = $("impError");
    box.hidden = true;
    const name = $("impName").value.trim();
    if (!name) {
      showError(box, { input: $("impName"), message: "Enter a name for this plan." });
      $("impName").focus();
      return;
    }
    $("impSave").disabled = true;
    try {
      const data = await U.api("/api/deploy/targets/validations/" + encodeURIComponent(currentId) + "/agent-import", {
        method: "POST",
        body: { name: name }
      });
      window.location.href = "/deployment-center/imports/" + encodeURIComponent(data.import.id);
    } catch (error) {
      showError(box, error);
      $("impSave").disabled = false;
    }
  }

  // ---------- Export CSV ----------
  function csvCell(value) {
    const text = value === null || value === undefined ? "" : String(value);
    const guarded = /^[=+\-@]/.test(text) ? "'" + text : text;
    return '"' + guarded.replace(/"/g, '""') + '"';
  }

  async function exportCsv() {
    const btn = $("actExport");
    btn.disabled = true;
    try {
      const rows = [];
      let fetchPage = 1;
      const pageSize = 1000;
      for (;;) {
        const params = new URLSearchParams({ view: "all", page: String(fetchPage), pageSize: String(pageSize) });
        const data = await U.api("/api/deploy/targets/validations/" + encodeURIComponent(currentId) + "/entries?" + params.toString());
        rows.push.apply(rows, data.rows || []);
        if (rows.length >= num(data.total) || !(data.rows || []).length) {
          break;
        }
        fetchPage += 1;
      }
      const header = ["Row", "Input", "Type", "Hostname", "FQDN", "IP", "Site", "Group", "OS", "Issues", "DNS", "Reachability", "Agent", "Eligible", "Reason"];
      const lines = [header.map(csvCell).join(",")];
      rows.forEach(function (e) {
        lines.push([
          e.row, e.input, e.type, e.hostname, e.fqdn, e.ip, e.site, e.group, e.os,
          (e.issues || []).join("; "), e.dns, e.reachability,
          e.agent ? e.agent.displayId : "", e.eligible ? "Yes" : "No", e.reason
        ].map(csvCell).join(","));
      });
      const blob = new Blob([lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "target-validation-" + currentId + ".csv";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      U.notify(error.message || "The export could not be built.", "danger");
    } finally {
      btn.disabled = false;
    }
  }

  // ---------- Events ----------
  document.querySelectorAll("[data-admin]").forEach(function (el) { el.hidden = el.hidden || !isAdmin; });

  const params = new URLSearchParams(window.location.search);
  if (params.get("for") === "agent") {
    $("valKind").value = "agent";
  }

  document.querySelectorAll('input[name="valSource"]').forEach(function (r) { r.addEventListener("change", syncValSource); });
  $("valForm").addEventListener("submit", function (event) { event.preventDefault(); submitValidate(); });
  $("valReset").addEventListener("click", resetValidation);

  $("sumTiles").addEventListener("click", function (event) {
    const btn = event.target.closest("button[data-view]");
    if (btn) {
      view = btn.dataset.view;
      page = 1;
      renderSummary();
      loadEntries();
    }
  });
  $("recordSearch").addEventListener("input", U.debounce(function () { page = 1; loadEntries(); }, 250));
  $("pageSize").addEventListener("change", function () { page = 1; loadEntries(); });
  $("pageButtons").addEventListener("click", function (event) {
    const btn = event.target.closest("button[data-page]");
    if (btn && !btn.disabled) {
      page = parseInt(btn.dataset.page, 10) || 1;
      loadEntries();
    }
  });

  $("actGroup").addEventListener("click", openGroupModal);
  $("groupForm").addEventListener("submit", function (event) { event.preventDefault(); saveGroup(); });
  $("actImport").addEventListener("click", openImportModal);
  $("importForm").addEventListener("submit", function (event) { event.preventDefault(); saveImport(); });
  $("actDeploy").addEventListener("click", function () {
    window.location.href = "/deployment-center/software#deploy=validation:" + encodeURIComponent(currentId);
  });
  $("actExport").addEventListener("click", exportCsv);

  syncValSource();
})();
