(function () {
  "use strict";
  const U = window.uAgent;
  let rows = [];
  let sortKey = "timestampUtc";
  let sortDir = "desc";
  let page = 1;

  const el = function (id) { return document.getElementById(id); };

  function populateUsers() {
    const select = el("userFilter");
    const current = select.value;
    const users = Array.from(new Set(rows.map(function (r) { return r.user; }))).sort();
    select.innerHTML = '<option value="">All users</option>' + users.map(function (u) {
      return '<option value="' + U.escapeHtml(u) + '">' + U.escapeHtml(u) + "</option>";
    }).join("");
    select.value = current;
  }

  function filtered() {
    const term = el("searchBox").value.trim().toLowerCase();
    const user = el("userFilter").value;
    const result = el("resultFilter").value;
    const fromValue = el("fromDate").value;
    const toValue = el("toDate").value;
    const from = fromValue ? new Date(fromValue + "T00:00:00") : null;
    const to = toValue ? new Date(toValue + "T23:59:59") : null;

    return rows.filter(function (row) {
      if (user && row.user !== user) { return false; }
      if (result && row.result !== result) { return false; }
      const ts = new Date(row.timestampUtc);
      if (from && ts < from) { return false; }
      if (to && ts > to) { return false; }
      if (term) {
        const haystack = [row.user, row.action, row.agentDisplayId, row.machineName,
          row.samAccountName, row.details, row.remoteIp].filter(Boolean).join(" ").toLowerCase();
        if (haystack.indexOf(term) === -1) { return false; }
      }
      return true;
    });
  }

  function sorted(list) {
    const dir = sortDir === "asc" ? 1 : -1;
    return list.slice().sort(function (a, b) {
      let av = a[sortKey];
      let bv = b[sortKey];
      if (sortKey === "timestampUtc") {
        av = new Date(av).getTime();
        bv = new Date(bv).getTime();
      } else {
        av = (av || "").toString().toLowerCase();
        bv = (bv || "").toString().toLowerCase();
      }
      if (av < bv) { return -1 * dir; }
      if (av > bv) { return 1 * dir; }
      return 0;
    });
  }

  function syncSortHeaders() {
    document.querySelectorAll("th.sortable").forEach(function (th) {
      const icon = th.querySelector(".bi");
      if (th.dataset.sort === sortKey) {
        th.setAttribute("aria-sort", sortDir === "asc" ? "ascending" : "descending");
        if (icon) { icon.className = "bi " + (sortDir === "asc" ? "bi-sort-up" : "bi-sort-down"); }
      } else {
        th.removeAttribute("aria-sort");
        if (icon) { icon.className = "bi bi-arrow-down-up"; }
      }
    });
  }

  function rowHtml(row) {
    const agent = row.agentId
      ? '<a class="id-chip" href="/agents/' + encodeURIComponent(row.agentDisplayId) + '">' + U.escapeHtml(row.agentDisplayId) + "</a> " + U.escapeHtml(row.machineName || "")
      : '<span class="subtle">Portal</span>';
    return "<tr>" +
      '<td class="nowrap">' + U.escapeHtml(U.formatDateTime(row.timestampUtc)) + "</td>" +
      "<td>" + U.escapeHtml(row.user) + "</td>" +
      "<td>" + U.escapeHtml(row.action) + "</td>" +
      "<td>" + agent + "</td>" +
      "<td>" + (row.samAccountName ? U.escapeHtml(row.samAccountName) : '<span class="subtle">\u2014</span>') + "</td>" +
      "<td>" + U.statusPill(row.result) + "</td>" +
      '<td><span class="truncate d-inline-block" title="' + U.escapeHtml(row.details || "") + '">' + U.escapeHtml(row.details || "") + "</span></td>" +
      '<td class="mono">' + U.escapeHtml(U.text(row.remoteIp)) + "</td>" +
      "</tr>";
  }

  function renderPager(total, pageSize, pageCount) {
    const pager = el("auditPager");
    if (total === 0) { pager.hidden = true; return; }
    pager.hidden = false;
    const first = (page - 1) * pageSize + 1;
    const last = Math.min(page * pageSize, total);
    el("pageInfo").textContent = "Showing " + first + "\u2013" + last + " of " + total;

    const btns = [];
    const add = function (label, target, disabled, active) {
      btns.push('<button type="button" data-page="' + target + '"' +
        (disabled ? " disabled" : "") + (active ? ' class="active"' : "") + ">" + label + "</button>");
    };
    add("\u2039", page - 1, page <= 1, false);
    const windowed = [];
    for (let p = 1; p <= pageCount; p++) {
      if (p === 1 || p === pageCount || Math.abs(p - page) <= 1) { windowed.push(p); }
    }
    let prev = 0;
    windowed.forEach(function (p) {
      if (p - prev > 1) { btns.push('<span class="subtle px-1">\u2026</span>'); }
      add(String(p), p, false, p === page);
      prev = p;
    });
    add("\u203a", page + 1, page >= pageCount, false);
    el("pageButtons").innerHTML = btns.join("");
  }

  function render() {
    const body = el("auditBody");
    const matched = sorted(filtered());
    const total = matched.length;
    const pageSize = parseInt(el("pageSize").value, 10) || 50;
    const pageCount = Math.max(1, Math.ceil(total / pageSize));
    if (page > pageCount) { page = pageCount; }
    const start = (page - 1) * pageSize;
    const slice = matched.slice(start, start + pageSize);

    el("auditCount").textContent = total + " of " + rows.length + " entries";
    syncSortHeaders();

    if (total === 0) {
      body.innerHTML = '<tr><td colspan="8" class="empty">No matching audit entries.</td></tr>';
      renderPager(0, pageSize, pageCount);
      return;
    }
    body.innerHTML = slice.map(rowHtml).join("");
    renderPager(total, pageSize, pageCount);
  }

  function exportCsv() {
    const matched = sorted(filtered());
    const headers = ["Time", "Administrator", "Action", "Target system", "Account", "Result", "Details", "Source address"];
    const esc = function (v) {
      const s = (v === null || v === undefined) ? "" : String(v);
      return '"' + s.replace(/"/g, '""') + '"';
    };
    const lines = [headers.map(esc).join(",")];
    matched.forEach(function (row) {
      lines.push([
        U.formatDateTime(row.timestampUtc),
        row.user,
        row.action,
        row.agentId ? (row.agentDisplayId + " " + (row.machineName || "")) : "Portal",
        row.samAccountName || "",
        row.result,
        row.details || "",
        row.remoteIp || ""
      ].map(esc).join(","));
    });
    const blob = new Blob([lines.join("\r\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "uagent-audit-" + new Date().toISOString().slice(0, 10) + ".csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function refresh() {
    try {
      rows = await U.api("/api/audit");
      populateUsers();
      render();
      el("lastUpdated").textContent = "Updated " + new Date().toLocaleTimeString();
    } catch (error) {
      U.notify(error.message || "Could not load the audit log.", "danger");
    }
  }

  document.querySelectorAll("th.sortable").forEach(function (th) {
    th.addEventListener("click", function () {
      const key = th.dataset.sort;
      if (sortKey === key) {
        sortDir = sortDir === "asc" ? "desc" : "asc";
      } else {
        sortKey = key;
        sortDir = key === "timestampUtc" ? "desc" : "asc";
      }
      render();
    });
  });

  ["userFilter", "resultFilter", "fromDate", "toDate"].forEach(function (id) {
    el(id).addEventListener("change", function () { page = 1; render(); });
  });
  el("searchBox").addEventListener("input", function () { page = 1; render(); });
  el("pageSize").addEventListener("change", function () { page = 1; render(); });
  el("exportBtn").addEventListener("click", exportCsv);
  el("pageButtons").addEventListener("click", function (e) {
    const btn = e.target.closest("button[data-page]");
    if (!btn || btn.disabled) { return; }
    page = parseInt(btn.dataset.page, 10);
    render();
  });

  refresh();
  setInterval(refresh, 30000);
})();
