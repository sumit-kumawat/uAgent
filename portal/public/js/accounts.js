(function () {
  "use strict";
  const U = window.uAgent;
  const $ = function (id) { return document.getElementById(id); };
  const body = $("accountsBody");
  const PAGE_SIZE = 50;

  const query = { q: "", agent: "", source: "", state: "All", page: 1, sort: "machine", dir: "asc" };
  let accountControls = [];
  let lastResult = null;
  let requestSeq = 0;

  function isExpired(account) {
    return account.accountExpirationDate && new Date(account.accountExpirationDate) < new Date();
  }

  function readUrl() {
    const params = new URLSearchParams(window.location.search);
    query.q = params.get("q") || "";
    query.agent = params.get("agent") || "";
    query.source = params.get("source") || "";
    query.state = params.get("state") || "All";
    query.page = Number.parseInt(params.get("page"), 10) || 1;
    query.sort = params.get("sort") || "machine";
    query.dir = params.get("dir") === "desc" ? "desc" : "asc";
    $("nameFilter").value = query.q;
    $("sourceFilter").value = query.source;
    if (Array.from($("stateFilter").options).some(function (o) { return o.value === query.state; })) {
      $("stateFilter").value = query.state;
    }
  }

  function writeUrl() {
    const url = new URL(window.location.href);
    const set = function (key, value, fallback) {
      if (!value || value === fallback) { url.searchParams.delete(key); } else { url.searchParams.set(key, value); }
    };
    set("q", query.q, "");
    set("agent", query.agent, "");
    set("source", query.source, "");
    set("state", query.state, "All");
    set("page", String(query.page), "1");
    set("sort", query.sort, "machine");
    set("dir", query.dir, "asc");
    window.history.replaceState(null, "", url);
  }

  function actionsMenu(row) {
    const items = accountControls.map(function (c) {
      let reason = "";
      if (!c.allowed) {
        reason = "Requires the " + c.minRole + " role.";
      } else if (!row.online) {
        reason = "The agent is offline.";
      }
      const disabled = Boolean(reason);
      return '<li><button type="button" class="dropdown-item' + (disabled ? " disabled" : "") + (c.sensitive && !disabled ? " text-danger" : "") +
        '" data-control="' + U.escapeHtml(c.type) + '" data-agent="' + U.escapeHtml(row.agentDisplayId) + '" data-machine="' + U.escapeHtml(row.machineName) +
        '" data-account="' + U.escapeHtml(row.account.samAccountName) + '" data-source="' + U.escapeHtml(row.account.source) +
        '" title="' + U.escapeHtml(reason || c.description) + '">' + U.escapeHtml(c.label) + "</button></li>";
    }).join("");
    return '<div class="dropdown"><button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false" aria-label="Manage ' + U.escapeHtml(row.account.samAccountName) + '">Manage</button>' +
      '<ul class="dropdown-menu dropdown-menu-end">' + items + "</ul></div>";
  }

  function groupsCell(groups) {
    if (!groups || !groups.length) {
      return '<span class="subtle">\u2014</span>';
    }
    const shown = groups.slice(0, 2).map(function (g) {
      return '<span class="tag' + (/^administrators$/i.test(g) ? " tag-strong" : "") + '">' + U.escapeHtml(g) + "</span>";
    }).join(" ");
    return shown + (groups.length > 2 ? ' <span class="subtle" title="' + U.escapeHtml(groups.join(", ")) + '">+' + (groups.length - 2) + "</span>" : "");
  }

  function renderAgents(agents) {
    const select = $("agentFilter");
    const options = ['<option value="">All agents</option>'].concat(agents.map(function (a) {
      return '<option value="' + U.escapeHtml(a.agentId) + '">' + U.escapeHtml(a.displayId + " \u00b7 " + (a.machineName || "Unknown") + " (" + a.accountCount + ")") + "</option>";
    }));
    select.innerHTML = options.join("");
    const wanted = agents.find(function (a) { return a.agentId === query.agent || a.displayId === query.agent; });
    select.value = wanted ? wanted.agentId : "";
  }

  function renderCounts(counts) {
    $("cTotal").textContent = counts.total;
    $("cAttention").textContent = counts.attention;
    $("cLocked").textContent = counts.locked;
    $("cDisabled").textContent = counts.disabled;
    $("cLocal").textContent = counts.local;
    $("cDomain").textContent = counts.domain;
  }

  function renderSortIndicators() {
    document.querySelectorAll("th.sortable").forEach(function (th) {
      const active = th.getAttribute("data-sort") === query.sort;
      const icon = !active ? "bi-arrow-down-up" : query.dir === "asc" ? "bi-sort-up" : "bi-sort-down";
      th.setAttribute("aria-sort", !active ? "none" : query.dir === "asc" ? "ascending" : "descending");
      const existing = th.querySelector(".bi");
      if (existing) { existing.remove(); }
      th.insertAdjacentHTML("beforeend", '<i class="bi ' + icon + '" aria-hidden="true"' + (active ? ' style="opacity:1"' : "") + "></i>");
    });
  }

  function renderPager(result) {
    const pager = $("pager");
    if (!result.total) { pager.hidden = true; return; }
    pager.hidden = false;
    const first = (result.page - 1) * result.pageSize + 1;
    const last = Math.min(result.page * result.pageSize, result.total);
    const btns = [];
    const add = function (label, target, disabled, active) {
      btns.push('<button type="button" data-page="' + target + '"' + (disabled ? " disabled" : "") + (active ? ' class="active"' : "") + ">" + label + "</button>");
    };
    add("\u2039", result.page - 1, result.page <= 1, false);
    let prev = 0;
    for (let p = 1; p <= result.pages; p++) {
      if (p !== 1 && p !== result.pages && Math.abs(p - result.page) > 1) { continue; }
      if (p - prev > 1) { btns.push('<span class="subtle px-1">\u2026</span>'); }
      add(String(p), p, false, p === result.page);
      prev = p;
    }
    add("\u203a", result.page + 1, result.page >= result.pages, false);
    pager.innerHTML = "<span>Showing " + first + "\u2013" + last + " of " + result.total + '</span><span class="pages">' + btns.join("") + "</span>";
  }

  function renderRows(result) {
    if (!result.items.length) {
      const passwordFilter = query.state === "PasswordExpired" || query.state === "PasswordWarning";
      const note = !result.counts.total
        ? "No account inventory has been reported yet."
        : passwordFilter
          ? "No accounts match. Password expiry is shown only when an agent reports it."
          : "No accounts match the current filters.";
      body.innerHTML = '<tr><td colspan="11" class="empty">' + note + "</td></tr>";
      return;
    }
    body.innerHTML = result.items.map(function (row) {
      const a = row.account;
      return "<tr>" +
        '<td><a class="id-chip" href="/agents/' + encodeURIComponent(row.agentDisplayId) + '">' + U.escapeHtml(row.agentDisplayId) + "</a></td>" +
        "<td>" + U.escapeHtml(U.text(row.machineName)) + "</td>" +
        '<td><span class="cell-primary" title="' + U.escapeHtml(a.displayName || "") + '">' + U.escapeHtml(a.samAccountName) + "</span></td>" +
        "<td>" + U.escapeHtml(a.source || "Local") + "</td>" +
        "<td>" + groupsCell(a.groups) + "</td>" +
        "<td>" + U.booleanPill(a.enabled, "Enabled", "Disabled", "success", "danger") + "</td>" +
        "<td>" + U.booleanPill(a.lockedOut, "Locked", "No", "danger", "neutral") + "</td>" +
        "<td>" + U.booleanPill(isExpired(a), "Expired", "No", "danger", "neutral") + "</td>" +
        '<td class="nowrap">' + U.escapeHtml(U.formatDateTime(a.lastPasswordSet)) + "</td>" +
        '<td class="nowrap">' + U.escapeHtml(U.formatDateTime(a.lastLogon)) + "</td>" +
        "<td>" + actionsMenu(row) + "</td>" +
        "</tr>";
    }).join("");
  }

  async function refresh() {
    const seq = ++requestSeq;
    const params = new URLSearchParams({
      q: query.q, agent: query.agent, source: query.source, state: query.state,
      page: String(query.page), pageSize: String(PAGE_SIZE), sort: query.sort, dir: query.dir
    });
    try {
      if (!accountControls.length) {
        const me = await U.loadMe();
        accountControls = me.catalog.filter(function (c) { return c.category === "account"; });
      }
      const result = await U.api("/api/accounts?" + params.toString());
      if (seq !== requestSeq) {
        return;
      }
      lastResult = result;
      query.page = result.page;
      renderAgents(result.agents);
      renderCounts(result.counts);
      renderRows(result);
      renderPager(result);
      renderSortIndicators();
      $("accountCount").textContent = result.total + " of " + result.counts.total + " accounts";
      $("lastUpdated").textContent = "Updated " + new Date().toLocaleTimeString();
      writeUrl();
    } catch (error) {
      U.notify(error.message || "Could not load accounts.", "danger");
    }
  }

  function setFilter(key, value) {
    query[key] = value;
    query.page = 1;
    refresh();
  }

  body.addEventListener("click", function (event) {
    const button = event.target.closest("[data-control]");
    if (!button || button.classList.contains("disabled")) {
      return;
    }
    const control = accountControls.find(function (c) { return c.type === button.getAttribute("data-control"); });
    if (!control) {
      return;
    }
    U.runAction({
      agentKey: button.getAttribute("data-agent"),
      machineName: button.getAttribute("data-machine"),
      control: control,
      samAccountName: button.getAttribute("data-account"),
      accountSource: button.getAttribute("data-source") || null,
      onUpdate: function (cmd) { if (U.isTerminal(cmd.status)) { refresh(); } }
    });
  });

  $("pager").addEventListener("click", function (event) {
    const button = event.target.closest("button[data-page]");
    if (!button || button.disabled) {
      return;
    }
    query.page = Number.parseInt(button.getAttribute("data-page"), 10) || 1;
    refresh();
  });

  document.querySelectorAll("th.sortable").forEach(function (th) {
    function sort() {
      const key = th.getAttribute("data-sort");
      query.dir = query.sort === key && query.dir === "asc" ? "desc" : "asc";
      query.sort = key;
      refresh();
    }
    th.addEventListener("click", sort);
    th.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        sort();
      }
    });
  });

  $("agentFilter").addEventListener("change", function (e) { setFilter("agent", e.target.value); });
  $("sourceFilter").addEventListener("change", function (e) { setFilter("source", e.target.value); });
  $("stateFilter").addEventListener("change", function (e) { setFilter("state", e.target.value); });
  $("nameFilter").addEventListener("input", U.debounce(function () { setFilter("q", $("nameFilter").value.trim()); }, 250));

  U.onChange(function (batch) {
    if (lastResult && batch.some(function (item) { return item.type === "accounts" || item.type === "removed"; })) {
      refresh();
    }
  });

  readUrl();
  refresh();
  setInterval(refresh, 60000);
})();