(function () {
  "use strict";

  const uAgent = {};

  uAgent.escapeHtml = function (value) {
    if (value === null || value === undefined) {
      return "";
    }
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  };

  uAgent.text = function (value) {
    return (value === null || value === undefined || value === "") ? "\u2014" : String(value);
  };

  uAgent.formatDateTime = function (value) {
    if (!value) {
      return "\u2014";
    }
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  };

  uAgent.relativeTime = function (value) {
    if (!value) {
      return "Never";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return String(value);
    }
    const seconds = Math.round((Date.now() - date.getTime()) / 1000);
    if (seconds < 5) {
      return "Just now";
    }
    if (seconds < 60) {
      return seconds + " sec ago";
    }
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) {
      return minutes === 1 ? "1 min ago" : minutes + " min ago";
    }
    const hours = Math.round(minutes / 60);
    if (hours < 24) {
      return hours === 1 ? "1 hour ago" : hours + " hours ago";
    }
    const days = Math.round(hours / 24);
    return days === 1 ? "1 day ago" : days + " days ago";
  };

  uAgent.formatUptime = function (value) {
    if (!value) {
      return "\u2014";
    }
    const match = /^(?:(\d+)\.)?(\d{1,2}):(\d{2}):(\d{2})/.exec(String(value));
    if (!match) {
      return String(value);
    }
    const days = Number(match[1] || 0);
    const hours = Number(match[2]);
    const minutes = Number(match[3]);
    if (days > 0) {
      return days + "d " + hours + "h " + minutes + "m";
    }
    return hours > 0 ? hours + "h " + minutes + "m" : minutes + "m";
  };

  uAgent.pill = function (tone, label, withDot) {
    return '<span class="pill pill-' + tone + '">' + (withDot ? '<span class="dot"></span>' : "") +
      uAgent.escapeHtml(label) + "</span>";
  };

  uAgent.booleanPill = function (value, trueText, falseText, trueTone, falseTone) {
    return value
      ? uAgent.pill(trueTone || "success", trueText)
      : uAgent.pill(falseTone || "neutral", falseText);
  };

  uAgent.connectionPill = function (online) {
    return online ? uAgent.pill("success", "Online", true) : uAgent.pill("neutral", "Offline", true);
  };

  const statusStyles = {
    Pending: { tone: "warning", label: "Pending" },
    Delivered: { tone: "info", label: "Running" },
    Success: { tone: "success", label: "Succeeded" },
    Failed: { tone: "danger", label: "Failed" },
    TimedOut: { tone: "danger", label: "Timed out" },
    Unavailable: { tone: "neutral", label: "Unavailable" },
    Denied: { tone: "danger", label: "Denied" }
  };

  uAgent.statusPill = function (status) {
    const style = statusStyles[status] || { tone: "neutral", label: status || "Unknown" };
    return uAgent.pill(style.tone, style.label, true);
  };

  uAgent.isTerminal = function (status) {
    return status === "Success" || status === "Failed" || status === "TimedOut";
  };

  uAgent.agentLink = function (displayId, label) {
    return '<a href="/agents/' + encodeURIComponent(displayId) + '">' + uAgent.escapeHtml(label) + "</a>";
  };

  uAgent.ApiError = function (message, status, code) {
    const error = new Error(message);
    error.status = status;
    error.code = code || "";
    return error;
  };

  uAgent.api = async function (path, options) {
    const opts = options || {};
    const init = {
      method: opts.method || "GET",
      headers: { "Accept": "application/json" },
      credentials: "same-origin",
      cache: "no-store"
    };
    if (Object.prototype.hasOwnProperty.call(opts, "body")) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.body);
    }
    let response;
    try {
      response = await fetch(path, init);
    } catch (networkError) {
      throw uAgent.ApiError("The portal could not be reached. Check your connection.", 0, "network");
    }
    if (response.status === 401) {
      window.location.href = "/login?returnUrl=" + encodeURIComponent(window.location.pathname);
      throw uAgent.ApiError("Your session has expired. Redirecting to sign in.", 401, "unauthenticated");
    }
    if (response.status === 204) {
      return null;
    }
    const contentType = response.headers.get("content-type") || "";
    let payload = null;
    if (contentType.indexOf("application/json") >= 0) {
      payload = await response.json();
    } else {
      const raw = await response.text();
      payload = raw ? { error: raw } : null;
    }
    if (!response.ok) {
      const message = payload && payload.error ? payload.error : "Request failed (HTTP " + response.status + ").";
      throw uAgent.ApiError(message, response.status, payload && payload.code);
    }
    return payload;
  };

  uAgent.notify = function (message, tone) {
    const kind = tone === true ? "danger" : (tone || "success");
    let host = document.getElementById("ua-toasts");
    if (!host) {
      host = document.createElement("div");
      host.id = "ua-toasts";
      host.style.cssText = "position:fixed;top:68px;right:20px;z-index:1080;width:360px;max-width:calc(100vw - 40px);";
      document.body.appendChild(host);
    }
    const icons = { success: "bi-check-circle", danger: "bi-exclamation-octagon", warning: "bi-exclamation-triangle", info: "bi-info-circle" };
    const el = document.createElement("div");
    el.className = "banner banner-" + (kind === "success" ? "info" : kind) + " shadow-sm mb-2";
    if (kind === "success") {
      el.style.cssText = "background:#ecfdf3;border-color:#c6f0d5;color:#14532d;";
    }
    el.innerHTML = '<i class="bi ' + (icons[kind] || icons.info) + '"></i><div></div>';
    el.querySelector("div").textContent = message;
    host.appendChild(el);
    setTimeout(function () { el.remove(); }, kind === "danger" ? 9000 : 6000);
  };

  // Polls a queued action until the agent reports a final result, then notifies the operator.
  uAgent.trackCommand = function (agentKey, command, onUpdate) {
    const started = Date.now();
    const label = command.label || command.commandType;
    async function tick() {
      try {
        const latest = await uAgent.api("/api/agents/" + encodeURIComponent(agentKey) + "/commands/" + encodeURIComponent(command.commandId));
        if (typeof onUpdate === "function") {
          onUpdate(latest);
        }
        if (uAgent.isTerminal(latest.status)) {
          if (latest.status === "Success") {
            uAgent.notify(label + " succeeded" + (latest.result ? ": " + latest.result.split("\n")[0] : "."), "success");
          } else if (latest.status === "TimedOut") {
            uAgent.notify(label + " timed out: the agent received it but did not report a result.", "danger");
          } else {
            uAgent.notify(label + " failed" + (latest.result ? ": " + latest.result : "."), "danger");
          }
          return;
        }
      } catch (error) {
        if (error.status === 401) {
          return;
        }
      }
      if (Date.now() - started < 5 * 60 * 1000) {
        setTimeout(tick, 2000);
      }
    }
    setTimeout(tick, 1500);
  };

  function ensureActionModal() {
    let el = document.getElementById("ua-action-modal");
    if (el) {
      return el;
    }
    el = document.createElement("div");
    el.id = "ua-action-modal";
    el.className = "modal fade";
    el.tabIndex = -1;
    el.innerHTML =
      '<div class="modal-dialog modal-dialog-centered">' +
      '  <form class="modal-content" novalidate>' +
      '    <div class="modal-header">' +
      '      <h5 class="modal-title" data-role="title">Confirm action</h5>' +
      '      <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>' +
      "    </div>" +
      '    <div class="modal-body">' +
      '      <p class="mb-2" data-role="summary"></p>' +
      '      <p class="text-muted small mb-3" data-role="description"></p>' +
      '      <div class="banner banner-warning mb-3 d-none" data-role="sensitive"><i class="bi bi-exclamation-triangle"></i><div>This is a sensitive action. It runs on the host and is recorded in the audit log.</div></div>' +
      '      <div class="mb-3 d-none" data-role="password-wrap">' +
      '        <label class="form-label" for="ua-action-password">New password</label>' +
      '        <div class="input-group">' +
      '          <input type="password" class="form-control" id="ua-action-password" autocomplete="new-password" spellcheck="false" />' +
      '          <button class="btn btn-outline-secondary" type="button" data-role="password-toggle" aria-label="Show password"><i class="bi bi-eye"></i></button>' +
      "        </div>" +
      "      </div>" +
      '      <div class="mb-3">' +
      '        <label class="form-label" for="ua-action-reason" data-role="reason-label">Reason (optional)</label>' +
      '        <textarea class="form-control" id="ua-action-reason" rows="2" maxlength="500" placeholder="Why is this action needed?"></textarea>' +
      "      </div>" +
      '      <div class="mb-1 d-none" data-role="typed-wrap">' +
      '        <label class="form-label" for="ua-action-typed">Type <span class="mono" data-role="typed-target"></span> to confirm</label>' +
      '        <input type="text" class="form-control" id="ua-action-typed" autocomplete="off" spellcheck="false" />' +
      "      </div>" +
      '      <div class="alert alert-danger py-2 mt-3 mb-0 d-none" data-role="error"></div>' +
      "    </div>" +
      '    <div class="modal-footer">' +
      '      <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>' +
      '      <button type="submit" class="btn btn-sm btn-primary" data-role="confirm">Run action</button>' +
      "    </div>" +
      "  </form>" +
      "</div>";
    document.body.appendChild(el);

    const toggle = el.querySelector('[data-role="password-toggle"]');
    toggle.addEventListener("click", function () {
      const input = el.querySelector("#ua-action-password");
      const icon = toggle.querySelector("i");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      icon.className = show ? "bi bi-eye-slash" : "bi bi-eye";
    });
    return el;
  }

  // Opens the confirmation dialog for a remote action and queues it on the agent.
  // opts: { agentKey, machineName, control: {type,label,description,sensitive,needsPassword,category}, samAccountName, onQueued, onUpdate }
  uAgent.runAction = function (opts) {
    const control = opts.control;
    const el = ensureActionModal();
    const modal = bootstrap.Modal.getOrCreateInstance(el);
    const q = function (role) { return el.querySelector('[data-role="' + role + '"]'); };
    const target = opts.samAccountName
      ? "account <strong>" + uAgent.escapeHtml(opts.samAccountName) + "</strong> on <strong>" + uAgent.escapeHtml(opts.machineName) + "</strong>"
      : "<strong>" + uAgent.escapeHtml(opts.machineName) + "</strong>";

    q("title").textContent = control.label;
    q("summary").innerHTML = "Run <strong>" + uAgent.escapeHtml(control.label.toLowerCase()) + "</strong> for " + target + "?";
    q("description").textContent = control.description || "";
    q("sensitive").classList.toggle("d-none", !control.sensitive);
    q("password-wrap").classList.toggle("d-none", !control.needsPassword);
    q("typed-wrap").classList.toggle("d-none", !control.sensitive);
    q("typed-target").textContent = opts.machineName;
    q("reason-label").textContent = control.sensitive ? "Reason (required)" : "Reason (optional)";
    q("error").classList.add("d-none");

    const password = el.querySelector("#ua-action-password");
    const reason = el.querySelector("#ua-action-reason");
    const typed = el.querySelector("#ua-action-typed");
    password.value = "";
    password.type = "password";
    reason.value = "";
    typed.value = "";

    const confirm = q("confirm");
    confirm.className = "btn btn-sm " + (control.sensitive ? "btn-danger" : "btn-primary");
    confirm.textContent = control.sensitive ? control.label : "Run action";

    function ready() {
      if (control.needsPassword && !password.value) { return false; }
      if (control.sensitive && !reason.value.trim()) { return false; }
      if (control.sensitive && typed.value.trim().toLowerCase() !== String(opts.machineName).toLowerCase()) { return false; }
      return true;
    }
    function refreshState() { confirm.disabled = !ready(); }
    [password, reason, typed].forEach(function (input) { input.oninput = refreshState; });
    refreshState();

    const form = el.querySelector("form");
    form.onsubmit = async function (event) {
      event.preventDefault();
      if (!ready()) {
        return;
      }
      confirm.disabled = true;
      q("error").classList.add("d-none");
      try {
        const command = await uAgent.api("/api/agents/" + encodeURIComponent(opts.agentKey) + "/commands", {
          method: "POST",
          body: {
            commandType: control.type,
            samAccountName: opts.samAccountName || "",
            newPassword: control.needsPassword ? password.value : null,
            reason: reason.value.trim(),
            confirmed: true
          }
        });
        password.value = "";
        modal.hide();
        uAgent.notify(control.label + " queued. Waiting for the agent to run it\u2026", "info");
        if (typeof opts.onQueued === "function") {
          opts.onQueued(command);
        }
        uAgent.trackCommand(opts.agentKey, command, opts.onUpdate);
      } catch (error) {
        const box = q("error");
        box.textContent = error.message || "The action could not be queued.";
        box.classList.remove("d-none");
        refreshState();
      }
    };

    modal.show();
    setTimeout(function () {
      (control.needsPassword ? password : reason).focus();
    }, 300);
  };

  // Shared agent table: Agent ID, Machine Name, OS Version, Domain, DNS, Last Heartbeat, Accounts.
  uAgent.agentRows = function (agents) {
    return agents.map(function (agent) {
      const domain = agent.isDomainJoined && agent.domainName
        ? uAgent.escapeHtml(agent.domainName)
        : '<span class="subtle">Workgroup</span>';
      const heartbeat = agent.lastSeenUtc
        ? '<span title="' + uAgent.escapeHtml(uAgent.formatDateTime(agent.lastSeenUtc)) + '">' + uAgent.escapeHtml(uAgent.relativeTime(agent.lastSeenUtc)) + "</span>"
        : '<span class="subtle">Never</span>';
      return '<tr class="row-link" tabindex="0" data-href="/agents/' + encodeURIComponent(agent.displayId) + '">' +
        '<td><span class="id-chip">' + uAgent.escapeHtml(agent.displayId) + "</span></td>" +
        '<td><span class="cell-primary"><span class="status-dot ' + (agent.online ? "online" : "offline") + '" title="' + (agent.online ? "Online" : "Offline") + '"></span>' +
        uAgent.escapeHtml(uAgent.text(agent.machineName)) + "</span></td>" +
        "<td>" + uAgent.escapeHtml(uAgent.text(agent.osVersion)) + "</td>" +
        "<td>" + domain + "</td>" +
        '<td class="mono nowrap">' + uAgent.escapeHtml(uAgent.text(agent.dnsName)) + "</td>" +
        '<td class="nowrap">' + heartbeat + "</td>" +
        '<td class="num">' + agent.accountCount + "</td>" +
        "</tr>";
    }).join("");
  };

  uAgent.bindRowLinks = function (tbody) {
    if (tbody.dataset.bound) {
      return;
    }
    tbody.dataset.bound = "1";
    function go(row) {
      if (row && row.dataset.href) {
        window.location.href = row.dataset.href;
      }
    }
    tbody.addEventListener("click", function (event) {
      if (event.target.closest("a, button")) {
        return;
      }
      go(event.target.closest("tr.row-link"));
    });
    tbody.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        go(event.target.closest("tr.row-link"));
      }
    });
  };

  uAgent.me = null;
  uAgent.loadMe = async function () {
    if (!uAgent.me) {
      uAgent.me = await uAgent.api("/api/me");
    }
    return uAgent.me;
  };

  document.addEventListener("DOMContentLoaded", function () {
    initSearch();
  });

  function initSearch() {
    const input = document.getElementById("globalSearchInput");
    const panel = document.getElementById("globalSearchPanel");
    const clearBtn = document.getElementById("globalSearchClear");
    const spin = document.getElementById("globalSearchSpin");
    if (!input || !panel) {
      return;
    }
    document.body.appendChild(panel);
    let timer = null;
    let controller = null;
    let results = [];
    let active = -1;
    let requestId = 0;

    function place() {
      const rect = input.getBoundingClientRect();
      panel.style.top = Math.round(rect.bottom + 6) + "px";
      panel.style.left = Math.round(rect.left) + "px";
      panel.style.width = Math.round(rect.width) + "px";
    }

    function connectionLabel(connection) {
      if (connection === "online") { return uAgent.pill("success", "Online", true); }
      if (connection === "disconnected") { return uAgent.pill("warning", "Disconnected", true); }
      if (connection === "pending") { return uAgent.pill("warning", "Pending", true); }
      if (connection === "inactive") { return uAgent.pill("danger", "Inactive", true); }
      return uAgent.pill("neutral", "Offline", true);
    }

    function hide() {
      panel.hidden = true;
      input.setAttribute("aria-expanded", "false");
      active = -1;
    }

    function show() {
      place();
      panel.hidden = false;
      input.setAttribute("aria-expanded", "true");
    }

    function setBusy(busy) {
      spin.hidden = !busy;
      clearBtn.hidden = busy || !input.value;
    }

    function renderHits(payload, query) {
      const hits = payload.results || [];
      results = hits;
      active = -1;
      if (!hits.length) {
        panel.innerHTML = '<div class="search-empty">No agents match <strong>' + uAgent.escapeHtml(query) + "</strong>.</div>";
        show();
        return;
      }
      const more = payload.total > hits.length
        ? '<div class="search-empty">Showing ' + hits.length + " of " + payload.total + ". Refine the search to narrow it.</div>"
        : "";
      panel.innerHTML = hits.map(function (hit, index) {
        const address = hit.ipAddresses && hit.ipAddresses.length ? hit.ipAddresses[0] : "";
        const detail = [hit.matchedOn, hit.dnsName || address || hit.osVersion].filter(Boolean).join(" · ");
        return '<a class="search-hit" role="option" data-index="' + index + '" href="/agents/' + encodeURIComponent(hit.displayId) + '">' +
          '<span class="id-chip">' + uAgent.escapeHtml(hit.displayId) + "</span>" +
          "<span><span class=\"search-hit-name\">" + uAgent.escapeHtml(hit.machineName || "Unnamed host") + "</span>" +
          '<span class="subtle">' + uAgent.escapeHtml(detail) + "</span></span>" +
          connectionLabel(hit.connection) +
          "</a>";
      }).join("") + more;
      show();
    }

    async function run(query) {
      if (controller) { controller.abort(); }
      controller = new AbortController();
      const mine = ++requestId;
      setBusy(true);
      try {
        const response = await fetch("/api/search?q=" + encodeURIComponent(query), {
          headers: { "Accept": "application/json" },
          credentials: "same-origin",
          cache: "no-store",
          signal: controller.signal
        });
        if (mine !== requestId) { return; }
        if (response.status === 401) {
          window.location.href = "/login?returnUrl=" + encodeURIComponent(window.location.pathname);
          return;
        }
        if (!response.ok) {
          panel.innerHTML = '<div class="search-empty">Search is unavailable right now.</div>';
          show();
          return;
        }
        renderHits(await response.json(), query);
      } catch (error) {
        if (error.name === "AbortError" || mine !== requestId) { return; }
        panel.innerHTML = '<div class="search-empty">Search is unavailable right now.</div>';
        show();
      } finally {
        if (mine === requestId) { setBusy(false); }
      }
    }

    function move(delta) {
      const hits = panel.querySelectorAll(".search-hit");
      if (!hits.length) { return; }
      active = (active + delta + hits.length) % hits.length;
      hits.forEach(function (hit, index) { hit.classList.toggle("active", index === active); });
      hits[active].scrollIntoView({ block: "nearest" });
    }

    input.addEventListener("input", function () {
      clearTimeout(timer);
      const query = input.value.trim();
      clearBtn.hidden = !input.value;
      if (!query) {
        if (controller) { controller.abort(); }
        requestId += 1;
        setBusy(false);
        hide();
        return;
      }
      setBusy(true);
      panel.innerHTML = '<div class="search-empty"><i class="bi bi-arrow-repeat search-spin-icon"></i> Searching…</div>';
      show();
      timer = setTimeout(function () { run(query); }, 180);
    });

    clearBtn.addEventListener("click", function () {
      input.value = "";
      clearBtn.hidden = true;
      hide();
      input.focus();
    });

    input.addEventListener("keydown", function (event) {
      if (event.key === "ArrowDown") { event.preventDefault(); move(1); }
      else if (event.key === "ArrowUp") { event.preventDefault(); move(-1); }
      else if (event.key === "Escape") { hide(); }
      else if (event.key === "Enter" && results.length) {
        event.preventDefault();
        const hit = active >= 0 ? results[active] : results[0];
        window.location.href = "/agents/" + encodeURIComponent(hit.displayId);
      }
    });

    document.addEventListener("click", function (event) {
      if (event.target === input || panel.contains(event.target) || event.target === clearBtn) { return; }
      hide();
    });
    window.addEventListener("resize", function () { if (!panel.hidden) { place(); } });
  }

  // Menus inside a scrolling table would be clipped. Build them with fixed positioning
  // before Bootstrap's own handler toggles the instance.
  document.addEventListener("click", function (event) {
    const toggle = event.target.closest("[data-bs-toggle='dropdown']");
    if (!toggle || !window.bootstrap || window.bootstrap.Dropdown.getInstance(toggle)) {
      return;
    }
    new window.bootstrap.Dropdown(toggle, {
      popperConfig: function (config) {
        return Object.assign({}, config, { strategy: "fixed" });
      }
    });
  }, true);

  window.uAgent = uAgent;
})();
