// The one control panel for an agent and its accounts. Every page opens this same panel; the server decides
// which actions apply to the current state and role, and the panel refreshes itself from live events.
(function () {
  "use strict";
  const U = window.uAgent;

  let el = null;
  let offcanvas = null;
  let ctx = null;
  let data = null;
  let loading = false;
  let reloadQueued = false;
  let unsubscribe = function () {};

  const passwordStates = {
    expired: ["danger", "Password expired"],
    warning: ["warning", "Password expires soon"],
    ok: ["success", "Password valid"],
    never: ["neutral", "Password never expires"],
    unreported: ["neutral", "Password expiry not reported"],
    disabled: ["neutral", "Password not evaluated (disabled)"]
  };

  function ensure() {
    if (el) {
      return;
    }
    el = document.createElement("div");
    el.className = "offcanvas offcanvas-end cp";
    el.id = "ua-control-panel";
    el.tabIndex = -1;
    el.setAttribute("aria-labelledby", "ua-cp-title");
    el.innerHTML =
      '<div class="offcanvas-header">' +
      '  <div class="cp-title">' +
      '    <span class="entity-icon"><i class="bi bi-sliders" aria-hidden="true"></i></span>' +
      '    <div><h2 class="offcanvas-title" id="ua-cp-title">Control panel</h2><div class="cp-sub" data-role="sub"></div></div>' +
      "  </div>" +
      '  <button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>' +
      "</div>" +
      '<div class="offcanvas-body" data-role="body" aria-live="polite"></div>';
    document.body.appendChild(el);
    offcanvas = new bootstrap.Offcanvas(el);
    el.addEventListener("hidden.bs.offcanvas", function () {
      unsubscribe();
      unsubscribe = function () {};
      const done = ctx && ctx.onClose;
      ctx = null;
      data = null;
      if (typeof done === "function") {
        done();
      }
    });
    el.addEventListener("click", onClick);
    el.addEventListener("change", function (event) {
      if (event.target.matches("[data-role='account-select']")) {
        const option = event.target.selectedOptions[0];
        ctx.account = option ? option.value : "";
        ctx.source = option ? option.getAttribute("data-source") || "" : "";
        load();
      }
    });
  }

  function pill(tone, label) {
    return U.pill(tone, label, true);
  }

  function age(ms) {
    if (ms === null || ms === undefined) {
      return "never";
    }
    const s = Math.round(ms / 1000);
    if (s < 60) { return "just now"; }
    if (s < 3600) { return Math.round(s / 60) + " min ago"; }
    if (s < 86400) { return Math.round(s / 3600) + " h ago"; }
    return Math.round(s / 86400) + " d ago";
  }

  function actionRow(action, attrs) {
    const available = action.state === "available";
    const running = action.state === "running";
    const hint = available ? action.description : action.reason;
    const right = running
      ? '<span class="cp-status"><span class="spinner-border spinner-border-sm" aria-hidden="true"></span> Running</span>'
      : available ? '<i class="bi bi-chevron-right cp-go" aria-hidden="true"></i>'
        : '<span class="cp-status">' + U.escapeHtml({ offline: "Offline", unsupported: "Not supported", blocked: "Unavailable" }[action.state] || "") + "</span>";
    return '<button type="button" class="cp-action' + (action.sensitive || action.danger ? " is-danger" : "") + '"' + attrs +
      (available ? "" : ' disabled aria-disabled="true"') + ">" +
      '<i class="bi ' + U.escapeHtml(action.icon || "bi-lightning") + ' cp-icon" aria-hidden="true"></i>' +
      '<span class="cp-text"><span class="cp-label">' + U.escapeHtml(action.label) + "</span>" +
      '<span class="cp-hint">' + U.escapeHtml(hint || "") + "</span></span>" + right + "</button>";
  }

  function removalBanner(removal) {
    const tone = { Queued: "info", Uninstalling: "info", Failed: "danger", Unverified: "warning" }[removal.state] || "info";
    const title = {
      Queued: removal.commandStatus === "Delivered" ? "Uninstall delivered" : "Removal pending",
      Uninstalling: "Uninstalling",
      Failed: "Removal failed",
      Unverified: "Removal not verified"
    }[removal.state] || removal.state;
    const icon = removal.state === "Failed" ? "bi-x-octagon" : removal.state === "Unverified" ? "bi-question-circle" : "bi-hourglass-split";
    return '<div class="banner banner-' + tone + '"><i class="bi ' + icon + '" aria-hidden="true"></i><div><strong>' + U.escapeHtml(title) + ".</strong> " +
      U.escapeHtml(removal.detail) + '<div class="subtle small mt-1">Requested by ' + U.escapeHtml(removal.requestedBy) + " " +
      U.escapeHtml(U.relativeTime(removal.requestedUtc).toLowerCase()) + (removal.reason ? " \u00b7 " + U.escapeHtml(removal.reason) : "") + "</div></div></div>";
  }

  function accountSection(d) {
    const options = ['<option value="">Choose an account\u2026</option>'].concat(d.accounts.map(function (a) {
      const selected = d.account && a.samAccountName.toLowerCase() === d.account.samAccountName.toLowerCase() && a.source === d.account.source;
      const flags = (a.enabled ? "" : " \u00b7 disabled") + (a.lockedOut ? " \u00b7 locked" : "");
      return '<option value="' + U.escapeHtml(a.samAccountName) + '" data-source="' + U.escapeHtml(a.source) + '"' + (selected ? " selected" : "") + ">" +
        U.escapeHtml(a.samAccountName + " (" + a.source.toLowerCase() + ")" + flags) + "</option>";
    }));
    let html = '<section class="cp-section"><h3>Account</h3>';
    if (!d.accounts.length) {
      return html + '<p class="subtle small mb-0">' + (d.agent.inventoryUtc ? "The agent reported no accounts." : "No account inventory has been received yet.") + "</p></section>";
    }
    html += '<label class="visually-hidden" for="ua-cp-account">Account</label><select class="form-select form-select-sm mb-2" id="ua-cp-account" data-role="account-select">' + options.join("") + "</select>";
    if (d.accountMissing) {
      html += '<div class="banner banner-warning"><i class="bi bi-exclamation-triangle" aria-hidden="true"></i><div>This account is no longer in the agent\'s inventory.</div></div>';
    }
    const a = d.account;
    if (!a) {
      return html + "</section>";
    }
    const pw = passwordStates[a.passwordState] || passwordStates.unreported;
    html += '<div class="cp-state">' +
      pill(a.enabled ? "success" : "danger", a.enabled ? "Enabled" : "Disabled") +
      pill(a.lockedOut ? "danger" : "neutral", a.lockedOut ? "Locked out" : "Not locked") +
      pill(pw[0], pw[1]) +
      (a.accountExpired ? pill("danger", "Account expired") : "") +
      pill("neutral", a.userCannotChangePassword === true ? "Cannot change password" : a.userCannotChangePassword === false ? "Can change password" : "Change-password setting not reported") +
      "</div>";
    html += '<div class="cp-meta' + (a.stale ? " is-stale" : "") + '"><i class="bi ' + (a.stale ? "bi-clock-history" : "bi-check2-circle") + '" aria-hidden="true"></i>' +
      (a.verifiedUtc && a.dataAgeMs !== null && a.dataAgeMs < 60000 ? "Verified on the computer " : "Account data from ") + U.escapeHtml(age(a.dataAgeMs)) +
      (a.stale ? ". It may be out of date; the agent checks the real state before changing anything." : ".") +
      (d.system.some(function (s) { return s.type === "RefreshInventory" && s.state === "available"; })
        ? ' <button type="button" class="btn btn-link btn-sm p-0 align-baseline" data-run="RefreshInventory" data-scope="system">Refresh now</button>' : "") +
      "</div>";
    if (!d.accountActions.length) {
      return html + '<p class="subtle small mb-0">Your role cannot change this account.</p></section>';
    }
    html += '<div class="cp-list">' + d.accountActions.map(function (action, i) {
      return actionRow(action, ' data-run="' + U.escapeHtml(action.type) + '" data-scope="account" data-index="' + i + '"');
    }).join("") + "</div></section>";
    return html;
  }

  function render() {
    const d = data;
    const agent = d.agent;
    el.querySelector("[data-role='sub']").innerHTML =
      U.escapeHtml(agent.machineName || agent.displayId) + ' <span class="id-chip">' + U.escapeHtml(agent.displayId) + "</span> " + U.connectionPill(agent.online);

    const banners = [];
    if (agent.removal) {
      banners.push(removalBanner(agent.removal));
    } else if (agent.status === "PendingApproval") {
      banners.push('<div class="banner banner-warning"><i class="bi bi-hourglass-split" aria-hidden="true"></i><div>Awaiting approval. Actions are held until an administrator approves this agent.</div></div>');
    } else if (agent.status === "Revoked") {
      banners.push('<div class="banner banner-danger"><i class="bi bi-slash-circle" aria-hidden="true"></i><div>The agent\'s credential is revoked.</div></div>');
    } else if (!agent.online) {
      banners.push('<div class="banner banner-warning"><i class="bi bi-wifi-off" aria-hidden="true"></i><div>The agent is offline' +
        (agent.lastSeenUtc ? " (last seen " + U.escapeHtml(U.relativeTime(agent.lastSeenUtc).toLowerCase()) + ")" : "") + ". Actions are available again when it reconnects.</div></div>");
    }

    let html = banners.join("");
    html += accountSection(d);

    if (d.system.length) {
      html += '<section class="cp-section"><h3>Agent</h3><div class="cp-list">' + d.system.map(function (action, i) {
        return actionRow(action, ' data-run="' + U.escapeHtml(action.type) + '" data-scope="system" data-index="' + i + '"');
      }).join("") + "</div></section>";
    }

    if (d.admin.length) {
      html += '<section class="cp-section"><h3>Administration</h3><div class="cp-list">' + d.admin.map(function (item) {
        return actionRow({ label: item.label, description: item.description, icon: item.icon, danger: item.danger, state: "available" }, ' data-admin="' + U.escapeHtml(item.action) + '"');
      }).join("") + "</div></section>";
    }

    if (d.active.length) {
      html += '<section class="cp-section"><h3>In progress</h3><ul class="cp-active">' + d.active.map(function (c) {
        return "<li>" + U.statusPill(c.status) + " <span>" + U.escapeHtml(c.label) + (c.samAccountName ? ' <span class="subtle">\u00b7 ' + U.escapeHtml(c.samAccountName) + "</span>" : "") +
          '</span><span class="subtle ms-auto">' + U.escapeHtml(U.relativeTime(c.createdUtc)) + "</span></li>";
      }).join("") + "</ul></section>";
    }

    html += '<p class="subtle small mb-0 mt-3">Every action is authorised by role, recorded in the Audit Log, and its result is shown on the agent\'s Action history.</p>';
    const body = el.querySelector("[data-role='body']");
    const focused = document.activeElement && el.contains(document.activeElement) ? document.activeElement.getAttribute("data-run") || document.activeElement.getAttribute("data-admin") : null;
    body.innerHTML = html;
    if (focused) {
      const again = body.querySelector('[data-run="' + focused + '"], [data-admin="' + focused + '"]');
      if (again && !again.disabled) { again.focus(); }
    }
  }

  async function load() {
    if (!ctx) {
      return;
    }
    if (loading) {
      reloadQueued = true;
      return;
    }
    loading = true;
    const params = new URLSearchParams();
    if (ctx.account) { params.set("account", ctx.account); }
    if (ctx.source) { params.set("source", ctx.source); }
    try {
      data = await U.api("/api/agents/" + encodeURIComponent(ctx.agentKey) + "/panel?" + params.toString());
      if (ctx) {
        render();
      }
    } catch (error) {
      if (error.status === 404) {
        removed();
      } else if (ctx) {
        el.querySelector("[data-role='body']").insertAdjacentHTML("afterbegin",
          '<div class="banner banner-danger"><i class="bi bi-exclamation-octagon" aria-hidden="true"></i><div>' + U.escapeHtml(error.message || "Could not load the control panel.") + "</div></div>");
      }
    } finally {
      loading = false;
      if (reloadQueued) {
        reloadQueued = false;
        load();
      }
    }
  }

  function removed() {
    if (!ctx) {
      return;
    }
    const done = ctx.onRemoved;
    el.querySelector("[data-role='body']").innerHTML =
      '<div class="banner banner-success"><i class="bi bi-check-circle" aria-hidden="true"></i><div>The agent was removed from the portal. Its audit history is kept in the Audit Log.</div></div>';
    unsubscribe();
    unsubscribe = function () {};
    if (typeof done === "function") {
      done();
    }
  }

  function runAction(action) {
    U.runAction({
      agentKey: ctx.agentKey,
      machineName: data.agent.machineName || data.agent.displayId,
      control: action,
      samAccountName: action.scope === "account" ? data.account.samAccountName : "",
      accountSource: action.scope === "account" ? data.account.source : null,
      onQueued: function () { load(); },
      onUpdate: function () { load(); },
      onError: function () { load(); }
    });
  }

  function removeAgent(mode) {
    const record = mode === "record";
    U.runAction({
      agentKey: ctx.agentKey,
      machineName: data.agent.machineName || data.agent.displayId,
      mode: mode,
      control: {
        label: record ? "Remove record" : "Remove agent",
        description: record
          ? "Removes this agent from the portal without uninstalling it. If the agent is still installed it registers again at its next check-in."
          : "Sends an authenticated uninstall to the computer. The uninstaller removes the uAgent service, program files, credentials and firewall rule, verifies they are gone, and reports back. The agent stays listed, marked as pending, until removal is verified. If it is offline, the uninstall runs when it reconnects.",
        sensitive: true,
        reauth: true
      },
      submit: async function (values) {
        const result = await U.api("/api/agents/" + encodeURIComponent(ctx.agentKey), {
          method: "DELETE",
          body: { confirmed: true, mode: mode, currentPassword: values.currentPassword, reason: values.reason }
        });
        if (result && result.removed) {
          U.notify("Agent record removed.", "success");
          removed();
        } else {
          U.notify(data.agent.online ? "Uninstall sent. The agent is removed once the computer confirms." : "Removal queued. The uninstall runs when the agent reconnects.", "info");
          load();
        }
      }
    });
  }

  async function admin(action) {
    if (action === "remove" || action === "remove-record") {
      removeAgent(action === "remove" ? "uninstall" : "record");
      return;
    }
    const prompts = {
      revoke: "Revoke this agent's credential? It stops receiving actions until it is reinstated or reinstalled.",
      "rotate-key": "Rotate this agent's credential? The new key is delivered at its next check-in.",
      "cancel-removal": data.agent.removal && data.agent.removal.state === "Queued" ? "Cancel the pending removal and keep this agent?" : "Clear the removal status and keep this agent?"
    };
    if (prompts[action] && !window.confirm(prompts[action])) {
      return;
    }
    const path = action === "cancel-removal" ? "/removal/cancel" : "/" + action;
    try {
      await U.api("/api/agents/" + encodeURIComponent(ctx.agentKey) + path, { method: "POST" });
      U.notify({ approve: "Agent approved.", revoke: "Agent revoked.", "rotate-key": "Credential rotation queued.", "cancel-removal": "Removal cancelled." }[action], "success");
    } catch (error) {
      U.notify(error.message || "The action failed.", "danger");
    }
    load();
  }

  function onClick(event) {
    const adminBtn = event.target.closest("[data-admin]");
    if (adminBtn && !adminBtn.disabled) {
      admin(adminBtn.getAttribute("data-admin"));
      return;
    }
    const btn = event.target.closest("[data-run]");
    if (!btn || btn.disabled || !data) {
      return;
    }
    const scope = btn.getAttribute("data-scope");
    const list = scope === "account" ? data.accountActions : data.system;
    const index = btn.hasAttribute("data-index") ? Number(btn.getAttribute("data-index")) : list.findIndex(function (a) { return a.type === btn.getAttribute("data-run"); });
    const action = list[index];
    if (action && action.state === "available") {
      runAction(Object.assign({}, action, { scope: scope }));
    }
  }

  // opts: { agentKey, account, source, onClose, onRemoved }
  function open(opts) {
    ensure();
    unsubscribe();
    ctx = Object.assign({}, opts);
    data = null;
    el.querySelector("[data-role='sub']").textContent = "";
    el.querySelector("[data-role='body']").innerHTML = '<p class="subtle small">Loading\u2026</p>';
    let timer = null;
    unsubscribe = U.onChange(function (batch) {
      if (!ctx || !data) {
        return;
      }
      const id = data.agent.agentId;
      const relevant = batch.some(function (e) {
        return e.bulk ? ["agent", "accounts", "command", "removed"].indexOf(e.type) >= 0
          : e.agentId === id && ["agent", "accounts", "command", "removed"].indexOf(e.type) >= 0;
      });
      if (batch.some(function (e) { return e.type === "removed" && e.agentId === id; })) {
        removed();
        return;
      }
      if (relevant) {
        clearTimeout(timer);
        timer = setTimeout(load, 150);
      }
    });
    offcanvas.show();
    load();
  }

  U.controlPanel = { open: open, reload: load };
})();
