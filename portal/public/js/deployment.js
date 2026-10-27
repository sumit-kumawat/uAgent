(function () {
  "use strict";
  const U = window.uAgent;
  const $ = function (id) { return document.getElementById(id); };
  const jobId = $("jobRoot").dataset.jobId;
  const base = "/api/deployments/" + encodeURIComponent(jobId);
  const isAdmin = document.body.dataset.role === "Administrator";
  const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  const jobStatus = { Scheduled: ["info", "Scheduled"], Running: ["info", "Running"], Paused: ["warning", "Paused"], Completed: ["success", "Completed"], Cancelled: ["neutral", "Cancelled"] };
  const targetState = {
    Pending: ["neutral", "Pending"], Waiting: ["neutral", "Waiting"], Offline: ["warning", "Offline"], Dispatched: ["info", "Dispatched"],
    Running: ["info", "Running"], Succeeded: ["success", "Succeeded"], Failed: ["danger", "Failed"], Skipped: ["neutral", "Skipped"], Cancelled: ["neutral", "Cancelled"]
  };
  const actionLabels = { upgrade: "Agent upgrade", repair: "Agent repair" };
  const tiles = [
    { key: "total", label: "Total", state: "" },
    { key: "succeeded", label: "Succeeded", state: "Succeeded", tone: "good" },
    { key: "failed", label: "Failed", state: "Failed", tone: "crit" },
    { key: "running", label: "Running", state: "Running", tone: "info" },
    { key: "waiting", label: "Waiting", state: "Waiting" },
    { key: "offline", label: "Offline", state: "Offline", tone: "warn" },
    { key: "pending", label: "Pending", state: "Pending" },
    { key: "skipped", label: "Skipped", state: "Skipped" },
    { key: "cancelled", label: "Cancelled", state: "Cancelled" },
    { key: "rebootRequired", label: "Restart required", tone: "warn" }
  ];

  let job = null;
  let page = 1;
  let waveBase = 1;
  let kindApplied = false;
  let openTarget = null;

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

  function when(value) {
    if (!value) {
      return '<span class="subtle">\u2014</span>';
    }
    return '<span title="' + U.escapeHtml(U.formatDateTime(value)) + '">' + U.escapeHtml(U.relativeTime(value)) + "</span>";
  }

  function set(id, html) {
    const el = $(id);
    if (el.innerHTML !== html) {
      el.innerHTML = html;
    }
  }

  function kv(rows) {
    return rows.map(function (r) { return "<dt>" + U.escapeHtml(r[0]) + "</dt><dd>" + r[1] + "</dd>"; }).join("");
  }

  function isTerminal() {
    return job && (job.status === "Completed" || job.status === "Cancelled");
  }

  function waveLabel(index) {
    return index === null || index === undefined ? "\u2014" : String(num(index) + waveBase);
  }

  function segments(counts, total) {
    const seg = function (cls, value) {
      return value > 0 && total > 0 ? '<span class="' + cls + '" style="width:' + (value * 100 / total).toFixed(2) + '%"></span>' : "";
    };
    return seg("seg-ok", num(counts.succeeded)) + seg("seg-fail", num(counts.failed)) +
      seg("seg-run", num(counts.running)) + seg("seg-skip", num(counts.skipped) + num(counts.cancelled));
  }

  function applyKind() {
    if (kindApplied || job.kind !== "agent") {
      return;
    }
    kindApplied = true;
    const crumb = document.querySelector(".page-crumbs a:last-of-type");
    if (crumb) {
      crumb.textContent = "Agents";
      crumb.href = "/deployment-center/agents";
    }
    $("hdrIcon").className = "bi bi-cloud-arrow-up";
  }

  function renderHeader() {
    document.title = (job.name || "Deployment") + " \u00b7 uAgent";
    $("hdrName").textContent = job.name || "Deployment";
    set("hdrStatus", mapPill(jobStatus, job.status, true));
    set("hdrWhat", job.kind === "agent"
      ? '<i class="bi bi-cloud-arrow-up me-1" aria-hidden="true"></i>' + plain(actionLabels[job.action] || job.action) + (job.packageVersion ? ' <span class="mono">' + U.escapeHtml(job.packageVersion) + "</span>" : "")
      : '<i class="bi bi-box-seam me-1" aria-hidden="true"></i>' + plain(job.packageName) + (job.packageVersion ? ' <span class="mono">' + U.escapeHtml(job.packageVersion) + "</span>" : ""));
    set("hdrCreated", "Created by " + plain(job.createdBy) + " " + when(job.createdUtc));
    let schedule = "";
    if (job.completedUtc) {
      schedule = "Finished " + when(job.completedUtc);
    } else if (job.startedUtc) {
      schedule = "Started " + when(job.startedUtc);
    } else if (job.startAt) {
      schedule = "Starts " + U.escapeHtml(U.formatDateTime(job.startAt));
    }
    set("hdrSchedule", schedule);
  }

  function renderBanners() {
    const items = [];
    const reason = job.statusReason ? " " + plain(job.statusReason) : "";
    if (job.status === "Paused") {
      items.push('<div class="banner banner-warning"><i class="bi bi-pause-circle"></i><div><strong>Paused.</strong> No new installs start until the deployment is resumed.' + reason + "</div></div>");
    } else if (job.status === "Scheduled") {
      items.push('<div class="banner banner-info"><i class="bi bi-calendar-event"></i><div>Scheduled to start ' + U.escapeHtml(U.formatDateTime(job.startAt)) + "." + reason + "</div></div>");
    } else if (job.status === "Cancelled") {
      items.push('<div class="banner banner-warning"><i class="bi bi-x-octagon"></i><div><strong>Cancelled.</strong>' + reason + "</div></div>");
    } else if (reason) {
      items.push('<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>' + reason.trim() + "</div></div>");
    }
    const w = job.options && job.options.maintenanceWindow;
    if (w && w.enabled && !isTerminal()) {
      items.push('<div class="banner banner-info"><i class="bi bi-clock"></i><div>Installs run only during the maintenance window: ' +
        U.escapeHtml((w.days || []).map(function (d) { return DAYS[d]; }).join(", ") + " " + (w.start || "") + "\u2013" + (w.end || "")) + " (agent local time).</div></div>");
    }
    set("banners", items.join(""));
  }

  function renderProgress() {
    const c = job.counts || {};
    const total = num(c.total);
    const done = num(c.succeeded) + num(c.failed) + num(c.skipped) + num(c.cancelled);
    const pct = total ? Math.floor(done * 100 / total) : 0;
    $("pctText").textContent = pct + "%";
    $("pctDetail").textContent = done + " of " + total + " systems finished";
    set("bigBar", segments(c, total));
    $("bigBar").setAttribute("aria-label", pct + "% finished");
    $("waveMeta").textContent = num(job.waveCount) ? "Wave " + waveLabel(job.currentWave) + " of " + num(job.waveCount) : "";
    const active = $("stateFilter").value;
    set("tiles", tiles.map(function (t) {
      const inner = '<div class="label">' + U.escapeHtml(t.label) + '</div><div class="value">' + num(c[t.key]) + "</div>";
      const cls = "tile" + (t.tone ? " tone-" + t.tone : "");
      if (t.state === undefined) {
        return '<div class="' + cls + '">' + inner + "</div>";
      }
      return '<button type="button" class="' + cls + (t.state === active ? " active" : "") + '" data-state="' + t.state + '" aria-pressed="' + (t.state === active) + '">' + inner + "</button>";
    }).join(""));
  }

  function renderControls() {
    const wrap = $("controls");
    wrap.hidden = !isAdmin;
    if (!isAdmin) {
      return;
    }
    const s = job.status;
    const lastWave = num(job.currentWave) + waveBase >= num(job.waveCount);
    const show = {
      pause: s === "Running" || s === "Scheduled",
      resume: s === "Paused",
      advance: (s === "Running" || s === "Paused") && num(job.waveCount) > 1 && !lastWave,
      retry: num(job.counts && job.counts.failed) > 0 && s !== "Cancelled",
      cancel: !isTerminal()
    };
    wrap.querySelectorAll("[data-control]").forEach(function (btn) { btn.hidden = !show[btn.dataset.control]; });
  }

  function renderWaves() {
    const waves = job.waves || [];
    $("cntWaves").textContent = waves.length;
    set("waveBody", waves.length ? waves.map(function (w) {
      const finished = num(w.succeeded) + num(w.failed) + num(w.skipped);
      let status = U.pill("neutral", "Not started");
      if (num(w.total) > 0 && finished >= num(w.total)) {
        status = U.pill("success", "Complete");
      } else if (w.active === true || num(w.active) > 0) {
        status = U.pill("info", "Current", true);
      }
      const label = w.index === 0 && waveBase === 1 && num(job.options && job.options.pilotCount) > 0 ? "Pilot" : "Wave " + waveLabel(w.index);
      return "<tr><td><span class=\"cell-primary\">" + U.escapeHtml(label) + "</span></td>" +
        "<td>" + status + "</td>" +
        '<td class="num">' + num(w.total) + "</td>" +
        '<td class="num">' + num(w.succeeded) + "</td>" +
        '<td class="num">' + num(w.failed) + "</td>" +
        '<td class="num">' + num(w.skipped) + "</td>" +
        '<td class="progress-cell"><div class="seg-bar">' + segments({ succeeded: w.succeeded, failed: w.failed, skipped: w.skipped }, num(w.total)) + "</div></td></tr>";
    }).join("") : '<tr><td colspan="7" class="empty">Waves are created when the deployment starts.</td></tr>');
  }

  function renderTimeline() {
    const events = (job.timeline || []).slice().sort(function (a, b) { return new Date(b.utc) - new Date(a.utc); });
    set("timeline", events.length ? events.map(function (e) {
      return '<li><span class="when">' + U.escapeHtml(U.formatDateTime(e.utc)) + '</span><span class="what"><strong>' + plain(e.event) + "</strong>" +
        (e.user ? ' <span class="subtle">by ' + U.escapeHtml(e.user) + "</span>" : "") +
        (e.detail ? '<div class="subtle">' + U.escapeHtml(e.detail) + "</div>" : "") + "</span></li>";
    }).join("") : '<li><span class="what subtle">No events yet.</span></li>');
  }

  function renderOptions() {
    const o = job.options || {};
    const w = o.maintenanceWindow || {};
    set("optionsKv", kv([
      ["Pilot systems", plain(o.pilotCount)],
      ["Wave size", plain(o.waveSize === 0 ? "All remaining at once" : o.waveSize)],
      ["Wave advance", plain(o.autoAdvance ? "Automatic after " + num(o.waveDelayMinutes) + " min" : "Manual")],
      ["Concurrency", plain(num(o.maxConcurrent) + " at a time, " + num(o.perSiteConcurrent) + " per site")],
      ["Failure threshold", plain(num(o.failureThresholdPercent) + "% after " + num(o.failureMinSample) + " results, then " + (o.onThreshold === "cancel" ? "cancel" : "pause"))],
      ["Retries", plain(num(o.maxAttempts) + " attempts, " + num(o.retryDelayMinutes) + " min apart")],
      ["Start", plain(o.startAt ? U.formatDateTime(o.startAt) : "Immediately")],
      ["Maintenance window", plain(w.enabled ? (w.days || []).map(function (d) { return DAYS[d]; }).join(", ") + " " + w.start + "\u2013" + w.end : "Any time")],
      ["Offline deadline", plain(o.offlineDeadlineHours ? o.offlineDeadlineHours + " hours" : "")],
      ["Reinstall when detected", plain(o.force ? "Yes" : "No")]
    ]));
  }

  function renderJob() {
    const waves = job.waves || [];
    waveBase = waves.length ? (waves.some(function (w) { return w.index === 0; }) ? 1 : 0) : (job.currentWave === 0 ? 1 : 0);
    applyKind();
    renderHeader();
    renderBanners();
    renderProgress();
    renderControls();
    renderWaves();
    renderTimeline();
    renderOptions();
  }

  // ---------- Systems ----------
  function stageHtml(t) {
    if (!t.stage) {
      return '<span class="subtle">\u2014</span>';
    }
    const pct = t.percent === null || t.percent === undefined ? null : Math.max(0, Math.min(100, num(t.percent)));
    return U.escapeHtml(t.stage) + (pct !== null ? " " + pct + "%" : "") +
      (pct !== null && (t.state === "Running" || t.state === "Dispatched") ? '<div class="seg-bar mt-1"><span class="seg-run" style="width:' + pct + '%"></span></div>' : "");
  }

  function targetRow(t) {
    const retry = t.nextAttemptUtc && t.state !== "Succeeded" ? '<div class="subtle">Next attempt ' + U.escapeHtml(U.formatDateTime(t.nextAttemptUtc)) + "</div>" : "";
    return '<tr class="row-link" tabindex="0" data-agent="' + U.escapeHtml(t.agentId) + '">' +
      '<td class="nowrap"><span class="cell-primary">' + plain(t.machineName) + "</span> " +
      (t.displayId ? '<a class="id-chip" href="/agents/' + encodeURIComponent(t.displayId) + '">' + U.escapeHtml(t.displayId) + "</a>" : "") + "</td>" +
      "<td>" + plain(t.site) + "</td>" +
      '<td class="num">' + U.escapeHtml(waveLabel(t.wave)) + "</td>" +
      '<td class="nowrap">' + mapPill(targetState, t.state, true) + (t.rebootRequired ? ' <span class="tag">Restart required</span>' : "") + "</td>" +
      '<td class="nowrap">' + stageHtml(t) + "</td>" +
      '<td class="num">' + num(t.attempts) + "</td>" +
      '<td class="num mono">' + plain(t.exitCode) + "</td>" +
      '<td><span class="truncate d-inline-block" title="' + U.escapeHtml(t.message || "") + '">' + plain(t.message) + "</span>" + retry + "</td>" +
      '<td class="nowrap">' + when(t.updatedUtc) + "</td></tr>";
  }

  function renderPager(total, pageSize) {
    const pager = $("targetPager");
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
    set("pageButtons", btns.join(""));
  }

  async function loadTargets() {
    const pageSize = parseInt($("pageSize").value, 10) || 50;
    const params = new URLSearchParams({ state: $("stateFilter").value, q: $("targetSearch").value.trim(), page: String(page), pageSize: String(pageSize) });
    const data = await U.api(base + "/targets?" + params.toString());
    const total = num(data.total);
    const pageCount = Math.max(1, Math.ceil(total / pageSize));
    if (page > pageCount) {
      page = pageCount;
      return loadTargets();
    }
    const rows = data.rows || [];
    $("cntSystems").textContent = num(job && job.counts && job.counts.total) || total;
    $("targetCount").textContent = total + (total === 1 ? " system" : " systems");
    set("targetBody", rows.length ? rows.map(targetRow).join("") : '<tr><td colspan="9" class="empty">No systems match.</td></tr>');
    renderPager(total, pageSize);
  }

  // ---------- Target details ----------
  async function showTarget(agentId) {
    try {
      const data = await U.api(base + "/targets/" + encodeURIComponent(agentId));
      const t = data.target;
      openTarget = t;
      $("targetTitle").textContent = t.machineName || t.displayId || "System";
      $("targetSub").innerHTML = mapPill(targetState, t.state, true) + (t.displayId ? '<a class="id-chip" href="/agents/' + encodeURIComponent(t.displayId) + '">' + U.escapeHtml(t.displayId) + "</a>" : "");
      $("targetKv").innerHTML = kv([
        ["Site", plain(t.site)],
        ["Wave", U.escapeHtml(waveLabel(t.wave))],
        ["State", mapPill(targetState, t.state, true)],
        ["Stage", stageHtml(t)],
        ["Outcome", plain(t.outcome)],
        ["Exit code", '<span class="mono">' + plain(t.exitCode) + "</span>"],
        ["Restart required", plain(t.rebootRequired ? "Yes" : "No")],
        ["Attempts", String(num(t.attempts))],
        ["Next attempt", plain(t.nextAttemptUtc ? U.formatDateTime(t.nextAttemptUtc) : "")],
        ["Updated", plain(U.formatDateTime(t.updatedUtc))],
        ["Message", plain(t.message)]
      ]);
      const history = (t.history || []).slice().sort(function (a, b) { return new Date(b.utc) - new Date(a.utc); });
      $("targetHistory").innerHTML = history.length ? history.map(function (h) {
        return '<li><span class="when">' + U.escapeHtml(U.formatDateTime(h.utc)) + '</span><span class="what">' + mapPill(targetState, h.state) +
          (h.message ? " " + U.escapeHtml(h.message) : "") + "</span></li>";
      }).join("") : '<li><span class="what subtle">No history yet.</span></li>';
      $("targetLog").textContent = t.log || "No log was returned for this system.";
      $("targetRetry").hidden = !(isAdmin && t.state === "Failed" && job && job.status !== "Cancelled");
      bootstrap.Modal.getOrCreateInstance($("targetModal")).show();
    } catch (error) {
      U.notify(error.message || "The system details could not be loaded.", "danger");
    }
  }

  // ---------- Controls ----------
  const controlDefs = {
    pause: { label: "Pause deployment", description: "No new installs start. Installs already running finish and report their results." },
    resume: { label: "Resume deployment", description: "Installs continue with the current wave." },
    advance: { label: "Advance wave", description: "Starts the next wave now instead of waiting for the delay or for manual approval." },
    cancel: { label: "Cancel deployment", description: "Systems that have not started are cancelled. Installs already running finish. This cannot be undone.", sensitive: true },
    retry: { label: "Retry failed systems", description: "Failed systems are queued again, subject to the deployment's concurrency limits." }
  };

  function runControl(name) {
    const def = controlDefs[name];
    U.runAction({
      machineName: job.name,
      control: def,
      submit: async function (values) {
        if (name === "retry") {
          const data = await U.api(base + "/retry", { method: "POST", body: { scope: "failed" } });
          U.notify(num(data && data.retried) + " failed systems queued again.", "success");
        } else {
          await U.api(base + "/" + name, { method: "POST", body: { reason: values.reason } });
          U.notify(def.label.replace(" deployment", "") + " requested.", "success");
        }
        live.now();
      }
    });
  }

  function retryTarget() {
    const t = openTarget;
    U.runAction({
      machineName: t.machineName || t.displayId,
      control: { label: "Retry system", description: "Queues this system again for the deployment." },
      submit: async function () {
        await U.api(base + "/retry", { method: "POST", body: { agentIds: [t.agentId] } });
        bootstrap.Modal.getOrCreateInstance($("targetModal")).hide();
        U.notify("System queued again.", "success");
        live.now();
      }
    });
  }

  // ---------- Refresh loop ----------
  function setLive(text, paused) {
    $("liveText").textContent = text;
    $("liveIndicator").classList.toggle("paused", paused);
  }

  async function refresh() {
    try {
      const data = await U.api(base);
      job = data.job;
      renderJob();
      await loadTargets();
      setLive(isTerminal() ? "Finished" : "Live", isTerminal());
    } catch (error) {
      if (error.status === 404) {
        set("banners", '<div class="banner banner-danger"><i class="bi bi-exclamation-circle"></i><div>This deployment does not exist or was removed.</div></div>');
        setLive("Unavailable", true);
        return;
      }
      setLive("Reconnecting\u2026", true);
    }
  }

  function reloadTargets() {
    loadTargets().catch(function (error) { U.notify(error.message || "Systems could not be loaded.", "danger"); });
  }

  const live = U.liveRefresh(refresh, {
    types: ["deployment"],
    fallbackMs: 5000,
    match: function (e) { return e.type === "deployment" && e.jobId === jobId; }
  });

  $("refreshBtn").addEventListener("click", function () { live.now(); });
  $("controls").addEventListener("click", function (event) {
    const btn = event.target.closest("[data-control]");
    if (btn && job) {
      runControl(btn.dataset.control);
    }
  });
  $("tiles").addEventListener("click", function (event) {
    const tile = event.target.closest("button[data-state]");
    if (tile) {
      $("stateFilter").value = tile.dataset.state;
      page = 1;
      renderProgress();
      reloadTargets();
    }
  });
  $("stateFilter").addEventListener("change", function () { page = 1; renderProgress(); reloadTargets(); });
  $("targetSearch").addEventListener("input", U.debounce(function () { page = 1; reloadTargets(); }, 250));
  $("pageSize").addEventListener("change", function () { page = 1; reloadTargets(); });
  $("pageButtons").addEventListener("click", function (event) {
    const btn = event.target.closest("button[data-page]");
    if (btn && !btn.disabled) {
      page = parseInt(btn.dataset.page, 10) || 1;
      reloadTargets();
    }
  });
  $("targetBody").addEventListener("click", function (event) {
    if (event.target.closest("a, button")) {
      return;
    }
    const row = event.target.closest("tr[data-agent]");
    if (row) {
      showTarget(row.dataset.agent);
    }
  });
  $("targetBody").addEventListener("keydown", function (event) {
    const row = event.target.closest("tr[data-agent]");
    if (event.key === "Enter" && row && event.target === row) {
      showTarget(row.dataset.agent);
    }
  });
  $("targetRetry").addEventListener("click", retryTarget);

  refresh();
})();
