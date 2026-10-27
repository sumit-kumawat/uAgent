(function () {
  "use strict";
  const U = window.uAgent;
  const $ = function (id) { return document.getElementById(id); };
  const isAdmin = document.body.dataset.role === "Administrator";

  const jobStatus = { Scheduled: ["info", "Scheduled"], Running: ["info", "Running"], Paused: ["warning", "Paused"], Completed: ["success", "Completed"], Cancelled: ["neutral", "Cancelled"] };
  const actionLabels = { upgrade: "Agent upgrade", repair: "Agent repair" };
  const DAY_MS = 24 * 60 * 60 * 1000;

  let jobs = [];

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

  function when(value) {
    if (!value) {
      return '<span class="subtle">\u2014</span>';
    }
    return '<span title="' + U.escapeHtml(U.formatDateTime(value)) + '">' + U.escapeHtml(U.relativeTime(value)) + "</span>";
  }

  function emptyRow(colspan, message) {
    return '<tr><td colspan="' + colspan + '" class="empty">' + U.escapeHtml(message) + "</td></tr>";
  }

  function progressHtml(counts) {
    const c = counts || {};
    const total = num(c.total);
    const ok = num(c.succeeded);
    const failed = num(c.failed);
    const running = num(c.running);
    const pending = num(c.pending) + num(c.waiting) + num(c.offline);
    const seg = function (cls, value) {
      return value > 0 && total > 0 ? '<span class="' + cls + '" style="width:' + (value * 100 / total).toFixed(2) + '%"></span>' : "";
    };
    return '<div class="seg-bar" role="img" aria-label="' + ok + " of " + total + ' succeeded">' +
      seg("seg-ok", ok) + seg("seg-fail", failed) + seg("seg-run", running) + seg("seg-skip", num(c.skipped) + num(c.cancelled)) + "</div>" +
      '<span class="seg-caption">' + ok + " succeeded \u00b7 " + failed + " failed \u00b7 " + running + " running \u00b7 " + pending + " pending</span>";
  }

  function typeLabel(j) {
    if (j.kind === "agent") {
      return plain(actionLabels[j.action] || j.action || "Agent");
    }
    return plain(j.packageName) + (j.packageVersion ? ' <span class="subtle mono">' + U.escapeHtml(j.packageVersion) + "</span>" : "");
  }

  function jobRow(j) {
    const c = j.counts || {};
    const pending = num(c.pending) + num(c.waiting) + num(c.offline) + num(c.running);
    return '<tr class="row-link" tabindex="0" data-href="/deployment-center/jobs/' + encodeURIComponent(j.id) + '">' +
      '<td><span class="cell-primary">' + plain(j.name) + "</span></td>" +
      "<td>" + (j.kind === "agent" ? '<i class="bi bi-pc-display-horizontal me-1" aria-hidden="true"></i>' : '<i class="bi bi-box-seam me-1" aria-hidden="true"></i>') + typeLabel(j) + "</td>" +
      '<td title="' + U.escapeHtml(j.statusReason || "") + '">' + mapPill(jobStatus, j.status, true) + "</td>" +
      '<td class="progress-cell">' + progressHtml(c) + "</td>" +
      '<td class="num">' + num(c.succeeded) + "</td>" +
      '<td class="num">' + num(c.failed) + "</td>" +
      '<td class="num">' + pending + "</td>" +
      "<td>" + plain(j.createdBy) + "</td>" +
      '<td class="nowrap">' + when(j.createdUtc) + "</td></tr>";
  }

  function renderStats() {
    const now = Date.now();
    let active = 0;
    let inProgress = 0;
    let succeeded = 0;
    let failed = 0;
    let scheduled = 0;
    jobs.forEach(function (j) {
      const c = j.counts || {};
      if (j.status === "Running" || j.status === "Paused") {
        active += 1;
        inProgress += num(c.running);
      }
      if (j.status === "Scheduled") {
        scheduled += 1;
      }
      const started = j.startedUtc ? Date.parse(j.startedUtc) : (j.createdUtc ? Date.parse(j.createdUtc) : 0);
      if (started && now - started <= DAY_MS) {
        succeeded += num(c.succeeded);
        failed += num(c.failed);
      }
    });
    $("statActive").textContent = active;
    $("statProgress").textContent = inProgress;
    $("statSucceeded").textContent = succeeded;
    $("statFailed").textContent = failed;
    $("statScheduled").textContent = scheduled;
  }

  function renderJobs() {
    $("jobCount").textContent = jobs.length + (jobs.length === 1 ? " deployment" : " deployments");
    $("jobBody").innerHTML = jobs.length ? jobs.map(jobRow).join("") : emptyRow(9, "No deployments match.");
  }

  async function load() {
    try {
      const params = new URLSearchParams({ q: $("jobSearch").value.trim(), kind: $("jobKind").value, status: $("jobStatus").value });
      const data = await U.api("/api/deployments?" + params.toString());
      jobs = data.jobs || [];
      renderStats();
      renderJobs();
    } catch (error) {
      $("jobBody").innerHTML = emptyRow(9, error.message || "Deployments could not be loaded.");
    }
  }

  document.querySelectorAll("[data-admin]").forEach(function (el) { el.hidden = !isAdmin; });

  $("jobSearch").addEventListener("input", U.debounce(load, 250));
  $("jobKind").addEventListener("change", load);
  $("jobStatus").addEventListener("change", load);
  U.bindRowLinks($("jobBody"));

  U.liveRefresh(load, { types: ["deployment"], fallbackMs: 5000 });
  load();
})();
