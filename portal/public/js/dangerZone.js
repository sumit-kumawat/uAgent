(function () {
  "use strict";

  // Reset & Recovery. Every operation follows the same path: read the preflight, show what it will touch,
  // collect the confirmations the server requires, then follow the job stage by stage. The buttons stay
  // disabled until the server says the operation is ready, so nothing destructive is one click away.
  const U = window.uAgent;
  const modalEl = document.getElementById("dz-modal");
  const modal = new bootstrap.Modal(modalEl);
  const titleEl = document.getElementById("dz-title");
  const bodyEl = document.getElementById("dz-body");
  const noteEl = document.getElementById("dz-note");
  const runBtn = document.getElementById("dz-run");
  const cancelBtn = document.getElementById("dz-cancel");
  let poll = null;
  let data = null;

  const esc = U.escapeHtml;
  const tone = { Succeeded: "success", Failed: "danger", NeedsAttention: "warning", Interrupted: "warning", Running: "info" };
  const stageIcon = {
    done: '<i class="bi bi-check-circle-fill text-success"></i>',
    warning: '<i class="bi bi-exclamation-triangle-fill text-warning"></i>',
    failed: '<i class="bi bi-x-circle-fill text-danger"></i>',
    running: '<span class="spinner-border spinner-border-sm text-primary"></span>',
    pending: '<i class="bi bi-circle text-muted"></i>',
    skipped: '<i class="bi bi-dash-circle text-muted"></i>',
    interrupted: '<i class="bi bi-slash-circle-fill text-warning"></i>'
  };

  const bytes = U.formatBytes;

  function banner(kind, icon, html) {
    return '<div class="alert alert-' + kind + ' d-flex align-items-start gap-2 py-2 px-3 mb-3">' +
      '<i class="bi ' + icon + ' mt-1"></i><div>' + html + "</div></div>";
  }

  async function load() {
    const res = await U.api("/api/maintenance");
    data = res;
    renderBanners();
    renderOperations();
    renderBackups();
    renderHistory();
    if (res.current) { follow(res.current.id); }
  }

  function renderBanners() {
    const parts = [];
    if (data.setupRequired) {
      parts.push(banner("warning", "bi-person-plus",
        "<strong>Setup is not finished.</strong> This portal has no administrator account. Sign out and open the portal to create one."));
    }
    if (data.restartRequired) {
      parts.push(banner("warning", "bi-arrow-repeat",
        "<strong>A restart is needed to finish.</strong> " + esc(data.restartRequired.detail) +
        ' <span class="subtle">On the server: <code>sudo systemctl restart uagent-portal</code></span>'));
    }
    if (data.current) {
      parts.push(banner("info", "bi-hourglass-split",
        "<strong>" + esc(data.current.title) + " is running</strong>, started by " + esc(data.current.user) +
        ". Other operations are blocked until it finishes."));
    }
    const interrupted = (data.history || []).find((job) => job.state === "Interrupted");
    if (interrupted) {
      parts.push(banner("warning", "bi-slash-circle",
        "<strong>" + esc(interrupted.title) + " did not finish</strong> (" + esc(interrupted.error || "interrupted") +
        ") Review it below and run it again, or restore the backup it took."));
    }
    document.getElementById("banners").innerHTML = parts.join("");
  }

  function renderConnectivity(report) {
    document.getElementById("connChecked").textContent = report.checkedUtc ? "checked " + U.relativeTime(report.checkedUtc) : "";
    const steps = [
      ["Certificate", report.certificate ? report.certificate.mode !== "untrusted" : false,
        report.certificate ? esc(report.certificate.subject) + " · " + esc(report.certificate.mode) + " · serving " + report.certificate.servedLength + " certificate(s) · valid to " + String(report.certificate.validTo).slice(0, 10) : "none installed"],
      ["DNS", report.live.dns.ok, esc(report.live.dns.detail)],
      ["Port " + report.port, report.live.tcp.ok, esc(report.live.tcp.detail)],
      ["TLS handshake", report.live.tls.ok, esc(report.live.tls.detail)]
    ];
    let html = '<div class="dz-steps">';
    for (const [name, ok, detail] of steps) {
      html += '<div class="dz-step"><span class="dz-step-icon">' + (ok ? stageIcon.done : stageIcon.failed) + "</span>" +
        '<span class="dz-step-name">' + esc(name) + "</span>" +
        '<span class="dz-step-detail">' + detail + "</span></div>";
    }
    html += "</div>";

    const cover = report.coverage || { covered: [], stranded: [], unknown: [] };
    if (cover.stranded.length || cover.covered.length || cover.unknown.length) {
      html += '<div class="mt-3"><div class="subtle mb-1">Addresses agents are using</div><div class="dz-steps">';
      for (const group of cover.stranded) {
        html += '<div class="dz-step"><span class="dz-step-icon">' + stageIcon.failed + '</span><span class="dz-step-name">' +
          esc(group.managerUrl) + '</span><span class="dz-step-detail">' + group.agents +
          " agent(s) — the certificate does not cover " + esc(group.host) + ", so these cannot connect</span></div>";
      }
      for (const group of cover.covered) {
        html += '<div class="dz-step"><span class="dz-step-icon">' + stageIcon.done + '</span><span class="dz-step-name">' +
          esc(group.managerUrl) + '</span><span class="dz-step-detail">' + group.agents + " agent(s), " + group.online + " online</span></div>";
      }
      for (const group of cover.unknown) {
        html += '<div class="dz-step"><span class="dz-step-icon">' + stageIcon.pending + '</span><span class="dz-step-name">not reported</span>' +
          '<span class="dz-step-detail">' + group.agents + " agent(s) on a build older than 1.5.0</span></div>";
      }
      html += "</div></div>";
    }

    for (const problem of report.problems || []) {
      html += banner("danger", "bi-exclamation-octagon", esc(problem));
    }
    for (const warning of report.warnings || []) {
      html += banner("warning", "bi-exclamation-triangle", esc(warning));
    }
    if (report.ok && !(report.warnings || []).length) {
      html += banner("success", "bi-check-circle", report.live.tls.verifiedBy === "pinned certificate"
        ? "Agents can reach this portal and recognise it by the pin in their installer. Browsers still warn, because the certificate is not issued by a trusted CA."
        : "Agents can reach this portal and verify its certificate against " + esc(report.live.tls.verifiedBy) + ".");
    }
    document.getElementById("connectivity").innerHTML = html;
  }

  async function checkConnectivity() {
    document.getElementById("connectivity").innerHTML = '<span class="subtle">Checking…</span>';
    try {
      renderConnectivity(await U.api("/api/maintenance/connectivity"));
    } catch (error) {
      document.getElementById("connectivity").innerHTML = banner("danger", "bi-exclamation-octagon", esc(error.message));
    }
  }

  function renderOperations() {
    const icons = {
      repair: "bi-tools",
      refresh: "bi-arrow-repeat",
      "agent-repair": "bi-pc-display",
      "agent-removal": "bi-pc-display-horizontal",
      reset: "bi-eraser",
      destroy: "bi-trash3"
    };
    document.getElementById("operations").innerHTML = data.operations.map(function (op) {
      return '<div class="dz-op' + (op.destructive ? " dz-op-danger" : "") + '">' +
        '<div class="dz-op-icon"><i class="bi ' + (icons[op.type] || "bi-gear") + '"></i></div>' +
        '<div class="dz-op-text"><div class="dz-op-title">' + esc(op.title) +
        (op.destructive ? ' <span class="badge text-bg-danger-subtle">Destructive</span>' : "") + "</div>" +
        '<div class="dz-op-summary">' + esc(op.summary) + "</div></div>" +
        '<button class="btn btn-sm ' + (op.destructive ? "btn-outline-danger" : "btn-outline-primary") +
        '" type="button" data-op="' + esc(op.type) + '">Review…</button></div>';
    }).join("");
    document.querySelectorAll("[data-op]").forEach(function (button) {
      button.addEventListener("click", function () { openOperation(button.getAttribute("data-op")); });
    });
  }

  function renderBackups() {
    const rows = data.backups || [];
    document.getElementById("backupRows").innerHTML = rows.length
      ? rows.map(function (entry) {
        return "<tr><td>" + U.formatDateTime(entry.createdUtc) + "</td><td>" + esc(entry.user || "—") + "</td>" +
          '<td class="subtle">' + esc(entry.reason || entry.label || "—") + "</td><td>" + bytes(entry.sizeBytes) + "</td>" +
          "<td>" + entry.contents.length + " file(s)" + (entry.readable ? "" : ' <span class="badge text-bg-danger-subtle">unreadable</span>') + "</td>" +
          '<td class="text-end"><button class="btn btn-sm btn-outline-secondary me-1" data-verify="' + esc(entry.name) + '">Verify</button>' +
          '<button class="btn btn-sm btn-outline-danger" data-restore="' + esc(entry.name) + '">Restore…</button></td></tr>';
      }).join("")
      : '<tr><td colspan="6" class="subtle">No backups yet. One is taken automatically before anything destructive.</td></tr>';
    document.querySelectorAll("[data-verify]").forEach(function (button) {
      button.addEventListener("click", async function () {
        button.disabled = true;
        try {
          const result = await U.api("/api/maintenance/backups/" + encodeURIComponent(button.getAttribute("data-verify")) + "/verify", { method: "POST" });
          U.notify(result.ok ? "The backup is complete and every file matches its checksum." : "This backup is not usable: " + result.problems.join("; "), result.ok ? "success" : "danger");
        } catch (error) {
          U.notify(error.message, "danger");
        }
        button.disabled = false;
      });
    });
    document.querySelectorAll("[data-restore]").forEach(function (button) {
      button.addEventListener("click", function () { openRestore(button.getAttribute("data-restore")); });
    });
  }

  function renderHistory() {
    const rows = data.history || [];
    document.getElementById("historyRows").innerHTML = rows.length
      ? rows.map(function (job) {
        return "<tr><td>" + U.formatDateTime(job.startedUtc) + "</td><td>" + esc(job.title) + "</td><td>" + esc(job.user) + "</td>" +
          '<td class="subtle">' + esc(job.reason || "—") + "</td>" +
          "<td>" + U.pill(tone[job.state] || "neutral", job.state === "NeedsAttention" ? "Needs attention" : job.state) + "</td>" +
          '<td class="text-end"><button class="btn btn-sm btn-outline-secondary" data-job="' + esc(job.id) + '">Details</button></td></tr>';
      }).join("")
      : '<tr><td colspan="6" class="subtle">Nothing has been run yet.</td></tr>';
    document.querySelectorAll("[data-job]").forEach(function (button) {
      button.addEventListener("click", function () { showJob(button.getAttribute("data-job")); });
    });
  }

  // ---- Operation flow ------------------------------------------------------------------------------

  async function openOperation(type) {
    titleEl.textContent = "Checking…";
    bodyEl.innerHTML = '<div class="py-4 text-center"><span class="spinner-border"></span></div>';
    noteEl.textContent = "";
    runBtn.classList.remove("d-none");
    runBtn.disabled = true;
    cancelBtn.textContent = "Cancel";
    modal.show();

    let scope = {};
    let fleet = [];
    if ((data.operations.find(function (op) { return op.type === type; }) || {}).selectsAgents) {
      fleet = await U.api("/api/agents");
      scope = { agentIds: [], includeOffline: true };
    }

    async function refresh() {
      const check = await U.api("/api/maintenance/" + type + "/preflight", { method: "POST", body: { scope } });
      titleEl.textContent = check.title;
      bodyEl.innerHTML = renderPreflight(check, fleet);
      wireScope(check);
      const confirmed = checkInputs(check);
      runBtn.disabled = !check.ready || !confirmed;
      runBtn.textContent = check.destructive ? check.title : "Run " + check.title.toLowerCase();
      runBtn.className = "btn " + (check.destructive ? "btn-danger" : "btn-primary");
      noteEl.textContent = check.ready ? "" : "Blocked: " + check.blockers[0];
      return check;
    }

    function wireScope(check) {
      bodyEl.querySelectorAll("[data-scope]").forEach(function (input) {
        input.addEventListener("change", function () {
          scope[input.getAttribute("data-scope")] = input.checked;
          refresh();
        });
      });
      bodyEl.querySelectorAll("[data-agent]").forEach(function (input) {
        input.addEventListener("change", function () {
          const id = input.getAttribute("data-agent");
          scope.agentIds = input.checked
            ? scope.agentIds.concat([id])
            : scope.agentIds.filter(function (other) { return other !== id; });
          refresh();
        });
      });
      const all = bodyEl.querySelector("#dz-all-agents");
      if (all) {
        all.addEventListener("change", function () {
          scope.agentIds = all.checked ? fleet.filter(selectable).map(function (agent) { return agent.agentId; }) : [];
          refresh();
        });
      }
      const offline = bodyEl.querySelector("#dz-include-offline");
      if (offline) {
        offline.addEventListener("change", function () {
          scope.includeOffline = offline.checked;
          refresh();
        });
      }
      bodyEl.querySelectorAll("[data-gate]").forEach(function (input) {
        input.addEventListener("input", function () { runBtn.disabled = !check.ready || !checkInputs(check); });
        input.addEventListener("change", function () { runBtn.disabled = !check.ready || !checkInputs(check); });
      });
    }

    function checkInputs(check) {
      if (check.type === "repair") { return true; }
      const reason = (bodyEl.querySelector("#dz-reason") || {}).value || "";
      if (reason.trim().length < 5) { return false; }
      if ((bodyEl.querySelector("#dz-password") || {}).value === "") { return false; }
      if (check.requiresUninstallKey && ((bodyEl.querySelector("#dz-ukey") || {}).value || "").replace(/[\s-]/g, "").length !== 25) { return false; }
      if (check.confirmPhrase) {
        if (((bodyEl.querySelector("#dz-confirm") || {}).value || "") !== check.confirmPhrase) { return false; }
        if (!(bodyEl.querySelector("#dz-ack") || {}).checked) { return false; }
      }
      return true;
    }

    const check = await refresh();
    runBtn.onclick = async function () {
      runBtn.disabled = true;
      const payload = {
        reason: (bodyEl.querySelector("#dz-reason") || {}).value || "",
        currentPassword: (bodyEl.querySelector("#dz-password") || {}).value || "",
        confirm: (bodyEl.querySelector("#dz-confirm") || {}).value || "",
        acknowledge: Boolean((bodyEl.querySelector("#dz-ack") || {}).checked),
        uninstallKey: (bodyEl.querySelector("#dz-ukey") || {}).value || undefined,
        scope: scope
      };
      try {
        const started = await U.api("/api/maintenance/" + type, { method: "POST", body: payload });
        runBtn.classList.add("d-none");
        cancelBtn.textContent = "Close";
        follow(started.job.id, true);
      } catch (error) {
        bodyEl.insertAdjacentHTML("afterbegin", banner("danger", "bi-exclamation-octagon", esc(error.message)));
        runBtn.disabled = false;
      }
    };
    return check;
  }

  // An agent is selectable when it is active (pending and revoked agents take no commands) and not
  // already on its way out.
  function selectable(agent) {
    return agent.status === "Active" && !(agent.removalState && agent.removalState !== "Failed");
  }

  function renderPreflight(check, fleet) {
    let html = '<p class="mb-3">' + esc(check.summary) + "</p>";
    for (const blocker of check.blockers) {
      html += banner("danger", "bi-slash-circle", esc(blocker));
    }
    for (const note of check.notes) {
      html += banner("info", "bi-info-circle", esc(note));
    }

    if (check.selectsAgents) {
      const chosen = {};
      (check.scope.agentIds || []).forEach(function (id) { chosen[id] = true; });
      const candidates = (fleet || []).filter(selectable);
      html += '<div class="dz-section-title">Choose the computers</div>';
      if (!candidates.length) {
        html += banner("info", "bi-info-circle", "No agents are registered, so there is nothing to act on.");
      } else {
        html += '<label class="dz-scope"><input class="form-check-input" type="checkbox" id="dz-all-agents"' +
          (candidates.length && candidates.every(function (a) { return chosen[a.agentId]; }) ? " checked" : "") + " />" +
          '<span><span class="dz-scope-title">Select all ' + candidates.length + " agent(s)</span></span></label>";
        html += '<div class="dz-agents">' + candidates.map(function (agent) {
          return '<label class="dz-agent"><input class="form-check-input" type="checkbox" data-agent="' + esc(agent.agentId) + '"' +
            (chosen[agent.agentId] ? " checked" : "") + " />" +
            '<span class="dz-agent-id">' + esc(agent.displayId) + "</span>" +
            '<span class="dz-agent-name">' + esc(agent.machineName || "—") + "</span>" +
            '<span class="dz-agent-meta">' + esc(agent.agentVersion || "") + "</span>" +
            '<span class="dz-agent-state">' + U.agentConnectionPill(agent) + "</span></label>";
        }).join("") + "</div>";
        html += '<div class="form-check mt-2"><input class="form-check-input" type="checkbox" id="dz-include-offline"' +
          (check.scope.includeOffline ? " checked" : "") + ' /><label class="form-check-label" for="dz-include-offline">' +
          "Include agents that are offline. Their command is queued and runs when they next connect.</label></div>";
      }
      if (check.selection.length) {
        html += '<div class="dz-section-title">This will reach</div><ul class="dz-affects">' +
          check.selection.map(function (agent) {
            return "<li><strong>" + esc(agent.displayId) + "</strong> — " + esc(agent.machineName) +
              (agent.online ? ", online now" : ", offline (queued)") + "</li>";
          }).join("") + "</ul>";
      }
    }

    if (check.type === "reset" || check.type === "destroy") {
      html += '<div class="dz-section-title">Choose what this affects</div>';
      html += '<div class="dz-scopes">' + (check.scopes || []).map(function (group) {
        const on = Boolean(check.scope && check.scope[group.key]);
        return '<label class="dz-scope"><input class="form-check-input" type="checkbox" data-scope="' + esc(group.key) + '"' + (on ? " checked" : "") + " />" +
          '<span><span class="dz-scope-title">' + esc(group.title) + '</span><span class="dz-scope-detail">' + esc(group.detail) + "</span></span></label>";
      }).join("") + "</div>";

      if (check.affects.length) {
        html += '<div class="dz-section-title">This will affect</div><ul class="dz-affects">' +
          check.affects.map(function (item) {
            return "<li><strong>" + esc(item.title) + "</strong> — " + esc(item.detail) +
              (item.files && item.files.length ? ' <span class="subtle">(' + esc(item.files.join(", ")) + ")</span>" : "") + "</li>";
          }).join("") + "</ul>";
      }
    }

    html += '<div class="dz-section-title">Stages</div><ol class="dz-stage-list">' +
      check.stages.map(function (stage) { return "<li>" + esc(stage.title) + "</li>"; }).join("") + "</ol>";

    if (check.type !== "repair") {
      html += '<div class="dz-section-title">Authorisation</div>';
      html += '<div class="mb-2"><label class="form-label" for="dz-reason">Reason <span class="subtle">(recorded in the audit log)</span></label>' +
        '<input class="form-control" id="dz-reason" data-gate autocomplete="off" placeholder="Why this is being done" /></div>';
      if (check.confirmPhrase) {
        html += '<div class="mb-2"><label class="form-label" for="dz-confirm">Type <code>' + esc(check.confirmPhrase) + "</code> to confirm</label>" +
          '<input class="form-control" id="dz-confirm" data-gate autocomplete="off" /></div>';
        html += '<div class="form-check mb-2"><input class="form-check-input" type="checkbox" id="dz-ack" data-gate />' +
          '<label class="form-check-label" for="dz-ack">I have read what this affects and a verified backup is taken first.</label></div>';
      }
      html += '<div class="mb-1"><label class="form-label" for="dz-password">Your portal password</label>' +
        '<input class="form-control" type="password" id="dz-password" data-gate autocomplete="current-password" /></div>';
      if (check.requiresUninstallKey) {
        html += '<div class="mt-2 mb-1"><label class="form-label" for="dz-ukey">Uninstall verification key</label>' +
          '<input class="form-control mono" type="password" id="dz-ukey" data-gate autocomplete="off" spellcheck="false" maxlength="40" placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" />' +
          '<div class="form-text">This portal\'s 25-character key, from Settings.</div></div>';
      }
    }
    return html;
  }

  function openRestore(name) {
    titleEl.textContent = "Restore from backup";
    runBtn.classList.remove("d-none");
    runBtn.className = "btn btn-danger";
    runBtn.textContent = "Restore";
    runBtn.disabled = true;
    cancelBtn.textContent = "Cancel";
    bodyEl.innerHTML = banner("warning", "bi-exclamation-triangle",
      "Restoring replaces the portal's current records with those in <strong>" + esc(name) + "</strong>. " +
      "The current state is saved as a new backup first, so this can be undone. The portal then restarts to load the restored records.") +
      '<div class="dz-section-title">Authorisation</div>' +
      '<div class="mb-2"><label class="form-label" for="dz-reason">Reason</label><input class="form-control" id="dz-reason" data-gate autocomplete="off" /></div>' +
      '<div class="mb-2"><label class="form-label" for="dz-confirm">Type <code>RESTORE</code> to confirm</label><input class="form-control" id="dz-confirm" data-gate autocomplete="off" /></div>' +
      '<div class="form-check mb-2"><input class="form-check-input" type="checkbox" id="dz-ack" data-gate /><label class="form-check-label" for="dz-ack">I understand the current records are replaced.</label></div>' +
      '<div><label class="form-label" for="dz-password">Your portal password</label><input class="form-control" type="password" id="dz-password" data-gate autocomplete="current-password" /></div>';
    const gate = function () {
      runBtn.disabled = !(bodyEl.querySelector("#dz-reason").value.trim().length >= 5 &&
        bodyEl.querySelector("#dz-confirm").value === "RESTORE" &&
        bodyEl.querySelector("#dz-ack").checked &&
        bodyEl.querySelector("#dz-password").value !== "");
    };
    bodyEl.querySelectorAll("[data-gate]").forEach(function (input) {
      input.addEventListener("input", gate);
      input.addEventListener("change", gate);
    });
    runBtn.onclick = async function () {
      runBtn.disabled = true;
      try {
        const result = await U.api("/api/maintenance/backups/" + encodeURIComponent(name) + "/restore", {
          method: "POST",
          body: {
            reason: bodyEl.querySelector("#dz-reason").value,
            confirm: bodyEl.querySelector("#dz-confirm").value,
            acknowledge: true,
            currentPassword: bodyEl.querySelector("#dz-password").value
          }
        });
        bodyEl.innerHTML = banner("success", "bi-check-circle",
          "Restored " + result.restored.length + " file(s). " + esc(result.note) +
          (result.safety ? ' <span class="subtle">The previous state was saved as ' + esc(result.safety) + ".</span>" : ""));
        runBtn.classList.add("d-none");
        cancelBtn.textContent = "Close";
        load();
      } catch (error) {
        bodyEl.insertAdjacentHTML("afterbegin", banner("danger", "bi-exclamation-octagon", esc(error.message)));
        runBtn.disabled = false;
      }
    };
    modal.show();
  }

  // ---- Following a running job ---------------------------------------------------------------------

  function renderJob(job) {
    let html = '<div class="d-flex align-items-center gap-2 mb-3">' + U.pill(tone[job.state] || "neutral",
      job.state === "NeedsAttention" ? "Needs attention" : job.state) +
      '<span class="subtle">started ' + U.formatDateTime(job.startedUtc) + " by " + esc(job.user) + "</span></div>";
    if (job.reason) { html += '<p class="subtle">Reason: ' + esc(job.reason) + "</p>"; }
    html += '<div class="dz-steps">' + job.stages.map(function (stage) {
      return '<div class="dz-step"><span class="dz-step-icon">' + (stageIcon[stage.state] || stageIcon.pending) + "</span>" +
        '<span class="dz-step-name">' + esc(stage.title) + "</span>" +
        '<span class="dz-step-detail">' + esc(stage.detail || "") + "</span></div>";
    }).join("") + "</div>";
    if (job.backupFile) {
      html += banner("info", "bi-archive", "Backup taken and verified: <code>" + esc(job.backupFile) + "</code>");
    }
    for (const correction of job.corrections || []) {
      html += banner("success", "bi-check2", esc(correction));
    }
    for (const finding of job.findings || []) {
      html += banner(finding.severity === "problem" ? "danger" : "warning",
        finding.severity === "problem" ? "bi-exclamation-octagon" : "bi-exclamation-triangle", esc(finding.message));
    }
    if (job.error) { html += banner("danger", "bi-x-octagon", esc(job.error)); }
    return html;
  }

  function follow(id, inModal) {
    if (poll) { clearInterval(poll); }
    const tick = async function () {
      let job = null;
      try {
        job = (await U.api("/api/maintenance/jobs/" + id)).job;
      } catch (error) {
        clearInterval(poll);
        return;
      }
      if (inModal) {
        titleEl.textContent = job.title;
        bodyEl.innerHTML = renderJob(job);
      }
      if (job.state !== "Running") {
        clearInterval(poll);
        poll = null;
        if (!inModal || !modalEl.classList.contains("show")) { load(); }
        else { U.api("/api/maintenance").then(function (fresh) { data = fresh; renderBanners(); renderBackups(); renderHistory(); }); }
        checkConnectivity();
      }
    };
    tick();
    poll = setInterval(tick, 1200);
  }

  async function showJob(id) {
    titleEl.textContent = "Operation";
    runBtn.classList.add("d-none");
    cancelBtn.textContent = "Close";
    bodyEl.innerHTML = '<div class="py-4 text-center"><span class="spinner-border"></span></div>';
    modal.show();
    const job = (await U.api("/api/maintenance/jobs/" + id)).job;
    bodyEl.innerHTML = renderJob(job);
  }

  document.getElementById("recheck").addEventListener("click", checkConnectivity);
  document.getElementById("newBackup").addEventListener("click", async function () {
    const button = document.getElementById("newBackup");
    button.disabled = true;
    try {
      const result = await U.api("/api/maintenance/backups", { method: "POST", body: { reason: "Created from the Danger Zone." } });
      U.notify("Backup created and verified: " + result.backup.name + " (" + bytes(result.backup.sizeBytes) + ").", "success");
      load();
    } catch (error) {
      U.notify(error.message, "danger");
    }
    button.disabled = false;
  });
  modalEl.addEventListener("hidden.bs.modal", function () {
    if (poll) { clearInterval(poll); poll = null; }
    load();
  });

  load();
  checkConnectivity();
})();
