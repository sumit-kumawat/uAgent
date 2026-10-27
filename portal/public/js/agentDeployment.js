(function () {
  "use strict";
  const U = window.uAgent;
  const $ = function (id) { return document.getElementById(id); };
  const isAdmin = document.body.dataset.role === "Administrator";
  const MAX_IMPORT_BYTES = 10 * 1024 * 1024;

  const signatureStatus = { Valid: ["success", "Signed"], Present: ["warning", "Signed, not trusted"], Invalid: ["danger", "Invalid signature"], Unsigned: ["neutral", "Unsigned"] };
  const jobStatus = { Scheduled: ["info", "Scheduled"], Running: ["info", "Running"], Paused: ["warning", "Paused"], Completed: ["success", "Completed"], Cancelled: ["neutral", "Cancelled"] };
  const importStatus = { Review: ["warning", "In review"], Approved: ["success", "Approved"] };
  const actionLabels = { upgrade: "Upgrade", repair: "Repair" };

  let releases = [];
  let activeTab = "imports";

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

  function emptyRow(colspan, message) {
    return '<tr><td colspan="' + colspan + '" class="empty">' + U.escapeHtml(message) + "</td></tr>";
  }

  function kv(rows) {
    return rows.map(function (r) { return "<dt>" + U.escapeHtml(r[0]) + "</dt><dd>" + r[1] + "</dd>"; }).join("");
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

  function initTabs() {
    const wanted = window.location.hash.slice(1);
    document.querySelectorAll('.tabs-card > .nav-tabs [data-bs-toggle="tab"]').forEach(function (btn) {
      const name = btn.getAttribute("data-bs-target").replace("#pane-", "");
      btn.addEventListener("shown.bs.tab", function () {
        activeTab = name;
        window.history.replaceState(null, "", "#" + name);
        if (name === "jobs") {
          loadJobs();
        }
      });
      if (name === wanted) {
        bootstrap.Tab.getOrCreateInstance(btn).show();
      }
    });
  }

  // ---------- Imports ----------
  async function loadImports() {
    try {
      const data = await U.api("/api/agent-deployment/imports");
      const list = data.imports || [];
      $("cntImports").textContent = list.length;
      $("importBody").innerHTML = list.length ? list.map(function (i) {
        const c = i.counts || {};
        const issues = num(c.invalid) + num(c.duplicates);
        return '<tr class="row-link" tabindex="0" data-href="/agent-deployment/imports/' + encodeURIComponent(i.id) + '">' +
          '<td><span class="cell-primary">' + plain(i.name) + '</span><div class="subtle">' + plain(i.fileName) + "</div></td>" +
          "<td>" + mapPill(importStatus, i.status, true) + "</td>" +
          '<td class="num">' + num(c.total) + "</td>" +
          '<td class="num">' + (issues ? '<span class="text-danger">' + issues + "</span>" : "0") + "</td>" +
          '<td class="num">' + num(c.install) + "</td>" +
          '<td class="num">' + num(c.upgrade) + "</td>" +
          '<td class="num">' + num(c.repair) + "</td>" +
          '<td class="num">' + num(c.current) + "</td>" +
          '<td class="nowrap">' + when(i.createdUtc) + '<div class="subtle">' + plain(i.createdBy) + "</div></td></tr>";
      }).join("") : emptyRow(9, "No imports yet.");
    } catch (error) {
      $("importBody").innerHTML = emptyRow(9, error.message || "Imports could not be loaded.");
    }
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

  async function submitImport() {
    const box = $("impError");
    box.hidden = true;
    const name = $("impName").value.trim();
    const file = $("impFile").files && $("impFile").files[0];
    const fail = function (message, input) {
      box.textContent = message;
      box.hidden = false;
      if (input) {
        input.focus();
      }
    };
    if (!name) {
      fail("Enter a name for this import.", $("impName"));
      return;
    }
    if (!file) {
      fail("Choose a CSV or Excel file.", $("impFile"));
      return;
    }
    if (!/\.(csv|xlsx)$/i.test(file.name)) {
      fail("Only .csv and .xlsx files are supported.", $("impFile"));
      return;
    }
    if (file.size > MAX_IMPORT_BYTES) {
      fail("The file is larger than 10 MB.", $("impFile"));
      return;
    }
    $("impSubmit").disabled = true;
    try {
      const contentBase64 = await readBase64(file);
      const data = await U.api("/api/agent-deployment/imports", {
        method: "POST",
        body: { name: name, fileName: file.name, contentBase64: contentBase64, checkDns: $("impDns").checked }
      });
      window.location.href = "/agent-deployment/imports/" + encodeURIComponent(data.import.id);
    } catch (error) {
      fail(error.message || "The import failed.");
      $("impSubmit").disabled = false;
    }
  }

  function downloadTemplate() {
    const lines = [
      "hostname,fqdn,ip,site,os,group,status",
      "PC-0001,pc-0001.corp.example.com,10.10.1.21,Headquarters,Windows 11 Enterprise,Finance,active",
      "PC-0002,,10.20.4.37,Branch East,Windows 10 Enterprise,Sales,active"
    ];
    const blob = new Blob([lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "uagent-import-template.csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  // ---------- Releases ----------
  function renderCurrent(current) {
    $("currentKv").innerHTML = current && current.version ? kv([
      ["Version", '<span class="mono">' + plain(current.version) + "</span>"],
      ["Size", plain(U.formatBytes(current.size))],
      ["Signature", current.signed ? U.pill("success", "Authenticode signed") : U.pill("neutral", "Unsigned")],
      ["SHA-256", '<span class="mono small">' + plain(current.sha256) + "</span>"],
      ["Source", plain(current.source)]
    ]) : "<dt>Version</dt><dd>No agent release is published. Upload and publish a build to enable upgrades.</dd>";
  }

  function renderReleases() {
    $("cntReleases").textContent = releases.length;
    $("releaseBody").innerHTML = releases.length ? releases.map(function (r) {
      const sig = r.signature || {};
      const actions = [];
      if (isAdmin && !r.published) {
        actions.push('<button type="button" class="btn btn-sm btn-outline-primary" data-act="publish">Publish</button>');
        actions.push('<button type="button" class="btn btn-sm btn-outline-danger" data-act="delete" aria-label="Delete release"><i class="bi bi-trash"></i></button>');
      }
      return '<tr data-id="' + U.escapeHtml(r.id) + '">' +
        '<td><span class="cell-primary mono">' + plain(r.version) + "</span></td>" +
        '<td class="mono">' + plain(r.fileName) + "</td>" +
        '<td class="num nowrap">' + U.escapeHtml(U.formatBytes(r.size)) + "</td>" +
        '<td title="' + U.escapeHtml(sig.subject || "") + '">' + mapPill(signatureStatus, sig.status) + "</td>" +
        '<td><span class="mono truncate d-inline-block" title="' + U.escapeHtml(r.sha256 || "") + '">' + plain(r.sha256) + "</span></td>" +
        '<td class="nowrap">' + U.escapeHtml(U.formatDateTime(r.uploadedUtc)) + '<div class="subtle">' + plain(r.uploadedBy) + "</div></td>" +
        "<td>" + (r.published ? U.pill("success", "Published", true) : U.pill("neutral", "Not published")) + "</td>" +
        '<td class="text-end nowrap">' + actions.join(" ") + "</td></tr>";
    }).join("") : emptyRow(8, "No agent builds uploaded.");
  }

  async function loadReleases() {
    try {
      const data = await U.api("/api/agent-deployment/releases");
      releases = data.releases || [];
      renderCurrent(data.current);
      renderReleases();
    } catch (error) {
      $("releaseBody").innerHTML = emptyRow(8, error.message || "Releases could not be loaded.");
    }
  }

  function releaseLabel(r) {
    return "agent " + (r.version || r.fileName || "build");
  }

  function publishRelease(r) {
    U.runAction({
      machineName: releaseLabel(r),
      control: { label: "Publish release", description: "New upgrade and repair jobs, and the deployment kit, use this build.", reauth: true },
      submit: async function (values) {
        await U.api("/api/agent-deployment/releases/" + encodeURIComponent(r.id) + "/publish", { method: "POST", body: { currentPassword: values.currentPassword } });
        U.notify("Release published.", "success");
        loadReleases();
      }
    });
  }

  function deleteRelease(r) {
    U.runAction({
      machineName: releaseLabel(r),
      control: { label: "Delete release", description: "Removes this agent build from the portal.", reauth: true },
      submit: async function (values) {
        await U.api("/api/agent-deployment/releases/" + encodeURIComponent(r.id), { method: "DELETE", body: { currentPassword: values.currentPassword } });
        U.notify("Release deleted.", "success");
        loadReleases();
      }
    });
  }

  function delay(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  async function sendChunk(uploadId, offset, blob, signal) {
    const response = await fetch("/api/uploads/" + encodeURIComponent(uploadId) + "?offset=" + offset, {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream", "Accept": "application/json" },
      body: blob,
      credentials: "same-origin",
      cache: "no-store",
      signal: signal
    });
    if (response.status === 401) {
      window.location.href = "/login?returnUrl=" + encodeURIComponent(window.location.pathname);
      throw U.ApiError("Your session has expired. Redirecting to sign in.", 401, "unauthenticated");
    }
    let payload = null;
    try {
      payload = await response.json();
    } catch (parseError) {
      payload = null;
    }
    if (!response.ok) {
      const failure = U.ApiError((payload && payload.error) || "Upload failed (HTTP " + response.status + ").", response.status, payload && payload.code);
      failure.payload = payload;
      throw failure;
    }
    return payload;
  }

  async function uploadFile(file, purpose) {
    const controller = new AbortController();
    let uploadId = null;
    let cancelled = false;
    const cancel = $("uploadCancel");
    cancel.hidden = false;
    cancel.onclick = function () {
      cancelled = true;
      controller.abort();
    };
    $("uploadPanel").hidden = false;
    $("uploadName").textContent = file.name;
    const bar = $("uploadBar");
    bar.className = "progress-bar";
    const progress = function (received) {
      const pct = file.size ? Math.floor(received * 100 / file.size) : 100;
      bar.style.width = pct + "%";
      $("uploadBarWrap").setAttribute("aria-valuenow", String(pct));
      $("uploadText").textContent = U.formatBytes(received) + " of " + U.formatBytes(file.size) + " \u00b7 " + pct + "%";
    };
    progress(0);
    try {
      const session = await U.api("/api/uploads", { method: "POST", body: { fileName: file.name, size: file.size, purpose: purpose } });
      uploadId = session.uploadId;
      if (session.maxBytes && file.size > session.maxBytes) {
        throw new Error("The file is larger than the " + U.formatBytes(session.maxBytes) + " limit.");
      }
      const chunkSize = Math.max(65536, num(session.chunkSize) || 4194304);
      let offset = 0;
      let failures = 0;
      while (offset < file.size) {
        if (cancelled) {
          throw new Error("cancelled");
        }
        try {
          const result = await sendChunk(uploadId, offset, file.slice(offset, Math.min(offset + chunkSize, file.size)), controller.signal);
          const received = Number(result && result.received);
          if (!Number.isFinite(received)) {
            throw new Error("The portal returned an unexpected upload response.");
          }
          offset = received;
          failures = 0;
        } catch (error) {
          if (cancelled) {
            throw error;
          }
          if (["offset_mismatch", "busy", "aborted"].indexOf(error.code) >= 0 && error.payload && Number.isFinite(Number(error.payload.received))) {
            if (error.code !== "offset_mismatch") {
              await delay(1000);
            }
            offset = Number(error.payload.received);
            continue;
          }
          if (error.status && error.status < 500) {
            throw error;
          }
          failures += 1;
          if (failures > 5) {
            throw error;
          }
          $("uploadText").textContent = "Connection interrupted. Resuming\u2026";
          await delay(1000 * failures);
          try {
            const status = await U.api("/api/uploads/" + encodeURIComponent(uploadId));
            offset = num(status.received);
          } catch (statusError) {
            if (statusError.status === 404) {
              throw statusError;
            }
          }
        }
        progress(offset);
      }
      cancel.hidden = true;
      return uploadId;
    } catch (error) {
      $("uploadPanel").hidden = true;
      if (uploadId) {
        U.api("/api/uploads/" + encodeURIComponent(uploadId), { method: "DELETE" }).catch(function () {});
      }
      if (cancelled) {
        U.notify("Upload cancelled.", "info");
        return null;
      }
      throw error;
    }
  }

  async function uploadRelease(file) {
    if (!/\.exe$/i.test(file.name)) {
      U.notify("Choose the agent installer (.exe).", "warning");
      return;
    }
    $("uploadBtn").disabled = true;
    try {
      const uploadId = await uploadFile(file, "agent-release");
      if (!uploadId) {
        return;
      }
      $("uploadBar").className = "progress-bar progress-bar-striped progress-bar-animated";
      $("uploadBar").style.width = "100%";
      $("uploadText").textContent = "Verifying the build and its signature\u2026";
      await U.api("/api/agent-deployment/releases", { method: "POST", body: { uploadId: uploadId } });
      $("uploadPanel").hidden = true;
      U.notify("Agent build uploaded. Publish it to use it for upgrades.", "success");
      loadReleases();
    } catch (error) {
      $("uploadPanel").hidden = true;
      U.notify(error.message || "The upload failed.", "danger");
    } finally {
      $("uploadBtn").disabled = false;
    }
  }

  // ---------- Upgrade jobs ----------
  async function loadJobs() {
    try {
      const data = await U.api("/api/deployments?kind=agent");
      const jobs = data.jobs || [];
      $("cntJobs").textContent = jobs.length;
      $("jobCount").textContent = jobs.length + (jobs.length === 1 ? " job" : " jobs");
      $("jobBody").innerHTML = jobs.length ? jobs.map(function (j) {
        return '<tr class="row-link" tabindex="0" data-href="/software/deployments/' + encodeURIComponent(j.id) + '">' +
          '<td><span class="cell-primary">' + plain(j.name) + "</span></td>" +
          "<td>" + plain(actionLabels[j.action] || j.action) + (j.packageVersion ? ' <span class="subtle mono">' + U.escapeHtml(j.packageVersion) + "</span>" : "") + "</td>" +
          '<td title="' + U.escapeHtml(j.statusReason || "") + '">' + mapPill(jobStatus, j.status, true) + "</td>" +
          '<td class="progress-cell">' + progressHtml(j.counts) + "</td>" +
          "<td>" + plain(j.createdBy) + "</td>" +
          '<td class="nowrap">' + when(j.createdUtc) + "</td></tr>";
      }).join("") : emptyRow(6, "No upgrade or repair jobs yet.");
    } catch (error) {
      $("jobBody").innerHTML = emptyRow(6, error.message || "Jobs could not be loaded.");
    }
  }

  // ---------- Events ----------
  document.querySelectorAll("[data-admin]").forEach(function (el) { el.hidden = !isAdmin; });
  if (!isAdmin) {
    $("importFields").disabled = true;
    $("banners").innerHTML = '<div class="banner banner-info"><i class="bi bi-eye"></i><div>You have read-only access. Importing systems, uploading builds and approving deployments requires the Administrator role.</div></div>';
  }

  $("importForm").addEventListener("submit", function (event) { event.preventDefault(); submitImport(); });
  $("templateBtn").addEventListener("click", downloadTemplate);
  U.bindRowLinks($("importBody"));
  U.bindRowLinks($("jobBody"));

  $("uploadBtn").addEventListener("click", function () { $("uploadInput").click(); });
  $("uploadInput").addEventListener("change", function (event) {
    const file = event.target.files && event.target.files[0];
    event.target.value = "";
    if (file) {
      uploadRelease(file);
    }
  });
  $("releaseBody").addEventListener("click", function (event) {
    const btn = event.target.closest("button[data-act]");
    if (!btn) {
      return;
    }
    const id = btn.closest("tr").dataset.id;
    const release = releases.find(function (r) { return r.id === id; });
    if (release && btn.dataset.act === "publish") {
      publishRelease(release);
    } else if (release && btn.dataset.act === "delete") {
      deleteRelease(release);
    }
  });

  initTabs();
  loadImports();
  loadReleases();
  loadJobs();
  setInterval(function () {
    if (activeTab === "jobs" && !document.hidden) {
      loadJobs();
    }
  }, 5000);
})();
