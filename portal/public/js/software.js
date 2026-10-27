(function () {
  "use strict";
  const U = window.uAgent;
  const $ = function (id) { return document.getElementById(id); };
  const isAdmin = document.body.dataset.role === "Administrator";
  const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  const packageStatus = { PendingReview: ["warning", "Pending review"], Approved: ["success", "Approved"], Rejected: ["danger", "Rejected"], Quarantined: ["danger", "Quarantined"] };
  const signatureStatus = { Valid: ["success", "Signed"], Present: ["warning", "Signed, not trusted"], Invalid: ["danger", "Invalid signature"], Unsigned: ["neutral", "Unsigned"] };
  const scanStatus = { Clean: ["success", "Clean"], Infected: ["danger", "Threat detected"], NotScanned: ["warning", "Not scanned"], Error: ["danger", "Scan failed"] };
  const jobStatus = { Scheduled: ["info", "Scheduled"], Running: ["info", "Running"], Paused: ["warning", "Paused"], Completed: ["success", "Completed"], Cancelled: ["neutral", "Cancelled"] };

  let packages = [];
  let groups = [];
  let secrets = [];
  let settings = null;

  const categoryLabels = { site: "Site", lab: "Lab", environment: "Environment", department: "Department", other: "Other" };

  // ---------- Shared helpers ----------
  function mapPill(map, value, withDot) {
    const style = map[value] || ["neutral", value || "Unknown"];
    return U.pill(style[0], style[1], withDot);
  }

  function num(value) {
    return Number(value) || 0;
  }

  function when(value) {
    if (!value) {
      return '<span class="subtle">\u2014</span>';
    }
    return '<span title="' + U.escapeHtml(U.formatDateTime(value)) + '">' + U.escapeHtml(U.relativeTime(value)) + "</span>";
  }

  function progressHtml(counts) {
    const c = counts || {};
    const total = num(c.total);
    const ok = num(c.succeeded);
    const failed = num(c.failed);
    const running = num(c.running);
    const skipped = num(c.skipped) + num(c.cancelled);
    const pending = num(c.pending) + num(c.waiting) + num(c.offline);
    const seg = function (cls, value) {
      return value > 0 && total > 0 ? '<span class="' + cls + '" style="width:' + (value * 100 / total).toFixed(2) + '%"></span>' : "";
    };
    return '<div class="seg-bar" role="img" aria-label="' + ok + " of " + total + ' succeeded">' +
      seg("seg-ok", ok) + seg("seg-fail", failed) + seg("seg-run", running) + seg("seg-skip", skipped) + "</div>" +
      '<span class="seg-caption">' + ok + " succeeded \u00b7 " + failed + " failed \u00b7 " + running + " running \u00b7 " + pending + " pending</span>";
  }

  function emptyRow(colspan, message) {
    return '<tr><td colspan="' + colspan + '" class="empty">' + U.escapeHtml(message) + "</td></tr>";
  }

  function fieldError(input, message) {
    const error = new Error(message);
    error.input = input;
    return error;
  }

  function showError(box, error) {
    box.textContent = error.message || "The request failed.";
    box.hidden = false;
    if (error.input) {
      const pane = error.input.closest(".tab-pane");
      const tab = pane && document.querySelector('[data-bs-target="#' + pane.id + '"]');
      if (tab) {
        bootstrap.Tab.getOrCreateInstance(tab).show();
      }
      error.input.focus();
    }
  }

  function readInt(id, label, min, max, optional) {
    const input = $(id);
    const raw = input.value.trim();
    if (raw === "" && optional) {
      return null;
    }
    const value = Number(raw);
    if (raw === "" || !Number.isInteger(value) || value < min || (max !== undefined && value > max)) {
      throw fieldError(input, label + " must be a whole number" + (max !== undefined ? " from " + min + " to " + max : " of at least " + min) + ".");
    }
    return value;
  }

  function readCodes(id, label, required) {
    const input = $(id);
    const parts = input.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
    if (required && !parts.length) {
      throw fieldError(input, "Enter at least one " + label.toLowerCase() + ".");
    }
    return parts.map(function (part) {
      if (!/^-?\d+$/.test(part)) {
        throw fieldError(input, label + " must be whole numbers separated by commas.");
      }
      return Number(part);
    });
  }

  function setAdminVisibility() {
    document.querySelectorAll("[data-admin]").forEach(function (el) { el.hidden = !isAdmin; });
    if (!isAdmin) {
      $("banners").innerHTML = '<div class="banner banner-info"><i class="bi bi-eye"></i><div>You have read-only access. Uploading, approving and deploying software requires the Administrator role.</div></div>';
    }
  }

  function initTabs() {
    const wanted = window.location.hash.slice(1);
    document.querySelectorAll('.tabs-card > .nav-tabs [data-bs-toggle="tab"]').forEach(function (btn) {
      const name = btn.getAttribute("data-bs-target").replace("#pane-", "");
      btn.addEventListener("shown.bs.tab", function () {
        window.history.replaceState(null, "", "#" + name);
      });
      if (name === wanted) {
        bootstrap.Tab.getOrCreateInstance(btn).show();
      }
    });
  }

  // ---------- Deploy wizard entry hash: #deploy, #deploy=<packageId>, #deploy=validation:<id> ----------
  function parseDeployHash() {
    const raw = window.location.hash.slice(1);
    if (raw.indexOf("deploy") !== 0) {
      return null;
    }
    const eq = raw.indexOf("=");
    if (eq < 0) {
      return { packageId: null, validationId: null };
    }
    const value = raw.slice(eq + 1);
    if (value.indexOf("validation:") === 0) {
      return { packageId: null, validationId: value.slice("validation:".length) };
    }
    return { packageId: value, validationId: null };
  }

  function checkDeployHash() {
    const parsed = parseDeployHash();
    if (parsed) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
      openWizard(parsed.packageId, parsed.validationId);
    }
  }

  // ---------- Agent picker (wizard targets and static groups) ----------
  function createPicker(root, opts) {
    const picker = { include: new Set(), exclude: new Set(), total: 0, page: 1, pageSize: 25, rows: [], showInclude: true, showExclude: !!opts.exclude };
    let request = 0;
    root.innerHTML =
      '<div class="picker">' +
      '  <div class="toolbar">' +
      '    <div class="search"><i class="bi bi-search"></i><input type="search" class="form-control form-control-sm" data-f="q" placeholder="Search host, agent ID, IP, DNS\u2026" aria-label="Search agents" autocomplete="off" /></div>' +
      '    <select class="form-select form-select-sm" data-f="domain" aria-label="Domain"><option value="">All domains</option></select>' +
      '    <select class="form-select form-select-sm" data-f="site" aria-label="Site"><option value="">All sites</option></select>' +
      '    <select class="form-select form-select-sm" data-f="os" aria-label="Operating system"><option value="">All operating systems</option></select>' +
      '    <select class="form-select form-select-sm" data-f="connection" aria-label="Connection"><option value="all">Any connection</option><option value="online">Online</option><option value="offline">Offline</option></select>' +
      '    <div class="form-check mb-0"><input class="form-check-input" type="checkbox" data-f="capable" id="' + root.id + 'Capable"' + (opts.capable ? " checked" : "") + ' /><label class="form-check-label small" for="' + root.id + 'Capable">Software installation supported</label></div>' +
      '    <span class="count" data-r="count"></span>' +
      "  </div>" +
      '  <div class="picker-scroll"><table class="data-table"><thead><tr>' +
      '    <th class="col-check" data-c="include"><input type="checkbox" class="form-check-input" data-r="all" aria-label="Select all agents on this page" /></th>' +
      "    <th>Machine</th><th>Agent ID</th><th>Domain</th><th>Site</th><th>Operating system</th><th>Connection</th><th>Agent version</th>" +
      '    <th class="col-check" data-c="exclude">Exclude</th>' +
      '  </tr></thead><tbody data-r="body"><tr><td colspan="9" class="empty">Loading\u2026</td></tr></tbody></table></div>' +
      '  <div class="pager"><span data-r="info"></span><div class="pages"><button type="button" data-r="prev" aria-label="Previous page">\u2039</button><button type="button" data-r="next" aria-label="Next page">\u203a</button></div></div>' +
      "</div>";
    const q = function (selector) { return root.querySelector(selector); };
    const field = function (name) { return q('[data-f="' + name + '"]'); };
    const body = q('[data-r="body"]');

    function changed() {
      if (typeof opts.onChange === "function") {
        opts.onChange();
      }
    }

    function facetValues(list) {
      return (list || []).map(function (v) {
        return typeof v === "string" ? v : (v && (v.value !== undefined ? v.value : v.name));
      }).filter(Boolean);
    }

    function fillSelect(select, values, allLabel) {
      const current = select.value;
      const list = facetValues(values);
      if (current && list.indexOf(current) < 0) {
        list.push(current);
      }
      select.innerHTML = '<option value="">' + U.escapeHtml(allLabel) + "</option>" + list.map(function (v) {
        return '<option value="' + U.escapeHtml(v) + '">' + U.escapeHtml(v) + "</option>";
      }).join("");
      select.value = current;
    }

    function syncHeader() {
      q('[data-c="include"]').hidden = !picker.showInclude;
      q('th[data-c="exclude"]').hidden = !picker.showExclude;
      const all = q('[data-r="all"]');
      const selected = picker.rows.filter(function (r) { return picker.include.has(r.agentId); }).length;
      all.checked = picker.rows.length > 0 && selected === picker.rows.length;
      all.indeterminate = selected > 0 && selected < picker.rows.length;
    }

    function render() {
      syncHeader();
      if (!picker.rows.length) {
        body.innerHTML = emptyRow(9, "No agents match.");
        return;
      }
      body.innerHTML = picker.rows.map(function (r) {
        const online = r.connection === "online";
        const id = U.escapeHtml(r.agentId);
        const name = U.escapeHtml(U.text(r.machineName));
        return '<tr data-id="' + id + '">' +
          '<td class="col-check"' + (picker.showInclude ? "" : " hidden") + '><input type="checkbox" class="form-check-input" data-pick="include" aria-label="Select ' + name + '"' + (picker.include.has(r.agentId) ? " checked" : "") + " /></td>" +
          '<td><span class="cell-primary"><span class="status-dot ' + (online ? "online" : "offline") + '"></span>' + name + "</span>" +
          (r.canInstallSoftware === false ? ' <span class="tag">Installation not supported</span>' : "") + "</td>" +
          '<td><span class="id-chip">' + U.escapeHtml(U.text(r.displayId)) + "</span></td>" +
          "<td>" + U.escapeHtml(U.text(r.domainName)) + "</td>" +
          "<td>" + U.escapeHtml(U.text(r.site)) + "</td>" +
          "<td>" + U.escapeHtml(U.text(r.osVersion)) + "</td>" +
          "<td>" + U.connectionStatePill(r.connection) + "</td>" +
          '<td class="mono">' + U.escapeHtml(U.text(r.agentVersion)) + "</td>" +
          '<td class="col-check"' + (picker.showExclude ? "" : " hidden") + '><input type="checkbox" class="form-check-input" data-pick="exclude" aria-label="Exclude ' + name + '"' + (picker.exclude.has(r.agentId) ? " checked" : "") + " /></td>" +
          "</tr>";
      }).join("");
    }

    function renderPager() {
      const pages = Math.max(1, Math.ceil(picker.total / picker.pageSize));
      const first = picker.total ? (picker.page - 1) * picker.pageSize + 1 : 0;
      q('[data-r="info"]').textContent = picker.total
        ? "Showing " + first + "\u2013" + Math.min(picker.page * picker.pageSize, picker.total) + " of " + picker.total
        : "";
      q('[data-r="count"]').textContent = picker.total + (picker.total === 1 ? " agent" : " agents");
      q('[data-r="prev"]').disabled = picker.page <= 1;
      q('[data-r="next"]').disabled = picker.page >= pages;
    }

    picker.filter = function () {
      return {
        q: field("q").value.trim(),
        domain: field("domain").value,
        os: field("os").value,
        site: field("site").value,
        connection: field("connection").value
      };
    };

    picker.reset = function (filter) {
      const f = filter || {};
      picker.include.clear();
      picker.exclude.clear();
      picker.page = 1;
      field("q").value = f.q || "";
      ["domain", "site", "os"].forEach(function (name) {
        const select = field(name);
        if (f[name] && !Array.prototype.some.call(select.options, function (o) { return o.value === f[name]; })) {
          select.insertAdjacentHTML("beforeend", '<option value="' + U.escapeHtml(f[name]) + '">' + U.escapeHtml(f[name]) + "</option>");
        }
        select.value = f[name] || "";
      });
      field("connection").value = f.connection || "all";
    };

    picker.setColumns = function (include, exclude) {
      picker.showInclude = include;
      picker.showExclude = exclude;
      render();
    };

    picker.load = async function () {
      const mine = ++request;
      const f = picker.filter();
      const params = new URLSearchParams({ q: f.q, domain: f.domain, os: f.os, site: f.site, connection: f.connection, page: String(picker.page), pageSize: String(picker.pageSize) });
      if (field("capable").checked) {
        params.set("capable", "1");
      }
      try {
        const data = await U.api("/api/deploy/agents?" + params.toString());
        if (mine !== request) {
          return;
        }
        picker.rows = data.rows || [];
        picker.total = num(data.total);
        const facets = data.facets || {};
        fillSelect(field("domain"), facets.domains, "All domains");
        fillSelect(field("site"), facets.sites, "All sites");
        fillSelect(field("os"), facets.os, "All operating systems");
        render();
        renderPager();
        changed();
      } catch (error) {
        if (mine === request) {
          body.innerHTML = emptyRow(9, error.message || "Agents could not be loaded.");
        }
      }
    };

    function refilter() {
      picker.page = 1;
      picker.load();
    }

    field("q").addEventListener("input", U.debounce(refilter, 250));
    ["domain", "site", "os", "connection", "capable"].forEach(function (name) {
      field(name).addEventListener("change", refilter);
    });
    q('[data-r="prev"]').addEventListener("click", function () { picker.page -= 1; picker.load(); });
    q('[data-r="next"]').addEventListener("click", function () { picker.page += 1; picker.load(); });
    q('[data-r="all"]').addEventListener("change", function (event) {
      picker.rows.forEach(function (r) {
        if (event.target.checked) {
          picker.include.add(r.agentId);
          picker.exclude.delete(r.agentId);
        } else {
          picker.include.delete(r.agentId);
        }
      });
      render();
      changed();
    });
    body.addEventListener("change", function (event) {
      const box = event.target.closest("input[data-pick]");
      if (!box) {
        return;
      }
      const id = box.closest("tr").dataset.id;
      const own = box.dataset.pick === "include" ? picker.include : picker.exclude;
      const other = box.dataset.pick === "include" ? picker.exclude : picker.include;
      if (box.checked) {
        own.add(id);
        other.delete(id);
      } else {
        own.delete(id);
      }
      render();
      changed();
    });
    return picker;
  }

  // ---------- Library ----------
  function packageRow(p) {
    const actions = ['<button type="button" class="btn btn-sm btn-outline-secondary" data-act="details">Details</button>'];
    if (isAdmin && p.status === "Approved") {
      actions.push('<button type="button" class="btn btn-sm btn-primary" data-act="deploy">Deploy</button>');
    }
    return '<tr class="row-link" tabindex="0" data-id="' + U.escapeHtml(p.id) + '">' +
      '<td><span class="cell-primary"><i class="bi bi-box-seam text-primary" aria-hidden="true"></i>' + U.escapeHtml(U.text(p.name)) + "</span></td>" +
      '<td class="mono">' + U.escapeHtml(U.text(p.version)) + "</td>" +
      "<td>" + U.escapeHtml(U.text(p.publisher)) + "</td>" +
      '<td><span class="tag">' + U.escapeHtml(String(p.installerType || "").toUpperCase()) + "</span></td>" +
      '<td class="num nowrap">' + U.escapeHtml(U.formatBytes(p.size)) + "</td>" +
      "<td>" + mapPill(signatureStatus, p.signature && p.signature.status) + "</td>" +
      "<td>" + mapPill(scanStatus, p.scan && p.scan.status) + "</td>" +
      '<td title="' + U.escapeHtml(p.statusReason || "") + '">' + mapPill(packageStatus, p.status, true) + "</td>" +
      '<td class="nowrap">' + U.escapeHtml(U.formatDateTime(p.uploadedUtc)) + '<div class="subtle">' + U.escapeHtml(U.text(p.uploadedBy)) + "</div></td>" +
      '<td class="num">' + num(p.deploymentCount) + (num(p.activeDeployments) ? ' <span class="pill pill-info">' + num(p.activeDeployments) + " active</span>" : "") + "</td>" +
      '<td class="text-end nowrap">' + actions.join(" ") + "</td>" +
      "</tr>";
  }

  function renderLibrary() {
    const term = $("libSearch").value.trim().toLowerCase();
    const status = $("libStatus").value;
    const list = packages.filter(function (p) {
      if (status && p.status !== status) {
        return false;
      }
      if (!term) {
        return true;
      }
      return [p.name, p.version, p.publisher, p.fileName].filter(Boolean).join(" ").toLowerCase().indexOf(term) >= 0;
    });
    $("cntLibrary").textContent = packages.length;
    $("libCount").textContent = list.length + " of " + packages.length + " packages";
    $("libBody").innerHTML = list.length
      ? list.map(packageRow).join("")
      : emptyRow(11, packages.length ? "No packages match." : "No packages yet." + (isAdmin ? " Upload an MSI or EXE installer to get started." : ""));
  }

  async function loadPackages() {
    try {
      const data = await U.api("/api/software/packages");
      packages = data.packages || [];
      renderLibrary();
    } catch (error) {
      $("libBody").innerHTML = emptyRow(11, error.message || "Packages could not be loaded.");
    }
  }

  // ---------- Chunked upload ----------
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

  async function uploadPackage(file) {
    if (!/\.(msi|exe)$/i.test(file.name)) {
      U.notify("Choose an .msi or .exe installer.", "warning");
      return;
    }
    $("uploadBtn").disabled = true;
    try {
      const uploadId = await uploadFile(file, "software");
      if (!uploadId) {
        return;
      }
      $("uploadBar").className = "progress-bar progress-bar-striped progress-bar-animated";
      $("uploadBar").style.width = "100%";
      $("uploadText").textContent = "Analyzing: computing hashes, reading metadata, checking the signature and scanning for malware\u2026";
      const result = await U.api("/api/software/packages", { method: "POST", body: { uploadId: uploadId } });
      $("uploadPanel").hidden = true;
      U.notify("Package uploaded. Review its install configuration, then approve it.", "success");
      await loadPackages();
      if (result && result.package) {
        openPackage(result.package.id);
      }
    } catch (error) {
      $("uploadPanel").hidden = true;
      U.notify(error.message || "The upload failed.", "danger");
    } finally {
      $("uploadBtn").disabled = false;
    }
  }

  // ---------- Package details ----------
  const pkgModalEl = $("packageModal");
  let currentPkg = null;
  let installBaseline = "";

  function kv(rows) {
    return rows.map(function (r) { return "<dt>" + U.escapeHtml(r[0]) + "</dt><dd>" + r[1] + "</dd>"; }).join("");
  }

  function plain(value) {
    return U.escapeHtml(U.text(value));
  }

  function needsScanAck(p) {
    return !p.scan || p.scan.status !== "Clean";
  }

  function needsSignatureAck(p) {
    return !p.signature || p.signature.status !== "Valid";
  }

  function canApprove(p) {
    return (p.status === "PendingReview" || p.status === "Rejected") && !(p.scan && p.scan.status === "Infected");
  }

  function fillInstall(p) {
    const i = p.install || {};
    const det = i.detection || {};
    const pre = i.prerequisites || {};
    $("pkgName").value = p.name || "";
    $("pkgVersion").value = p.version || "";
    $("pkgPublisher").value = p.publisher || "";
    $("pkgNotes").value = p.notes || "";
    $("cfgArguments").value = i.arguments || "";
    $("cfgTimeout").value = i.timeoutMinutes !== undefined && i.timeoutMinutes !== null ? i.timeoutMinutes : 30;
    $("cfgSuccess").value = (i.successExitCodes || [0]).join(", ");
    $("cfgReboot").value = (i.rebootExitCodes || [3010, 1641]).join(", ");
    $("cfgRetry").value = (i.retryExitCodes || [1618]).join(", ");
    $("cfgRequireSig").checked = !!i.requireSignature;
    $("cfgSigner").value = i.expectedSigner || "";
    $("cfgDefender").checked = !!i.scanWithDefender;
    $("cfgDetType").value = det.type || "none";
    $("cfgProductCode").value = det.productCode || "";
    $("cfgDisplayName").value = det.displayName || "";
    $("cfgMinVersion").value = det.minVersion || "";
    $("cfgPath").value = det.path || "";
    $("cfgMinBuild").value = num(pre.minOsBuild);
    $("cfgArch").value = pre.architecture || "any";
    $("cfgMinDisk").value = num(pre.minFreeDiskMb);
    $("cfgPendingReboot").checked = !!pre.blockOnPendingReboot;
    $("cfgRestart").value = i.restartBehavior || "never";
    $("cfgRestartDelay").value = i.restartDelayMinutes !== undefined && i.restartDelayMinutes !== null ? i.restartDelayMinutes : 5;
    $("cfgArgumentsHelp").innerHTML = p.installerType === "exe"
      ? "Required for EXE installers. Enter the vendor's complete silent-install switches (for example <span class=\"mono\">/S</span>, <span class=\"mono\">/quiet</span> or <span class=\"mono\">/silent</span>); they differ by vendor, so check the vendor documentation. Reference secrets as <span class=\"mono\">{{secret:NAME}}</span>."
      : "Appended after <span class=\"mono\">msiexec /i &lt;file&gt; /qn /norestart /l*v &lt;log&gt;</span>, for example <span class=\"mono\">ALLUSERS=1 LICENSEKEY={{secret:NAME}}</span>.";
    syncDetection();
  }

  function syncDetection() {
    const type = $("cfgDetType").value;
    document.querySelectorAll("#pkg-config [data-det]").forEach(function (el) {
      el.hidden = el.dataset.det.split(" ").indexOf(type) < 0;
    });
  }

  function readInstall() {
    const type = $("cfgDetType").value;
    const detection = { type: type, productCode: "", displayName: "", minVersion: "", path: "" };
    if (type === "msiProductCode") {
      detection.productCode = $("cfgProductCode").value.trim();
      if (!/^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$/.test(detection.productCode)) {
        throw fieldError($("cfgProductCode"), "Enter the product code as a GUID in braces.");
      }
    } else if (type === "registry") {
      detection.displayName = $("cfgDisplayName").value.trim();
      if (!detection.displayName) {
        throw fieldError($("cfgDisplayName"), "Enter the display name to look for.");
      }
    } else if (type === "file") {
      detection.path = $("cfgPath").value.trim();
      if (!detection.path) {
        throw fieldError($("cfgPath"), "Enter the file path to look for.");
      }
    }
    if (type !== "none") {
      detection.minVersion = $("cfgMinVersion").value.trim();
    }
    const args = $("cfgArguments").value.trim();
    if (currentPkg && currentPkg.installerType === "exe" && !args) {
      throw fieldError($("cfgArguments"), "EXE installers need the vendor's silent-install arguments.");
    }
    return {
      arguments: args,
      timeoutMinutes: readInt("cfgTimeout", "Timeout", 1, 1440),
      successExitCodes: readCodes("cfgSuccess", "Success exit codes", true),
      rebootExitCodes: readCodes("cfgReboot", "Reboot exit codes", false),
      retryExitCodes: readCodes("cfgRetry", "Retry exit codes", false),
      requireSignature: $("cfgRequireSig").checked,
      expectedSigner: $("cfgSigner").value.trim(),
      scanWithDefender: $("cfgDefender").checked,
      detection: detection,
      prerequisites: {
        minOsBuild: readInt("cfgMinBuild", "Minimum OS build", 0),
        architecture: $("cfgArch").value,
        minFreeDiskMb: readInt("cfgMinDisk", "Minimum free disk", 0),
        blockOnPendingReboot: $("cfgPendingReboot").checked
      },
      restartBehavior: $("cfgRestart").value,
      restartDelayMinutes: readInt("cfgRestartDelay", "Restart delay", 0, 1440)
    };
  }

  function renderPackage(p, deployments) {
    currentPkg = p;
    const sig = p.signature || {};
    const scan = p.scan || {};
    const meta = p.metadata || {};
    $("pkgTitle").textContent = [p.name, p.version].filter(Boolean).join(" ");
    $("pkgSub").innerHTML = mapPill(packageStatus, p.status, true) + mapPill(signatureStatus, sig.status) + mapPill(scanStatus, scan.status) +
      '<span class="tag">' + U.escapeHtml(String(p.installerType || "").toUpperCase()) + "</span>";

    const banners = [];
    if (scan.status === "Infected") {
      banners.push('<div class="banner banner-danger"><i class="bi bi-bug"></i><div><strong>Threat detected.</strong> ' + plain(scan.detail) + "</div></div>");
    }
    if ((p.status === "Rejected" || p.status === "Quarantined") && p.statusReason) {
      banners.push('<div class="banner banner-danger"><i class="bi bi-x-octagon"></i><div>' + plain(p.statusReason) + "</div></div>");
    }
    if (p.status === "PendingReview") {
      banners.push('<div class="banner banner-info"><i class="bi bi-info-circle"></i><div>Check the install configuration, then approve the package. Only approved packages can be deployed.</div></div>');
    }
    if (p.installerType === "exe" && !(p.install && p.install.arguments)) {
      banners.push('<div class="banner banner-warning"><i class="bi bi-exclamation-triangle"></i><div>EXE installers have no standard silent switch. Set the vendor\'s silent-install arguments before approving.</div></div>');
    }
    $("pkgBanners").innerHTML = banners.join("");
    $("pkgBanners").hidden = !banners.length;

    $("pkgFile").innerHTML = kv([
      ["File name", '<span class="mono">' + plain(p.fileName) + "</span>"],
      ["Installer type", plain(String(p.installerType || "").toUpperCase())],
      ["Size", plain(U.formatBytes(p.size))],
      ["SHA-256", '<span class="mono small">' + plain(p.sha256) + "</span>"],
      ["Uploaded", plain(U.formatDateTime(p.uploadedUtc)) + ' <span class="subtle">by ' + plain(p.uploadedBy) + "</span>"]
    ]);
    $("pkgReview").innerHTML = kv([
      ["Status", mapPill(packageStatus, p.status, true)],
      ["Reason", plain(p.statusReason)],
      ["Approved", p.approvedUtc ? plain(U.formatDateTime(p.approvedUtc)) + ' <span class="subtle">by ' + plain(p.approvedBy) + "</span>" : plain("")],
      ["Secrets used", (p.secretsUsed || []).length ? p.secretsUsed.map(function (s) { return '<span class="tag mono">' + U.escapeHtml(s) + "</span>"; }).join(" ") : plain("")],
      ["Deployments", num(p.deploymentCount) + (num(p.activeDeployments) ? " (" + num(p.activeDeployments) + " active)" : "")],
      ["Last deployed", plain(U.formatDateTime(p.lastDeployedUtc))]
    ]);
    $("pkgTrust").innerHTML = kv([
      ["Signature", mapPill(signatureStatus, sig.status)],
      ["Signer", plain(sig.subject)],
      ["Signature detail", plain(sig.detail)],
      ["Malware scan", mapPill(scanStatus, scan.status)],
      ["Scan engine", plain(scan.engine)],
      ["Scan detail", plain(scan.detail)],
      ["Scanned", plain(U.formatDateTime(scan.scannedUtc))]
    ]);
    $("pkgMeta").innerHTML = kv([
      ["Product name", plain(meta.productName)],
      ["Product version", plain(meta.productVersion)],
      ["Manufacturer", plain(meta.manufacturer)],
      ["Product code", '<span class="mono">' + plain(meta.productCode) + "</span>"],
      ["File description", plain(meta.fileDescription)],
      ["Company", plain(meta.companyName)],
      ["File version", plain(meta.fileVersion)]
    ]);

    const approvable = isAdmin && canApprove(p);
    $("ackUnscannedWrap").hidden = !(approvable && needsScanAck(p));
    $("ackUnsignedWrap").hidden = !(approvable && needsSignatureAck(p));
    $("pkgAckWrap").hidden = $("ackUnscannedWrap").hidden && $("ackUnsignedWrap").hidden;
    $("ackUnscanned").checked = false;
    $("ackUnsigned").checked = false;

    fillInstall(p);
    $("pkgFields").disabled = !isAdmin;
    installBaseline = JSON.stringify(readInstallSafe());

    $("pkgApprove").hidden = !approvable;
    $("pkgReject").hidden = !(p.status === "PendingReview" || p.status === "Approved");
    $("pkgDeploy").hidden = p.status !== "Approved";

    $("pkgJobs").innerHTML = (deployments || []).length ? deployments.map(function (j) {
      return '<tr class="row-link" tabindex="0" data-href="/deployment-center/jobs/' + encodeURIComponent(j.id) + '">' +
        '<td><span class="cell-primary">' + plain(j.name) + "</span></td>" +
        "<td>" + mapPill(jobStatus, j.status, true) + "</td>" +
        '<td class="progress-cell">' + progressHtml(j.counts) + "</td>" +
        "<td>" + plain(j.createdBy) + "</td>" +
        '<td class="nowrap">' + when(j.createdUtc) + "</td></tr>";
    }).join("") : emptyRow(5, "This package has not been deployed.");
    U.bindRowLinks($("pkgJobs"));
    $("pkgError").hidden = true;
  }

  function readInstallSafe() {
    try {
      return readInstall();
    } catch (error) {
      return null;
    }
  }

  async function openPackage(id, keepTab) {
    try {
      const data = await U.api("/api/software/packages/" + encodeURIComponent(id));
      renderPackage(data.package, data.deployments);
      if (!keepTab) {
        bootstrap.Tab.getOrCreateInstance(document.querySelector('#packageModal [data-bs-target="#pkg-overview"]')).show();
      }
      bootstrap.Modal.getOrCreateInstance(pkgModalEl).show();
    } catch (error) {
      U.notify(error.message || "The package could not be loaded.", "danger");
    }
  }

  async function savePackage() {
    const box = $("pkgError");
    box.hidden = true;
    let install;
    try {
      install = readInstall();
      if (!$("pkgName").value.trim()) {
        throw fieldError($("pkgName"), "Enter a package name.");
      }
    } catch (error) {
      showError(box, error);
      return;
    }
    if (currentPkg.status === "Approved" && JSON.stringify(install) !== installBaseline &&
      !window.confirm("Changing the install configuration returns this package to Pending review. It must be approved again before new deployments. Continue?")) {
      return;
    }
    $("pkgSave").disabled = true;
    try {
      const data = await U.api("/api/software/packages/" + encodeURIComponent(currentPkg.id), {
        method: "PATCH",
        body: {
          name: $("pkgName").value.trim(),
          version: $("pkgVersion").value.trim(),
          publisher: $("pkgPublisher").value.trim(),
          notes: $("pkgNotes").value.trim(),
          install: install
        }
      });
      U.notify("Package configuration saved.", "success");
      await openPackage(data.package.id, true);
      loadPackages();
    } catch (error) {
      showError(box, error);
    } finally {
      $("pkgSave").disabled = false;
    }
  }

  function approvePackage() {
    const p = currentPkg;
    const box = $("pkgError");
    box.hidden = true;
    if ((!$("ackUnscannedWrap").hidden && !$("ackUnscanned").checked) || (!$("ackUnsignedWrap").hidden && !$("ackUnsigned").checked)) {
      bootstrap.Tab.getOrCreateInstance(document.querySelector('#packageModal [data-bs-target="#pkg-overview"]')).show();
      showError(box, new Error("Confirm the acknowledgements in the overview before approving."));
      return;
    }
    if (p.installerType === "exe" && !(p.install && p.install.arguments)) {
      showError(box, fieldError($("cfgArguments"), "Save the silent-install arguments before approving."));
      return;
    }
    U.runAction({
      machineName: [p.name, p.version].filter(Boolean).join(" "),
      control: { label: "Approve package", description: "Approved packages can be deployed by administrators. The approval is recorded in the audit log.", reauth: true },
      submit: async function (values) {
        await U.api("/api/software/packages/" + encodeURIComponent(p.id) + "/approve", {
          method: "POST",
          body: {
            currentPassword: values.currentPassword,
            acknowledgeUnscanned: needsScanAck(p) && $("ackUnscanned").checked,
            acknowledgeUnsigned: needsSignatureAck(p) && $("ackUnsigned").checked
          }
        });
        U.notify("Package approved.", "success");
        openPackage(p.id, true);
        loadPackages();
      }
    });
  }

  function rejectPackage() {
    const p = currentPkg;
    U.runAction({
      machineName: [p.name, p.version].filter(Boolean).join(" "),
      control: { label: "Reject package", description: "Rejected packages cannot be deployed. Enter the reason below; it is shown to other administrators." },
      submit: async function (values) {
        if (!values.reason) {
          throw new Error("Enter a reason for rejecting this package.");
        }
        await U.api("/api/software/packages/" + encodeURIComponent(p.id) + "/reject", { method: "POST", body: { reason: values.reason } });
        U.notify("Package rejected.", "success");
        openPackage(p.id, true);
        loadPackages();
      }
    });
  }

  function deletePackage() {
    const p = currentPkg;
    U.runAction({
      machineName: [p.name, p.version].filter(Boolean).join(" "),
      control: { label: "Delete package", description: "Removes the installer file and its configuration. A package used by an active deployment cannot be deleted.", reauth: true },
      submit: async function (values) {
        await U.api("/api/software/packages/" + encodeURIComponent(p.id), { method: "DELETE", body: { currentPassword: values.currentPassword } });
        bootstrap.Modal.getOrCreateInstance(pkgModalEl).hide();
        U.notify("Package deleted.", "success");
        loadPackages();
      }
    });
  }

  // ---------- New deployment wizard ----------
  const wzModalEl = $("wizardModal");
  const wz = { step: 1, packageId: null, mode: "agents", groupIds: new Set(), excludeGroupIds: new Set(), validationId: null, validationSummary: null, preview: null, pickerLoaded: false };
  const wzPicker = createPicker($("wzPicker"), { capable: true, exclude: true, onChange: syncSelection });

  function approvedPackages() {
    return packages.filter(function (p) { return p.status === "Approved"; });
  }

  function selectedPackage() {
    return packages.find(function (p) { return p.id === wz.packageId; }) || null;
  }

  function groupChecks(container, set, name) {
    container.innerHTML = groups.length ? groups.map(function (g) {
      const id = name + "-" + U.escapeHtml(g.id);
      return '<div class="form-check"><input class="form-check-input" type="checkbox" id="' + id + '" data-group="' + U.escapeHtml(g.id) + '"' + (set.has(g.id) ? " checked" : "") + " />" +
        '<label class="form-check-label" for="' + id + '">' + U.escapeHtml(g.name) + ' <span class="subtle">(' + num(g.memberCount) + ")</span></label></div>";
    }).join("") : '<span class="subtle">No target groups. Create them on the Target groups tab.</span>';
  }

  function syncSelection() {
    const mode = wz.mode;
    const label = {
      all: "All agents with installation support",
      filter: wzPicker.total + " agents match the filter",
      agents: wzPicker.include.size + " selected",
      groups: wz.groupIds.size + (wz.groupIds.size === 1 ? " group selected" : " groups selected"),
      validation: num(wz.validationSummary && wz.validationSummary.eligible) + " from target validation"
    }[mode];
    $("wzSelCount").textContent = label;
    $("wzExclCount").textContent = wzPicker.exclude.size + " excluded";
    $("wzSelectMatching").hidden = mode !== "agents";
    $("wzClearSel").hidden = mode !== "agents";
    $("wzGroupsWrap").hidden = mode !== "groups";
    renderValidationPanel();
  }

  function setMode(mode) {
    wz.mode = mode;
    document.querySelectorAll('input[name="wzMode"]').forEach(function (r) { r.checked = r.value === mode; });
    const isValidation = mode === "validation";
    wzPicker.setColumns(mode === "agents", true);
    $("wzValidationWrap").hidden = !isValidation;
    $("wzSelectionBar").hidden = isValidation;
    $("wzPicker").hidden = isValidation;
    $("wzExcludeWrap").hidden = isValidation;
    syncSelection();
  }

  // ---------- Inline target validation (Targets step) ----------
  let validationPoll = null;

  function renderValidationPanel() {
    const active = wz.mode === "validation" && !!wz.validationId && wz.validationSummary;
    $("wzValidationActive").hidden = !active;
    $("wzValidationForm").hidden = active;
    if (active) {
      $("wzValidationCount").textContent = num(wz.validationSummary.eligible) + " systems";
    }
  }

  function resetValidation() {
    clearTimeout(validationPoll);
    wz.validationId = null;
    wz.validationSummary = null;
    $("wzValidationText").value = "";
    $("wzValidationProgress").hidden = true;
    $("wzValidationStart").disabled = false;
    renderValidationPanel();
    syncSelection();
  }

  function trackValidation(id) {
    clearTimeout(validationPoll);
    (function tick() {
      U.api("/api/deploy/targets/validations/" + encodeURIComponent(id)).then(function (data) {
        const v = data.validation;
        const pct = num(v.total) ? Math.min(100, Math.floor(num(v.checked) * 100 / num(v.total))) : 0;
        $("wzValidationBar").style.width = pct + "%";
        $("wzValidationStatus").textContent = num(v.checked) + " of " + num(v.total) + " checked";
        if (v.status === "Completed") {
          wz.validationId = v.id;
          wz.validationSummary = v.summary || {};
          $("wzValidationStart").disabled = false;
          $("wzValidationProgress").hidden = true;
          renderValidationPanel();
          syncSelection();
          return;
        }
        validationPoll = setTimeout(tick, 1000);
      }).catch(function (error) {
        U.notify(error.message || "Validation status could not be loaded.", "danger");
        $("wzValidationStart").disabled = false;
        $("wzValidationProgress").hidden = true;
      });
    })();
  }

  function startValidation() {
    const text = $("wzValidationText").value.trim();
    if (!text) {
      U.notify("Enter at least one system.", "warning");
      return;
    }
    $("wzValidationStart").disabled = true;
    $("wzValidationProgress").hidden = false;
    $("wzValidationBar").style.width = "0%";
    $("wzValidationStatus").textContent = "Starting\u2026";
    U.api("/api/deploy/targets/validate", {
      method: "POST",
      body: { kind: "software", text: text, checkDns: $("wzValidationDns").checked, checkReachability: $("wzValidationReach").checked }
    }).then(function (data) {
      trackValidation(data.validation.id);
    }).catch(function (error) {
      U.notify(error.message || "Validation could not be started.", "danger");
      $("wzValidationStart").disabled = false;
      $("wzValidationProgress").hidden = true;
    });
  }

  function showStep(step) {
    wz.step = step;
    document.querySelectorAll("#wizardModal [data-step]").forEach(function (pane) { pane.hidden = Number(pane.dataset.step) !== step; });
    document.querySelectorAll("#wizardModal .wizard-steps li").forEach(function (li) {
      const n = Number(li.dataset.for);
      li.classList.toggle("active", n === step);
      li.classList.toggle("complete", n < step);
    });
    $("wzBack").hidden = step === 1;
    $("wzNext").textContent = step === 4 ? "Start deployment" : "Next";
    $("wzNext").disabled = false;
    $("wzError").hidden = true;
    if (step === 2 && !wz.pickerLoaded) {
      wz.pickerLoaded = true;
      wzPicker.load();
    }
    if (step === 4) {
      runPreview();
    }
  }

  function renderWizardPackages() {
    const list = approvedPackages();
    $("wzPackages").innerHTML = list.length ? list.map(function (p) {
      const id = "wzPkg-" + U.escapeHtml(p.id);
      return '<tr><td class="col-check"><input class="form-check-input" type="radio" name="wzPackage" id="' + id + '" value="' + U.escapeHtml(p.id) + '"' + (p.id === wz.packageId ? " checked" : "") + " /></td>" +
        '<td><label class="cell-primary mb-0" for="' + id + '">' + plain(p.name) + "</label></td>" +
        '<td class="mono">' + plain(p.version) + "</td>" +
        "<td>" + plain(p.publisher) + "</td>" +
        '<td><span class="tag">' + U.escapeHtml(String(p.installerType || "").toUpperCase()) + "</span></td>" +
        '<td class="num nowrap">' + U.escapeHtml(U.formatBytes(p.size)) + "</td>" +
        "<td>" + mapPill(signatureStatus, p.signature && p.signature.status) + "</td></tr>";
    }).join("") : emptyRow(7, "No approved packages. Approve a package in the library first.");
  }

  function renderDays() {
    $("optDays").innerHTML = DAYS.map(function (d, i) {
      return '<div class="form-check form-check-inline me-0"><input class="form-check-input" type="checkbox" id="optDay' + i + '" value="' + i + '"' + (i > 0 && i < 6 ? " checked" : "") + " />" +
        '<label class="form-check-label" for="optDay' + i + '">' + d + "</label></div>";
    }).join("");
  }

  async function openWizard(packageId, validationId) {
    try {
      await Promise.all([loadPackages(), loadGroups(), settings ? Promise.resolve() : loadSettings()]);
    } catch (error) {
      U.notify(error.message || "Deployment data could not be loaded.", "danger");
      return;
    }
    if (!approvedPackages().length) {
      U.notify("Approve a package in the library before creating a deployment.", "warning");
      return;
    }
    wz.packageId = packageId || null;
    wz.groupIds.clear();
    wz.excludeGroupIds.clear();
    wz.preview = null;
    wz.pickerLoaded = false;
    resetValidation();
    wzPicker.reset();
    renderWizardPackages();
    groupChecks($("wzGroups"), wz.groupIds, "wzg");
    groupChecks($("wzExcludeGroups"), wz.excludeGroupIds, "wzx");
    $("optMaxConc").value = settings ? num(settings.maxConcurrent) || "" : "";
    $("optPerSite").value = settings ? num(settings.perSiteConcurrent) || "" : "";
    $("optAttempts").value = settings && settings.defaultMaxAttempts ? settings.defaultMaxAttempts : 3;
    $("optRestartBehavior").value = "package";
    $("wzName").value = "";
    if (validationId) {
      try {
        const data = await U.api("/api/deploy/targets/validations/" + encodeURIComponent(validationId));
        wz.validationId = data.validation.id;
        wz.validationSummary = data.validation.summary || {};
      } catch (error) {
        U.notify("The target validation could not be loaded.", "warning");
      }
    }
    setMode(wz.validationId ? "validation" : "agents");
    showStep(packageId ? 2 : 1);
    bootstrap.Modal.getOrCreateInstance(wzModalEl).show();
  }

  function selector() {
    if (wz.mode === "validation") {
      return { mode: "validation", validationId: wz.validationId };
    }
    return {
      mode: wz.mode,
      agentIds: wz.mode === "agents" ? Array.from(wzPicker.include) : [],
      groupIds: wz.mode === "groups" ? Array.from(wz.groupIds) : [],
      filter: wz.mode === "filter" ? wzPicker.filter() : {},
      excludeAgentIds: Array.from(wzPicker.exclude),
      excludeGroupIds: Array.from(wz.excludeGroupIds)
    };
  }

  function readOptions() {
    const later = $("optStartLater").checked;
    let startAt = null;
    if (later) {
      const value = $("optStartAt").value;
      const date = value ? new Date(value) : null;
      if (!date || Number.isNaN(date.getTime())) {
        throw fieldError($("optStartAt"), "Choose a start time.");
      }
      if (date.getTime() < Date.now() - 60000) {
        throw fieldError($("optStartAt"), "The start time is in the past.");
      }
      startAt = date.toISOString();
    }
    const windowOn = $("optWindow").checked;
    const days = Array.prototype.filter.call($("optDays").querySelectorAll("input"), function (i) { return i.checked; }).map(function (i) { return Number(i.value); });
    if (windowOn && !days.length) {
      throw fieldError($("optDay0"), "Choose at least one maintenance day.");
    }
    if (windowOn && (!$("optWinStart").value || !$("optWinEnd").value || $("optWinStart").value === $("optWinEnd").value)) {
      throw fieldError($("optWinStart"), "Enter different start and end times for the maintenance window.");
    }
    return {
      pilotCount: readInt("optPilot", "Pilot systems", 0),
      waveSize: readInt("optWave", "Wave size", 0),
      autoAdvance: $("optAutoAdvance").checked,
      waveDelayMinutes: readInt("optWaveDelay", "Delay between waves", 0),
      maxConcurrent: readInt("optMaxConc", "Maximum concurrent installs", 1),
      perSiteConcurrent: readInt("optPerSite", "Maximum concurrent per site", 1),
      failureThresholdPercent: readInt("optThreshold", "Failure threshold", 0, 100),
      failureMinSample: readInt("optMinSample", "Minimum sample", 1),
      onThreshold: $("optOnThreshold").value,
      maxAttempts: readInt("optAttempts", "Maximum attempts", 1, 10),
      retryDelayMinutes: readInt("optRetryDelay", "Retry delay", 0),
      startAt: startAt,
      maintenanceWindow: { enabled: windowOn, days: windowOn ? days : [], start: $("optWinStart").value, end: $("optWinEnd").value },
      offlineDeadlineHours: readInt("optOfflineHours", "Offline deadline", 1),
      restartBehavior: $("optRestartBehavior").value,
      force: $("optForce").checked
    };
  }

  function validateStep(step) {
    if (step === 1 && !selectedPackage()) {
      throw new Error("Choose a package.");
    }
    if (step === 2) {
      if (wz.mode === "agents" && !wzPicker.include.size) {
        throw new Error("Select at least one agent, or choose another targeting option.");
      }
      if (wz.mode === "groups" && !wz.groupIds.size) {
        throw new Error("Select at least one target group.");
      }
      if (wz.mode === "validation" && !wz.validationId) {
        throw new Error("Validate the systems before continuing.");
      }
    }
    if (step === 3) {
      wz.options = readOptions();
    }
  }

  const restartLabels = { package: "Use package setting", never: "Never restart", ifRequired: "Restart if required" };

  function describeTargets() {
    const sel = selector();
    if (sel.mode === "validation") {
      return num(wz.validationSummary && wz.validationSummary.eligible) + " systems from target validation";
    }
    let text = {
      all: "All agents with installation support",
      filter: "Agents matching the filter",
      agents: sel.agentIds.length + " selected agents",
      groups: groups.filter(function (g) { return wz.groupIds.has(g.id); }).map(function (g) { return g.name; }).join(", ")
    }[sel.mode];
    if (sel.mode === "filter") {
      const f = sel.filter;
      const parts = [f.q && "\u201c" + f.q + "\u201d", f.domain, f.site, f.os, f.connection !== "all" && f.connection].filter(Boolean);
      text += parts.length ? ": " + parts.join(", ") : " (no filter, all agents)";
    }
    const excl = [];
    if (sel.excludeAgentIds.length) { excl.push(sel.excludeAgentIds.length + " agents"); }
    if (sel.excludeGroupIds.length) { excl.push(sel.excludeGroupIds.length + " groups"); }
    return text + (excl.length ? "; excluding " + excl.join(" and ") : "");
  }

  function renderSummary() {
    const o = wz.options;
    const p = selectedPackage();
    const w = o.maintenanceWindow;
    $("wzSummary").innerHTML = kv([
      ["Package", plain([p.name, p.version].filter(Boolean).join(" "))],
      ["Targets", plain(describeTargets())],
      ["Waves", plain((o.pilotCount ? "Pilot of " + o.pilotCount + ", then " : "") + (o.waveSize ? o.waveSize + " per wave" : "all remaining at once") + (o.autoAdvance ? ", advancing automatically after " + o.waveDelayMinutes + " min" : ", advanced manually"))],
      ["Concurrency", plain(o.maxConcurrent + " at a time, " + o.perSiteConcurrent + " per site")],
      ["Failure threshold", plain(o.failureThresholdPercent + "% after " + o.failureMinSample + " results, then " + (o.onThreshold === "cancel" ? "cancel" : "pause"))],
      ["Retries", plain(o.maxAttempts + " attempts, " + o.retryDelayMinutes + " min apart")],
      ["Start", plain(o.startAt ? U.formatDateTime(o.startAt) : "Immediately")],
      ["Maintenance window", plain(w.enabled ? w.days.map(function (d) { return DAYS[d]; }).join(", ") + " " + w.start + "\u2013" + w.end : "Any time")],
      ["Offline systems", plain("Wait up to " + o.offlineDeadlineHours + " hours")],
      ["Restart behaviour", plain(restartLabels[o.restartBehavior] || o.restartBehavior)],
      ["Reinstall", plain(o.force ? "Yes, even when already installed" : "No, skip systems where it is detected")]
    ]);
  }

  async function runPreview() {
    renderSummary();
    $("wzPreviewTiles").innerHTML = '<div class="subtle">Calculating targets\u2026</div>';
    $("wzSkipped").innerHTML = "";
    $("wzSample").innerHTML = emptyRow(5, "Loading\u2026");
    $("wzNext").disabled = true;
    const p = selectedPackage();
    if (!$("wzName").value.trim()) {
      $("wzName").value = [p.name, p.version].filter(Boolean).join(" ");
    }
    try {
      const data = await U.api("/api/deploy/preview", {
        method: "POST",
        body: { kind: "software", packageId: wz.packageId, selector: selector(), options: { force: wz.options.force } }
      });
      wz.preview = data;
      const skipped = data.skipped || {};
      const skippedTotal = Object.keys(skipped).reduce(function (sum, k) { return sum + num(skipped[k]); }, 0);
      $("wzPreviewTiles").innerHTML =
        '<div class="tile"><div class="label">Targeted</div><div class="value">' + num(data.total) + "</div></div>" +
        '<div class="tile tone-good"><div class="label">Will install</div><div class="value">' + num(data.eligible) + "</div></div>" +
        '<div class="tile tone-warn"><div class="label">Skipped</div><div class="value">' + skippedTotal + "</div></div>";
      $("wzSkipped").innerHTML = Object.keys(skipped).length
        ? kv(Object.keys(skipped).map(function (k) { return [k, String(num(skipped[k]))]; }))
        : "<dt>None</dt><dd>Every targeted system is eligible.</dd>";
      $("wzSample").innerHTML = (data.sample || []).length ? data.sample.map(function (s) {
        return '<tr><td><span class="id-chip">' + plain(s.displayId) + "</span></td><td>" + plain(s.machineName) + "</td><td>" + plain(s.site) + "</td>" +
          "<td>" + (s.eligible ? U.pill("success", "Yes") : U.pill("neutral", "No")) + "</td><td>" + plain(s.reason) + "</td></tr>";
      }).join("") : emptyRow(5, "No systems are targeted.");
      if (!num(data.eligible)) {
        showError($("wzError"), new Error("No system is eligible for this deployment. Change the targets or options."));
        return;
      }
      $("wzNext").disabled = false;
    } catch (error) {
      $("wzPreviewTiles").innerHTML = "";
      $("wzSample").innerHTML = emptyRow(5, "Preview unavailable.");
      showError($("wzError"), error);
    }
  }

  function startDeployment() {
    const name = $("wzName").value.trim();
    if (!name) {
      showError($("wzError"), fieldError($("wzName"), "Enter a deployment name."));
      return;
    }
    const p = selectedPackage();
    const body = {
      kind: "software",
      packageId: wz.packageId,
      name: name,
      selector: selector(),
      options: wz.options,
      confirmed: true,
      confirmText: name
    };
    U.runAction({
      machineName: name,
      control: {
        label: "Start deployment",
        description: "Installs " + [p.name, p.version].filter(Boolean).join(" ") + " on up to " + num(wz.preview && wz.preview.eligible) + " systems" + (wz.options.startAt ? " starting " + U.formatDateTime(wz.options.startAt) : "") + ".",
        sensitive: true,
        reauth: true
      },
      submit: async function (values) {
        body.currentPassword = values.currentPassword;
        body.reason = values.reason;
        const data = await U.api("/api/deployments", { method: "POST", body: body });
        delete body.currentPassword;
        window.location.href = "/deployment-center/jobs/" + encodeURIComponent(data.job.id);
      }
    });
  }

  // ---------- Target groups ----------
  const grpModalEl = $("groupModal");
  let editingGroup = null;
  const grpPicker = createPicker($("grpPicker"), { capable: false, exclude: false, onChange: syncGroupSelection });

  function groupType() {
    return document.querySelector('input[name="grpType"]:checked').value;
  }

  function syncGroupSelection() {
    const isStatic = groupType() === "static";
    $("grpSelCount").textContent = isStatic
      ? grpPicker.include.size + (grpPicker.include.size === 1 ? " agent selected" : " agents selected")
      : grpPicker.total + " agents currently match";
  }

  function renderGroups() {
    const cat = $("grpCategoryFilter").value;
    const list = cat ? groups.filter(function (g) { return (g.category || "other") === cat; }) : groups;
    $("cntGroups").textContent = groups.length;
    $("grpCount").textContent = list.length + " of " + groups.length + (groups.length === 1 ? " group" : " groups");
    $("groupBody").innerHTML = list.length ? list.map(function (g) {
      const actions = isAdmin
        ? '<button type="button" class="btn btn-sm btn-outline-secondary" data-act="edit">Edit</button> <button type="button" class="btn btn-sm btn-outline-danger" data-act="delete" aria-label="Delete group"><i class="bi bi-trash"></i></button>'
        : "";
      return '<tr data-id="' + U.escapeHtml(g.id) + '">' +
        '<td><span class="cell-primary">' + plain(g.name) + "</span></td>" +
        "<td>" + (g.type === "dynamic" ? U.pill("info", "Dynamic") : U.pill("neutral", "Static")) + "</td>" +
        '<td><span class="tag">' + U.escapeHtml(categoryLabels[g.category] || "Other") + "</span></td>" +
        '<td class="num">' + num(g.memberCount) + "</td>" +
        '<td><span class="truncate d-inline-block" title="' + U.escapeHtml(g.description || "") + '">' + plain(g.description) + "</span></td>" +
        '<td class="nowrap">' + when(g.updatedUtc) + "</td>" +
        "<td>" + plain(g.createdBy) + "</td>" +
        '<td class="text-end nowrap">' + actions + "</td></tr>";
    }).join("") : emptyRow(8, groups.length ? "No groups in this category." : "No target groups yet.");
  }

  async function loadGroups() {
    try {
      const data = await U.api("/api/deploy/groups");
      groups = data.groups || [];
      renderGroups();
    } catch (error) {
      $("groupBody").innerHTML = emptyRow(8, error.message || "Groups could not be loaded.");
    }
  }

  function openGroup(group) {
    editingGroup = group || null;
    $("groupTitle").textContent = group ? "Edit target group" : "New target group";
    $("grpName").value = group ? group.name : "";
    $("grpCategory").value = group ? (group.category || "other") : "other";
    $("grpDesc").value = group ? group.description || "" : "";
    const type = group ? group.type : "static";
    document.querySelectorAll('input[name="grpType"]').forEach(function (r) { r.checked = r.value === type; });
    grpPicker.reset(group && group.type === "dynamic" ? group.filter : null);
    if (group && group.type === "static") {
      (group.agentIds || []).forEach(function (id) { grpPicker.include.add(id); });
    }
    grpPicker.setColumns(type === "static", false);
    $("grpError").hidden = true;
    grpPicker.load();
    syncGroupSelection();
    bootstrap.Modal.getOrCreateInstance(grpModalEl).show();
  }

  async function saveGroup() {
    const box = $("grpError");
    box.hidden = true;
    const type = groupType();
    const name = $("grpName").value.trim();
    if (!name) {
      showError(box, fieldError($("grpName"), "Enter a group name."));
      return;
    }
    if (type === "static" && !grpPicker.include.size) {
      showError(box, new Error("Select at least one agent for a static group."));
      return;
    }
    const body = {
      name: name,
      category: $("grpCategory").value,
      description: $("grpDesc").value.trim(),
      type: type,
      agentIds: type === "static" ? Array.from(grpPicker.include) : [],
      filter: type === "dynamic" ? grpPicker.filter() : null
    };
    $("grpSave").disabled = true;
    try {
      await U.api("/api/deploy/groups" + (editingGroup ? "/" + encodeURIComponent(editingGroup.id) : ""), { method: editingGroup ? "PATCH" : "POST", body: body });
      bootstrap.Modal.getOrCreateInstance(grpModalEl).hide();
      U.notify(editingGroup ? "Group updated." : "Group created.", "success");
      loadGroups();
    } catch (error) {
      showError(box, error);
    } finally {
      $("grpSave").disabled = false;
    }
  }

  function deleteGroup(group) {
    U.runAction({
      machineName: group.name,
      control: { label: "Delete group", description: "Deployments that already started keep their resolved targets." },
      submit: async function () {
        await U.api("/api/deploy/groups/" + encodeURIComponent(group.id), { method: "DELETE" });
        U.notify("Group deleted.", "success");
        loadGroups();
      }
    });
  }

  // ---------- Secrets ----------
  const secModalEl = $("secretModal");
  let rotatingSecret = null;

  function renderSecrets() {
    $("cntSecrets").textContent = secrets.length;
    $("secretBody").innerHTML = secrets.length ? secrets.map(function (s) {
      const actions = isAdmin
        ? '<button type="button" class="btn btn-sm btn-outline-secondary" data-act="rotate">Rotate</button> <button type="button" class="btn btn-sm btn-outline-danger" data-act="delete" aria-label="Delete secret"><i class="bi bi-trash"></i></button>'
        : "";
      return '<tr data-name="' + U.escapeHtml(s.name) + '">' +
        '<td><span class="cell-primary mono"><i class="bi bi-key" aria-hidden="true"></i>' + plain(s.name) + "</span></td>" +
        "<td>" + plain(s.description) + "</td>" +
        '<td class="nowrap">' + U.escapeHtml(U.formatDateTime(s.createdUtc)) + '<div class="subtle">' + plain(s.createdBy) + "</div></td>" +
        '<td class="nowrap">' + when(s.rotatedUtc) + "</td>" +
        '<td class="nowrap">' + when(s.lastUsedUtc) + "</td>" +
        '<td class="num">' + num(s.useCount) + "</td>" +
        '<td class="text-end nowrap">' + actions + "</td></tr>";
    }).join("") : emptyRow(7, "No secrets stored.");
  }

  async function loadSecrets() {
    if (!isAdmin) {
      return;
    }
    try {
      const data = await U.api("/api/deploy/secrets");
      secrets = data.secrets || [];
      renderSecrets();
    } catch (error) {
      $("secretBody").innerHTML = emptyRow(7, error.message || "Secrets could not be loaded.");
    }
  }

  function openSecret(secret) {
    rotatingSecret = secret || null;
    $("secretTitle").textContent = secret ? "Rotate secret " + secret.name : "Add secret";
    $("secNameWrap").hidden = !!secret;
    $("secDescWrap").hidden = !!secret;
    $("secName").value = "";
    $("secDesc").value = "";
    $("secValue").value = "";
    $("secReauth").value = "";
    $("secError").hidden = true;
    $("secSave").textContent = secret ? "Rotate secret" : "Save secret";
    bootstrap.Modal.getOrCreateInstance(secModalEl).show();
  }

  async function saveSecret() {
    const box = $("secError");
    box.hidden = true;
    const name = $("secName").value.trim();
    if (!rotatingSecret && !/^[A-Za-z0-9_.-]{1,64}$/.test(name)) {
      showError(box, fieldError($("secName"), "Use letters, digits, dots, dashes and underscores only."));
      return;
    }
    if (!$("secValue").value) {
      showError(box, fieldError($("secValue"), "Enter the secret value."));
      return;
    }
    if (!$("secReauth").value) {
      showError(box, fieldError($("secReauth"), "Enter your portal password."));
      return;
    }
    $("secSave").disabled = true;
    try {
      if (rotatingSecret) {
        await U.api("/api/deploy/secrets/" + encodeURIComponent(rotatingSecret.name), {
          method: "PUT",
          body: { value: $("secValue").value, currentPassword: $("secReauth").value }
        });
      } else {
        await U.api("/api/deploy/secrets", {
          method: "POST",
          body: { name: name, value: $("secValue").value, description: $("secDesc").value.trim(), currentPassword: $("secReauth").value }
        });
      }
      bootstrap.Modal.getOrCreateInstance(secModalEl).hide();
      U.notify(rotatingSecret ? "Secret rotated." : "Secret saved.", "success");
      loadSecrets();
    } catch (error) {
      showError(box, error);
    } finally {
      $("secValue").value = "";
      $("secReauth").value = "";
      $("secSave").disabled = false;
    }
  }

  function deleteSecret(secret) {
    U.runAction({
      machineName: secret.name,
      control: { label: "Delete secret", description: "Installer arguments that reference this secret fail until it is added again.", reauth: true },
      submit: async function (values) {
        await U.api("/api/deploy/secrets/" + encodeURIComponent(secret.name), { method: "DELETE", body: { currentPassword: values.currentPassword } });
        U.notify("Secret deleted.", "success");
        loadSecrets();
      }
    });
  }

  // ---------- Settings ----------
  function siteRow(site) {
    return '<div class="site-row">' +
      '<input class="form-control form-control-sm" data-site="name" placeholder="Site name" maxlength="100" aria-label="Site name" value="' + U.escapeHtml(site.name || "") + '" />' +
      '<input class="form-control form-control-sm mono" data-site="cidrs" placeholder="10.1.0.0/16, 10.2.0.0/24" aria-label="CIDR ranges" spellcheck="false" value="' + U.escapeHtml((site.cidrs || []).join(", ")) + '" />' +
      '<button type="button" class="btn btn-sm btn-outline-secondary" data-site="remove" aria-label="Remove site"' + (isAdmin ? "" : " hidden") + '><i class="bi bi-x-lg"></i></button>' +
      "</div>";
  }

  function renderSettings() {
    const s = settings;
    $("siteRows").innerHTML = (s.sites || []).length ? s.sites.map(siteRow).join("") : '<p class="subtle" data-empty>No sites defined. All agents share the global limits.</p>';
    $("setMaxConcurrent").value = s.maxConcurrent || "";
    $("setPerSite").value = s.perSiteConcurrent || "";
    $("setMaxAttempts").value = s.defaultMaxAttempts || "";
    $("setHeartbeat").value = s.agentHeartbeatSeconds || "";
    $("settingsFields").disabled = !isAdmin;
    const scanner = s.scanner || {};
    $("scannerKv").innerHTML = kv([
      ["Status", scanner.available ? U.pill("success", "Available", true) : U.pill("warning", "Unavailable", true)],
      ["Engine", plain(scanner.engine)],
      ["Mode", plain(scanner.mode)]
    ]);
    const l = s.limits || {};
    const quota = num(l.storageQuotaGb) * 1073741824;
    const used = num(l.usedBytes);
    $("storageKv").innerHTML = kv([
      ["Used", plain(U.formatBytes(used) + (quota ? " of " + U.formatBytes(quota) : "")) +
        (quota ? '<div class="seg-bar mt-1"><span class="' + (used / quota > 0.9 ? "seg-fail" : "seg-run") + '" style="width:' + Math.min(100, used * 100 / quota).toFixed(1) + '%"></span></div>' : "")],
      ["Free disk", plain(U.formatBytes(l.freeBytes))],
      ["Maximum package size", plain(l.maxPackageMb ? l.maxPackageMb + " MB" : "")]
    ]);
  }

  async function loadSettings() {
    const data = await U.api("/api/deploy/settings");
    settings = data;
    renderSettings();
  }

  function readSites() {
    const seen = new Set();
    return Array.prototype.map.call($("siteRows").querySelectorAll(".site-row"), function (row) {
      const nameInput = row.querySelector('[data-site="name"]');
      const cidrInput = row.querySelector('[data-site="cidrs"]');
      const name = nameInput.value.trim();
      if (!name) {
        throw fieldError(nameInput, "Enter a name for every site.");
      }
      if (seen.has(name.toLowerCase())) {
        throw fieldError(nameInput, "Site names must be unique.");
      }
      seen.add(name.toLowerCase());
      const cidrs = cidrInput.value.split(/[\s,;]+/).filter(Boolean);
      if (!cidrs.length) {
        throw fieldError(cidrInput, "Enter at least one CIDR range for " + name + ".");
      }
      cidrs.forEach(function (c) {
        if (!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(c) && !/^[0-9a-fA-F:]+\/\d{1,3}$/.test(c)) {
          throw fieldError(cidrInput, c + " is not a valid CIDR range.");
        }
      });
      return { name: name, cidrs: cidrs };
    });
  }

  async function saveSettings() {
    let body;
    try {
      body = {
        sites: readSites(),
        maxConcurrent: readInt("setMaxConcurrent", "Maximum concurrent installs", 1),
        perSiteConcurrent: readInt("setPerSite", "Maximum concurrent per site", 1),
        defaultMaxAttempts: readInt("setMaxAttempts", "Default maximum attempts", 1, 10),
        agentHeartbeatSeconds: readInt("setHeartbeat", "Agent heartbeat interval", 5, 300)
      };
    } catch (error) {
      U.notify(error.message, "warning");
      if (error.input) {
        error.input.focus();
      }
      return;
    }
    $("settingsSave").disabled = true;
    try {
      await U.api("/api/deploy/settings", { method: "PUT", body: body });
      U.notify("Deployment settings saved.", "success");
      await loadSettings();
    } catch (error) {
      U.notify(error.message || "Settings could not be saved.", "danger");
    } finally {
      $("settingsSave").disabled = false;
    }
  }

  // ---------- Events ----------
  function bindRowActions(tbody, key, handlers) {
    tbody.addEventListener("click", function (event) {
      const row = event.target.closest("tr[data-" + key + "]");
      if (!row) {
        return;
      }
      const btn = event.target.closest("button[data-act]");
      const act = btn ? btn.dataset.act : (row.classList.contains("row-link") ? "row" : null);
      if (act && handlers[act]) {
        handlers[act](row.dataset[key]);
      }
    });
    tbody.addEventListener("keydown", function (event) {
      const row = event.target.closest("tr.row-link[data-" + key + "]");
      if (event.key === "Enter" && row && event.target === row && handlers.row) {
        handlers.row(row.dataset[key]);
      }
    });
  }

  $("libSearch").addEventListener("input", renderLibrary);
  $("libStatus").addEventListener("change", renderLibrary);
  $("uploadBtn").addEventListener("click", function () { $("uploadInput").click(); });
  $("uploadInput").addEventListener("change", function (event) {
    const file = event.target.files && event.target.files[0];
    event.target.value = "";
    if (file) {
      uploadPackage(file);
    }
  });
  bindRowActions($("libBody"), "id", {
    row: function (id) { openPackage(id); },
    details: function (id) { openPackage(id); },
    deploy: function (id) { openWizard(id); }
  });
  $("newDeployBtn").addEventListener("click", function () { openWizard(null); });

  $("cfgDetType").addEventListener("change", syncDetection);
  $("pkgForm").addEventListener("submit", function (event) { event.preventDefault(); savePackage(); });
  $("pkgApprove").addEventListener("click", approvePackage);
  $("pkgReject").addEventListener("click", rejectPackage);
  $("pkgDelete").addEventListener("click", deletePackage);
  $("pkgDeploy").addEventListener("click", function () {
    const id = currentPkg.id;
    pkgModalEl.addEventListener("hidden.bs.modal", function () { openWizard(id); }, { once: true });
    bootstrap.Modal.getOrCreateInstance(pkgModalEl).hide();
  });

  $("wzPackages").addEventListener("change", function (event) {
    if (event.target.name === "wzPackage") {
      wz.packageId = event.target.value;
    }
  });
  document.querySelectorAll('input[name="wzMode"]').forEach(function (r) {
    r.addEventListener("change", function () { setMode(r.value); });
  });
  $("wzGroups").addEventListener("change", function (event) {
    const id = event.target.dataset.group;
    if (id) {
      if (event.target.checked) { wz.groupIds.add(id); } else { wz.groupIds.delete(id); }
      syncSelection();
    }
  });
  $("wzExcludeGroups").addEventListener("change", function (event) {
    const id = event.target.dataset.group;
    if (id) {
      if (event.target.checked) { wz.excludeGroupIds.add(id); } else { wz.excludeGroupIds.delete(id); }
    }
  });
  $("wzSelectMatching").addEventListener("click", function () {
    wzPicker.include.clear();
    setMode("filter");
  });
  $("wzClearSel").addEventListener("click", function () {
    wzPicker.include.clear();
    wzPicker.setColumns(wz.mode === "agents", true);
    syncSelection();
  });
  $("wzClearExcl").addEventListener("click", function () {
    wzPicker.exclude.clear();
    wzPicker.setColumns(wz.mode === "agents", true);
    syncSelection();
  });
  $("wzValidationStart").addEventListener("click", startValidation);
  $("wzValidationReset").addEventListener("click", resetValidation);
  $("optStartNow").addEventListener("change", function () { $("optStartAt").disabled = true; });
  $("optStartLater").addEventListener("change", function () { $("optStartAt").disabled = false; $("optStartAt").focus(); });
  $("optWindow").addEventListener("change", function () { $("optWindowFields").hidden = !$("optWindow").checked; });
  $("wzBack").addEventListener("click", function () { showStep(wz.step - 1); });
  $("wzForm").addEventListener("submit", function (event) {
    event.preventDefault();
    if (wz.step === 4) {
      startDeployment();
      return;
    }
    try {
      validateStep(wz.step);
      showStep(wz.step + 1);
    } catch (error) {
      showError($("wzError"), error);
    }
  });

  $("newGroupBtn").addEventListener("click", function () { openGroup(null); });
  document.querySelectorAll('input[name="grpType"]').forEach(function (r) {
    r.addEventListener("change", function () {
      grpPicker.setColumns(groupType() === "static", false);
      syncGroupSelection();
    });
  });
  $("groupForm").addEventListener("submit", function (event) { event.preventDefault(); saveGroup(); });
  $("grpCategoryFilter").addEventListener("change", renderGroups);
  bindRowActions($("groupBody"), "id", {
    edit: function (id) { openGroup(groups.find(function (g) { return g.id === id; })); },
    delete: function (id) { deleteGroup(groups.find(function (g) { return g.id === id; })); }
  });

  $("newSecretBtn").addEventListener("click", function () { openSecret(null); });
  $("secretForm").addEventListener("submit", function (event) { event.preventDefault(); saveSecret(); });
  secModalEl.addEventListener("hidden.bs.modal", function () {
    $("secValue").value = "";
    $("secReauth").value = "";
  });
  bindRowActions($("secretBody"), "name", {
    rotate: function (name) { openSecret(secrets.find(function (s) { return s.name === name; })); },
    delete: function (name) { deleteSecret(secrets.find(function (s) { return s.name === name; })); }
  });

  $("addSiteBtn").addEventListener("click", function () {
    const empty = $("siteRows").querySelector("[data-empty]");
    if (empty) {
      empty.remove();
    }
    $("siteRows").insertAdjacentHTML("beforeend", siteRow({ name: "", cidrs: [] }));
    $("siteRows").lastElementChild.querySelector("input").focus();
  });
  $("siteRows").addEventListener("click", function (event) {
    const btn = event.target.closest('[data-site="remove"]');
    if (btn) {
      btn.closest(".site-row").remove();
    }
  });
  $("settingsForm").addEventListener("submit", function (event) { event.preventDefault(); saveSettings(); });

  setAdminVisibility();
  renderDays();
  initTabs();
  loadPackages();
  loadGroups();
  loadSecrets();
  loadSettings().catch(function (error) { U.notify(error.message || "Deployment settings could not be loaded.", "danger"); });
  checkDeployHash();
})();
