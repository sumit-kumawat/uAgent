(function () {
  "use strict";
  const U = window.uAgent;
  const card = document.getElementById("uninstallKeyCard");
  const modalEl = document.getElementById("ukModal");
  if (!card || !modalEl) {
    return;
  }
  const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
  const q = function (role) { return modalEl.querySelector('[data-role="' + role + '"]'); };
  const reason = document.getElementById("ukReason");
  const password = document.getElementById("ukPassword");
  const value = document.getElementById("ukValue");
  const stored = document.getElementById("ukStored");
  let pending = null;
  let showingKey = false;

  function row(label, html) {
    return "<dt>" + U.escapeHtml(label) + "</dt><dd>" + html + "</dd>";
  }

  function render(status) {
    const rows = [];
    if (status.configured) {
      rows.push(row("Status", U.pill("success", "Configured", true)));
      rows.push(row("Key", '<span class="mono">' + U.escapeHtml(status.keyId) + "</span> <span class=\"subtle\">ending " + U.escapeHtml(status.hint) + "</span>"));
      rows.push(row("Created", U.escapeHtml(U.formatDateTime(status.createdUtc)) + (status.createdBy ? " by " + U.escapeHtml(status.createdBy) : "")));
    } else if (status.revoked) {
      rows.push(row("Status", U.pill("danger", "Revoked", true)));
      rows.push(row("Revoked", U.escapeHtml(U.formatDateTime(status.revoked.utc)) + " by " + U.escapeHtml(status.revoked.by) + ". Agents cannot be removed until a new key is generated."));
    } else {
      rows.push(row("Status", U.pill("warning", "Not generated", true)));
      rows.push(row("Effect", "Agents cannot be removed until a key is generated."));
    }
    rows.push(row("Portal identity", '<span class="mono">' + U.escapeHtml(String(status.portalId || "").slice(0, 8)) + "</span> <span class=\"subtle\">keys from other portals are not accepted</span>"));
    card.querySelector('[data-role="uk-status"]').innerHTML = rows.join("");
    const actions = [];
    if (status.configured) {
      actions.push('<button type="button" class="btn btn-sm btn-outline-primary" data-uk="issue"><i class="bi bi-arrow-repeat me-1" aria-hidden="true"></i>Rotate key</button>');
      actions.push('<button type="button" class="btn btn-sm btn-outline-danger" data-uk="revoke"><i class="bi bi-slash-circle me-1" aria-hidden="true"></i>Revoke</button>');
    } else {
      actions.push('<button type="button" class="btn btn-sm btn-primary" data-uk="issue"><i class="bi bi-key me-1" aria-hidden="true"></i>Generate key</button>');
    }
    card.querySelector('[data-role="uk-actions"]').innerHTML = actions.join("");
    card.dataset.configured = status.configured ? "1" : "0";
  }

  async function load() {
    try {
      render(await U.api("/api/settings/uninstall-key"));
    } catch (error) {
      card.querySelector('[data-role="uk-status"]').innerHTML = row("Status", '<span class="text-danger">' + U.escapeHtml(error.message) + "</span>");
    }
  }

  function readyToConfirm() {
    return reason.value.trim().length >= 5 && password.value.length > 0;
  }

  function refresh() {
    q("confirm").disabled = showingKey ? !stored.checked : !readyToConfirm();
  }

  function open(action) {
    pending = action;
    showingKey = false;
    const rotating = card.dataset.configured === "1";
    q("title").textContent = action === "revoke" ? "Revoke the uninstall verification key" : rotating ? "Rotate the uninstall verification key" : "Generate an uninstall verification key";
    q("summary").textContent = action === "revoke"
      ? "Agents cannot be removed until a new key is generated. Removals already queued are not affected."
      : rotating
        ? "A new key replaces the current one immediately. The current key stops working."
        : "The key is shown once. Anyone removing an agent will need it, together with their password.";
    q("step-confirm").classList.remove("d-none");
    q("step-key").classList.add("d-none");
    q("error").classList.add("d-none");
    q("cancel").classList.remove("d-none");
    q("confirm").className = "btn btn-sm " + (action === "revoke" ? "btn-danger" : "btn-primary");
    q("confirm").textContent = action === "revoke" ? "Revoke key" : rotating ? "Rotate key" : "Generate key";
    reason.value = "";
    password.value = "";
    value.value = "";
    stored.checked = false;
    refresh();
    modal.show();
  }

  [reason, password, stored].forEach(function (input) { input.addEventListener("input", refresh); input.addEventListener("change", refresh); });

  card.addEventListener("click", function (event) {
    const button = event.target.closest("[data-uk]");
    if (button) {
      open(button.getAttribute("data-uk"));
    }
  });

  q("copy").addEventListener("click", function () {
    if (value.value && navigator.clipboard) {
      navigator.clipboard.writeText(value.value).then(function () { U.notify("Key copied to the clipboard.", "info"); }, function () {});
    }
  });

  modalEl.querySelector("form").addEventListener("submit", async function (event) {
    event.preventDefault();
    if (showingKey) {
      if (stored.checked) {
        modal.hide();
      }
      return;
    }
    if (!readyToConfirm()) {
      return;
    }
    q("confirm").disabled = true;
    q("error").classList.add("d-none");
    try {
      const result = await U.api("/api/settings/uninstall-key", {
        method: "POST",
        body: { action: pending, reason: reason.value.trim(), currentPassword: password.value }
      });
      password.value = "";
      render(result);
      if (pending === "revoke") {
        modal.hide();
        U.notify("The uninstall verification key was revoked.", "info");
        return;
      }
      showingKey = true;
      value.value = result.key;
      q("step-confirm").classList.add("d-none");
      q("step-key").classList.remove("d-none");
      q("cancel").classList.add("d-none");
      q("confirm").className = "btn btn-sm btn-primary";
      q("confirm").textContent = "Done";
      refresh();
    } catch (error) {
      password.value = "";
      q("error").textContent = error.message || "The key could not be changed.";
      q("error").classList.remove("d-none");
      refresh();
    }
  });

  modalEl.addEventListener("hide.bs.modal", function (event) {
    if (showingKey && !stored.checked) {
      event.preventDefault();
      q("error").textContent = "Confirm that you have stored the key before closing. It is not shown again.";
      q("error").classList.remove("d-none");
    }
  });

  modalEl.addEventListener("hidden.bs.modal", function () {
    value.value = "";
    password.value = "";
    showingKey = false;
  });

  load();
})();
