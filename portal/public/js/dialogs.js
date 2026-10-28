// Lightbox dialogs shared by every page: password change (forced after the first sign-in) and the
// DNS/FQDN wizard that sets the address agents contact.
(function () {
  "use strict";
  const U = window.uAgent;
  const MIN_PASSWORD = 6;
  const HOST_PROMPT_KEY = "uagent.hostPromptDismissed";

  function busy(button, on) {
    button.disabled = on;
    const spinner = button.querySelector(".spinner-border");
    if (spinner) { spinner.hidden = !on; }
  }

  function showStep(root, step) {
    root.querySelectorAll("[data-step]").forEach(function (el) { el.hidden = el.getAttribute("data-step") !== step; });
    root.querySelectorAll(".wizard-steps li").forEach(function (li) {
      const order = ["enter", "review", "done"];
      const at = order.indexOf(step);
      const mine = order.indexOf(li.getAttribute("data-for"));
      li.classList.toggle("active", mine === at);
      li.classList.toggle("complete", mine < at);
    });
  }

  function fieldError(input, message) {
    input.classList.toggle("is-invalid", Boolean(message));
    const feedback = input.parentElement.querySelector(".invalid-feedback");
    if (feedback) { feedback.textContent = message || ""; }
  }

  function banner(root, message) {
    const box = root.querySelector("[data-error]");
    box.textContent = message || "";
    box.hidden = !message;
  }

  // --- Password -------------------------------------------------------------------------------
  function initPassword() {
    const modalEl = document.getElementById("passwordModal");
    if (!modalEl) { return null; }
    const form = document.getElementById("passwordForm");
    const current = document.getElementById("pwCurrent");
    const next = document.getElementById("pwNew");
    const confirm = document.getElementById("pwConfirm");
    const submit = form.querySelector("[data-submit]");
    const forced = document.body.getAttribute("data-must-change") === "1";
    const user = (document.body.getAttribute("data-user") || "").toLowerCase();
    const modal = new bootstrap.Modal(modalEl, forced ? { backdrop: "static", keyboard: false } : { backdrop: true, keyboard: true });

    modalEl.querySelectorAll("[data-forced-text]").forEach(function (el) { el.hidden = !forced; });
    modalEl.querySelectorAll("[data-dismiss-optional]").forEach(function (el) { el.hidden = forced; });

    function validate(final) {
      let ok = true;
      const value = next.value;
      let nextMessage = "";
      if (value.length > 0 || final) {
        if (value.length < MIN_PASSWORD) { nextMessage = "Use at least " + MIN_PASSWORD + " characters."; }
        else if (value === current.value) { nextMessage = "Choose a password that is different from the current one."; }
        else if (user && value.toLowerCase() === user) { nextMessage = "The password cannot match the username."; }
      }
      fieldError(next, nextMessage);
      ok = ok && !nextMessage;
      const confirmMessage = (confirm.value.length > 0 || final) && confirm.value !== value ? "The passwords do not match." : "";
      fieldError(confirm, confirmMessage);
      ok = ok && !confirmMessage;
      const currentMessage = final && !current.value ? "Enter your current password." : "";
      fieldError(current, currentMessage);
      return ok && !currentMessage;
    }

    [current, next, confirm].forEach(function (input) { input.addEventListener("input", function () { validate(false); }); });

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      banner(modalEl, "");
      if (!validate(true)) { return; }
      busy(submit, true);
      try {
        await U.api("/api/account/password", { method: "POST", body: { currentPassword: current.value, newPassword: next.value, confirmPassword: confirm.value } });
        form.reset();
        showStep(modalEl, "done");
      } catch (error) {
        const field = error.payload && error.payload.field;
        const target = field === "currentPassword" ? current : field === "confirmPassword" ? confirm : field === "newPassword" ? next : null;
        if (target) { fieldError(target, error.message); target.focus(); } else { banner(modalEl, error.message); }
      } finally {
        busy(submit, false);
      }
    });

    modalEl.querySelector("[data-finish]").addEventListener("click", function () {
      if (forced) {
        window.location.href = "/";
        return;
      }
      modal.hide();
      U.notify("Password changed.");
    });

    modalEl.addEventListener("hidden.bs.modal", function () {
      form.reset();
      [current, next, confirm].forEach(function (input) { fieldError(input, ""); });
      banner(modalEl, "");
      showStep(modalEl, "form");
    });
    modalEl.addEventListener("shown.bs.modal", function () { current.focus(); });

    document.querySelectorAll("[data-open-password]").forEach(function (el) {
      el.addEventListener("click", function (event) { event.preventDefault(); modal.show(); });
    });
    return { modal: modal, forced: forced };
  }

  // --- Agent host wizard -----------------------------------------------------------------------
  function initHost() {
    const modalEl = document.getElementById("hostModal");
    if (!modalEl) { return null; }
    const form = document.getElementById("hostForm");
    const input = document.getElementById("hostInput");
    const confirmBox = document.getElementById("hostConfirm");
    const nextBtn = form.querySelector("[data-next]");
    const backBtn = form.querySelector("[data-back]");
    const detectBtn = form.querySelector("[data-detect]");
    const laterBtn = form.querySelector("[data-later]");
    const modal = new bootstrap.Modal(modalEl);
    let step = "enter";
    let preview = null;
    let changed = false;

    function setStep(name) {
      step = name;
      showStep(modalEl, name);
      backBtn.hidden = name !== "review";
      detectBtn.hidden = name !== "enter";
      laterBtn.hidden = name === "done";
      nextBtn.querySelector("[data-label]").textContent = name === "enter" ? "Check" : name === "review" ? "Save and apply" : "Done";
      nextBtn.disabled = name === "review" && !confirmBox.checked;
    }

    function row(label, value, mono) {
      return "<dt>" + U.escapeHtml(label) + "</dt><dd" + (mono ? ' class="mono"' : "") + ">" + value + "</dd>";
    }

    function certificateText(p) {
      switch (p.certificate) {
        case "covered": return U.pill("success", "Covers this address");
        case "reissue": return U.pill("info", "Will be reissued for this address") + ' <span class="subtle">(' + U.escapeHtml(p.certificateMode) + ")</span>";
        case "missing": return U.pill("danger", "Does not cover this address");
        default: return U.pill("neutral", "HTTPS disabled");
      }
    }

    function renderReview(p) {
      const resolved = (p.resolvesTo || []).length ? U.escapeHtml(p.resolvesTo.join(", ")) : '<span class="text-danger">Does not resolve</span>';
      modalEl.querySelector("[data-review]").innerHTML =
        row("Address", U.escapeHtml(p.host), true) +
        row("Agent contact URL", U.escapeHtml(p.managerUrl), true) +
        row("Resolves to", resolved, true) +
        row("This server", U.escapeHtml((p.serverAddresses || []).join(", ") || "Unknown"), true) +
        row("TLS certificate", certificateText(p), false);
      modalEl.querySelector("[data-warnings]").innerHTML = (p.warnings || []).map(function (w) {
        return '<div class="banner banner-warning mt-2"><i class="bi bi-exclamation-triangle" aria-hidden="true"></i><div>' + U.escapeHtml(w) + "</div></div>";
      }).join("");
      confirmBox.checked = false;
      confirmBox.disabled = Boolean(p.blocking);
    }

    async function check() {
      const value = input.value.trim();
      if (!value) { fieldError(input, "Enter a DNS name, FQDN or IP address."); return; }
      if (/[/?#\s]/.test(value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/\/+$/, ""))) {
        fieldError(input, "Enter only the host name, without a path or spaces.");
        return;
      }
      fieldError(input, "");
      busy(nextBtn, true);
      try {
        preview = await U.api("/api/settings/host/preview", { method: "POST", body: { host: value } });
        renderReview(preview);
        setStep("review");
      } catch (error) {
        fieldError(input, error.message);
      } finally {
        busy(nextBtn, false);
      }
    }

    async function save() {
      if (!confirmBox.checked || !preview) { return; }
      busy(nextBtn, true);
      try {
        const result = await U.api("/api/settings/host", { method: "POST", body: { host: preview.host, confirm: true } });
        finish(result.managerUrl, result.certificate && result.certificate.issued
          ? "The TLS certificate was reissued for this address. Installed agents switch at their next check-in."
          : "New downloads use this address now. Installed agents switch at their next check-in.");
      } catch (error) {
        banner(modalEl, error.message);
      } finally {
        busy(nextBtn, false);
        nextBtn.disabled = false;
      }
    }

    function finish(url, detail) {
      changed = true;
      modalEl.querySelector("[data-new-url]").textContent = url;
      modalEl.querySelector("[data-done-detail]").textContent = detail;
      setStep("done");
    }

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      banner(modalEl, "");
      if (step === "enter") { check(); }
      else if (step === "review") { save(); }
      else { modal.hide(); }
    });
    confirmBox.addEventListener("change", function () { nextBtn.disabled = !confirmBox.checked; });
    backBtn.addEventListener("click", function () { banner(modalEl, ""); setStep("enter"); input.focus(); });
    input.addEventListener("input", function () { fieldError(input, ""); });
    laterBtn.addEventListener("click", function () { sessionStorage.setItem(HOST_PROMPT_KEY, "1"); });

    detectBtn.addEventListener("click", async function () {
      if (!window.confirm("Use this server's IP address for agents instead of a DNS name?")) { return; }
      banner(modalEl, "");
      busy(detectBtn, true);
      try {
        const result = await U.api("/api/settings/host", { method: "POST", body: { action: "detect" } });
        finish(result.managerUrl, "New downloads use this address now. Installed agents switch at their next check-in.");
      } catch (error) {
        banner(modalEl, error.message);
      } finally {
        busy(detectBtn, false);
      }
    });

    modalEl.addEventListener("show.bs.modal", function () {
      banner(modalEl, "");
      fieldError(input, "");
      modalEl.querySelector("[data-current]").textContent = document.body.getAttribute("data-agent-url") || "";
      setStep("enter");
    });
    modalEl.addEventListener("shown.bs.modal", function () { input.focus(); });
    modalEl.addEventListener("hidden.bs.modal", function () {
      if (changed) { window.location.reload(); }
    });

    if (document.body.getAttribute("data-role") !== "Administrator") {
      return null;
    }
    document.querySelectorAll("[data-open-host]").forEach(function (el) {
      el.addEventListener("click", function (event) {
        event.preventDefault();
        input.value = el.getAttribute("data-host") || "";
        modal.show();
      });
    });
    return { modal: modal };
  }

  document.addEventListener("DOMContentLoaded", function () {
    if (!window.bootstrap || !document.getElementById("sidebar")) { return; }
    const password = initPassword();
    const host = initHost();
    const isAdmin = document.body.getAttribute("data-role") === "Administrator";
    if (password && password.forced) {
      password.modal.show();
    } else if (host && isAdmin && document.body.getAttribute("data-needs-dns") === "1" && !sessionStorage.getItem(HOST_PROMPT_KEY) &&
               !document.getElementById("dz-modal")) {
      // Reset & Recovery reports the agent contact address in its own connectivity panel and runs its
      // own confirmations, so the prompt is not opened on top of them there.
      host.modal.show();
    }
  });
})();
