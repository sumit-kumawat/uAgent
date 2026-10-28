(function () {
  "use strict";

  // First-run setup. The server is the authority on what is acceptable and on whether setup is still
  // open, so this only submits the form and shows what came back, against the field it belongs to.
  const form = document.getElementById("setupForm");
  const submit = document.getElementById("submit");
  const error = document.getElementById("error");
  const errorText = document.getElementById("errorText");

  function show(message, field) {
    errorText.textContent = message;
    error.classList.remove("d-none");
    form.querySelectorAll(".is-invalid").forEach(function (el) { el.classList.remove("is-invalid"); });
    const target = field ? document.getElementById(field) : null;
    if (target) {
      target.classList.add("is-invalid");
      target.focus();
    }
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    error.classList.add("d-none");
    submit.disabled = true;
    submit.textContent = "Creating…";
    try {
      const response = await fetch("/api/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        credentials: "same-origin",
        cache: "no-store",
        body: JSON.stringify({
          setupCode: document.getElementById("setupCode").value,
          username: document.getElementById("username").value,
          password: document.getElementById("password").value,
          confirmPassword: document.getElementById("confirmPassword").value
        })
      });
      const payload = await response.json().catch(function () { return null; });
      if (response.ok) {
        window.location.href = "/";
        return;
      }
      if (payload && payload.code === "already_setup") {
        window.location.href = "/login";
        return;
      }
      show(payload && payload.error ? payload.error : "The account could not be created (HTTP " + response.status + ").",
        payload ? payload.field : "");
    } catch (networkError) {
      show("The portal could not be reached. Check your connection and try again.", "");
    }
    submit.disabled = false;
    submit.textContent = "Create account and sign in";
  });
})();
