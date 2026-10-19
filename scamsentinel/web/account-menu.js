// Account menu at the top right of every page: log in or create a local account, then go
// to the saved analyses; when signed in, show the email with "Saved analyses" and
// "Log out". Wrapped in its own scope so it can't clash with app.js or results.js.
// Plain text only (textContent), same-origin JSON requests, nothing stored in the browser:
// the session lives in an httpOnly, SameSite=Strict cookie set by the server.
(() => {
  const root = document.querySelector("#account-menu");
  if (!root) return;

  const button = root.querySelector("#account-button");
  const label = root.querySelector("#account-button-label");
  const panel = root.querySelector("#account-panel");
  const signedOut = root.querySelector("#account-signed-out");
  const signedIn = root.querySelector("#account-signed-in");
  const form = root.querySelector("#account-form");
  const submit = root.querySelector("#account-submit");
  const error = root.querySelector("#account-error");
  const hint = root.querySelector("#account-hint");
  const emailText = root.querySelector("#account-menu-email");
  const password = form.querySelector('input[name="password"]');
  let mode = "login";

  async function request(url, options = {}) {
    const response = await fetch(url, { credentials: "same-origin", ...options });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = typeof body.detail === "string" ? body.detail : null;
      throw new Error(detail || `Request failed (${response.status}).`);
    }
    return body;
  }

  function setOpen(open) {
    panel.hidden = !open;
    button.setAttribute("aria-expanded", String(open));
    if (open) {
      const first = signedIn.hidden
        ? signedOut.querySelector('input[name="email"]')
        : signedIn.querySelector("a");
      first?.focus();
    }
  }

  function showAccount(email) {
    signedOut.hidden = Boolean(email);
    signedIn.hidden = !email;
    label.textContent = email || "Log in";
    const name = email ? `Account menu, signed in as ${email}` : "Log in or create an account";
    button.title = name;
    button.setAttribute("aria-label", name);  // the label is hidden on small screens
    emailText.textContent = email || "";
  }

  function setMode(next) {
    mode = next;
    for (const tab of root.querySelectorAll("[data-menu-mode]")) {
      const selected = tab.dataset.menuMode === mode;
      tab.classList.toggle("selected", selected);
      tab.setAttribute("aria-pressed", String(selected));
    }
    submit.textContent = mode === "login" ? "Log in" : "Create account";
    password.autocomplete = mode === "login" ? "current-password" : "new-password";
    hint.hidden = mode === "login";
    error.hidden = true;
  }

  button.addEventListener("click", () => setOpen(panel.hidden));
  for (const tab of root.querySelectorAll("[data-menu-mode]")) {
    tab.addEventListener("click", () => setMode(tab.dataset.menuMode));
  }
  document.addEventListener("click", (event) => {
    if (!panel.hidden && !root.contains(event.target)) setOpen(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !panel.hidden) {
      setOpen(false);
      button.focus();
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.hidden = true;
    const data = new FormData(form);
    submit.disabled = true;
    try {
      await request(`/v1/auth/${mode === "login" ? "login" : "register"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: data.get("email"), password: data.get("password") }),
      });
      form.reset();
      // The point of signing in here is to reach the saved analyses.
      window.location.assign("/saved");
    } catch (requestError) {
      error.textContent = requestError.message;
      error.hidden = false;
    } finally {
      submit.disabled = false;
    }
  });

  root.querySelector("#account-logout").addEventListener("click", async () => {
    try {
      await request("/v1/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
    } finally {
      // Reload so every part of the page (save buttons, saved list) shows signed out.
      window.location.reload();
    }
  });

  setMode("login");
  request("/v1/auth/me")
    .then((me) => showAccount(me.email))
    .catch(() => showAccount(null));
})();
