// Login page: password form, language switch. Redirects to the app when login is off or already signed in.
import { applyStatic, lang, setLang, t } from "./i18n.js";

applyStatic();
document.title = `Emberwatch – ${t("login.title")}`;
for (const b of document.querySelectorAll("[data-lang]")) {
  b.classList.toggle("on", b.dataset.lang === lang);
  b.addEventListener("click", () => setLang(b.dataset.lang));
}

const form = document.getElementById("login-form");
const err = document.getElementById("login-error");
const input = document.getElementById("password");

fetch("api/auth/status", { headers: { Accept: "application/json" } })
  .then((r) => r.json())
  .then((s) => { if (s.mode !== "password" || s.authenticated) window.location.replace("./"); })
  .catch(() => { /* stay on the form */ });

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  err.hidden = true;
  const btn = form.querySelector("button[type=submit]");
  btn.disabled = true;
  try {
    const r = await fetch("api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ password: input.value }),
    });
    if (r.ok) {
      window.location.replace("./");
      return;
    }
    let msg = `HTTP ${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* ignore */ }
    err.textContent = t("login.failed", { msg });
    err.hidden = false;
    input.select();
  } catch (ex) {
    err.textContent = t("login.failed", { msg: ex.message });
    err.hidden = false;
  } finally {
    btn.disabled = false;
  }
});
