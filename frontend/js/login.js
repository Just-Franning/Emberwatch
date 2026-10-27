// Sign-in in steps (see backend auth.py): user name and password -> new password (if due) -> set up the authenticator
// app or enter its code (or a recovery code) -> session. Only i18n.js is imported: the page works without a session.
import { applyStatic, lang, setLang, t } from "./i18n.js";

applyStatic();
document.title = `Emberwatch – ${t("login.title")}`;
for (const b of document.querySelectorAll("[data-lang]")) {
  b.classList.toggle("on", b.dataset.lang === lang);
  b.addEventListener("click", () => setLang(b.dataset.lang));
}

const $ = (id) => document.getElementById(id);
const forms = { login: $("f-login"), password: $("f-newpw"), enroll: $("f-enroll"), totp: $("f-code"), recovery: $("f-recovery") };
const err = $("login-error");
let ticket = null;
let recoveryMode = false;

function show(step) {
  for (const [k, f] of Object.entries(forms)) f.hidden = k !== step;
  const second = step !== "login" && step !== "password";
  document.querySelectorAll("#login-steps li").forEach((li) => li.classList.toggle("on", li.dataset.step === (second ? "2" : "1")));
  $("login-hint").hidden = step !== "login";
  err.hidden = true;
  const first = forms[step].querySelector("input:not([type=checkbox]), button.primary");
  if (first) setTimeout(() => first.focus(), 0);
}

function fail(msg) {
  err.textContent = msg;
  err.hidden = false;
}

async function post(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  let data = {};
  try { data = await r.json(); } catch { /* empty answer */ }
  if (!r.ok) {
    const e = new Error(typeof data.detail === "string" ? data.detail : `HTTP ${r.status}`);
    e.key = data.key || "";
    throw e;
  }
  return data;
}

/** Runs a step; an expired ticket sends back to the start. */
async function step(form, fn) {
  const btn = form.querySelector("button[type=submit]");
  if (btn) btn.disabled = true;
  err.hidden = true;
  try {
    await fn();
  } catch (e) {
    if (e.key === "err.login_expired") {
      ticket = null;
      show("login");
    }
    fail(t("login.failed", { msg: e.message }));
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function next(d) {
  if (d.step === "done") {
    window.location.replace("./");
    return;
  }
  ticket = d.ticket;
  if (d.step === "enroll") {
    const e = await post("api/auth/enroll", { ticket });
    $("qr").src = e.qr;
    $("qr").alt = t("login.qr_alt");
    $("secret").textContent = e.secret.replace(/(.{4})/g, "$1 ").trim();
    $("enroll-code").value = "";
  }
  show(d.step);
}

function codeMode(recovery) {
  recoveryMode = recovery;
  const input = $("code");
  input.value = "";
  input.inputMode = recovery ? "text" : "numeric";
  input.autocomplete = recovery ? "off" : "one-time-code";
  input.maxLength = recovery ? 11 : 6;
  if (recovery) input.removeAttribute("pattern"); else input.pattern = "[0-9]{6}";
  $("code-label").textContent = t(recovery ? "login.recovery_code" : "login.code");
  $("use-recovery").textContent = t(recovery ? "login.use_app" : "login.use_recovery");
  input.focus();
}

function showCodes(codes, afterwards) {
  const list = $("codes");
  list.replaceChildren(...codes.map((c) => { const li = document.createElement("li"); li.textContent = c; return li; }));
  $("codes-ok").checked = false;
  $("codes-done").disabled = true;
  $("codes-done").onclick = afterwards;
  show("recovery");
}

fetch("api/auth/status", { headers: { Accept: "application/json" } })
  .then((r) => r.json())
  .then((s) => { if (s.mode !== "password" || s.authenticated) window.location.replace("./"); })
  .catch(() => { /* stay on the form */ });

forms.login.addEventListener("submit", (e) => {
  e.preventDefault();
  step(forms.login, async () => {
    const d = await post("api/auth/login", { user: $("user").value.trim(), password: $("password").value });
    $("password").value = "";
    codeMode(false);
    await next(d);
  });
});

forms.password.addEventListener("submit", (e) => {
  e.preventDefault();
  if ($("newpw").value !== $("newpw2").value) {
    fail(t("login.newpw_mismatch"));
    return;
  }
  step(forms.password, async () => {
    const d = await post("api/auth/password", { ticket, password: $("newpw").value });
    $("newpw").value = "";
    $("newpw2").value = "";
    await next(d);
  });
});

forms.enroll.addEventListener("submit", (e) => {
  e.preventDefault();
  step(forms.enroll, async () => {
    const d = await post("api/auth/enroll/confirm", { ticket, code: $("enroll-code").value.trim() });
    showCodes(d.recovery, () => window.location.replace("./"));
  });
});

forms.totp.addEventListener("submit", (e) => {
  e.preventDefault();
  step(forms.totp, async () => {
    const d = await post("api/auth/totp", { ticket, code: $("code").value.trim() });
    if (d.recovery_used) {
      err.hidden = true;
      forms.totp.hidden = true;
      const note = $("login-hint");
      note.textContent = t("login.recovery_left", { n: d.recovery_left });
      note.hidden = false;
      setTimeout(() => window.location.replace("./"), 2500);
      return;
    }
    window.location.replace("./");
  });
});
$("use-recovery").addEventListener("click", () => codeMode(!recoveryMode));

$("codes-ok").addEventListener("change", () => { $("codes-done").disabled = !$("codes-ok").checked; });
$("codes-copy").addEventListener("click", async () => {
  const text = [...$("codes").children].map((li) => li.textContent).join("\n");
  try { await navigator.clipboard.writeText(text); $("codes-copy").textContent = t("login.codes_copied"); } catch { /* no clipboard: save instead */ }
});
$("codes-save").addEventListener("click", () => {
  const text = `Emberwatch – ${t("login.recovery_title")}\n${new Date().toISOString().slice(0, 10)}\n\n` +
    [...$("codes").children].map((li) => li.textContent).join("\n") + "\n";
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = "emberwatch-recovery-codes.txt";
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
});
