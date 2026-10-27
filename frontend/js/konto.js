// Account area (#/konto): the own account for everyone (password, second factor, recovery codes, sessions);
// users and the audit log for administrators. The header button opens a short menu (renderUserMenu).
import { t } from "./i18n.js";
import { href } from "./router.js";
import { accounts, isAdmin, me } from "./session.js";
import { ago, api, dateTime, download, el, kids, num } from "./util.js";

/** Pages of administrators: users only with sign-in by password; the audit log also behind a proxy. */
const adminViews = () => (!isAdmin() ? [] : accounts() ? ["users", "audit"] : ["audit"]);
const navLink = (path, label, on) => el("a", { href: href(path), class: on ? "on" : null }, el("span", { class: "lbl" }, label));

/** "Firefox · Linux" from a User-Agent (only for recognising one's own sessions). */
export function device(ua) {
  const s = String(ua || "");
  const browser = /Edg\//.test(s) ? "Edge" : /Firefox\//.test(s) ? "Firefox" : /Chrome\//.test(s) ? "Chrome" : /Safari\//.test(s) ? "Safari" : null;
  const os = /Android/.test(s) ? "Android" : /iPhone|iPad/.test(s) ? "iOS" : /Windows/.test(s) ? "Windows" : /Mac OS X/.test(s) ? "macOS" : /Linux/.test(s) ? "Linux" : null;
  return [browser, os].filter(Boolean).join(" · ") || (s ? s.slice(0, 40) : t("common.unknown"));
}

function secretBox(label, value, note) {
  const copy = el("button", { type: "button", class: "small", onclick: async () => {
    try { await navigator.clipboard.writeText(value); copy.textContent = t("acct.copied"); } catch { /* no clipboard */ }
  } }, t("acct.copy"));
  return el("div", { class: "secret-box", role: "status" }, el("span", { class: "k-label" }, label), el("code", { translate: "no" }, value), copy,
    note ? el("p", { class: "note" }, note) : null);
}

function codesBox(codes) {
  const save = () => download("emberwatch-recovery-codes.txt", `Emberwatch – ${t("login.recovery_title")} (${me.name})\n${new Date().toISOString().slice(0, 10)}\n\n${codes.join("\n")}\n`);
  return el("div", { class: "secret-box" }, el("span", { class: "k-label" }, t("acct.codes_new")),
    el("ol", { class: "codes", translate: "no" }, codes.map((c) => el("li", {}, c))),
    el("div", { class: "row" }, el("button", { type: "button", class: "small", onclick: save }, t("login.codes_save"))),
    el("p", { class: "note" }, t("acct.codes_once")));
}

function feedback() {
  return el("p", { class: "note", "aria-live": "polite" });
}
function say(node, msg, bad = false) {
  node.className = bad ? "state err" : "note ok-txt";
  node.textContent = msg;
}

export function renderUserMenu(panel, { onLogout }) {
  const role = t(`acct.role.${me.role}`);
  kids(panel,
    el("div", { class: "um-head" }, el("b", {}, accounts() ? me.name || "–" : t("acct.proxy_name")), el("span", { class: "note" }, role)),
    el("nav", { class: "um-links" },
      el("a", { href: href("konto") }, t("acct.nav.me")),
      ...adminViews().map((v) => el("a", { href: href(`konto/${v}`) }, t(`acct.nav.${v}`)))),
    accounts() ? el("div", { class: "row" }, el("button", { type: "button", onclick: onLogout }, t("set.logout")))
      : el("p", { class: "note" }, t("acct.proxy_short")));
}

export class Konto {
  constructor({ nav, main }) {
    this.navBox = nav;
    this.main = main;
    this.box = el("div", { class: "wrap konto" });
    kids(main, this.box);
    this.seq = 0;
    this.status = null;
  }

  setStatus(status) { this.status = status; }

  leave() {}

  async show(route) {
    const seq = ++this.seq;
    const view = adminViews().includes(route.parts[0]) ? route.parts[0] : null;
    kids(this.navBox, navLink("konto", t("acct.nav.me"), !view),
      ...adminViews().map((v) => navLink(`konto/${v}`, t(`acct.nav.${v}`), view === v)));
    this.main.scrollTop = 0;
    if (!accounts() && !view) {
      kids(this.box, el("h2", { class: "page-title" }, t("acct.nav.me")), el("p", { class: "lead" }, t("acct.proxy")));
      return;
    }
    kids(this.box, el("p", { class: "state" }, t("common.loading")));
    try {
      if (view === "users") await this.users(seq);
      else if (view === "audit") await this.audit(seq);
      else await this.account(seq);
    } catch (e) {
      if (seq === this.seq) kids(this.box, el("p", { class: "state err" }, t("common.error", { msg: e.message })));
    }
  }

  // --- own account ------------------------------------------------------------------------------------------------
  async account(seq) {
    const a = await api("api/account");
    if (seq !== this.seq) return;
    const reload = () => this.account(this.seq);

    // password
    const cur = el("input", { type: "password", autocomplete: "current-password", required: true, maxlength: 1024 });
    const pw1 = el("input", { type: "password", autocomplete: "new-password", required: true, minlength: 12, maxlength: 256 });
    const pw2 = el("input", { type: "password", autocomplete: "new-password", required: true, minlength: 12, maxlength: 256 });
    const pwMsg = feedback();
    const pwForm = el("form", { class: "form-grid", onsubmit: async (e) => {
      e.preventDefault();
      if (pw1.value !== pw2.value) { say(pwMsg, t("login.newpw_mismatch"), true); return; }
      try {
        await api("api/account/password", { json: { current: cur.value, new: pw1.value } });
        cur.value = pw1.value = pw2.value = "";
        say(pwMsg, t("acct.pw_saved"));
      } catch (er) { say(pwMsg, er.message, true); }
    } },
    el("label", {}, t("acct.pw_current"), cur), el("label", {}, t("login.newpw"), pw1), el("label", {}, t("login.newpw2"), pw2),
    el("button", { type: "submit", class: "primary" }, t("acct.pw_change")), pwMsg);

    // second factor: new device, new recovery codes (each asks for the password)
    const tfaOut = el("div", {});
    const tfaMsg = feedback();
    const askPassword = (label, run) => {
      const p = el("input", { type: "password", autocomplete: "current-password", required: true, maxlength: 1024, "aria-label": t("acct.pw_current") });
      kids(tfaOut, el("form", { class: "inline-form", onsubmit: async (e) => { e.preventDefault(); try { await run(p.value); } catch (er) { say(tfaMsg, er.message, true); } } },
        el("label", {}, t("acct.pw_current"), p), el("button", { type: "submit", class: "primary" }, label),
        el("button", { type: "button", class: "plain", onclick: () => kids(tfaOut) }, t("common.close"))));
      p.focus();
    };
    const newDevice = () => askPassword(t("acct.tfa_start"), async (password) => {
      const d = await api("api/account/totp", { json: { password } });
      const code = el("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: 6, required: true });
      kids(tfaOut, el("div", { class: "enroll" },
        el("div", { class: "qr-box" }, el("img", { src: d.qr, alt: t("login.qr_alt"), width: 170, height: 170 })),
        el("div", {}, el("p", { class: "note" }, t("acct.tfa_scan")), el("p", { class: "secret", translate: "no" }, d.secret.replace(/(.{4})/g, "$1 ").trim()),
          el("form", { class: "inline-form", onsubmit: async (e) => {
            e.preventDefault();
            try {
              const r = await api("api/account/totp/confirm", { json: { code: code.value.trim() } });
              kids(tfaOut, codesBox(r.recovery));
              say(tfaMsg, t("acct.tfa_done"));
            } catch (er) { say(tfaMsg, er.message, true); }
          } }, el("label", {}, t("login.code"), code), el("button", { type: "submit", class: "primary" }, t("login.enroll_confirm"))))));
      code.focus();
    });
    const newCodes = () => askPassword(t("acct.codes_make"), async (password) => {
      const r = await api("api/account/recovery", { json: { password } });
      kids(tfaOut, codesBox(r.recovery));
      say(tfaMsg, t("acct.codes_made"));
    });

    // sessions
    const sessions = el("table", { class: "res" },
      el("thead", {}, el("tr", {}, ...["acct.s.device", "acct.s.ip", "acct.s.since", "acct.s.seen", "acct.s.expires", ""].map((k) => el("th", {}, k ? t(k) : "")))),
      el("tbody", {}, a.sessions.map((s) => el("tr", { class: s.current ? "current" : null },
        el("td", {}, device(s.ua), s.current ? el("span", { class: "tag" }, t("acct.s.this")) : null),
        el("td", { class: "mono" }, s.ip || "–"), el("td", {}, dateTime(s.created_at)), el("td", {}, ago(s.last_seen)), el("td", {}, dateTime(s.expires_at)),
        el("td", {}, el("button", { type: "button", class: "small", onclick: async () => {
          try {
            const r = await api(`api/account/sessions/${s.id}`, { method: "DELETE" });
            if (r.current) window.location.assign("login"); else reload();
          } catch (e) { say(tfaMsg, e.message, true); }
        } }, t("acct.s.end")))))));

    kids(this.box,
      el("h2", { class: "page-title" }, t("acct.nav.me")),
      el("p", { class: "lead" }, t("acct.lead", { name: a.name, role: t(`acct.role.${a.role}`) })),
      el("div", { class: "cards" },
        el("section", { class: "card" }, el("h3", {}, t("acct.signin")),
          el("dl", { class: "kv" },
            el("dt", {}, t("login.user")), el("dd", { class: "mono" }, a.name),
            el("dt", {}, t("acct.role")), el("dd", {}, t(`acct.role.${a.role}`)),
            el("dt", {}, t("acct.since")), el("dd", {}, dateTime(a.created_at)),
            el("dt", {}, t("acct.last_login")), el("dd", {}, a.last_login ? dateTime(a.last_login) : t("common.never")),
            el("dt", {}, t("acct.pw_changed")), el("dd", {}, a.pw_changed ? ago(a.pw_changed) : "–"))),
        el("section", { class: "card" }, el("h3", {}, t("acct.pw_change")), pwForm),
        el("section", { class: "card" }, el("h3", {}, t("acct.tfa")),
          el("p", {}, a.totp ? t("acct.tfa_on") : t("acct.tfa_off")),
          el("p", { class: a.recovery_left <= 2 ? "warn-txt" : "note" }, t("acct.codes_left", { n: num(a.recovery_left) })),
          el("div", { class: "row" }, el("button", { type: "button", onclick: newDevice }, t("acct.tfa_new")),
            el("button", { type: "button", onclick: newCodes }, t("acct.codes_make"))),
          tfaOut, tfaMsg),
        el("section", { class: "card wide" }, el("h3", {}, t("acct.sessions")), el("p", { class: "note" }, t("acct.sessions_note")), sessions)));
  }

  // --- users (administrators) ----------------------------------------------------------------------------------------
  /** Every change renders the list again; what it produced (a temporary password, a message) is shown in the new page. */
  async users(seq) {
    const d = await api("api/admin/users");
    if (seq !== this.seq) return;
    const out = el("div", {});
    const msg = feedback();
    const flash = this.flash;
    this.flash = null;
    const reload = (next = null) => { this.flash = next; return this.users(this.seq); };
    const act = (fn) => async () => { try { await fn(); } catch (e) { say(msg, e.message, true); } };

    const name = el("input", { type: "text", required: true, minlength: 2, maxlength: 32, pattern: "[a-z0-9][a-z0-9._\\-]{1,31}", autocapitalize: "none",
      spellcheck: "false", title: t("acct.u.name_rule") });
    const role = el("select", {}, el("option", { value: "viewer" }, t("acct.role.viewer")), el("option", { value: "admin" }, t("acct.role.admin")));
    const create = el("form", { class: "inline-form", onsubmit: async (e) => {
      e.preventDefault();
      try {
        const r = await api("api/admin/users", { json: { name: name.value.trim().toLowerCase(), role: role.value } });
        await reload({ secret: [t("acct.u.created", { name: r.user.name }), r.password] });
      } catch (er) { say(msg, er.message, true); }
    } }, el("label", {}, t("login.user"), name), el("label", {}, t("acct.role"), role), el("button", { type: "submit", class: "primary" }, t("acct.u.create")));

    const row = (u) => {
      const self = u.name === me.name;
      const roleSel = el("select", { disabled: self, "aria-label": t("acct.role"), onchange: act(async () => {
        await api(`api/admin/users/${u.id}`, { method: "PATCH", json: { role: roleSel.value } });
        await reload({ msg: t("acct.u.saved") });
      }) }, ...["admin", "viewer"].map((r) => el("option", { value: r, selected: u.role === r }, t(`acct.role.${r}`))));
      const state = u.disabled ? t("acct.u.disabled") : u.must_change ? t("acct.u.must_change") : !u.totp ? t("acct.u.no_tfa") : t("acct.u.active");
      const btn = (label, fn, cls = "small") => el("button", { type: "button", class: cls, disabled: self, onclick: act(fn) }, label);
      return el("tr", { class: u.disabled ? "muted" : null },
        el("td", { class: "mono" }, u.name, self ? el("span", { class: "tag" }, t("acct.u.you")) : null),
        el("td", {}, roleSel),
        el("td", {}, u.totp ? t("common.yes") : t("common.no")),
        el("td", {}, state),
        el("td", {}, u.last_login ? ago(u.last_login) : t("common.never")),
        el("td", { class: "num" }, num(u.sessions)),
        el("td", { class: "actions-cell" },
          btn(t("acct.u.reset_pw"), async () => {
            if (!window.confirm(t("acct.u.reset_pw_q", { name: u.name }))) return;
            const r = await api(`api/admin/users/${u.id}/password`, { method: "POST" });
            await reload({ secret: [t("acct.u.temp_for", { name: u.name }), r.password] });
          }),
          btn(t("acct.u.reset_tfa"), async () => {
            if (!window.confirm(t("acct.u.reset_tfa_q", { name: u.name }))) return;
            await api(`api/admin/users/${u.id}/totp`, { method: "POST" });
            await reload({ msg: t("acct.u.tfa_reset", { name: u.name }) });
          }),
          btn(t("acct.u.signout"), async () => {
            const r = await api(`api/admin/users/${u.id}/sessions`, { method: "DELETE" });
            await reload({ msg: t("acct.u.signed_out", { n: num(r.ended) }) });
          }),
          btn(u.disabled ? t("acct.u.enable") : t("acct.u.disable"), async () => {
            await api(`api/admin/users/${u.id}`, { method: "PATCH", json: { disabled: !u.disabled } });
            await reload({ msg: t("acct.u.saved") });
          }),
          btn(t("common.delete"), async () => {
            if (!window.confirm(t("acct.u.delete_q", { name: u.name }))) return;
            await api(`api/admin/users/${u.id}`, { method: "DELETE" });
            await reload({ msg: t("acct.u.deleted", { name: u.name }) });
          }, "small danger")));
    };

    if (flash?.secret) kids(out, secretBox(flash.secret[0], flash.secret[1], t("acct.u.temp_note")));
    if (flash?.msg) say(msg, flash.msg);
    kids(this.box,
      el("h2", { class: "page-title" }, t("acct.nav.users")),
      el("p", { class: "lead" }, t("acct.u.lead")),
      el("section", { class: "card" }, el("h3", {}, t("acct.u.create")), create, out, msg),
      el("div", { class: "tbl-wrap" }, el("table", { class: "res users" },
        el("thead", {}, el("tr", {}, ...["login.user", "acct.role", "acct.u.tfa", "acct.u.state", "acct.last_login", "acct.sessions", ""].map((k) => el("th", {}, k ? t(k) : "")))),
        el("tbody", {}, d.users.map(row)))),
      el("p", { class: "note" }, t("acct.u.cli")));
  }

  // --- audit log (administrators) ----------------------------------------------------------------------------------
  async audit(seq) {
    const state = { action: "", user: "", entries: [], done: false };
    const tbody = el("tbody", {});
    const more = el("button", { type: "button", class: "plain" }, t("acct.a.more"));
    const actSel = el("select", { "aria-label": t("acct.a.action") }, el("option", { value: "" }, t("common.all")));
    const userIn = el("input", { type: "search", maxlength: 40, placeholder: t("acct.a.user_ph"), "aria-label": t("acct.a.user") });
    const detail = (e) => {
      const d = e.detail || {};
      return Object.entries(d).map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join(", ");
    };
    const load = async (reset) => {
      const p = new URLSearchParams({ limit: "200" });
      if (state.action) p.set("action", state.action);
      if (state.user) p.set("user", state.user);
      if (!reset && state.entries.length) p.set("before", String(state.entries[state.entries.length - 1].id));
      const d = await api(`api/admin/audit?${p}`);
      if (seq !== this.seq) return;
      if (actSel.options.length === 1) for (const a of d.actions) actSel.append(el("option", { value: a }, t(`au.${a}`)));
      state.entries = reset ? d.entries : [...state.entries, ...d.entries];
      state.done = d.entries.length < 200;
      kids(tbody, state.entries.length ? state.entries.map((e) => el("tr", { class: /fail|disabled/.test(e.action) ? "warn" : null },
        el("td", {}, dateTime(e.ts)), el("td", { class: "mono" }, e.user_name || "–"), el("td", {}, t(`au.${e.action}`)),
        el("td", { class: "mono" }, e.target || "–"), el("td", { class: "mono" }, e.ip || "–"), el("td", { class: "note" }, detail(e))))
        : el("tr", {}, el("td", { colspan: 6, class: "empty" }, t("acct.a.none"))));
      more.hidden = state.done;
    };
    actSel.addEventListener("change", () => { state.action = actSel.value; load(true); });
    let timer = null;
    userIn.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { state.user = userIn.value.trim().toLowerCase(); load(true); }, 300); });
    more.addEventListener("click", () => load(false));
    kids(this.box,
      el("h2", { class: "page-title" }, t("acct.nav.audit")),
      el("p", { class: "lead" }, t("acct.a.lead", { days: num(this.status?.accounts?.audit_days || 365) })),
      el("div", { class: "filters" }, el("label", {}, t("acct.a.action"), actSel), el("label", {}, t("acct.a.user"), userIn)),
      el("table", { class: "res audit" },
        el("thead", {}, el("tr", {}, ...["acct.a.time", "acct.a.user", "acct.a.action", "acct.a.target", "acct.s.ip", "acct.a.detail"].map((k) => el("th", {}, t(k))))),
        tbody),
      more);
    await load(true);
  }
}
