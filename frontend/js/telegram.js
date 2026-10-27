// Telegram window of the Weltlage: public channels of hacktivist groups, read from the web preview (t.me/s/<name>)
// without an account. The posts are claims of the groups, not verified. What a claim names is extracted automatically:
// countries, kinds of attack, targets (domains, addresses; shown defanged), proof links (check-host.net). A claimed
// DDoS attack on a country is compared with Cloudflare Radar (the same check as for the reports of the Weltlage).
// Everyone reads; adding and removing channels, reading a channel now and translations (Gemini) need the role admin.
import { lang, t } from "./i18n.js";
import { objLink } from "./router.js";
import { isAdmin } from "./session.js";
import { ago, api, countryName, el, kids, num, safeLink } from "./util.js";
import { checkLines, checkTitle } from "./welt.js";
import { front } from "./windows.js";

const PAGE = 40;
const DAYS = [1, 7, 30, 90];
const VERDICTS = ["supported", "not_supported", "unclear"];
const FETCH_ERRORS = ["blocked", "network", "timeout", "redirect", "scheme", "too_large"];
const ccOk = (cc) => typeof cc === "string" && /^[A-Z]{2}$/.test(cc);
const defang = (v) => String(v).replace(/\.(?=[^.]*$)/, "[.]"); // example[.]com, 192.0.2[.]1
const defangUrl = (u) => String(u).replace(/^http(s?)/i, "hxxp$1").replace(/\./g, "[.]");
const kindLabel = (k) => { const l = t(`wl.kind.${k}`); return l === `wl.kind.${k}` ? k : l; };

/** Why a channel could not be read (stored as a code by the server). */
function channelError(code) {
  const c = String(code || "");
  if (c === "err.tg.http") return t("tg.err.http");
  if (c === "err.tg.no_preview") return t("tg.err.no_preview");
  const f = c.startsWith("fetch:") ? c.slice(6) : "";
  return FETCH_ERRORS.includes(f) ? t(`tg.err.fetch_${f}`) : t("tg.err.other");
}

/** Overall result of the comparisons of one post: confirmed if one measurement supports the claim. */
function verdict(checks) {
  const r = (checks || []).map((c) => c?.result).filter((x) => VERDICTS.includes(x));
  if (!r.length) return null;
  return r.includes("supported") ? "supported" : r.every((x) => x === "not_supported") ? "not_supported" : "unclear";
}

export class TelegramWindow {
  constructor({ map, onMap }) {
    this.map = map;
    this.onMap = onMap; // () => the Weltlage map must be visible
    this.win = document.getElementById("panel-tg");
    this.body = document.getElementById("tg-body");
    this.btn = document.getElementById("btn-telegram");
    this.f = { days: 7, channel: "", country: "", q: "" };
    this.data = null;
    this.posts = [];
    this.total = 0;
    this.seq = 0;
    this.open = new Set(); // posts with the full text shown
    this.orig = new Set(); // posts shown in the original language although a translation exists
    this.mapped = null;
    this.btn.addEventListener("click", () => (this.win.hidden ? this.show() : this.hide()));
    document.getElementById("tg-close").addEventListener("click", () => this.hide());
  }

  /** The pill is shown only when the monitoring is switched on. */
  setStatus(status) {
    this.btn.hidden = status?.v4?.telegram === false;
    if (this.btn.hidden && !this.win.hidden) this.hide();
  }

  show() {
    this.win.hidden = false;
    this.btn.setAttribute("aria-pressed", "true");
    front(this.win);
    this.load();
  }

  hide() {
    this.win.hidden = true;
    this.btn.setAttribute("aria-pressed", "false");
    this.clearMap();
  }

  /** Leaving the Weltlage: the window stays open for the return, the map mark goes. */
  leave() {
    this.clearMap();
  }

  /** Periodic refresh of the interface: only while the window is open. */
  refresh() {
    if (!this.win.hidden) this.load();
  }

  clearMap() {
    if (this.mapped) {
      this.map.clearWeltItem();
      this.mapped = null;
    }
  }

  params(extra = {}) {
    const p = new URLSearchParams({ days: String(this.f.days), limit: String(PAGE) });
    if (this.f.channel) p.set("channel", this.f.channel);
    if (this.f.country) p.set("country", this.f.country);
    if (this.f.q) p.set("q", this.f.q);
    for (const [k, v] of Object.entries(extra)) p.set(k, String(v));
    return p.toString();
  }

  set(partial) {
    Object.assign(this.f, partial);
    this.load();
  }

  async load() {
    const seq = ++this.seq;
    if (!this.data) kids(this.body, el("p", { class: "state" }, t("common.loading")));
    try {
      const d = await api(`api/telegram?${this.params()}`);
      if (seq !== this.seq) return;
      this.data = d;
      this.posts = d.posts;
      this.total = d.total;
      this.render();
    } catch (e) {
      if (seq === this.seq) kids(this.body, el("p", { class: "state err" }, t("common.error", { msg: e.message })));
    }
  }

  async more(btn) {
    btn.disabled = true;
    const seq = this.seq;
    try {
      const d = await api(`api/telegram?${this.params({ offset: this.posts.length })}`);
      if (seq !== this.seq) return;
      const known = new Set(this.posts.map((p) => `${p.channel}/${p.post_id}`));
      this.posts.push(...d.posts.filter((p) => !known.has(`${p.channel}/${p.post_id}`)));
      this.total = d.total;
      this.render();
    } catch (e) {
      btn.replaceWith(el("p", { class: "state err" }, t("common.error", { msg: e.message })));
    }
  }

  render() {
    const d = this.data;
    if (!d.enabled) {
      kids(this.body, el("p", { class: "state" }, t("tg.off")));
      return;
    }
    const scroll = this.list?.parentElement === this.body ? this.body.scrollTop : 0;
    const chan = el("select", { "aria-label": t("tg.f.channel") }, el("option", { value: "" }, t("tg.f.channel_all")),
      ...d.channels.map((c) => el("option", { value: c.name, selected: c.name === this.f.channel }, `@${c.name}${c.title ? ` – ${c.title}` : ""}`)));
    chan.addEventListener("change", () => this.set({ channel: chan.value }));
    const days = el("select", { "aria-label": t("wl.period") }, DAYS.map((v) => el("option", { value: v, selected: v === this.f.days }, t(`wl.d${v}`))));
    days.addEventListener("change", () => this.set({ days: Number(days.value) }));
    const q = el("input", { type: "search", maxlength: 100, value: this.f.q, placeholder: t("tg.f.q"), "aria-label": t("tg.f.q") });
    const bar = el("form", { class: "tg-bar", role: "search", onsubmit: (e) => { e.preventDefault(); this.set({ q: q.value.trim() }); } }, chan, days, q);
    const ccs = Object.entries(d.countries || {}).filter(([cc]) => ccOk(cc)).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const chips = [];
    if (this.f.country) chips.push(el("span", { class: "fchip" }, countryName(this.f.country), el("button", { type: "button", class: "small", title: t("wl.filter_clear"), onclick: () => this.set({ country: "" }) }, "×")));
    if (this.f.q) chips.push(el("span", { class: "fchip" }, `„${this.f.q}“`, el("button", { type: "button", class: "small", title: t("wl.filter_clear"), onclick: () => this.set({ q: "" }) }, "×")));
    this.list = el("ol", { class: "tg-posts" }, this.posts.map((p) => this.post(p)));
    const moreBtn = el("button", { type: "button", class: "small" }, t("wl.more", { n: num(Math.min(PAGE, this.total - this.posts.length)) }));
    moreBtn.addEventListener("click", () => this.more(moreBtn));
    kids(this.body,
      bar,
      el("p", { class: "note tg-lead" }, t("tg.lead")),
      chips.length ? el("div", { class: "fchips" }, chips) : null,
      el("p", { class: "note" }, t("tg.count", { n: num(this.total), c: num(d.channels.length), d: num(this.f.days) })),
      ccs.length ? el("div", { class: "tg-ccs", role: "group", "aria-label": t("tg.ccs") }, el("span", { class: "muted" }, t("tg.ccs")),
        ccs.map(([cc, n]) => el("button", { type: "button", class: `small${cc === this.f.country ? " on" : ""}`, "aria-pressed": String(cc === this.f.country),
          onclick: () => this.set({ country: cc === this.f.country ? "" : cc }) }, countryName(cc), " ", el("b", {}, num(n))))) : null,
      this.posts.length ? this.list : el("p", { class: "empty" }, d.channels.length ? t("tg.none") : t("tg.no_channels")),
      this.total > this.posts.length ? el("p", { class: "more-link" }, moreBtn) : null,
      this.channels(d));
    if (scroll) this.body.scrollTop = scroll;
  }

  post(p) {
    const key = `${p.channel}/${p.post_id}`;
    const ch = this.data.channels.find((c) => c.name === p.channel);
    const translated = p.translation && p.translated_to === lang;
    const showOrig = !translated || this.orig.has(key);
    const text = showOrig ? p.text : p.translation;
    const long = (text || "").length > 420 || (text || "").split("\n").length > 7;
    const full = this.open.has(key);
    const body = el("p", { class: `tg-text${long && !full ? " clamp" : ""}`, dir: "auto" }, text || t("tg.no_text"));
    const v = verdict(p.checks);
    const tags = [
      ...p.kinds.slice(0, 4).map((k) => el("span", { class: "wtag" }, kindLabel(k))),
      v === "supported" ? el("span", { class: "wtag chk", title: t("tg.chk_supported_title") }, t("tg.chk_supported")) : null,
    ].filter(Boolean);
    const ccs = p.countries.filter(ccOk);
    const targets = (p.targets || []).filter((x) => x && (x.kind === "domain" || x.kind === "ip")).slice(0, 12);
    const checks = (p.checks || []).filter((c) => c && VERDICTS.includes(c.result));
    const proofs = (p.proofs || []).slice(0, 5);
    const others = (p.links || []).filter((u) => !proofs.includes(u)).slice(0, 12);
    const tr = this.translateBtn(p, translated);
    return el("li", { class: "tg-post" },
      el("div", { class: "tg-meta" },
        el("strong", { class: "mono" }, `@${p.channel}`), ch?.title ? el("span", { class: "muted" }, ch.title) : null,
        el("span", { class: "muted", title: p.date }, ago(p.date)),
        p.views !== null && p.views !== undefined ? el("span", { class: "muted" }, t("tg.views", { n: num(p.views) })) : null,
        p.fwd ? el("span", { class: "muted", title: t("tg.fwd_title") }, t("tg.fwd", { from: p.fwd })) : null),
      translated && !showOrig ? el("p", { class: "tg-tr note" }, t("tg.translated")) : null,
      body,
      long ? el("button", { type: "button", class: "link small", onclick: () => { if (full) this.open.delete(key); else this.open.add(key); this.rerender(p); } },
        t(full ? "tg.less" : "tg.more_text")) : null,
      tags.length ? el("div", { class: "ntags" }, tags) : null,
      ccs.length ? el("div", { class: "tg-facts" }, el("span", { class: "muted" }, t("tg.named")),
        ccs.map((cc) => el("button", { type: "button", class: "link", onclick: () => this.set({ country: cc }) }, countryName(cc)))) : null,
      targets.length ? el("div", { class: "tg-facts" }, el("span", { class: "muted" }, t("tg.targets")),
        targets.map((x) => objLink(x.kind, x.value, defang(x.value), "echip mono"))) : null,
      checks.length ? el("ul", { class: "chk-list tg-checks" }, checks.map((c) => el("li", {},
        el("span", { class: `chk-r ${c.result}` }, t(`wl.chk.r.${c.result}`)),
        el("span", { class: "chk-body" }, el("strong", {}, checkTitle(c)), el("span", { class: "chk-detail" }, ...checkLines(c)))))) : null,
      proofs.length ? el("div", { class: "tg-facts" }, el("span", { class: "muted" }, t("tg.proofs")),
        proofs.map((u) => safeLink(u, u.replace(/^https:\/\//, "").slice(0, 60)) || el("span", { class: "mono" }, defangUrl(u)))) : null,
      others.length ? el("details", { class: "tg-links" }, el("summary", {}, t("tg.links", { n: num(others.length) })),
        el("ul", { class: "plain mono-sm" }, others.map((u) => el("li", {}, defangUrl(u))))) : null,
      el("div", { class: "tg-actions" },
        safeLink(p.url, t("tg.open")),
        ccs.length ? el("button", { type: "button", class: "small", onclick: () => this.showOnMap(p) }, t("tg.map")) : null,
        translated ? el("button", { type: "button", class: "small", onclick: () => { if (showOrig) this.orig.delete(key); else this.orig.add(key); this.rerender(p); } },
          t(showOrig ? "tg.show_tr" : "tg.show_orig")) : tr));
  }

  /** Translation button (administrators, Gemini switched on); the translation is stored with the post. */
  translateBtn(p, translated) {
    if (translated || !isAdmin() || !this.data.ai || !p.text) return null;
    const b = el("button", { type: "button", class: "small", title: t("tg.translate_title") }, t("tg.translate"));
    b.addEventListener("click", async () => {
      b.disabled = true;
      b.textContent = t("tg.translating");
      try {
        const r = await api("api/telegram/translate", { json: { channel: p.channel, post_id: p.post_id } });
        p.translation = r.text;
        p.translated_to = r.lang;
        this.orig.delete(`${p.channel}/${p.post_id}`);
        this.rerender(p);
      } catch (e) {
        b.replaceWith(el("span", { class: "state err" }, e.message));
      }
    });
    return b;
  }

  /** Renders one post again in place (full text, translation). */
  rerender(p) {
    const i = this.posts.indexOf(p);
    const li = this.list?.children[i];
    if (li) li.replaceWith(this.post(p));
  }

  showOnMap(p) {
    this.onMap?.();
    const n = this.map.showWeltItem({ origin: null, countries: p.countries.filter(ccOk), cables: [] });
    this.mapped = n ? `${p.channel}/${p.post_id}` : null;
  }

  // --- channels ----------------------------------------------------------------------------------------------------
  channels(d) {
    const admin = isAdmin();
    const msg = el("p", { class: "note", "aria-live": "polite" });
    const say = (text, bad = false) => { msg.className = bad ? "state err" : "note ok-txt"; msg.textContent = text; };
    const rows = d.channels.map((c) => el("tr", {},
      el("td", {}, safeLink(`https://t.me/s/${c.name}`, `@${c.name}`) || `@${c.name}`, c.title ? el("div", { class: "muted" }, c.title) : null,
        c.note ? el("div", { class: "muted" }, c.note) : null),
      el("td", { class: "num" }, num(c.posts)),
      el("td", { class: c.error ? "warn-txt" : "muted" }, c.error ? channelError(c.error) : c.last_ok ? ago(c.last_ok) : t("tg.waiting")),
      admin ? el("td", { class: "num" },
        el("button", { type: "button", class: "small", title: t("tg.ch_refresh_title"), onclick: async () => {
          try { await api(`api/telegram/channels/${encodeURIComponent(c.name)}/refresh`, { method: "POST" }); say(t("tg.ch_reading", { name: c.name })); setTimeout(() => this.load(), 6000); } catch (e) { say(e.message, true); }
        } }, t("tg.ch_refresh")),
        el("button", { type: "button", class: "small danger", title: t("common.delete"), "aria-label": t("tg.ch_remove", { name: c.name }), onclick: async () => {
          if (!window.confirm(t("tg.ch_remove_q", { name: c.name }))) return;
          try { await api(`api/telegram/channels/${encodeURIComponent(c.name)}`, { method: "DELETE" }); if (this.f.channel === c.name) this.f.channel = ""; this.load(); } catch (e) { say(e.message, true); }
        } }, "×")) : null));
    const name = el("input", { type: "text", required: true, maxlength: 120, placeholder: t("tg.ch_name_ph"), "aria-label": t("tg.ch_name"), spellcheck: "false" });
    const note = el("input", { type: "text", maxlength: 200, placeholder: t("tg.ch_note_ph"), "aria-label": t("tg.ch_note") });
    const add = admin ? el("form", { class: "tg-add", onsubmit: async (e) => {
      e.preventDefault();
      try {
        const r = await api("api/telegram/channels", { json: { name: name.value.trim(), note: note.value.trim() || null } });
        name.value = note.value = "";
        say(t("tg.ch_added", { name: r.name }));
        setTimeout(() => this.load(), 6000);
        this.load();
      } catch (er) { say(er.message, true); }
    } }, name, note, el("button", { type: "submit", class: "primary" }, t("tg.ch_add"))) : null;
    return el("details", { class: "tg-channels", open: !d.channels.length },
      el("summary", {}, t("tg.channels", { n: num(d.channels.length) })),
      d.channels.length ? el("table", { class: "res" },
        el("thead", {}, el("tr", {}, el("th", {}, t("tg.ch")), el("th", { class: "num" }, t("tg.ch_posts")), el("th", {}, t("tg.ch_state")), admin ? el("th", {}) : null)),
        el("tbody", {}, rows)) : el("p", { class: "empty" }, t("tg.no_channels")),
      add, msg,
      el("ul", { class: "plain method" }, ["tg.m1", "tg.m2", "tg.m3"].map((k) => el("li", {}, t(k)))));
  }
}
