// Weltlage: security reports of authorities and specialist media on the world map (indigo mode).
// Band: layers (country pairs, countries), "corroborated" and "law & sanctions" filters, sources, focus, period.
// Side panel: reports, actors, country pairs, briefing (Gemini) with the source list.
// Drawer (#/welt/n/<id>): one report in its context with the local data on it.
// Origin and actors are recognised automatically from headline and teaser; attributions are statements of the sources.
import { reportArticle } from "./ai.js";
import { destroy, lineChart } from "./charts.js";
import { locale, t } from "./i18n.js";
import { kpiTile } from "./panels.js";
import { go, href, objLink, routes } from "./router.js";
import { ago, api, countryName, dateOnly, dateTime, dec2, el, kids, num, pct, safeLink } from "./util.js";

export const KINDS = ["ransomware", "ddos", "espionage", "sabotage", "phishing", "breach", "vulnerability", "supply_chain", "botnet",
  "disinfo", "law", "sanctions", "policy"];
const LAW = "law,sanctions";
const PAGE = 40;
const httpsImg = (u) => (typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u) ? u : null);
const kindLabel = (k) => t(`wl.kind.${k}`);
const FEED_ERRORS = ["http", "timeout", "network", "too_large", "redirect", "redirect_http", "redirect_private", "parse", "entities", "other"];
/** Why a feed could not be read (stored as a code by the server, rendered in the interface language). */
function feedError(s) {
  const code = FEED_ERRORS.includes(s.error) ? s.error : "other";
  const p = s.error_params || {};
  const text = t(`wl.feed_err.${code}`, { status: String(p.status ?? "?") });
  return (code === "network" || code === "other") && p.detail ? `${text} (${p.detail})` : text;
}
const destroyIn = (node) => node.querySelectorAll("canvas").forEach(destroy);

/** Preview image of the publisher: loaded by the browser without referrer; removed if it fails. */
function thumb(url, cls, fallback) {
  const src = httpsImg(url);
  if (!src) return el("div", { class: `${cls} noimg`, "aria-hidden": "true" }, fallback);
  const img = el("img", { class: cls, src, alt: "", loading: "lazy", decoding: "async", referrerpolicy: "no-referrer" });
  img.addEventListener("error", () => img.replaceWith(el("div", { class: `${cls} noimg`, "aria-hidden": "true" }, fallback)), { once: true });
  return img;
}

const initials = (name) => (name || "?").replace(/[^A-Za-zÄÖÜäöü0-9 ]/g, "").split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]).join("").toUpperCase();

function pairLabel(it) {
  if (!it.origin) return null;
  const to = it.countries.slice(0, 3).join(", ");
  return `${it.origin} → ${to || t("wl.world")}`;
}

export class Welt {
  constructor({ map, onCyber, onMap }) {
    this.map = map;
    this.onCyber = onCyber; // (cc) => switch to the Cyberlage with this country
    this.onMap = onMap; // () => the map must be visible
    this.f = { days: 7, source: "", focus: "", kind: "", q: "", mine: false, confirmed: false, actor: "", origin: "", target: "" };
    this.tab = "news";
    this.ov = null;
    this.items = [];
    this.total = null;
    this.status = null;
    this.seq = 0;
    this.drawerSeq = 0;
    this.active = false;
    this.focusOptions = new Set();
    this.side = document.getElementById("side");
    this.drawer = document.getElementById("news-drawer");
    this.drawerBody = document.getElementById("drawer-body");
    this.panels = Object.fromEntries(["news", "actors", "pairs", "brief"].map((k) => [k, document.getElementById(`tp-${k}`)]));
    this.sel = { source: document.getElementById("wl-source"), focus: document.getElementById("wl-focus"), days: document.getElementById("wl-days") };
    this.bindBand();
    document.querySelectorAll("#tabs-welt button").forEach((b) => b.addEventListener("click", () => this.setTab(b.dataset.side)));
    document.getElementById("drawer-close").addEventListener("click", () => go(routes.welt()));
  }

  // --- band ----------------------------------------------------------------------------------------------------
  bindBand() {
    const arcs = document.getElementById("wl-arcs"), dots = document.getElementById("wl-dots");
    arcs.addEventListener("change", () => this.map.setWeltVisible("pairs", arcs.checked));
    dots.addEventListener("change", () => this.map.setWeltVisible("dots", dots.checked));
    // the browser may restore checkbox states on reload: the map follows the boxes from the start
    this.map.setWeltVisible("pairs", arcs.checked);
    this.map.setWeltVisible("dots", dots.checked);
    const confirmed = document.getElementById("wl-confirmed"), law = document.getElementById("wl-law");
    confirmed.addEventListener("change", () => this.set({ confirmed: confirmed.checked }));
    law.addEventListener("change", () => this.set({ kind: law.checked ? LAW : "" }));
    this.sel.days.addEventListener("change", () => { this.daysUser = true; this.set({ days: Number(this.sel.days.value) }); });
    this.sel.source.addEventListener("change", () => this.set({ source: this.sel.source.value }));
    this.sel.focus.addEventListener("change", () => this.setFocus(this.sel.focus.value));
  }

  syncBand() {
    document.getElementById("wl-confirmed").checked = this.f.confirmed;
    document.getElementById("wl-law").checked = this.f.kind === LAW;
    this.sel.days.value = String(this.f.days);
    this.fillSources();
    this.fillFocus();
  }

  fillSources() {
    const srcs = this.ov?.sources || [];
    const opts = [["", t("wl.src.all")], ["gov", t("wl.src.gov")], ["press", t("wl.src.press")], ...srcs.map((s) => [s.id, s.name])];
    kids(this.sel.source, ...opts.map(([v, l]) => el("option", { value: v, selected: v === this.f.source }, l)));
  }

  fillFocus() {
    const region = this.status?.region?.codes || [];
    const opts = [["", t("wl.focus.world")]];
    if (region.length) opts.push(["region", this.status.region.name || region.join(", ")]);
    if (this.f.focus && this.f.focus !== "region") this.focusOptions.add(this.f.focus);
    for (const cc of this.focusOptions) opts.push([cc, countryName(cc)]);
    kids(this.sel.focus, ...opts.map(([v, l]) => el("option", { value: v, selected: v === this.f.focus }, l)));
  }

  /** Focus on a country ("DE"), the home region ("region") or the world (""). */
  setFocus(v) {
    const val = v === "region" || /^[A-Z]{2}$/.test(v || "") ? v : "";
    if (val === this.f.focus) return;
    this.map.select(/^[A-Z]{2}$/.test(val) ? val : null);
    this.set({ focus: val });
  }

  set(partial) {
    Object.assign(this.f, partial);
    this.syncBand();
    this.load();
  }

  setStatus(status) {
    this.status = status;
    if (this.active) this.fillFocus();
  }

  // --- data ------------------------------------------------------------------------------------------------------
  params(extra = {}) {
    const f = this.f;
    const p = new URLSearchParams({ days: String(f.days) });
    if (f.source === "gov" || f.source === "press") p.set("tier", f.source);
    else if (f.source) p.set("source", f.source);
    const region = this.status?.region?.codes || [];
    if (f.focus === "region" && region.length) p.set("country", "region"); // the server expands HOME_REGION (any size)
    else if (/^[A-Z]{2}$/.test(f.focus)) p.set("country", f.focus);
    for (const k of ["kind", "q", "actor", "origin", "target"]) if (f[k]) p.set(k, f[k]);
    if (f.mine) p.set("mine", "true");
    if (f.confirmed) p.set("confirmed", "true");
    for (const [k, v] of Object.entries(extra)) p.set(k, String(v));
    return p.toString();
  }

  async load() {
    const seq = ++this.seq;
    if (!this.ov) kids(this.panels.news, el("p", { class: "state" }, t("wl.loading")));
    try {
      const ov = await api(`api/welt?${this.params()}`);
      if (seq !== this.seq) return;
      if (!this.active) { // left the Weltlage meanwhile: the key figures belong to the Cyberlage now
        this.stale = true;
        return;
      }
      this.ov = ov;
      this.items = ov.items;
      this.total = ov.kpis.events;
      this.fillSources();
      this.map.setWelt({ pairs: ov.pairs, mentioned: ov.countries, origins: ov.origins });
      this.renderKpis();
      this.renderTab();
    } catch (e) {
      if (seq !== this.seq || !this.active) return;
      const msg = e.status === 404 ? t("wl.off") : t("common.error", { msg: e.message });
      kids(this.panels.news, el("p", { class: "state err" }, msg));
      kids(document.getElementById("kpis"));
    }
  }

  async more(btn) {
    btn.disabled = true;
    const seq = this.seq; // a filter changed meanwhile: these items belong to the old selection
    try {
      const r = await api(`api/news?${this.params({ offset: this.items.length, limit: PAGE })}`);
      if (seq !== this.seq || !this.active) return;
      const known = new Set(this.items.map((x) => x.id));
      this.items.push(...r.items.filter((x) => !known.has(x.id)));
      this.total = r.total;
      this.renderTab();
    } catch (e) {
      if (seq !== this.seq || !btn.isConnected) return;
      btn.replaceWith(el("p", { class: "state err" }, t("common.error", { msg: e.message })));
    }
  }

  // --- area ----------------------------------------------------------------------------------------------------
  /** Route #/welt[?…] or #/welt/n/<id>. ctx.country: the country selected in the Cyberlage. */
  show(r, ctx = {}) {
    const first = !this.active;
    this.active = true;
    const q = r.query;
    const fromLink = {};
    if (q.get("actor")) fromLink.actor = q.get("actor").slice(0, 120);
    if (q.get("kind") && KINDS.includes(q.get("kind"))) fromLink.kind = q.get("kind");
    if (/^[A-Z]{2}$/.test(q.get("country") || "")) fromLink.focus = q.get("country");
    if (["1", "7", "30", "90"].includes(q.get("days") || "")) fromLink.days = Number(q.get("days"));
    if (first && ctx.country && !fromLink.focus && !this.f.focus) fromLink.focus = ctx.country;
    // period chosen in the Cyberlage: only when entering, not on the drawer routes (#/welt/n/<id>) inside the Weltlage
    if (first && ctx.days && !fromLink.days && ctx.days !== this.f.days) fromLink.days = ctx.days;
    if (fromLink.actor || fromLink.kind || fromLink.focus) {
      // a link from elsewhere ("reports on actor X") starts from a clean selection; source and period stay
      Object.assign(this.f, { q: "", mine: false, origin: "", target: "", kind: "", actor: "", confirmed: false });
      if (fromLink.actor && !fromLink.focus) fromLink.focus = "";
      this.tab = "news";
    }
    if (Object.keys(fromLink).length) Object.assign(this.f, fromLink);
    this.map.select(/^[A-Z]{2}$/.test(this.f.focus) ? this.f.focus : null);
    this.syncBand();
    this.syncTabs();
    if (first || this.stale || Object.keys(fromLink).length || !this.ov) {
      this.stale = false;
      this.load();
    }
    const id = r.parts[0] === "n" && /^\d{1,12}$/.test(r.parts[1] || "") ? Number(r.parts[1]) : null;
    if (id) this.openDrawer(id);
    else this.closeDrawer();
  }

  leave() {
    this.active = false;
    this.closeDrawer();
  }

  /** Context for the Cyberlage: the focused country and the period. */
  context() {
    return { country: /^[A-Z]{2}$/.test(this.f.focus) ? this.f.focus : null, days: this.daysUser ? this.f.days : null };
  }

  /** A country was clicked on the map. */
  pickCountry(cc) {
    if (this.f.focus === cc) return;
    this.focusOptions.add(cc);
    this.setFocus(cc);
  }

  /** Country selected in the Cyberlage (context). */
  setCountry(cc) {
    if (cc && /^[A-Z]{2}$/.test(cc)) this.focusOptions.add(cc);
    if (this.active) return;
    const focus = cc || (this.f.focus === "region" ? "region" : "");
    if (focus !== this.f.focus) {
      this.f.focus = focus;
      this.stale = true; // reload when the Weltlage is shown again
    }
  }

  setTab(tab) {
    this.tab = tab;
    this.syncTabs();
    this.renderTab();
  }

  syncTabs() {
    document.querySelectorAll("#tabs-welt button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.side === this.tab)));
    for (const [k, node] of Object.entries(this.panels)) node.hidden = k !== this.tab;
  }

  // --- key figures and legend --------------------------------------------------------------------------------------
  renderKpis() {
    const k = this.ov.kpis;
    const days = this.ov.days;
    const region = this.status?.region?.codes?.length ? (this.status.region.name || this.status.region.codes.join(", ")) : null;
    const tiles = [
      { key: "news", label: t("wl.kpi.reports"), value: num(k.items), sub: t("wl.kpi.reports_sub", { e: num(k.events), d: num(days) }) },
      { key: "pairs", label: t("wl.kpi.pairs"), value: num(k.pairs), sub: t("wl.kpi.pairs_sub") },
      { key: "home", label: region ? t("wl.kpi.home", { name: region }) : t("wl.kpi.home_de"), value: num(k.home), sub: t("wl.kpi.home_sub", { d: num(days) }) },
      { key: "mine", label: t("wl.kpi.mine"), value: num(k.mine), sub: t("wl.kpi.mine_sub", { n: num(k.vendor) }), hot: k.mine > 0 },
    ];
    kids(document.getElementById("kpis"), ...tiles.map((x) => kpiTile(x, (key) => this.onKpi(key))));
    kids(document.getElementById("maphint"),
      el("span", { class: "lg-sym" }, el("i", { class: "sw sw-wpair", "aria-hidden": "true" }), t("wl.hint.pairs"),
        el("i", { class: "sw sw-wdot", "aria-hidden": "true" }), t("wl.hint.dots"), el("i", { class: "sw sw-wring", "aria-hidden": "true" }), t("wl.hint.rings")),
      el("span", { class: "lg-stamp" }, t("wl.hint.auto")));
  }

  onKpi(key) {
    if (key === "pairs") return this.setTab("pairs");
    if (key === "home") return this.setFocus(this.status?.region?.codes?.length ? "region" : "DE");
    if (key === "mine") { this.set({ mine: !this.f.mine }); return this.setTab("news"); }
    return this.setTab("news");
  }

  // --- side panel ------------------------------------------------------------------------------------------------
  renderTab() {
    if (!this.ov) return;
    const node = this.panels[this.tab];
    destroyIn(node);
    if (this.tab === "news") this.renderNews(node);
    else if (this.tab === "actors") this.renderActors(node);
    else if (this.tab === "pairs") this.renderPairs(node);
    else this.renderBrief(node);
  }

  activeFilters() {
    const f = this.f;
    const chips = [];
    const clear = (partial) => el("button", { type: "button", class: "small", title: t("wl.filter_clear"), onclick: () => this.set(partial) }, "×");
    if (f.actor) chips.push(el("span", { class: "fchip" }, t("wl.f.actor", { name: f.actor }), clear({ actor: "" })));
    if (f.origin || f.target) chips.push(el("span", { class: "fchip" }, `${f.origin || "*"} → ${f.target || "*"}`, clear({ origin: "", target: "" })));
    if (f.mine) chips.push(el("span", { class: "fchip" }, t("wl.f.mine"), clear({ mine: false })));
    if (f.q) chips.push(el("span", { class: "fchip" }, `„${f.q}“`, clear({ q: "" })));
    return chips.length ? el("div", { class: "fchips" }, ...chips) : null;
  }

  renderNews(node) {
    const kind = el("select", { "aria-label": t("wl.f.kind") },
      el("option", { value: "" }, t("wl.f.kind_all")),
      el("option", { value: LAW, selected: this.f.kind === LAW }, t("wl.chip.law")),
      ...KINDS.map((k) => el("option", { value: k, selected: this.f.kind === k }, kindLabel(k))));
    kind.addEventListener("change", () => this.set({ kind: kind.value }));
    const q = el("input", { type: "search", maxlength: 100, placeholder: t("wl.f.q"), "aria-label": t("wl.f.q"), value: this.f.q });
    const form = el("form", { class: "wl-filter", role: "search" }, kind, q);
    form.addEventListener("submit", (e) => { e.preventDefault(); this.set({ q: q.value.trim() }); });
    const mine = el("input", { type: "checkbox", checked: this.f.mine });
    mine.addEventListener("change", () => this.set({ mine: mine.checked }));
    const items = this.items;
    const list = items.length
      ? el("ol", { class: "news" }, items.map((it) => this.card(it)))
      : el("p", { class: "empty" }, this.ov.sources?.some((s) => s.last_ok) ? t("wl.none") : t("wl.none_yet"));
    const moreBtn = el("button", { type: "button", class: "small" }, t("wl.more", { n: num(Math.min(PAGE, (this.total || 0) - items.length)) }));
    moreBtn.addEventListener("click", () => this.more(moreBtn));
    kids(node,
      form,
      el("label", { class: "pcheck wl-mine" }, mine, t("wl.f.mine_label")),
      this.activeFilters(),
      el("p", { class: "note" }, t("wl.count", { n: num(this.total || 0), d: num(this.f.days) })),
      list,
      this.total > items.length ? el("p", { class: "more-link" }, moreBtn) : null);
  }

  card(it) {
    const tags = [];
    for (const a of it.actors.slice(0, 2)) tags.push(el("span", { class: "wtag actor" }, a));
    const pl = pairLabel(it);
    if (pl) tags.push(el("span", { class: "wtag pair", title: it.origin_by === "actor" ? t("wl.origin_by_actor") : t("wl.origin_by_text") }, pl));
    for (const k of it.kinds.slice(0, 2)) tags.push(el("span", { class: "wtag" }, kindLabel(k)));
    for (const c of it.cves.slice(0, 1)) tags.push(el("span", { class: "wtag mono" }, c));
    const mine = it.mine.filter((m) => m.type !== "vendor");
    if (mine.length) tags.push(el("span", { class: "wtag mine", title: mine.map((m) => m.label).join(", ") }, t("wl.tag.mine")));
    else if (it.mine.length) tags.push(el("span", { class: "wtag vendor", title: it.mine.map((m) => m.label).join(", ") }, t("wl.tag.vendor")));
    return el("li", {},
      el("a", { class: "ncard", href: href(routes.news(it.id)) },
        thumb(it.image, "nthumb", initials(it.source.name)),
        el("span", { class: "nbody" },
          el("span", { class: "ntitle", lang: it.lang || null }, it.title),
          el("span", { class: "nmeta" }, it.source.tier === "gov" ? el("span", { class: "gov" }, t("wl.gov")) : null, it.source.name, " · ", ago(it.latest),
            it.n > 1 ? ` · ${t("wl.n_sources", { n: num(it.sources.length), r: num(it.n) })}` : ""),
          tags.length ? el("span", { class: "ntags" }, tags) : null)));
  }

  renderActors(node) {
    const acts = this.ov.actors || [];
    const max = acts.reduce((a, x) => Math.max(a, x.n), 0) || 1;
    kids(node,
      el("h3", { class: "tp-h" }, t("wl.actors_h")),
      el("p", { class: "note" }, t("wl.actors_note")),
      acts.length ? el("ol", { class: "rank" }, acts.map((a) => el("li", { class: "clickable", onclick: (e) => {
        if (e.target.closest("a")) return; // the link opens the actor page
        this.set({ actor: a.name });
        this.setTab("news");
      } },
        el("span", { class: "lbl" }, a.name, a.canonical && a.canonical !== a.name ? el("span", { class: "muted" }, ` (${a.canonical})`) : null),
        el("span", { class: "val" }, num(a.n)),
        el("span", { class: "sub" }, a.country ? t("wl.actor_cc", { name: countryName(a.country) }) : t("wl.actor_nocc"), " · ",
          objLink("actor", a.canonical || a.name, t("wl.actor_page"))),
        el("span", { class: "bar", "aria-hidden": "true" }, el("i", { style: `width:${Math.max(2, (a.n / max) * 100)}%` })))))
        : el("p", { class: "empty" }, t("wl.actors_none")));
  }

  renderPairs(node) {
    const ov = this.ov;
    const rows = (list, fmt) => list.length ? el("ol", { class: "rank" }, list) : el("p", { class: "empty" }, fmt);
    const maxP = ov.pairs.reduce((a, x) => Math.max(a, x.n), 0) || 1;
    const pairItems = ov.pairs.slice(0, 25).map((p) => el("li", { class: "clickable", onclick: () => { this.set({ origin: p.origin, target: p.target }); this.setTab("news"); } },
      el("span", { class: "lbl" }, `${countryName(p.origin)} → ${countryName(p.target)}`), el("span", { class: "val" }, num(p.n)),
      el("span", { class: "bar", "aria-hidden": "true" }, el("i", { style: `width:${Math.max(2, (p.n / maxP) * 100)}%` }))));
    const ranked = (obj) => Object.entries(obj || {}).sort((a, b) => b[1] - a[1]).slice(0, 15);
    const ccItems = (obj) => ranked(obj).map(([cc, n]) => el("li", { dataset: { cc }, onclick: () => this.pickCountry(cc) },
      el("span", { class: "lbl" }, countryName(cc)), el("span", { class: "val" }, num(n))));
    kids(node,
      el("h3", { class: "tp-h" }, t("wl.pairs_h")), el("p", { class: "note" }, t("wl.pairs_note")), rows(pairItems, t("wl.pairs_none")),
      el("h3", { class: "tp-h" }, t("wl.origins_h")), el("p", { class: "note" }, t("wl.origins_note")), rows(ccItems(ov.origins), t("common.no_data")),
      el("h3", { class: "tp-h" }, t("wl.named_h")), rows(ccItems(ov.countries), t("common.no_data")),
      el("h3", { class: "tp-h" }, t("wl.kinds_h")),
      Object.keys(ov.kinds).length ? el("div", { class: "chips" }, Object.entries(ov.kinds).map(([k, n]) =>
        el("button", { type: "button", class: "small", onclick: () => { this.set({ kind: k }); this.setTab("news"); } }, kindLabel(k), " ", el("b", {}, num(n))))) : el("p", { class: "empty" }, t("common.no_data")));
  }

  renderBrief(node) {
    const enabled = Boolean(this.status?.ai?.enabled);
    const scope = `welt:${this.f.days}`;
    const out = el("div", { class: "ai-out" });
    const run = el("button", { type: "button", class: "primary", disabled: !enabled }, t("wl.brief_run", { d: num(this.f.days) }));
    const q = el("input", { type: "text", maxlength: 600, placeholder: t("wl.brief_q"), "aria-label": t("wl.brief_q") });
    const ask = el("button", { type: "submit", disabled: !enabled }, t("ai.ask"));
    const form = el("form", { class: "ai-ask" }, q, ask);
    let current = null, thread = [];
    const show = () => { destroyIn(out); kids(out, reportArticle(current, thread, { onFollowup: (fm) => follow(fm) })); };
    const follow = async (fm) => {
      const question = fm.querySelector("input").value.trim();
      if (!question || !current?.id) return;
      fm.querySelector("button").disabled = true;
      const wait = el("p", { class: "state" }, t("ai.followup_running"));
      fm.before(wait);
      try { thread.push(await api("api/ai/followup", { json: { report_id: current.id, question } })); show(); } catch (e) {
        wait.className = "state err";
        wait.textContent = t("ai.followup_failed", { msg: e.message });
        fm.querySelector("button").disabled = false;
      }
    };
    const go2 = async (question) => {
      run.disabled = ask.disabled = true;
      destroyIn(out);
      kids(out, el("p", { class: "state" }, t("ai.running")));
      try {
        current = await api("api/ai/welt", { json: { days: this.f.days, question: question || null } });
        thread = [];
        show();
      } catch (e) {
        kids(out, el("p", { class: "state err" }, t("ai.failed", { msg: e.message })));
      } finally {
        run.disabled = ask.disabled = !enabled;
      }
    };
    run.addEventListener("click", () => go2(null));
    form.addEventListener("submit", (e) => { e.preventDefault(); if (q.value.trim()) go2(q.value.trim()); });
    if (enabled) {
      api(`api/ai/reports?limit=1&scope=${encodeURIComponent(scope)}`).then(async (list) => {
        if (!list.length || current) return;
        current = list[0];
        try { thread = await api(`api/ai/reports/${current.id}/thread`); } catch { thread = []; }
        show();
      }).catch(() => {});
    }
    const srcs = this.ov.sources || [];
    kids(node,
      el("h3", { class: "tp-h" }, t("wl.brief_h")),
      el("p", { class: "note" }, enabled ? t("wl.brief_note") : t("an.ai_off")),
      el("div", { class: "btnrow" }, run), form, out,
      el("h3", { class: "tp-h" }, t("wl.sources_h")),
      el("table", { class: "res srcs" }, el("tbody", {}, srcs.map((s) => el("tr", {},
        el("td", {}, el("i", { class: `dot ${s.ok === true ? "ok" : s.ok === false ? "fail" : ""}`, "aria-hidden": "true" }), s.name,
          s.tier === "gov" ? el("span", { class: "gov" }, t("wl.gov")) : null),
        el("td", { class: "num" }, t("wl.src_items", { n: num(s.items_7d) })),
        el("td", { class: s.ok === false ? "warn-txt" : "muted" }, s.ok === false ? feedError(s) : s.last_ok ? ago(s.last_ok) : t("st.not_fetched")))))),
      el("h3", { class: "tp-h" }, t("wl.method_h")),
      el("ul", { class: "plain method" }, ["wl.method1", "wl.method2", "wl.method3", "wl.method4"].map((k) => el("li", {}, t(k)))));
  }

  // --- drawer: one report in its context ------------------------------------------------------------------------------
  closeDrawer() {
    if (this.drawer.hidden) return;
    this.drawerSeq++;
    destroyIn(this.drawerBody);
    this.drawer.hidden = true;
    document.body.classList.remove("drawer-open");
    this.map.clearWeltItem();
  }

  async openDrawer(id) {
    const seq = ++this.drawerSeq;
    this.drawer.hidden = false;
    document.body.classList.add("drawer-open");
    destroyIn(this.drawerBody);
    kids(this.drawerBody, el("p", { class: "state" }, t("wl.loading")));
    let it;
    try {
      it = await api(`api/news/${id}`);
    } catch (e) {
      if (seq !== this.drawerSeq) return;
      kids(this.drawerBody, el("p", { class: "state err" }, e.status === 404 ? t("wl.gone") : t("common.error", { msg: e.message })),
        el("p", {}, el("a", { class: "btn", href: href(routes.welt()) }, t("wl.back"))));
      return;
    }
    if (seq !== this.drawerSeq) return;
    this.drawerBody.scrollTop = 0;
    kids(this.drawerBody, ...this.drawerContent(it));
    this.map.showWeltItem(it);
  }

  drawerContent(it) {
    const kv = (rows) => el("dl", { class: "kv dkv" }, rows.filter(([, v]) => v !== null && v !== undefined && v !== "").flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
    const sect = (title, ...body) => el("section", { class: "dsect" }, el("h3", {}, title), ...body);
    // classification
    const attribution = it.origin
      ? [countryName(it.origin), " ", el("span", { class: "muted" }, it.origin_by === "actor" ? t("wl.origin_by_actor_long", { actor: it.actor_info?.[0]?.name || "" }) : t("wl.origin_by_text_long"))]
      : t("wl.no_origin");
    const chips = [];
    for (const a of it.actor_info || []) chips.push(objLink("actor", a.canonical || a.name, a.name, "echip"));
    for (const a of it.actors.filter((x) => !(it.actor_info || []).some((i) => i.name === x))) chips.push(objLink("actor", a, a, "echip"));
    for (const cc of [it.origin, ...it.countries].filter(Boolean)) chips.push(objLink("country", cc, countryName(cc), "echip"));
    for (const c of it.cves) chips.push(objLink("cve", c, c, "echip mono"));
    for (const m of it.malware) chips.push(objLink("malware", m, m, "echip"));
    const actorRows = (it.actor_info || []).map((a) => [a.name, [a.country ? countryName(a.country) : t("wl.actor_nocc"),
      a.sponsor ? ` · ${t("wl.sponsor", { s: a.sponsor })}` : "", a.confidence ? ` · ${t("wl.confidence", { v: a.confidence })}` : "",
      a.synonyms?.length ? el("span", { class: "muted" }, ` · ${t("wl.aka", { names: a.synonyms.slice(0, 4).join(", ") })}`) : null]]);
    // same event
    const members = it.members || [];
    const srcCountries = it.source_countries || [];
    const same = sect(t("wl.d.same"),
      el("p", {}, members.length > 1
        ? [t("wl.d.same_n", { n: num(members.length), s: num(new Set(members.map((m) => m.source)).size) }),
          srcCountries.length ? ` ${t("wl.d.same_cc", { list: srcCountries.map(countryName).join(", ") })}` : ""].join("")
        : t("wl.d.same_one")),
      members.length > 1 ? el("ol", { class: "members" }, members.map((m) => el("li", {},
        el("span", { class: "muted" }, `${m.source} · ${dateTime(m.published)} `), safeLink(m.url, m.title) || m.title))) : null);
    // data on it
    const data = [];
    const pair = it.pair;
    let pairCanvas = null;
    if (pair) {
      const nNews = pair.news.reduce((a, v) => a + (v || 0), 0);
      data.push([t("wl.d.pair_news", { o: pair.origin, t: pair.target }), t("wl.d.pair_news_v", { n: num(nNews), d: num(pair.labels.length) })]);
      const last = [...pair.radar].reverse().find((v) => v !== null && v !== undefined);
      data.push([t("wl.d.pair", { o: pair.origin, t: pair.target }), last !== undefined ? t("wl.d.pair_last", { v: pct(last) }) : t("wl.d.pair_none")]);
      // one series, one unit: the Cloudflare share per day (null = the pair was not among the top pairs that day)
      if (pair.radar.some((v) => v !== null && v !== undefined)) pairCanvas = el("canvas", { role: "img", "aria-label": t("wl.d.pair_aria", { o: pair.origin, t: pair.target }) });
    }
    for (const c of it.cve_info || []) {
      data.push([c.cve, [c.kev ? t("wl.d.kev", { d: dateOnly(c.kev_added) }) : t("wl.d.no_kev"), c.epss !== null && c.epss !== undefined ? ` · EPSS ${dec2(c.epss)}` : "",
        c.ransomware ? ` · ${t("wl.d.ransom")}` : ""].join("")]);
    }
    for (const m of it.malware_info || []) data.push([m.name, t("wl.d.c2", { n: num(m.c2_30d) })]);
    const mineReal = it.mine.filter((m) => m.type !== "vendor");
    const mineVendor = it.mine.filter((m) => m.type === "vendor");
    const mineLink = (m) => (m.type === "domain" ? el("a", { href: href(routes.asset(m.id)) }, m.label) : el("a", { href: href(routes.product(m.id)) }, m.label));
    const enabled = Boolean(this.status?.ai?.enabled);
    const aiOut = el("div", { class: "ai-out" });
    const aiBtn = el("button", { type: "button", disabled: !enabled, title: enabled ? t("wl.d.ai_title") : t("an.ai_off") }, t("wl.d.ai"));
    aiBtn.addEventListener("click", () => this.aiNews(it, aiBtn, aiOut));
    const target = it.countries[0] || it.origin;
    const firstObj = it.actor_info?.[0] ? ["actor", it.actor_info[0].canonical || it.actor_info[0].name] : it.cves[0] ? ["cve", it.cves[0]]
      : it.malware[0] ? ["malware", it.malware[0]] : target ? ["country", target] : null;
    const img = httpsImg(it.image);
    const nodes = [
      img ? this.figure(img, it.image_source || it.source.name) : null,
      el("header", { class: "dhead" },
        el("h2", { lang: it.lang || null }, it.title),
        el("p", { class: "nmeta" }, it.source.tier === "gov" ? el("span", { class: "gov" }, t("wl.gov")) : null, it.source.name, " · ", dateTime(it.published), " · ",
          safeLink(it.url, t("wl.d.open")) || ""),
        it.summary ? el("p", { class: "dlead", lang: it.lang || null }, it.summary) : null),
      sect(t("wl.d.class"),
        kv([[t("wl.d.kind"), it.kinds.length ? it.kinds.map(kindLabel).join(" · ") : t("wl.d.kind_none")],
          [t("wl.d.attr"), el("span", {}, ...[attribution].flat())],
          [t("wl.d.found"), chips.length ? el("span", { class: "echips" }, chips) : t("common.none")],
          ...actorRows]),
        el("p", { class: "note" }, t("wl.d.auto"))),
      same,
      sect(t("wl.d.data"), data.length ? kv(data) : el("p", { class: "note" }, t("wl.d.data_none")),
        pairCanvas ? el("div", { class: "chart-box small" }, pairCanvas) : null,
        pair ? el("p", { class: "note" }, t("wl.d.pair_note")) : null),
      sect(t("wl.d.mine"),
        mineReal.length ? el("ul", { class: "plain mine-list" }, mineReal.map((m) => el("li", { class: "warn-txt" }, t(`wl.d.mine_${m.type}`), " ", mineLink(m)))) : null,
        mineVendor.length ? el("p", { class: "note" }, t("wl.d.mine_vendor", { names: mineVendor.map((m) => m.label).join(", ") })) : null,
        !it.mine.length ? el("p", { class: "note" }, t("wl.d.mine_none")) : null),
      el("div", { class: "dactions" },
        el("button", { type: "button", class: "primary", onclick: () => { this.onMap?.(); this.map.showWeltItem(it); } }, t("wl.d.map")),
        target ? el("button", { type: "button", onclick: () => this.toCyber(target) }, t("wl.d.cyber", { name: countryName(target) })) : null,
        aiBtn,
        firstObj ? el("a", { class: "btn", href: href(routes.obj(firstObj[0], firstObj[1])) }, t("wl.d.obj")) : null),
      aiOut,
    ];
    if (pairCanvas) {
      const labels = pair.labels.map((d) => new Date(`${d}T12:00:00Z`).toLocaleDateString(locale, { day: "2-digit", month: "2-digit" }));
      requestAnimationFrame(() => {
        if (!pairCanvas.isConnected) return;
        lineChart(pairCanvas, { labels, unit: "%", series: [{ name: t("wl.d.series_radar", { o: pair.origin, t: pair.target }), values: pair.radar }], spanGaps: false });
      });
    }
    // show the stored assessment of this report, if there is one
    if (enabled) {
      api(`api/ai/reports?limit=1&scope=${encodeURIComponent(`news:${it.id}`)}`).then(async (list) => {
        if (!list.length || aiOut.childElementCount || !aiOut.isConnected) return;
        await this.showNewsReport(list[0], aiOut, true);
      }).catch(() => {});
    }
    return nodes.filter(Boolean);
  }

  /** To the Cyberlage with this country: it becomes the focus here, so the Cyberlage takes it over as context. */
  toCyber(cc) {
    this.focusOptions.add(cc);
    if (this.f.focus !== cc) {
      this.f.focus = cc;
      this.stale = true;
    }
    this.onCyber(cc);
  }

  /** Preview image of the publisher; the whole figure goes away if the image cannot be loaded. */
  figure(src, by) {
    const img = el("img", { class: "dpic", src, alt: "", decoding: "async", referrerpolicy: "no-referrer" });
    const fig = el("figure", { class: "dimg" }, img, el("figcaption", {}, t("wl.d.img", { src: by })));
    img.addEventListener("error", () => fig.remove(), { once: true });
    return fig;
  }

  async aiNews(it, btn, out) {
    btn.disabled = true;
    destroyIn(out);
    kids(out, el("p", { class: "state" }, t("ai.running")));
    try {
      const r = await api("api/ai/news", { json: { id: it.id } });
      await this.showNewsReport(r, out, false);
      out.scrollIntoView({ block: "start" });
    } catch (e) {
      kids(out, el("p", { class: "state err" }, t("ai.failed", { msg: e.message })));
    } finally {
      btn.disabled = false;
    }
  }

  async showNewsReport(r, out, loadThread) {
    let thread = [];
    if (loadThread && r.id) {
      try { thread = await api(`api/ai/reports/${r.id}/thread`); } catch { thread = []; }
    }
    const render = () => { destroyIn(out); kids(out, reportArticle(r, thread, { onFollowup: (fm) => follow(fm) })); };
    const follow = async (fm) => {
      const question = fm.querySelector("input").value.trim();
      if (!question || !r.id) return;
      fm.querySelector("button").disabled = true;
      const wait = el("p", { class: "state" }, t("ai.followup_running"));
      fm.before(wait);
      try { thread.push(await api("api/ai/followup", { json: { report_id: r.id, question } })); render(); } catch (e) {
        wait.className = "state err";
        wait.textContent = t("ai.followup_failed", { msg: e.message });
        fm.querySelector("button").disabled = false;
      }
    };
    render();
  }
}
