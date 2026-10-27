// Personen (#/personen[/<case id>]): people search by user name, e-mail address or name, always inside a case.
// Administrators only (the server refuses every other role, every search is in the audit log).
//   Band         case, kind of search, query; layers of the black and white map; the graph window
//   Side panel   Treffer (progress of the running search, accounts per platform), Verknüpfungen (what connects the
//                accounts, in words), Fälle (cases, export, deletion, site lists)
//   Drawer       one account in its context (profile, operator, connections)
//   Window       the link graph (graph.js): drag, connect, add and edit nodes and lines
//   Map          countries of the platform operators (filled: account found) and the countries profiles state (ring)
// A hit only means that an account with this name exists. Whether it is the same person shows in the links.
import { Graph, graphLegend, nodeLabel } from "./graph.js";
import { t } from "./i18n.js";
import { setCollapsed } from "./layout.js";
import { kpiTile } from "./panels.js";
import { go, routes } from "./router.js";
import { ago, api, countryName, dateOnly, dateTime, el, geo, kids, num, safeLink } from "./util.js";
import { front } from "./windows.js";

const CASE_KEY = "emberwatch.osint.case";
const POLL_MS = 1500;
const LAYOUT_DELAY = 700;
const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/;
const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;
const MANUAL_KINDS = ["person", "account", "username", "email", "phone", "name", "org", "location", "domain", "url", "note"];
const RUNNING = ["queued", "running"];
const PHASES = ["queued", "lists", "gravatar", "checking", "profiles", "graph", "done", "cancelled", "failed"];
const SOURCES = { sherlock: "Sherlock", wmn: "WhatsMyName", gravatar: "Gravatar" };
const LINK_KINDS = ["states", "links_to", "verified"];
const MAX_VARIANTS = 12;
const DEFAULT_VARIANTS = 3;
const MAX_PARALLEL = 5; // the server queues at most five searches

// the case shown last (per browser); "new" when "new case" was chosen on purpose
const stored = () => { try { return localStorage.getItem(CASE_KEY); } catch { return null; } };
const store = (id) => { try { if (id) localStorage.setItem(CASE_KEY, String(id)); else localStorage.removeItem(CASE_KEY); } catch { /* ignore */ } };
const catLabel = (c) => { const l = t(`os.cat.${c}`); return l === `os.cat.${c}` ? c : l; };
const ccOk = (cc) => typeof cc === "string" && /^[A-Z]{2}$/.test(cc);

/** User names someone with this name may use: "Max Mustermann" -> maxmustermann, max.mustermann, max_mustermann, … */
export function nameVariants(full) {
  const clean = (s) => s.toLowerCase().replace(/ä/g, "ae").replace(/ö/g, "oe").replace(/ü/g, "ue").replace(/ß/g, "ss")
    .normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]/g, "");
  const parts = String(full || "").split(/[\s,]+/).map(clean).filter(Boolean);
  if (!parts.length) return [];
  const f = parts[0], l = parts[parts.length - 1];
  const list = parts.length === 1 ? [f] : [`${f}${l}`, `${f}.${l}`, `${f}_${l}`, `${f}-${l}`, `${f[0]}${l}`, `${f[0]}.${l}`, `${l}${f}`,
    `${l}.${f}`, `${f}${l[0]}`, `${l}${f[0]}`, f, l];
  return [...new Set(list)].filter((u) => u.length >= 3 && USERNAME_RE.test(u)).slice(0, MAX_VARIANTS);
}

export class Personen {
  constructor({ map }) {
    this.map = map;
    this.active = false;
    this.disabled = false;
    this.cases = [];
    this.retention = 90;
    this.info = null; // site lists, gravatar
    this.cid = null;
    this.view = null; // {case, searches, hits, graph}
    this.tab = "o-hits";
    this.f = { search: "", status: "found", cat: "", q: "", cc: "" };
    this.variants = null;
    this.notice = null;
    this.pollTimer = null;
    this.seq = 0;
    this.layoutQueue = new Map();
    this.layoutTimer = null;
    this.drawerHit = null;
    this.graph = null;
    this.gsel = null;
    this.side = document.getElementById("side");
    this.panels = Object.fromEntries(["o-hits", "o-links", "o-cases"].map((k) => [k, document.getElementById(`tp-${k}`)]));
    this.drawer = document.getElementById("osint-drawer");
    this.drawerBody = document.getElementById("osint-drawer-body");
    this.win = document.getElementById("panel-graph");
    this.winBody = document.getElementById("graph-body");
    this.band = { form: document.getElementById("os-form"), cases: document.getElementById("os-case"), kind: document.getElementById("os-kind"),
      q: document.getElementById("os-q"), go: document.getElementById("os-go"), graph: document.getElementById("btn-graph") };
    this.h = null; // persistent parts of the hits panel
    this.bind();
  }

  // --- wiring --------------------------------------------------------------------------------------------------
  bind() {
    document.querySelectorAll("#tabs-osint button").forEach((b) => b.addEventListener("click", () => {
      setCollapsed("side", false);
      this.setTab(b.dataset.side);
    }));
    this.band.form.addEventListener("submit", (e) => { e.preventDefault(); this.submit(); });
    this.band.kind.addEventListener("change", () => this.syncKind());
    this.band.cases.addEventListener("change", () => {
      const v = this.band.cases.value;
      if (v === "new") { this.cid = null; this.view = null; store("new"); go(routes.personen()); this.band.q.focus(); } else go(routes.personen(Number(v)));
    });
    for (const [id, layer] of [["os-ops", "ops"], ["os-locs", "locs"]]) {
      const cb = document.getElementById(id);
      this.map.setOsintVisible(layer, cb.checked);
      if (layer === "locs") this.map.setOsintVisible("lines", cb.checked);
      cb.addEventListener("change", () => {
        this.map.setOsintVisible(layer, cb.checked);
        if (layer === "locs") this.map.setOsintVisible("lines", cb.checked);
      });
    }
    this.band.graph.addEventListener("click", () => (this.win.hidden ? this.openGraph() : this.closeGraph()));
    document.getElementById("graph-close").addEventListener("click", () => this.closeGraph());
    document.getElementById("osint-drawer-close").addEventListener("click", () => this.closeDrawer());
    this.syncKind();
  }

  syncKind() {
    const kind = this.band.kind.value;
    this.band.q.placeholder = t(`os.ph.${kind}`);
    this.band.q.maxLength = kind === "email" ? 254 : kind === "name" ? 80 : 40;
    this.band.go.textContent = t(kind === "name" ? "os.variants_make" : "os.search");
  }

  // --- area ----------------------------------------------------------------------------------------------------
  async show(r) {
    const seq = ++this.seq;
    this.active = true;
    const wanted = /^\d{1,12}$/.test(r.parts[0] || "") ? Number(r.parts[0]) : null;
    await this.loadCases();
    if (seq !== this.seq || !this.active) return;
    if (this.disabled) { this.renderOff(); return; }
    // without a case in the link: the one shown last, else the most recent one (cases are ordered by their last change)
    const last = stored();
    const known = this.cases.find((c) => String(c.id) === last);
    const cid = wanted ?? (last === "new" ? null : known ? known.id : this.cases[0]?.id ?? null);
    if (cid !== this.cid || !this.view) await this.openCase(cid, seq);
    else this.renderAll();
  }

  leave() {
    this.active = false;
    this.seq++;
    clearTimeout(this.pollTimer);
    this.flushLayout();
    this.closeDrawer();
  }

  /** A country was clicked on the map: hits whose operator or profile is there. */
  pickCountry(cc) {
    if (!ccOk(cc)) return;
    this.f.cc = this.f.cc === cc ? "" : cc;
    setCollapsed("side", false);
    this.setTab("o-hits");
    this.renderHits();
  }

  setTab(tab) {
    this.tab = tab;
    document.querySelectorAll("#tabs-osint button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.side === tab)));
    for (const [k, node] of Object.entries(this.panels)) node.hidden = k !== tab;
    if (tab === "o-links") this.renderLinks();
    else if (tab === "o-cases") this.renderCases();
    else this.renderHits();
  }

  /** Escape: the drawer first, then the connect mode of the graph. */
  escape() {
    if (!this.drawer.hidden) { this.closeDrawer(); return true; }
    if (this.graph?.mode === "connect") { this.setGraphMode("select"); return true; }
    return false;
  }

  // --- data ----------------------------------------------------------------------------------------------------
  async loadCases() {
    try {
      const [d, info] = await Promise.all([api("api/personen/cases"), this.info ? Promise.resolve(this.info) : api("api/personen/status")]);
      this.disabled = false;
      this.cases = d.cases;
      this.retention = d.retention_days;
      this.info = info;
    } catch (e) {
      if (e.status === 404) this.disabled = true;
      else this.notice = { text: t("common.error", { msg: e.message }), bad: true };
    }
    this.fillCases();
  }

  fillCases() {
    const sel = this.band.cases;
    kids(sel, el("option", { value: "new", selected: !this.cid }, t("os.case_new")),
      ...this.cases.map((c) => el("option", { value: c.id, selected: c.id === this.cid }, `${c.name} (${num(c.found)})`)));
    this.band.form.querySelectorAll("select, input, button").forEach((n) => (n.disabled = this.disabled));
  }

  async openCase(cid, seq = this.seq) {
    clearTimeout(this.pollTimer);
    this.flushLayout();
    this.closeDrawer();
    this.cid = cid;
    this.view = null;
    this.f = { ...this.f, search: "", cc: "" };
    if (cid || stored() !== "new") store(cid);
    this.fillCases();
    if (cid) {
      kids(this.panels["o-hits"], el("p", { class: "state" }, t("common.loading")));
      try {
        const v = await api(`api/personen/cases/${cid}`);
        if (seq !== this.seq || cid !== this.cid) return;
        this.view = v;
      } catch (e) {
        if (seq !== this.seq) return;
        this.cid = null;
        store(null);
        this.fillCases();
        this.notice = { text: e.status === 404 ? t("os.case_gone") : t("common.error", { msg: e.message }), bad: true };
      }
    }
    this.markSubjects();
    this.h = null;
    this.renderAll();
    this.fitMap();
    if (!this.win.hidden) this.drawGraph({ fit: true });
    this.schedulePoll();
  }

  /** The countries of an opened case on the map: operators and the places the profiles state. */
  fitMap() {
    const pts = [];
    for (const cc of new Set((this.view?.hits || []).flatMap((h) => [h.operator_cc, h.profile?.country]).filter(ccOk))) {
      const c = geo.centroids[cc];
      if (c) pts.push([c.lon, c.lat]);
    }
    if (pts.length > 1) this.map.fitTo(pts, 3);
    else if (pts.length === 1) this.map.flyTo(pts[0][0], pts[0][1], 2.5);
  }

  /** Reloads the open case (after a search ended or the graph changed). */
  async reload() {
    if (!this.cid) return;
    const cid = this.cid;
    await this.flushLayout(); // positions first: the reloaded case must not be laid out again
    try {
      const v = await api(`api/personen/cases/${cid}`);
      if (cid !== this.cid || !this.active) return;
      this.view = v;
      this.markSubjects();
      this.renderAll();
      if (!this.win.hidden) this.drawGraph();
      if (this.drawerHit) {
        const h = this.view.hits.find((x) => x.id === this.drawerHit.id);
        if (h) this.openDrawer(h); else this.closeDrawer();
      }
    } catch (e) {
      this.notice = { text: t("common.error", { msg: e.message }), bad: true };
      this.renderHits();
    }
    this.schedulePoll();
  }

  /** The searched user names and e-mail addresses are drawn as the subjects of the graph. */
  markSubjects() {
    if (!this.view) return;
    const q = new Set(this.view.searches.map((s) => `${s.kind}:${s.query.toLowerCase()}`));
    for (const n of this.view.graph.nodes) n.subject = !n.manual && q.has(`${n.kind}:${n.ref}`);
  }

  running() {
    return (this.view?.searches || []).filter((s) => RUNNING.includes(s.status));
  }

  schedulePoll() {
    clearTimeout(this.pollTimer);
    // searches run one after another: the oldest one that is not finished is the one that runs
    const run = this.running().sort((a, b) => a.id - b.id)[0];
    if (!run || !this.active) return;
    this.pollTimer = setTimeout(() => this.poll(run.id), POLL_MS);
  }

  async poll(sid) {
    const cid = this.cid;
    let d;
    try {
      d = await api(`api/personen/searches/${sid}`);
    } catch {
      if (this.active && cid === this.cid) this.schedulePoll();
      return;
    }
    if (!this.active || cid !== this.cid || !this.view) return;
    const i = this.view.searches.findIndex((s) => s.id === sid);
    if (i >= 0) this.view.searches[i] = { ...d.search, live: d.live };
    this.view.hits = [...this.view.hits.filter((h) => h.search_id !== sid), ...d.hits];
    if (!RUNNING.includes(d.search.status)) {
      await this.reload();
      this.loadCases();
      return;
    }
    this.renderHits();
    this.renderMap();
    this.renderKpis();
    this.schedulePoll();
  }

  // --- searching -----------------------------------------------------------------------------------------------
  async submit() {
    if (this.disabled) return;
    const kind = this.band.kind.value;
    const q = this.band.q.value.trim();
    if (!q) { this.band.q.focus(); return; }
    this.notice = null;
    if (kind === "name") {
      const list = nameVariants(q);
      this.variants = list.length ? { name: q, list: list.map((u, i) => ({ u, on: i < DEFAULT_VARIANTS })) } : null;
      if (!list.length) this.notice = { text: t("os.variants_none"), bad: true };
      setCollapsed("side", false);
      this.setTab("o-hits");
      return;
    }
    if (kind === "username" && !USERNAME_RE.test(q)) { this.say(t("os.bad_username"), true); return; }
    if (kind === "email" && !EMAIL_RE.test(q)) { this.say(t("os.bad_email"), true); return; }
    await this.start(kind, [q], q);
  }

  say(text, bad = false) {
    this.notice = { text, bad };
    setCollapsed("side", false);
    this.setTab("o-hits");
  }

  /** Starts searches in the open case; without a case a new one named after the query is created first. */
  async start(kind, queries, caseName) {
    this.band.go.disabled = true;
    let cid = this.cid;
    let started = 0;
    try {
      if (!cid) {
        const c = await api("api/personen/cases", { json: { name: caseName.slice(0, 80) } });
        cid = c.id;
      }
      for (const query of queries.slice(0, MAX_PARALLEL)) {
        await api(`api/personen/cases/${cid}/searches`, { json: { kind, query } });
        started++;
      }
      this.band.q.value = "";
      this.variants = null;
      this.notice = queries.length > MAX_PARALLEL ? { text: t("os.variants_cut", { n: MAX_PARALLEL }) } : null;
    } catch (e) {
      this.notice = { text: started ? t("os.started_part", { n: num(started), msg: e.message }) : e.message, bad: true };
    } finally {
      this.band.go.disabled = false;
    }
    if (!cid) { this.renderHits(); return; }
    this.tab = "o-hits";
    if (cid !== this.cid) go(routes.personen(cid));
    else await this.reload();
    this.loadCases();
  }

  async stop(sid) {
    try { await api(`api/personen/searches/${sid}`, { method: "DELETE" }); } catch (e) { this.say(e.message, true); return; }
    this.reload();
  }

  async removeSearch(s) {
    if (!window.confirm(t("os.search_delete_q", { q: s.query }))) return;
    try { await api(`api/personen/searches/${s.id}`, { method: "DELETE" }); } catch (e) { this.say(e.message, true); return; }
    if (String(this.f.search) === String(s.id)) this.f.search = "";
    this.reload();
    this.loadCases();
  }

  // --- rendering -----------------------------------------------------------------------------------------------
  renderOff() {
    const off = el("p", { class: "state" }, t("os.off"));
    for (const p of Object.values(this.panels)) kids(p, off.cloneNode(true));
    kids(document.getElementById("kpis"));
    kids(document.getElementById("maphint"));
    this.map.setOsint({});
  }

  renderAll() {
    if (!this.active) return;
    this.setTab(this.tab);
    this.renderMap();
    this.renderKpis();
  }

  /** Hits after the filters of the hits panel (search, status, category, text, country). */
  filtered() {
    const f = this.f;
    const q = f.q.toLowerCase();
    return (this.view?.hits || []).filter((h) => (!f.search || String(h.search_id) === f.search)
      && (f.status === "all" || h.status === f.status) && (!f.cat || h.cat === f.cat)
      && (!f.cc || h.operator_cc === f.cc || h.profile?.country === f.cc)
      && (!q || `${h.site} ${h.host} ${h.profile?.name || ""} ${h.profile?.location || ""}`.toLowerCase().includes(q)));
  }

  stats() {
    const hits = this.view?.hits || [];
    const found = hits.filter((h) => h.status === "found");
    return {
      found: found.length, unsure: hits.length - found.length,
      ops: new Set(found.map((h) => h.operator_cc).filter(ccOk)).size,
      checked: (this.view?.searches || []).reduce((a, s) => a + (s.live?.checked ?? s.checked ?? 0), 0),
      links: this.view ? this.linkData().count : 0,
    };
  }

  renderKpis() {
    if (!this.active) return;
    const s = this.stats();
    const tiles = [
      { key: "found", label: t("os.kpi.found"), value: num(s.found), sub: t("os.kpi.found_sub", { n: num(s.unsure) }) },
      { key: "ops", label: t("os.kpi.ops"), value: num(s.ops), sub: t("os.kpi.ops_sub") },
      { key: "links", label: t("os.kpi.links"), value: num(s.links), sub: t("os.kpi.links_sub"), hot: s.links > 0 },
      { key: "checked", label: t("os.kpi.checked"), value: num(s.checked), sub: t("os.kpi.checked_sub") },
    ];
    kids(document.getElementById("kpis"), ...(this.view ? tiles.map((x) => kpiTile(x, (key) => {
      if (key === "links") this.setTab("o-links");
      else { this.f.status = key === "found" ? "found" : this.f.status; this.setTab("o-hits"); }
      setCollapsed("side", false);
    })) : []));
    const sym = (cls, label) => [el("i", { class: `sw ${cls}`, "aria-hidden": "true" }), label];
    kids(document.getElementById("maphint"),
      el("span", { class: "lg-sym" }, ...sym("sw-oops", t("os.hint.ops")), ...sym("sw-oops-unsure", t("os.hint.ops_unsure")),
        ...sym("sw-oloc", t("os.hint.locs")), ...sym("sw-oline", t("os.hint.lines"))),
      el("span", { class: "lg-stamp" }, t("os.hint.note")));
  }

  renderMap() {
    const ops = {};
    const locs = {};
    for (const h of this.view?.hits || []) {
      if (ccOk(h.operator_cc)) {
        const o = ops[h.operator_cc] || (ops[h.operator_cc] = { n: 0, found: 0, sites: [] });
        o.n++;
        if (h.status === "found") o.found++;
        if (o.sites.length < 12) o.sites.push(h.site);
      }
      const cc = h.profile?.country;
      if (h.status === "found" && ccOk(cc)) locs[cc] = (locs[cc] || 0) + 1;
    }
    this.map.setOsint({ ops, locs });
  }

  // --- hits panel ----------------------------------------------------------------------------------------------
  buildHits() {
    const panel = this.panels["o-hits"];
    const search = el("select", { "aria-label": t("os.f.search") });
    const status = el("select", { "aria-label": t("os.f.status") },
      el("option", { value: "found" }, t("os.f.found")), el("option", { value: "all" }, t("os.f.all")), el("option", { value: "unsure" }, t("os.f.unsure")));
    const cat = el("select", { "aria-label": t("os.f.cat") });
    const q = el("input", { type: "search", maxlength: 60, placeholder: t("os.f.q"), "aria-label": t("os.f.q") });
    search.addEventListener("change", () => { this.f.search = search.value; this.renderHits(); });
    status.addEventListener("change", () => { this.f.status = status.value; this.renderHits(); });
    cat.addEventListener("change", () => { this.f.cat = cat.value; this.renderHits(); });
    let timer = null;
    q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { this.f.q = q.value.trim(); this.renderHits(); }, 200); });
    this.h = {
      notice: el("div", { "aria-live": "polite" }), pick: el("div"), run: el("div", { class: "os-runs", "aria-live": "polite" }),
      filters: el("div", { class: "os-filters" }, search, status, cat, q), chips: el("div"), count: el("p", { class: "note" }),
      list: el("ol", { class: "hits" }), searches: el("div", { class: "os-searches" }), search, status, cat, q,
    };
    kids(panel, this.h.notice, this.h.pick, this.h.run, this.h.filters, this.h.chips, this.h.count, this.h.list, this.h.searches);
  }

  renderHits() {
    if (!this.active || this.disabled) return;
    const panel = this.panels["o-hits"];
    if (!this.h || !panel.contains(this.h.list)) this.buildHits();
    const h = this.h;
    kids(h.notice, this.notice ? el("p", { class: this.notice.bad ? "state err" : "note" }, this.notice.text) : null);
    kids(h.pick, this.variants ? this.variantPicker() : null);
    if (!this.view) {
      kids(h.run);
      h.filters.hidden = true;
      kids(h.chips);
      kids(h.count);
      kids(h.list, this.variants ? null : this.intro());
      kids(h.searches);
      return;
    }
    h.filters.hidden = !this.view.hits.length;
    kids(h.run, ...this.running().sort((a, b) => a.id - b.id).map((s, i) => this.runCard(s, i)));
    // filter options follow the data; the chosen values stay
    const searches = this.view.searches;
    const cats = [...new Set(this.view.hits.map((x) => x.cat))].sort();
    if (this.f.cat && !cats.includes(this.f.cat)) this.f.cat = "";
    if (this.f.search && !searches.some((s) => String(s.id) === this.f.search)) this.f.search = "";
    kids(h.search, el("option", { value: "" }, t("os.f.search_all")),
      ...searches.map((s) => el("option", { value: s.id, selected: String(s.id) === this.f.search }, `${s.query} (${t(`os.kind.${s.kind}`)})`)));
    kids(h.cat, el("option", { value: "" }, t("os.f.cat_all")), ...cats.map((c) => el("option", { value: c, selected: c === this.f.cat }, catLabel(c))));
    h.status.value = this.f.status;
    kids(h.chips, this.f.cc ? el("div", { class: "fchips" }, el("span", { class: "fchip" }, t("os.f.cc", { name: countryName(this.f.cc) }),
      el("button", { type: "button", class: "small", title: t("wl.filter_clear"), onclick: () => { this.f.cc = ""; this.renderHits(); } }, "×"))) : null);
    const rows = this.filtered().sort((a, b) => (a.status === b.status ? a.site.localeCompare(b.site) : a.status === "found" ? -1 : 1));
    const s = this.stats();
    kids(h.count, this.view.hits.length ? t("os.count", { found: num(s.found), unsure: num(s.unsure), ops: num(s.ops), shown: num(rows.length) }) : "");
    kids(h.list, rows.length ? rows.slice(0, 600).map((x) => this.hitRow(x))
      : el("li", { class: "empty" }, this.view.hits.length ? t("os.none_filtered") : searches.length ? (this.running().length ? t("os.none_yet") : t("os.none")) : t("os.case_empty")));
    kids(h.searches, searches.length ? [el("h3", { class: "tp-h" }, t("os.searches_h")), el("ul", { class: "plain os-slist" }, searches.map((x) => this.searchRow(x)))] : null);
  }

  intro() {
    const n = this.info?.lists?.total;
    return el("li", { class: "os-intro" },
      el("p", {}, n ? t("os.intro", { n: num(n) }) : t("os.intro_any")),
      el("ul", { class: "plain method" }, ["os.intro1", "os.intro2", "os.intro3", "os.intro4"].map((k) => el("li", {}, t(k, { days: num(this.retention) })))),
      this.info && !this.info.gravatar ? el("p", { class: "note" }, t("os.no_gravatar")) : null);
  }

  variantPicker() {
    const v = this.variants;
    const boxes = v.list.map((x) => {
      const cb = el("input", { type: "checkbox", checked: x.on });
      cb.addEventListener("change", () => { x.on = cb.checked; btn.disabled = !v.list.some((y) => y.on); });
      return el("label", { class: "pcheck mono" }, cb, x.u);
    });
    const btn = el("button", { type: "button", class: "primary", disabled: !v.list.some((y) => y.on) }, t("os.variants_go"));
    btn.addEventListener("click", () => {
      const chosen = v.list.filter((y) => y.on).map((y) => y.u);
      if (chosen.length) this.start("username", chosen, v.name);
    });
    return el("section", { class: "os-pick" },
      el("h3", { class: "tp-h" }, t("os.variants_h", { name: v.name })),
      el("p", { class: "note" }, t("os.variants_note", { n: MAX_PARALLEL })),
      el("div", { class: "os-boxes" }, boxes),
      el("div", { class: "row" }, btn, el("button", { type: "button", class: "plain", onclick: () => { this.variants = null; this.renderHits(); } }, t("common.cancel"))));
  }

  runCard(s, i) {
    const live = s.live || {};
    const phase = PHASES.includes(live.phase) ? live.phase : s.status === "queued" ? "queued" : "checking";
    const total = live.total || s.sites || 0;
    const checked = live.checked ?? s.checked ?? 0;
    const waiting = i > 0 || phase === "queued";
    return el("div", { class: `os-run${waiting ? " waiting" : ""}` },
      el("div", { class: "os-run-head" },
        el("strong", { class: "mono" }, s.query), el("span", { class: "note" }, t(`os.kind.${s.kind}`)),
        el("span", { class: "spacer" }),
        el("button", { type: "button", class: "small", onclick: () => this.stop(s.id) }, waiting ? t("common.cancel") : t("os.stop"))),
      el("p", { class: "os-phase" }, waiting ? t("os.phase.queued") : t(`os.phase.${phase}`, { n: num(checked), total: num(total) })),
      waiting ? null : el("progress", { max: Math.max(total, 1), value: Math.min(checked, total || 1), "aria-label": t("os.progress") }),
      waiting ? null : el("p", { class: "note" }, t("os.live", { found: num(live.found ?? s.found ?? 0), unsure: num(live.unsure ?? s.unsure ?? 0),
        errors: num(live.errors ?? s.errors ?? 0) })));
  }

  searchRow(s) {
    const stat = RUNNING.includes(s.status) ? t(`os.st.${s.status}`)
      : s.status === "failed" ? t("os.st.failed_why", { why: t(`os.err.${["interrupted", "no_lists"].includes(s.error) ? s.error : "other"}`) })
        : t(`os.st.${s.status}`);
    return el("li", { class: s.status === "failed" ? "warn-txt" : null },
      el("button", { type: "button", class: "link mono", title: t("os.f.search"), onclick: () => { this.f.search = String(s.id); this.f.status = "all"; this.renderHits(); } }, s.query),
      el("span", { class: "muted" }, ` ${t(`os.kind.${s.kind}`)} · ${stat} · ${t("os.s_counts", { found: num(s.found || 0), unsure: num(s.unsure || 0), n: num(s.checked || 0) })} · ${ago(s.started_at)}`),
      RUNNING.includes(s.status) ? null : el("button", { type: "button", class: "small del", title: t("common.delete"), "aria-label": t("os.search_delete"), onclick: () => this.removeSearch(s) }, "×"));
  }

  hitRow(h) {
    const p = h.profile || {};
    const query = this.view.searches.length > 1 ? this.view.searches.find((s) => s.id === h.search_id)?.query : null;
    const sub = [query, catLabel(h.cat), ccOk(h.operator_cc) ? countryName(h.operator_cc) : null, p.name || null,
      p.country ? t("os.lives", { name: countryName(p.country) }) : p.location || null].filter(Boolean).join(" · ");
    const on = this.drawerHit?.id === h.id;
    return el("li", { class: `hit ${h.status}${on ? " on" : ""}` },
      el("button", { type: "button", class: "hit-row", "aria-pressed": String(on), onclick: () => this.openDrawer(h) },
        el("span", { class: `hit-mark ${h.status}`, title: t(`os.status.${h.status}`), "aria-label": t(`os.status.${h.status}`) }),
        el("span", { class: "hit-main" }, el("span", { class: "hit-site" }, h.site), el("span", { class: "hit-sub" }, sub)),
        el("span", { class: "hit-tag" }, h.status === "unsure" ? t("os.status.unsure") : p.verified?.length ? t("os.verified_short") : "")));
  }

  // --- drawer: one account -------------------------------------------------------------------------------------
  accountNode(h) {
    return this.view?.graph.nodes.find((n) => n.kind === "account" && n.data?.hit === h.id) || null;
  }

  openDrawer(h) {
    this.drawerHit = h;
    this.drawer.hidden = false;
    document.body.classList.add("drawer-open");
    front(this.drawer);
    this.map.selectOsint(ccOk(h.operator_cc) ? h.operator_cc : null);
    const p = h.profile || {};
    const kv = (rows) => el("dl", { class: "kv dkv" }, rows.filter(([, v]) => v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && !v.length))
      .flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
    const sect = (title, ...body) => el("section", { class: "dsect" }, el("h3", {}, title), ...body);
    const links = (list) => el("ul", { class: "plain os-links" }, list.slice(0, 40).map((u) => el("li", {}, safeLink(u, u.replace(/^https:\/\//, "")) || el("span", { class: "mono" }, u))));
    const node = this.accountNode(h);
    const edges = node ? this.view.graph.edges.filter((e) => e.src === node.id || e.dst === node.id) : [];
    const byId = new Map(this.view.graph.nodes.map((n) => [n.id, n]));
    const conn = edges.map((e) => {
      const other = byId.get(e.src === node.id ? e.dst : e.src);
      if (!other) return null;
      return el("li", { class: e.strength },
        el("button", { type: "button", class: "link", onclick: () => this.openGraph(other.id) }, nodeLabel(other, 50)),
        el("span", { class: "muted" }, ` ${t(`os.nk.${other.kind}`)} · ${t(`os.ek.${e.kind}`)} · ${t(`os.str.${e.strength}`)}${e.mutual ? ` · ${t("os.lg.mutual")}` : ""}`));
    }).filter(Boolean);
    const open = safeLink(h.url, t("os.d.open"));
    if (open) open.className = "btn primary";
    kids(this.drawerBody,
      el("header", { class: "dhead" },
        el("h2", {}, h.site),
        el("p", { class: "nmeta" }, el("span", { class: `badge ${h.status === "found" ? "info" : "low"}` }, t(`os.status.${h.status}`)),
          catLabel(h.cat), " · ", t("os.via", { src: SOURCES[h.source] || h.source }), h.http_status ? ` · HTTP ${h.http_status}` : "", " · ", dateTime(h.checked_at)),
        el("p", { class: "os-url mono" }, safeLink(h.url, h.url) || h.url),
        el("p", { class: "dlead" }, t(h.status === "found" ? "os.d.found" : "os.d.unsure"))),
      sect(t("os.d.profile"), Object.keys(p).length ? kv([
        [t("os.p.name"), p.name], [t("os.p.bio"), p.bio], [t("os.p.location"), p.location],
        [t("os.p.country"), p.country ? countryName(p.country) : null], [t("os.p.company"), p.company],
        [t("os.p.created"), p.created ? dateOnly(p.created) : null],
        [t("os.p.emails"), p.emails?.length ? p.emails.join(", ") : null],
        [t("os.p.verified"), p.verified?.length ? links(p.verified) : null],
        [t("os.p.links"), p.links?.length ? links(p.links) : null],
        [t("os.p.source"), t(`os.psrc.${p.source === "api" ? "api" : "page"}`)],
      ]) : el("p", { class: "note" }, t(h.status === "found" ? "os.d.no_profile" : "os.d.no_profile_unsure"))),
      sect(t("os.d.operator"), ccOk(h.operator_cc)
        ? el("p", {}, countryName(h.operator_cc), " ", el("span", { class: "muted" }, t(`os.op.${h.operator_src === "list" ? "list" : "tld"}`)))
        : el("p", { class: "note" }, t("os.op.none")),
      el("p", { class: "note mono" }, h.host)),
      sect(t("os.d.links"), conn.length ? el("ul", { class: "plain os-conn" }, conn) : el("p", { class: "note" }, t("os.d.links_none"))),
      el("div", { class: "dactions" },
        open,
        node ? el("button", { type: "button", onclick: () => this.openGraph(node.id) }, t("os.d.graph")) : null,
        ccOk(h.operator_cc) ? el("button", { type: "button", onclick: () => this.map.focus(h.operator_cc) }, t("os.d.map")) : null),
      el("p", { class: "note dnote" }, t("os.d.note")));
    this.drawerBody.scrollTop = 0;
    this.renderHits();
  }

  closeDrawer() {
    if (this.drawer.hidden) return;
    this.drawer.hidden = true;
    this.drawerHit = null;
    document.body.classList.remove("drawer-open");
    this.map.selectOsint(null);
    if (this.active) this.renderHits();
  }

  // --- links panel ---------------------------------------------------------------------------------------------
  /** What connects the accounts: statements several profiles share, links between accounts, own lines. */
  linkData() {
    const g = this.view?.graph || { nodes: [], edges: [] };
    const byId = new Map(g.nodes.map((n) => [n.id, n]));
    const accounts = new Set(g.nodes.filter((n) => n.kind === "account").map((n) => n.id));
    const from = new Map();
    for (const e of g.edges) {
      if (!accounts.has(e.src) || accounts.has(e.dst) || !LINK_KINDS.includes(e.kind)) continue;
      if (!from.has(e.dst)) from.set(e.dst, new Set());
      from.get(e.dst).add(e.src);
    }
    const shared = [...from].filter(([, s]) => s.size >= 2).map(([id, s]) => ({ node: byId.get(id), accounts: [...s].map((a) => byId.get(a)) }))
      .filter((x) => x.node).sort((a, b) => b.accounts.length - a.accounts.length);
    const seen = new Set();
    const pairs = [];
    for (const e of g.edges) {
      if (!accounts.has(e.src) || !accounts.has(e.dst) || !["links_to", "verified"].includes(e.kind)) continue;
      const key = e.mutual ? `m:${Math.min(e.src, e.dst)}:${Math.max(e.src, e.dst)}` : `${e.kind}:${e.src}:${e.dst}`;
      if (seen.has(key)) continue;
      seen.add(key);
      pairs.push(e);
    }
    const manual = g.edges.filter((e) => e.manual);
    return { byId, shared, pairs, manual, count: shared.length + pairs.length + manual.length };
  }

  renderLinks() {
    const panel = this.panels["o-links"];
    if (!this.view) { kids(panel, el("p", { class: "empty" }, t("os.links_nocase"))); return; }
    const d = this.linkData();
    const name = (n) => el("button", { type: "button", class: "link", onclick: () => this.openGraph(n.id) }, nodeLabel(n, 44));
    const sharedList = d.shared.length ? el("ol", { class: "rank os-shared" }, d.shared.slice(0, 60).map((x) => el("li", {},
      el("span", { class: "lbl" }, name(x.node), el("span", { class: "muted" }, ` ${t(`os.nk.${x.node.kind}`)}`)),
      el("span", { class: "val" }, num(x.accounts.length)),
      el("span", { class: "sub" }, t("os.l.by", { list: x.accounts.map((a) => a.label).slice(0, 8).join(", ") }))))) : el("p", { class: "empty" }, t("os.l.shared_none"));
    const pairItem = (e) => el("li", {}, name(d.byId.get(e.src)), el("span", { class: "muted" }, e.mutual ? " ⇄ " : " → "), name(d.byId.get(e.dst)),
      el("span", { class: "muted" }, ` · ${e.mutual ? t("os.lg.mutual") : t(`os.ek.${e.kind}`)}`));
    const manualItem = (e) => el("li", { class: e.strength },
      name(d.byId.get(e.src)), el("span", { class: "muted" }, " – "), name(d.byId.get(e.dst)),
      el("span", { class: "muted" }, ` · ${t(`os.str.${e.strength}`)}${e.label ? ` · ${e.label}` : ""}`));
    kids(panel,
      el("div", { class: "row tp-row" }, el("h3", { class: "tp-h" }, t("os.l.h")),
        el("button", { type: "button", class: "primary small", onclick: () => this.openGraph() }, t("os.graph_open"))),
      el("p", { class: "note" }, t("os.l.lead")),
      el("h3", { class: "tp-h" }, t("os.l.shared"), " ", el("span", { class: "count" }, num(d.shared.length))), sharedList,
      el("h3", { class: "tp-h" }, t("os.l.pairs"), " ", el("span", { class: "count" }, num(d.pairs.length))),
      d.pairs.length ? el("ul", { class: "plain os-pairs" }, d.pairs.slice(0, 80).map(pairItem)) : el("p", { class: "empty" }, t("os.l.pairs_none")),
      el("h3", { class: "tp-h" }, t("os.l.manual"), " ", el("span", { class: "count" }, num(d.manual.length))),
      d.manual.length ? el("ul", { class: "plain os-pairs" }, d.manual.map(manualItem)) : el("p", { class: "empty" }, t("os.l.manual_none")),
      el("h3", { class: "tp-h" }, t("os.l.add")), this.nodeForm(),
      el("p", { class: "note" }, t("os.l.note")));
  }

  /** Form for a node added by hand (person, organisation, phone, note, …). */
  nodeForm(onDone = null) {
    const kind = el("select", { "aria-label": t("os.n.kind") }, MANUAL_KINDS.map((k) => el("option", { value: k }, t(`os.nk.${k}`))));
    const label = el("input", { type: "text", required: true, maxlength: 160, placeholder: t("os.n.label_ph"), "aria-label": t("os.n.label") });
    const note = el("input", { type: "text", maxlength: 1000, placeholder: t("os.n.note_ph"), "aria-label": t("os.n.note") });
    const msg = el("p", { class: "note", "aria-live": "polite" });
    return el("form", { class: "os-nodeform", onsubmit: async (e) => {
      e.preventDefault();
      if (!this.cid || !label.value.trim()) return;
      try {
        const r = await api(`api/personen/cases/${this.cid}/nodes`, { json: { kind: kind.value, label: label.value.trim(), note: note.value.trim() || null } });
        label.value = note.value = "";
        msg.className = "note ok-txt";
        msg.textContent = t("os.n.added");
        this.pendingReveal = r.id;
        await this.reload();
        onDone?.(r.id);
      } catch (er) { msg.className = "state err"; msg.textContent = er.message; }
    } }, kind, label, note, el("button", { type: "submit" }, t("os.n.add")), msg);
  }

  // --- cases panel ---------------------------------------------------------------------------------------------
  renderCases() {
    const panel = this.panels["o-cases"];
    const name = el("input", { type: "text", required: true, maxlength: 80, placeholder: t("os.c.name_ph"), "aria-label": t("os.c.name") });
    const note = el("input", { type: "text", maxlength: 1000, placeholder: t("os.c.note_ph"), "aria-label": t("os.c.note") });
    const msg = el("p", { class: "note", "aria-live": "polite" });
    const create = el("form", { class: "os-caseform", onsubmit: async (e) => {
      e.preventDefault();
      try {
        const c = await api("api/personen/cases", { json: { name: name.value.trim(), note: note.value.trim() || null } });
        await this.loadCases();
        go(routes.personen(c.id));
      } catch (er) { msg.className = "state err"; msg.textContent = er.message; }
    } }, name, note, el("button", { type: "submit", class: "primary" }, t("os.c.create")), msg);
    const cur = this.view?.case;
    const list = this.cases.length ? el("ol", { class: "rank os-cases" }, this.cases.map((c) => el("li", { class: `clickable${c.id === this.cid ? " on" : ""}`,
      onclick: () => go(routes.personen(c.id)) },
      el("span", { class: "lbl" }, c.name), el("span", { class: "val" }, num(c.found)),
      el("span", { class: "sub" }, [t("os.c.counts", { s: num(c.searches), n: num(c.nodes) }), t("os.c.changed", { t: ago(c.updated_at) }),
        t("os.c.expires", { d: dateOnly(c.expires) }), c.created_by ? t("os.c.by", { name: c.created_by }) : null].filter(Boolean).join(" · ")),
      c.note ? el("span", { class: "sub note" }, c.note) : null))) : el("p", { class: "empty" }, t("os.c.none"));
    kids(panel,
      cur ? this.caseEditor(cur) : null,
      el("h3", { class: "tp-h" }, t("os.c.all"), " ", el("span", { class: "count" }, num(this.cases.length))), list,
      el("h3", { class: "tp-h" }, t("os.c.new")), create,
      el("p", { class: "note" }, t("os.c.retention", { days: num(this.retention) })),
      this.listsInfo());
  }

  caseEditor(c) {
    const name = el("input", { type: "text", required: true, maxlength: 80, value: c.name, "aria-label": t("os.c.name") });
    const note = el("textarea", { rows: 2, maxlength: 1000, "aria-label": t("os.c.note"), placeholder: t("os.c.note_ph") });
    note.value = c.note || "";
    const msg = el("p", { class: "note", "aria-live": "polite" });
    const save = el("form", { class: "os-caseedit", onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api(`api/personen/cases/${c.id}`, { method: "PATCH", json: { name: name.value.trim(), note: note.value.trim() } });
        msg.className = "note ok-txt";
        msg.textContent = t("os.c.saved");
        await this.loadCases();
        await this.reload();
      } catch (er) { msg.className = "state err"; msg.textContent = er.message; }
    } }, el("label", {}, t("os.c.name"), name), el("label", {}, t("os.c.note"), note),
    el("div", { class: "row" }, el("button", { type: "submit" }, t("common.save")),
      el("a", { class: "btn", href: `api/personen/cases/${c.id}/export`, download: "" }, t("os.c.export")),
      el("button", { type: "button", class: "danger", onclick: () => this.deleteCase(c) }, t("os.c.delete"))), msg);
    return el("section", { class: "os-current" },
      el("h3", { class: "tp-h" }, t("os.c.current")),
      el("p", { class: "note" }, t("os.c.meta", { t: dateTime(c.created_at), by: c.created_by || "–", d: dateOnly(c.expires) })),
      save);
  }

  async deleteCase(c) {
    if (!window.confirm(t("os.c.delete_q", { name: c.name }))) return;
    try {
      await api(`api/personen/cases/${c.id}`, { method: "DELETE" });
    } catch (e) { this.say(e.message, true); return; }
    this.cid = null;
    this.view = null;
    store(null);
    await this.loadCases();
    go(routes.personen());
    this.openCase(null);
  }

  listsInfo() {
    const l = this.info?.lists;
    if (!l) return null;
    const msg = el("p", { class: "note", "aria-live": "polite" });
    const btn = el("button", { type: "button", class: "small", onclick: async () => {
      btn.disabled = true;
      msg.textContent = t("os.lists_loading");
      try {
        const r = await api("api/personen/lists", { method: "POST" });
        this.info = { ...this.info, lists: r };
        this.renderCases();
      } catch (e) { msg.className = "state err"; msg.textContent = e.message; btn.disabled = false; }
    } }, t("os.lists_refresh"));
    const src = (k, name) => {
      const at = l.fetched?.[k];
      const err = l.errors?.[k];
      return el("li", { class: err ? "warn-txt" : null }, `${name}: ${num(l.counts?.[k] ?? 0)} · ${at ? ago(at) : t("st.not_fetched")}${err ? ` · ${t("os.lists_err")}` : ""}`);
    };
    return el("section", { class: "os-lists" },
      el("h3", { class: "tp-h" }, t("os.lists_h")),
      el("p", { class: "note" }, t("os.lists_total", { n: num(l.total) })),
      el("ul", { class: "plain" }, src("sherlock", "Sherlock (MIT)"), src("wmn", "WhatsMyName (CC BY-SA 4.0)")),
      el("div", { class: "row" }, btn), msg,
      el("p", { class: "note" }, t("os.lists_note")));
  }

  // --- graph window --------------------------------------------------------------------------------------------
  openGraph(reveal = null) {
    if (!this.view) { this.say(t("os.links_nocase")); return; }
    this.win.hidden = false;
    this.band.graph.setAttribute("aria-pressed", "true");
    front(this.win);
    if (!this.graph) this.buildGraph();
    requestAnimationFrame(() => {
      this.drawGraph({ fit: !this.graph.fitted });
      if (reveal && this.graph.reveal(reveal)) this.showSel(this.graph.byId.get(reveal), "node");
    });
  }

  closeGraph() {
    this.flushLayout();
    this.win.hidden = true;
    this.band.graph.setAttribute("aria-pressed", "false");
    if (this.graph) this.setGraphMode("select");
  }

  buildGraph() {
    const tools = el("div", { class: "g-tools", role: "toolbar", "aria-label": t("os.g.tools") });
    this.gmode = {
      select: el("button", { type: "button", "aria-pressed": "true", onclick: () => this.setGraphMode("select") }, t("os.g.select")),
      connect: el("button", { type: "button", "aria-pressed": "false", onclick: () => this.setGraphMode("connect") }, t("os.g.connect")),
    };
    this.gconn = {
      strength: el("select", { "aria-label": t("os.g.strength") }, el("option", { value: "hint" }, t("os.str.hint")), el("option", { value: "confirmed" }, t("os.str.confirmed"))),
      label: el("input", { type: "text", maxlength: 80, placeholder: t("os.g.label_ph"), "aria-label": t("os.g.label") }),
    };
    const connBox = el("span", { class: "g-conn", hidden: true }, this.gconn.strength, this.gconn.label);
    this.gconnBox = connBox;
    tools.append(
      el("span", { class: "seg" }, this.gmode.select, this.gmode.connect), connBox,
      el("span", { class: "spacer" }),
      el("button", { type: "button", title: t("os.g.relayout_title"), onclick: () => this.relayout() }, t("os.g.relayout")),
      el("button", { type: "button", onclick: () => this.graph.fit() }, t("os.g.fit")),
      el("button", { type: "button", "aria-label": t("os.g.zoom_out"), onclick: () => this.graph.zoom(1 / 1.25) }, "−"),
      el("button", { type: "button", "aria-label": t("os.g.zoom_in"), onclick: () => this.graph.zoom(1.25) }, "+"));
    const canvas = el("div", { class: "g-canvas" });
    this.gdetail = el("aside", { class: "g-detail", "aria-live": "polite" });
    this.gstatus = el("p", { class: "g-status note", "aria-live": "polite" });
    kids(this.winBody, tools, el("div", { class: "g-main" }, canvas, this.gdetail), el("div", { class: "g-foot" }, graphLegend(), this.gstatus));
    this.graph = new Graph(canvas, {
      onSelect: (x, type) => this.showSel(x, type),
      onConnect: (a, b) => this.connect(a, b),
      onMove: (pos) => this.queueLayout(pos),
    });
    this.showSel(null, null);
  }

  setGraphMode(mode) {
    if (!this.graph) return;
    this.graph.setMode(mode);
    this.gmode.select.setAttribute("aria-pressed", String(mode !== "connect"));
    this.gmode.connect.setAttribute("aria-pressed", String(mode === "connect"));
    this.gconnBox.hidden = mode !== "connect";
    this.gstatus.textContent = mode === "connect" ? t("os.g.connect_hint") : "";
  }

  drawGraph({ fit = false } = {}) {
    if (!this.graph || !this.view) return;
    const fresh = this.graph.set(this.view.graph, { fit });
    if (fresh.length) this.queueLayout(fresh);
    if (this.pendingReveal && this.graph.reveal(this.pendingReveal)) this.showSel(this.graph.byId.get(this.pendingReveal), "node");
    this.pendingReveal = null;
    const sel = this.graph.sel ? this.graph.find(this.graph.sel) : null;
    this.showSel(sel, sel ? this.graph.sel.type : null);
    const n = this.view.graph.nodes.length;
    kids(this.gstatus, n ? t("os.g.size", { n: num(n), e: num(this.view.graph.edges.length) }) : t("os.g.empty"));
  }

  relayout() {
    if (!this.graph) return;
    this.queueLayout(this.graph.relayout());
  }

  queueLayout(positions) {
    for (const [id, x, y] of positions) this.layoutQueue.set(id, [id, x, y]);
    clearTimeout(this.layoutTimer);
    this.layoutTimer = setTimeout(() => this.flushLayout(), LAYOUT_DELAY);
  }

  /** Stores the queued node positions (they are a convenience: a failure is ignored). */
  async flushLayout() {
    clearTimeout(this.layoutTimer);
    if (!this.layoutQueue.size || !this.cid) { this.layoutQueue.clear(); return; }
    const positions = [...this.layoutQueue.values()];
    this.layoutQueue.clear();
    try {
      await api(`api/personen/cases/${this.cid}/layout`, { method: "PUT", json: { positions } });
    } catch { /* the graph stays usable; the next layout is computed again */ }
  }

  /** Connect mode: a line drawn by hand; it is selected afterwards, so strength and label can be changed at once. */
  async connect(a, b) {
    try {
      const r = await api(`api/personen/cases/${this.cid}/edges`, { json: { src: a.id, dst: b.id, strength: this.gconn.strength.value, label: this.gconn.label.value.trim() || null } });
      this.gconn.label.value = "";
      await this.reload();
      const e = this.view?.graph.edges.find((x) => x.id === r.id);
      if (e && this.graph) { this.graph.select("edge", e.id); this.showSel(e, "edge"); }
      this.gstatus.textContent = t("os.g.connected", { a: nodeLabel(a), b: nodeLabel(b) });
    } catch (e) { this.gstatus.textContent = e.message; }
  }

  /** Details of the selection in the graph, with editing. */
  showSel(x, type) {
    if (!this.gdetail) return;
    if (!x) {
      kids(this.gdetail, el("h3", {}, t("os.g.help_h")), el("ul", { class: "plain method" }, ["os.g.help1", "os.g.help2", "os.g.help3", "os.g.help4"].map((k) => el("li", {}, t(k)))),
        el("h3", {}, t("os.l.add")), this.nodeForm((id) => this.graph?.reveal(id)));
      return;
    }
    this.gsel = { x, type };
    const msg = el("p", { class: "note", "aria-live": "polite" });
    const fail = (e) => { msg.className = "state err"; msg.textContent = e.message; };
    if (type === "node") {
      const label = el("input", { type: "text", maxlength: 160, value: x.label, "aria-label": t("os.n.label") });
      const note = el("textarea", { rows: 3, maxlength: 1000, "aria-label": t("os.n.note"), placeholder: t("os.n.note_ph") });
      note.value = x.data?.note || "";
      const byId = this.graph.byId;
      const edges = (this.graph.incident.get(x.id) || []);
      const hit = x.kind === "account" ? this.view.hits.find((h) => h.id === x.data?.hit) : null;
      kids(this.gdetail,
        el("p", { class: "g-kind" }, t(`os.nk.${x.kind}`), x.manual ? el("span", { class: "tag" }, t("os.g.manual")) : null,
          x.subject ? el("span", { class: "tag" }, t("os.g.subject")) : null),
        el("h3", { class: "g-title" }, nodeLabel(x, 80)),
        x.data?.url ? el("p", { class: "mono-sm" }, safeLink(x.data.url, x.data.url) || x.data.url) : null,
        hit ? el("button", { type: "button", class: "small", onclick: () => this.openDrawer(hit) }, t("os.g.open_hit")) : null,
        el("form", { class: "g-edit", onsubmit: async (e) => {
          e.preventDefault();
          try {
            await api(`api/personen/nodes/${x.id}`, { method: "PATCH", json: { label: x.kind === "location" ? null : label.value.trim() || null, note: note.value.trim() } });
            await this.reload();
          } catch (er) { fail(er); }
        } },
        x.kind === "location" ? null : el("label", {}, t("os.n.label"), label), el("label", {}, t("os.n.note"), note),
        el("div", { class: "row" }, el("button", { type: "submit" }, t("common.save")),
          el("button", { type: "button", class: "danger", onclick: async () => {
            if (!window.confirm(t("os.n.delete_q", { name: nodeLabel(x, 60) }))) return;
            try { await api(`api/personen/nodes/${x.id}`, { method: "DELETE" }); this.graph.select(null); await this.reload(); this.showSel(null, null); } catch (er) { fail(er); }
          } }, t("common.delete")))),
        msg,
        el("h3", {}, t("os.g.links", { n: num(edges.length) })),
        edges.length ? el("ul", { class: "plain g-links" }, edges.map((e) => {
          const other = byId.get(e.src === x.id ? e.dst : e.src);
          return el("li", { class: e.strength }, el("button", { type: "button", class: "link", onclick: () => { this.graph.reveal(other.id); this.showSel(other, "node"); } }, nodeLabel(other, 40)),
            el("span", { class: "muted" }, ` ${t(`os.ek.${e.kind}`)} · ${t(`os.str.${e.strength}`)}`));
        })) : el("p", { class: "note" }, t("os.g.no_links")));
      return;
    }
    const a = this.graph.byId.get(x.src), b = this.graph.byId.get(x.dst);
    const strength = el("select", { "aria-label": t("os.g.strength") }, ["confirmed", "hint"].map((s) => el("option", { value: s, selected: x.strength === s }, t(`os.str.${s}`))));
    const label = el("input", { type: "text", maxlength: 80, value: x.manual ? x.label || "" : "", "aria-label": t("os.g.label"), placeholder: t("os.g.label_ph") });
    kids(this.gdetail,
      el("p", { class: "g-kind" }, t(`os.ek.${x.kind}`), x.manual ? el("span", { class: "tag" }, t("os.g.manual")) : null, x.mutual ? el("span", { class: "tag" }, t("os.lg.mutual")) : null),
      el("h3", { class: "g-title" }, nodeLabel(a || {}, 40), x.mutual ? " ⇄ " : " → ", nodeLabel(b || {}, 40)),
      x.evidence ? el("p", { class: "note" }, x.evidence) : null,
      el("p", { class: "note" }, t(`os.ek_note.${x.kind}`)),
      el("form", { class: "g-edit", onsubmit: async (e) => {
        e.preventDefault();
        try {
          await api(`api/personen/edges/${x.id}`, { method: "PATCH", json: { strength: strength.value, label: x.manual ? label.value.trim() : null } });
          await this.reload();
        } catch (er) { fail(er); }
      } },
      el("label", {}, t("os.g.strength"), strength), x.manual ? el("label", {}, t("os.g.label"), label) : null,
      el("div", { class: "row" }, el("button", { type: "submit" }, t("common.save")),
        el("button", { type: "button", class: "danger", onclick: async () => {
          if (!window.confirm(t("os.g.delete_q"))) return;
          try { await api(`api/personen/edges/${x.id}`, { method: "DELETE" }); this.graph.select(null); await this.reload(); this.showSel(null, null); } catch (er) { fail(er); }
        } }, t("common.delete")))),
      msg);
  }
}
