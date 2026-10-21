// Map tool bar of the situation view (ping, traceroute, IP info; more: path quality, Globalping, mail hops)
// with a result window. Live events are drawn on the map while the tool runs; the final result replaces them.
import { t } from "./i18n.js";
import { flags, loadRegistry, paramForm } from "./registry.js";
import { destroyIn, renderResult } from "./result.js";
import { go, href, routes } from "./router.js";
import { startRun } from "./runner.js";
import { countryName, el, kids, num } from "./util.js";

const MAX_MAIL = 15 * 1024 * 1024;

const where = (g) => (g ? [g.city, g.country ? countryName(g.country) : null].filter(Boolean).join(", ") : "");
const asTxt = (g) => (g?.asn ? `AS${g.asn} ${g.as_name || ""}`.trim() : "");
const hasGeo = (g) => g && Number.isFinite(g.lat) && Number.isFinite(g.lon);

export class MapTools {
  constructor({ map }) {
    this.map = map;
    this.bar = document.getElementById("maptools");
    this.input = document.getElementById("mt-target");
    this.mainBox = document.getElementById("mt-main");
    this.moreBtn = document.getElementById("mt-more-btn");
    this.menu = document.getElementById("mt-menu");
    this.panel = document.getElementById("panel-tools");
    this.title = document.getElementById("mt-title");
    this.body = document.getElementById("mt-body");
    this.reg = null;
    this.tool = null;
    this.run = null;
    document.getElementById("tools-close").addEventListener("click", () => this.close());
    document.getElementById("mt-form").addEventListener("submit", (e) => {
      e.preventDefault();
      this.open(this.tool?.bar ? this.tool.id : "ping", this.input.value.trim(), true);
    });
    this.moreBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      this.menu.hidden = !this.menu.hidden;
      this.moreBtn.setAttribute("aria-expanded", String(!this.menu.hidden));
    });
    document.addEventListener("click", (e) => {
      if (!this.menu.hidden && !this.menu.contains(e.target)) { this.menu.hidden = true; this.moreBtn.setAttribute("aria-expanded", "false"); }
    });
  }

  async init() {
    try {
      this.reg = await loadRegistry();
    } catch (e) {
      kids(this.mainBox, el("span", { class: "warn-txt" }, e.message));
      return;
    }
    const btn = (tool) => el("button", {
      type: "button", disabled: !this.reg.enabled || !tool.available, title: tool.available ? tool.desc : tool.reason,
      onclick: () => { this.menu.hidden = true; this.open(tool.id, this.input.value.trim(), tool.id !== "mailhdr"); },
    }, tool.name);
    const main = this.reg.tools.filter((x) => x.bar === "main");
    const more = this.reg.tools.filter((x) => x.bar === "more");
    kids(this.mainBox, ...main.map(btn));
    kids(this.menu, ...more.map((tool) => el("button", {
      type: "button", class: "menu-item", disabled: !this.reg.enabled || !tool.available,
      onclick: () => { this.menu.hidden = true; this.moreBtn.setAttribute("aria-expanded", "false"); this.open(tool.id, this.input.value.trim(), tool.id !== "mailhdr"); },
    }, el("strong", {}, tool.name), el("span", { class: "sub" }, tool.available ? tool.desc : tool.reason))),
    el("button", { type: "button", class: "menu-item", onclick: () => { this.menu.hidden = true; go(routes.tools(this.input.value.trim())); } },
      el("strong", {}, t("mt.all_tools")), el("span", { class: "sub" }, t("mt.all_tools_sub"))));
    if (!this.reg.enabled) this.input.placeholder = t("mt.disabled");
  }

  focus() { this.input.focus(); this.input.select(); }

  /** Opens the result window for a tool; autorun starts it right away when a target is given. */
  async open(toolId, target = "", autorun = false) {
    if (!this.reg) await this.init();
    const tool = this.reg?.byId[toolId];
    if (!tool) return;
    this.stop();
    this.tool = tool;
    this.panel.hidden = false;
    this.title.textContent = tool.name;
    if (target) this.input.value = target;
    const isMail = tool.id === "mailhdr";
    const field = isMail
      ? el("textarea", { rows: 6, maxlength: MAX_MAIL, spellcheck: "false", placeholder: t("mt.mail_ph"), class: "mail-in" })
      : el("input", { type: "text", maxlength: 2048, spellcheck: "false", value: target, placeholder: t("mt.target_ph"), required: true });
    const pf = paramForm(tool, { compact: true });
    const runBtn = el("button", { type: "submit", class: "primary" }, t("common.run"));
    const stopBtn = el("button", { type: "button", hidden: true, onclick: () => this.stop() }, t("common.stop"));
    const clearBtn = el("button", { type: "button", onclick: () => { this.stop(); this.map.clearTool(); destroyIn(this.out); kids(this.out); kids(this.live); } }, t("mt.clear"));
    const file = isMail ? el("input", { type: "file", class: "sr-only", id: "mt-eml", accept: ".eml,.txt,message/rfc822,text/plain" }) : null;
    if (file) {
      file.addEventListener("change", async () => {
        const f = file.files[0];
        if (!f) return;
        if (f.size > MAX_MAIL) { kids(this.live, el("p", { class: "state err" }, t("mt.too_big"))); return; }
        field.value = await f.text();
      });
    }
    const form = el("form", { class: "tool-form", autocomplete: "off" },
      el("div", { class: "tool-about" }, flags(tool), el("span", { class: "note" }, tool.desc)),
      el("label", { class: "grow" }, isMail ? t("mt.mail_label") : t("mt.target"), field),
      pf.node,
      el("div", { class: "btnrow" }, runBtn, stopBtn, clearBtn,
        file ? el("label", { for: "mt-eml", class: "btn plain" }, t("mt.load_file")) : null, file,
        el("a", { class: "btn plain", href: href(routes.tools(isMail ? "" : (field.value || target), tool.id)) }, t("mt.in_analyse"))));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const value = field.value.trim();
      if (!value) { field.focus(); return; }
      if (pf.consentMissing()) { kids(this.live, el("p", { class: "state err" }, t("tb.consent_missing"))); return; }
      if (!isMail) this.input.value = value;
      this.execute(tool, isMail ? "" : value, isMail ? { ...pf.values(), text: value } : pf.values(), pf.consent(), { runBtn, stopBtn });
    });
    this.live = el("div", { class: "tool-live", "aria-live": "polite" });
    this.out = el("div", { class: "tool-out" });
    destroyIn(this.body);
    kids(this.body, form, this.live, this.out);
    this.form = form;
    if (autorun && target && !isMail) form.requestSubmit();
    else field.focus();
  }

  close() {
    this.stop();
    this.panel.hidden = true;
  }

  stop() {
    if (this.run && !this.run.done) this.run.stop();
    this.run = null;
  }

  execute(tool, target, params, consent, { runBtn, stopBtn }) {
    this.stop();
    this.map.clearTool();
    destroyIn(this.out);
    kids(this.out);
    const live = new LiveView(this.map, tool, this.live);
    runBtn.disabled = true;
    stopBtn.hidden = false;
    const done = () => { runBtn.disabled = false; stopBtn.hidden = true; };
    this.run = startRun({ tool: tool.id, target, params, consent }, {
      onEvent: (ev) => live.event(ev),
      onResult: (r) => {
        done();
        live.finish();
        if (r.map) this.map.showResult(r.map);
        kids(this.out, renderResult(r, { onMap: (m) => this.map.showResult(m) }));
      },
      onError: (msg) => {
        done();
        live.finish();
        kids(this.out, el("p", { class: "state err" }, msg === null ? t("mt.stopped") : msg));
      },
    });
  }
}

/** Live display of streaming tools (ping, traceroute, path quality, Globalping) incl. map drawing. */
class LiveView {
  constructor(map, tool, box) {
    this.map = map;
    this.tool = tool;
    this.box = box;
    this.points = [];
    this.path = [];
    this.rows = null;
    kids(box, el("p", { class: "state" }, t("common.running")));
  }

  draw(fit = false) {
    this.map.showResult({ points: this.points, paths: this.path.length > 1 ? [{ coords: this.path }] : [] }, { fit });
  }

  table(cols) {
    this.rows = el("tbody");
    this.box.append(el("div", { class: "tbl-wrap" }, el("table", { class: "res" }, el("thead", {}, el("tr", {}, cols.map((c) => el("th", {}, c)))), this.rows)));
  }

  event(ev) {
    const id = this.tool.id;
    if (ev.type === "start") {
      const o = ev.origin;
      kids(this.box, el("dl", { class: "kv" },
        el("dt", {}, t("mt.target")), el("dd", {}, `${ev.ip}${ev.geo ? ` · ${[where(ev.geo), asTxt(ev.geo)].filter(Boolean).join(" · ")}` : ""}`),
        el("dt", {}, t("mt.origin")), el("dd", {}, o?.ip ? `${o.ip}${where(o) ? ` · ${where(o)}` : ""}` : t("mt.origin_unknown"))));
      if (hasGeo(o)) {
        this.points.push({ lon: o.lon, lat: o.lat, kind: "origin", label: t("map.server"), ip: o.ip });
        this.path.push([o.lon, o.lat]);
      }
      if (id === "ping" && hasGeo(ev.geo)) {
        this.points.push({ lon: ev.geo.lon, lat: ev.geo.lat, kind: "target", label: ev.ip, ip: ev.ip });
        this.path.push([ev.geo.lon, ev.geo.lat]);
      }
      if (id === "ping") this.table([t("tool.seq"), "TTL", "RTT"]);
      else this.table(id === "pathq" ? [t("tool.hop"), "IP", t("mt.loss"), "Ø RTT"] : [t("tool.hop"), "IP", t("tool.loc_as"), "RTT"]);
      this.draw(true);
    } else if (ev.type === "row" && this.rows) {
      if (ev.kind === "reply") this.rows.append(el("tr", {}, el("td", {}, ev.seq), el("td", {}, ev.ttl ?? "–"), el("td", {}, `${ev.rtt} ms`)));
      else if (ev.kind === "timeout") this.rows.append(el("tr", {}, el("td", {}, ev.seq), el("td", {}, "–"), el("td", { class: "warn-txt" }, t("tool.no_reply"))));
      else if (ev.kind === "hop") {
        const loc = ev.private ? t("tool.private") : [where(ev.geo), asTxt(ev.geo)].filter(Boolean).join("; ");
        if (id === "pathq") {
          this.rows.append(el("tr", {}, el("td", {}, ev.n), el("td", { class: "mono" }, ev.ip || "*"),
            el("td", { class: ev.loss >= 50 ? "warn-txt" : null }, ev.loss === null || ev.loss === undefined ? "–" : `${ev.loss} %`),
            el("td", {}, ev.avg === null || ev.avg === undefined ? "–" : `${ev.avg} ms`)));
        } else {
          this.rows.append(el("tr", {}, el("td", {}, ev.n), el("td", { class: "mono" }, ev.ip || "*", ev.c2 ? el("span", { class: "tag bad" }, "C2") : null),
            el("td", {}, loc || "–"), el("td", {}, ev.rtt === null || ev.rtt === undefined ? "–" : `${ev.rtt} ms`)));
        }
        if (hasGeo(ev.geo)) {
          this.points.push({ lon: ev.geo.lon, lat: ev.geo.lat, kind: "hop", label: String(ev.n), ip: ev.ip });
          this.path.push([ev.geo.lon, ev.geo.lat]);
          this.draw(false);
        }
      }
    } else if (ev.type === "info") {
      this.box.append(el("p", { class: "note" }, ev.text));
    } else if (ev.type === "progress") {
      let p = this.box.querySelector(".progress-line");
      if (!p) { p = el("p", { class: "state progress-line" }); this.box.append(p); }
      p.textContent = t("mt.progress", { done: num(ev.done), total: num(ev.total) });
    }
  }

  finish() {
    // the final result shows everything again: keep only the target/origin block
    const kv = this.box.querySelector("dl.kv");
    kids(this.box, ...(kv ? [kv] : []));
  }
}
