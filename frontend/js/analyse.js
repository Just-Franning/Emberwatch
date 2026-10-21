// Analysis area: start page, object pages, tool box, deep views (KEV, infrastructure, C2, ransomware), run history,
// Gemini per object. Everything below the header; the map stays in the situation view ("show on map" switches there).
import { reportArticle } from "./ai.js";
import { t } from "./i18n.js";
import { alertItem } from "./panels.js";
import { GROUPS, LEVELS, cyberChefUrl, detect, flags, loadRegistry, objectOf, paramForm } from "./registry.js";
import { destroyIn, findingsNode, relatedNode, renderResult, sectionNode } from "./result.js";
import { go, href, isPinned, objLink, pinned, recent, remember, routes, togglePin } from "./router.js";
import { RunStack } from "./runstack.js";
import { api, countryName, dateOnly, dateTime, dec2, el, kids, num, safeLink, sevTag } from "./util.js";

const VIEWS = ["kev", "infra", "c2", "ransom"];
let handoff = null; // long input (mail header) passed from the start page to the tool box

const debounce = (fn, ms) => {
  let h = null;
  return (...a) => { clearTimeout(h); h = setTimeout(() => fn(...a), ms); };
};
const navLink = (path, label, on, extra = null) => el("a", { href: href(path), class: on ? "on" : null }, label, extra);
const typeChip = (type) => el("span", { class: "kind" }, t(`obj.type.${type}`));

/** Target string a tool needs for an object (AS numbers with prefix). */
const toolTarget = (o) => (o.type === "asn" ? `AS${o.value}` : o.value);

export class Analyse {
  constructor({ nav, main, onMap }) {
    this.navBox = nav;
    this.main = main;
    this.onMap = onMap;
    this.status = null;
    this.stack = new RunStack({ onMap });
    this.seq = 0;
  }

  setStatus(status) { this.status = status; }

  leave() { this.stack.stopAll(); }

  async show(route) {
    const seq = ++this.seq;
    this.stack.clear();
    const [section, a, ...rest] = route.parts;
    this.renderNav(section, a);
    destroyIn(this.main);
    this.main.scrollTop = 0;
    const box = el("div", { class: "wrap" });
    kids(this.main, box);
    try {
      if (section === "obj" && a && rest.length) await this.objectPage(box, a, rest.join("/"), seq);
      else if (section === "tools") await this.toolbox(box, route.query, seq, route.internal);
      else if (section === "view" && VIEWS.includes(a)) await this[`view_${a}`](box, seq);
      else if (section === "history") await this.history(box);
      else if (section === "run" && a) await this.runView(box, a);
      else await this.start(box);
    } catch (e) {
      if (seq === this.seq) kids(box, el("p", { class: "state err" }, t("common.error", { msg: e.message })));
    }
  }

  renderNav(section, a) {
    const items = [
      navLink("analyse", t("an.nav.start"), !section),
      navLink(routes.tools(), t("an.nav.tools"), section === "tools"),
      navLink("analyse/history", t("an.nav.history"), section === "history" || section === "run"),
      el("h4", {}, t("an.nav.views")),
      ...VIEWS.map((v) => navLink(routes.view(v), t(`an.view.${v}`), section === "view" && a === v)),
    ];
    const pins = pinned();
    if (pins.length) items.push(el("h4", {}, t("an.nav.pinned")), ...pins.map((o) => navLink(routes.obj(o.type, o.value), o.title, false, el("span", { class: "kind" }, t(`obj.type.${o.type}`)))));
    const rec = recent();
    if (rec.length) items.push(el("h4", {}, t("an.nav.recent")), ...rec.slice(0, 10).map((o) => navLink(routes.obj(o.type, o.value), o.title, false, el("span", { class: "kind" }, t(`obj.type.${o.type}`)))));
    kids(this.navBox, ...items);
  }

  // --- start ------------------------------------------------------------------------------------------------------
  async start(box) {
    const input = el("textarea", { rows: 1, class: "big-in", spellcheck: "false", maxlength: 15 * 1024 * 1024, placeholder: t("an.input_ph"), "aria-label": t("an.input_ph") });
    const hint = el("div", { class: "detect-line" });
    const go_ = el("button", { type: "submit", class: "primary" }, t("an.analyse"));
    const form = el("form", { class: "big-form" }, input, go_);
    const grow = () => { input.style.height = "auto"; input.style.height = `${Math.min(320, input.scrollHeight + 2)}px`; };
    let det = null;
    const update = debounce(async () => {
      const q = input.value.trim();
      if (!q) { kids(hint); det = null; return; }
      try { det = await detect(q.slice(0, 4096)); } catch { det = null; }
      kids(hint, ...this.detectHint(det, q));
    }, 250);
    input.addEventListener("input", () => { grow(); update(); });
    input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !input.value.includes("\n")) { e.preventDefault(); form.requestSubmit(); } });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const q = input.value.trim();
      if (!q) return;
      try { det = await detect(q.slice(0, 4096)); } catch { det = null; }
      this.openInput(q, det);
    });
    const views = el("div", { class: "cards" }, ...[["tools", routes.tools()], ...VIEWS.map((v) => [v, routes.view(v)])].map(([k, path]) =>
      el("a", { class: "card link-card", href: href(path) }, el("strong", {}, t(k === "tools" ? "an.nav.tools" : `an.view.${k}`)), el("span", { class: "note" }, t(`an.card.${k}`)))));
    let hist = [];
    let reg = null;
    try { [hist, reg] = await Promise.all([api("api/tb/history?limit=8").then((d) => d.runs), loadRegistry()]); } catch { hist = []; }
    kids(box,
      el("h2", { class: "page-title" }, t("an.title")),
      el("p", { class: "lead" }, t("an.lead")),
      form, hint,
      el("h3", { class: "page-h" }, t("an.quick")), views,
      hist.length ? el("h3", { class: "page-h" }, t("an.recent_runs")) : null,
      hist.length ? this.historyTable(hist, reg, false) : null,
    );
    input.focus();
  }

  detectHint(det, q) {
    if (!det || det.type === "empty") return [];
    const parts = [el("span", { class: "muted" }, t("an.detected")), el("strong", {}, t(`tb.in.${det.type}`)),
      det.display && det.display !== q ? el("span", { class: "mono" }, ` ${det.display}`) : null];
    const o = objectOf(det);
    if (o) parts.push(el("a", { class: "btn", href: href(routes.obj(o.type, o.value)) }, t("an.open_object")));
    for (const r of det.recipes || []) parts.push(el("button", { type: "button", onclick: () => this.recipeFromStart(r, q) }, t(`tb.recipe.${r}`)));
    if (det.type !== "mailhdr") parts.push(el("a", { class: "btn plain", href: href(routes.tools(q.slice(0, 500))) }, t("an.to_tools")));
    return parts;
  }

  recipeFromStart(r, q) {
    handoff = { q, recipe: r };
    go(routes.tools());
  }

  openInput(q, det) {
    const o = objectOf(det);
    if (o) return go(routes.obj(o.type, o.value));
    if (det?.type === "mailhdr") { handoff = { q, recipe: "mail" }; return go(routes.tools()); }
    // free text: a malware family, ransomware group or vendor name
    const box = this.main.querySelector(".detect-line");
    if (box) kids(box, el("span", { class: "muted" }, t("an.text_as")),
      ...["malware", "group", "vendor"].map((ty) => el("a", { class: "btn", href: href(routes.obj(ty, q.slice(0, 200))) }, t(`obj.type.${ty}`))),
      el("a", { class: "btn plain", href: href(routes.tools(q.slice(0, 500))) }, t("an.to_tools")));
  }

  // --- object page --------------------------------------------------------------------------------------------------
  async objectPage(box, type, value, seq) {
    kids(box, el("p", { class: "state" }, t("an.loading_obj", { value })));
    const [page, reg] = await Promise.all([api(`api/obj?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`), loadRegistry()]);
    if (seq !== this.seq) return;
    remember({ type: page.type, value: page.value, title: page.title, sev: page.risk.sev });
    this.renderNav("obj");
    const o = { type: page.type, value: page.value };
    const pin = el("button", { type: "button", class: "small" }, isPinned(o.type, o.value) ? t("an.unpin") : t("an.pin"));
    pin.addEventListener("click", () => {
      const on = togglePin({ ...o, title: page.title });
      pin.textContent = on ? t("an.unpin") : t("an.pin");
      this.renderNav("obj");
    });
    const head = el("header", { class: "obj-head" },
      el("div", { class: "obj-title" }, typeChip(page.type), el("h2", {}, page.title), page.subtitle ? el("span", { class: "muted" }, page.subtitle) : null),
      el("div", { class: "obj-risk" }, el("span", { class: `risk ${page.risk.sev}` }, sevTag(page.risk.sev), page.risk.text), pin));
    const mine = this.mineBanner(page.mine);
    // actions: tools by question group, recipes, map, Gemini
    const tools = (page.tools || []).map((id) => reg.byId[id]).filter((x) => x && !x.client_only);
    const groups = GROUPS.map((g) => [g, tools.filter((x) => x.group === g)]).filter(([, l]) => l.length);
    const actions = el("section", { class: "obj-actions" },
      ...(page.recipes || []).map((r) => el("button", { type: "button", class: "primary", title: t(`an.recipe_hint`),
        onclick: () => this.stack.recipe(r, toolTarget(o), t(`tb.recipe.${r}`)) }, t(`tb.recipe.${r}`))),
      ...groups.map(([g, list]) => el("div", { class: "act-group" }, el("span", { class: "act-label" }, t(`tb.group.${g}`)),
        ...list.map((x) => el("button", { type: "button", disabled: !reg.enabled || !x.available, title: `${x.desc}${x.available ? "" : ` (${x.reason})`}`,
          class: `lvl-btn lvl-${x.level}`, onclick: () => this.stack.tool(x.id, toolTarget(o)) }, x.name)))),
      page.map ? el("button", { type: "button", onclick: () => this.onMap(page.map) }, t("common.show_map")) : null,
      tools.length ? el("a", { class: "btn plain", href: href(routes.tools(toolTarget(o))) }, t("an.more_options")) : null);
    const reasons = page.risk.reasons?.length ? el("section", { class: "res-sec" }, el("h4", {}, t("an.assessment")), findingsNode(page.risk.reasons)) : null;
    const sections = (page.sections || []).map(sectionNode);
    const alerts = page.alerts?.length ? el("section", { class: "res-sec" }, el("h4", {}, t("an.own_alerts", { n: num(page.alerts.length) })),
      el("ol", { class: "patterns" }, page.alerts.slice(0, 20).map((a) => alertItem(a, { onOpen: (x) => go(x.asset_id ? routes.asset(x.asset_id) : x.product_id ? routes.product(x.product_id) : "netz/alerts") })))) : null;
    const hist = page.history?.length ? el("section", { class: "res-sec" }, el("h4", {}, t("an.obj_history")), this.historyTable(page.history, reg, false)) : null;
    kids(box, head, mine, actions, this.stack.node, reasons, ...sections, relatedNode(page.related), alerts, hist,
      this.geminiBlock(page));
  }

  mineBanner(mine) {
    if (!mine) return null;
    const parts = [];
    if (mine.myip) parts.push(el("span", {}, t(`an.mine.myip_${mine.myip}`), " ", el("a", { href: href("netz/myip") }, t("an.mine.to_myip"))));
    for (const a of mine.assets || []) parts.push(el("span", {}, t("an.mine.asset"), " ", el("a", { href: href(routes.asset(a.id)) }, a.kind === "asn" ? `AS${a.value}` : a.value), a.label ? ` (${a.label})` : ""));
    for (const p of mine.products || []) parts.push(el("span", {}, t("an.mine.product"), " ", el("a", { href: href(routes.product(p.id)) }, `${p.vendor} ${p.product}`.trim())));
    return parts.length ? el("div", { class: "mine" }, el("strong", {}, t("an.mine.title")), ...parts) : null;
  }

  geminiBlock(page) {
    const enabled = Boolean(this.status?.ai?.enabled);
    const scope = `obj:${page.type}:${page.value}`;
    const out = el("div", { class: "ai-out" });
    const q = el("input", { type: "text", maxlength: 600, placeholder: t("an.ai_q_ph"), "aria-label": t("an.ai_q_ph") });
    const run = el("button", { type: "button", class: "primary", disabled: !enabled }, t("an.ai_run"));
    const ask = el("button", { type: "submit", disabled: !enabled }, t("ai.ask"));
    let thread = [];
    let current = null;
    const show = () => {
      destroyIn(out);
      kids(out, reportArticle(current, thread, { onFollowup: (form) => follow(form) }));
    };
    const follow = async (form) => {
      const inp = form.querySelector("input");
      const question = inp.value.trim();
      if (!question || !current?.id) return;
      form.querySelector("button").disabled = true;
      const wait = el("p", { class: "state" }, t("ai.followup_running"));
      form.before(wait);
      try {
        thread.push(await api("api/ai/followup", { json: { report_id: current.id, question } }));
        show();
      } catch (e) {
        wait.className = "state err";
        wait.textContent = t("ai.followup_failed", { msg: e.message });
        form.querySelector("button").disabled = false;
      }
    };
    const analyse = async (question) => {
      run.disabled = ask.disabled = true;
      destroyIn(out);
      kids(out, el("p", { class: "state" }, t("ai.running")));
      try {
        current = await api("api/ai/object", { json: { type: page.type, value: page.value, question: question || null } });
        thread = [];
        show();
      } catch (e) {
        kids(out, el("p", { class: "state err" }, t("ai.failed", { msg: e.message })));
      } finally {
        run.disabled = ask.disabled = !enabled;
      }
    };
    run.addEventListener("click", () => analyse(null));
    const form = el("form", { class: "ai-ask" }, q, ask);
    form.addEventListener("submit", (e) => { e.preventDefault(); if (q.value.trim()) analyse(q.value.trim()); });
    if (enabled) {
      api(`api/ai/reports?limit=1&scope=${encodeURIComponent(scope)}`).then(async (list) => {
        if (!list.length || current) return;
        current = list[0];
        try { thread = await api(`api/ai/reports/${current.id}/thread`); } catch { thread = []; }
        show();
      }).catch(() => {});
    }
    return el("section", { class: "res-sec gemini" }, el("h4", {}, t("an.ai_title")),
      el("p", { class: "note" }, enabled ? t("an.ai_note") : t("an.ai_off")),
      el("div", { class: "btnrow" }, run), form, out);
  }

  // --- tool box -----------------------------------------------------------------------------------------------------
  async toolbox(box, query, seq, internal = false) {
    const reg = await loadRegistry();
    if (seq !== this.seq) return;
    const start = handoff;
    handoff = null;
    const input = el("textarea", { rows: 1, class: "big-in", spellcheck: "false", maxlength: 15 * 1024 * 1024, placeholder: t("an.tools_ph"), "aria-label": t("an.tools_ph") });
    input.value = start?.q || query.get("q") || "";
    const detLine = el("div", { class: "detect-line" });
    const recipes = el("div", { class: "recipes" });
    const groupsBox = el("div", { class: "tool-groups" });
    const panel = el("div", { class: "tool-panel", "data-empty": t("an.pick_tool") });
    let det = null;
    let selected = null;
    const grow = () => { input.style.height = "auto"; input.style.height = `${Math.min(320, input.scrollHeight + 2)}px`; };

    const drawRecipes = () => kids(recipes, el("span", { class: "act-label" }, t("an.recipes")),
      ...reg.recipes.map((r) => el("button", {
        type: "button", class: "primary", disabled: !reg.enabled || !(det?.recipes || []).includes(r.id), title: r.desc,
        onclick: () => this.stack.recipe(r.id, r.id === "mail" ? input.value : (det?.value || input.value.trim()), r.name),
      }, r.name)));

    const select = (tool) => {
      selected = tool;
      groupsBox.querySelectorAll(".tool-row").forEach((n) => n.classList.toggle("on", n.dataset.id === tool?.id));
      if (!tool) { kids(panel); return; }
      const pf = paramForm(tool);
      const runBtn = el("button", { type: "submit", class: "primary", disabled: !reg.enabled || !tool.available }, tool.client_only ? t("an.open_cyberchef") : t("common.run"));
      const err = el("p", { class: "state err", hidden: true });
      const form = el("form", { class: "tool-run" },
        el("div", { class: "tool-run-head" }, el("strong", {}, tool.name), flags(tool)),
        el("p", { class: "note" }, tool.desc),
        !tool.available ? el("p", { class: "warn-txt" }, tool.reason) : null,
        pf.node, el("div", { class: "btnrow" }, runBtn), err);
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        err.hidden = true;
        const raw = input.value.trim();
        if (!raw) { input.focus(); return; }
        if (pf.consentMissing()) { err.textContent = t("tb.consent_missing"); err.hidden = false; return; }
        if (tool.client_only) { window.open(cyberChefUrl(reg.cyberchef_url, input.value), "_blank", "noopener,noreferrer"); return; }
        if (tool.id === "mailhdr") this.stack.tool(tool.id, "", { ...pf.values(), text: input.value }, false);
        else this.stack.tool(tool.id, raw.length > 500 ? raw.slice(0, 500) : raw, pf.values(), pf.consent());
      });
      kids(panel, form);
      return form;
    };

    const drawGroups = () => {
      const fit = new Set(det?.tools || []);
      kids(groupsBox, ...GROUPS.map((g) => {
        const list = reg.tools.filter((x) => x.group === g);
        return el("section", { class: "tool-group" },
          el("h4", {}, t(`tb.group.${g}`)), el("p", { class: "note" }, t(`tb.group_q.${g}`)),
          ...list.map((x) => {
            const usable = reg.enabled && x.available;
            const fits = !det || fit.has(x.id);
            return el("button", {
              type: "button", class: `tool-row${fits ? "" : " dim"}${selected?.id === x.id ? " on" : ""}`, dataset: { id: x.id },
              title: !usable ? x.reason || t("mt.disabled") : !fits ? t("an.not_fitting", { type: t(`tb.in.${det.type}`) }) : x.desc,
              onclick: () => select(x),
            }, el("span", { class: "tool-name" }, x.name), flags(x, { short: true }), el("span", { class: "tool-desc" }, x.desc));
          }));
      }));
    };

    const refresh = debounce(async () => {
      const q = input.value.trim();
      det = null;
      if (q) { try { det = await detect(q.slice(0, 4096)); } catch { det = null; } }
      kids(detLine, ...(det ? [el("span", { class: "muted" }, t("an.detected")), el("strong", {}, t(`tb.in.${det.type}`)),
        det.display && det.display !== q ? el("span", { class: "mono" }, ` ${det.display}`) : null,
        objectOf(det) ? el("a", { class: "btn plain", href: href(routes.obj(objectOf(det).type, objectOf(det).value)) }, t("an.open_object")) : null] : []));
      drawRecipes();
      drawGroups();
    }, 250);
    input.addEventListener("input", () => { grow(); refresh(); });

    const legend = el("details", { class: "legend-box" }, el("summary", {}, t("an.legend")),
      el("dl", { class: "kv" }, ...LEVELS.flatMap((l) => [el("dt", {}, el("span", { class: `flag lvl-${l}` }, t(`tb.level.${l}`))), el("dd", {}, t(`tb.level_title.${l}`))]),
        el("dt", {}, el("span", { class: "flag sees" }, t("tb.sees_short"))), el("dd", {}, t("tb.sees_title")),
        el("dt", {}, el("span", { class: "flag third" }, t("tb.third_short"))), el("dd", {}, t("tb.third_title"))));

    kids(box,
      el("h2", { class: "page-title" }, t("an.nav.tools")),
      el("p", { class: "lead" }, t("an.tools_lead")),
      !reg.enabled ? el("p", { class: "state err" }, t("mt.disabled")) : null,
      el("div", { class: "big-form" }, input), detLine, recipes,
      el("div", { class: "toolbox" }, groupsBox, el("div", { class: "toolbox-side" }, panel, legend)),
      el("h3", { class: "page-h" }, t("an.results")), this.stack.node);
    grow();
    det = input.value.trim() ? await detect(input.value.trim().slice(0, 4096)).catch(() => null) : null;
    if (seq !== this.seq) return;
    refresh();
    drawRecipes();
    drawGroups();
    const pre = query.get("tool") && reg.byId[query.get("tool")];
    if (pre) {
      const form = select(pre);
      // links from outside (bookmarks, other sites) never start a run by themselves
      if (internal && query.get("run") === "1" && input.value.trim() && form) form.requestSubmit();
    }
    const recipe = start?.recipe || (internal && reg.recipes.some((r) => r.id === query.get("recipe")) ? query.get("recipe") : null);
    if (recipe && input.value.trim() && reg.enabled) this.stack.recipe(recipe, recipe === "mail" ? input.value : (det?.value || input.value.trim()), t(`tb.recipe.${recipe}`));
    if (!pre) input.focus();
  }

  // --- history ------------------------------------------------------------------------------------------------------
  historyTable(runs, reg, withDelete = true) {
    return el("div", { class: "tbl-wrap" }, el("table", { class: "res" },
      el("thead", {}, el("tr", {}, el("th", {}, t("an.h.when")), el("th", {}, t("an.h.tool")), el("th", {}, t("an.h.target")), el("th", {}, t("an.h.result")), el("th", {}, ""))),
      el("tbody", {}, runs.map((r) => {
        const row = el("tr", {},
          el("td", {}, dateTime(r.created_at)),
          el("td", {}, r.recipe ? t(`tb.recipe.${r.recipe}`) : reg?.byId[r.tool]?.name || r.tool),
          el("td", {}, r.obj_type ? objLink(r.obj_type, r.obj_value, r.target || r.obj_value) : el("span", { class: "mono" }, r.target || "–")),
          el("td", {}, r.sev ? sevTag(r.sev) : "–"),
          el("td", { class: "num" }, el("a", { class: "btn small", href: href(routes.run(r.id)) }, t("common.open")),
            withDelete ? el("button", { type: "button", class: "small danger", onclick: async () => {
              try { await api(`api/tb/history/${r.id}`, { method: "DELETE" }); row.remove(); } catch (e) { row.after(el("tr", {}, el("td", { colspan: 5, class: "state err" }, e.message))); }
            } }, "×") : null));
        return row;
      }))));
  }

  async history(box) {
    const [data, reg] = await Promise.all([api("api/tb/history?limit=300"), loadRegistry()]);
    kids(box, el("h2", { class: "page-title" }, t("an.nav.history")), el("p", { class: "lead" }, t("an.history_lead")),
      data.runs.length ? this.historyTable(data.runs, reg) : el("p", { class: "empty" }, t("an.history_none")));
  }

  async runView(box, id) {
    const r = await api(`api/tb/history/${encodeURIComponent(id)}`);
    kids(box, el("div", { class: "btnrow" }, el("a", { class: "btn", href: href("analyse/history") }, `← ${t("an.nav.history")}`)),
      renderResult(r, { onMap: this.onMap }));
  }

  // --- deep views ---------------------------------------------------------------------------------------------------
  viewHead(name) {
    return [el("h2", { class: "page-title" }, t(`an.view.${name}`)), el("p", { class: "lead" }, t(`an.view_lead.${name}`))];
  }

  async view_kev(box, seq) {
    const f = { q: "", vendor: "", days: "0", ransomware: false, min_epss: "0", mine: false, sort: "date" };
    const out = el("div");
    const q = el("input", { type: "search", placeholder: t("an.kev.q_ph"), "aria-label": t("an.kev.q_ph"), maxlength: 100 });
    const vendor = el("select", { "aria-label": t("an.kev.vendor") }, el("option", { value: "" }, t("common.all")));
    const days = el("select", { "aria-label": t("an.kev.period") }, ...[["0", t("an.kev.all_time")], ["7", t("t.days", { n: 7 })], ["30", t("t.days", { n: 30 })], ["90", t("t.days", { n: 90 })], ["365", t("t.days", { n: 365 })]].map(([v, l]) => el("option", { value: v }, l)));
    const epss = el("select", { "aria-label": "EPSS" }, ...[["0", t("common.all")], ["0.1", "≥ 0,1"], ["0.5", "≥ 0,5"], ["0.9", "≥ 0,9"]].map(([v, l]) => el("option", { value: v }, l)));
    const sort = el("select", { "aria-label": t("an.kev.sort") }, el("option", { value: "date" }, t("an.kev.by_date")), el("option", { value: "epss" }, t("an.kev.by_epss")));
    const rw = el("input", { type: "checkbox" });
    const mine = el("input", { type: "checkbox" });
    const load = async () => {
      const p = new URLSearchParams({ sort: f.sort, limit: "500" });
      for (const k of ["q", "vendor"]) if (f[k]) p.set(k, f[k]);
      if (f.days !== "0") p.set("days", f.days);
      if (f.min_epss !== "0") p.set("min_epss", f.min_epss);
      if (f.ransomware) p.set("ransomware", "true");
      if (f.mine) p.set("mine", "true");
      kids(out, el("p", { class: "state" }, t("common.loading")));
      const d = await api(`api/kev?${p}`);
      if (seq !== this.seq) return;
      if (vendor.options.length === 1) vendor.append(...d.vendors.map((v) => el("option", { value: v.key }, `${v.key} (${num(v.count)})`)));
      kids(out, el("p", { class: "note" }, t("an.kev.count", { n: num(d.total), total: num(d.catalog) })),
        d.rows.length ? el("div", { class: "tbl-wrap" }, el("table", { class: "res" },
          el("thead", {}, el("tr", {}, ["CVE", t("an.kev.vendor"), t("an.kev.product"), t("an.kev.added"), t("an.kev.due"), "EPSS", ""].map((h) => el("th", {}, h)))),
          el("tbody", {}, d.rows.map((r) => el("tr", {},
            el("td", {}, objLink("cve", r.cve)),
            el("td", {}, objLink("vendor", r.vendor, r.vendor)),
            el("td", {}, r.product || "", el("div", { class: "muted" }, r.name || "")),
            el("td", {}, dateOnly(r.date_added)), el("td", {}, dateOnly(r.due_date)),
            el("td", { class: r.epss >= 0.5 ? "warn-txt" : null }, r.epss === null || r.epss === undefined ? "–" : dec2(r.epss)),
            el("td", {}, (r.ransomware || "").toLowerCase() === "known" ? el("span", { class: "tag bad" }, t("pr.ransom_tag")) : null,
              r.watched ? el("span", { class: "tag warn" }, t("an.kev.watched")) : null, r.exposed ? el("span", { class: "tag bad" }, t("an.kev.exposed")) : null))))))
          : el("p", { class: "empty" }, t("common.no_data")));
    };
    const apply = debounce(() => {
      Object.assign(f, { q: q.value.trim(), vendor: vendor.value, days: days.value, min_epss: epss.value, sort: sort.value, ransomware: rw.checked, mine: mine.checked });
      load().catch((e) => kids(out, el("p", { class: "state err" }, e.message)));
    }, 250);
    for (const n of [q, vendor, days, epss, sort, rw, mine]) n.addEventListener(n === q ? "input" : "change", apply);
    kids(box, ...this.viewHead("kev"),
      el("div", { class: "filters wide" }, el("label", { class: "grow" }, t("an.kev.search"), q), el("label", {}, t("an.kev.vendor"), vendor),
        el("label", {}, t("an.kev.period"), days), el("label", {}, "EPSS", epss), el("label", {}, t("an.kev.sort"), sort),
        el("label", { class: "pcheck" }, rw, t("an.kev.ransom_only")), el("label", { class: "pcheck" }, mine, t("an.kev.mine_only"))),
      out);
    await load();
  }

  async view_infra(box, seq) {
    const out = el("div");
    const days = el("select", { "aria-label": t("an.kev.period") }, ...[7, 30, 60].map((v) => el("option", { value: v, selected: v === 30 }, t("t.days", { n: v }))));
    const kind = el("select", { "aria-label": t("an.infra.kind") }, el("option", { value: "" }, t("common.all")),
      ...["outage", "hijack", "leak", "anomaly"].map((k) => el("option", { value: k }, t(`an.infra.k.${k}`))));
    const cc = el("input", { type: "text", maxlength: 2, placeholder: "DE", "aria-label": t("an.infra.country"), class: "cc-in" });
    const load = async () => {
      const p = new URLSearchParams({ days: days.value });
      if (kind.value) p.set("kind", kind.value);
      if (/^[A-Za-z]{2}$/.test(cc.value.trim())) p.set("cc", cc.value.trim().toUpperCase());
      kids(out, el("p", { class: "state" }, t("common.loading")));
      const d = await api(`api/infra?${p}`);
      if (seq !== this.seq) return;
      kids(out,
        el("p", { class: "note" }, t("an.infra.count", { n: num(d.total) }), " ",
          ...Object.entries(d.counts).map(([k, v]) => el("span", { class: "tag" }, `${t(`an.infra.k.${k}`)}: ${num(v)}`))),
        d.events.length ? el("div", { class: "tbl-wrap" }, el("table", { class: "res" },
          el("thead", {}, el("tr", {}, [t("an.infra.event"), t("an.infra.countries"), "AS", t("an.infra.start"), t("an.infra.end"), ""].map((h) => el("th", {}, h)))),
          el("tbody", {}, d.events.map((e) => el("tr", {},
            el("td", {}, el("strong", {}, e.title), el("div", { class: "muted" }, (e.detail || "").slice(0, 240))),
            el("td", {}, ...(e.countries || []).flatMap((c, i) => [i ? ", " : null, objLink("country", c, countryName(c))])),
            el("td", {}, ...(e.asns || []).slice(0, 6).flatMap((a, i) => [i ? ", " : null, objLink("asn", String(a), `AS${a}`)])),
            el("td", {}, dateTime(e.start_ts)),
            el("td", {}, e.ongoing ? el("span", { class: "tag warn" }, t("t.ongoing")) : dateTime(e.end_ts)),
            el("td", {}, safeLink(e.url, "↗"))))))) : el("p", { class: "empty" }, t("common.no_data")));
    };
    const apply = debounce(() => load().catch((e) => kids(out, el("p", { class: "state err" }, e.message))), 250);
    for (const n of [days, kind]) n.addEventListener("change", apply);
    cc.addEventListener("input", apply);
    kids(box, ...this.viewHead("infra"),
      el("div", { class: "filters wide" }, el("label", {}, t("an.kev.period"), days), el("label", {}, t("an.infra.kind"), kind), el("label", {}, t("an.infra.country"), cc)),
      out);
    await load();
  }

  async view_c2(box, seq) {
    const out = el("div");
    const days = el("select", { "aria-label": t("an.kev.period") }, ...[1, 7, 30, 90].map((v) => el("option", { value: v, selected: v === 30 }, v === 1 ? t("t.24h") : t("t.days", { n: v }))));
    const fam = el("select", { "aria-label": t("t.c2_family") }, el("option", { value: "" }, t("t.c2_all_families")));
    const src = el("select", { "aria-label": t("t.c2_source") }, ...[["all", t("common.all")], ["feodo", "Feodo Tracker"], ["threatfox", "ThreatFox"]].map(([v, l]) => el("option", { value: v }, l)));
    let data = null;
    const draw = () => {
      const rows = data.features.map((f) => f.properties).filter((p) => !fam.value || p.malware === fam.value);
      const byFam = new Map();
      for (const p of rows) byFam.set(p.malware || "?", (byFam.get(p.malware || "?") || 0) + 1);
      const q = new URLSearchParams({ days: days.value, source: src.value });
      if (fam.value) q.set("family", fam.value);
      kids(out,
        el("p", { class: "note" }, t("an.c2.count", { n: num(rows.length) })),
        el("div", { class: "chiplist" }, [...byFam.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20).map(([k, v]) =>
          el("span", {}, objLink("malware", k, k), ` ${num(v)}`))),
        el("div", { class: "btnrow" },
          el("a", { class: "btn", href: `api/export/c2?fmt=txt&${q}`, download: "" }, t("t.blocklist")),
          el("a", { class: "btn", href: `api/export/c2?fmt=csv&${q}`, download: "" }, t("t.export_csv"))),
        rows.length ? el("div", { class: "tbl-wrap" }, el("table", { class: "res" },
          el("thead", {}, el("tr", {}, ["IOC", t("c2.malware"), t("c2.country"), "AS", t("c2.status"), t("c2.first"), t("c2.last"), ""].map((h) => el("th", {}, h)))),
          el("tbody", {}, rows.slice(0, 1000).map((p) => el("tr", {},
            el("td", {}, p.ip ? objLink("ip", p.ip, p.ioc || p.ip, "obj mono") : el("span", { class: "mono" }, p.ioc)),
            el("td", {}, p.malware ? objLink("malware", p.malware) : "–"),
            el("td", {}, p.country ? objLink("country", p.country, countryName(p.country)) : "–"),
            el("td", {}, p.asn ? objLink("asn", String(p.asn), `AS${p.asn} ${p.as_name || ""}`.trim()) : "–"),
            el("td", {}, p.status || "–"), el("td", {}, dateTime(p.first_seen)), el("td", {}, dateTime(p.last_seen)),
            el("td", {}, /^https:\/\/(threatfox|feodotracker)\.abuse\.ch\//.test(p.reference || "") ? safeLink(p.reference, "↗") : null)))))) : el("p", { class: "empty" }, t("common.no_data")),
        rows.length > 1000 ? el("p", { class: "note" }, t("common.more", { n: num(rows.length - 1000) })) : null);
    };
    const load = async () => {
      kids(out, el("p", { class: "state" }, t("common.loading")));
      data = await api(`api/c2?days=${days.value}&source=${src.value}`);
      if (seq !== this.seq) return;
      const fams = [...new Set(data.features.map((f) => f.properties.malware).filter(Boolean))].sort((a, b) => a.localeCompare(b));
      const cur = fam.value;
      kids(fam, el("option", { value: "" }, t("t.c2_all_families")), ...fams.map((x) => el("option", { value: x, selected: x === cur }, x)));
      draw();
    };
    days.addEventListener("change", () => load().catch((e) => kids(out, el("p", { class: "state err" }, e.message))));
    src.addEventListener("change", () => load().catch((e) => kids(out, el("p", { class: "state err" }, e.message))));
    fam.addEventListener("change", draw);
    kids(box, ...this.viewHead("c2"),
      el("div", { class: "filters wide" }, el("label", {}, t("an.kev.period"), days), el("label", {}, t("t.c2_family"), fam), el("label", {}, t("t.c2_source"), src)),
      el("p", { class: "note" }, t("an.c2.geo_note")), out);
    await load();
  }

  async view_ransom(box, seq) {
    const out = el("div");
    const days = el("select", { "aria-label": t("an.kev.period") }, ...[7, 30, 90].map((v) => el("option", { value: v, selected: v === 30 }, t("t.days", { n: v }))));
    const grp = el("select", { "aria-label": t("t.groups") }, el("option", { value: "" }, t("common.all")));
    const cc = el("input", { type: "text", maxlength: 2, placeholder: "DE", "aria-label": t("an.infra.country"), class: "cc-in" });
    let data = [];
    const draw = () => {
      const want = cc.value.trim().toUpperCase();
      const rows = data.filter((v) => (!grp.value || v.grp === grp.value) && (!/^[A-Z]{2}$/.test(want) || v.country === want));
      const byGrp = new Map();
      for (const v of rows) byGrp.set(v.grp, (byGrp.get(v.grp) || 0) + 1);
      kids(out,
        el("p", { class: "note" }, t("an.ransom.count", { n: num(rows.length) })),
        el("div", { class: "chiplist" }, [...byGrp.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20).map(([k, v]) => el("span", {}, objLink("group", k, k), ` ${num(v)}`))),
        rows.length ? el("div", { class: "tbl-wrap" }, el("table", { class: "res" },
          el("thead", {}, el("tr", {}, [t("an.ransom.date"), t("an.ransom.victim"), t("t.groups"), t("c2.country"), t("t.sectors"), ""].map((h) => el("th", {}, h)))),
          el("tbody", {}, rows.map((v) => el("tr", {},
            el("td", {}, dateTime(v.discovered)), el("td", {}, v.victim || "–"),
            el("td", {}, objLink("group", v.grp)), el("td", {}, v.country ? objLink("country", v.country, countryName(v.country)) : "–"),
            el("td", {}, v.activity || "–"), el("td", {}, safeLink(v.permalink, "↗"))))))) : el("p", { class: "empty" }, t("common.no_data")));
    };
    const load = async () => {
      kids(out, el("p", { class: "state" }, t("common.loading")));
      data = await api(`api/victims?days=${days.value}&limit=1000`);
      if (seq !== this.seq) return;
      const cur = grp.value;
      const groups = [...new Set(data.map((v) => v.grp).filter(Boolean))].sort((a, b) => a.localeCompare(b));
      kids(grp, el("option", { value: "" }, t("common.all")), ...groups.map((g) => el("option", { value: g, selected: g === cur }, g)));
      draw();
    };
    days.addEventListener("change", () => load().catch((e) => kids(out, el("p", { class: "state err" }, e.message))));
    grp.addEventListener("change", draw);
    cc.addEventListener("input", draw);
    kids(box, ...this.viewHead("ransom"),
      el("div", { class: "filters wide" }, el("label", {}, t("an.kev.period"), days), el("label", {}, t("t.groups"), grp), el("label", {}, t("an.infra.country"), cc)),
      el("p", { class: "note" }, t("t.latest_note")), out);
    await load();
  }
}

