// Generic renderer for the unified result format of all tools, recipes and object pages:
// {tool, title, target, object, level, target_sees, third_party, verdict{sev,text}, findings[], sections[], map, related[], raw}
// Section kinds: kv | table | text | list | chart. Cells: plain values or {t, sev, href (https only), obj{type,value}, mono}.
import { barChart, destroy, lineChart, valueTable } from "./charts.js";
import { t } from "./i18n.js";
import { flags } from "./registry.js";
import { objLink } from "./router.js";
import { dateTime, download, el, safeLink, sevTag } from "./util.js";

export function cellNode(c) {
  if (c === null || c === undefined || c === "") return document.createTextNode("–");
  if (Array.isArray(c)) return el("span", { class: "cell-list" }, ...c.slice(0, 200).flatMap((x, i) => [i ? ", " : "", cellNode(x)])); // several entries
  if (typeof c !== "object") return document.createTextNode(String(c));
  const txt = c.t ?? "";
  let node;
  if (c.obj) node = objLink(c.obj.type, c.obj.value, txt || c.obj.value);
  else if (c.href) node = safeLink(c.href, txt || "↗") || document.createTextNode(txt);
  else node = document.createTextNode(txt);
  if (!c.sev && !c.mono) return node;
  return el("span", { class: [c.mono ? "mono" : null, c.sev ? `mk ${c.sev}` : null].filter(Boolean).join(" ") }, node);
}

function kvSection(s) {
  return el("dl", { class: "kv" }, (s.rows || []).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, cellNode(v))]));
}

function tableSection(s) {
  if (!s.rows?.length) return el("p", { class: "empty" }, s.empty || t("common.no_data"));
  const wrap = el("div", { class: "tbl-wrap" }, el("table", { class: "res" },
    s.columns?.some(Boolean) ? el("thead", {}, el("tr", {}, s.columns.map((c) => el("th", {}, c || "")))) : null,
    el("tbody", {}, s.rows.map((row) => el("tr", {}, row.map((c) => el("td", {}, cellNode(c))))))));
  return wrap;
}

function chartSection(s) {
  const canvas = el("canvas", { role: "img", "aria-label": s.title || "" });
  requestAnimationFrame(() => {
    if (!canvas.isConnected) return;
    const spec = { labels: s.labels, unit: s.unit || "", series: s.series, vertical: true, spanGaps: false };
    if (s.type === "line") lineChart(canvas, spec);
    else barChart(canvas, spec);
  });
  return el("div", {}, el("div", { class: "chart-box" }, canvas), valueTable({ labels: s.labels, unit: s.unit, series: s.series }));
}

export function sectionNode(s) {
  let body;
  if (s.kind === "kv") body = kvSection(s);
  else if (s.kind === "table") body = tableSection(s);
  else if (s.kind === "text") body = s.mono ? el("pre", { class: "res-pre" }, s.text) : el("p", { class: "res-text" }, s.text);
  else if (s.kind === "list") body = el("div", { class: "chiplist" }, (s.items || []).map((x) => el("span", {}, cellNode(x))));
  else if (s.kind === "chart") body = chartSection(s);
  else return null;
  return el("section", { class: "res-sec" }, s.title ? el("h4", {}, s.title) : null, body,
    s.note ? el("p", { class: "note" }, s.note) : null);
}

export function findingsNode(findings, { withTool = false } = {}) {
  if (!findings?.length) return null;
  return el("ul", { class: "findings res-findings" }, findings.map((f) => el("li", {},
    sevTag(f.sev), withTool && f.tool ? el("span", { class: "cat" }, `${f.tool} · `) : null,
    el("span", { class: "ftext" }, f.text), f.detail ? el("div", { class: "fdetail" }, f.detail) : null)));
}

export function relatedNode(related, title = t("res.related")) {
  if (!related?.length) return null;
  return el("section", { class: "res-sec" }, el("h4", {}, title),
    el("div", { class: "chiplist" }, related.map((r) => el("span", {}, el("span", { class: "kind" }, t(`obj.type.${r.type}`)), objLink(r.type, r.value, r.label || r.value)))));
}

function slug(s) {
  return String(s || "result").toLowerCase().replace(/[^a-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "result";
}

/**
 * Renders a tool or recipe result. opts: {onMap(map), compact, actions: [nodes]}.
 * Charts are created after insertion; call destroyIn(container) before replacing a rendered result.
 */
export function renderResult(r, opts = {}) {
  if (r.tool === "recipe") return renderRecipe(r, opts);
  const head = el("div", { class: "res-head" },
    el("div", { class: "res-title" }, el("h3", {}, r.title || r.tool), r.target ? el("span", { class: "res-target mono" }, r.target) : null),
    el("div", { class: "res-meta" }, flags(r, { short: opts.compact }),
      el("span", { class: "muted" }, [r.saved_at ? dateTime(r.saved_at) : r.started_at ? dateTime(r.started_at) : null,
        Number.isFinite(r.ms) ? `${r.ms} ms` : null].filter(Boolean).join(" · "))));
  const verdict = el("p", { class: "verdict" }, sevTag(r.verdict?.sev || "ok"), r.verdict?.text || "");
  const actions = el("div", { class: "btnrow res-actions" },
    r.object ? objLink(r.object.type, r.object.value, t("res.open_object"), "btn") : null,
    r.map && opts.onMap ? el("button", { type: "button", onclick: () => opts.onMap(r.map, `${r.title}: ${r.target}`) }, t("common.show_map")) : null,
    el("button", { type: "button", onclick: () => download(`emberwatch-${slug(r.tool)}-${slug(r.target)}.json`, JSON.stringify(r, null, 2), "application/json") }, t("res.json")),
    ...(opts.actions || []));
  const raw = r.raw ? el("details", { class: "res-raw" }, el("summary", {}, t("res.raw"))) : null;
  if (raw) {
    raw.addEventListener("toggle", () => {
      if (raw.open && raw.childElementCount === 1) raw.append(el("pre", { class: "res-pre" }, JSON.stringify(r.raw, null, 2).slice(0, 200000)));
    }, { once: false });
  }
  return el("article", { class: `result${opts.compact ? " compact" : ""}` },
    head, verdict, findingsNode(r.findings),
    ...(r.sections || []).map(sectionNode),
    relatedNode(r.related), actions, raw);
}

function renderRecipe(r, opts) {
  const steps = el("div", { class: "steps" }, (r.steps || []).map((s) => {
    const d = el("details", { class: "step" },
      el("summary", {}, s.error ? el("span", { class: "sev medium" }, t("res.step_failed")) : sevTag(s.sev),
        el("strong", {}, s.title || s.tool), " ", el("span", { class: "muted" }, s.error || s.text || "")));
    if (s.result) {
      d.addEventListener("toggle", () => {
        if (d.open && d.childElementCount === 1) d.append(renderResult(s.result, { compact: true, onMap: opts.onMap }));
      });
    }
    return d;
  }));
  return el("article", { class: "result recipe" },
    el("div", { class: "res-head" }, el("div", { class: "res-title" }, el("h3", {}, r.title), r.target ? el("span", { class: "res-target mono" }, r.target) : null),
      el("div", { class: "res-meta" }, r.level ? flags(r, { short: true }) : null, el("span", { class: "muted" }, [r.saved_at ? dateTime(r.saved_at) : dateTime(r.started_at), `${r.ms} ms`].join(" · ")))),
    el("p", { class: "verdict" }, sevTag(r.verdict?.sev || "ok"), r.verdict?.text || ""),
    findingsNode(r.findings, { withTool: true }),
    el("h4", { class: "res-h" }, t("res.steps")), steps,
    el("div", { class: "btnrow res-actions" },
      r.object ? objLink(r.object.type, r.object.value, t("res.open_object"), "btn") : null,
      ...collectMaps(r, opts),
      el("button", { type: "button", onclick: () => download(`emberwatch-${slug(r.recipe)}-${slug(r.target)}.json`, JSON.stringify(r, null, 2), "application/json") }, t("res.json")),
      ...(opts.actions || [])));
}

function collectMaps(r, opts) {
  if (!opts.onMap) return [];
  const points = [];
  const paths = [];
  for (const s of r.steps || []) {
    if (s.result?.map) {
      points.push(...(s.result.map.points || []));
      paths.push(...(s.result.map.paths || []));
    }
  }
  return points.length ? [el("button", { type: "button", onclick: () => opts.onMap({ points, paths }, `${r.title}: ${r.target}`) }, t("common.show_map"))] : [];
}

export function destroyIn(node) {
  node?.querySelectorAll?.("canvas").forEach(destroy);
}
