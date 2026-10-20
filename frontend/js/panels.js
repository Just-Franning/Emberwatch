// Left panel (KPIs, rankings incl. filter/export), patterns, alert feed, legend.
import { destroy, lineChart } from "./charts.js";
import { locale, t } from "./i18n.js";
import { COLORS, RAMP, ago, countryName, dateOnly, dateTime, dec1, dec2, el, num, pct, pp, safeLink, sevTag } from "./util.js";

// --- building blocks ---------------------------------------------------------------------
export function rankList(items, { color, fmt = num, onCountry, onClick } = {}) {
  if (!items?.length) return el("p", { class: "empty" }, t("common.no_data"));
  const max = items.reduce((a, it) => Math.max(a, it.value || 0), 0) || 1;
  return el("ol", { class: "rank" }, items.map((it) => {
    const click = it.cc && onCountry ? () => onCountry(it.cc) : onClick && it.ref !== undefined ? () => onClick(it.ref) : null;
    return el("li", { dataset: it.cc && onCountry ? { cc: it.cc } : {}, class: click && !it.cc ? "clickable" : null, onclick: click, title: it.title || null },
      el("span", { class: "lbl" }, it.label),
      el("span", { class: "val" }, fmt(it.value), it.delta !== undefined && it.delta !== null ? deltaTag(it.delta) : null, it.tag || null),
      it.sub ? el("span", { class: "sub" }, it.sub) : null,
      color ? el("span", { class: "bar", "aria-hidden": "true" }, el("i", { style: `width:${Math.max(2, ((it.value || 0) / max) * 100)}%;background:${color}` })) : null);
  }));
}

function deltaTag(d) {
  if (Math.abs(d) < 0.05) return el("span", { class: "delta" }, pp(0));
  return el("span", { class: `delta ${d > 0 ? "up" : ""}`, title: t("rank.delta_title") }, pp(d));
}

function radarRows(rad, key, field, baseKey) {
  const base = {};
  for (const r of rad[baseKey]?.rows || []) base[r[field]] = r.value;
  return (rad[key]?.rows || []).map((r) => ({
    cc: r[field], label: countryName(r[field]), value: r.value,
    delta: baseKey ? (base[r[field]] !== undefined ? r.value - base[r[field]] : null) : undefined,
    title: baseKey && base[r[field]] === undefined ? t("rank.not_top") : null,
  }));
}

function summaryRows(rad, key, baseKey) {
  const s = rad[key]?.summary || {};
  const b = rad[baseKey]?.summary || {};
  return Object.entries(s).sort((a, c) => c[1] - a[1]).map(([k, v]) => ({ label: k, value: v, delta: baseKey ? v - (b[k] ?? 0) : undefined }));
}

function section(title, note, ...content) {
  return [el("h3", {}, title), note ? el("p", { class: "note" }, note) : null, ...content];
}

function stamp(block) {
  return block?.fetched_at ? t("radar.stamp", { ago: ago(block.fetched_at) }) : t("radar.never");
}

function seriesChart(block, n = 3) {
  if (!block?.series || !block.timestamps?.length) return null;
  const ranked = Object.entries(block.series)
    .map(([k, vals]) => [k, vals.reduce((a, v) => a + (v || 0), 0)])
    .sort((a, b) => b[1] - a[1]).slice(0, n).map(([k]) => k);
  const labels = block.timestamps.map((x) => new Date(x).toLocaleString(locale, { weekday: "short", hour: "2-digit" }));
  const canvas = el("canvas", { role: "img", "aria-label": t("chart.series_7d", { names: ranked.join(", ") }) });
  requestAnimationFrame(() => lineChart(canvas, { labels, unit: "%", series: ranked.map((k) => ({ name: k, values: block.series[k] })) }));
  return el("div", { class: "chart-box" }, canvas);
}

export const causeName = (c) => t(`cause.${c || "UNKNOWN"}`);
const empty = (key = "common.no_data") => el("p", { class: "empty" }, t(key));

// --- KPIs ----------------------------------------------------------------------------------
export function renderKpis(ov) {
  const top = ov.radar.l7_target_1d?.rows?.[0];
  const ic = ov.infra?.counts_7d || {};
  const w = ov.watch || {};
  const tiles = [
    [num(ov.c2.new_24h), t("kpi.c2_new"), t("kpi.c2_total", { n: num(ov.c2.total) })],
    [num(ov.ransomware.total_7d), t("kpi.ransom"), ov.ransomware.prev_window_complete ? t("kpi.ransom_prev", { n: num(ov.ransomware.total_prev_7d) }) : t("kpi.ransom_prev_na")],
    [top ? countryName(top.target) : "–", t("kpi.top_target"), top ? t("kpi.share", { v: pct(top.value) }) : t("kpi.no_radar")],
    [num(ov.kev.added_14d), t("kpi.kev"), ov.kev.epss_available ? t("kpi.kev_epss", { n: num(ov.kev.epss_high_14d), thr: dec1(0.5) }) : t("kpi.epss_na")],
    [num(ic.outage || 0), t("kpi.outages"), t("kpi.bgp", { n: num((ic.hijack || 0) + (ic.leak || 0)) })],
    [num(w.hits_7d || 0), t("kpi.alerts"), t("kpi.alerts_sub", { high: num(w.high_7d || 0), assets: num(w.entries || 0), products: num(w.products || 0) })],
  ];
  document.getElementById("kpis").replaceChildren(...tiles.map(([b, s, small], i) =>
    el("div", { class: `kpi${i === 5 && (w.high_7d || 0) > 0 ? " alert" : ""}` },
      el("b", { class: /^[\d.,–\s]+$/.test(b) ? null : "word" }, b), el("span", {}, s), el("small", {}, small))));
}

// --- tabs ---------------------------------------------------------------------------------------
export function renderTab(tab, ctx) {
  const { ov, victims, onCountry, onCve } = ctx;
  const rad = ov.radar;
  const panel = document.getElementById("tabpanel");
  let content = [];
  if (tab === "targets") {
    content = [
      ...section(t("t.l7_target"), t("t.l7_target_note", { stamp: stamp(rad.l7_target_1d) }),
        rankList(radarRows(rad, "l7_target_1d", "target", "l7_target_7d"), { color: COLORS.attack, fmt: pct, onCountry })),
      ...section(t("t.l3_target"), null,
        rankList(radarRows(rad, "l3_target_1d", "target", "l3_target_7d"), { color: COLORS.attack, fmt: pct, onCountry })),
      ...section(t("t.industry"), t("t.share24"), rankList(summaryRows(rad, "l7_industry_1d"), { color: COLORS.attack, fmt: pct })),
    ];
  } else if (tab === "origins") {
    content = [
      ...section(t("t.l7_origin"), t("t.l7_origin_note"),
        rankList(radarRows(rad, "l7_origin_1d", "origin", "l7_origin_7d"), { color: COLORS.attack, fmt: pct, onCountry })),
      ...section(t("t.l3_origin"), t("t.l3_origin_note"),
        rankList(radarRows(rad, "l3_origin_1d", "origin", "l3_origin_7d"), { color: COLORS.attack, fmt: pct, onCountry })),
      ...section(t("t.pairs"), t("t.pairs_note"),
        rankList((rad.l7_pairs_1d?.rows || []).map((r) => ({ label: `${countryName(r.origin)} → ${countryName(r.target)}`, value: r.value, cc: r.target })),
          { color: COLORS.attack, fmt: pct, onCountry })),
    ];
  } else if (tab === "vectors") {
    content = [
      ...section(t("t.vectors"), t("t.vectors_note", { stamp: stamp(rad.l3_vector_1d) }),
        rankList(summaryRows(rad, "l3_vector_1d", "l3_vector_7d").slice(0, 12), { color: COLORS.attack, fmt: pct })),
      ...section(t("t.vectors_ts"), t("t.top3"), seriesChart(rad.l3_vector_ts_7d) || empty()),
      ...section(t("t.rules"), t("t.rules_note"),
        rankList(summaryRows(rad, "l7_rules_1d", "l7_rules_7d").slice(0, 12), { color: COLORS.attack, fmt: pct })),
      ...section(t("t.rules_ts"), t("t.top3"), seriesChart(rad.l7_rules_ts_7d) || empty()),
      ...section(t("t.protocols"), null, rankList(summaryRows(rad, "l3_protocol_1d"), { color: COLORS.attack, fmt: pct })),
      ...section(t("t.products"), null, rankList(summaryRows(rad, "l7_product_1d"), { color: COLORS.attack, fmt: pct })),
    ];
  } else if (tab === "c2") {
    content = c2Tab(ov, ctx);
  } else if (tab === "ransom") {
    const rw = ov.ransomware;
    content = [
      ...section(t("t.ransom_country"), t("t.ransom_note", { n: num(rw.total_7d), prev: rw.prev_window_complete ? num(rw.total_prev_7d) : t("t.ransom_prev_na") }),
        rankList(rw.by_country.filter((x) => x.key !== "??").map((x) => ({ label: countryName(x.key), value: x.count, cc: x.key })), { color: COLORS.ransom, onCountry })),
      ...section(t("t.groups"), null, rankList(rw.by_group.map((x) => ({ label: x.key, value: x.count })), { color: COLORS.ransom })),
      ...section(t("t.sectors"), null, rankList(rw.by_sector.map((x) => ({ label: x.key || t("t.unknown_sector"), value: x.count })), { color: COLORS.ransom })),
      ...section(t("t.group_country"), null, rankList(rw.group_country.map((x) => ({ label: t("t.group_in", { group: x.group, country: countryName(x.country) }), value: x.count, cc: x.country })), { color: COLORS.ransom, onCountry })),
      ...section(t("t.latest"), t("t.latest_note"),
        victims?.length
          ? el("ol", { class: "rank" }, victims.slice(0, 40).map((v) => el("li", { dataset: v.country ? { cc: v.country } : {}, onclick: v.country ? () => onCountry(v.country) : null },
              el("span", { class: "lbl" }, v.victim),
              el("span", { class: "val" }, v.grp),
              el("span", { class: "sub" }, `${countryName(v.country)}, ${v.activity || t("t.sector_unknown")}, ${dateTime(v.discovered)}`))))
          : empty()),
    ];
  } else if (tab === "infra") {
    content = infraTab(ov, onCountry);
  } else if (tab === "kev") {
    const kev = ov.kev;
    const kevItem = (k) => el("li", { class: "clickable", onclick: () => onCve?.(k.cve) },
      el("span", { class: "lbl" }, el("a", { href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(k.cve)}`, target: "_blank", rel: "noopener noreferrer", onclick: (e) => e.stopPropagation() }, k.cve)),
      el("span", { class: "val" }, k.epss !== null && k.epss !== undefined ? `EPSS ${dec2(k.epss)}` : dateOnly(k.date_added)),
      el("span", { class: "sub" }, t("t.kev_added", { vendor: k.vendor, product: k.product, date: dateOnly(k.date_added) })
        + ((k.ransomware || "").toLowerCase() === "known" ? t("t.kev_ransom") : "")));
    content = [
      ...section(t("t.kev_new"), t("t.kev_note", { n30: num(kev.added_30d), total: num(kev.total) }),
        kev.latest.length ? el("ol", { class: "rank" }, kev.latest.map(kevItem)) : empty()),
      ...section(t("t.kev_top"), null, kev.top_epss_90d?.length ? el("ol", { class: "rank" }, kev.top_epss_90d.map(kevItem)) : empty("t.epss_na")),
      ...section(t("t.kev_vendors"), null, rankList(kev.vendors_14d.map((x) => ({ label: x.key, value: x.count })), { color: COLORS.text3 })),
    ];
  }
  panel.querySelectorAll("canvas").forEach(destroy);
  panel.replaceChildren(...content.filter(Boolean));
}

function c2Tab(ov, ctx) {
  const { onCountry, c2Filter, onC2Filter, families, c2Count } = ctx;
  const c2 = ov.c2;
  const f = c2Filter;
  const fam = el("select", {}, el("option", { value: "" }, t("t.c2_all_families")),
    ...families.map((x) => el("option", { value: x, selected: f.family === x }, x)));
  const days = el("select", {}, ...[[1, t("t.24h")], [7, t("t.days", { n: 7 })], [30, t("t.days", { n: 30 })]].map(([v, l]) => el("option", { value: v, selected: f.days === v }, l)));
  const src = el("select", {}, ...[["all", t("common.all")], ["feodo", "Feodo"], ["threatfox", "ThreatFox"]].map(([v, l]) => el("option", { value: v, selected: f.source === v }, l)));
  const conf = el("select", {}, ...[[0, t("common.all")], [50, "≥ 50 %"], [75, "≥ 75 %"], [100, "100 %"]].map(([v, l]) => el("option", { value: v, selected: f.minConf === v }, l)));
  const apply = () => onC2Filter({ family: fam.value || null, days: Number(days.value), source: src.value, minConf: Number(conf.value) });
  for (const s of [fam, days, src, conf]) s.addEventListener("change", apply);
  const q = new URLSearchParams({ days: String(f.days || 30), source: f.source || "all", min_confidence: String(f.minConf || 0) });
  if (f.family) q.set("family", f.family);
  return [
    ...section(t("t.c2_filter"), t("t.c2_on_map", { n: num(c2Count ?? 0) }),
      el("div", { class: "filters" },
        el("label", {}, t("t.c2_family"), fam), el("label", {}, t("t.c2_period"), days),
        el("label", {}, t("t.c2_source"), src), el("label", {}, t("t.c2_conf"), conf)),
      el("div", { class: "btnrow" },
        el("a", { class: "btn", href: `api/export/c2?fmt=txt&${q}`, download: "" }, t("t.blocklist")),
        el("a", { class: "btn", href: `api/export/c2?fmt=csv&${q}`, download: "" }, t("t.export_csv")))),
    ...section(t("t.c2_families"), t("t.c2_families_note", { total: num(c2.total), geo: num(c2.geolocated) }),
      rankList(c2.by_malware.map((x) => ({ label: x.key, value: x.count, ref: x.key })), { color: COLORS.c2, onClick: (k) => onC2Filter({ family: k }) })),
    ...section(t("t.c2_new24"), null, rankList(c2.new_24h_by_malware.map((x) => ({ label: x.key, value: x.count, ref: x.key })), { color: COLORS.c2, onClick: (k) => onC2Filter({ family: k }) })),
    ...section(t("t.c2_countries"), t("t.c2_countries_note"),
      rankList(c2.by_country.map((x) => ({ label: countryName(x.key), value: x.count, cc: x.key })), { color: COLORS.c2, onCountry })),
    ...section(t("t.c2_asn"), null,
      rankList(c2.by_asn.map((x) => ({ label: `AS${x.key} ${x.name || ""}`.trim(), value: x.count })), { color: COLORS.c2 })),
  ];
}

function infraTab(ov, onCountry) {
  const inf = ov.infra || { events: [], outages_by_cause: [], outages_by_country: [], hijacks_by_country: [], counts_7d: {} };
  const evItem = (e) => el("li", { dataset: e.countries?.[0] ? { cc: e.countries[0] } : {}, onclick: e.countries?.[0] ? () => onCountry(e.countries[0]) : null },
    el("span", { class: "lbl" }, `${e.title}${e.countries?.length ? ": " + e.countries.map(countryName).join(", ") : ""}`),
    el("span", { class: "val" }, e.ongoing ? el("span", { class: "tag warn" }, t("t.ongoing")) : dateTime(e.start_ts)),
    el("span", { class: "sub" }, (e.detail || "").slice(0, 220)));
  const outages = inf.events.filter((e) => e.kind === "outage");
  const bgp = inf.events.filter((e) => e.kind === "hijack" || e.kind === "leak");
  const anomalies = inf.events.filter((e) => e.kind === "anomaly");
  const c = inf.counts_7d || {};
  return [
    ...section(t("t.outages"), t("t.outages_note", { n: num(c.outage || 0) }),
      outages.length ? el("ol", { class: "rank" }, outages.slice(0, 25).map(evItem)) : empty("t.no_outages")),
    ...section(t("t.causes"), null, rankList(inf.outages_by_cause.map((x) => ({ label: causeName(x.key), value: x.count })), { color: COLORS.infra })),
    ...section(t("t.bgp"), t("t.bgp_note", { h: num(c.hijack || 0), l: num(c.leak || 0) }),
      bgp.length ? el("ol", { class: "rank" }, bgp.slice(0, 25).map(evItem)) : empty("t.no_events")),
    ...section(t("t.hijack_cc"), t("t.hijack_cc_note"), rankList(inf.hijacks_by_country.map((x) => ({ label: countryName(x.key), value: x.count, cc: x.key })), { color: COLORS.infra, onCountry })),
    ...section(t("t.anomalies"), t("t.anomalies_note", { n: num(c.anomaly || 0) }),
      anomalies.length ? el("ol", { class: "rank" }, anomalies.slice(0, 20).map(evItem)) : empty("t.no_anomalies")),
  ];
}

// --- patterns ---------------------------------------------------------------------------------
export function renderPatterns(patterns, onCountry) {
  const list = document.getElementById("patterns");
  const high = patterns.filter((p) => p.severity === "high").length;
  document.getElementById("pattern-count").textContent = patterns.length
    ? (high ? t("patterns.count_high", { n: patterns.length, h: high }) : t("patterns.count", { n: patterns.length })) : "";
  if (!patterns.length) {
    list.replaceChildren(el("li", { class: "empty" }, t("patterns.none")));
    return;
  }
  list.replaceChildren(...patterns.map((p) =>
    el("li", { dataset: p.country ? { cc: p.country } : {}, onclick: p.country ? () => onCountry(p.country) : null },
      el("div", {}, sevTag(p.severity), el("span", { class: "cat" }, p.category_label || p.category)),
      el("div", { class: "ptitle" }, p.title),
      el("div", { class: "pdetail" }, p.detail))));
}

// --- alert feed (right panel) -----------------------------------------------------------------
export function alertItem(a, { onOpen } = {}) {
  return el("li", { class: onOpen && (a.asset_id || a.product_id) ? "clickable" : null, onclick: onOpen && (a.asset_id || a.product_id) ? () => onOpen(a) : null },
    el("div", {}, sevTag(a.severity), el("span", { class: "cat" }, t(`src.${a.source}`)), el("span", { class: "when" }, ago(a.created_at))),
    el("div", { class: "ptitle" }, a.title),
    el("div", { class: "pdetail" }, a.detail, " ", safeLink(a.url, "↗")));
}

export function renderAlertFeed(data, { onOpen, onWindow }) {
  const list = document.getElementById("alerts-feed");
  const st = data?.stats || {};
  document.getElementById("alert-count").textContent = st.total_7d ? t("alerts.count", { n: num(st.total_7d) }) : "";
  const items = (data?.alerts || []).slice(0, 12);
  list.replaceChildren(
    ...(items.length ? items.map((a) => alertItem(a, { onOpen })) : [el("li", { class: "empty" }, t("alerts.none"))]),
    el("li", { class: "more" }, el("button", { type: "button", onclick: onWindow }, t("alerts.open_window"))),
  );
}

// --- legend -----------------------------------------------------------------------------------
export function renderLegend(info, { historicalDay } = {}) {
  const box = document.getElementById("legend-scale");
  const parts = [];
  if (historicalDay) parts.push(el("div", { class: "hist" }, t("legend.timeline", { day: historicalDay })));
  if (info.meta && info.max) {
    parts.push(el("div", {}, info.meta.label),
      el("div", { class: "ramp", style: `background:linear-gradient(90deg, ${RAMP.join(", ")})` }),
      el("div", { class: "ends" }, el("span", {}, "0"), el("span", {}, info.meta.fmt(info.max))));
  } else if (info.meta) {
    parts.push(el("div", {}, t("legend.no_data", { label: info.meta.label })));
  }
  box.replaceChildren(...parts);
}

export function initLegend() {
  const lg = document.getElementById("legend");
  const btn = document.getElementById("legend-toggle");
  const set = (collapsed) => {
    lg.classList.toggle("collapsed", collapsed);
    btn.setAttribute("aria-expanded", String(!collapsed));
    btn.querySelector("[aria-hidden]").textContent = collapsed ? "+" : "–";
    try { localStorage.setItem("emberwatch.legend", collapsed ? "1" : "0"); } catch { /* ignore */ }
  };
  let start = window.matchMedia("(max-width: 900px)").matches;
  try { const v = localStorage.getItem("emberwatch.legend"); if (v !== null) start = v === "1"; } catch { /* ignore */ }
  set(start);
  btn.addEventListener("click", () => set(!lg.classList.contains("collapsed")));
}
