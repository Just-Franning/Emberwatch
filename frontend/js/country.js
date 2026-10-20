// Country view in the right panel: shares, vectors, C2, ransomware, infrastructure, submarine cables, 30-day trend.
import { barChart, destroy, lineChart } from "./charts.js";
import { locale, t } from "./i18n.js";
import { api, countryName, dateTime, el, num, pct } from "./util.js";

export async function renderCountry(cc, { onClose, onAnalyze }) {
  const box = document.getElementById("country");
  box.hidden = false;
  box.querySelectorAll("canvas").forEach(destroy);
  box.replaceChildren(el("p", { class: "empty" }, t("country.loading", { name: countryName(cc) })));
  document.getElementById("right-body").scrollTop = 0;
  let d, tr;
  try {
    [d, tr] = await Promise.all([api(`api/country/${encodeURIComponent(cc)}`), api(`api/trends/${encodeURIComponent(cc)}?days=30`)]);
  } catch (e) {
    box.replaceChildren(el("p", { class: "state err" }, t("country.failed", { msg: e.message })));
    return;
  }
  const s = d.radar_shares_pct;
  const row = (label, a, b) => [el("dt", {}, label), el("dd", {}, pct(a)), el("dd", { class: "weak" }, pct(b))];
  const chips = (items, fmt = (x) => x.key || t("t.unknown_sector")) => items?.length
    ? el("div", { class: "chips" }, items.slice(0, 8).map((x) => el("span", {}, fmt(x), " ", el("b", {}, num(x.count)))))
    : el("p", { class: "note" }, t("common.none"));
  const vec = (blk) => Object.entries(blk?.summary || {}).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const vecChips = (blk) => (blk?.error ? el("p", { class: "note" }, t("country.na"))
    : vec(blk).length ? el("div", { class: "chips" }, vec(blk).map(([k, v]) => el("span", {}, k, " ", el("b", {}, pct(v))))) : el("p", { class: "note" }, t("map.no_data")));

  // trend charts: shares (%) and counts separately, one axis each
  const labels = tr.labels.map((x) => new Date(`${x}T12:00:00Z`).toLocaleDateString(locale, { day: "2-digit", month: "2-digit" }));
  const shareSeries = [["country.l7_target", "l7_target"], ["country.l3_target", "l3_target"], ["country.l7_origin", "l7_origin"]]
    .map(([name, key]) => ({ name: t(name), values: tr.series[key] })).filter((x) => x.values.some((v) => v !== null));
  const countSeries = [["country.ransom_series", "ransomware"], ["country.c2_series", "c2_new"]].map(([name, key]) => ({ name: t(name), values: tr.series[key] }))
    .filter((x) => x.values.some((v) => v));
  const c1 = el("canvas", { role: "img", "aria-label": t("country.trend_aria") });
  const c2 = el("canvas", { role: "img", "aria-label": t("country.counts_aria") });

  const cab = d.cables || { cables: [] };
  box.replaceChildren(...[
    el("div", { class: "chead" },
      el("h2", {}, d.name),
      el("button", { class: "collapse", type: "button", onclick: onClose, title: t("country.close") }, el("span", { "aria-hidden": "true" }, "×"), el("span", { class: "sr-only" }, t("country.close")))),
    el("dl", {},
      el("dt", { style: "color:var(--text-3)" }, t("country.share")), el("dd", { class: "weak" }, "24 h"), el("dd", { class: "weak" }, t("country.7d")),
      ...row(t("country.l7_target"), s.l7_target_1d, s.l7_target_7d), ...row(t("country.l3_target"), s.l3_target_1d, s.l3_target_7d),
      ...row(t("country.l7_origin"), s.l7_origin_1d, s.l7_origin_7d), ...row(t("country.l3_origin"), s.l3_origin_1d, s.l3_origin_7d)),
    el("h3", {}, t("country.trend")),
    shareSeries.length ? el("div", { class: "chart-box" }, c1) : el("p", { class: "note" }, t("country.no_trend")),
    countSeries.length ? el("div", { class: "chart-box", style: "height:120px" }, c2) : null,
    el("h3", {}, t("country.vectors")), vecChips(d.radar_drilldown?.l3_vector_target_1d),
    el("h3", {}, t("country.rules")), vecChips(d.radar_drilldown?.l7_rules_origin_1d),
    el("h3", {}, t("country.infra", { n: num(d.infra_events.length) })),
    d.infra_events.length ? el("ul", { class: "events" }, d.infra_events.slice(0, 8).map((e) => el("li", {},
      `${e.title}${e.ongoing ? t("map.ongoing") : ""}, ${dateTime(e.start_ts)}`,
      el("span", { class: "sub" }, (e.detail || "").slice(0, 200))))) : el("p", { class: "note" }, t("country.no_events")),
    el("h3", {}, t("country.cables", { n: num(cab.cables.length) })),
    cab.cables.length ? el("p", { class: "note" }, t("country.cables_list", { list: cab.cables.slice(0, 14).join(", "),
      more: cab.cables.length > 14 ? t("country.cables_more", { n: cab.cables.length - 14 }) : "", snap: cab.snapshot || "2021" }))
      : el("p", { class: "note" }, t("country.no_cables")),
    el("h3", {}, t("country.c2", { n: num(d.c2.total) })), chips(d.c2.by_malware),
    d.c2.by_asn.length ? chips(d.c2.by_asn) : null,
    el("h3", {}, t("country.ransom", { n: num(d.ransomware_7d.total) })), chips(d.ransomware_7d.by_group),
    d.ransomware_7d.by_sector.length ? chips(d.ransomware_7d.by_sector) : null,
    d.patterns.length ? el("h3", {}, t("country.patterns")) : null,
    d.patterns.length ? el("ul", { class: "events" }, d.patterns.map((p) => el("li", {}, p.title))) : null,
    el("div", { class: "ai-actions", style: "margin-top:10px" }, el("button", { type: "button", class: "primary", onclick: () => onAnalyze(cc) }, t("country.analyze", { name: d.name }))),
  ].filter(Boolean));
  requestAnimationFrame(() => {
    if (shareSeries.length) lineChart(c1, { labels, unit: "%", series: shareSeries, spanGaps: false });
    if (countSeries.length) barChart(c2, { labels, unit: "", series: countSeries, vertical: true });
  });
}

export function hideCountry() {
  const box = document.getElementById("country");
  box.querySelectorAll("canvas").forEach(destroy);
  box.hidden = true;
  box.replaceChildren();
}
