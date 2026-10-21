// Emberwatch web interface. Three areas, switched by the hash router (router.js):
//   LAGE     world map with rankings, country card, patterns, alerts, Gemini and the map tool bar
//   ANALYSE  object pages, tool box, deep views, run history (analyse.js)
//   MEIN NETZ  overview, own IPs, assets, products, alerts, logs (netz.js, assets.js)
import { AIPanel } from "./ai.js";
import { Analyse } from "./analyse.js";
import { hideCountry, renderCountry } from "./country.js";
import { applyStatic, t } from "./i18n.js";
import { initPanels, initShortcuts, renderSettings, renderStatusDots, renderStatusPanel, setCollapsed } from "./layout.js";
import { Emberwatch } from "./map.js";
import { MapTools } from "./maptools.js";
import { Netz } from "./netz.js";
import { Palette } from "./palette.js";
import { initLegend, renderAlertFeed, renderKpis, renderLegend, renderPatterns, renderTab } from "./panels.js";
import { AREAS, go, onRoute, routes, start as startRouter } from "./router.js";
import { Search } from "./search.js";
import { Timeline } from "./timeline.js";
import { api, dateTime, el, kids, loadCentroids, num } from "./util.js";
import { initWindows } from "./windows.js";

const REFRESH_MS = 5 * 60 * 1000;
const boot = window.EmberBoot || { step() {}, progress() {}, done() {} };
const state = {
  ov: null, victims: [], status: null, alerts: null, tab: "targets", country: null, historical: null, area: "lage",
  c2Filter: { days: 30, source: "all", minConf: 0, family: null }, families: [],
};

function waitForLibs() {
  return new Promise((resolve) => {
    if (window.maplibregl && window.Chart) return resolve();
    window.addEventListener("load", () => resolve(), { once: true });
  });
}

function infraForDay(events, day) {
  if (!day) return events;
  const s = Date.parse(`${day}T00:00:00Z`), e = s + 86400000;
  return events.filter((x) => (Date.parse(x.start_ts) || 0) < e && (!x.end_ts || Date.parse(x.end_ts) >= s));
}

const alertRoute = (a) => (a.asset_id ? routes.asset(a.asset_id) : a.product_id ? routes.product(a.product_id) : "netz/alerts");

async function main() {
  applyStatic();
  boot.step(t("boot.init"), "ok");
  boot.progress(0.1);
  document.getElementById("stamp").textContent = t("app.loading");
  await waitForLibs();
  await loadCentroids();
  initPanels();
  initLegend();
  initWindows(["panel-left", "panel-right", "panel-tools"]);
  // the header height varies with width and language: panels and pages start below it
  const header = document.querySelector(".hud-top");
  const setTop = () => document.documentElement.style.setProperty("--top-h", `${Math.ceil(header.getBoundingClientRect().height)}px`);
  new ResizeObserver(setTop).observe(header);
  setTop();

  let maptools;
  boot.step(t("boot.map"), "run");
  const map = new Emberwatch(document.getElementById("map"), {
    onCountry: (cc) => selectCountry(cc),
    onIp: (ip) => mapTool("ipinfo", ip),
  });
  await map.ready;
  boot.progress(0.45);
  maptools = new MapTools({ map });
  maptools.init();
  const ai = new AIPanel();
  const statusPanel = document.getElementById("status-panel");
  const settingsPanel = document.getElementById("settings-panel");

  /** Shows a tool/object result on the map: switches to the situation view first and names what is shown. */
  const note = document.getElementById("map-note");
  document.getElementById("map-note-clear").addEventListener("click", () => { map.clearTool(); note.hidden = true; });
  function showOnMap(m, label = "") {
    if (state.area !== "lage") go("lage");
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const n = map.showResult(m);
      document.getElementById("map-note-txt").textContent = t("mt.on_map", { what: label || t("mt.result"), n: num(n) });
      note.hidden = false;
    }));
  }

  /** Runs a map tool (situation view) with a target. */
  function mapTool(tool, target) {
    if (state.area !== "lage") go("lage");
    maptools.open(tool, target, true);
  }

  /** Tool from the palette or a link: map tools stay on the map, everything else runs in the tool box. */
  function runTool(toolId, target) {
    const tool = (maptools.reg || {}).byId?.[toolId];
    if (tool?.bar && state.area === "lage") maptools.open(toolId, target, true);
    else go(routes.tools(target, toolId, true));
  }

  const analyse = new Analyse({ nav: document.getElementById("an-nav"), main: document.getElementById("an-main"), onMap: showOnMap });
  const netz = new Netz({ nav: document.getElementById("nz-nav"), main: document.getElementById("nz-main"), onMap: showOnMap, onChange: () => refresh() });
  const palette = new Palette({ onTool: runTool });

  function selectCountry(cc) {
    if (!cc || !/^[A-Z]{2}$/.test(cc)) return;
    state.country = cc;
    setCollapsed("panel-right", false);
    map.select(cc);
    map.focus(cc);
    ai.setCountry(cc);
    renderCountry(cc, {
      onClose: () => { state.country = null; map.select(null); ai.setCountry(null); hideCountry(); },
      onAnalyze: (c) => ai.run({ scope: "country", country: c }),
    });
  }

  // --- areas --------------------------------------------------------------------------------------------------------
  const pages = { analyse: document.getElementById("area-analyse"), netz: document.getElementById("area-netz") };
  function setArea(area) {
    if (state.area === area) return;
    if (state.area === "analyse") analyse.leave();
    if (state.area === "netz") netz.leave();
    state.area = area;
    for (const a of AREAS) document.body.classList.toggle(`area-${a}`, a === area);
    for (const [a, node] of Object.entries(pages)) node.hidden = a !== area;
    document.querySelectorAll("#areas a").forEach((x) => (x.dataset.area === area ? x.setAttribute("aria-current", "page") : x.removeAttribute("aria-current")));
    map.pause(area !== "lage");
    statusPanel.hidden = true;
    settingsPanel.hidden = true;
  }
  onRoute((r) => {
    setArea(r.area);
    if (r.area === "analyse") analyse.show(r);
    else if (r.area === "netz") netz.show(r);
  });
  document.querySelectorAll("#areas a").forEach((x) => (x.dataset.area === "lage" ? x.setAttribute("aria-current", "page") : null));

  const onCve = (cve) => go(routes.obj("cve", cve));

  function onC2Filter(partial) {
    state.c2Filter = { ...state.c2Filter, ...partial };
    map.setC2Filter(state.c2Filter);
    if (state.tab === "c2") drawTab();
  }

  function drawTab() {
    if (!state.ov) return;
    renderTab(state.tab, {
      ov: state.ov, victims: state.victims, onCountry: selectCountry, onCve, onObject: (type, value) => go(routes.obj(type, value)),
      c2Filter: state.c2Filter, onC2Filter, families: state.families, c2Count: map.c2Count,
    });
  }

  function dayLabel(day) { return Timeline.dayLabel(day); }

  function applyLive() {
    const ov = state.ov;
    map.setCountries(ov.countries);
    map.setArcs(ov.radar.l7_pairs_1d?.rows || []);
    map.setInfra(ov.infra?.events || []);
    renderLegend(map.legendInfo());
  }

  const timeline = new Timeline({
    onDay: (data) => {
      state.historical = data.day;
      map.setCountries(data.countries);
      map.setArcs(data.pairs);
      map.setInfra(infraForDay(state.ov?.infra?.events || [], data.day));
      map.setC2Filter({ window: [Date.parse(data.c2_window[0]), Date.parse(data.c2_window[1])] });
      renderLegend(map.legendInfo(), { historicalDay: dayLabel(data.day) });
    },
    onLive: () => {
      state.historical = null;
      map.setC2Filter({ window: null });
      if (state.ov) applyLive();
    },
  });

  const search = new Search({
    onCountry: (cc) => (state.area === "lage" ? selectCountry(cc) : go(routes.obj("country", cc))),
    onC2: (c) => {
      if (state.area !== "lage") go("lage");
      requestAnimationFrame(() => {
        if (c.lon !== null && c.lon !== undefined) {
          map.flyTo(c.lon, c.lat, 5);
          map.c2Popup(c, [c.lon, c.lat]);
        } else if (c.country) selectCountry(c.country);
      });
    },
    onIp: (ip) => mapTool("ipinfo", ip),
    onCve,
    onAsn: (asn) => go(routes.obj("asn", String(asn).replace(/^as/i, ""))),
    onWatchProduct: async (vendor, product) => {
      try {
        await netz.assets.watchProduct(vendor, product);
        search.notice(t("s.product_added", { name: `${vendor} ${product}`.trim() }));
        go("netz/products");
      } catch (e) { search.notice(e.message); }
    },
    onWatchAsset: (value) => {
      netz.assets.prefill = value;
      go("netz/assets");
    },
    onOpenAsset: (id) => go(routes.asset(id)),
    onOpenProducts: (id) => go(id ? routes.product(id) : "netz/products"),
  });

  initShortcuts({
    onPalette: () => palette.toggle(),
    onArea: (a) => go(a),
    onTools: () => (state.area === "lage" ? maptools.focus() : go(routes.tools())),
    onSearch: () => search.focus(),
    onEscape: () => { maptools.close(); search.hide(); palette.close(); statusPanel.hidden = true; settingsPanel.hidden = true; },
    isLage: () => state.area === "lage",
  });

  // --- controls -----------------------------------------------------------------------------------------------------
  for (const [id, layer] of [["lyr-arcs", "arcs"], ["lyr-c2", "c2"], ["lyr-ransom", "ransom"], ["lyr-infra", "infra"], ["lyr-cables", "cables"]]) {
    const cb = document.getElementById(id);
    map.setVisible(layer, cb.checked);
    cb.addEventListener("change", () => map.setVisible(layer, cb.checked));
  }
  const metric = document.getElementById("choro-metric");
  metric.addEventListener("change", () => {
    map.setMetric(metric.value);
    renderLegend(map.legendInfo(), { historicalDay: state.historical ? dayLabel(state.historical) : null });
  });
  const projBtn = document.getElementById("btn-projection");
  projBtn.addEventListener("click", () => { projBtn.textContent = t(map.toggleProjection() === "globe" ? "btn.flat" : "btn.globe"); });
  document.getElementById("btn-palette").addEventListener("click", () => palette.open());
  document.getElementById("btn-alerts").addEventListener("click", () => go("netz/alerts"));
  const popover = (btn, panel, render) => {
    document.getElementById(btn).addEventListener("click", (e) => {
      e.stopPropagation();
      for (const p of [statusPanel, settingsPanel]) if (p !== panel) p.hidden = true;
      panel.hidden = !panel.hidden;
      if (!panel.hidden) render();
    });
  };
  popover("btn-status", statusPanel, () => state.status && renderStatusPanel(state.status, { basemapFailed: map.basemapFailed }));
  popover("btn-settings", settingsPanel, () => renderSettings(state.status));
  document.addEventListener("click", (e) => {
    for (const p of [statusPanel, settingsPanel]) if (!p.hidden && !p.contains(e.target)) p.hidden = true;
  });
  map.onFallback = () => { if (!statusPanel.hidden && state.status) renderStatusPanel(state.status, { basemapFailed: true }); };
  document.querySelectorAll("#panel-left .tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#panel-left .tabs button").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    state.tab = b.dataset.tab;
    drawTab();
  }));

  function renderAlertBadge(stats) {
    const badge = document.getElementById("alert-badge");
    const high = stats?.high_7d || 0;
    const medium = stats?.medium_7d || 0;
    const btn = document.getElementById("btn-alerts");
    btn.classList.toggle("hot", high > 0);
    kids(badge, t("btn.alerts"), high || medium ? el("b", {}, num(high + medium)) : null);
    btn.title = t("btn.alerts_title_n", { high: num(high), medium: num(medium), low: num(stats?.low_7d || 0) });
  }

  async function refresh(first = false) {
    try {
      if (first) boot.step(t("boot.feeds"), "run");
      const [ov, c2, victims, status, alertData] = await Promise.all([
        api("api/overview"), api("api/c2?days=30"), api("api/victims?days=7&limit=200"), api("api/status"),
        api("api/alerts?limit=20&min_severity=low"),
      ]);
      state.ov = ov;
      state.victims = victims;
      state.status = status;
      state.alerts = alertData;
      state.families = [...new Set(c2.features.map((f) => f.properties.malware).filter(Boolean))].sort((a, b) => a.localeCompare(b));
      map.setC2(c2);
      if (!state.historical) applyLive();
      renderKpis(ov);
      drawTab();
      renderPatterns(ov.patterns, selectCountry);
      renderAlertFeed(alertData, { onOpen: (a) => go(alertRoute(a)), onWindow: () => go("netz/alerts") });
      renderAlertBadge(alertData.stats);
      renderStatusDots(status);
      ai.setRegion(status.region);
      analyse.setStatus(status);
      netz.setStatus(status);
      if (!statusPanel.hidden) renderStatusPanel(status, { basemapFailed: map.basemapFailed });
      document.getElementById("stamp").textContent = t("stamp.as_of", { t: dateTime(ov.generated_at) });
      if (first) {
        const src = status.sources || [];
        boot.progress(0.8);
        boot.step(t("boot.sources", { ok: src.filter((s) => s.ok).length, n: src.length }), src.some((s) => !s.ok) ? "warn" : "ok");
        boot.step(`${t("boot.c2", { n: num(ov.c2.total) })} · ${t("boot.patterns", { n: num(ov.patterns.length) })} · ${t("boot.alerts", { n: num(ov.watch?.hits_7d || 0) })}`, "ok");
      }
      await timeline.load();
    } catch (e) {
      kids(document.getElementById("stamp"), el("span", { class: "warn-txt" }, t("stamp.failed", { msg: e.message })));
      if (first) boot.step(t("stamp.failed", { msg: e.message }), "fail");
    }
  }

  map.setC2Filter(state.c2Filter);
  await refresh(true);
  // the address this interface is opened from (via the reverse proxy): sighting for "my IP"
  api("api/myip/visit", { method: "POST" }).catch(() => {});
  startRouter();
  boot.progress(1);
  boot.step(t("boot.ready"), "ok");
  boot.done();
  setInterval(refresh, REFRESH_MS);
}

main().catch((e) => {
  boot.step(String(e?.message || e), "fail");
  boot.done();
});
