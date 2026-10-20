import { AIPanel } from "./ai.js";
import { Assets } from "./assets.js";
import { hideCountry, renderCountry } from "./country.js";
import { applyStatic, t } from "./i18n.js";
import { initPanels, initShortcuts, renderSettings, renderStatusDots, renderStatusPanel, setCollapsed } from "./layout.js";
import { Emberwatch } from "./map.js";
import { initLegend, renderAlertFeed, renderKpis, renderLegend, renderPatterns, renderTab } from "./panels.js";
import { Search } from "./search.js";
import { Timeline } from "./timeline.js";
import { Tools } from "./tools.js";
import { api, dateTime, el, loadCentroids, num } from "./util.js";
import { initWindows } from "./windows.js";

const REFRESH_MS = 5 * 60 * 1000;
const boot = window.EmberBoot || { step() {}, progress() {}, done() {} };
const state = {
  ov: null, victims: [], status: null, alerts: null, tab: "targets", country: null, historical: null,
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

async function main() {
  applyStatic();
  boot.step(t("boot.init"), "ok");
  boot.progress(0.1);
  document.getElementById("stamp").textContent = t("app.loading");
  await waitForLibs();
  await loadCentroids();
  initPanels();
  initLegend();
  initWindows(["panel-left", "panel-right", "panel-tools", "panel-assets"]);
  // the header height varies with width and language: panels start below it
  const header = document.querySelector(".hud-top");
  const setTop = () => document.documentElement.style.setProperty("--top-h", `${Math.ceil(header.getBoundingClientRect().height)}px`);
  new ResizeObserver(setTop).observe(header);
  setTop();

  let tools;
  let assets;
  boot.step(t("boot.map"), "run");
  const map = new Emberwatch(document.getElementById("map"), {
    onCountry: (cc) => selectCountry(cc),
    onIp: (ip) => tools.open("ipinfo", ip, true),
  });
  await map.ready;
  boot.progress(0.45);
  tools = new Tools(map);
  const ai = new AIPanel();
  assets = new Assets({ map, tools, onChange: () => refresh() });
  const statusPanel = document.getElementById("status-panel");
  const settingsPanel = document.getElementById("settings-panel");

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

  const onCve = (cve) => window.open(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`, "_blank", "noopener,noreferrer");

  function onC2Filter(partial) {
    state.c2Filter = { ...state.c2Filter, ...partial };
    map.setC2Filter(state.c2Filter);
    if (state.tab === "c2") drawTab();
  }

  function drawTab() {
    if (!state.ov) return;
    renderTab(state.tab, {
      ov: state.ov, victims: state.victims, onCountry: selectCountry, onCve,
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
    onCountry: selectCountry,
    onC2: (c) => {
      if (c.lon !== null && c.lon !== undefined) {
        map.flyTo(c.lon, c.lat, 5);
        map.c2Popup(c, [c.lon, c.lat]);
      } else if (c.country) selectCountry(c.country);
    },
    onIp: (ip) => tools.open("ipinfo", ip, true),
    onCve,
    onAsn: (asn) => tools.open("rdap", asn, true),
    onWatchProduct: async (vendor, product) => {
      try {
        await assets.watchProduct(vendor, product);
        search.notice(t("s.product_added", { name: `${vendor} ${product}`.trim() }));
        assets.open("products");
      } catch (e) { search.notice(e.message); }
    },
    onWatchAsset: (value) => {
      assets.open("assets");
      const input = document.querySelector("#assets-body .watch-form input");
      if (input) { input.value = value; input.focus(); }
    },
    onOpenAsset: (id) => assets.openAsset(id),
    onOpenProducts: (id) => (id ? assets.openProduct(id) : assets.open("products")),
  });

  initShortcuts({
    onTools: () => tools.toggle(),
    onAssets: () => assets.toggle(),
    onSearch: () => search.focus(),
    onEscape: () => { tools.close(); assets.close(); search.hide(); statusPanel.hidden = true; settingsPanel.hidden = true; },
  });

  // controls
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
  document.getElementById("btn-tools").addEventListener("click", () => tools.toggle());
  document.getElementById("btn-assets").addEventListener("click", () => assets.toggle());
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
      renderAlertFeed(alertData, { onOpen: (a) => (a.asset_id ? assets.openAsset(a.asset_id) : assets.openProduct(a.product_id)), onWindow: () => assets.open("alerts") });
      renderStatusDots(status);
      ai.setRegion(status.region);
      assets.setStatus(status);
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
      document.getElementById("stamp").replaceChildren(el("span", { class: "warn-txt" }, t("stamp.failed", { msg: e.message })));
      if (first) boot.step(t("stamp.failed", { msg: e.message }), "fail");
    }
  }

  map.setC2Filter(state.c2Filter);
  await refresh(true);
  boot.progress(1);
  boot.step(t("boot.ready"), "ok");
  boot.done();
  setInterval(refresh, REFRESH_MS);
}

main().catch((e) => {
  boot.step(String(e?.message || e), "fail");
  boot.done();
});
