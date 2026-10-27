// Emberwatch web interface. Six areas, switched by the hash router (router.js):
//   CYBERLAGE  world map with attack data: layers, key figures, side panel (today, rankings, patterns, Gemini, company
//              behind an IP address), map tools
//   WELTLAGE   the same map in indigo with security reports, actors, country pairs and the Telegram window (welt.js,
//              telegram.js)
//   PERSONEN   the map in black and white: people search with cases and the link graph (personen.js, administrators)
//   ANALYSE    object pages, tool box, deep views, run history (analyse.js)
//   MEIN NETZ  overview, own IPs, assets, products, alerts, logs (netz.js, assets.js)
//   KONTO      own account; users and audit log for administrators (konto.js, opened from the user menu)
// The selected country and the period carry over between Cyberlage and Weltlage. The role of the account (session.js)
// decides what is offered; the server checks it on every request.
import { AIPanel } from "./ai.js";
import { Analyse } from "./analyse.js";
import { hideCountry, renderCountry } from "./country.js";
import { applyStatic, t } from "./i18n.js";
import { Konto, renderUserMenu } from "./konto.js";
import { initPanels, initShortcuts, renderSettings, renderStatusDots, renderStatusPanel, setCollapsed } from "./layout.js";
import { Emberwatch } from "./map.js";
import { MapTools } from "./maptools.js";
import { Netz } from "./netz.js";
import { Owner } from "./owner.js";
import { Palette } from "./palette.js";
import { renderKpis, renderLegend, renderPatterns, renderTab, renderToday } from "./panels.js";
import { Personen } from "./personen.js";
import { AREAS, go, MAP_AREAS, onRoute, routes, start as startRouter } from "./router.js";
import { Search } from "./search.js";
import { accounts, isAdmin, loadSession, me } from "./session.js";
import { TelegramWindow } from "./telegram.js";
import { Timeline } from "./timeline.js";
import { api, dateTime, el, kids, loadCentroids, num } from "./util.js";
import { Welt } from "./welt.js";
import { initWindows } from "./windows.js";

const REFRESH_MS = 5 * 60 * 1000;
const TOOLBAR_KEY = "emberwatch.maptools";
const MODE = { lage: "cyber", welt: "welt", personen: "osint" }; // colour mode of the map per map area
const boot = window.EmberBoot || { step() {}, progress() {}, done() {} };
const state = {
  ov: null, victims: [], status: null, alerts: null, today: null, tab: "targets", side: "today", country: null, historical: null, area: "lage",
  mapArea: "lage", // the map view shown last (Cyberlage, Weltlage or Personen)
  c2Filter: { days: 30, source: "all", minConf: 0, family: null }, families: [], stamp: "–",
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
const stored = (key, dflt) => { try { return localStorage.getItem(key) ?? dflt; } catch { return dflt; } };
const store = (key, v) => { try { localStorage.setItem(key, v); } catch { /* ignore */ } };

async function main() {
  applyStatic();
  boot.step(t("boot.init"), "ok");
  boot.progress(0.05);
  await loadSession(); // the role decides what is offered; without a session api() sends to the login page
  boot.step(accounts() ? t("boot.user", { name: me.name || "–", role: t(`acct.role.${me.role}`) }) : t("boot.proxy"), "ok");
  boot.progress(0.1);
  await waitForLibs();
  await loadCentroids();
  initPanels();
  initWindows(["side", "panel-tools", "panel-graph", "panel-tg"]);
  // header and mode band heights vary with width and language: panels and pages start below them
  const header = document.querySelector(".hud-top");
  const band = document.getElementById("modebar");
  const footer = document.querySelector(".hud-bottom");
  const setSizes = () => {
    const root = document.documentElement.style;
    root.setProperty("--top-h", `${Math.ceil(header.getBoundingClientRect().height)}px`);
    root.setProperty("--band-h", `${Math.ceil(band.getBoundingClientRect().height)}px`);
    root.setProperty("--bottom-h", `${Math.ceil(footer.getBoundingClientRect().height)}px`);
  };
  const ro = new ResizeObserver(setSizes);
  for (const n of [header, band, footer]) ro.observe(n);
  setSizes();

  boot.step(t("boot.map"), "run");
  const map = new Emberwatch(document.getElementById("map"), {
    onCountry: (cc) => (state.area === "welt" ? welt.pickCountry(cc) : state.area === "personen" ? personen.pickCountry(cc) : selectCountry(cc)),
    onIp: (ip) => mapTool("ipinfo", ip),
  });
  await map.ready;
  boot.progress(0.45);
  const maptools = new MapTools({ map });
  maptools.init();
  const ai = new AIPanel({ onShow: () => setSide("ai") });
  const statusPanel = document.getElementById("status-panel");
  const settingsPanel = document.getElementById("settings-panel");
  const userPanel = document.getElementById("user-panel");
  const userBtn = document.getElementById("btn-user");
  const popovers = [statusPanel, settingsPanel, userPanel];

  // --- map tool bar (Cyberlage, on demand) ------------------------------------------------------------------------
  const toolbar = document.getElementById("maptools");
  const toolbarBtn = document.getElementById("btn-maptools");
  function showToolbar(on, persist = true) {
    toolbar.hidden = !on;
    toolbarBtn.setAttribute("aria-pressed", String(on));
    if (persist) store(TOOLBAR_KEY, on ? "1" : "0");
  }
  showToolbar(isAdmin() && stored(TOOLBAR_KEY, "0") === "1", false); // the tools run on the server: administrators only
  toolbarBtn.addEventListener("click", () => {
    showToolbar(toolbar.hidden);
    if (!toolbar.hidden) maptools.focus();
  });

  /** Shows a tool/object result on the map: switches to the Cyberlage first and names what is shown. */
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

  /** Runs a map tool (Cyberlage) with a target; readers get the object page instead. */
  function mapTool(tool, target) {
    if (!isAdmin()) { go(routes.obj("ip", target)); return; }
    if (state.area !== "lage") go("lage");
    showToolbar(true);
    maptools.open(tool, target, true);
  }

  /** Tool from the palette or a link: map tools stay on the map, everything else runs in the tool box. */
  function runTool(toolId, target) {
    const tool = (maptools.reg || {}).byId?.[toolId];
    if (tool?.bar && state.area === "lage" && isAdmin()) { showToolbar(true); maptools.open(toolId, target, true); } else go(routes.tools(target, toolId, true));
  }

  const analyse = new Analyse({ nav: document.getElementById("an-nav"), main: document.getElementById("an-main"), onMap: showOnMap });
  const netz = new Netz({ nav: document.getElementById("nz-nav"), main: document.getElementById("nz-main"), onMap: showOnMap, onChange: () => refresh() });
  const konto = new Konto({ nav: document.getElementById("ko-nav"), main: document.getElementById("ko-main") });
  const palette = new Palette({ onTool: runTool });
  const welt = new Welt({
    map,
    onCyber: () => go("lage"), // the country comes along as context (enterCyber)
    onMap: () => { if (state.area !== "welt") go("welt"); },
  });
  const telegram = new TelegramWindow({ map, onMap: () => { if (state.area !== "welt") go("welt"); } });
  const personen = new Personen({ map });
  const owner = new Owner({ box: document.getElementById("tp-owner"), onMap: (m, label) => showOnMap(m, label),
    onClear: () => { map.clearTool(); note.hidden = true; } });

  // --- side panel (Cyberlage) ---------------------------------------------------------------------------------------
  const sidePanels = { today: "tp-today", rank: "tp-rank", patterns: "tp-patterns", ai: "tp-ai", owner: "tp-owner" };
  function setSide(tab) {
    state.side = tab;
    setCollapsed("side", false);
    document.querySelectorAll("#tabs-cyber button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.side === tab)));
    for (const [k, id] of Object.entries(sidePanels)) document.getElementById(id).hidden = k !== tab;
    if (tab === "rank") drawTab();
  }
  document.querySelectorAll("#tabs-cyber button").forEach((b) => b.addEventListener("click", () => setSide(b.dataset.side)));

  function selectCountry(cc) {
    if (!cc || !/^[A-Z]{2}$/.test(cc)) return;
    state.country = cc;
    welt.setCountry(cc);
    setCollapsed("side", false);
    map.select(cc);
    map.focus(cc);
    ai.setCountry(cc);
    renderCountry(cc, {
      onClose: () => closeCountry(),
      onAnalyze: (c) => ai.run({ scope: "country", country: c }),
    });
  }
  function closeCountry() {
    state.country = null;
    welt.setCountry(null);
    map.select(null);
    ai.setCountry(null);
    hideCountry();
  }

  // --- areas --------------------------------------------------------------------------------------------------------
  const pages = { analyse: document.getElementById("area-analyse"), netz: document.getElementById("area-netz"), konto: document.getElementById("area-konto") };
  const leaving = { analyse: () => analyse.leave(), netz: () => netz.leave(), konto: () => konto.leave(),
    welt: () => { welt.leave(); telegram.leave(); }, personen: () => personen.leave() };
  function setArea(area) {
    if (state.area === area) return;
    leaving[state.area]?.();
    state.area = area;
    for (const a of AREAS) document.body.classList.toggle(`area-${a}`, a === area);
    for (const [a, node] of Object.entries(pages)) node.hidden = a !== area;
    document.querySelectorAll("#areas a").forEach((x) => (x.dataset.area === area ? x.setAttribute("aria-current", "page") : x.removeAttribute("aria-current")));
    const onMap = MAP_AREAS.includes(area);
    map.pause(!onMap);
    if (onMap) {
      const mode = MODE[area];
      for (const m of Object.values(MODE)) document.body.classList.toggle(`mode-${m}`, m === mode);
      map.setMode(mode);
      band.scrollLeft = 0; // small screens: the band scrolls; start at its beginning in each mode
      if (mode === "cyber") enterCyber(state.mapArea); // also after a detour: Weltlage → Analyse → Cyberlage
      state.mapArea = area;
    }
    for (const p of popovers) p.hidden = true;
    userBtn.setAttribute("aria-expanded", "false");
  }

  /** Back in the Cyberlage: take over the country of the Weltlage, the period for the C2 filter; draw its legend again. */
  function enterCyber(prevMap) {
    if (prevMap === "lage") return;
    if (prevMap === "welt") {
      const ctx = welt.context();
      if (ctx.days) setC2({ days: Math.min(30, ctx.days) });
      state.c2DaysUser = false; // carried over from the Weltlage: only a new choice here goes back
      if (ctx.country && ctx.country !== state.country) selectCountry(ctx.country);
      else if (!ctx.country && state.country) closeCountry();
      else if (state.country) map.select(state.country);
    } else if (state.country) map.select(state.country);
    if (state.ov && !state.historical) applyLive();
    else legend(); // the legend of the other mode must not stay (historical day: applyLive is skipped)
  }

  onRoute((r) => {
    if (r.area === "personen" && !isAdmin()) { go("lage"); return; } // readers: no personal data
    setArea(r.area);
    if (r.area === "analyse") analyse.show(r);
    else if (r.area === "netz") netz.show(r);
    else if (r.area === "konto") konto.show(r);
    else if (r.area === "personen") personen.show(r);
    else if (r.area === "welt") welt.show(r, { country: state.country, days: state.c2DaysUser ? state.c2Filter.days : null });
    else if (r.area === "lage") {
      const ip = (r.query.get("owner") || "").trim().slice(0, 60);
      if (ip) {
        setSide("owner");
        owner.open(ip, { run: r.internal }); // a link from outside shows only what is stored; a lookup needs a click
      }
    }
  });
  document.querySelectorAll("#areas a").forEach((x) => (x.dataset.area === "lage" ? x.setAttribute("aria-current", "page") : null));

  const onCve = (cve) => go(routes.obj("cve", cve));

  function setC2(partial) {
    state.c2Filter = { ...state.c2Filter, ...partial };
    map.setC2Filter(state.c2Filter);
    if (state.tab === "c2" && state.side === "rank") drawTab();
  }
  /** C2 filter changed in the rankings; a period chosen there carries over to the Weltlage. */
  function onC2Filter(partial) {
    if (partial.days && partial.days !== state.c2Filter.days) state.c2DaysUser = true;
    setC2(partial);
  }

  function drawTab() {
    if (!state.ov) return;
    renderTab(state.tab, {
      ov: state.ov, victims: state.victims, onCountry: selectCountry, onCve, onObject: (type, value) => go(routes.obj(type, value)),
      c2Filter: state.c2Filter, onC2Filter, families: state.families, c2Count: map.c2Count,
    });
  }
  document.querySelectorAll("#rank-tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#rank-tabs button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    state.tab = b.dataset.tab;
    drawTab();
  }));
  function openRank(tab) {
    state.tab = tab;
    document.querySelectorAll("#rank-tabs button").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.tab === tab)));
    setSide("rank");
  }

  function legend() {
    renderLegend(map.legendInfo(), { historicalDay: state.historical ? Timeline.dayLabel(state.historical) : null, stamp: t("stamp.as_of", { t: state.stamp }) });
  }

  function applyLive() {
    const ov = state.ov;
    map.setCountries(ov.countries);
    map.setArcs(ov.radar.l7_pairs_1d?.rows || []);
    map.setInfra(ov.infra?.events || []);
    if (state.area === "lage") legend();
  }

  // --- timeline (on demand) -----------------------------------------------------------------------------------------
  const timeline = new Timeline({
    onDay: (data) => {
      state.historical = data.day;
      map.setCountries(data.countries);
      map.setArcs(data.pairs);
      map.setInfra(infraForDay(state.ov?.infra?.events || [], data.day));
      map.setC2Filter({ window: [Date.parse(data.c2_window[0]), Date.parse(data.c2_window[1])] });
      legend();
    },
    onLive: () => {
      state.historical = null;
      map.setC2Filter({ window: null });
      if (state.ov) applyLive();
    },
  });
  const tlBox = document.getElementById("timeline");
  const tlBtn = document.getElementById("btn-timeline");
  tlBtn.addEventListener("click", () => {
    const on = tlBox.hidden;
    tlBox.hidden = !on;
    tlBtn.setAttribute("aria-pressed", String(on));
    document.body.classList.toggle("tl-on", on);
    if (!on && state.historical) timeline.setLive(); // hiding the timeline returns to the live view
  });

  const search = new Search({
    onCountry: (cc) => (state.area === "lage" ? selectCountry(cc) : state.area === "welt" ? welt.pickCountry(cc)
      : state.area === "personen" ? personen.pickCountry(cc) : go(routes.obj("country", cc))),
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
    onOwner: (ip) => go(routes.owner(ip)),
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

  const closePopovers = () => {
    for (const p of popovers) p.hidden = true;
    userBtn.setAttribute("aria-expanded", "false");
  };
  initShortcuts({
    areas: isAdmin() ? ["lage", "welt", "personen", "analyse", "netz"] : ["lage", "welt", "analyse", "netz"],
    onPalette: () => palette.toggle(),
    onArea: (a) => go(a),
    onTools: () => {
      if (state.area === "lage" && isAdmin()) { showToolbar(true); maptools.focus(); } else go(routes.tools());
    },
    onSearch: () => search.focus(),
    onEscape: () => {
      maptools.close(); search.hide(); palette.close(); closePopovers();
      if (state.area === "personen") personen.escape();
      if (state.area === "welt" && !document.getElementById("news-drawer").hidden) go(routes.welt());
    },
    isMap: () => MAP_AREAS.includes(state.area),
  });

  // --- controls -----------------------------------------------------------------------------------------------------
  for (const [id, layer] of [["lyr-arcs", "arcs"], ["lyr-c2", "c2"], ["lyr-ransom", "ransom"], ["lyr-infra", "infra"], ["lyr-cables", "cables"], ["lyr-cloud", "cloud"]]) {
    const cb = document.getElementById(id);
    map.setVisible(layer, cb.checked);
    cb.addEventListener("change", () => {
      map.setVisible(layer, cb.checked);
      if (layer === "cloud" && state.area === "lage") legend();
    });
  }
  const metric = document.getElementById("choro-metric");
  metric.addEventListener("change", () => {
    map.setMetric(metric.value);
    legend();
  });
  // one projection switch per mode band; all show the projection the next click leads to
  const projBtns = [...document.querySelectorAll(".proj-btn")];
  const syncProjection = () => { for (const b of projBtns) b.textContent = t(map.projection === "globe" ? "btn.flat" : "btn.globe"); };
  for (const b of projBtns) b.addEventListener("click", () => { map.toggleProjection(); syncProjection(); });
  syncProjection();
  document.getElementById("btn-palette").addEventListener("click", () => palette.open());
  document.getElementById("btn-alerts").addEventListener("click", () => go("netz/alerts"));

  // user menu: own account, users and audit log (administrators), sign out; behind a proxy without sign-in
  const shownName = accounts() ? me.name || "–" : t("acct.proxy_name");
  userBtn.hidden = false;
  document.getElementById("user-mark").textContent = shownName.slice(0, 1).toUpperCase();
  document.getElementById("user-name").textContent = shownName;
  document.getElementById("user-role").textContent = t(`acct.role.${me.role}`);
  userBtn.title = t("acct.menu_title", { name: shownName, role: t(`acct.role.${me.role}`) });
  const logout = async () => {
    try { await api("api/auth/logout", { method: "POST" }); } catch { /* the session ends on the server side anyway */ }
    window.location.assign("login");
  };
  userPanel.addEventListener("click", (e) => { if (e.target.closest("a")) closePopovers(); });

  const popover = (btn, panel, render) => {
    document.getElementById(btn).addEventListener("click", (e) => {
      e.stopPropagation();
      for (const p of popovers) if (p !== panel) p.hidden = true;
      panel.hidden = !panel.hidden;
      userBtn.setAttribute("aria-expanded", String(panel === userPanel && !panel.hidden));
      if (!panel.hidden) render();
    });
  };
  const statusOpts = () => ({ basemapFailed: map.basemapFailed, stampText: state.stamp });
  popover("btn-status", statusPanel, () => state.status && renderStatusPanel(state.status, statusOpts()));
  popover("btn-settings", settingsPanel, () => renderSettings(state.status, { map }));
  popover("btn-user", userPanel, () => renderUserMenu(userPanel, { onLogout: logout }));
  document.addEventListener("click", (e) => {
    for (const p of popovers) if (!p.hidden && !p.contains(e.target)) p.hidden = true;
    if (userPanel.hidden) userBtn.setAttribute("aria-expanded", "false");
  });
  map.onFallback = () => { if (!statusPanel.hidden && state.status) renderStatusPanel(state.status, { ...statusOpts(), basemapFailed: true }); };

  function renderAlertBadge(stats) {
    const badge = document.getElementById("alert-badge");
    const high = stats?.high_7d || 0;
    const medium = stats?.medium_7d || 0;
    const btn = document.getElementById("btn-alerts");
    btn.classList.toggle("hot", high > 0);
    kids(badge, t("btn.alerts"), high || medium ? el("b", {}, num(high + medium)) : null);
    btn.title = t("btn.alerts_title_n", { high: num(high), medium: num(medium), low: num(stats?.low_7d || 0) });
  }

  function onToday(x) {
    const r = x.ref || {};
    if (x.kind === "alert") go(alertRoute(r));
    else if (x.kind === "news" && r.news) go(routes.news(r.news));
    else if (x.kind === "pattern") {
      if (r.country) selectCountry(r.country);
      else setSide("patterns");
    }
  }

  function onKpi(key) {
    if (key === "attack") {
      const home = state.status?.region?.codes?.[0];
      if (home) selectCountry(home); else openRank("targets");
    } else openRank({ c2: "c2", ransom: "ransom", kev: "kev" }[key] || "targets");
  }

  async function refresh(first = false) {
    try {
      if (first) boot.step(t("boot.feeds"), "run");
      const [ov, c2, victims, status, alertData, today, cloud] = await Promise.all([
        api("api/overview"), api("api/c2?days=30"), api("api/victims?days=7&limit=200"), api("api/status"),
        api("api/alerts?limit=1&min_severity=low"), api("api/today?limit=5").catch(() => ({ items: [] })),
        api("api/platforms?active=true").catch(() => ({ incidents: [] })),
      ]);
      state.ov = ov;
      state.victims = victims;
      state.status = status;
      state.alerts = alertData;
      state.today = today;
      state.stamp = dateTime(ov.generated_at);
      state.families = [...new Set(c2.features.map((f) => f.properties.malware).filter(Boolean))].sort((a, b) => a.localeCompare(b));
      map.setC2(c2);
      map.setCloud(cloud.incidents);
      if (!state.historical) applyLive();
      if (state.area === "lage") renderKpis(ov, status, { onTile: onKpi }); // the other map areas draw their own figures
      if (state.side === "rank") drawTab();
      renderPatterns(ov.patterns, selectCountry);
      renderToday(today, { onItem: onToday });
      renderAlertBadge(alertData.stats);
      renderStatusDots(status);
      document.getElementById("btn-status").title = `${t("btn.status_title")} · ${t("stamp.as_of", { t: state.stamp })}`;
      ai.setRegion(status.region);
      analyse.setStatus(status);
      netz.setStatus(status);
      welt.setStatus(status);
      konto.setStatus(status);
      telegram.setStatus(status);
      if (!statusPanel.hidden) renderStatusPanel(status, statusOpts());
      if (first) {
        const src = status.sources || [];
        boot.progress(0.8);
        boot.step(t("boot.sources", { ok: src.filter((s) => s.ok).length, n: src.length }), src.some((s) => !s.ok) ? "warn" : "ok");
        boot.step(`${t("boot.c2", { n: num(ov.c2.total) })} · ${t("boot.patterns", { n: num(ov.patterns.length) })} · ${t("boot.alerts", { n: num(ov.watch?.hits_7d || 0) })}`, "ok");
      } else if (state.area === "welt") {
        welt.load();
        telegram.refresh();
      }
      await timeline.load();
    } catch (e) {
      kids(document.getElementById("maphint"), el("span", { class: "warn-txt" }, t("stamp.failed", { msg: e.message })));
      if (first) boot.step(t("stamp.failed", { msg: e.message }), "fail");
    }
  }

  // back in the Cyberlage: its figures replace those of the other map areas
  onRoute((r) => { if (r.area === "lage" && state.ov) renderKpis(state.ov, state.status, { onTile: onKpi }); });

  map.setC2Filter(state.c2Filter);
  await refresh(true);
  // the address this interface is opened from (via the reverse proxy): sighting for "my IP" (a change: administrators)
  if (isAdmin()) api("api/myip/visit", { method: "POST" }).catch(() => {});
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
