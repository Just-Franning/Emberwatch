// World map: labelled basemap (OpenFreeMap) with offline fallback (Natural Earth).
// Cyberlage: country shading, L7 attack flows, C2 servers, ransomware, infrastructure, submarine cables, cloud platform
//   incidents, tool results.
// Weltlage: country pairs and countries named in security reports, submarine cables named in them, internet blocking
//   (OONI, government-directed shutdowns), the selected report; borders and labels in indigo.
import { t } from "./i18n.js";
import { href, objLink, routes } from "./router.js";
import { COLORS, countryName, dateTime, el, geo, kids, num, pct, RAMP, reduceMotion, safeLink } from "./util.js";

const EMPTY = { type: "FeatureCollection", features: [] };
// Weltlage colours (indigo; the land stays dark, only lines and marks change)
export const WELT = { line: "#818cf8", dot: "#a5b4fc", ring: "#6366f1", sel: "#e0e7ff", border: "rgba(99, 102, 241, 0.72)", border2: "rgba(99, 102, 241, 0.85)",
  state: "#1a1c33", label: "#a9b0cc", labelState: "#62677d", outline: "#e0e7ff", cable: "#c7d2fe",
  shutdown: "rgba(251, 113, 133, 0.62)", blocking: "rgba(251, 113, 133, 0.2)" };
// basemap paint values that follow the mode: [layer, property, Weltlage value]
const MODE_PAINT = [
  ["boundary_country_z0-4", "line-color", WELT.border], ["boundary_country_z5-", "line-color", WELT.border2],
  ["boundary_state", "line-color", WELT.state], ["ne-borders", "line-color", WELT.border],
  ["place_country_other", "text-color", WELT.label], ["place_country_minor", "text-color", WELT.label],
  ["place_country_major", "text-color", WELT.label], ["place_state", "text-color", WELT.labelState],
  ["selected", "line-color", WELT.outline],
];
const CYBER_LAYERS = {
  arcs: ["arcs", "heads"], c2: ["c2-cluster", "c2-count", "c2-point"], ransom: ["ransom"], infra: ["infra"],
  cables: ["cables", "cables-hl", "landing"], tool: ["tool-path", "tool-points", "tool-labels"], cloud: ["cloud"],
};
const WELT_LAYERS = {
  pairs: ["welt-pairs"], dots: ["welt-dots", "welt-origins", "welt-count"], cables: ["welt-cables"], block: ["welt-block"],
  sel: ["welt-sel-cable", "welt-sel-line", "welt-sel-pt", "welt-sel-label"],
};
const NONE = ["==", ["get", "iso"], "\u0000"]; // a filter that matches no feature
const PAIR_OPACITY = ["interpolate", ["linear"], ["get", "w"], 0, 0.4, 1, 0.9];
const CHORO_OPACITY = ["case", ["<", ["to-number", ["coalesce", ["feature-state", "v"], -1]], 0], 0, 0.7];
const FONT = ["Noto Sans Regular"];
const PREF_KEY = "emberwatch.basemap";

export const METRICS = Object.fromEntries(
  [["l7_target", pct], ["l3_target", pct], ["l7_origin", pct], ["l3_origin", pct], ["ransomware_7d", num], ["c2", num], ["outages_7d", num]]
    .map(([k, fmt]) => [k, { label: t(`metricl.${k}`), fmt }]),
);

function pref() {
  try { return localStorage.getItem(PREF_KEY) || "online"; } catch { return "online"; }
}
export function setBasemapPref(v) {
  try { localStorage.setItem(PREF_KEY, v); } catch { /* ignore */ }
}
export const basemapPref = pref;

// --- geometry ----------------------------------------------------------------
const rad = (d) => (d * Math.PI) / 180;
const deg = (r) => (r * 180) / Math.PI;
export function greatCircle([lon1, lat1], [lon2, lat2], n = 64) {
  const p1 = [Math.cos(rad(lat1)) * Math.cos(rad(lon1)), Math.cos(rad(lat1)) * Math.sin(rad(lon1)), Math.sin(rad(lat1))];
  const p2 = [Math.cos(rad(lat2)) * Math.cos(rad(lon2)), Math.cos(rad(lat2)) * Math.sin(rad(lon2)), Math.sin(rad(lat2))];
  const dot = Math.min(1, Math.max(-1, p1[0] * p2[0] + p1[1] * p2[1] + p1[2] * p2[2]));
  const omega = Math.acos(dot);
  if (omega < 1e-6) return [[lon1, lat1], [lon2, lat2]];
  const pts = [];
  let prev = null;
  for (let i = 0; i <= n; i++) {
    const t = i / n;
    const a = Math.sin((1 - t) * omega) / Math.sin(omega);
    const b = Math.sin(t * omega) / Math.sin(omega);
    const x = a * p1[0] + b * p2[0], y = a * p1[1] + b * p2[1], z = a * p1[2] + b * p2[2];
    let lon = deg(Math.atan2(y, x));
    const lat = deg(Math.atan2(z, Math.sqrt(x * x + y * y)));
    if (prev !== null) {
      while (lon - prev > 180) lon -= 360;
      while (lon - prev < -180) lon += 360;
    }
    prev = lon;
    pts.push([lon, lat]);
  }
  return pts;
}

// Flat map: curved arc without antimeridian jump
export function bezierArc([lon1, lat1], [lon2, lat2], n = 48) {
  const dx = lon2 - lon1, dy = lat2 - lat1;
  const dist = Math.hypot(dx, dy);
  let nx = -dy / (dist || 1), ny = dx / (dist || 1);
  if (ny < 0) { nx = -nx; ny = -ny; }
  const k = Math.min(0.28 * dist, 28);
  const cx = (lon1 + lon2) / 2 + nx * k, cy = Math.min((lat1 + lat2) / 2 + ny * k, 80);
  const pts = [];
  for (let i = 0; i <= n; i++) {
    const t = i / n, u = 1 - t;
    pts.push([u * u * lon1 + 2 * u * t * cx + t * t * lon2, u * u * lat1 + 2 * u * t * cy + t * t * lat2]);
  }
  return pts;
}

function pointAt(line, t) {
  const f = t * (line.length - 1);
  const i = Math.min(Math.floor(f), line.length - 2);
  const r = f - i;
  return [line[i][0] + (line[i + 1][0] - line[i][0]) * r, line[i][1] + (line[i + 1][1] - line[i][1]) * r];
}

// --- symbols (canvas, no sprite dependency) -----------------------------------
function icon(draw, size = 22) {
  const c = document.createElement("canvas");
  c.width = c.height = size * 2;
  const g = c.getContext("2d");
  g.scale(2, 2);
  draw(g, size);
  return { width: c.width, height: c.height, data: g.getImageData(0, 0, c.width, c.height).data };
}
const ICONS = {
  "ico-outage": (g, s) => { // triangle
    g.beginPath(); g.moveTo(s / 2, 3); g.lineTo(s - 3, s - 4); g.lineTo(3, s - 4); g.closePath();
    g.fillStyle = COLORS.infra; g.fill(); g.lineWidth = 2; g.strokeStyle = "#060607"; g.stroke();
  },
  "ico-bgp": (g, s) => { // diamond
    g.beginPath(); g.moveTo(s / 2, 2); g.lineTo(s - 3, s / 2); g.lineTo(s / 2, s - 2); g.lineTo(3, s / 2); g.closePath();
    g.fillStyle = COLORS.infra; g.fill(); g.lineWidth = 2; g.strokeStyle = "#060607"; g.stroke();
  },
  "ico-anomaly": (g, s) => { // hollow square
    g.lineWidth = 2.5; g.strokeStyle = COLORS.infra; g.strokeRect(5, 5, s - 10, s - 10);
  },
  "ico-cloud": (g, s) => { // cloud: three arcs on a flat base
    g.beginPath();
    g.moveTo(5, s - 6);
    g.arc(7.5, s - 9, 3.5, Math.PI * 0.5, Math.PI * 1.5);
    g.arc(s / 2 - 0.5, s / 2 - 1.5, 5.5, Math.PI * 1.05, Math.PI * 1.9);
    g.arc(s - 7.5, s - 9.5, 4, Math.PI * 1.4, Math.PI * 0.5);
    g.closePath();
    g.fillStyle = COLORS.cloud; g.fill(); g.lineWidth = 1.6; g.strokeStyle = "#060607"; g.stroke();
  },
};

// --- map ----------------------------------------------------------------------
export class Emberwatch {
  constructor(container, { onCountry, onIp }) {
    this.onCountry = onCountry;
    this.onIp = onIp;
    this.mode = "cyber";
    this.vis = { arcs: true, c2: true, ransom: true, infra: true, cables: false, tool: true, cloud: true };
    this.wvis = { pairs: true, dots: true, cables: false, block: false, sel: true };
    this.cloudCount = 0;
    this.weltCables = {};
    this.blocking = {};
    this.welt = { mentioned: {}, origins: {} };
    this.metric = "l7_target";
    this.countries = {};
    this.arcRows = [];
    this.arcs = [];
    this.arcsVisible = true;
    this.c2All = EMPTY;
    this.c2Filter = {};
    this.projection = "mercator";
    this.offline = pref() === "offline";
    this.basemapFailed = false;
    this.tip = document.getElementById("map-tip");
    this.ready = this._init(container);
  }

  async _init(container) {
    let base = null;
    if (!this.offline) {
      try {
        const r = await fetch("data/basemap-style.json");
        if (r.ok) base = await r.json();
      } catch { /* offline */ }
    }
    if (!base) this.offline = true;
    window.maplibregl.setWorkerUrl("vendor/maplibre-gl-csp-worker.js");
    this.map = new window.maplibregl.Map({
      container,
      style: this._style(base),
      bounds: [[-168, -52], [178, 76]],
      fitBoundsOptions: { padding: 20 },
      minZoom: 0.6,
      maxZoom: 12,
      attributionControl: { compact: true },
      renderWorldCopies: false,
      dragRotate: false,
      pitchWithRotate: false,
    });
    this.map.addControl(new window.maplibregl.NavigationControl({ showCompass: false }), "top-right");
    if (!this.offline) this._watchBasemap(); // register before "load": TileJSON/sprite errors arrive early
    await new Promise((res) => this.map.on("load", res));
    for (const [id, draw] of Object.entries(ICONS)) this.map.addImage(id, icon(draw), { pixelRatio: 2 });
    // the Cyberlage values of the mode-dependent paint properties, read from the style
    this.cyberPaint = MODE_PAINT.filter(([id]) => this.map.getLayer(id)).map(([id, prop, w]) => [id, prop, this.map.getPaintProperty(id, prop), w]);
    this._bind();
  }

  _style(base) {
    const withText = !this.offline;
    const sources = {
      countries: { type: "geojson", data: "data/countries.geojson", promoteId: "iso" },
      cables: { type: "geojson", data: "data/cables.geojson" },
      landing: { type: "geojson", data: "data/landing-points.geojson" },
      arcs: { type: "geojson", data: EMPTY },
      heads: { type: "geojson", data: EMPTY },
      ransom: { type: "geojson", data: EMPTY },
      infra: { type: "geojson", data: EMPTY },
      c2: { type: "geojson", data: EMPTY, cluster: true, clusterRadius: 34, clusterMaxZoom: 6 },
      tool: { type: "geojson", data: EMPTY },
      cloud: { type: "geojson", data: EMPTY },
      "welt-pairs": { type: "geojson", data: EMPTY },
      "welt-dots": { type: "geojson", data: EMPTY },
      "welt-sel": { type: "geojson", data: EMPTY },
    };
    const vis = (on) => ({ visibility: on ? "visible" : "none" });
    const under = [ // below the basemap's boundaries and labels
      { id: "ne-land", type: "fill", source: "countries", layout: vis(this.offline), paint: { "fill-color": COLORS.land } },
      {
        id: "choro", type: "fill", source: "countries",
        paint: {
          "fill-color": ["interpolate", ["linear"], ["to-number", ["coalesce", ["feature-state", "v"], 0]],
            0, RAMP[0], 0.25, RAMP[1], 0.5, RAMP[2], 0.75, RAMP[3], 1, RAMP[4]],
          "fill-opacity": CHORO_OPACITY,
        },
      },
      { // Weltlage: blocking and shutdowns (colour per country, set in setWeltBlocking)
        id: "welt-block", type: "fill", source: "countries", filter: NONE, layout: vis(false),
        paint: { "fill-color": WELT.blocking, "fill-opacity": 1 },
      },
      { id: "ne-borders", type: "line", source: "countries", layout: vis(this.offline), paint: { "line-color": "rgba(170, 38, 38, 0.6)", "line-width": 0.6 } },
      {
        id: "cables", type: "line", source: "cables", layout: { ...vis(false), "line-cap": "round" },
        paint: { "line-color": COLORS.cable, "line-opacity": 0.55, "line-width": ["interpolate", ["linear"], ["zoom"], 1, 0.6, 6, 1.4] },
      },
    ];
    const over = [
      { id: "hover", type: "line", source: "countries", paint: { "line-color": "#d4d4d8", "line-width": ["case", ["boolean", ["feature-state", "hover"], false], 1.1, 0] } },
      { id: "selected", type: "line", source: "countries", filter: ["==", ["get", "iso"], ""], paint: { "line-color": "#fee2e2", "line-width": 1.8 } },
      {
        id: "cables-hl", type: "line", source: "cables", filter: ["in", "", ["get", "countries"]], layout: { ...vis(false), "line-cap": "round" },
        paint: { "line-color": "#e5e7eb", "line-opacity": 0.9, "line-width": ["interpolate", ["linear"], ["zoom"], 1, 1.2, 6, 2.4] },
      },
      {
        id: "landing", type: "circle", source: "landing", minzoom: 1.5, layout: vis(false),
        paint: { "circle-radius": ["interpolate", ["linear"], ["zoom"], 1.5, 1.4, 6, 3.5], "circle-color": "#9ca3af", "circle-stroke-color": COLORS.water, "circle-stroke-width": 0.6 },
      },
      {
        id: "arcs", type: "line", source: "arcs", layout: { "line-cap": "round" },
        paint: {
          "line-color": COLORS.attack,
          "line-width": ["interpolate", ["linear"], ["get", "w"], 0, 1, 1, 3.2],
          "line-opacity": ["interpolate", ["linear"], ["get", "w"], 0, 0.35, 1, 0.9],
        },
      },
      {
        id: "ransom", type: "circle", source: "ransom",
        paint: {
          "circle-radius": ["+", 5, ["*", 3.2, ["sqrt", ["get", "n"]]]],
          "circle-color": "rgba(145, 121, 242, 0.12)", "circle-stroke-color": COLORS.ransom, "circle-stroke-width": 2,
        },
      },
      {
        id: "infra", type: "symbol", source: "infra",
        layout: {
          "icon-image": ["match", ["get", "group"], "outage", "ico-outage", "bgp", "ico-bgp", "ico-anomaly"],
          "icon-size": ["interpolate", ["linear"], ["get", "count"], 1, 0.8, 10, 1.25],
          "icon-allow-overlap": true, "icon-ignore-placement": true,
          "icon-offset": ["match", ["get", "group"], "outage", ["literal", [0, -16]], "bgp", ["literal", [16, -6]], ["literal", [-16, -6]]],
          ...(withText ? {
            "text-field": ["case", [">", ["get", "count"], 1], ["to-string", ["get", "count"]], ""],
            "text-font": FONT, "text-size": 10,
            "text-offset": ["match", ["get", "group"], "outage", ["literal", [0, -2.2]], "bgp", ["literal", [2.2, -0.9]], ["literal", [-2.2, -0.9]]],
            "text-allow-overlap": true, "text-ignore-placement": true,
          } : {}),
        },
        paint: withText ? { "text-color": "#fee2e2", "text-halo-color": "#060607", "text-halo-width": 1.2, "icon-opacity": ["case", ["get", "ongoing"], 1, 0.6] }
          : { "icon-opacity": ["case", ["get", "ongoing"], 1, 0.6] },
      },
      {
        id: "cloud", type: "symbol", source: "cloud",
        layout: {
          "icon-image": "ico-cloud", "icon-size": ["interpolate", ["linear"], ["get", "n"], 1, 0.9, 6, 1.3],
          "icon-allow-overlap": true, "icon-ignore-placement": true,
          ...(withText ? {
            "text-field": ["case", [">", ["get", "n"], 1], ["to-string", ["get", "n"]], ""], "text-font": FONT, "text-size": 10,
            "text-offset": [1.4, -0.9], "text-allow-overlap": true, "text-ignore-placement": true,
          } : {}),
        },
        paint: withText ? { "icon-opacity": ["match", ["get", "precision"], "country", 0.6, 1], "text-color": "#dbeafe", "text-halo-color": "#060607", "text-halo-width": 1.2 }
          : { "icon-opacity": ["match", ["get", "precision"], "country", 0.6, 1] },
      },
      {
        id: "c2-cluster", type: "circle", source: "c2", filter: ["has", "point_count"],
        paint: {
          "circle-color": COLORS.c2, "circle-opacity": 0.88,
          "circle-radius": ["step", ["get", "point_count"], 9, 10, 13, 50, 18, 200, 24],
          "circle-stroke-color": COLORS.water, "circle-stroke-width": 2,
        },
      },
      ...(withText ? [{
        id: "c2-count", type: "symbol", source: "c2", filter: ["has", "point_count"],
        layout: { "text-field": ["get", "point_count_abbreviated"], "text-font": FONT, "text-size": 10.5, "text-allow-overlap": true },
        paint: { "text-color": "#041314" },
      }] : []),
      {
        id: "c2-point", type: "circle", source: "c2", filter: ["!", ["has", "point_count"]],
        paint: {
          "circle-color": COLORS.c2, "circle-radius": 4.5,
          "circle-opacity": ["match", ["get", "geo_precision"], "country", 0.45, 0.95],
          "circle-stroke-color": COLORS.water, "circle-stroke-width": 1.5,
        },
      },
      {
        id: "heads", type: "circle", source: "heads",
        paint: {
          "circle-color": COLORS.attackLight, "circle-radius": ["interpolate", ["linear"], ["get", "w"], 0, 2.2, 1, 4.2],
          "circle-stroke-color": COLORS.attack, "circle-stroke-width": 1,
        },
      },
      {
        id: "tool-path", type: "line", source: "tool", filter: ["==", ["get", "kind"], "path"], layout: { "line-cap": "round" },
        paint: {
          "line-color": ["match", ["coalesce", ["get", "sev"], ""], "high", COLORS.high, "medium", COLORS.medium, COLORS.tool],
          "line-width": 1.6, "line-dasharray": [2, 1.5], "line-opacity": 0.9,
        },
      },
      {
        // tool and object results: kind = origin | target | hop | probe | mail | c2 | ransom; sev colours findings
        id: "tool-points", type: "circle", source: "tool", filter: ["!=", ["get", "kind"], "path"],
        paint: {
          "circle-color": ["case",
            ["==", ["get", "kind"], "origin"], "#060607",
            ["==", ["coalesce", ["get", "sev"], ""], "high"], COLORS.high,
            ["==", ["coalesce", ["get", "sev"], ""], "medium"], COLORS.medium,
            ["==", ["get", "kind"], "c2"], COLORS.c2,
            ["==", ["get", "kind"], "ransom"], COLORS.ransom,
            ["==", ["get", "kind"], "mail"], COLORS.attackLight,
            COLORS.tool],
          "circle-radius": ["match", ["get", "kind"], "target", 6.5, "origin", 6, "probe", 5, 4.5],
          "circle-stroke-color": ["match", ["get", "kind"], "origin", COLORS.tool, "#060607"],
          "circle-stroke-width": ["match", ["get", "kind"], "origin", 2, 1.5],
        },
      },
      ...(withText ? [{
        id: "tool-labels", type: "symbol", source: "tool", filter: ["has", "label"],
        layout: { "text-field": ["get", "label"], "text-font": FONT, "text-size": 10.5, "text-offset": [0, -1.3], "text-allow-overlap": false },
        paint: { "text-color": "#ffffff", "text-halo-color": "#060607", "text-halo-width": 1.4 },
      }] : []),
      // Weltlage (hidden in the Cyberlage)
      {
        id: "welt-cables", type: "line", source: "cables", filter: ["in", ["get", "id"], ["literal", []]], layout: { ...vis(false), "line-cap": "round" },
        paint: { "line-color": WELT.cable, "line-opacity": 0.85, "line-width": ["interpolate", ["linear"], ["zoom"], 1, 1.6, 6, 3.2] },
      },
      {
        id: "welt-sel-cable", type: "line", source: "cables", filter: ["in", ["get", "id"], ["literal", []]], layout: { ...vis(false), "line-cap": "round" },
        paint: { "line-color": WELT.sel, "line-opacity": 0.95, "line-width": ["interpolate", ["linear"], ["zoom"], 1, 2.2, 6, 4] },
      },
      {
        id: "welt-pairs", type: "line", source: "welt-pairs", layout: { ...vis(false), "line-cap": "round" },
        paint: {
          "line-color": WELT.line,
          "line-width": ["interpolate", ["linear"], ["get", "w"], 0, 1, 1, 3.6],
          "line-opacity": PAIR_OPACITY,
        },
      },
      {
        id: "welt-origins", type: "circle", source: "welt-dots", filter: [">", ["get", "o"], 0], layout: vis(false),
        paint: {
          "circle-radius": ["+", 7, ["*", 2.6, ["sqrt", ["get", "o"]]]], "circle-color": "rgba(99, 102, 241, 0.08)",
          "circle-stroke-color": WELT.ring, "circle-stroke-width": 1.6,
        },
      },
      {
        id: "welt-dots", type: "circle", source: "welt-dots", filter: [">", ["get", "n"], 0], layout: vis(false),
        paint: {
          "circle-radius": ["+", 3, ["*", 2.2, ["sqrt", ["get", "n"]]]], "circle-color": WELT.dot, "circle-opacity": 0.92,
          "circle-stroke-color": COLORS.water, "circle-stroke-width": 1.5,
        },
      },
      ...(withText ? [{
        id: "welt-count", type: "symbol", source: "welt-dots", filter: [">", ["get", "n"], 2], layout: {
          ...vis(false), "text-field": ["to-string", ["get", "n"]], "text-font": FONT, "text-size": 9.5, "text-allow-overlap": true,
        },
        paint: { "text-color": "#0b0d24" },
      }] : []),
      {
        id: "welt-sel-line", type: "line", source: "welt-sel", filter: ["==", ["geometry-type"], "LineString"], layout: { ...vis(false), "line-cap": "round" },
        paint: { "line-color": WELT.sel, "line-width": 2.4, "line-opacity": 0.95 },
      },
      {
        id: "welt-sel-pt", type: "circle", source: "welt-sel", filter: ["==", ["geometry-type"], "Point"], layout: vis(false),
        paint: {
          "circle-radius": ["match", ["get", "kind"], "origin", 7, 6], "circle-color": ["match", ["get", "kind"], "origin", "#060607", WELT.sel],
          "circle-stroke-color": WELT.sel, "circle-stroke-width": 2,
        },
      },
      ...(withText ? [{
        id: "welt-sel-label", type: "symbol", source: "welt-sel", filter: ["has", "label"],
        layout: { ...vis(false), "text-field": ["get", "label"], "text-font": FONT, "text-size": 11, "text-offset": [0, -1.4], "text-allow-overlap": true },
        paint: { "text-color": "#ffffff", "text-halo-color": "#060607", "text-halo-width": 1.5 },
      }] : []),
    ];
    if (!base) {
      return {
        version: 8,
        sources,
        layers: [{ id: "bg", type: "background", paint: { "background-color": COLORS.water } }, ...under, ...over],
      };
    }
    const layers = [...base.layers];
    const idx = Math.max(0, layers.findIndex((l) => l.id === "boundary_state"));
    layers.splice(idx, 0, ...under);
    return { ...base, sources: { ...base.sources, ...sources }, layers: [...layers, ...over] };
  }

  _watchBasemap() {
    let errors = 0;
    this.map.on("error", (e) => {
      const txt = `${e?.error?.message || ""} ${e?.error?.url || ""}`;
      if (e?.sourceId === "openmaptiles" || /openfreemap/.test(txt)) errors++;
      else console.warn("map:", e?.error?.message || e); // style and expression errors stay visible (this listener mutes MapLibre's own log)
    });
    const check = () => {
      // isSourceLoaded() also reports "loaded" on source errors; what matters is whether tiles have content
      let features = 0;
      try { features = this.map.querySourceFeatures("openmaptiles", { sourceLayer: "water" }).length; } catch { features = 0; }
      if (errors > 0 && features === 0) this._fallback();
    };
    setTimeout(check, 8000);
    setTimeout(check, 20000);
  }

  _fallback() {
    if (this.basemapFailed) return;
    this.basemapFailed = true;
    const m = this.map;
    for (const id of ["ne-land", "ne-borders"]) m.setLayoutProperty(id, "visibility", "visible");
    if (m.getLayer("background")) m.setPaintProperty("background", "background-color", COLORS.water);
    if (m.getLayer("water")) m.setLayoutProperty("water", "visibility", "none");
    this.onFallback?.();
  }

  _tipShow(e, title, sub) {
    kids(this.tip, el("strong", {}, title), ...(sub ? [el("small", {}, sub)] : []));
    this.tip.hidden = false;
    const x = e.originalEvent.clientX, y = e.originalEvent.clientY;
    this.tip.style.left = `${Math.min(x + 14, window.innerWidth - 290)}px`;
    this.tip.style.top = `${y + 14}px`;
  }

  _tipHide() { this.tip.hidden = true; }

  _bind() {
    const m = this.map;
    let hovered = null;
    const pointLayers = ["c2-point", "c2-cluster", "ransom", "infra", "cloud", "tool-points", "landing", "welt-dots", "welt-origins"];
    m.on("mousemove", "choro", (e) => {
      const f = e.features?.[0];
      if (!f) return;
      if (hovered !== null && hovered !== f.id) m.setFeatureState({ source: "countries", id: hovered }, { hover: false });
      hovered = f.id;
      m.setFeatureState({ source: "countries", id: hovered }, { hover: true });
      if (m.queryRenderedFeatures(e.point, { layers: pointLayers.filter((l) => m.getLayer(l)) }).length) return;
      if (this.mode === "welt") {
        this._tipShow(e, countryName(f.id) || f.properties.name, this._weltTip(f.id));
        m.getCanvas().style.cursor = "pointer";
        return;
      }
      const v = this.countries[f.id]?.[this.metric];
      const meta = METRICS[this.metric];
      this._tipShow(e, countryName(f.id) || f.properties.name, meta ? `${meta.label}: ${v === undefined ? t("map.no_data") : meta.fmt(v)}` : null);
      m.getCanvas().style.cursor = "pointer";
    });
    m.on("mouseleave", "choro", () => {
      if (hovered !== null) m.setFeatureState({ source: "countries", id: hovered }, { hover: false });
      hovered = null;
      this._tipHide();
      m.getCanvas().style.cursor = "";
    });
    m.on("click", (e) => {
      const hits = m.queryRenderedFeatures(e.point, { layers: pointLayers.filter((l) => m.getLayer(l)) });
      if (hits.length) return;
      const land = m.queryRenderedFeatures(e.point, { layers: ["choro"] })[0];
      if (land && /^[A-Z]{2}$/.test(String(land.id))) this.onCountry(String(land.id));
    });
    m.on("click", "c2-cluster", async (e) => {
      const f = e.features[0];
      const z = await m.getSource("c2").getClusterExpansionZoom(f.properties.cluster_id);
      m.easeTo({ center: f.geometry.coordinates, zoom: Math.min(z, 10), duration: reduceMotion ? 0 : 500 });
    });
    m.on("click", "c2-point", (e) => this.c2Popup(e.features[0].properties, e.lngLat));
    m.on("click", "ransom", (e) => {
      const p = e.features[0].properties;
      this.popup(e.lngLat, el("div", { class: "pop" }, el("h4", {}, countryName(p.cc)), t("map.ransom_pop", { n: num(p.n) })));
      this.onCountry(p.cc);
    });
    m.on("click", "infra", (e) => {
      const p = e.features[0].properties;
      let evs = [];
      try { evs = JSON.parse(p.events); } catch { /* ignore */ }
      this.popup(e.lngLat, el("div", { class: "pop" },
        el("h4", {}, `${t(`map.group.${p.group}`)}: ${countryName(p.cc)}`),
        el("ul", {}, evs.slice(0, 8).map((x) => el("li", {}, `${x.title}${x.ongoing ? t("map.ongoing") : ""}, ${x.start ? dateTime(x.start) : "?"}`))),
        evs.length > 8 ? el("div", { class: "note" }, t("common.more", { n: evs.length - 8 })) : null,
        el("div", { class: "row" }, el("button", { type: "button", onclick: () => this.onCountry(p.cc) }, t("map.open_country")),
          objLink("country", p.cc, t("country.deep"), "btn"))));
    });
    m.on("click", "landing", (e) => {
      const p = e.features[0].properties;
      let cab = Array.isArray(p.cables) ? p.cables : [];
      if (!cab.length) { try { cab = JSON.parse(p.cables); } catch { /* ignore */ } }
      this.popup(e.lngLat, el("div", { class: "pop" }, el("h4", {}, p.name), el("div", { class: "note" }, t("map.landing")),
        el("ul", {}, cab.slice(0, 12).map((c) => el("li", {}, c))), cab.length > 12 ? el("div", { class: "note" }, t("common.more", { n: cab.length - 12 })) : null));
    });
    m.on("mousemove", "cables", (e) => {
      const p = e.features[0].properties;
      this._tipShow(e, p.name, [p.rfs ? `RFS ${p.rfs}` : null, p.length, p.owners].filter(Boolean).join(", ").slice(0, 160));
    });
    m.on("mouseleave", "cables", () => this._tipHide());
    m.on("click", "cloud", (e) => this.cloudPopup(e.features[0].properties, e.lngLat));
    for (const id of ["welt-cables", "welt-sel-cable"]) {
      m.on("mousemove", id, (e) => {
        const p = e.features[0].properties;
        const n = this.weltCables[p.id] || 0;
        this._tipShow(e, p.name, [n ? t("wl.map.cable_tip", { n: num(n) }) : null, p.rfs ? `RFS ${p.rfs}` : null].filter(Boolean).join(" · "));
      });
      m.on("mouseleave", id, () => this._tipHide());
    }
    for (const id of ["welt-dots", "welt-origins"]) {
      m.on("click", id, (e) => { const cc = e.features[0].properties.cc; if (cc) this.onCountry(cc); });
      m.on("mousemove", id, (e) => this._tipShow(e, countryName(e.features[0].properties.cc), this._weltTip(e.features[0].properties.cc)));
      m.on("mouseleave", id, () => this._tipHide());
    }
    m.on("mousemove", "welt-pairs", (e) => {
      const p = e.features[0].properties;
      this._tipShow(e, `${countryName(p.o)} → ${countryName(p.t)}`, t("wl.map.pair_tip", { n: num(p.n) }));
    });
    m.on("mouseleave", "welt-pairs", () => this._tipHide());
    m.on("click", "tool-points", (e) => {
      const p = e.features[0].properties;
      if (p.ip) this.onIp?.(p.ip);
    });
    for (const id of pointLayers) {
      m.on("mouseenter", id, () => { m.getCanvas().style.cursor = "pointer"; });
      m.on("mouseleave", id, () => { m.getCanvas().style.cursor = ""; });
    }
  }

  popup(lngLat, node) {
    if (this._popup) this._popup.remove();
    this._popup = new window.maplibregl.Popup({ maxWidth: "340px" }).setLngLat(lngLat).setDOMContent(node).addTo(this.map);
    return this._popup;
  }

  c2Popup(p, lngLat) {
    const rows = [
      [t("c2.malware"), p.malware], [t("c2.ioc"), p.ioc], [t("c2.source"), p.source === "feodo" ? "Feodo Tracker" : "ThreatFox"],
      [t("c2.status"), p.status], [t("c2.country"), `${countryName(p.country)}${p.city ? ", " + p.city : ""}`],
      [t("c2.location"), p.geo_precision === "country" ? t("c2.loc_country") : t("c2.loc_city")],
      [t("c2.as"), p.asn ? `AS${p.asn} ${p.as_name || ""}` : "–"], [t("c2.first"), p.first_seen ? dateTime(p.first_seen) : "–"],
      [t("c2.last"), p.last_seen ? dateTime(p.last_seen) : "–"], [t("c2.conf"), p.confidence ? `${p.confidence} %` : "–"],
    ];
    this.popup(lngLat, el("div", { class: "pop" },
      el("h4", {}, `C2: ${p.malware}`),
      el("dl", {}, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v ?? "–")])),
      el("div", { class: "row" },
        p.ip ? objLink("ip", p.ip, t("c2.open_ip"), "btn") : null,
        p.malware ? objLink("malware", p.malware, t("c2.open_family"), "btn") : null,
        p.ip ? el("button", { type: "button", onclick: () => this.onIp?.(p.ip) }, t("c2.ipinfo")) : null,
        p.reference && /^https:\/\/(threatfox|feodotracker)\.abuse\.ch\//.test(p.reference)
          ? el("a", { class: "btn", href: p.reference, target: "_blank", rel: "noopener noreferrer" }, "abuse.ch") : null)));
  }

  cloudPopup(p, lngLat) {
    let items = [];
    try { items = JSON.parse(p.items); } catch { items = []; }
    this.popup(lngLat, el("div", { class: "pop" },
      el("h4", {}, t("map.cloud_h", { provider: p.provider_name }), p.used === true || p.used === "true" ? el("span", { class: "tag warn" }, t("map.cloud_used")) : null),
      el("div", { class: "note" }, `${p.region}${p.precision !== "city" ? ` · ${t(`map.cloud_prec.${p.precision === "country" ? "country" : "region"}`)}` : ""}`),
      el("ul", {}, items.slice(0, 6).map((x) => el("li", {}, safeLink(x.url, x.title) || x.title, el("span", { class: "muted" }, ` · ${t("map.cloud_since", { t: dateTime(x.started) })}`)))),
      items.length > 6 ? el("div", { class: "note" }, t("common.more", { n: items.length - 6 })) : null,
      el("div", { class: "row" }, el("a", { class: "btn", href: href(routes.view("platforms")) }, t("map.cloud_all")))));
  }

  // --- data ---------------------------------------------------------------------
  /** Active cloud platform incidents: one symbol per provider and location, the incidents in the popup. */
  setCloud(incidents) {
    const groups = new Map();
    for (const inc of incidents || []) {
      if (inc.status !== "active") continue;
      for (const r of inc.regions || []) {
        if (!Number.isFinite(r.lat) || !Number.isFinite(r.lon)) continue;
        const key = `${inc.provider}|${r.lat.toFixed(2)}|${r.lon.toFixed(2)}`;
        if (!groups.has(key)) {
          groups.set(key, { provider: inc.provider, provider_name: inc.provider_name || inc.provider, used: Boolean(inc.used), lat: r.lat, lon: r.lon,
            precision: r.precision || "city", region: r.code && r.name !== r.code ? `${r.name} (${r.code})` : r.name || r.code || "", items: [] });
        }
        const g = groups.get(key);
        if (!g.items.some((x) => x.id === inc.id)) g.items.push({ id: inc.id, title: inc.title, url: inc.url, started: inc.started });
      }
    }
    const feats = [...groups.values()].map((g) => ({
      type: "Feature", geometry: { type: "Point", coordinates: [g.lon, g.lat] },
      properties: { provider: g.provider, provider_name: g.provider_name, used: g.used, region: g.region, precision: g.precision, n: g.items.length, items: JSON.stringify(g.items) },
    }));
    this.cloudCount = feats.length;
    this.map.getSource("cloud").setData({ type: "FeatureCollection", features: feats });
  }

  setCountries(countries) {
    this.countries = countries || {};
    this.paintChoropleth();
    const feats = [];
    for (const [cc, mm] of Object.entries(this.countries)) {
      const c = geo.centroids[cc];
      if (c && mm.ransomware_7d) feats.push({ type: "Feature", geometry: { type: "Point", coordinates: [c.lon, c.lat] }, properties: { cc, n: mm.ransomware_7d } });
    }
    this.map.getSource("ransom").setData({ type: "FeatureCollection", features: feats });
  }

  setMetric(metric) {
    this.metric = metric;
    this.paintChoropleth();
  }

  paintChoropleth() {
    const m = this.map;
    m.removeFeatureState({ source: "countries" });
    this.max = 0;
    if (this.metric === "none") return;
    const vals = Object.entries(this.countries).map(([cc, x]) => [cc, x[this.metric]]).filter(([, v]) => typeof v === "number" && v > 0);
    this.max = vals.reduce((a, [, v]) => Math.max(a, v), 0);
    for (const [cc, v] of vals) m.setFeatureState({ source: "countries", id: cc }, { v: this.max ? v / this.max : 0 });
  }

  legendInfo() { return { metric: this.metric, meta: METRICS[this.metric], max: this.max || 0, cloud: this.vis.cloud && this.cloudCount > 0 }; }

  setC2(fc) {
    this.c2All = fc || EMPTY;
    this._applyC2();
  }

  setC2Filter(f) {
    this.c2Filter = { ...this.c2Filter, ...f };
    this._applyC2();
  }

  _applyC2() {
    const f = this.c2Filter;
    const now = Date.now();
    const feats = this.c2All.features.filter((x) => {
      const p = x.properties;
      if (f.family && p.malware !== f.family) return false;
      if (f.source && f.source !== "all" && p.source !== f.source) return false;
      if (f.minConf && p.confidence !== null && p.confidence !== undefined && p.confidence < f.minConf) return false;
      const seen = Date.parse(p.last_seen || p.first_seen || "") || 0;
      if (f.window) { // timeline: [start, end)
        const first = Date.parse(p.first_seen || "") || 0;
        if (first && first >= f.window[1]) return false;
        if (seen && seen < f.window[0]) return false;
      } else if (f.days && seen && now - seen > f.days * 86400000) {
        return false;
      }
      return true;
    });
    this.c2Count = feats.length;
    this.map.getSource("c2").setData({ type: "FeatureCollection", features: feats });
  }

  setArcs(rows) {
    this.arcRows = rows || [];
    const valid = this.arcRows.filter((r) => geo.centroids[r.origin] && geo.centroids[r.target] && r.origin !== r.target);
    const maxV = valid.reduce((a, r) => Math.max(a, r.value), 0) || 1;
    this.arcs = valid.map((r, i) => {
      const o = geo.centroids[r.origin], t = geo.centroids[r.target];
      const path = this.projection === "globe" ? greatCircle : bezierArc;
      return { line: path([o.lon, o.lat], [t.lon, t.lat]), w: r.value / maxV, offset: (i * 0.137) % 1 };
    });
    this.map.getSource("arcs").setData({
      type: "FeatureCollection",
      features: this.arcs.map((a) => ({ type: "Feature", geometry: { type: "LineString", coordinates: a.line }, properties: { w: a.w } })),
    });
    this.animate();
  }

  animate() {
    if (this._raf) cancelAnimationFrame(this._raf);
    const src = this.map.getSource("heads");
    let last = -1e9;
    const frame = (ts) => {
      if (this.paused) return;
      if (!this.arcsVisible || this.mode !== "cyber") { src.setData(EMPTY); return; }
      if (ts - last >= 33 || reduceMotion) { // about 30 fps
        last = ts;
        const phase = (ts / 4200) % 1;
        const visible = this._hemisphere();
        src.setData({
          type: "FeatureCollection",
          features: this.arcs.map((a) => ({
            type: "Feature",
            geometry: { type: "Point", coordinates: pointAt(a.line, reduceMotion ? 1 : (phase + a.offset) % 1) },
            properties: { w: a.w },
          })).filter((f) => visible(f.geometry.coordinates)),
        });
      }
      if (!reduceMotion) this._raf = requestAnimationFrame(frame);
    };
    this._raf = requestAnimationFrame(frame);
  }

  // Globe: hide points on the far side (circles would otherwise be drawn over the rim)
  _hemisphere() {
    if (this.projection !== "globe") return () => true;
    const c = this.map.getCenter();
    const cv = [Math.cos(rad(c.lat)) * Math.cos(rad(c.lng)), Math.cos(rad(c.lat)) * Math.sin(rad(c.lng)), Math.sin(rad(c.lat))];
    return ([lon, lat]) => {
      const v = [Math.cos(rad(lat)) * Math.cos(rad(lon)), Math.cos(rad(lat)) * Math.sin(rad(lon)), Math.sin(rad(lat))];
      return cv[0] * v[0] + cv[1] * v[1] + cv[2] * v[2] > 0.25; // the camera sees less than a hemisphere
    };
  }

  setInfra(events) {
    const groups = new Map();
    for (const e of events || []) {
      const group = e.kind === "outage" ? "outage" : (e.kind === "hijack" || e.kind === "leak") ? "bgp" : "anomaly";
      for (const cc of e.countries || []) {
        if (!geo.centroids[cc]) continue;
        const key = `${cc}|${group}`;
        if (!groups.has(key)) groups.set(key, { cc, group, events: [], ongoing: false });
        const g = groups.get(key);
        g.events.push({ title: e.title, start: e.start_ts, ongoing: e.ongoing });
        g.ongoing = g.ongoing || e.ongoing;
      }
    }
    const feats = [...groups.values()].map((g) => {
      const c = geo.centroids[g.cc];
      return {
        type: "Feature", geometry: { type: "Point", coordinates: [c.lon, c.lat] },
        properties: { cc: g.cc, group: g.group, count: g.events.length, ongoing: g.ongoing, events: JSON.stringify(g.events) },
      };
    });
    this.map.getSource("infra").setData({ type: "FeatureCollection", features: feats });
  }

  _layers(ids, on) {
    for (const id of ids) if (this.map.getLayer(id)) this.map.setLayoutProperty(id, "visibility", on ? "visible" : "none");
  }

  /** Layer switch of the Cyberlage (arcs, c2, ransom, infra, cables). Applies when the Cyberlage is shown. */
  setVisible(layer, on) {
    this.vis[layer] = on;
    if (this.mode === "cyber") this._layers(CYBER_LAYERS[layer], on);
    if (layer === "arcs") { this.arcsVisible = on; this.animate(); }
  }

  /** Layer switch of the Weltlage (pairs, dots). */
  setWeltVisible(layer, on) {
    this.wvis[layer] = on;
    if (this.mode === "welt") this._layers(WELT_LAYERS[layer], on);
  }

  /** Cyberlage (red) or Weltlage (indigo): swaps the data layers and recolours borders and country labels. */
  setMode(mode) {
    if (mode === this.mode) return;
    this.mode = mode;
    const welt = mode === "welt";
    const m = this.map;
    for (const [id, prop, cyber, w] of this.cyberPaint) m.setPaintProperty(id, prop, welt ? w : cyber);
    m.setPaintProperty("choro", "fill-opacity", welt ? 0 : CHORO_OPACITY); // stays for hover and clicks
    for (const [k, ids] of Object.entries(CYBER_LAYERS)) this._layers(ids, !welt && this.vis[k]);
    for (const [k, ids] of Object.entries(WELT_LAYERS)) this._layers(ids, welt && this.wvis[k]);
    if (this._popup) this._popup.remove();
    this._tipHide();
    this.animate();
  }

  _weltTip(cc) {
    const n = this.welt.mentioned[cc] || 0, o = this.welt.origins[cc] || 0;
    const parts = [n ? t("wl.map.named", { n: num(n) }) : null, o ? t("wl.map.origin_n", { n: num(o) }) : null];
    const b = this.wvis.block ? this.blocking.info?.[cc] : null;
    if (b) {
      if (b.shutdown) parts.push(t("wl.map.blk_shut"));
      if (b.confirmed) parts.push(t("wl.map.blk_conf", { n: num(b.confirmed), d: num(this.blocking.days || 7) }));
      else if (b.anomaly_pct !== null && b.anomaly_pct !== undefined) parts.push(t("wl.map.blk_anom", { p: pct(b.anomaly_pct) }));
    }
    return parts.filter(Boolean).join(" · ") || t("wl.map.none");
  }

  /** Submarine cables named in the reports of the selection: {cable id: number of reports}. */
  setWeltCables(counts) {
    this.weltCables = counts || {};
    this.map.setFilter("welt-cables", ["in", ["get", "id"], ["literal", Object.keys(this.weltCables).slice(0, 300)]]);
  }

  /** Internet blocking per country: shutdowns ordered by a government and confirmed blocking (OONI). */
  setWeltBlocking({ shutdown = [], confirmed = [], info = {}, days = 7 } = {}) {
    this.blocking = { info, days };
    const shut = [...new Set(shutdown)].filter((c) => /^[A-Z]{2}$/.test(c));
    const conf = [...new Set(confirmed)].filter((c) => /^[A-Z]{2}$/.test(c) && !shut.includes(c));
    if (!shut.length && !conf.length) {
      this.map.setFilter("welt-block", NONE);
      return;
    }
    const color = ["match", ["get", "iso"]]; // match labels are plain arrays of literals (no "literal" wrapper)
    if (shut.length) color.push(shut, WELT.shutdown);
    if (conf.length) color.push(conf, WELT.blocking);
    color.push("rgba(0, 0, 0, 0)");
    this.map.setPaintProperty("welt-block", "fill-color", color);
    this.map.setFilter("welt-block", ["in", ["get", "iso"], ["literal", [...shut, ...conf]]]);
  }

  /** Weltlage data: pairs [{origin, target, n}], mentioned {cc: n}, origins {cc: n}. */
  setWelt({ pairs = [], mentioned = {}, origins = {} }) {
    this.welt = { mentioned, origins };
    const valid = pairs.filter((r) => geo.centroids[r.origin] && geo.centroids[r.target] && r.origin !== r.target);
    const maxN = valid.reduce((a, r) => Math.max(a, r.n), 0) || 1;
    const path = this.projection === "globe" ? greatCircle : bezierArc;
    this.map.getSource("welt-pairs").setData({
      type: "FeatureCollection",
      features: valid.map((r) => {
        const o = geo.centroids[r.origin], tg = geo.centroids[r.target];
        return { type: "Feature", geometry: { type: "LineString", coordinates: path([o.lon, o.lat], [tg.lon, tg.lat]) },
          properties: { o: r.origin, t: r.target, n: r.n, w: r.n / maxN } };
      }),
    });
    const ccs = new Set([...Object.keys(mentioned), ...Object.keys(origins)]);
    const feats = [];
    for (const cc of ccs) {
      const c = geo.centroids[cc];
      if (c) feats.push({ type: "Feature", geometry: { type: "Point", coordinates: [c.lon, c.lat] }, properties: { cc, n: mentioned[cc] || 0, o: origins[cc] || 0 } });
    }
    this.map.getSource("welt-dots").setData({ type: "FeatureCollection", features: feats });
    this._weltPairs = pairs;
  }

  /** One report on the map: origin (ring, label) to the named countries. Returns the number of countries shown. */
  showWeltItem(it, { fit = true } = {}) {
    const feats = [];
    const pts = [];
    const o = it?.origin && geo.centroids[it.origin];
    const path = this.projection === "globe" ? greatCircle : bezierArc;
    if (o) {
      feats.push({ type: "Feature", geometry: { type: "Point", coordinates: [o.lon, o.lat] }, properties: { kind: "origin", label: t("wl.map.attributed", { cc: it.origin }) } });
      pts.push([o.lon, o.lat]);
    }
    for (const cc of (it?.countries || []).slice(0, 6)) {
      const c = geo.centroids[cc];
      if (!c || cc === it.origin) continue;
      feats.push({ type: "Feature", geometry: { type: "Point", coordinates: [c.lon, c.lat] }, properties: { kind: "target", label: t("wl.map.target", { name: countryName(cc) }) } });
      if (o) feats.push({ type: "Feature", geometry: { type: "LineString", coordinates: path([o.lon, o.lat], [c.lon, c.lat]) }, properties: {} });
      pts.push([c.lon, c.lat]);
    }
    this.map.getSource("welt-sel").setData({ type: "FeatureCollection", features: feats });
    const cables = (it?.cables || []).filter((x) => typeof x === "string").slice(0, 8);
    this.map.setFilter("welt-sel-cable", ["in", ["get", "id"], ["literal", cables]]);
    this.map.setPaintProperty("welt-pairs", "line-opacity", 0.18); // the selected report stands out
    if (fit && pts.length > 1) this.fitTo(pts, 4);
    else if (fit && pts.length === 1) this.flyTo(pts[0][0], pts[0][1], 3);
    return pts.length;
  }

  clearWeltItem() {
    this.map.getSource("welt-sel")?.setData(EMPTY);
    if (this.map.getLayer("welt-sel-cable")) this.map.setFilter("welt-sel-cable", ["in", ["get", "id"], ["literal", []]]);
    this.map.setPaintProperty("welt-pairs", "line-opacity", PAIR_OPACITY);
  }

  select(cc) {
    this.map.setFilter("selected", ["==", ["get", "iso"], cc || ""]);
    this.map.setFilter("cables-hl", ["in", cc || "", ["get", "countries"]]);
  }

  focus(cc) {
    const c = geo.centroids[cc];
    if (c) this.map.easeTo({ center: [c.lon, c.lat], zoom: Math.max(this.map.getZoom(), 2.4), padding: this.viewPadding(), duration: reduceMotion ? 0 : 900 });
  }

  // Visible map area without docked panels (for centring and fitBounds)
  viewPadding() {
    const small = window.innerWidth <= 900;
    const tools = document.getElementById("panel-tools");
    const toolsH = tools && !tools.hidden && !tools.classList.contains("floating") ? tools.getBoundingClientRect().height + 10 : 0;
    const top = document.getElementById("modebar")?.getBoundingClientRect().bottom || 100;
    // the right edge: the open report (Weltlage) or the docked side panel
    const drawer = document.getElementById("news-drawer");
    const side = document.getElementById("side");
    const panel = drawer && !drawer.hidden ? drawer : side && !side.classList.contains("collapsed") && !side.classList.contains("floating") ? side : null;
    const shown = (n) => Boolean(n) && n.getClientRects().length > 0; // fixed elements have no offsetParent
    const visible = shown(panel);
    const dock = document.getElementById("kpidock");
    const dockH = shown(dock) ? dock.getBoundingClientRect().height : 0;
    return {
      top: Math.round(top + 10),
      bottom: Math.max(40, toolsH + 40, small ? 40 : dockH + 24),
      left: 20,
      right: small || !visible ? 20 : Math.round(window.innerWidth - panel.getBoundingClientRect().left + 20),
    };
  }

  flyTo(lon, lat, zoom = 4) {
    this.map.easeTo({ center: [lon, lat], zoom: Math.max(this.map.getZoom(), zoom), padding: this.viewPadding(), duration: reduceMotion ? 0 : 900 });
  }

  fitTo(points, maxZoom = 5) {
    if (!points.length) return;
    const lons = points.map((x) => x[0]), lats = points.map((x) => x[1]);
    try {
      this.map.fitBounds([[Math.min(...lons), Math.min(...lats)], [Math.max(...lons), Math.max(...lats)]],
        { padding: this.viewPadding(), maxZoom, duration: reduceMotion ? 0 : 900 });
    } catch { /* panels larger than the map: ignore */ }
  }

  toggleProjection() {
    this.projection = this.projection === "globe" ? "mercator" : "globe";
    this.map.setProjection({ type: this.projection });
    const opts = { duration: reduceMotion ? 0 : 700 };
    if (this.projection === "globe") this.map.easeTo({ center: [15, 28], zoom: 1.8, ...opts });
    else this.map.fitBounds([[-168, -52], [178, 76]], { padding: 20, ...opts });
    this.setArcs(this.arcRows);
    if (this._weltPairs) this.setWelt({ pairs: this._weltPairs, ...this.welt });
    this.onProjection?.();
    return this.projection;
  }

  // --- tool results -----------------------------------------------------------------
  setTool(features) {
    this.map.getSource("tool").setData({ type: "FeatureCollection", features: features || [] });
  }

  /** Draws the map part of a tool or object result: {points: [{lon, lat, kind, label, ip, sev}], paths: [{coords, sev}]}. */
  showResult(m, { fit = true } = {}) {
    const points = (m?.points || []).filter((p) => Number.isFinite(p.lon) && Number.isFinite(p.lat));
    const feats = [];
    for (const p of m?.paths || []) {
      for (const f of this.toolPath(p.coords || [])) {
        if (p.sev) f.properties.sev = p.sev;
        feats.push(f);
      }
    }
    for (const p of points) {
      const props = { kind: p.kind || "target" };
      for (const k of ["label", "ip", "sev"]) if (p[k] !== undefined && p[k] !== null) props[k] = p[k];
      feats.push({ type: "Feature", geometry: { type: "Point", coordinates: [p.lon, p.lat] }, properties: props });
    }
    this.setTool(feats);
    const coords = points.map((p) => [p.lon, p.lat]);
    if (fit && coords.length > 1) this.fitTo(coords, 6);
    else if (fit && coords.length === 1) this.flyTo(coords[0][0], coords[0][1], 4);
    return points.length;
  }

  /** Stops the arc animation while the map is covered by a page (analysis, my network). */
  pause(on) {
    this.paused = on;
    if (on) {
      if (this._raf) cancelAnimationFrame(this._raf);
      this._raf = null;
    } else {
      this.animate();
      this.map.resize();
    }
  }

  clearTool() { this.setTool([]); }

  toolPath(points) {
    const feats = [];
    for (let i = 1; i < points.length; i++) {
      const a = points[i - 1], b = points[i];
      if (Math.abs(a[0] - b[0]) < 1e-6 && Math.abs(a[1] - b[1]) < 1e-6) continue;
      const line = this.projection === "globe" ? greatCircle(a, b, 24) : bezierArc(a, b, 24);
      feats.push({ type: "Feature", geometry: { type: "LineString", coordinates: line }, properties: { kind: "path" } });
    }
    return feats;
  }
}
