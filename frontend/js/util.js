// Helpers. Dynamic content is always set via textContent, never via innerHTML.
import { lang, locale, t } from "./i18n.js";

export function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k === "style") e.style.cssText = v;
    else if (k === "dataset") Object.assign(e.dataset, v);
    else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

const nf = new Intl.NumberFormat(locale);
const nf1 = new Intl.NumberFormat(locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 });
const nf2 = new Intl.NumberFormat(locale, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const PCT_SEP = lang === "de" ? " " : "";

export const num = (v) => (v === null || v === undefined ? "–" : nf.format(v));
export const pct = (v) => (v === null || v === undefined ? "–" : `${nf1.format(v)}${PCT_SEP}%`);
export const pp = (v) => `${v > 0 ? "+" : v < 0 ? "−" : "±"}${nf1.format(Math.abs(v))} pp`;
export const dec1 = (v) => (v === null || v === undefined ? "–" : nf1.format(v));
export const dec2 = (v) => (v === null || v === undefined ? "–" : nf2.format(v));

const rtf = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
export function ago(iso) {
  if (!iso) return "–";
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return "–";
  const s = Math.max(0, (Date.now() - ts) / 1000);
  if (s < 90) return rtf.format(0, "second");
  if (s < 3600) return rtf.format(-Math.round(s / 60), "minute");
  if (s < 86400 * 2) return rtf.format(-Math.round(s / 3600), "hour");
  return rtf.format(-Math.round(s / 86400), "day");
}

export function dateTime(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "–";
  return d.toLocaleString(locale, { dateStyle: "short", timeStyle: "short" });
}

export function dateOnly(iso) {
  if (!iso) return "–";
  const d = new Date(iso.length === 10 ? `${iso}T12:00:00Z` : iso);
  if (Number.isNaN(d.getTime())) return "–";
  return d.toLocaleDateString(locale, { dateStyle: "short" });
}

export function bytes(n) {
  if (n < 1024) return `${num(n)} B`;
  if (n < 1024 * 1024) return `${dec1(n / 1024)} KB`;
  return `${dec1(n / 1024 / 1024)} MB`;
}

/** fetch wrapper: JSON in/out, server error text as Error message, 401 -> login page */
export async function api(path, opts = {}) {
  const init = { ...opts, headers: { Accept: "application/json", ...(opts.headers || {}) } };
  if (opts.json !== undefined) {
    init.method = init.method || "POST";
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.json);
    delete init.json;
  }
  const r = await fetch(path, init);
  if (r.status === 401) {
    let key = "";
    try { key = (await r.clone().json()).key || ""; } catch { /* ignore */ }
    if (key === "err.auth_required") {
      window.location.assign("login");
      throw new Error(t("login.title"));
    }
  }
  if (!r.ok) {
    let msg = "";
    try {
      const j = await r.json();
      msg = typeof j.detail === "string" ? j.detail : "";
    } catch { /* ignore */ }
    const err = new Error(msg || `HTTP ${r.status}`);
    err.status = r.status;
    throw err;
  }
  return r.json();
}

export const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Country names (German and English) and centroids from Natural Earth
export const geo = { centroids: {} };
export async function loadCentroids() {
  geo.centroids = await api("data/centroids.json");
}
export const countryName = (cc) => {
  const c = cc && geo.centroids[cc];
  if (!c) return cc || t("common.unknown");
  return (lang === "en" ? c.name_en : c.name) || c.name || cc;
};

// Data colours (see styles.css; amber/cyan/violet validated against #0a0a0a)
export const COLORS = {
  attack: "#c98500",
  attackLight: "#e9b04a",
  c2: "#13a2a6",
  ransom: "#9179f2",
  infra: "#e5e7eb",
  cable: "#6b7280",
  tool: "#ffffff",
  accent: "#f87171",
  rule: "rgba(220, 38, 38, 0.16)",
  text: "#d4d4d8",
  text2: "#9ca3af",
  text3: "#6b7280",
  bg: "#0a0a0a",
  land: "#101012",
  water: "#060607",
};
// Categorical order for charts (max. 3 series, validated)
export const SERIES = ["#13a2a6", "#c98500", "#9179f2"];
// Sequential ramp for the choropleth (one red hue, dark to light)
export const RAMP = ["#2b0d0d", "#5c1616", "#8f1f1f", "#c63333", "#f07070"];

export function download(name, text, type = "text/plain;charset=utf-8") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export const isoDay = (d) => d.toISOString().slice(0, 10);

/** Only https links from the server are rendered as links. */
export function safeLink(url, label) {
  return url && /^https:\/\/[^\s"'<>]+$/.test(url) ? el("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, label) : null;
}

export function sevTag(sev) {
  return el("span", { class: `sev ${sev}` }, t(`sev.${sev}`));
}
