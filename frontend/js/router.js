// Hash router for the areas:
//   #/lage[?owner=<ip>]                    Cyberlage (world map with attack data; owner: "who owns this IP" for the address)
//   #/welt[?country=…&actor=…&kind=…]       Weltlage (security news on the world map)
//   #/welt/n/<id>                          one report in its context
//   #/personen[/<case id>]                 people search (black and white globe), administrators only
//   #/konto[/users|/audit]                 own account; users and audit log for administrators
//   #/analyse                              start page of the analysis area
//   #/analyse/obj/<type>/<value>           object page (IP, network, AS, domain, URL, hash, CVE, country, …)
//   #/analyse/tools[?q=…&tool=…&run=1]     tool box
//   #/analyse/view/<kev|infra|c2|ransom>   deep views
//   #/analyse/history, #/analyse/run/<id>  tool history and one stored result
//   #/netz[/assets[/<id>]|/products[/<id>]|/alerts|/logs|/myip]   my network
// Object values are URI-encoded, so values with "/" (networks, URLs) survive.
import { el } from "./util.js";

export const AREAS = ["lage", "welt", "personen", "analyse", "netz", "konto"];
export const MAP_AREAS = ["lage", "welt", "personen"]; // areas that show the world map
export const OBJ_TYPES = ["ip", "cidr", "asn", "domain", "url", "hash", "cve", "country", "malware", "group", "vendor", "actor"];
const listeners = new Set();
let internal = false; // set by go(): only in-app navigation may start tool runs from the URL (run=1, recipe=…)

export function parse(hash = window.location.hash) {
  const raw = hash.replace(/^#\/?/, "");
  const q = raw.indexOf("?");
  const path = q >= 0 ? raw.slice(0, q) : raw;
  const query = new URLSearchParams(q >= 0 ? raw.slice(q + 1) : "");
  const parts = path.split("/").filter(Boolean).map((p) => {
    try { return decodeURIComponent(p); } catch { return p; }
  });
  const area = AREAS.includes(parts[0]) ? parts[0] : "lage";
  return { area, parts: AREAS.includes(parts[0]) ? parts.slice(1) : [], query };
}

export function onRoute(fn) { listeners.add(fn); }

function dispatch() {
  const r = parse();
  r.internal = internal;
  internal = false;
  for (const fn of listeners) fn(r);
}

/** Navigates to "area/part/…" (without "#/"). The same route again re-renders the view. */
export function go(path) {
  const h = `#/${path}`;
  internal = true;
  if (window.location.hash === h) dispatch();
  else window.location.hash = h;
}

export function start() {
  window.addEventListener("hashchange", dispatch);
  dispatch();
}

const enc = encodeURIComponent;
export const routes = {
  obj: (type, value) => `analyse/obj/${enc(type)}/${enc(value)}`,
  tools: (q, tool, run, recipe) => {
    const p = new URLSearchParams();
    if (q) p.set("q", q);
    if (tool) p.set("tool", tool);
    if (run) p.set("run", "1");
    if (recipe) p.set("recipe", recipe);
    const s = p.toString();
    return `analyse/tools${s ? `?${s}` : ""}`;
  },
  view: (name) => `analyse/view/${enc(name)}`,
  run: (id) => `analyse/run/${enc(id)}`,
  news: (id) => `welt/n/${enc(id)}`,
  welt: (params = {}) => {
    const p = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== null && v !== undefined && v !== ""));
    const s = p.toString();
    return `welt${s ? `?${s}` : ""}`;
  },
  asset: (id) => `netz/assets/${enc(id)}`,
  product: (id) => `netz/products/${enc(id)}`,
  owner: (ip) => `lage?owner=${enc(ip)}`,
  personen: (caseId) => (caseId ? `personen/${enc(caseId)}` : "personen"),
  konto: (view) => (view ? `konto/${enc(view)}` : "konto"),
};

export const href = (path) => `#/${path}`;

/** Link to an object page. Real anchors: middle click and "open in new tab" work. */
export function objLink(type, value, label = null, cls = "obj") {
  if (!OBJ_TYPES.includes(type) || value === null || value === undefined || value === "") return document.createTextNode(label ?? String(value ?? "–"));
  return el("a", { class: cls, href: href(routes.obj(type, String(value))) }, label ?? String(value));
}

// Recently opened and pinned objects (per browser)
const RECENT_KEY = "emberwatch.recent";
const PIN_KEY = "emberwatch.pinned";

function load(key) {
  try { const v = JSON.parse(localStorage.getItem(key) || "[]"); return Array.isArray(v) ? v : []; } catch { return []; }
}
function store(key, v) {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* ignore */ }
}

export function remember(o) {
  const list = load(RECENT_KEY).filter((x) => !(x.type === o.type && x.value === o.value));
  list.unshift({ type: o.type, value: o.value, title: o.title || o.value, sev: o.sev || null });
  store(RECENT_KEY, list.slice(0, 15));
}
export const recent = () => load(RECENT_KEY);
export const pinned = () => load(PIN_KEY);
export const isPinned = (type, value) => load(PIN_KEY).some((x) => x.type === type && x.value === value);
export function togglePin(o) {
  const list = load(PIN_KEY);
  const i = list.findIndex((x) => x.type === o.type && x.value === o.value);
  if (i >= 0) list.splice(i, 1);
  else list.unshift({ type: o.type, value: o.value, title: o.title || o.value });
  store(PIN_KEY, list.slice(0, 30));
  return i < 0;
}
