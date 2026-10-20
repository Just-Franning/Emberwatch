// Floating windows: drag by the title bar, resize at the bottom right corner, bring to front on click,
// geometry and opacity stored per browser. Double-click on the title bar docks a window again.
// On small screens (<= 900 px) windows stay docked.
import { t } from "./i18n.js";

const KEY = "emberwatch.windows";
const OPACITY_KEY = "emberwatch.opacity";
const MIN_W = 260;
const MIN_H = 140;
const small = () => window.matchMedia("(max-width: 900px)").matches;

function load() {
  try { return JSON.parse(localStorage.getItem(KEY) || "{}"); } catch { return {}; }
}
function store(s) {
  try { localStorage.setItem(KEY, JSON.stringify(s)); } catch { /* ignore */ }
}

let z = 30;
const listeners = new Set();
export function onLayout(fn) { listeners.add(fn); }
function changed() { for (const fn of listeners) fn(); }

function clamp(win, g) {
  const vw = window.innerWidth, vh = window.innerHeight;
  const w = Math.min(Math.max(MIN_W, g.w), vw - 8);
  const h = g.h ? Math.min(Math.max(MIN_H, g.h), vh - 8) : null;
  const x = Math.min(Math.max(4 - w + 80, g.x), vw - 80); // at least 80 px stay visible
  const y = Math.min(Math.max(4, g.y), vh - 36); // the title bar stays reachable
  return { x, y, w, h };
}

function apply(win, g) {
  win.classList.add("floating");
  win.style.left = `${g.x}px`;
  win.style.top = `${g.y}px`;
  win.style.width = `${g.w}px`;
  win.style.height = g.h ? `${g.h}px` : "";
  document.body.classList.toggle(`${win.id}-floating`, true);
}

export function dock(win, persist = true) {
  win.classList.remove("floating");
  for (const p of ["left", "top", "width", "height"]) win.style[p] = "";
  document.body.classList.remove(`${win.id}-floating`);
  if (persist) {
    const s = load();
    delete s[win.id];
    store(s);
  }
  changed();
}

function save(win) {
  const r = win.getBoundingClientRect();
  const s = load();
  const h = win.classList.contains("collapsed") ? (s[win.id]?.h ?? null) : (win.style.height ? Math.round(r.height) : null);
  s[win.id] = { x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h };
  store(s);
}

export function front(win) {
  if (win.style.zIndex === String(z)) return;
  if (z >= 4000) { // keep windows below the header (6000) and popovers: renumber in current order
    const wins = [...document.querySelectorAll(".panel")].filter((w) => w.style.zIndex).sort((a, b) => Number(a.style.zIndex) - Number(b.style.zIndex));
    z = 30;
    for (const w of wins) w.style.zIndex = String(++z);
  }
  win.style.zIndex = String(++z);
}

export function initWindow(win) {
  const head = win.querySelector(".panel-head");
  head.title = t("panel.move_hint");
  const grip = document.createElement("div");
  grip.className = "grip";
  grip.setAttribute("aria-hidden", "true");
  grip.title = t("panel.resize");
  win.append(grip);
  const saved = load()[win.id];
  if (saved && !small()) apply(win, clamp(win, saved));

  win.addEventListener("pointerdown", () => front(win), true);
  head.addEventListener("dblclick", (e) => {
    if (e.target.closest("button, select, input, a")) return;
    dock(win);
  });

  head.addEventListener("pointerdown", (e) => {
    if (e.button !== 0 || small() || e.target.closest("button, select, input, a, textarea")) return;
    e.preventDefault();
    window.getSelection()?.removeAllRanges();
    document.body.classList.add("dragging");
    const r = win.getBoundingClientRect();
    // keep the current size; a collapsed window keeps its previously stored height
    const h = win.classList.contains("collapsed") ? (load()[win.id]?.h ?? null) : r.height;
    const start = { px: e.clientX, py: e.clientY, x: r.left, y: r.top, w: r.width, h };
    let moved = false;
    head.setPointerCapture(e.pointerId);
    const move = (ev) => {
      const dx = ev.clientX - start.px, dy = ev.clientY - start.py;
      if (!moved && Math.abs(dx) + Math.abs(dy) < 4) return;
      moved = true;
      apply(win, clamp(win, { x: start.x + dx, y: start.y + dy, w: start.w, h: start.h }));
    };
    const up = () => {
      document.body.classList.remove("dragging");
      head.removeEventListener("pointermove", move);
      head.removeEventListener("pointerup", up);
      head.removeEventListener("pointercancel", up);
      if (moved) { save(win); changed(); }
    };
    head.addEventListener("pointermove", move);
    head.addEventListener("pointerup", up);
    head.addEventListener("pointercancel", up);
  });

  grip.addEventListener("pointerdown", (e) => {
    if (e.button !== 0 || small()) return;
    e.preventDefault();
    e.stopPropagation();
    window.getSelection()?.removeAllRanges();
    document.body.classList.add("dragging");
    const r = win.getBoundingClientRect();
    const start = { px: e.clientX, py: e.clientY, x: r.left, y: r.top, w: r.width, h: r.height };
    grip.setPointerCapture(e.pointerId);
    const move = (ev) => {
      apply(win, clamp(win, { x: start.x, y: start.y, w: start.w + ev.clientX - start.px, h: start.h + ev.clientY - start.py }));
    };
    const up = () => {
      document.body.classList.remove("dragging");
      grip.removeEventListener("pointermove", move);
      grip.removeEventListener("pointerup", up);
      grip.removeEventListener("pointercancel", up);
      save(win);
      changed();
    };
    grip.addEventListener("pointermove", move);
    grip.addEventListener("pointerup", up);
    grip.addEventListener("pointercancel", up);
  });
}

export function initWindows(ids) {
  const wins = ids.map((id) => document.getElementById(id)).filter(Boolean);
  wins.forEach(initWindow);
  let timer = null;
  window.addEventListener("resize", () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      for (const w of wins) {
        if (small()) { if (w.classList.contains("floating")) dock(w, false); continue; }
        const g = load()[w.id];
        if (g) apply(w, clamp(w, g));
      }
      changed();
    }, 150);
  });
  setOpacity(getOpacity());
}

export function resetLayout() {
  store({});
  for (const w of document.querySelectorAll(".panel.floating, .legend.floating")) dock(w, false);
  changed();
}

export function getOpacity() {
  let v = 0.9;
  try { v = Number(localStorage.getItem(OPACITY_KEY) || "0.9"); } catch { /* ignore */ }
  return Number.isFinite(v) ? Math.min(1, Math.max(0.35, v)) : 0.9;
}

export function setOpacity(v) {
  const val = Math.min(1, Math.max(0.35, Number(v) || 0.9));
  document.documentElement.style.setProperty("--panel-alpha", String(val));
  document.documentElement.style.setProperty("--panel-blur", val < 0.97 ? "4px" : "0px");
  try { localStorage.setItem(OPACITY_KEY, String(val)); } catch { /* ignore */ }
}

export const isFloating = (id) => document.getElementById(id)?.classList.contains("floating");
