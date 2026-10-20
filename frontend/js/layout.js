// Collapsible panels (click, shortcuts, stored), status popover and settings popover.
import { LANGS, lang, setLang, t } from "./i18n.js";
import { basemapPref, setBasemapPref } from "./map.js";
import { ago, api, el, num } from "./util.js";
import { getOpacity, resetLayout, setOpacity } from "./windows.js";

const KEY = "emberwatch.panels";
const BOOT_KEY = "emberwatch.boot";

function saved() {
  try { return JSON.parse(localStorage.getItem(KEY) || "{}"); } catch { return {}; }
}
function save(state) {
  try { localStorage.setItem(KEY, JSON.stringify(state)); } catch { /* ignore */ }
}

export function initPanels() {
  const state = saved();
  const small = window.matchMedia("(max-width: 900px)").matches;
  for (const btn of document.querySelectorAll("button[data-collapse]")) {
    const id = btn.dataset.collapse;
    setCollapsed(id, state[id] ?? small, false);
    btn.addEventListener("click", () => toggle(id));
  }
}

export function setCollapsed(id, collapsed, persist = true) {
  const panel = document.getElementById(id);
  const btn = panel.querySelector("button[data-collapse]");
  panel.classList.toggle("collapsed", collapsed);
  btn.setAttribute("aria-expanded", String(!collapsed));
  btn.querySelector("[aria-hidden]").textContent = collapsed ? "+" : "–";
  const key = id === "panel-left" ? "[" : "]";
  btn.title = `${t(collapsed ? "panel.expand" : "panel.collapse")} ( ${key} )`;
  btn.querySelector(".sr-only").textContent = t(collapsed ? "panel.expand" : "panel.collapse");
  document.body.classList.toggle(id === "panel-left" ? "left-collapsed" : "right-collapsed", collapsed);
  if (persist) {
    const s = saved();
    s[id] = collapsed;
    save(s);
  }
}

export function toggle(id) {
  setCollapsed(id, !document.getElementById(id).classList.contains("collapsed"));
}

export function initShortcuts({ onTools, onAssets, onSearch, onEscape }) {
  document.addEventListener("keydown", (e) => {
    const tgt = e.target;
    if (tgt instanceof HTMLInputElement || tgt instanceof HTMLTextAreaElement || tgt instanceof HTMLSelectElement || tgt.isContentEditable) {
      if (e.key === "Escape") tgt.blur();
      return;
    }
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "[") { toggle("panel-left"); e.preventDefault(); }
    else if (e.key === "]") { toggle("panel-right"); e.preventDefault(); }
    else if (e.key === "t" || e.key === "T") { onTools(); e.preventDefault(); }
    else if (e.key === "a" || e.key === "A") { onAssets(); e.preventDefault(); }
    else if (e.key === "/") { onSearch(); e.preventDefault(); }
    else if (e.key === "Escape") onEscape();
  });
}

// --- status -------------------------------------------------------------------------------
const SRC = {
  cloudflare_radar: "Cloudflare Radar", radar_infra: null, feodo: "Feodo Tracker", threatfox: "ThreatFox", threatfox_iocs: null,
  ransomware_live: "Ransomware.live", cisa_kev: "CISA KEV", epss: "FIRST EPSS", spamhaus_drop: null, tor_exits: null,
  internetdb: null, nvd: null, certspotter: null, typosquatting: null, ris_live: null,
};
const CORE = ["cloudflare_radar", "radar_infra", "feodo", "threatfox", "ransomware_live", "cisa_kev", "epss"];
const srcName = (k) => SRC[k] || t(`src_name.${k}`);

export function renderStatusDots(status) {
  const dots = document.getElementById("status-dots");
  const by = Object.fromEntries((status.sources || []).map((s) => [s.source, s]));
  dots.replaceChildren(...CORE.map((k) => el("i", { class: !by[k] ? "" : by[k].ok ? "ok" : "fail", title: srcName(k) })));
}

export function renderStatusPanel(status, { basemapFailed }) {
  const panel = document.getElementById("status-panel");
  const by = Object.fromEntries((status.sources || []).map((s) => [s.source, s]));
  const keys = [...CORE, ...Object.keys(SRC).filter((k) => !CORE.includes(k) && by[k])];
  const rows = keys.map((k) => {
    const s = by[k];
    const txt = !s ? t("st.not_fetched") : s.ok ? t("st.ok", { n: num(s.count ?? 0), ago: ago(s.last_ok) }) : t("st.failed", { msg: s.message || t("common.unknown") });
    const dot = el("i", { class: `dot ${!s ? "" : s.ok ? "ok" : "fail"}` });
    return el("tr", {}, el("td", {}, dot, srcName(k)),
      el("td", { class: s && !s.ok ? "warn-txt" : null, title: s?.ok && s.message ? s.message : null }, txt));
  });
  const k = status.keys || {};
  const yes = (v) => t(v ? "common.set" : "common.missing");
  const opt = (v) => t(v ? "common.set" : "st.optional");
  const notifyMsg = el("span", { class: "note" });
  const testBtn = el("button", { type: "button", disabled: !status.matrix?.enabled, onclick: async () => {
    notifyMsg.textContent = t("st.matrix_sending");
    try { await api("api/notify/test", { method: "POST" }); notifyMsg.textContent = t("st.matrix_sent"); } catch (e) { notifyMsg.textContent = e.message; }
  } }, t("st.matrix_test"));
  const row = (a, b) => el("tr", {}, el("td", {}, a), el("td", {}, b));
  const sl = status.syslog || {};
  const bgp = status.bgp || {};
  panel.replaceChildren(
    el("h3", {}, t("st.sources")), el("table", {}, el("tbody", {}, rows)),
    el("h3", {}, t("st.config")),
    el("table", {}, el("tbody", {},
      row(t("st.version"), status.version || "–"),
      row(t("st.auth"), status.auth?.mode === "password" ? t("st.auth_password") : t("st.auth_none")),
      row(t("st.cf"), yes(k.cloudflare)), row(t("st.abusech"), yes(k.abusech)),
      row(t("st.rl"), k.ransomware_live ? t("common.set") : t("st.rl_missing")),
      row(t("st.abuseipdb"), opt(k.abuseipdb)), row(t("st.nvd"), opt(k.nvd)), row(t("st.certspotter"), opt(k.certspotter)),
      row(t("st.gemini"), status.ai?.enabled ? status.ai.model : t("common.off")),
      row(t("st.matrix"), status.matrix?.enabled ? t("st.matrix_on", { sev: t(`sev.${status.matrix.min_severity}`) }) : t("common.off")),
      row(t("st.daily"), status.daily_report?.time ? t("st.daily_on", { time: status.daily_report.time, tz: status.daily_report.timezone, last: status.daily_report.last || "–" }) : t("common.off")),
      row(t("st.tools"), status.tools?.enabled ? t(status.tools.allow_private ? "st.tools_private" : "st.tools_public") : t("common.off")),
      row(t("st.scan"), status.scan?.enabled ? t("st.scan_on", { h: status.scan.interval_h, ports: status.scan.ports }) : t("common.off")),
      row(t("st.syslog"), sl.enabled ? t("st.syslog_on", { port: sl.port }) : t("common.off")),
      row(t("st.bgp"), bgp.enabled ? t("st.bgp_on", { state: t(bgp.connected ? "as.d.connected" : "as.d.disconnected"), n: num(bgp.watches) }) : t("common.off")),
      row(t("st.geo"), status.geo?.available ? `DB-IP ${status.geo.city_db}${status.geo.asn_db ? ", ASN " + status.geo.asn_db : ""}` : t("common.missing")),
      row(t("st.history"), t("st.history_txt", { n: num(status.history?.radar_days_final || 0), target: num(status.history?.backfill_target || 0),
        rw: t(status.history?.ransomware_backfill ? "st.done" : "st.pending") })),
      row(t("st.cables"), status.cables?.snapshot ? `TeleGeography ${status.cables.snapshot}` : t("common.missing")))),
    el("div", { class: "row" }, testBtn, notifyMsg),
    el("h3", {}, t("st.map")),
    el("p", { class: "note" }, basemapFailed ? t("st.map_failed") : basemapPref() === "offline" ? t("st.map_offline") : t("st.map_online")),
    el("div", { class: "row" }, el("button", { type: "button", onclick: () => { setBasemapPref(basemapPref() === "offline" ? "online" : "offline"); window.location.reload(); } },
      t(basemapPref() === "offline" ? "st.map_use_online" : "st.map_use_offline"))),
  );
}

// --- settings -----------------------------------------------------------------------------
export function bootEnabled() {
  try { return localStorage.getItem(BOOT_KEY) !== "off"; } catch { return true; }
}

export function renderSettings(status) {
  const panel = document.getElementById("settings-panel");
  const langSel = el("select", { "aria-label": t("set.language") },
    ...LANGS.map((l) => el("option", { value: l, selected: l === lang }, l === "de" ? "Deutsch" : "English")));
  langSel.addEventListener("change", () => setLang(langSel.value));
  const op = el("input", { type: "range", min: 35, max: 100, step: 5, value: Math.round(getOpacity() * 100), "aria-label": t("set.opacity") });
  const opVal = el("span", { class: "note" }, `${op.value} %`);
  op.addEventListener("input", () => { setOpacity(Number(op.value) / 100); opVal.textContent = `${op.value} %`; });
  const boot = el("input", { type: "checkbox", checked: bootEnabled() });
  boot.addEventListener("change", () => { try { localStorage.setItem(BOOT_KEY, boot.checked ? "on" : "off"); } catch { /* ignore */ } });
  const logout = status?.auth?.mode === "password"
    ? [el("h3", {}, t("set.session")), el("div", { class: "row" }, el("button", { type: "button", onclick: async () => {
        try { await api("api/auth/logout", { method: "POST" }); } finally { window.location.assign("login"); }
      } }, t("set.logout")))]
    : [];
  panel.replaceChildren(
    el("h3", {}, t("set.language")), el("div", { class: "row" }, langSel),
    el("h3", {}, t("set.opacity")), el("div", { class: "row" }, op, opVal),
    el("h3", {}, t("set.layout")), el("p", { class: "note" }, t("set.layout_note")),
    el("div", { class: "row" }, el("button", { type: "button", onclick: () => resetLayout() }, t("set.reset_layout"))),
    el("h3", {}, t("set.animation")), el("label", { class: "row" }, boot, t("set.animation_on")),
    ...logout,
    el("h3", {}, t("st.shortcuts")),
    el("table", {}, el("tbody", {},
      ...[["[", "st.k_left"], ["]", "st.k_right"], ["T", "st.k_tools"], ["A", "st.k_assets"], ["/", "st.k_search"], ["Esc", "st.k_esc"]]
        .map(([a, b]) => el("tr", {}, el("td", {}, el("kbd", {}, a)), el("td", {}, t(b)))))),
  );
}
