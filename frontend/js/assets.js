// "My network" views: own assets (watchlist with attack surface, active scan, CT, lookalike domains, live BGP,
// reputation), watched products (KEV/NVD), log analysis and the alert list. Rendered into the page of the area.
import { t } from "./i18n.js";
import { alertItem } from "./panels.js";
import { go, href, objLink, routes } from "./router.js";
import { isAdmin } from "./session.js";
import { ago, api, bytes, dateOnly, dateTime, dec1, dec2, el, kids, num, safeLink, sevTag } from "./util.js";

const SOURCES = ["watch", "surface", "scan", "product", "ct", "typo", "bgp", "syslog", "rep", "myip", "news", "platform"];
const label = (w) => (w.kind === "asn" ? `AS${w.value}` : w.value);
const kindTag = (k) => el("span", { class: "kind" }, t(`as.kind.${k}`));
const msg = (cls = "note") => el("p", { class: cls });
const table = (head, rows) => el("div", { class: "tbl-wrap" }, el("table", { class: "res" }, el("thead", {}, el("tr", {}, head.map((h) => el("th", {}, h)))), el("tbody", {}, rows)));

function setMsg(node, text, err = false) {
  node.className = err ? "state err" : "note";
  node.textContent = text;
}

const alertTarget = (a) => (a.asset_id ? routes.asset(a.asset_id) : a.product_id ? routes.product(a.product_id) : null);

export class Assets {
  constructor({ body, scroller, onChange, onMap }) {
    this.body = body;
    this.scroller = scroller || body; // the element that actually scrolls
    this.onChange = onChange;
    this.onMap = onMap;
    this.tab = "assets";
    this.detail = null; // asset id
    this.product = null; // product id
    this.status = null;
    this.visible = false;
    this.alertFilter = { source: "", sev: "low" };
    this.poll = null;
  }

  setStatus(status) { this.status = status; }

  get isOpen() { return this.visible; }

  /** view: assets | products | logs | alerts; id: asset or product id for the detail view */
  show(view, id = null) {
    this.visible = true;
    this.tab = view;
    this.detail = view === "assets" && id ? Number(id) : null;
    this.product = view === "products" && id ? Number(id) : null;
    clearTimeout(this.poll);
    return this.render();
  }

  hide() {
    this.visible = false;
    clearTimeout(this.poll);
  }

  async render() {
    if (!this.visible) return;
    // keep the scroll position when the same view is re-rendered (e.g. scan progress), reset it on navigation
    const view = `${this.tab}:${this.detail ?? ""}:${this.product ?? ""}`;
    if (view !== this.view) this.scroller.scrollTop = 0;
    this.view = view;
    try {
      if (this.tab === "assets") await (this.detail ? this.renderAsset(this.detail) : this.renderAssets());
      else if (this.tab === "products") await (this.product ? this.renderProduct(this.product) : this.renderProducts());
      else if (this.tab === "logs") await this.renderLogs();
      else await this.renderAlerts();
    } catch (e) {
      kids(this.body, el("p", { class: "state err" }, t("common.error", { msg: e.message })));
    }
  }

  changed() { this.onChange?.(); }

  // --- assets list ---------------------------------------------------------------------------
  addForm(feedback) {
    const value = el("input", { type: "text", maxlength: 260, placeholder: t("as.value_ph"), "aria-label": t("as.value_ph"), required: true, value: this.prefill || "" });
    this.prefill = null;
    const lbl = el("input", { type: "text", maxlength: 80, placeholder: t("as.label_ph"), "aria-label": t("as.label_ph") });
    const scan = el("input", { type: "checkbox" });
    const consent = el("input", { type: "checkbox" });
    const consentRow = el("label", { class: "consent", hidden: true }, consent, t("as.consent"));
    scan.addEventListener("change", () => { consentRow.hidden = !scan.checked; });
    const form = el("form", { class: "watch-form admin-only" }, value, lbl, el("button", { type: "submit", class: "primary" }, t("common.add")),
      el("label", { class: "scan-opt", hidden: this.status && !this.status.scan?.enabled }, scan, t("as.scan_opt")), consentRow);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!value.value.trim()) return;
      try {
        const r = await api("api/watchlist", { json: { value: value.value.trim(), label: lbl.value.trim() || null, scan: scan.checked, scan_ack: scan.checked && consent.checked } });
        setMsg(feedback, t("as.added", { kind: t(`as.kind.${r.kind}`), value: r.kind === "asn" ? `AS${r.value}` : r.value, n: num(r.new_alerts) }));
        value.value = "";
        lbl.value = "";
        await this.renderAssets(feedback);
        this.changed();
      } catch (err) {
        setMsg(feedback, err.message, true);
      }
    });
    return form;
  }

  async renderAssets(feedback = msg()) {
    const data = await api("api/watchlist");
    const refresh = el("button", { type: "button", onclick: async () => {
      try { await api("api/assets/refresh", { method: "POST" }); setMsg(feedback, t("as.refresh_started")); } catch (e) { setMsg(feedback, e.message, true); }
    } }, t("as.refresh"));
    const rows = data.entries.map((w) => {
      const badges = [];
      if (w.alerts_7d) badges.push(el("span", { class: `tag ${w.high_7d ? "bad" : "warn"}` }, t("as.alerts7", { n: num(w.alerts_7d) })));
      if (w.surface?.ports?.length) badges.push(el("span", { class: "tag" }, t("as.ports", { list: w.surface.ports.slice(0, 8).join(", ") + (w.surface.ports.length > 8 ? " …" : "") })));
      if (w.surface?.vulns) badges.push(el("span", { class: "tag warn" }, t("as.vulns", { n: num(w.surface.vulns) })));
      if (w.surface?.kev) badges.push(el("span", { class: "tag bad" }, t("as.kev", { n: num(w.surface.kev) })));
      if (w.scan) badges.push(el("span", { class: "tag" }, t("as.scan_on")));
      if (w.reputation?.drop) badges.push(el("span", { class: "tag bad" }, t("as.drop")));
      if (w.bgp?.watches) badges.push(el("span", { class: "tag" }, t("as.bgp", { n: w.bgp.watches })));
      if (w.domain?.ct_total) badges.push(el("span", { class: "tag" }, t("as.ct", { n: num(w.domain.ct_total) })));
      if (w.domain?.typos) badges.push(el("span", { class: "tag warn" }, t("as.typos", { n: num(w.domain.typos) })));
      return el("li", { class: "clickable", onclick: () => go(routes.asset(w.id)) },
        el("span", { class: "lbl" }, kindTag(w.kind), label(w), w.label ? el("span", { class: "muted" }, ` ${w.label}`) : null),
        el("span", { class: "val" }, w.alerts_total ? num(w.alerts_total) : ""),
        badges.length ? el("span", { class: "sub badges" }, badges) : null);
    });
    kids(this.body,
      el("h2", { class: "page-title" }, t("nz.nav.assets")),
      el("p", { class: "lead" }, t("as.intro")),
      this.addForm(feedback), feedback,
      el("div", { class: "btnrow" }, el("span", { class: "admin-only" }, refresh), el("span", { class: "note" }, t("as.limit", { n: num(data.entries.length), max: num(data.max) }))),
      rows.length ? el("ol", { class: "rank assets" }, rows) : el("p", { class: "empty" }, t("as.none")),
    );
  }

  // --- asset detail -----------------------------------------------------------------------------
  async renderAsset(id) {
    let d;
    try {
      d = await api(`api/assets/${id}`);
    } catch (e) {
      if (e.status === 404) { go("netz/assets"); return undefined; }
      throw e;
    }
    if (this.detail !== id || this.tab !== "assets") return;
    clearTimeout(this.poll);
    const sd = d.scan_detail;
    const running = Boolean(sd?.progress) || sd?.run?.status === "running";
    if (this.scanWait?.id === id) {
      // a manually started scan resolves its targets before its run appears: wait for it (max. 30 s)
      const appeared = (sd?.run?.id ?? 0) > this.scanWait.after;
      if (Date.now() > this.scanWait.until || (appeared && !running)) this.scanWait = null;
    }
    const scrollTop = this.scroller.scrollTop;
    const feedback = msg();
    const lblInput = el("input", { type: "text", maxlength: 80, value: d.label || "", "aria-label": t("as.d.label") });
    const head = el("div", { class: "detail-head" },
      el("a", { class: "btn", href: "#/netz/assets" }, `← ${t("nz.nav.assets")}`),
      el("h3", {}, kindTag(d.kind), objLink(d.kind === "asn" ? "asn" : d.kind, d.value, label(d))),
      el("form", { class: "inline admin-only", onsubmit: async (e) => {
        e.preventDefault();
        try { await api(`api/watchlist/${id}`, { method: "PATCH", json: { label: lblInput.value } }); setMsg(feedback, "✓"); this.changed(); } catch (err) { setMsg(feedback, err.message, true); }
      } }, lblInput, el("button", { type: "submit" }, t("as.d.save"))),
      el("button", { type: "button", class: "danger admin-only", onclick: async () => {
        if (!window.confirm(t("as.delete_q", { value: label(d) }))) return;
        try { await api(`api/watchlist/${id}`, { method: "DELETE" }); this.changed(); go("netz/assets"); } catch (err) { setMsg(feedback, err.message, true); }
      } }, t("common.delete")));
    const parts = [head, feedback];
    parts.push(el("h4", {}, t("as.d.alerts")),
      d.alerts.length ? el("ol", { class: "patterns" }, d.alerts.slice(0, 50).map((a) => alertItem(a))) : el("p", { class: "empty" }, t("al.none")));
    if (d.surface_rows !== undefined) parts.push(...this.exposure(d));
    if (d.kind === "ip" || d.kind === "cidr") parts.push(...this.reputationBlock(d));
    if (d.scan_detail !== undefined) parts.push(...this.scanBlock(d));
    if (d.domain_detail) parts.push(...this.domainBlock(d.domain_detail));
    if (d.bgp_detail) parts.push(...this.bgpBlock(d.bgp_detail));
    kids(this.body, ...parts);
    this.scroller.scrollTop = scrollTop;
    if (running || this.scanWait?.id === id) {
      this.poll = setTimeout(() => { if (this.detail === id && this.isOpen) this.renderAsset(id).catch(() => {}); }, running ? 2000 : 1000);
    }
  }

  exposure(d) {
    const rows = d.surface_rows || [];
    const out = [el("h4", {}, t("as.d.exposure")), el("p", { class: "note" }, t("as.d.exposure_note"))];
    if (!rows.length) return [...out, el("p", { class: "empty" }, t("as.d.no_exposure"))];
    const geo = rows.filter((r) => r.lat !== null && r.lat !== undefined);
    if (geo.length) {
      out.push(el("div", { class: "btnrow" }, el("button", { type: "button", onclick: () => {
        this.onMap({ points: geo.map((r) => ({ lon: r.lon, lat: r.lat, kind: "target", label: r.ip, ip: r.ip })) }, label(d));
      } }, t("common.show_map"))));
    }
    out.push(table([t("as.d.ip"), t("as.d.ports"), t("as.d.vulns"), t("as.d.as")], rows.map((r) => el("tr", {},
      el("td", {}, objLink("ip", r.ip),
        r.reputation?.drop ? el("span", { class: "tag bad" }, "DROP") : null, r.reputation?.tor ? el("span", { class: "tag warn" }, "Tor") : null,
        r.hostnames?.length ? el("div", { class: "muted" }, r.hostnames.slice(0, 3).join(", ")) : null,
        r.tags?.length ? el("div", { class: "muted" }, r.tags.join(", ")) : null),
      el("td", {}, r.status === "ok" ? r.ports.join(", ") || "–" : el("span", { class: "muted" }, t("as.d.nodata"))),
      el("td", {}, r.vulns.length ? r.vulns.slice(0, 12).map((v) => el("div", {}, objLink("cve", v),
        r.kev.includes(v) ? el("span", { class: "tag bad" }, "KEV") : null)) : "–",
        r.vulns.length > 12 ? el("div", { class: "muted" }, t("common.more", { n: r.vulns.length - 12 })) : null),
      el("td", {}, r.asn ? `AS${r.asn} ${r.as_name || ""}` : "–", el("div", { class: "muted" }, t("as.d.fetched", { t: ago(r.fetched_at) })))))));
    return out;
  }

  reputationBlock(d) {
    const drop = d.reputation?.drop;
    return [el("h4", {}, t("as.d.reputation")),
      el("p", { class: drop ? "bad-txt" : "note" }, drop ? t("as.d.on_drop", { cidr: `${drop.cidr} (${drop.sblid})` }) : t("as.d.not_drop")),
      d.kind === "ip" ? el("div", { class: "btnrow" }, objLink("ip", d.value, t("as.d.open_object"), "btn")) : null];
  }

  scanBlock(d) {
    const id = d.id;
    const st = this.status?.scan || {};
    const out = [el("h4", {}, t("as.d.scan"))];
    if (!st.enabled) return [...out, el("p", { class: "note" }, t("as.d.scan_global_off"))];
    const scanMsg = msg(); // feedback directly at the buttons, not at the top of the (scrolled) detail view
    if (!d.scan) {
      const consent = el("input", { type: "checkbox" });
      const btn = el("button", { type: "button", class: "primary", onclick: async () => {
        if (!consent.checked) { setMsg(scanMsg, t("as.d.consent_needed"), true); return; }
        btn.disabled = true;
        try { await api(`api/watchlist/${id}`, { method: "PATCH", json: { scan: true, scan_ack: true } }); await this.render(); } catch (e) { btn.disabled = false; setMsg(scanMsg, e.message, true); }
      } }, t("as.d.scan_enable"));
      return [...out, el("p", { class: "note" }, t("as.d.scan_off")), el("label", { class: "consent admin-only" }, consent, t("as.consent")),
        el("div", { class: "btnrow admin-only" }, btn), scanMsg];
    }
    const sd = d.scan_detail || {};
    const run = sd.run;
    const progress = sd.progress;
    const waiting = this.scanWait?.id === id;
    const btnScan = el("button", { type: "button", class: "primary", disabled: Boolean(progress) || waiting, onclick: async () => {
      btnScan.disabled = true;
      setMsg(scanMsg, t("as.d.scan_starting"));
      try {
        const r = await api(`api/assets/${id}/scan`, { method: "POST" });
        this.scanWait = { id, after: run?.id ?? 0, until: Date.now() + 30000, targets: r.targets, ports: r.ports };
        await this.renderAsset(id);
      } catch (e) {
        btnScan.disabled = false;
        setMsg(scanMsg, e.message, true);
      }
    } }, t("as.d.scan_now"));
    const btnOff = el("button", { type: "button", onclick: async () => {
      try { await api(`api/watchlist/${id}`, { method: "PATCH", json: { scan: false } }); await this.render(); } catch (e) { setMsg(scanMsg, e.message, true); }
    } }, t("as.d.scan_disable"));
    out.push(el("p", { class: "note" }, t("as.d.scan_note", { ports: num(st.ports), h: num(st.interval_h) })),
      el("p", { class: "note" }, t("as.d.scan_inside")), el("div", { class: "btnrow admin-only" }, btnScan, btnOff), scanMsg);
    if (progress) {
      out.push(el("p", { class: "state" }, t("as.d.scan_running", { done: num(progress.done), total: num(progress.total) })),
        el("progress", { max: progress.total || 1, value: progress.done }));
    } else if (waiting && (run?.id ?? 0) <= this.scanWait.after) {
      setMsg(scanMsg, t("as.d.scan_wait", { targets: num(this.scanWait.targets), ports: num(this.scanWait.ports) }));
    }
    const res = sd.result_run;
    if (res) {
      out.push(el("p", { class: "note" }, t("as.d.scan_last", { t: dateTime(res.finished_at || res.started_at), n: num(sd.ports.length),
        status: t(`as.d.st.${res.status}`) })));
      if (!sd.ports.length) out.push(el("p", { class: "note" }, t("as.d.scan_none_open", { targets: num(res.targets) })));
    } else if (!progress && !run) out.push(el("p", { class: "note" }, t("as.d.scan_never")));
    if (run && run.status === "error") out.push(el("p", { class: "state err" }, t("common.error", { msg: run.error || "?" })));
    if (sd.ports?.length) {
      out.push(table([t("as.d.ip"), t("tool.port"), t("as.d.service"), t("as.d.detail")], sd.ports.map((p) => {
        const det = [];
        if (p.tls && !p.tls.error) {
          det.push(el("div", { class: p.tls.days_left !== null && p.tls.days_left <= 14 ? "warn-txt" : null },
            t("as.d.tls_days", { date: dateOnly(p.tls.not_after), n: p.tls.days_left }), p.tls.valid === false ? el("span", { class: "tag warn" }, "!") : null));
          det.push(el("div", { class: "muted" }, `${p.tls.subject || ""} · ${p.tls.issuer || ""}`));
        }
        if (p.http?.status) det.push(el("div", {}, `${p.http.status}${p.http.server ? " · " + p.http.server : ""}`));
        if (p.banner) det.push(el("div", { class: "mono-sm" }, p.banner));
        return el("tr", {}, el("td", {}, p.ip), el("td", { class: p.risky ? "bad-txt" : null }, p.port), el("td", {}, p.service || "–"), el("td", {}, det.length ? det : "–"));
      })));
    }
    return out;
  }

  domainBlock(dd) {
    const out = [el("h4", {}, t("as.d.domain")), el("p", { class: "note" }, t("as.d.ct_note"))];
    out.push(dd.certs.length ? table([t("tool.valid_until"), "SAN", t("tool.issuer")], dd.certs.slice(0, 40).map((c) => el("tr", {},
      el("td", {}, `${dateOnly(c.not_before)} – ${dateOnly(c.not_after)}`), el("td", {}, c.names.slice(0, 6).join(", ") + (c.names.length > 6 ? " …" : "")),
      el("td", {}, c.issuer || "–")))) : el("p", { class: "empty" }, t("as.d.ct_none")));
    out.push(el("h4", {}, t("as.d.typos")), el("p", { class: "note" }, t("as.d.typos_note", { n: num(dd.typo_checked), t: dd.typo_last ? ago(dd.typo_last) : t("common.never") })));
    out.push(dd.typos.length ? table(["Domain", t("tool.type"), "IP", t("c2.first")], dd.typos.map((x) => el("tr", {},
      el("td", {}, objLink("domain", x.candidate),
        x.mx ? el("span", { class: "tag warn" }, t("as.d.mx")) : null),
      el("td", {}, x.technique), el("td", {}, x.ips.join(", ") || "–"), el("td", {}, x.first_seen ? dateOnly(x.first_seen) : "–")))) : el("p", { class: "empty" }, t("as.d.typos_none")));
    return out;
  }

  bgpBlock(b) {
    const out = [el("h4", {}, t("as.d.bgp"))];
    if (!b.enabled) return [...out, el("p", { class: "note" }, t("as.d.bgp_off"))];
    out.push(el("p", { class: b.connected ? "note ok-txt" : "note warn-txt" }, t("as.d.bgp_state", { state: t(b.connected ? "as.d.connected" : "as.d.disconnected") })));
    if (!b.watches.length) return [...out, el("p", { class: "empty" }, t("as.d.no_bgp"))];
    out.push(table([t("as.d.prefix"), t("as.d.expected")], b.watches.map((w) => el("tr", {}, el("td", {}, w.prefix),
      el("td", {}, w.expected.map((a) => `AS${a}`).join(", ") || t("common.none"))))));
    if (b.events.length) {
      out.push(el("h4", {}, t("as.d.events")), table(["", t("as.d.prefix"), "Origin", "Peer"], b.events.slice(0, 30).map((e) => el("tr", {},
        el("td", {}, ago(e.ts)), el("td", {}, e.prefix), el("td", { class: e.verdict === "unexpected" ? "bad-txt" : null },
          e.type === "withdraw" ? `withdraw (${e.verdict})` : (e.origin || []).map((a) => `AS${a}`).join(", ")),
        el("td", {}, `${e.peer_asn ? "AS" + e.peer_asn : ""} ${e.host || ""}`)))));
    }
    return out;
  }

  // --- products -----------------------------------------------------------------------------------
  async renderProducts() {
    const [data, pf] = await Promise.all([api("api/products"), api("api/platforms?active=true").catch(() => null)]);
    const feedback = msg();
    const vendor = el("input", { type: "text", maxlength: 60, placeholder: t("pr.vendor_ph"), "aria-label": t("pr.vendor_ph"), required: true });
    const product = el("input", { type: "text", maxlength: 80, placeholder: t("pr.product_ph"), "aria-label": t("pr.product_ph") });
    const form = el("form", { class: "watch-form admin-only" }, vendor, product, el("button", { type: "submit", class: "primary" }, t("common.add")));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await this.watchProduct(vendor.value.trim(), product.value.trim());
        await this.renderProducts();
      } catch (err) { setMsg(feedback, err.message, true); }
    });
    const rows = data.products.map((p) => el("li", { class: "clickable", onclick: () => go(routes.product(p.id)) },
      el("span", { class: "lbl" }, `${p.vendor} ${p.product}`.trim()),
      el("span", { class: "val" }, p.kev ? el("span", { class: "tag bad" }, t("pr.kev", { n: num(p.kev) })) : null,
        p.critical ? el("span", { class: "tag warn" }, t("pr.critical", { n: num(p.critical) })) : null),
      el("span", { class: "sub" }, `${t("pr.nvd", { n: num(p.nvd) })} · ${p.checked_at ? t("pr.checked", { t: ago(p.checked_at) }) : t("pr.pending")}`)));
    kids(this.body,
      el("h2", { class: "page-title" }, t("nz.nav.products")),
      el("p", { class: "lead" }, t("pr.intro", { cvss: dec1(data.min_cvss) })),
      data.nvd_key ? null : el("p", { class: "note" }, t("pr.nvd_nokey")),
      form, feedback,
      rows.length ? el("ol", { class: "rank" }, rows) : el("p", { class: "empty" }, t("pr.none")),
      el("p", { class: "note" }, t("pr.nvd_notice")),
      pf?.enabled ? this.platformsBox(pf) : null,
    );
  }

  /** Cloud platforms in use: their new incidents raise alerts (platforms.py). */
  platformsBox(pf) {
    const feedback = msg();
    const boxes = pf.providers.map((p) => el("input", { type: "checkbox", value: p.id, checked: p.used, disabled: !isAdmin() }));
    const save = async () => {
      boxes.forEach((b) => { b.disabled = true; });
      try {
        await api("api/platforms/used", { json: { providers: boxes.filter((b) => b.checked).map((b) => b.value) } });
        setMsg(feedback, t("pf.saved"));
      } catch (e) { setMsg(feedback, e.message, true); } finally { boxes.forEach((b) => { b.disabled = false; }); }
    };
    boxes.forEach((b) => b.addEventListener("change", save));
    const active = pf.incidents.length;
    return el("section", { class: "card wide pf-used" },
      el("h3", {}, t("pf.used_h")), el("p", { class: "note" }, t("pf.used_note")),
      el("div", { class: "pf-boxes" }, pf.providers.map((p, i) => el("label", { class: "pcheck" }, boxes[i], p.name, " ", safeLink(p.page, "↗")))),
      active ? el("p", {}, el("a", { href: href(routes.view("platforms")) }, t("pf.active_n", { n: num(active) }))) : null,
      feedback);
  }

  async watchProduct(vendor, product) {
    await api("api/products", { json: { vendor, product } });
    this.changed();
  }

  async renderProduct(id) {
    const [list, data] = await Promise.all([api("api/products"), api(`api/products/${id}/cves`)]);
    const p = list.products.find((x) => x.id === id);
    if (!p) { go("netz/products"); return undefined; }
    const name = `${p.vendor} ${p.product}`.trim();
    const feedback = msg();
    const head = el("div", { class: "detail-head" },
      el("a", { class: "btn", href: "#/netz/products" }, `← ${t("nz.nav.products")}`),
      el("h3", {}, objLink("vendor", p.vendor, name)),
      el("button", { type: "button", class: "admin-only", onclick: async () => {
        try { await api(`api/products/${id}/check`, { method: "POST" }); setMsg(feedback, t("pr.check_started")); } catch (e) { setMsg(feedback, e.message, true); }
      } }, t("common.check_now")),
      el("button", { type: "button", class: "danger admin-only", onclick: async () => {
        if (!window.confirm(t("pr.delete_q", { name }))) return;
        try { await api(`api/products/${id}`, { method: "DELETE" }); this.changed(); go("netz/products"); } catch (e) { setMsg(feedback, e.message, true); }
      } }, t("common.delete")));
    const rows = data.cves.map((c) => el("tr", {},
      el("td", {}, objLink("cve", c.cve),
        c.kev_name ? el("span", { class: "tag bad" }, t("pr.kev_tag")) : null,
        (c.kev_ransomware || "").toLowerCase() === "known" ? el("span", { class: "tag bad" }, t("pr.ransom_tag")) : null),
      el("td", { class: "num" }, c.cvss !== null && c.cvss !== undefined ? dec1(c.cvss) : "–"),
      el("td", { class: "num" }, c.epss !== null && c.epss !== undefined ? dec2(c.epss) : "–"),
      el("td", { class: "num" }, dateOnly(c.kev_added || c.published)),
      el("td", {}, c.kev_name || c.summary || "")));
    kids(this.body, head, feedback, el("h4", {}, t("pr.cves", { name })),
      rows.length ? table(["CVE", "CVSS", "EPSS", "", ""], rows) : el("p", { class: "empty" }, t("pr.no_cves")));
  }

  // --- log analysis -----------------------------------------------------------------------------------
  async renderLogs() {
    let st = { max_mb: 25, indexes: null, syslog: { enabled: false } };
    try { st = await api("api/logs/status"); } catch { /* keep defaults */ }
    const file = el("input", { type: "file", class: "sr-only", id: "log-file" });
    const chosen = el("span", { class: "note" }, t("lg.max", { n: st.max_mb }));
    const result = el("div", { class: "log-result" });
    const go = el("button", { type: "button", class: "primary", disabled: true }, t("lg.analyze"));
    let current = null;
    const pick = (f) => {
      current = f || null;
      chosen.textContent = current ? `${current.name} (${bytes(current.size)})` : t("lg.max", { n: st.max_mb });
      go.disabled = !current;
    };
    file.addEventListener("change", () => pick(file.files[0]));
    const zone = el("div", { class: "dropzone" }, el("label", { for: "log-file", class: "btn" }, t("lg.choose")), el("span", { class: "note" }, t("lg.drop")), chosen);
    zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("over"));
    zone.addEventListener("drop", (e) => { e.preventDefault(); zone.classList.remove("over"); pick(e.dataTransfer.files[0]); });
    go.addEventListener("click", async () => {
      if (!current) return;
      if (current.size > st.max_mb * 1024 * 1024) { kids(result, el("p", { class: "state err" }, t("common.error", { msg: `> ${st.max_mb} MB` }))); return; }
      go.disabled = true;
      kids(result, el("p", { class: "state" }, t("lg.running", { name: current.name, size: bytes(current.size) })));
      try {
        const r = await api("api/logs/analyze", { method: "POST", body: current, headers: { "Content-Type": "application/octet-stream" } });
        this.logResult(result, r);
      } catch (e) {
        kids(result, el("p", { class: "state err" }, t("common.error", { msg: e.message })));
      } finally {
        go.disabled = false;
      }
    });
    const idx = st.indexes;
    const sl = st.syslog || {};
    kids(this.body,
      el("h2", { class: "page-title" }, t("nz.nav.logs")),
      el("p", { class: "lead" }, t("lg.intro")),
      el("div", { class: "admin-only" }, file, zone, el("div", { class: "btnrow" }, go)),
      el("p", { class: "note viewer-only" }, t("role.viewer_logs")),
      idx ? el("p", { class: "note" }, t("lg.indexes", { ips: num(idx.ips), domains: num(idx.domains), urls: num(idx.urls), drop: num(idx.drop), tor: num(idx.tor) })) : null,
      result,
      el("h4", {}, t("lg.syslog")),
      sl.enabled
        ? el("div", {}, el("p", { class: "note" }, t("lg.syslog_on", { port: sl.port, allow: (sl.allow || []).join(", ") })),
          sl.error ? el("p", { class: "state err" }, t("lg.syslog_error", { msg: sl.error })) : null,
          el("p", { class: "note" }, t("lg.syslog_stats", { received: num(sl.received), matched: num(sl.matched), alerts: num(sl.alerts),
            rejected: num(sl.rejected), dropped: num(sl.dropped_rate) })),
          sl.senders?.length ? el("p", { class: "note" }, `${t("lg.senders")}: ${sl.senders.map((s) => `${s.ip} (${num(s.lines)})`).join(", ")}`) : null)
        : el("p", { class: "note" }, t("lg.syslog_off")),
    );
  }

  logResult(box, r) {
    const parts = [el("p", { class: "note" }, t("lg.summary", { lines: num(r.lines), ips: num(r.unique.ips), domains: num(r.unique.domains), urls: num(r.unique.urls), ms: num(r.duration_ms) }))];
    if (r.truncated) parts.push(el("p", { class: "warn-txt" }, t("lg.truncated")));
    if (r.capped) parts.push(el("p", { class: "warn-txt" }, t("lg.capped")));
    parts.push(el("h4", {}, t("lg.hits", { n: num(r.hits_total) })));
    if (!r.hits.length) parts.push(el("p", { class: "ok-txt" }, t("lg.no_hits")));
    else {
      const geo = r.hits.filter((h) => h.geo && h.geo.lat !== undefined && h.geo.lat !== null);
      if (geo.length) {
        parts.push(el("div", { class: "btnrow" }, el("button", { type: "button", onclick: () => {
          this.onMap({ points: geo.map((h) => ({ lon: h.geo.lon, lat: h.geo.lat, kind: "target", label: h.indicator, ip: h.indicator, sev: h.severity })) }, t("nz.nav.logs"));
        } }, t("common.show_map"))));
      }
      parts.push(table(["", t("lg.indicator"), t("lg.count"), t("lg.match"), t("lg.line")], r.hits.map((h) => el("tr", {},
        el("td", {}, sevTag(h.severity)),
        el("td", {}, ["ip", "domain", "url"].includes(h.type) ? objLink(h.type, h.indicator) : h.indicator,
          el("div", { class: "mono-sm muted" }, h.sample)),
        el("td", { class: "num" }, num(h.count)),
        el("td", {}, h.labels.join("; "), " ", ...h.matches.map((m) => (m.reference ? safeLink(m.reference, "↗") : null))),
        el("td", { class: "num" }, num(h.line))))));
    }
    if (r.top_ips?.length) {
      parts.push(el("h4", {}, t("lg.top_ips")), table(["IP", t("lg.count"), t("as.d.as")], r.top_ips.slice(0, 15).map((x) => el("tr", {},
        el("td", { class: x.hit ? "bad-txt" : null }, objLink("ip", x.ip)),
        el("td", { class: "num" }, num(x.count)), el("td", {}, x.geo?.asn ? `AS${x.geo.asn} ${x.geo.as_name || ""}` : "–")))));
    }
    kids(box, ...parts);
  }

  // --- alerts -------------------------------------------------------------------------------------------
  async renderAlerts() {
    const f = this.alertFilter;
    const q = new URLSearchParams({ limit: "300", min_severity: f.sev });
    if (f.source) q.set("source", f.source);
    const data = await api(`api/alerts?${q}`);
    const src = el("select", { "aria-label": t("al.filter_source") }, el("option", { value: "" }, t("common.all")),
      ...SOURCES.map((s) => el("option", { value: s, selected: f.source === s }, t(`src.${s}`))));
    const sev = el("select", { "aria-label": t("al.filter_sev") }, ...["low", "medium", "high"].map((s) => el("option", { value: s, selected: f.sev === s }, `≥ ${t(`sev.${s}`)}`)));
    const apply = () => { this.alertFilter = { source: src.value, sev: sev.value }; this.renderAlerts(); };
    src.addEventListener("change", apply);
    sev.addEventListener("change", apply);
    const s = data.stats;
    kids(this.body,
      el("h2", { class: "page-title" }, t("nz.nav.alerts")),
      el("div", { class: "filters wide" }, el("label", {}, t("al.filter_source"), src), el("label", {}, t("al.filter_sev"), sev)),
      el("p", { class: "note" }, t("al.stats", { total: num(s.total_7d), high: num(s.high_7d), medium: num(s.medium_7d), low: num(s.low_7d) })),
      data.alerts.length
        ? el("ol", { class: "patterns" }, data.alerts.map((a) => alertItem(a, { onOpen: (x) => { const r = alertTarget(x); if (r) go(r); } })))
        : el("p", { class: "empty" }, t("al.none")),
    );
  }
}
