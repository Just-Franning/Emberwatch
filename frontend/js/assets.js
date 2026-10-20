// Assets window: own assets (watchlist with attack surface, active scan, CT, lookalike domains, live BGP, reputation),
// watched products (KEV/NVD), log analysis and the alert list.
import { t } from "./i18n.js";
import { alertItem } from "./panels.js";
import { ago, api, bytes, dateOnly, dateTime, dec1, dec2, el, num, safeLink, sevTag } from "./util.js";

const SOURCES = ["watch", "surface", "scan", "product", "ct", "typo", "bgp", "syslog", "rep"];
const label = (w) => (w.kind === "asn" ? `AS${w.value}` : w.value);
const kindTag = (k) => el("span", { class: "kind" }, t(`as.kind.${k}`));
const msg = (cls = "note") => el("p", { class: cls });
const table = (head, rows) => el("table", {}, el("thead", {}, el("tr", {}, head.map((h) => el("th", {}, h)))), el("tbody", {}, rows));

function setMsg(node, text, err = false) {
  node.className = err ? "state err" : "note";
  node.textContent = text;
}

function point(lon, lat, props) {
  return { type: "Feature", geometry: { type: "Point", coordinates: [lon, lat] }, properties: props };
}

export class Assets {
  constructor({ map, tools, onChange }) {
    this.map = map;
    this.tools = tools;
    this.onChange = onChange;
    this.panel = document.getElementById("panel-assets");
    this.body = document.getElementById("assets-body");
    this.scroller = this.body.closest(".panel-body") || this.body; // the element that actually scrolls
    this.tab = "assets";
    this.detail = null; // asset id
    this.product = null; // product id
    this.status = null;
    this.alertFilter = { source: "", sev: "low" };
    this.poll = null;
    this.panel.querySelectorAll(".tabs button[data-atab]").forEach((b) => b.addEventListener("click", () => {
      this.detail = null;
      this.product = null;
      this.select(b.dataset.atab);
    }));
    document.getElementById("assets-close").addEventListener("click", () => this.close());
  }

  setStatus(status) { this.status = status; }

  get isOpen() { return !this.panel.hidden; }

  open(tab = this.tab) {
    this.panel.hidden = false;
    this.select(tab);
  }

  close() {
    clearTimeout(this.poll);
    this.panel.hidden = true;
  }

  toggle() { if (this.panel.hidden) this.open(); else this.close(); }

  openAsset(id) { this.detail = id; this.open("assets"); }

  openProduct(id) { this.product = id; this.open("products"); }

  select(tab) {
    this.tab = tab;
    clearTimeout(this.poll);
    this.panel.querySelectorAll(".tabs button[data-atab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.atab === tab)));
    this.render();
  }

  async render() {
    if (this.panel.hidden) return;
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
      this.body.replaceChildren(el("p", { class: "state err" }, t("common.error", { msg: e.message })));
    }
  }

  changed() { this.onChange?.(); }

  // --- assets list ---------------------------------------------------------------------------
  addForm(feedback) {
    const value = el("input", { type: "text", maxlength: 260, placeholder: t("as.value_ph"), "aria-label": t("as.value_ph"), required: true });
    const lbl = el("input", { type: "text", maxlength: 80, placeholder: t("as.label_ph"), "aria-label": t("as.label_ph") });
    const scan = el("input", { type: "checkbox" });
    const consent = el("input", { type: "checkbox" });
    const consentRow = el("label", { class: "consent", hidden: true }, consent, t("as.consent"));
    scan.addEventListener("change", () => { consentRow.hidden = !scan.checked; });
    const form = el("form", { class: "watch-form" }, value, lbl, el("button", { type: "submit", class: "primary" }, t("common.add")),
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
      return el("li", { class: "clickable", onclick: () => { this.detail = w.id; this.render(); } },
        el("span", { class: "lbl" }, kindTag(w.kind), label(w), w.label ? el("span", { class: "muted" }, ` ${w.label}`) : null),
        el("span", { class: "val" }, w.alerts_total ? num(w.alerts_total) : ""),
        badges.length ? el("span", { class: "sub badges" }, badges) : null);
    });
    this.body.replaceChildren(
      el("p", { class: "note" }, t("as.intro")),
      this.addForm(feedback), feedback,
      el("div", { class: "btnrow" }, refresh, el("span", { class: "note" }, t("as.limit", { n: num(data.entries.length), max: num(data.max) }))),
      rows.length ? el("ol", { class: "rank assets" }, rows) : el("p", { class: "empty" }, t("as.none")),
    );
  }

  // --- asset detail -----------------------------------------------------------------------------
  async renderAsset(id) {
    let d;
    try {
      d = await api(`api/assets/${id}`);
    } catch (e) {
      this.detail = null;
      if (e.status === 404) return this.renderAssets();
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
      el("button", { type: "button", onclick: () => { this.detail = null; this.render(); } }, `← ${t("common.back")}`),
      el("h3", {}, kindTag(d.kind), label(d)),
      el("form", { class: "inline", onsubmit: async (e) => {
        e.preventDefault();
        try { await api(`api/watchlist/${id}`, { method: "PATCH", json: { label: lblInput.value } }); setMsg(feedback, "✓"); this.changed(); } catch (err) { setMsg(feedback, err.message, true); }
      } }, lblInput, el("button", { type: "submit" }, t("as.d.save"))),
      el("button", { type: "button", class: "danger", onclick: async () => {
        if (!window.confirm(t("as.delete_q", { value: label(d) }))) return;
        try { await api(`api/watchlist/${id}`, { method: "DELETE" }); this.detail = null; this.changed(); this.render(); } catch (err) { setMsg(feedback, err.message, true); }
      } }, t("common.delete")));
    const parts = [head, feedback];
    parts.push(el("h4", {}, t("as.d.alerts")),
      d.alerts.length ? el("ol", { class: "patterns" }, d.alerts.slice(0, 50).map((a) => alertItem(a))) : el("p", { class: "empty" }, t("al.none")));
    if (d.surface_rows !== undefined) parts.push(...this.exposure(d));
    if (d.kind === "ip" || d.kind === "cidr") parts.push(...this.reputationBlock(d));
    if (d.scan_detail !== undefined) parts.push(...this.scanBlock(d));
    if (d.domain_detail) parts.push(...this.domainBlock(d.domain_detail));
    if (d.bgp_detail) parts.push(...this.bgpBlock(d.bgp_detail));
    this.body.replaceChildren(...parts);
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
        this.map.setTool(geo.map((r) => point(r.lon, r.lat, { kind: "target", label: r.ip, ip: r.ip })));
        this.map.fitTo(geo.map((r) => [r.lon, r.lat]), 6);
      } }, t("common.show_map"))));
    }
    out.push(table([t("as.d.ip"), t("as.d.ports"), t("as.d.vulns"), t("as.d.as")], rows.map((r) => el("tr", {},
      el("td", {}, el("button", { type: "button", class: "link", onclick: () => this.tools.open("ipinfo", r.ip, true) }, r.ip),
        r.reputation?.drop ? el("span", { class: "tag bad" }, "DROP") : null, r.reputation?.tor ? el("span", { class: "tag warn" }, "Tor") : null,
        r.hostnames?.length ? el("div", { class: "muted" }, r.hostnames.slice(0, 3).join(", ")) : null,
        r.tags?.length ? el("div", { class: "muted" }, r.tags.join(", ")) : null),
      el("td", {}, r.status === "ok" ? r.ports.join(", ") || "–" : el("span", { class: "muted" }, t("as.d.nodata"))),
      el("td", {}, r.vulns.length ? r.vulns.slice(0, 12).map((v) => el("div", {},
        el("a", { href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}`, target: "_blank", rel: "noopener noreferrer" }, v),
        r.kev.includes(v) ? el("span", { class: "tag bad" }, "KEV") : null)) : "–",
        r.vulns.length > 12 ? el("div", { class: "muted" }, t("common.more", { n: r.vulns.length - 12 })) : null),
      el("td", {}, r.asn ? `AS${r.asn} ${r.as_name || ""}` : "–", el("div", { class: "muted" }, t("as.d.fetched", { t: ago(r.fetched_at) })))))));
    return out;
  }

  reputationBlock(d) {
    const drop = d.reputation?.drop;
    return [el("h4", {}, t("as.d.reputation")),
      el("p", { class: drop ? "bad-txt" : "note" }, drop ? t("as.d.on_drop", { cidr: `${drop.cidr} (${drop.sblid})` }) : t("as.d.not_drop")),
      d.kind === "ip" ? el("div", { class: "btnrow" }, el("button", { type: "button", onclick: () => this.tools.open("ipinfo", d.value, true) }, t("tool.ipinfo"))) : null];
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
      return [...out, el("p", { class: "note" }, t("as.d.scan_off")), el("label", { class: "consent" }, consent, t("as.consent")),
        el("div", { class: "btnrow" }, btn), scanMsg];
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
      el("p", { class: "note" }, t("as.d.scan_inside")), el("div", { class: "btnrow" }, btnScan, btnOff), scanMsg);
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
      el("td", {}, el("button", { type: "button", class: "link", onclick: () => this.tools.open("rdap", x.candidate, true) }, x.candidate),
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
    const data = await api("api/products");
    const feedback = msg();
    const vendor = el("input", { type: "text", maxlength: 60, placeholder: t("pr.vendor_ph"), "aria-label": t("pr.vendor_ph"), required: true });
    const product = el("input", { type: "text", maxlength: 80, placeholder: t("pr.product_ph"), "aria-label": t("pr.product_ph") });
    const form = el("form", { class: "watch-form" }, vendor, product, el("button", { type: "submit", class: "primary" }, t("common.add")));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await this.watchProduct(vendor.value.trim(), product.value.trim());
        await this.renderProducts();
      } catch (err) { setMsg(feedback, err.message, true); }
    });
    const rows = data.products.map((p) => el("li", { class: "clickable", onclick: () => { this.product = p.id; this.render(); } },
      el("span", { class: "lbl" }, `${p.vendor} ${p.product}`.trim()),
      el("span", { class: "val" }, p.kev ? el("span", { class: "tag bad" }, t("pr.kev", { n: num(p.kev) })) : null,
        p.critical ? el("span", { class: "tag warn" }, t("pr.critical", { n: num(p.critical) })) : null),
      el("span", { class: "sub" }, `${t("pr.nvd", { n: num(p.nvd) })} · ${p.checked_at ? t("pr.checked", { t: ago(p.checked_at) }) : t("pr.pending")}`)));
    this.body.replaceChildren(
      el("p", { class: "note" }, t("pr.intro", { cvss: dec1(data.min_cvss) })),
      data.nvd_key ? null : el("p", { class: "note" }, t("pr.nvd_nokey")),
      form, feedback,
      rows.length ? el("ol", { class: "rank" }, rows) : el("p", { class: "empty" }, t("pr.none")),
      el("p", { class: "note" }, t("pr.nvd_notice")),
    );
  }

  async watchProduct(vendor, product) {
    await api("api/products", { json: { vendor, product } });
    this.changed();
  }

  async renderProduct(id) {
    const [list, data] = await Promise.all([api("api/products"), api(`api/products/${id}/cves`)]);
    const p = list.products.find((x) => x.id === id);
    if (!p) { this.product = null; return this.renderProducts(); }
    const name = `${p.vendor} ${p.product}`.trim();
    const feedback = msg();
    const head = el("div", { class: "detail-head" },
      el("button", { type: "button", onclick: () => { this.product = null; this.render(); } }, `← ${t("common.back")}`),
      el("h3", {}, name),
      el("button", { type: "button", onclick: async () => {
        try { await api(`api/products/${id}/check`, { method: "POST" }); setMsg(feedback, t("pr.check_started")); } catch (e) { setMsg(feedback, e.message, true); }
      } }, t("common.check_now")),
      el("button", { type: "button", class: "danger", onclick: async () => {
        if (!window.confirm(t("pr.delete_q", { name }))) return;
        try { await api(`api/products/${id}`, { method: "DELETE" }); this.product = null; this.changed(); this.render(); } catch (e) { setMsg(feedback, e.message, true); }
      } }, t("common.delete")));
    const rows = data.cves.map((c) => el("tr", {},
      el("td", {}, el("a", { href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cve)}`, target: "_blank", rel: "noopener noreferrer" }, c.cve),
        c.kev_name ? el("span", { class: "tag bad" }, t("pr.kev_tag")) : null,
        (c.kev_ransomware || "").toLowerCase() === "known" ? el("span", { class: "tag bad" }, t("pr.ransom_tag")) : null),
      el("td", { class: "num" }, c.cvss !== null && c.cvss !== undefined ? dec1(c.cvss) : "–"),
      el("td", { class: "num" }, c.epss !== null && c.epss !== undefined ? dec2(c.epss) : "–"),
      el("td", { class: "num" }, dateOnly(c.kev_added || c.published)),
      el("td", {}, c.kev_name || c.summary || "")));
    this.body.replaceChildren(head, feedback, el("h4", {}, t("pr.cves", { name })),
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
      if (current.size > st.max_mb * 1024 * 1024) { result.replaceChildren(el("p", { class: "state err" }, t("common.error", { msg: `> ${st.max_mb} MB` }))); return; }
      go.disabled = true;
      result.replaceChildren(el("p", { class: "state" }, t("lg.running", { name: current.name, size: bytes(current.size) })));
      try {
        const r = await api("api/logs/analyze", { method: "POST", body: current, headers: { "Content-Type": "application/octet-stream" } });
        this.logResult(result, r);
      } catch (e) {
        result.replaceChildren(el("p", { class: "state err" }, t("common.error", { msg: e.message })));
      } finally {
        go.disabled = false;
      }
    });
    const idx = st.indexes;
    const sl = st.syslog || {};
    this.body.replaceChildren(
      el("p", { class: "note" }, t("lg.intro")),
      file, zone, el("div", { class: "btnrow" }, go),
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
          this.map.setTool(geo.map((h) => point(h.geo.lon, h.geo.lat, { kind: "target", label: h.indicator, ip: h.indicator })));
          this.map.fitTo(geo.map((h) => [h.geo.lon, h.geo.lat]), 5);
        } }, t("common.show_map"))));
      }
      parts.push(table(["", t("lg.indicator"), t("lg.count"), t("lg.match"), t("lg.line")], r.hits.map((h) => el("tr", {},
        el("td", {}, sevTag(h.severity)),
        el("td", {}, h.type === "ip" ? el("button", { type: "button", class: "link", onclick: () => this.tools.open("ipinfo", h.indicator, true) }, h.indicator) : h.indicator,
          el("div", { class: "mono-sm muted" }, h.sample)),
        el("td", { class: "num" }, num(h.count)),
        el("td", {}, h.labels.join("; "), " ", ...h.matches.map((m) => (m.reference ? safeLink(m.reference, "↗") : null))),
        el("td", { class: "num" }, num(h.line))))));
    }
    if (r.top_ips?.length) {
      parts.push(el("h4", {}, t("lg.top_ips")), table(["IP", t("lg.count"), t("as.d.as")], r.top_ips.slice(0, 15).map((x) => el("tr", {},
        el("td", { class: x.hit ? "bad-txt" : null }, el("button", { type: "button", class: "link", onclick: () => this.tools.open("ipinfo", x.ip, true) }, x.ip)),
        el("td", { class: "num" }, num(x.count)), el("td", {}, x.geo?.asn ? `AS${x.geo.asn} ${x.geo.as_name || ""}` : "–")))));
    }
    box.replaceChildren(...parts);
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
    this.body.replaceChildren(
      el("div", { class: "filters" }, el("label", {}, t("al.filter_source"), src), el("label", {}, t("al.filter_sev"), sev)),
      el("p", { class: "note" }, t("al.stats", { total: num(s.total_7d), high: num(s.high_7d), medium: num(s.medium_7d), low: num(s.low_7d) })),
      data.alerts.length
        ? el("ol", { class: "patterns" }, data.alerts.map((a) => alertItem(a, { onOpen: (x) => (x.asset_id ? this.openAsset(x.asset_id) : this.openProduct(x.product_id)) })))
        : el("p", { class: "empty" }, t("al.none")),
    );
  }
}
