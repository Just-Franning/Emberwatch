// Search across C2, ThreatFox IOCs, KEV, NVD, ransomware victims, infrastructure events, countries,
// your assets and watched products. Vendor/product queries (e.g. "Sophos") can be watched directly.
import { t } from "./i18n.js";
import { api, countryName, dateOnly, dateTime, dec1, dec2, el, num } from "./util.js";

function splitProduct(q) {
  const words = q.trim().split(/\s+/);
  return { vendor: words[0], product: words.slice(1).join(" ") };
}

export class Search {
  constructor(cb) {
    this.cb = cb; // onCountry, onC2, onIp, onCve, onAsn, onWatchProduct, onWatchAsset, onOpenAsset, onOpenProducts
    this.form = document.getElementById("search");
    this.input = document.getElementById("search-q");
    this.box = document.getElementById("search-results");
    this.seq = 0;
    this.form.addEventListener("submit", (e) => { e.preventDefault(); this.run(); });
    this.input.addEventListener("keydown", (e) => { if (e.key === "Escape") this.hide(); });
    document.addEventListener("click", (e) => { if (!this.form.contains(e.target)) this.hide(); });
  }

  focus() { this.input.focus(); this.input.select(); }

  hide() { this.box.hidden = true; }

  item(label, sub, onclick, cls = null) {
    return el("button", { type: "button", class: cls, onclick: () => { this.hide(); onclick(); } }, el("span", {}, label), el("span", { class: "sub" }, sub || ""));
  }

  async run() {
    const q = this.input.value.trim();
    if (q.length < 2) return;
    const seq = ++this.seq;
    this.box.hidden = false;
    this.box.replaceChildren(el("div", { class: "empty" }, t("s.searching")));
    let r;
    try {
      r = await api(`api/search?q=${encodeURIComponent(q)}`);
    } catch (e) {
      this.box.replaceChildren(el("div", { class: "empty" }, t("common.error", { msg: e.message })));
      return;
    }
    if (seq !== this.seq) return;
    const g = [];
    const item = this.item.bind(this);
    if (r.type === "ip") {
      g.push(el("h4", {}, t("s.tools")), item(t("s.ipinfo", { q }), t("s.ipinfo_sub"), () => this.cb.onIp(q)));
    }
    if (r.type === "asn") {
      g.push(el("h4", {}, t("s.tools")), item(t("s.whois", { q: q.toUpperCase() }), "RDAP", () => this.cb.onAsn(q)));
    }
    if (r.reputation && (r.reputation.drop || r.reputation.tor)) {
      g.push(el("h4", {}, t("s.reputation")));
      if (r.reputation.drop) g.push(el("div", { class: "empty warn-txt" }, t("s.drop", { cidr: r.reputation.drop.cidr })));
      if (r.reputation.tor) g.push(el("div", { class: "empty" }, t("s.tor")));
    }
    if (["ip", "cidr", "asn", "domain"].includes(r.type)) {
      g.push(item(t("s.watch_asset", { q }), "", () => this.cb.onWatchAsset(q), "action"));
    }
    if (r.assets?.length) {
      g.push(el("h4", {}, t("s.assets")), ...r.assets.map((a) =>
        item(a.kind === "asn" ? `AS${a.value}` : a.value, a.label || t(`as.kind.${a.kind}`), () => this.cb.onOpenAsset(a.id))));
    }
    if (r.type === "text" || r.type === "domain") {
      const vendors = r.vendors || [];
      const watched = r.products || [];
      if (watched.length) {
        g.push(el("h4", {}, t("s.watched")), ...watched.map((p) => item(`${p.vendor} ${p.product}`.trim(), "", () => this.cb.onOpenProducts(p.id))));
      }
      if (r.type === "text") {
        if (vendors.length) {
          g.push(el("h4", {}, t("s.vendors")), ...vendors.map((v) =>
            item(v.vendor, t("s.vendor_sub", { n: num(v.n), date: dateOnly(v.latest) }), () => this.cb.onWatchProduct(v.vendor, ""), "vendor")));
        }
        const sp = splitProduct(q);
        g.push(item(t("s.watch_product", { name: `${sp.vendor}${sp.product ? " / " + sp.product : ""}` }), t("s.watch_product_sub"),
          () => this.cb.onWatchProduct(sp.vendor, sp.product), "action"));
      }
    }
    if (r.countries?.length) {
      g.push(el("h4", {}, t("s.countries")), ...r.countries.map((c) => item(c.name, c.cc, () => this.cb.onCountry(c.cc))));
    }
    if (r.c2?.length) {
      g.push(el("h4", {}, t("s.c2", { n: r.c2.length })), ...r.c2.slice(0, 20).map((c) =>
        item(`${c.malware}: ${c.ioc}`, `${countryName(c.country)}${c.asn ? ", AS" + c.asn : ""}`, () => this.cb.onC2(c))));
    }
    if (r.iocs?.length) {
      g.push(el("h4", {}, t("s.iocs", { n: r.iocs.length })), ...r.iocs.slice(0, 15).map((c) =>
        item(c.ioc, `${c.threat_type || ""} ${c.malware || ""}, ${dateTime(c.first_seen)}`,
          () => /^https:\/\/threatfox\.abuse\.ch\//.test(c.reference || "") && window.open(c.reference, "_blank", "noopener,noreferrer"))));
    }
    if (r.infra?.length) {
      g.push(el("h4", {}, t("s.infra", { n: r.infra.length })), ...r.infra.slice(0, 10).map((e) =>
        item(e.title, `${(e.countries || []).map(countryName).join(", ")}, ${dateTime(e.start_ts)}`, () => e.countries?.[0] && this.cb.onCountry(e.countries[0]))));
    }
    if (r.kev?.length) {
      g.push(el("h4", {}, t("s.kev", { n: r.kev.length })), ...r.kev.slice(0, 15).map((k) =>
        item(k.cve, `${k.vendor} ${k.product}${k.epss !== null && k.epss !== undefined ? `, EPSS ${dec2(k.epss)}` : ""}`, () => this.cb.onCve(k.cve))));
    }
    if (r.nvd?.length) {
      g.push(el("h4", {}, "NVD"), ...r.nvd.map((c) => item(c.cve, `CVSS ${dec1(c.cvss)} ${c.summary?.slice(0, 80) || ""}`, () => this.cb.onCve(c.cve))));
    }
    if (r.victims?.length) {
      g.push(el("h4", {}, t("s.victims", { n: r.victims.length })), ...r.victims.slice(0, 15).map((v) =>
        item(v.victim, `${v.grp}, ${countryName(v.country)}, ${dateTime(v.discovered)}`, () => v.country && this.cb.onCountry(v.country))));
    }
    const nvdBox = el("div");
    if (r.type === "text" && q.length >= 3) {
      g.push(el("h4", {}, t("s.nvd")), nvdBox);
      nvdBox.replaceChildren(el("div", { class: "empty" }, t("s.nvd_loading")));
      this.loadNvd(q, nvdBox, seq);
    }
    const hasResults = g.some((n) => n.tagName === "BUTTON" && !n.classList.contains("action")) || nvdBox.isConnected || g.includes(nvdBox);
    if (!hasResults) g.unshift(el("div", { class: "empty" }, t("s.none")));
    this.box.replaceChildren(...g);
  }

  async loadNvd(q, box, seq) {
    try {
      const r = await api(`api/search/nvd?q=${encodeURIComponent(q)}`);
      if (seq !== this.seq) return;
      if (!r.cves.length) { box.replaceChildren(el("div", { class: "empty" }, t("s.nvd_none"))); return; }
      box.replaceChildren(...r.cves.slice(0, 25).map((c) => this.item(
        el("span", {}, c.cve, c.kev ? el("span", { class: "tag warn" }, "KEV") : null),
        [c.cvss !== null && c.cvss !== undefined ? `CVSS ${dec1(c.cvss)}` : null, c.epss !== null && c.epss !== undefined ? `EPSS ${dec2(c.epss)}` : null,
          dateOnly(c.published), (c.summary || "").slice(0, 90)].filter(Boolean).join(" · "),
        () => this.cb.onCve(c.cve))));
    } catch (e) {
      if (seq === this.seq) box.replaceChildren(el("div", { class: "empty" }, e.message));
    }
  }

  notice(text) {
    this.box.hidden = false;
    this.box.replaceChildren(el("div", { class: "empty ok-txt" }, text));
    setTimeout(() => this.hide(), 3500);
  }
}
