// "Who owns this IP" (Cyberlage, side tab "Firma"): the company that uses a public address, with contact, the
// registry entry of the network, the evidence chain and a confidence; seat of the company and location of the address
// on the map. A new lookup needs the role admin (it contacts the address and the company website); stored results of
// the last 7 days can be read by everyone.
import { t } from "./i18n.js";
import { objLink } from "./router.js";
import { ndjson } from "./runner.js";
import { isAdmin } from "./session.js";
import { api, countryName, dateTime, el, kids, safeLink } from "./util.js";

const STEPS = ["rdap", "dns", "tls", "domains", "imprint", "geocode"];
const LEVEL = { high: 3, medium: 2, low: 1 };
const IP_RE = /^[0-9a-fA-F:.[\]]{2,60}$/;

const confidence = (c) => el("span", { class: `ow-conf conf-${c}` },
  el("span", { class: "meter", "aria-hidden": "true" }, [1, 2, 3].map((i) => el("i", { class: i <= (LEVEL[c] || 1) ? "on" : null }))),
  t(`ow.conf.${c}`));

const EVIDENCE = ["rdap_holder", "rdap_assigned", "as", "ptr", "ptr_generic", "cert_org", "cert_names", "domain_here", "imprint", "jsonld",
  "imprint_failed", "geocoded"];

/** One step of the evidence chain (codes of owner/lookup.py), in the interface language. */
function evidence(e) {
  const p = e.params || {};
  if (!EVIDENCE.includes(e.code)) return e.code;
  if (e.code === "imprint_failed") return t("ow.ev.imprint_failed", { domain: p.domain, reason: t(`ow.why.${["unreachable", "robots", "none"].includes(p.reason) ? p.reason : "none"}`) });
  if (e.code === "imprint" || e.code === "jsonld") return el("span", {}, t(`ow.ev.${e.code}`, { domain: p.domain }), " ", safeLink(p.url, "↗"));
  if (e.code === "cert_org") {
    const place = [p.town, /^[A-Z]{2}$/.test(p.country || "") ? countryName(p.country) : p.country].filter(Boolean).join(", ");
    return t("ow.ev.cert_org", { org: p.org, place: place ? ` (${place})` : "" });
  }
  return t(`ow.ev.${e.code}`, p);
}

export class Owner {
  constructor({ box, onMap, onClear }) {
    this.box = box;
    this.onMap = onMap; // ({points, paths}, label) => void
    this.onClear = onClear; // () => void: removes what an earlier result drew on the map
    this.drawn = false;
    this.run = null;
    this.result = null;
    this.input = el("input", { type: "text", maxlength: 60, spellcheck: "false", placeholder: t("ow.ph"), "aria-label": t("ow.ip") });
    this.active = el("input", { type: "checkbox", checked: true });
    this.out = el("div", { class: "ow-out", "aria-live": "polite" });
    this.form = el("form", { class: "ow-form", autocomplete: "off", onsubmit: (e) => { e.preventDefault(); this.lookup(this.input.value.trim()); } },
      this.input, el("button", { type: "submit", class: "primary admin-only" }, t("ow.go")),
      el("button", { type: "button", class: "viewer-only", onclick: () => this.open(this.input.value.trim()) }, t("ow.show")),
      el("label", { class: "check admin-only", title: t("ow.active_title") }, this.active, t("ow.active")));
    kids(this.box, el("h3", { class: "tp-h" }, t("ow.title")), el("p", { class: "note" }, t("ow.lead")), this.form, this.out);
    this.empty();
  }

  empty() {
    kids(this.out, el("p", { class: "empty" }, t(isAdmin() ? "ow.empty" : "ow.empty_viewer")));
  }

  /** Shows the stored result for an address (no lookup); with run=true an administrator looks it up if there is none. */
  async open(ip, { run = false } = {}) {
    if (!ip) return;
    this.input.value = ip;
    try {
      const d = await api(`api/owner?ip=${encodeURIComponent(ip)}`);
      if (d.result) this.render(d.result);
      else if (run && isAdmin()) this.lookup(d.ip);
      else kids(this.out, el("p", { class: "empty" }, t(isAdmin() ? "ow.none_yet" : "ow.none_viewer", { ip: d.ip })));
    } catch (e) {
      kids(this.out, el("p", { class: "state err" }, e.message));
    }
  }

  lookup(ip, { refresh = false } = {}) {
    if (!ip || !IP_RE.test(ip)) {
      kids(this.out, el("p", { class: "state err" }, t("ow.bad_ip")));
      return;
    }
    if (this.run) this.run.abort();
    const ctl = new AbortController();
    this.run = ctl;
    const steps = Object.fromEntries(STEPS.map((s) => [s, el("li", { class: "todo" }, t(`ow.step.${s}`))]));
    if (!this.active.checked) { steps.tls.hidden = true; steps.imprint.hidden = true; }
    kids(this.out, el("ol", { class: "ow-steps" }, Object.values(steps)));
    let current = null;
    (async () => {
      try {
        for await (const ev of ndjson("api/owner", { ip, active: this.active.checked, refresh }, ctl.signal)) {
          if (ev.type === "step") {
            if (current) current.className = "done";
            current = steps[ev.step];
            if (current) {
              current.className = "now";
              if (ev.domain) current.textContent = t("ow.step.imprint_d", { domain: ev.domain });
            }
          } else if (ev.type === "result") {
            this.render(ev.result);
            return;
          } else if (ev.type === "error") {
            kids(this.out, el("p", { class: "state err" }, ev.text || ev.key));
            return;
          }
        }
      } catch (e) {
        if (e.name !== "AbortError") kids(this.out, el("p", { class: "state err" }, e.message));
      } finally {
        if (this.run === ctl) this.run = null;
      }
    })();
  }

  mapData(r) {
    const points = [];
    const paths = [];
    const loc = r.location;
    const ipl = r.ip_location;
    const name = r.company?.company;
    if (loc && Number.isFinite(loc.lat) && loc.precision !== "ip") points.push({ lon: loc.lon, lat: loc.lat, kind: "target", label: name || t("ow.seat") });
    if (ipl && Number.isFinite(ipl.lat)) points.push({ lon: ipl.lon, lat: ipl.lat, kind: "hop", label: t("ow.ip_place", { ip: r.ip }) });
    if (points.length === 2) paths.push({ coords: points.map((p) => [p.lon, p.lat]) });
    return { points, paths };
  }

  render(r) {
    this.result = r;
    const c = r.company || {};
    const n = r.network || {};
    const contact = r.contact || {};
    const addr = c.street || c.postcode || c.city ? [c.street, [c.postcode, c.city].filter(Boolean).join(" "), c.country ? countryName(c.country) : null].filter(Boolean)
      : c.address ? String(c.address).split("\n") : [];
    const kv = (rows) => el("dl", { class: "kv" }, rows.filter(([, v]) => v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && !v.length))
      .flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
    const people = (c.people || []).map(([who, role]) => `${who} (${t(`ow.role.${role}`)})`).join(", ");
    const map = this.mapData(r);
    const asLink = r.as ? objLink("asn", String(r.as.asn), `AS${r.as.asn} ${r.as.name || ""}`.trim()) : null;
    kids(this.out, el("article", { class: "ow-result" },
      el("header", { class: "ow-head" },
        el("p", { class: "ow-ip mono" }, objLink("ip", r.ip, r.ip), asLink ? [" · ", asLink] : null),
        el("h3", { class: "ow-name" }, c.company || t("ow.unknown")),
        el("div", { class: "ow-sub" }, confidence(r.confidence), c.source ? el("span", { class: "note" }, t(`ow.src.${c.source}`)) : null)),
      kv([
        [t("ow.address"), addr.length ? addr.flatMap((x, i) => (i ? [el("br"), x] : [x])) : null],
        [t("ow.phone"), contact.phone ? el("a", { href: `tel:${contact.phone.replace(/[^+\d]/g, "")}` }, contact.phone) : null],
        [t("ow.email"), contact.email ? el("a", { href: `mailto:${contact.email}` }, contact.email) : null],
        [t("ow.web"), contact.web ? safeLink(contact.web, contact.web.replace(/^https:\/\//, "").replace(/\/$/, "")) : null],
        [t("ow.people"), people || null],
        [t("ow.register"), c.register || null],
        [t("ow.vat"), c.vat_id || null],
        [t("ow.abuse"), r.abuse?.email ? el("a", { href: `mailto:${r.abuse.email}` }, r.abuse.email) : null],
      ]),
      el("div", { class: "row" },
        map.points.length ? el("button", { type: "button", class: "primary", onclick: () => this.onMap(map, c.company || r.ip) }, t("common.show_map")) : null,
        objLink("ip", r.ip, t("ow.object"), "btn"),
        isAdmin() ? el("button", { type: "button", onclick: () => this.lookup(r.ip, { refresh: true }) }, t("ow.again")) : null),
      r.network ? el("h4", {}, t("ow.network")) : null,
      r.network ? kv([
        [t("ow.n.name"), n.name], [t("ow.n.range"), n.range ? n.range.join(" – ") : null], [t("ow.n.type"), n.type ? `${n.type} · ${t(n.assigned ? "ow.n.assigned" : "ow.n.allocated")}` : null],
        [t("ow.n.holder"), n.holder?.name], [t("ow.n.country"), n.country ? countryName(n.country) : null],
        [t("ow.n.descr"), n.descr?.length ? n.descr.join(" · ") : null],
        [t("ow.n.contacts"), (n.contacts || []).map((x) => [x.name, x.email].filter(Boolean).join(", ")).filter(Boolean).join(" · ") || null],
      ]) : null,
      r.domains?.length ? el("div", {}, el("h4", {}, t("ow.domains")),
        el("ul", { class: "ow-domains" }, r.domains.slice(0, 12).map((d) => el("li", { class: d.provider ? "muted" : null },
          objLink("domain", d.domain, d.domain), " ", el("span", { class: "note" },
            [...d.sources.map((x) => t(`ow.ds.${x}`)), d.points_here ? t("ow.ds.here") : null, d.provider ? t("ow.ds.provider") : null].filter(Boolean).join(" · ")))))) : null,
      r.evidence?.length ? el("h4", {}, t("ow.evidence")) : null,
      r.evidence?.length ? el("ol", { class: "ow-evidence" }, r.evidence.map((e) => el("li", { class: e.code === "imprint_failed" || e.code === "ptr_generic" ? "weak" : null }, evidence(e)))) : null,
      (r.notes || []).length ? el("ul", { class: "ow-notes" }, r.notes.filter((x) => ["passive", "shared_possible", "rdap_failed"].includes(x.code))
        .map((x) => el("li", {}, t(`ow.note.${x.code}`)))) : null,
      el("p", { class: "note" }, t("ow.stamp", { t: dateTime(r.fetched_at) }), r.cached ? ` · ${t("ow.cached")}` : "", " · ", t("ow.sources"),
        r.location?.source === "nominatim" ? [" · ", el("a", { href: "https://www.openstreetmap.org/copyright", target: "_blank", rel: "noopener noreferrer" }, t("ow.osm"))] : null)));
    if (map.points.length) {
      this.onMap(map, c.company || r.ip);
      this.drawn = true;
    } else if (this.drawn) { // the map must not keep showing the company of the previous address
      this.onClear?.();
      this.drawn = false;
    }
  }
}
