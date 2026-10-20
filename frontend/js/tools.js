// Network tools with live map display: ping, traceroute (SSE stream), DNS, RDAP/whois, IP info, ports, HTTP/TLS.
import { t } from "./i18n.js";
import { api, countryName, dateTime, el, num, safeLink } from "./util.js";

const TOOLS = {
  ping: { fields: [["target", "tool.f.target_host", "text", ""], ["count", "tool.f.count", "number", 5, 1, 20]], stream: true },
  traceroute: { fields: [["target", "tool.f.target_host", "text", ""], ["max_hops", "tool.f.max_hops", "number", 30, 1, 40]], stream: true },
  dns: { fields: [["target", "tool.f.dns_target", "text", ""], ["resolver", "tool.f.resolver", "select", "cloudflare"]] },
  rdap: { fields: [["target", "tool.f.rdap_target", "text", ""]] },
  ipinfo: { fields: [["target", "tool.f.ip_or_host", "text", ""]] },
  ports: { fields: [["target", "tool.f.target_host", "text", ""], ["ports", "tool.f.ports", "text", "22,80,443"]] },
  http: { fields: [["target", "tool.f.url", "text", ""]] },
};
const RESOLVERS = [["cloudflare", "Cloudflare 1.1.1.1"], ["google", "Google 8.8.8.8"], ["quad9", "Quad9 9.9.9.9"], ["system", null]];

const kv = (pairs) => el("dl", { class: "kv" }, pairs.filter(([, v]) => v !== undefined && v !== null && v !== "").flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]));
const where = (g) => (g ? [g.city, countryName(g.country)].filter(Boolean).join(", ") : "–");
const asTxt = (g) => (g?.asn ? `AS${g.asn} ${g.as_name || ""}`.trim() : "–");
const hasGeo = (g) => g?.lat !== undefined && g?.lat !== null;

function pt(lon, lat, props) {
  const clean = Object.fromEntries(Object.entries(props).filter(([, v]) => v !== undefined && v !== null));
  return { type: "Feature", geometry: { type: "Point", coordinates: [lon, lat] }, properties: clean };
}

export class Tools {
  constructor(map) {
    this.map = map;
    this.panel = document.getElementById("panel-tools");
    this.form = document.getElementById("tool-form");
    this.out = document.getElementById("tool-out");
    this.tool = "ping";
    this.es = null;
    document.querySelectorAll("#panel-tools .tool-tabs button").forEach((b) => b.addEventListener("click", () => this.select(b.dataset.tool)));
    document.getElementById("tools-close").addEventListener("click", () => this.close());
    this.form.addEventListener("submit", (e) => { e.preventDefault(); this.run(); });
    this.select("ping");
  }

  open(tool, target, autorun = false) {
    this.panel.hidden = false;
    if (tool) this.select(tool);
    if (target) this.form.elements.target.value = target;
    if (autorun && target) this.run();
    else this.form.elements.target.focus();
  }

  close() {
    this.stop();
    this.panel.hidden = true;
  }

  toggle() { if (this.panel.hidden) this.open(); else this.close(); }

  select(tool) {
    const prev = this.form.elements?.target?.value || "";
    this.tool = tool;
    document.querySelectorAll("#panel-tools .tool-tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tool === tool)));
    const fields = TOOLS[tool].fields.map(([name, label, type, def, min, max]) => {
      let input;
      if (type === "select") {
        input = el("select", { name }, ...RESOLVERS.map(([v, l]) => el("option", { value: v, selected: v === def }, l || t("tool.resolver.system"))));
      } else {
        input = el("input", { name, type, value: name === "target" ? prev : def, min, max, required: name === "target", maxlength: name === "target" ? 500 : 80, spellcheck: "false" });
      }
      return el("label", { class: name === "target" ? "grow" : null }, t(label), input);
    });
    this.form.replaceChildren(...fields, el("button", { type: "submit", class: "primary" }, t("common.run")),
      el("button", { type: "button", onclick: () => { this.stop(); this.map.clearTool(); this.out.replaceChildren(); } }, t("common.clear")));
  }

  stop() {
    if (this.es) { this.es.close(); this.es = null; }
  }

  setOut(...nodes) {
    this.out.replaceChildren(...nodes.filter((n) => n !== null && n !== undefined && n !== false));
  }

  params() {
    const p = new URLSearchParams();
    for (const [name] of TOOLS[this.tool].fields) {
      const v = this.form.elements[name]?.value?.trim();
      if (v) p.set(name, v);
    }
    return p;
  }

  async run() {
    this.stop();
    this.map.clearTool();
    const p = this.params();
    if (!p.get("target")) return;
    this.out.replaceChildren(el("p", { class: "hint" }, t("common.running")));
    if (TOOLS[this.tool].stream) return this.stream(p);
    try {
      const r = await api(`api/tools/${this.tool}?${p}`);
      this[`render_${this.tool}`](r);
    } catch (e) {
      this.out.replaceChildren(el("p", { class: "state err" }, e.message));
    }
  }

  // --- ping & traceroute (server-sent events) ----------------------------------------------
  stream(p) {
    const tool = this.tool;
    const rows = el("tbody");
    const head = tool === "ping"
      ? el("tr", {}, el("th", {}, t("tool.seq")), el("th", {}, t("tool.ttl")), el("th", {}, t("tool.rtt")), el("th", {}, t("tool.method")))
      : el("tr", {}, el("th", {}, t("tool.hop")), el("th", {}, t("tool.host")), el("th", {}, t("tool.loc_as")), el("th", {}, t("tool.rtt")));
    const info = el("div");
    const summary = el("div");
    this.out.replaceChildren(info, el("table", {}, el("thead", {}, head), rows), summary);
    const pts = [];
    const feats = [];
    const redraw = () => this.map.setTool([...this.map.toolPath(pts.map((x) => x.c)), ...feats]);
    const es = new EventSource(`api/tools/${tool}?${p}`);
    this.es = es;
    const data = (e) => { try { return JSON.parse(e.data); } catch { return {}; } };
    es.addEventListener("start", (e) => {
      const d = data(e);
      info.replaceChildren(kv([[t("tool.target"), `${d.target} (${d.ip})`], [t("tool.location"), d.geo ? `${where(d.geo)}, ${asTxt(d.geo)}` : t("common.unknown")],
        ...(d.origin ? [[t("tool.start"), d.origin.ip ? `${d.origin.ip}, ${where(d.origin)}` : t("tool.server_unknown")]] : [])]));
      if (hasGeo(d.origin)) {
        pts.push({ c: [d.origin.lon, d.origin.lat] });
        feats.push(pt(d.origin.lon, d.origin.lat, { kind: "origin", label: t("map.server"), ip: d.origin.ip }));
      }
      if (hasGeo(d.geo)) {
        feats.push(pt(d.geo.lon, d.geo.lat, { kind: "target", label: tool === "ping" ? d.target : undefined, ip: d.ip }));
        if (tool === "ping") {
          if (pts.length) pts.push({ c: [d.geo.lon, d.geo.lat] });
          this.map.flyTo(d.geo.lon, d.geo.lat, 3);
        }
      }
      redraw();
    });
    es.addEventListener("reply", (e) => {
      const d = data(e);
      rows.append(el("tr", {}, el("td", {}, d.seq), el("td", {}, d.ttl ?? "–"), el("td", { class: "num" }, `${d.rtt} ms`), el("td", {}, d.method)));
    });
    es.addEventListener("timeout", (e) => {
      const d = data(e);
      rows.append(el("tr", {}, el("td", {}, d.seq), el("td", {}, "–"), el("td", { class: "num warn-txt" }, t("tool.no_reply")), el("td", {}, "")));
    });
    es.addEventListener("hop", (e) => {
      const d = data(e);
      const host = d.ip ? `${d.ip}${d.ptr ? " (" + d.ptr + ")" : ""}` : "*";
      const loc = d.private ? t("tool.private") : d.geo ? `${where(d.geo)}; ${asTxt(d.geo)}` : d.ip ? t("common.unknown") : "";
      rows.append(el("tr", {}, el("td", {}, d.n), el("td", {}, host, d.c2 ? el("span", { class: "tag warn" }, `C2: ${d.c2.map((x) => x.malware).join(", ")}`) : null),
        el("td", {}, loc), el("td", { class: "num" }, d.rtt !== null && d.rtt !== undefined ? `${d.rtt} ms${d.note ? " " + d.note : ""}` : "–")));
      if (hasGeo(d.geo)) {
        pts.push({ c: [d.geo.lon, d.geo.lat] });
        feats.push(pt(d.geo.lon, d.geo.lat, { kind: "hop", label: String(d.n), ip: d.ip }));
        redraw();
      }
    });
    es.addEventListener("info", (e) => info.append(el("p", { class: "hint" }, data(e).text)));
    es.addEventListener("done", (e) => {
      const d = data(e);
      if (tool === "ping") {
        summary.replaceChildren(kv([[t("tool.sent_recv"), `${d.sent} / ${d.received}`], [t("tool.loss"), `${d.loss_pct} %`],
          [t("tool.rtt_stats"), d.avg !== null ? `${d.min} / ${d.avg} / ${d.max} ms` : "–"]]));
      } else {
        summary.replaceChildren(el("p", { class: d.reached ? "hint ok-txt" : "hint warn-txt" }, t(d.reached ? "tool.reached" : "tool.not_reached")));
        if (pts.length > 1) this.map.fitTo(pts.map((x) => x.c));
      }
    });
    es.addEventListener("error", (e) => {
      if (e.data) summary.append(el("p", { class: "state err" }, data(e).text || t("common.error", { msg: "?" })));
      else if (es.readyState !== EventSource.CLOSED) summary.append(el("p", { class: "state err" }, t("tool.stream_lost")));
      this.stop();
    });
    es.addEventListener("end", () => this.stop());
  }

  // --- single requests -------------------------------------------------------------------------
  render_dns(r) {
    const markers = (r.geo || []).map((g) => pt(g.lon, g.lat, { kind: "target", label: g.ip, ip: g.ip }));
    this.map.setTool(markers);
    if (markers.length) this.map.flyTo(r.geo[0].lon, r.geo[0].lat, 3);
    const tables = Object.entries(r.records).map(([type, recs]) => el("tr", {}, el("td", {}, type),
      el("td", {}, ...recs.map((x) => el("div", { class: x.error ? "warn-txt" : null }, x.error || x.value))),
      el("td", { class: "num" }, recs[0]?.ttl ?? "")));
    const ms = r.mail_security;
    this.setOut(
      kv([[t("tool.query"), r.target], [t("tool.f.resolver"), r.resolver], [t("tool.ad"), r.ad_flag === null ? "–" : t(r.ad_flag ? "tool.ad_set" : "tool.ad_unset")],
        ...(ms ? [["SPF", ms.spf.length ? ms.spf.join(" | ") : t("tool.spf_none")], ["DMARC", ms.dmarc.length ? ms.dmarc.join(" | ") : t("tool.dmarc_none")]] : [])]),
      el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, t("tool.type")), el("th", {}, t("tool.value")), el("th", {}, "TTL"))), el("tbody", {}, tables)));
  }

  render_rdap(r) {
    const s = r.summary || {};
    const raw = el("pre");
    raw.textContent = JSON.stringify(r.raw, null, 2).slice(0, 60000);
    this.setOut(
      kv([[t("tool.query"), `${r.kind}: ${r.query}`], [t("tool.object"), s.object], [t("tool.handle"), s.handle], [t("tool.name"), s.name], [t("tool.type"), s.type],
        [t("tool.country"), s.country ? countryName(s.country) : null], [t("tool.range"), s.range ? s.range.join(" – ") : null],
        [t("tool.as_range"), s.autnum ? s.autnum.join(" – ") : null], [t("tool.status"), (s.status || []).join(", ")],
        [t("tool.nameservers"), (s.nameservers || []).join(", ")], ["port43", s.port43]]),
      s.events?.length ? el("h4", {}, t("tool.events")) : null,
      s.events?.length ? kv(s.events.map((e) => [e.action, dateTime(e.date)])) : null,
      s.entities?.length ? el("h4", {}, t("tool.contacts")) : null,
      s.entities?.length ? el("table", {}, el("tbody", {}, s.entities.map((e) => el("tr", {},
        el("td", {}, (e.roles || []).join(", ")), el("td", {}, [e.fn, e.org].filter(Boolean).join(", ") || e.handle || "–"), el("td", {}, e.email || ""))))) : null,
      el("details", {}, el("summary", {}, t("tool.raw")), raw));
  }

  reputation(rep) {
    if (!rep) return null;
    const ab = rep.abuseipdb || {};
    let abTxt;
    if (ab.status === "ok") abTxt = el("span", { class: ab.score >= 75 ? "bad-txt" : ab.score >= 25 ? "warn-txt" : "ok-txt" },
      t("tool.abuse_score", { s: ab.score ?? "–", r: num(ab.reports ?? 0), u: [ab.usage, ab.isp].filter(Boolean).join(", ") || "–" }), " ", safeLink(ab.link, "↗"));
    else abTxt = t({ disabled: "tool.abuse_disabled", budget: "tool.abuse_budget", private: "tool.abuse_private" }[ab.status] || "tool.abuse_error");
    return [el("h4", {}, t("tool.reputation")), kv([
      [t("tool.drop"), rep.drop ? el("span", { class: "bad-txt" }, `${rep.drop.cidr} (${rep.drop.sblid || "SBL"})`) : t("tool.drop_no")],
      [t("tool.tor"), rep.tor ? el("span", { class: "warn-txt" }, t("common.yes")) : t("common.no")],
      [t("tool.abuseipdb"), abTxt]])];
  }

  render_ipinfo(r) {
    if (hasGeo(r.geo)) {
      this.map.setTool([pt(r.geo.lon, r.geo.lat, { kind: "target", label: r.ip, ip: r.ip })]);
      this.map.flyTo(r.geo.lon, r.geo.lat, 4);
    }
    const rt = r.routing || {};
    const fromAbuse = (u) => (u && /^https:\/\/(threatfox|feodotracker)\.abuse\.ch\//.test(u) ? safeLink(u, "abuse.ch") : "");
    this.setOut(
      kv([["IP", r.ip], ["PTR", r.ptr || "–"], [t("tool.loc_dbip"), where(r.geo)], [t("tool.as_dbip"), asTxt(r.geo)],
        [t("tool.prefix"), rt.error || rt.prefix], [t("tool.announced"), rt.announced === undefined ? null : t(rt.announced ? "common.yes" : "common.no")],
        [t("tool.origin_as"), (rt.asns || []).map((a) => `AS${a.asn} ${a.holder || ""}`.trim()).join(", ")]]),
      ...(this.reputation(r.reputation) || []),
      el("h4", {}, t("tool.c2_entries", { n: num(r.c2.length) })),
      r.c2.length ? el("table", {}, el("tbody", {}, r.c2.map((c) => el("tr", {}, el("td", {}, c.malware), el("td", {}, c.ioc), el("td", {}, dateTime(c.first_seen)),
        el("td", {}, fromAbuse(c.reference)))))) : el("p", { class: "hint" }, t("tool.not_c2")),
      r.iocs?.length ? el("h4", {}, t("tool.iocs", { n: num(r.iocs.length) })) : null,
      r.iocs?.length ? el("table", {}, el("tbody", {}, r.iocs.map((c) => el("tr", {}, el("td", {}, c.threat_type || ""), el("td", {}, c.malware || ""),
        el("td", {}, c.ioc), el("td", {}, fromAbuse(c.reference)))))) : null,
      el("h4", {}, t("tool.infra", { n: num(r.infra.length) })),
      r.infra.length ? el("table", {}, el("tbody", {}, r.infra.map((e) => el("tr", {}, el("td", {}, e.title), el("td", {}, dateTime(e.start_ts)), el("td", {}, e.detail || ""))))) : null,
      el("div", { class: "btnrow" },
        el("button", { type: "button", onclick: () => this.open("rdap", r.ip, true) }, t("tool.rdap")),
        el("button", { type: "button", onclick: () => this.open("traceroute", r.ip, true) }, t("tool.traceroute"))));
  }

  render_ports(r) {
    if (hasGeo(r.geo)) this.map.setTool([pt(r.geo.lon, r.geo.lat, { kind: "target", label: r.target, ip: r.ip })]);
    this.setOut(kv([[t("tool.target"), `${r.target} (${r.ip})`]]),
      el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, t("tool.port")), el("th", {}, t("tool.status")), el("th", {}, t("tool.time")))),
        el("tbody", {}, r.results.map((x) => el("tr", {}, el("td", {}, x.port),
          el("td", { class: x.state === "open" ? "ok-txt" : x.state === "closed" ? "" : "warn-txt" }, x.label || x.state),
          el("td", { class: "num" }, x.ms !== null ? `${x.ms} ms` : "–"))))),
      el("p", { class: "hint" }, t("tool.ports_hint")));
  }

  render_http(r) {
    if (hasGeo(r.geo)) this.map.setTool([pt(r.geo.lon, r.geo.lat, { kind: "target", label: r.ip, ip: r.ip })]);
    const tl = r.tls;
    const h = r.http || {};
    const sec = Object.entries(r.security_headers || {});
    this.setOut(
      kv([["URL", r.url], ["IP", r.ip], [t("tool.response"), h.error || h.status], [t("tool.time"), h.ms !== undefined ? `${h.ms} ms` : null]]),
      tl ? el("h4", {}, t("tool.tls")) : null,
      tl ? (tl.error ? el("p", { class: "state err" }, tl.error) : kv([
        [t("tool.validity"), el("span", { class: tl.valid ? "ok-txt" : tl.valid === false ? "bad-txt" : "warn-txt" }, tl.validation)],
        [t("tool.proto_cipher"), `${tl.version || "–"} / ${tl.cipher || "–"}`], [t("tool.subject"), tl.subject], [t("tool.issuer"), tl.issuer],
        [t("tool.san"), (tl.san || []).slice(0, 12).join(", ") + ((tl.san || []).length > 12 ? " …" : "")],
        [t("tool.valid_until"), tl.not_after ? t("tool.days_left", { t: dateTime(tl.not_after), n: tl.days_left }) : null],
        [t("tool.key_sig"), `${tl.key || "–"} / ${tl.signature || "–"}`]])) : null,
      el("h4", {}, t("tool.sec_headers")),
      kv(sec.map(([k, v]) => [k, el("span", { class: v ? "ok-txt" : "warn-txt" }, v || t("tool.header_missing"))])),
      Object.keys(r.disclosure || {}).length ? el("h4", {}, t("tool.disclosure")) : null,
      Object.keys(r.disclosure || {}).length ? kv(Object.entries(r.disclosure)) : null,
      el("details", {}, el("summary", {}, t("tool.all_headers")), el("table", {}, el("tbody", {}, (h.headers || []).map(([k, v]) => el("tr", {}, el("td", {}, k), el("td", {}, v)))))),
      el("p", { class: "hint" }, t("tool.http_hint")));
  }
}
