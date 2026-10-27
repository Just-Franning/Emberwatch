// "My network" area: overview, own IP addresses (home connection and this server), and the asset, product,
// alert and log views (assets.js).
import { Assets } from "./assets.js";
import { t } from "./i18n.js";
import { alertItem } from "./panels.js";
import { go, href, objLink, routes } from "./router.js";
import { ago, api, countryName, dateTime, el, kids, num, sevTag } from "./util.js";

const VIEWS = ["assets", "products", "alerts", "logs", "myip"];
const navLink = (path, label, on) => el("a", { href: href(path), class: on ? "on" : null, title: label }, el("span", { class: "lbl" }, label));
const geoTxt = (g) => (g ? [g.asn ? `AS${g.asn} ${g.as_name || ""}`.trim() : null, g.country ? countryName(g.country) : null].filter(Boolean).join(" · ") : "");

export class Netz {
  constructor({ nav, main, onMap, onChange }) {
    this.navBox = nav;
    this.main = main;
    this.box = el("div", { class: "wrap" });
    kids(this.main, this.box);
    this.assets = new Assets({ body: this.box, scroller: main, onChange, onMap });
    this.onChange = onChange;
    this.status = null;
    this.seq = 0;
    this.token = null; // shown once after creation
  }

  setStatus(status) {
    this.status = status;
    this.assets.setStatus(status);
  }

  leave() { this.assets.hide(); }

  async show(route) {
    const seq = ++this.seq;
    const [view, id] = route.parts;
    kids(this.navBox,
      navLink("netz", t("nz.nav.overview"), !view),
      ...VIEWS.map((v) => navLink(`netz/${v}`, t(`nz.nav.${v}`), view === v)));
    if (["assets", "products", "alerts", "logs"].includes(view)) {
      await this.assets.show(view, id);
      return;
    }
    this.assets.hide();
    this.main.scrollTop = 0;
    kids(this.box, el("p", { class: "state" }, t("common.loading")));
    try {
      if (view === "myip") await this.myip(seq);
      else await this.overview(seq);
    } catch (e) {
      if (seq === this.seq) kids(this.box, el("p", { class: "state err" }, t("common.error", { msg: e.message })));
    }
  }

  // --- overview -----------------------------------------------------------------------------------------------------
  async overview(seq) {
    const d = await api("api/netz/overview");
    if (seq !== this.seq) return;
    const ipLine = (kind) => {
      const m = d.myip[kind];
      const ips = [m.ip, m.ip6].filter(Boolean);
      return el("div", { class: "ipline" }, el("span", { class: "kind" }, t(`myip.kind.${kind}`)),
        ips.length ? ips.flatMap((ip, i) => [i ? " · " : null, objLink("ip", ip, ip, "obj mono")]) : el("span", { class: "muted" }, t("nz.ip_unknown")),
        ips.length ? el("span", { class: "muted" }, ` ${t("nz.since", { t: ago(m.updated_at) })}`) : null,
        ...checkBadges(m.checks));
    };
    const ab = d.assets;
    const st = d.alerts.stats;
    const you = d.you;
    const youHint = you?.public && !you.is_home
      ? el("p", { class: "note" }, t("nz.you_hint", { ip: you.ip }), " ", el("a", { href: href("netz/myip") }, t("nz.you_setup")))
      : null;
    kids(this.box,
      el("h2", { class: "page-title" }, t("nz.title")), el("p", { class: "lead" }, t("nz.lead")),
      el("div", { class: "cards" },
        el("section", { class: "card" }, el("h3", {}, t("nz.nav.myip")), ipLine("home"), ipLine("server"),
          !d.myip_configured && !d.myip.home.ip ? el("p", { class: "note" }, t("nz.myip_setup_hint")) : null, youHint,
          el("a", { class: "btn plain", href: href("netz/myip") }, t("nz.open_myip"))),
        el("section", { class: "card" }, el("h3", {}, t("nz.alerts_7d")),
          el("div", { class: "stats" }, ...["high", "medium", "low"].map((s) => el("span", {}, sevTag(s), num(st[`${s}_7d`] || 0)))),
          d.alerts.latest.length ? el("ol", { class: "patterns" }, d.alerts.latest.slice(0, 5).map((a) => alertItem(a, { onOpen: (x) => go(x.asset_id ? routes.asset(x.asset_id) : routes.product(x.product_id)) })))
            : el("p", { class: "empty" }, t("alerts.none")),
          el("a", { class: "btn plain", href: href("netz/alerts") }, t("nz.all_alerts"))),
        el("section", { class: "card" }, el("h3", {}, t("nz.assets_risk")),
          el("div", { class: "stats" }, ...["high", "medium", "ok"].map((s) => el("span", {}, sevTag(s), num(ab.by_risk[s] || 0)))),
          ab.top.length ? el("ol", { class: "rank" }, ab.top.map((a) => el("li", { class: "clickable", onclick: () => go(routes.asset(a.id)) },
            el("span", { class: "lbl" }, el("span", { class: "kind" }, t(`as.kind.${a.kind}`)), a.kind === "asn" ? `AS${a.value}` : a.value, a.label ? el("span", { class: "muted" }, ` ${a.label}`) : null),
            el("span", { class: "val" }, sevTag(a.risk))))) : el("p", { class: "empty" }, t("as.none")),
          el("p", { class: "note" }, t("as.limit", { n: num(ab.total), max: num(ab.max) })),
          el("a", { class: "btn plain", href: href("netz/assets") }, t("nz.manage_assets"))),
        el("section", { class: "card" }, el("h3", {}, t("nz.nav.products")),
          el("p", {}, t("nz.products_txt", { n: num(d.products.total), kev: num(d.products.with_kev), crit: num(d.products.with_critical) })),
          el("a", { class: "btn plain", href: href("netz/products") }, t("nz.manage_products"))),
        el("section", { class: "card" }, el("h3", {}, t("nz.ops")),
          el("p", {}, d.scan.enabled ? (d.scan.running ? t("nz.scan_running") : t("nz.scan_on")) : t("nz.scan_off")),
          el("p", {}, d.syslog.enabled ? t("nz.syslog_on", { port: d.syslog.port, n: num(d.syslog.received || 0) }) : t("nz.syslog_off")),
          el("a", { class: "btn plain", href: href("netz/logs") }, t("nz.nav.logs")))));
  }

  // --- own IP ------------------------------------------------------------------------------------------------------------
  async myip(seq) {
    const d = await api("api/myip");
    if (seq !== this.seq) return;
    const feedback = el("p", { class: "note", "aria-live": "polite" });
    const fail = (e) => { feedback.className = "state err"; feedback.textContent = e.message; };
    const reload = () => this.myip(this.seq).catch(fail);
    const cfg = d.home.config || {};
    const base = window.location.origin;

    const kindCard = (kind) => {
      const m = d[kind];
      const ips = [m.ip, m.ip6].filter(Boolean);
      const checks = ips.map((ip) => checkTable(ip, m.checks?.[ip], m.geo?.[ip]));
      return el("section", { class: "card" },
        el("h3", {}, t(`myip.kind.${kind}`)),
        el("p", { class: "note" }, t(`nz.myip_${kind}_note`)),
        ips.length ? el("dl", { class: "kv" },
          el("dt", {}, "IPv4"), el("dd", {}, m.ip ? objLink("ip", m.ip, m.ip, "obj mono") : "–"),
          el("dt", {}, "IPv6"), el("dd", {}, m.ip6 ? objLink("ip", m.ip6, m.ip6, "obj mono") : "–"),
          el("dt", {}, t("nz.source")), el("dd", {}, m.source ? t(`myip.src.${m.source}`) : "–"),
          el("dt", {}, t("nz.changed")), el("dd", {}, dateTime(m.updated_at)),
          el("dt", {}, t("nz.checked")), el("dd", {}, m.checked_at ? dateTime(m.checked_at) : t("common.never")))
          : el("p", { class: "empty" }, t("nz.ip_unknown")),
        ...checks,
        m.history?.length ? el("details", {}, el("summary", {}, t("nz.history", { n: num(m.history.length) })),
          el("div", { class: "tbl-wrap" }, el("table", { class: "res" },
            el("thead", {}, el("tr", {}, ["IP", t("nz.first"), t("nz.last"), t("nz.source"), "AS"].map((h) => el("th", {}, h)))),
            el("tbody", {}, m.history.map((h) => el("tr", {}, el("td", {}, objLink("ip", h.ip, h.ip, "obj mono")), el("td", {}, dateTime(h.first_seen)),
              el("td", {}, dateTime(h.last_seen)), el("td", {}, h.source ? t(`myip.src.${h.source}`) : "–"),
              el("td", {}, h.asn ? `AS${h.asn} ${h.as_name || ""}`.trim() : "–"))))))) : null,
        ips.length ? el("div", { class: "btnrow admin-only" },
          el("button", { type: "button", class: "small danger", onclick: async () => {
            if (!window.confirm(t("nz.clear_q", { kind: t(`myip.kind.${kind}`) }))) return;
            try { await api("api/myip/clear", { json: { kind } }); reload(); } catch (e) { fail(e); }
          } }, t("nz.clear"))) : null);
    };

    // detection by visit
    const you = d.you || {};
    const auto = el("input", { type: "checkbox", checked: Boolean(cfg.auto_asn) });
    const visit = el("section", { class: "card" }, el("h3", {}, t("nz.m.visit")),
      you.public
        ? el("div", {},
          el("p", {}, t("nz.m.you", { ip: you.ip }), " ", el("span", { class: "muted" }, geoTxt(you.geo))),
          you.is_home ? el("p", { class: "ok-txt" }, t("nz.m.is_home"))
            : el("div", {}, el("label", { class: "pcheck" }, auto, t("nz.m.auto")),
              el("div", { class: "btnrow" }, el("button", { type: "button", class: "primary", onclick: async () => {
                try { await api("api/myip/confirm", { json: { auto: auto.checked } }); reload(); } catch (e) { fail(e); }
              } }, t("nz.m.take")))),
          cfg.auto_asn ? el("p", { class: "note" }, t("nz.m.auto_on", { asn: cfg.auto_asn }), " ",
            el("button", { type: "button", class: "link", onclick: async () => {
              try { await api("api/myip/config", { json: { auto_asn: false } }); reload(); } catch (e) { fail(e); }
            } }, t("nz.m.auto_off"))) : null)
        : el("p", { class: "note" }, t("nz.m.private", { ip: you.ip || "?" })),
      el("p", { class: "note" }, t("nz.m.visit_note")));

    // DynDNS host name
    const dyn = el("input", { type: "text", maxlength: 253, value: cfg.dyndns || "", placeholder: "home.example.net", spellcheck: "false" });
    const dynForm = el("form", { class: "inline-form" }, dyn, el("button", { type: "submit" }, t("as.d.save")));
    dynForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      try { await api("api/myip/config", { json: { dyndns: dyn.value.trim() } }); feedback.className = "note ok-txt"; feedback.textContent = t("nz.m.saved"); } catch (er) { fail(er); }
    });
    const dynCard = el("section", { class: "card" }, el("h3", {}, t("nz.m.dyndns")), el("p", { class: "note" }, t("nz.m.dyndns_note")), dynForm);

    // reporter token
    const tokenBox = el("div");
    const showToken = (tok) => {
      const curl = `curl -fsS -X POST -H "Authorization: Bearer ${tok}" ${base}/api/myip/report`;
      const ddc = `protocol=dyndns2\nssl=yes\nserver=${window.location.host}\nlogin=emberwatch\npassword='${tok}'\nemberwatch`;
      kids(tokenBox,
        el("p", { class: "warn-txt" }, t("nz.m.token_once")),
        el("pre", { class: "res-pre" }, tok),
        el("h4", {}, t("nz.m.curl")), el("pre", { class: "res-pre" }, curl),
        el("p", { class: "note" }, t("nz.m.curl_note")),
        el("h4", {}, t("nz.m.dyndns2")), el("pre", { class: "res-pre" }, `${base}/nic/update?myip=<ipaddr>`),
        el("p", { class: "note" }, t("nz.m.dyndns2_note")),
        el("h4", {}, "ddclient"), el("pre", { class: "res-pre" }, ddc));
    };
    const tokCard = el("section", { class: "card wide" }, el("h3", {}, t("nz.m.reporter")),
      el("p", { class: "note" }, t("nz.m.reporter_note")),
      el("p", {}, cfg.token_set ? t("nz.m.token_set", { t: dateTime(cfg.token_created) }) : t("nz.m.token_none")),
      el("div", { class: "btnrow" },
        el("button", { type: "button", class: "primary", onclick: async () => {
          if (cfg.token_set && !window.confirm(t("nz.m.token_replace_q"))) return;
          try { const r = await api("api/myip/token", { method: "POST" }); this.token = r.token; reload(); } catch (e) { fail(e); }
        } }, cfg.token_set ? t("nz.m.token_renew") : t("nz.m.token_new")),
        cfg.token_set ? el("button", { type: "button", class: "danger", onclick: async () => {
          if (!window.confirm(t("nz.m.token_revoke_q"))) return;
          try { await api("api/myip/token", { method: "DELETE" }); reload(); } catch (e) { fail(e); }
        } }, t("nz.m.token_revoke")) : null),
      tokenBox,
      el("p", { class: "note" }, t("nz.m.proxy_note")));

    const sightings = d.sightings?.length ? el("section", { class: "card wide" }, el("h3", {}, t("nz.m.sightings")),
      el("p", { class: "note" }, t("nz.m.sightings_note")),
      el("div", { class: "tbl-wrap" }, el("table", { class: "res" },
        el("thead", {}, el("tr", {}, ["IP", t("nz.m.count"), t("nz.first"), t("nz.last"), "AS", t("c2.country")].map((h) => el("th", {}, h)))),
        el("tbody", {}, d.sightings.map((s) => el("tr", {}, el("td", {}, objLink("ip", s.ip, s.ip, "obj mono")), el("td", {}, num(s.count)),
          el("td", {}, dateTime(s.first_seen)), el("td", {}, dateTime(s.last_seen)), el("td", {}, s.asn ? `AS${s.asn} ${s.as_name || ""}`.trim() : "–"),
          el("td", {}, s.country ? countryName(s.country) : "–"))))))) : null;

    const checkBtn = el("button", { type: "button", onclick: async () => {
      try { await api("api/myip/check", { method: "POST" }); feedback.className = "note"; feedback.textContent = t("nz.m.check_started"); setTimeout(reload, 4000); } catch (e) { fail(e); }
    } }, t("common.check_now"));
    kids(this.box,
      el("h2", { class: "page-title" }, t("nz.nav.myip")), el("p", { class: "lead" }, t("nz.m.lead")),
      el("div", { class: "btnrow admin-only" }, checkBtn), feedback,
      el("div", { class: "cards" }, kindCard("home"), kindCard("server")),
      el("h3", { class: "page-h admin-only" }, t("nz.m.setup")),
      el("div", { class: "cards admin-only" }, visit, dynCard, tokCard), sightings);
    if (this.token) { showToken(this.token); this.token = null; }
  }
}

function checkBadges(checks) {
  const out = [];
  for (const [ip, c] of Object.entries(checks || {})) {
    if (c.drop) out.push(el("span", { class: "tag bad", title: ip }, "DROP"));
    if (c.tor) out.push(el("span", { class: "tag warn", title: ip }, "Tor"));
    if (c.threats?.length) out.push(el("span", { class: "tag bad", title: ip }, t("nz.threats")));
    if ((c.abuseipdb?.score ?? 0) >= 25) out.push(el("span", { class: "tag warn", title: ip }, `AbuseIPDB ${c.abuseipdb.score}`));
    const ports = c.internetdb?.status === "ok" ? c.internetdb.ports || [] : [];
    if (ports.length) out.push(el("span", { class: "tag", title: ip }, t("nz.ports", { list: ports.slice(0, 6).join(", ") })));
  }
  return out;
}

function checkTable(ip, c, g) {
  if (!c) return el("p", { class: "note" }, t("nz.not_checked", { ip }));
  const ab = c.abuseipdb || {};
  const idb = c.internetdb || {};
  const abTxt = ab.status === "ok" ? el("span", { class: ab.score >= 75 ? "bad-txt" : ab.score >= 25 ? "warn-txt" : "ok-txt" }, t("nz.abuse", { s: ab.score ?? 0, n: num(ab.reports ?? 0) }))
    : t(`nz.abuse_${["disabled", "budget", "private"].includes(ab.status) ? ab.status : "na"}`);
  const idbTxt = idb.status === "ok"
    ? [idb.ports?.length ? t("nz.ports", { list: idb.ports.join(", ") }) : t("nz.no_ports"), idb.vulns?.length ? ` · ${t("nz.vulns", { n: num(idb.vulns.length) })}` : ""].join("")
    : idb.status === "none" ? t("nz.idb_none") : t("nz.idb_error");
  return el("div", { class: "checks" }, el("h4", {}, ip, " ", el("span", { class: "muted" }, geoTxt(g))),
    el("dl", { class: "kv" },
      el("dt", {}, "Spamhaus DROP"), el("dd", { class: c.drop ? "bad-txt" : "ok-txt" }, c.drop ? c.drop.cidr : t("common.no")),
      el("dt", {}, "Tor"), el("dd", { class: c.tor ? "warn-txt" : null }, c.tor ? t("common.yes") : t("common.no")),
      el("dt", {}, t("nz.threat_data")), el("dd", { class: c.threats?.length ? "bad-txt" : "ok-txt" },
        c.threats?.length ? c.threats.map((x) => x.malware || x.kind).join(", ") : t("nz.not_listed")),
      el("dt", {}, "AbuseIPDB"), el("dd", {}, abTxt),
      el("dt", {}, "Shodan InternetDB"), el("dd", {}, idbTxt)));
}

