"""Object pages for the analysis area: everything the local data knows about an IP, network, AS, domain, URL, hash, CVE,
country, malware family, ransomware group or vendor, with a risk assessment, the relation to the user's own assets
and the tools that fit. Object pages only read local data (and cached third-party answers); nothing is sent anywhere,
except that a CVE page loads the CVE from NVD once if it is not cached yet.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from . import alerts, i18n
from .config import Settings
from .db import DB
from .domains import registrable
from .geo import Geo
from .i18n import AppError
from .logs import _norm_url
from .toolbox import registry as tbreg
from .toolbox import runner as tbrun
from .toolbox.common import cache_get
from .toolbox.detect import detect
from .toolbox.result import Result, cell, max_sev

TYPES = ("ip", "cidr", "asn", "domain", "url", "hash", "cve", "country", "malware", "group", "vendor", "actor")


def _cutoff(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _d(v: Any) -> str:
    return str(v)[:16].replace("T", " ") if v else "–"


def _needle_re(needle: str, kind: str) -> re.Pattern[str]:
    """The object value as a whole token inside the JSON of alert parameters (see Objects._alerts_with)."""
    n = re.escape(needle)
    if kind == "domain":  # subdomains, mail addresses and URLs count: www.example.de, a@example.de, https://example.de/x
        return re.compile(r"(?<![A-Za-z0-9_-])" + n + r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9])", re.I)
    if kind == "ip" and ":" in needle:
        return re.compile(r"(?<![A-Za-z0-9_.:-])" + n + r"(?![A-Za-z0-9_:-]|\.[0-9])", re.I)
    if kind == "ip":  # 1.2.3.4:443 and client:1.2.3.4 count
        return re.compile(r"(?<![A-Za-z0-9_.-])" + n + r"(?![A-Za-z0-9_-]|\.[0-9])", re.I)
    return re.compile(r"(?<![A-Za-z0-9_.-])" + n + r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9])", re.I)


def _asn_field(v: Any, asn: int, key: str = "") -> bool:
    if isinstance(v, dict):
        return any(_asn_field(x, asn, str(k)) for k, x in v.items())
    if isinstance(v, list):
        return any(_asn_field(x, asn, key) for x in v)
    return isinstance(v, int) and not isinstance(v, bool) and v == asn and any(s in key for s in ("asn", "origin", "expected"))


def normalize(otype: str, value: str) -> str:
    """Validated, canonical object value. Raises AppError for invalid input."""
    v = (value or "").strip()
    if otype not in TYPES or not v or len(v) > (2048 if otype == "url" else 300):
        raise AppError("err.obj.invalid")
    if otype in ("ip", "cidr", "asn", "domain", "url", "hash", "cve"):
        det = detect(v if otype != "asn" or v.upper().startswith("AS") else f"AS{v}")
        if det["type"] != otype:
            raise AppError("err.obj.invalid")
        return det["value"]
    if otype == "country":
        if len(v) != 2 or not v.isalpha():
            raise AppError("err.obj.invalid")
        return v.upper()
    if any(c in v for c in "\r\n\t<>"):
        raise AppError("err.obj.invalid")
    return v


class Objects:
    def __init__(self, s: Settings, db: DB, geo: Geo, rep: Any, matcher: Any, products: Any, domains: Any, surface: Any,
                 myip: Any = None, actors: Any = None, news: Any = None) -> None:
        self.s = s
        self.db = db
        self.geo = geo
        self.rep = rep
        self.matcher = matcher
        self.products = products
        self.domains = domains
        self.surface = surface
        self.myip = myip
        self.actors = actors
        self.news = news

    # --- shared ------------------------------------------------------------------------------------------------
    def _alerts_with(self, needle: str, lang: str, kind: str = "other", limit: int = 30) -> list[dict[str, Any]]:
        """Alerts whose parameters name the object as a whole value: 1.2.3.4 does not match 1.2.3.45, AS1 not AS13335.
        Domains also match their subdomains; an ASN also matches numeric origin/asn fields (BGP alerts)."""
        rx = _needle_re(needle, kind)
        asn = int(needle[2:]) if kind == "asn" else None
        likes = [needle] + ([str(asn)] if asn is not None else [])
        where = " OR ".join("params LIKE ? ESCAPE '\\'" for _ in likes)
        args = ["%" + x.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%" for x in likes]
        out: list[dict[str, Any]] = []
        # The LIKE filter also returns near misses (1.2.3.40 for 1.2.3.4): page through them until enough real matches
        # are found, so a noisy neighbour cannot push the object's own alerts out (at most 20 000 rows are looked at).
        last_id = None
        for _ in range(40):
            cond = f"({where})" + (" AND id < ?" if last_id is not None else "")
            rows = self.db.query(f"SELECT * FROM alerts WHERE {cond} ORDER BY id DESC LIMIT 500",
                                 (*args, *([last_id] if last_id is not None else [])))
            for r in rows:
                try:
                    params = json.loads(r["params"] or "{}")
                except ValueError:
                    continue
                if rx.search(json.dumps(params, ensure_ascii=False)) or (asn is not None and _asn_field(params, asn)):
                    out.append(alerts.render(r, lang))
                    if len(out) >= limit:
                        return out
            if len(rows) < 500:
                break
            last_id = rows[-1]["id"]
        return out

    def _assets_with_ip(self, ip: str) -> list[dict[str, Any]]:
        out = []
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return out
        for w in self.db.query("SELECT id, kind, value, label FROM watchlist WHERE kind IN ('ip','cidr','domain')"):
            hit = False
            if w["kind"] == "ip":
                hit = w["value"] == ip
            elif w["kind"] == "cidr":
                try:
                    hit = addr in ipaddress.ip_network(w["value"], strict=False)
                except ValueError:
                    hit = False
            else:
                hit = ip in self.surface.ips_of(w)
            if hit:
                out.append(w)
        return out

    def _history(self, otype: str, value: str) -> list[dict[str, Any]]:
        return self.db.query("SELECT id, created_at, tool, recipe, obj_type, obj_value, target, sev FROM tool_runs "
                             "WHERE obj_type=? AND obj_value=? "
                             "ORDER BY id DESC LIMIT 30", (otype, value))

    def _page(self, r: Result, otype: str, value: str, title: str, subtitle: str | None, mine: dict[str, Any],
              alert_rows: list[dict[str, Any]]) -> dict[str, Any]:
        sev = max_sev(*(f["sev"] for f in r.findings))
        reasons = sorted(r.findings, key=lambda f: -["ok", "info", "low", "medium", "high"].index(f["sev"]))
        det = {"type": otype, "value": value}
        if otype == "url":
            det = detect(value)
        host_t = tbreg.effective_type(det) if otype == "url" else otype
        private = otype in ("ip", "cidr", "domain", "url") and tbrun.private_target(det.get("host") or value if otype == "url" else value,
                                                                                    host_t)
        return {
            "type": otype, "value": value, "title": title, "subtitle": subtitle,
            "private": private,  # private address or internal name: not sent to Gemini or other third parties
            "risk": {"sev": sev, "text": i18n.t(r.lang, f"ob.risk.{sev}"), "reasons": reasons},
            "sections": r.sections, "map": {"points": r.points, "paths": r.paths} if r.points else None,
            "related": r.related, "mine": mine, "alerts": alert_rows,
            "tools": tbrun.fitting_tools(det) if otype in ("ip", "cidr", "asn", "domain", "url", "hash") else [],
            "recipes": tbreg.recipes_for(det) if otype in ("ip", "domain", "url") else [],
            "history": self._history(otype, value),
        }

    def _mine_assets(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"id": w["id"], "kind": w["kind"], "value": w["value"], "label": w.get("label")} for w in rows]

    # --- dispatcher --------------------------------------------------------------------------------------------
    async def build(self, otype: str, value: str, lang: str, client: httpx.AsyncClient,
                    country: dict[str, Any] | None = None, trends: dict[str, Any] | None = None) -> dict[str, Any]:
        value = normalize(otype, value)
        self.matcher.ensure()
        fn = getattr(self, f"_{otype}")
        if otype == "cve":
            return await fn(value, lang, client)
        if otype == "country":
            return fn(value, lang, country or {}, trends or {})
        return fn(value, lang)

    # --- IP ------------------------------------------------------------------------------------------------------
    def _ip(self, ip: str, lang: str) -> dict[str, Any]:
        r = Result("obj", lang, ip, ("ip", ip))
        g = self.geo.lookup(ip) or {}
        asn = f"AS{g['asn']} {g.get('as_name') or ''}".strip() if g.get("asn") else None
        place = ", ".join(x for x in (g.get("city"), self.geo.country_name(g.get("country"), lang) if g.get("country") else None) if x)
        flags = self.rep.flags(ip)
        ab = self.db.query("SELECT score, reports, fetched_at FROM abuseipdb_cache WHERE ip=?", (ip,))
        r.kv(r.t("ob.sec.facts"), [
            ("IP", cell(ip, mono=True)), (r.t("ob.k.as"), cell(asn, obj=("asn", str(g["asn"]))) if asn else None),
            (r.t("ob.k.location"), place or None),
            (r.t("ob.k.type"), r.t("ob.v.public") if ipaddress.ip_address(ip).is_global else r.t("ob.v.private")),
            ("Spamhaus DROP", cell(f"{flags['drop']['cidr']} ({flags['drop'].get('sblid')})", sev="high") if flags.get("drop") else r.t("ob.v.no")),
            ("Tor", cell(r.t("ob.v.yes"), sev="low") if flags.get("tor") else r.t("ob.v.no")),
            ("AbuseIPDB", cell(r.t("ob.v.abuse", s=ab[0]["score"], n=ab[0]["reports"], t=_d(ab[0]["fetched_at"])),
                               sev="high" if (ab[0]["score"] or 0) >= 75 else "medium" if (ab[0]["score"] or 0) >= 25 else "ok") if ab else None)])
        if flags.get("drop"):
            r.find("high", "ob.f.drop", cidr=flags["drop"]["cidr"])
        if flags.get("tor"):
            r.find("info", "ob.f.tor")
        if ab and (ab[0]["score"] or 0) >= 25:
            r.find("high" if ab[0]["score"] >= 75 else "medium", "ob.f.abuse", s=ab[0]["score"])
        c2 = self.db.query("SELECT malware, source, ioc, status, first_seen, last_seen, reference FROM c2 WHERE ip=? "
                           "ORDER BY first_seen DESC LIMIT 30", (ip,))
        r.table(r.t("ob.sec.c2", n=len(c2)), [r.t("ob.c.malware"), "IOC", r.t("ob.c.status"), r.t("ob.c.first"), r.t("ob.c.last"), ""],
                [[cell(c["malware"] or "?", obj=("malware", c["malware"]) if c["malware"] else None), cell(c["ioc"], mono=True),
                  c["status"] or "", _d(c["first_seen"]), _d(c["last_seen"]), cell("↗", href=c["reference"])] for c in c2])
        for c in c2:
            if c["malware"]:
                r.rel("malware", c["malware"])
        if c2:
            r.find("high", "ob.f.c2", malware=", ".join(sorted({c["malware"] or "?" for c in c2})))
        iocs = self.db.query("SELECT ioc, threat_type, malware, confidence, first_seen, reference FROM iocs WHERE ip=? "
                             "ORDER BY first_seen DESC LIMIT 30", (ip,))
        r.table(r.t("ob.sec.iocs", n=len(iocs)), [r.t("ob.c.threat"), r.t("ob.c.malware"), "IOC", r.t("ob.c.first"), ""],
                [[i["threat_type"] or "", cell(i["malware"] or "", obj=("malware", i["malware"]) if i["malware"] else None),
                  cell(i["ioc"], mono=True), _d(i["first_seen"]), cell("↗", href=i["reference"])] for i in iocs])
        if iocs and not c2:
            r.find("high" if any(i["threat_type"] == "botnet_cc" for i in iocs) else "medium", "ob.f.ioc", n=len(iocs))
        sf = self.surface.surface_for([ip])
        if sf:
            s0 = sf[0]
            r.kv(r.t("ob.sec.exposure"), [(r.t("ob.k.ports"), ", ".join(str(p) for p in s0["ports"]) or "–"),
                                          (r.t("ob.k.vulns"), ", ".join(s0["vulns"][:20]) or "–"),
                                          ("KEV", cell(", ".join(s0["kev"]), sev="high") if s0["kev"] else None),
                                          (r.t("ob.k.fetched"), _d(s0["fetched_at"]))])
            for v in s0["vulns"][:20]:
                r.rel("cve", v)
        typos = [t for t in self.db.query("SELECT domain, candidate, ips FROM typo WHERE registered=1") if ip in json.loads(t["ips"] or "[]")]
        for t in typos[:10]:
            r.find("high", "ob.f.typo_ip", candidate=t["candidate"], domain=t["domain"])
            r.rel("domain", t["candidate"])
        if g.get("asn"):
            r.rel("asn", str(g["asn"]), asn)
        if g.get("country"):
            r.rel("country", g["country"])
        r.point(g, "target", ip, ip)
        own = self._assets_with_ip(ip)
        myip = self.myip.match(ip) if self.myip else None
        if own:
            r.find("info", "ob.f.own", value=", ".join(w["value"] for w in own[:3]))
        if myip:
            r.find("info", "ob.f.myip", kind=r.t(f"ob.myip.{myip}"))
        al = self._alerts_with(ip, lang, "ip")
        return self._page(r, "ip", ip, ip, " · ".join(x for x in (asn, place) if x) or None,
                          {"assets": self._mine_assets(own), "myip": myip}, al)

    # --- network -----------------------------------------------------------------------------------------------------
    def _cidr(self, net_s: str, lang: str) -> dict[str, Any]:
        r = Result("obj", lang, net_s, ("cidr", net_s))
        net = ipaddress.ip_network(net_s, strict=False)
        drop = self.rep.drop_for(net_s)
        r.kv(r.t("ob.sec.facts"), [(r.t("ob.k.network"), cell(net_s, mono=True)), (r.t("ob.k.size"), net.num_addresses),
                                   ("Spamhaus DROP", cell(f"{drop['cidr']} ({drop.get('sblid')})", sev="high") if drop else r.t("ob.v.no"))])
        if drop:
            r.find("high", "ob.f.drop", cidr=drop["cidr"])
        rows = []
        if net.prefixlen >= (8 if net.version == 4 else 16):
            for c in self.db.query("SELECT ip, malware, first_seen FROM c2 WHERE ip IS NOT NULL"):
                try:
                    if ipaddress.ip_address(c["ip"]) in net:
                        rows.append(c)
                except ValueError:
                    continue
        r.table(r.t("ob.sec.c2", n=len(rows)), ["IP", r.t("ob.c.malware"), r.t("ob.c.first")],
                [[cell(c["ip"], obj=("ip", c["ip"]), mono=True), cell(c["malware"] or "?", obj=("malware", c["malware"]) if c["malware"] else None),
                  _d(c["first_seen"])] for c in rows[:100]])
        if rows:
            r.find("medium" if len(rows) < 5 else "high", "ob.f.net_c2", n=len(rows))
        own = []
        for w in self.db.query("SELECT id, kind, value, label FROM watchlist WHERE kind IN ('ip','cidr')"):
            try:
                other = ipaddress.ip_network(w["value"], strict=False)
                if other.version == net.version and (other.overlaps(net)):
                    own.append(w)
            except ValueError:
                continue
        if own:
            r.find("info", "ob.f.own", value=", ".join(w["value"] for w in own[:3]))
        return self._page(r, "cidr", net_s, net_s, None, {"assets": self._mine_assets(own), "myip": None}, self._alerts_with(net_s, lang, "cidr"))

    # --- AS --------------------------------------------------------------------------------------------------------------
    def _asn(self, asn_s: str, lang: str) -> dict[str, Any]:
        asn = int(asn_s)
        r = Result("obj", lang, f"AS{asn}", ("asn", asn_s))
        c2 = self.db.query("SELECT ip, malware, country, as_name, first_seen, last_seen FROM c2 WHERE asn=? ORDER BY first_seen DESC", (asn,))
        name = next((c["as_name"] for c in c2 if c["as_name"]), None)
        fams: dict[str, int] = {}
        ccs: dict[str, int] = {}
        for c in c2:
            fams[c["malware"] or "?"] = fams.get(c["malware"] or "?", 0) + 1
            if c["country"]:
                ccs[c["country"]] = ccs.get(c["country"], 0) + 1
        recent = [c for c in c2 if (c["last_seen"] or c["first_seen"] or "") >= _cutoff(30)]
        r.kv(r.t("ob.sec.facts"), [("ASN", f"AS{asn}"), (r.t("ob.k.name"), name), (r.t("ob.k.c2_total"), len(c2)),
                                   (r.t("ob.k.c2_30d"), len(recent)),
                                   (r.t("ob.k.countries"), ", ".join(self.geo.country_name(k, lang) for k, _ in sorted(ccs.items(), key=lambda x: -x[1])[:6]) or None)])
        r.table(r.t("ob.sec.families"), [r.t("ob.c.malware"), r.t("ob.c.count")],
                [[cell(k, obj=("malware", k) if k != "?" else None), v] for k, v in sorted(fams.items(), key=lambda x: -x[1])[:20]])
        r.table(r.t("ob.sec.c2_latest"), ["IP", r.t("ob.c.malware"), r.t("ob.c.first")],
                [[cell(c["ip"], obj=("ip", c["ip"]), mono=True) if c["ip"] else "–", c["malware"] or "?", _d(c["first_seen"])] for c in c2[:50]])
        if len(recent) >= 20:
            r.find("high", "ob.f.asn_c2", n=len(recent))
        elif recent:
            r.find("medium" if len(recent) >= 5 else "low", "ob.f.asn_c2", n=len(recent))
        ev = [e for e in self.db.query("SELECT kind, start_ts, end_ts, asns, countries, meta FROM infra_events ORDER BY start_ts DESC LIMIT 500")
              if asn in json.loads(e["asns"] or "[]")][:20]
        rows = []
        bgp7: list[str] = []
        for e in ev:
            try:
                meta = json.loads(e["meta"] or "{}")
            except ValueError:
                meta = {}
            meta["kind"] = e["kind"]
            rows.append([i18n.render_infra_title(e["kind"], meta, lang), _d(e["start_ts"]), i18n.render_infra_detail(meta, lang)[:200]])
            if e["kind"] in ("hijack", "leak") and (e["start_ts"] or "") >= _cutoff(7):
                bgp7.append(rows[-1][0])
        if bgp7:
            r.find("medium", "ob.f.asn_bgp", n=len(bgp7), title=bgp7[0])
        r.table(r.t("ob.sec.infra"), [r.t("ob.c.event"), r.t("ob.c.start"), r.t("ob.c.detail")], rows)
        own = self.db.query("SELECT id, kind, value, label FROM watchlist WHERE kind='asn' AND value=?", (asn_s,))
        own_ips = [s0 for s0 in self.db.query("SELECT ip FROM surface")]
        for s0 in own_ips:
            g = self.geo.lookup(s0["ip"]) or {}
            if g.get("asn") == asn:
                own += self._assets_with_ip(s0["ip"])
        own = list({w["id"]: w for w in own}.values())
        if own:
            r.find("info", "ob.f.own", value=", ".join(w["value"] for w in own[:3]))
        for k in list(ccs)[:5]:
            r.rel("country", k)
        return self._page(r, "asn", asn_s, f"AS{asn}", name, {"assets": self._mine_assets(own), "myip": None},
                          self._alerts_with(f"AS{asn}", lang, "asn"))

    # --- domain ------------------------------------------------------------------------------------------------------------
    def _domain(self, dom: str, lang: str) -> dict[str, Any]:
        r = Result("obj", lang, dom, ("domain", dom))
        name, sfx = registrable(dom)
        base = f"{name}.{sfx}" if sfx else dom
        hits = self.matcher.match("domain", dom)
        iocs = self.db.query("SELECT ioc, ioc_type, host, threat_type, malware, first_seen, reference FROM iocs "
                             "WHERE host=? OR host LIKE ? ESCAPE '\\' ORDER BY first_seen DESC LIMIT 50",
                             (dom, "%." + dom.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")))
        r.kv(r.t("ob.sec.facts"), [(r.t("ob.k.domain"), cell(dom, mono=True)),
                                   (r.t("ob.k.base"), cell(base, obj=("domain", base)) if base != dom else None),
                                   (r.t("ob.k.matches"), len(hits) + len(iocs))])
        r.table(r.t("ob.sec.iocs", n=len(iocs)), [r.t("ob.c.threat"), r.t("ob.c.malware"), "IOC", r.t("ob.c.first"), ""],
                [[i["threat_type"] or "", cell(i["malware"] or "", obj=("malware", i["malware"]) if i["malware"] else None),
                  cell(i["ioc"], mono=True), _d(i["first_seen"]), cell("↗", href=i["reference"])] for i in iocs])
        if hits or iocs:
            high = any(h.get("threat") == "botnet_cc" for h in hits) or any(i["threat_type"] == "botnet_cc" for i in iocs)
            r.find("high" if high else "medium", "ob.f.domain_ioc", n=len(iocs) or len(hits))
            for i in iocs:
                if i["malware"]:
                    r.rel("malware", i["malware"])
        typo = self.db.query("SELECT domain, technique, mx, ips, first_seen FROM typo WHERE candidate=? AND registered=1", (dom,))
        for t in typo:
            r.find("high" if t["mx"] else "medium", "ob.f.typo", domain=t["domain"], technique=t["technique"])
            r.rel("domain", t["domain"])
            for ip in json.loads(t["ips"] or "[]")[:4]:
                r.rel("ip", ip)
        own = self.db.query("SELECT id, kind, value, label FROM watchlist WHERE kind='domain' AND (value=? OR ? LIKE '%.' || value)", (dom, dom))
        if own:
            r.find("info", "ob.f.own", value=", ".join(w["value"] for w in own[:3]))
            lst = self.domains.listing(own[0]["value"])
            n_before = len(r.sections)
            r.table(r.t("ob.sec.typos", n=len(lst["typos"])), [r.t("ob.c.domain"), r.t("ob.c.technique"), "MX", "IP"],
                    [[cell(t["candidate"], obj=("domain", t["candidate"])), t["technique"], r.t("ob.v.yes") if t["mx"] else "–",
                      ", ".join(t["ips"][:3])] for t in lst["typos"][:50]])
            r.table(r.t("ob.sec.certs", n=lst["ct_total"]), [r.t("ob.c.from"), r.t("ob.c.until"), r.t("ob.c.names"), r.t("ob.c.issuer")],
                    [[(c["not_before"] or "")[:10], (c["not_after"] or "")[:10], ", ".join(c["names"][:5]), c["issuer"] or ""] for c in lst["certs"][:30]])
            for sec in r.sections[n_before:]:
                sec["no_ai"] = True  # monitoring data of the user's own domain stays local
            ips = self.surface.ips_of(own[0])
            for ip in ips[:10]:
                r.rel("ip", ip)
        if base != dom:
            r.rel("domain", base)
        al = self._alerts_with(dom, lang, "domain")
        return self._page(r, "domain", dom, dom, None, {"assets": self._mine_assets(own), "myip": None}, al)

    # --- URL -------------------------------------------------------------------------------------------------------------------
    def _url(self, url: str, lang: str) -> dict[str, Any]:
        r = Result("obj", lang, url, ("url", url))
        det = detect(url)
        host = det.get("host") or ""
        try:
            ipaddress.ip_address(host)
            hkind = "ip"
        except ValueError:
            hkind = "domain"
        n = _norm_url(url)
        hits = (self.matcher.match("url", n) if n else []) + (self.matcher.match(hkind, host) if host else [])
        r.kv(r.t("ob.sec.facts"), [("URL", cell(url, mono=True)), (r.t("ob.k.host"), cell(host, obj=(hkind, host)) if host else None),
                                   (r.t("ob.k.matches"), len(hits))])
        r.table(r.t("ob.sec.matches"), [r.t("ob.c.source"), r.t("ob.c.malware"), r.t("ob.c.threat")],
                [[h.get("kind"), h.get("malware") or "", h.get("threat") or ""] for h in hits])
        if hits:
            r.find("high", "ob.f.url_ioc", n=len(hits))
        if host:
            r.rel(hkind, host)
        return self._page(r, "url", url, url, host, {"assets": [], "myip": None}, self._alerts_with(host, lang, hkind) if host else [])

    # --- hash -------------------------------------------------------------------------------------------------------------------
    def _hash(self, h: str, lang: str) -> dict[str, Any]:
        r = Result("obj", lang, h, ("hash", h))
        mb = cache_get(self.db, f"mb:{h}", 7 * 86400)
        r.kv(r.t("ob.sec.facts"), [(r.t("ob.k.hash"), cell(h, mono=True)), (r.t("ob.k.kind"), {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(h)))])
        if mb and mb.get("status") == "ok":
            d = mb["data"]
            r.kv(r.t("ob.sec.mb"), [(r.t("ob.k.file"), d.get("file_name")), (r.t("ob.k.signature"), cell(d.get("signature") or "", obj=("malware", d["signature"]) if d.get("signature") else None)),
                                    (r.t("ob.k.first"), d.get("first_seen")), (r.t("ob.k.tags"), ", ".join(d.get("tags") or []))])
            r.find("high", "ob.f.mb", sig=d.get("signature") or "?")
        elif mb:
            r.kv(r.t("ob.sec.mb"), [(r.t("ob.k.status"), r.t("ob.v.mb_unknown"))])
        else:
            r.kv(r.t("ob.sec.mb"), [(r.t("ob.k.status"), r.t("ob.v.mb_not_checked"))])
        return self._page(r, "hash", h, h, None, {"assets": [], "myip": None}, self._alerts_with(h, lang))

    # --- CVE ---------------------------------------------------------------------------------------------------------------------
    async def _cve(self, cve: str, lang: str, client: httpx.AsyncClient) -> dict[str, Any]:
        r = Result("obj", lang, cve, ("cve", cve))
        kev = self.db.query("SELECT vendor, product, name, date_added, due_date, ransomware FROM kev WHERE cve=?", (cve,))
        ep = self.db.query("SELECT epss, percentile FROM epss WHERE cve=?", (cve,))
        nvd = None
        nvd_err = None
        try:
            nvd = await self.products.cve_detail(client, cve)
        except AppError as exc:
            nvd_err = exc.render(lang)
        rows: list[tuple[str, Any]] = [("CVE", cell(cve, href=f"https://nvd.nist.gov/vuln/detail/{cve}"))]
        if nvd:
            cv = nvd.get("cvss")
            rows += [(r.t("ob.k.cvss"), cell(f"{cv} {nvd.get('severity') or ''}".strip(), sev="high" if (cv or 0) >= 9 else "medium" if (cv or 0) >= 7 else "low") if cv is not None else "–"),
                     (r.t("ob.k.published"), _d(nvd.get("published")))]
        if ep:
            e = ep[0]["epss"]
            rows.append(("EPSS", cell(f"{e:.3f} ({(ep[0]['percentile'] or 0) * 100:.0f}. Perz.)" if lang == "de" else f"{e:.3f} ({(ep[0]['percentile'] or 0) * 100:.0f}th pct.)",
                                      sev="high" if e >= 0.5 else "medium" if e >= 0.1 else None)))
        if kev:
            k = kev[0]
            rows += [("CISA KEV", cell(r.t("ob.v.kev", date=k["date_added"] or "?"), sev="high")),
                     (r.t("ob.k.product"), cell(f"{k['vendor']} {k['product']}", obj=("vendor", k["vendor"]))),
                     (r.t("ob.k.ransomware"), r.t("ob.v.yes") if (k["ransomware"] or "").lower() == "known" else r.t("ob.v.unknown"))]
            r.find("high", "ob.f.kev", date=k["date_added"] or "?")
            r.rel("vendor", k["vendor"])
        elif ep and ep[0]["epss"] >= 0.5:
            r.find("high", "ob.f.epss", e=f"{ep[0]['epss']:.2f}")
        if nvd and (nvd.get("cvss") or 0) >= 9 and not kev:
            r.find("medium", "ob.f.cvss", s=nvd["cvss"])
        r.kv(r.t("ob.sec.facts"), rows)
        if nvd and nvd.get("summary"):
            r.text(r.t("ob.sec.description"), nvd["summary"])
        elif nvd_err:
            r.text(r.t("ob.sec.description"), nvd_err)
        # own exposure: InternetDB vulns of own IPs and watched products
        exposed = [x["ip"] for x in self.db.query("SELECT ip, vulns FROM surface") if cve in json.loads(x["vulns"] or "[]")]
        prods = self.db.query("SELECT p.id, p.vendor, p.product FROM product_cves c JOIN products p ON p.id = c.product_id WHERE c.cve=?", (cve,))
        own: list[dict[str, Any]] = []
        for ip in exposed:
            own += self._assets_with_ip(ip)
        own = list({w["id"]: w for w in own}.values())
        if exposed:
            r.find("high", "ob.f.cve_exposed", ips=", ".join(exposed[:5]))
        if prods:
            r.find("medium", "ob.f.cve_product", products=", ".join(f"{p['vendor']} {p['product']}".strip() for p in prods[:5]))
        return self._page(r, "cve", cve, cve, f"{kev[0]['vendor']} {kev[0]['product']}" if kev else None,
                          {"assets": self._mine_assets(own), "products": prods, "myip": None}, self._alerts_with(cve, lang))

    # --- country ----------------------------------------------------------------------------------------------------------------------
    def _country(self, cc: str, lang: str, d: dict[str, Any], tr: dict[str, Any]) -> dict[str, Any]:
        r = Result("obj", lang, cc, ("country", cc))
        name = self.geo.country_name(cc, lang)
        s = d.get("radar_shares_pct") or {}

        def pct(v: Any) -> str:
            return "–" if v is None else (f"{v:.1f} %".replace(".", ",") if lang == "de" else f"{v:.1f} %")
        r.table(r.t("ob.sec.shares"), [r.t("ob.c.metric"), "24 h", r.t("ob.c.7d")],
                [[r.t("ob.m.l7_target"), pct(s.get("l7_target_1d")), pct(s.get("l7_target_7d"))],
                 [r.t("ob.m.l3_target"), pct(s.get("l3_target_1d")), pct(s.get("l3_target_7d"))],
                 [r.t("ob.m.l7_origin"), pct(s.get("l7_origin_1d")), pct(s.get("l7_origin_7d"))],
                 [r.t("ob.m.l3_origin"), pct(s.get("l3_origin_1d")), pct(s.get("l3_origin_7d"))]])
        labels = tr.get("labels") or []
        series = tr.get("series") or {}
        share = [{"name": r.t(f"ob.m.{k}"), "values": series.get(k) or []} for k in ("l7_target", "l3_target", "l7_origin")
                 if any(v is not None for v in series.get(k) or [])]
        counts = [{"name": r.t(f"ob.m.{k}"), "values": series.get(k) or []} for k in ("ransomware", "c2_new")
                  if any(series.get(k) or [])]
        r.chart(r.t("ob.sec.trend"), "line", labels, share, "%")
        r.chart(r.t("ob.sec.counts"), "bar", labels, counts, "")
        c2 = d.get("c2") or {}
        r.table(r.t("ob.sec.c2_families", n=c2.get("total", 0)), [r.t("ob.c.malware"), r.t("ob.c.count")],
                [[cell(x["key"], obj=("malware", x["key"]) if x["key"] != "unknown" else None), x["count"]] for x in c2.get("by_malware") or []])
        r.table(r.t("ob.sec.c2_asn"), ["AS", r.t("ob.c.count")], [[x["key"], x["count"]] for x in c2.get("by_asn") or []])
        rw = d.get("ransomware_7d") or {}
        r.table(r.t("ob.sec.ransom", n=rw.get("total", 0)), [r.t("ob.c.group"), r.t("ob.c.count")],
                [[cell(x["key"], obj=("group", x["key"])), x["count"]] for x in rw.get("by_group") or []])
        r.table(r.t("ob.sec.sectors"), [r.t("ob.c.sector"), r.t("ob.c.count")], [[x["key"] or "–", x["count"]] for x in rw.get("by_sector") or []])
        r.table(r.t("ob.sec.infra"), [r.t("ob.c.event"), r.t("ob.c.start"), r.t("ob.c.detail")],
                [[e["title"], _d(e["start_ts"]), (e.get("detail") or "")[:200]] for e in d.get("infra_events") or []])
        dd = d.get("radar_drilldown") or {}
        vec = sorted(((dd.get("l3_vector_target_1d") or {}).get("summary") or {}).items(), key=lambda x: -x[1])[:8]
        if vec:
            r.table(r.t("ob.sec.vectors"), [r.t("ob.c.vector"), "%"], [[k, pct(v)] for k, v in vec])
        cab = d.get("cables") or {}
        if cab.get("cables"):
            r.items(r.t("ob.sec.cables", n=len(cab["cables"])), cab["cables"][:40], note=r.t("ob.n.cables", snap=cab.get("snapshot") or "2021"))
        for p in d.get("patterns") or []:
            r.findings.append({"sev": p.get("severity") or "info", "text": p.get("title"), "detail": p.get("detail")})
        for x in (rw.get("by_group") or [])[:5]:
            r.rel("group", x["key"])
        for x in (c2.get("by_malware") or [])[:5]:
            if x["key"] != "unknown":
                r.rel("malware", x["key"])
        cen = self.geo.centroid(cc)
        if cen:
            r.point({"lat": cen[0], "lon": cen[1]}, "target", name)
        return self._page(r, "country", cc, name, cc, {"assets": [], "myip": None}, [])

    # --- malware family ----------------------------------------------------------------------------------------------------------
    def _malware(self, fam: str, lang: str) -> dict[str, Any]:
        r = Result("obj", lang, fam, ("malware", fam))
        c2 = self.db.query("SELECT ip, ioc, country, asn, as_name, status, first_seen, last_seen, lat, lon FROM c2 WHERE malware=? "
                           "ORDER BY first_seen DESC", (fam,))
        iocs = self.db.query("SELECT ioc_type, COUNT(*) AS n, MIN(first_seen) AS first, MAX(first_seen) AS last FROM iocs "
                             "WHERE malware=? GROUP BY ioc_type", (fam,))
        new24 = sum(1 for c in c2 if (c["first_seen"] or "") >= _cutoff(1))
        ccs: dict[str, int] = {}
        asns: dict[str, int] = {}
        for c in c2:
            if c["country"]:
                ccs[c["country"]] = ccs.get(c["country"], 0) + 1
            if c["asn"]:
                k = f"{c['asn']}|{c['as_name'] or ''}"
                asns[k] = asns.get(k, 0) + 1
        r.kv(r.t("ob.sec.facts"), [(r.t("ob.k.family"), fam), (r.t("ob.k.c2_total"), len(c2)), (r.t("ob.k.c2_24h"), new24),
                                   (r.t("ob.k.iocs"), sum(i["n"] for i in iocs)),
                                   (r.t("ob.k.first"), _d(min((c["first_seen"] for c in c2 if c["first_seen"]), default=None))),
                                   (r.t("ob.k.last"), _d(max((c["last_seen"] or c["first_seen"] for c in c2 if c["last_seen"] or c["first_seen"]), default=None)))])
        r.table(r.t("ob.sec.countries"), [r.t("ob.c.country"), r.t("ob.c.count")],
                [[cell(self.geo.country_name(k, lang), obj=("country", k)), v] for k, v in sorted(ccs.items(), key=lambda x: -x[1])[:15]])
        r.table(r.t("ob.sec.c2_asn"), ["AS", r.t("ob.c.count")],
                [[cell(f"AS{k.split('|')[0]} {k.split('|')[1]}".strip(), obj=("asn", k.split("|")[0])), v]
                 for k, v in sorted(asns.items(), key=lambda x: -x[1])[:15]])
        r.table(r.t("ob.sec.ioc_types"), [r.t("ob.c.type"), r.t("ob.c.count"), r.t("ob.c.first"), r.t("ob.c.last")],
                [[i["ioc_type"], i["n"], _d(i["first"]), _d(i["last"])] for i in iocs])
        r.table(r.t("ob.sec.c2_latest"), ["IP / IOC", r.t("ob.c.country"), "AS", r.t("ob.c.status"), r.t("ob.c.first")],
                [[cell(c["ip"] or c["ioc"], obj=("ip", c["ip"]) if c["ip"] else None, mono=True),
                  self.geo.country_name(c["country"], lang) if c["country"] else "–", f"AS{c['asn']}" if c["asn"] else "–",
                  c["status"] or "", _d(c["first_seen"])] for c in c2[:60]])
        for c in c2[:300]:
            if c["lat"] is not None:
                r.point({"lat": c["lat"], "lon": c["lon"]}, "c2", None, c["ip"])
        if new24:
            r.find("medium", "ob.f.family_new", n=new24)
        own_hits = [c["ip"] for c in c2 if c["ip"] and self._assets_with_ip(c["ip"])]
        if own_hits:
            r.find("high", "ob.f.family_own", ips=", ".join(own_hits[:3]))
        for k, _ in sorted(ccs.items(), key=lambda x: -x[1])[:5]:
            r.rel("country", k)
        return self._page(r, "malware", fam, fam, None, {"assets": [], "myip": None}, self._alerts_with(fam, lang))

    # --- ransomware group --------------------------------------------------------------------------------------------------------------
    def _group(self, grp: str, lang: str) -> dict[str, Any]:
        r = Result("obj", lang, grp, ("group", grp))
        rows = self.db.query("SELECT victim, country, activity, discovered, permalink FROM victims WHERE grp=? AND discovered >= ? "
                             "ORDER BY discovered DESC", (grp, _cutoff(90)))
        d7 = sum(1 for v in rows if (v["discovered"] or "") >= _cutoff(7))
        d30 = sum(1 for v in rows if (v["discovered"] or "") >= _cutoff(30))
        ccs: dict[str, int] = {}
        secs: dict[str, int] = {}
        for v in rows:
            ccs[v["country"] or "??"] = ccs.get(v["country"] or "??", 0) + 1
            secs[v["activity"] or ""] = secs.get(v["activity"] or "", 0) + 1
        r.kv(r.t("ob.sec.facts"), [(r.t("ob.k.group"), grp), (r.t("ob.k.victims_7d"), d7), (r.t("ob.k.victims_30d"), d30),
                                   (r.t("ob.k.victims_90d"), len(rows))])
        r.table(r.t("ob.sec.countries"), [r.t("ob.c.country"), r.t("ob.c.count")],
                [[cell(self.geo.country_name(k, lang), obj=("country", k)) if k != "??" else "?", v] for k, v in sorted(ccs.items(), key=lambda x: -x[1])[:15]])
        r.table(r.t("ob.sec.sectors"), [r.t("ob.c.sector"), r.t("ob.c.count")],
                [[k or "–", v] for k, v in sorted(secs.items(), key=lambda x: -x[1])[:15]])
        r.table(r.t("ob.sec.victims"), [r.t("ob.c.victim"), r.t("ob.c.country"), r.t("ob.c.sector"), r.t("ob.c.date"), ""],
                [[v["victim"], self.geo.country_name(v["country"], lang) if v["country"] else "?", v["activity"] or "–",
                  _d(v["discovered"]), cell("↗", href=v["permalink"])] for v in rows[:80]])
        if r.sections and r.sections[-1].get("title") == r.t("ob.sec.victims"):
            r.sections[-1]["no_ai"] = True  # leak site titles are attacker-controlled free text
        region = set(self.s.home_region)
        home = sum(1 for v in rows if v["country"] in region and (v["discovered"] or "") >= _cutoff(30))
        if home:
            r.find("medium", "ob.f.group_region", n=home, region=self.s.home_region_name or ", ".join(sorted(region)))
        if d7:
            r.find("info", "ob.f.group_active", n=d7)
        own_names = [w["value"].split(".")[0].lower() for w in self.db.query("SELECT value FROM watchlist WHERE kind='domain'")]
        pats = [re.compile(r"(?<![a-z0-9])" + re.escape(n) + r"(?![a-z0-9])") for n in own_names if n and len(n) >= 4]
        hits = [v["victim"] for v in rows if any(p.search((v["victim"] or "").lower()) for p in pats)]
        if hits:  # name match only: a hint to check, not a confirmed relation
            r.find("medium", "ob.f.group_own", victims=", ".join(hits[:3]))
        for k, _ in sorted(ccs.items(), key=lambda x: -x[1])[:5]:
            if k != "??":
                r.rel("country", k)
                c = self.geo.centroid(k)
                if c:
                    r.point({"lat": c[0], "lon": c[1]}, "ransom", self.geo.country_name(k, lang))
        return self._page(r, "group", grp, grp, None, {"assets": [], "myip": None}, [])

    # --- threat actor (MISP Galaxy) ---------------------------------------------------------------------------------------------------
    def _actor(self, name: str, lang: str) -> dict[str, Any]:
        a = self.actors.get(name) if self.actors else None
        if not a:
            raise AppError("err.obj.actor", 404)
        name = a["name"]
        r = Result("obj", lang, name, ("actor", name))
        cname = self.geo.country_name(a["country"], lang) if a["country"] else None
        r.kv(r.t("ob.sec.facts"), [
            (r.t("ob.k.actor"), name), (r.t("ob.k.synonyms"), ", ".join(a["synonyms"][:14]) or None),
            (r.t("ob.k.origin_country"), cell(cname, obj=("country", a["country"])) if cname else None),
            (r.t("ob.k.sponsor"), a["sponsor"]), (r.t("ob.k.incident"), a["incident"]),
            (r.t("ob.k.confidence"), r.t("ob.v.pct", v=a["confidence"]) if a["confidence"] else None),
            (r.t("ob.k.target_cats"), ", ".join(a["targets"]) or None), (r.t("ob.k.sectors"), ", ".join(a["sectors"]) or None),
            (r.t("ob.k.victims"), ", ".join(a["victims"][:15]) or None)])
        r.sections[-1]["note"] = r.t("ob.n.actor")
        if a["description"]:
            r.text(r.t("ob.sec.actor_about"), a["description"])
        reports = []
        if self.news:
            items = [x for x in self.news.clusters(self.news._rows(90))
                     if any(self.actors.canonical(a) == name for a in x["actors"])]
            reports = items
            r.table(r.t("ob.sec.actor_news"), [r.t("ob.c.date"), r.t("ob.c.title"), r.t("ob.c.source")],
                    [[_d(x["latest"]), cell(x["title"], href=x["url"]), ", ".join(x["sources"][:3])] for x in items[:40]],
                    note=r.t("ob.n.actor_news"), empty=r.t("ob.v.none"))
            d30 = _cutoff(30)
            n30 = sum(1 for x in items if x["latest"] >= d30)
            if n30:
                r.find("info", "ob.f.actor_news", n=n30)
            named: dict[str, int] = {}
            for x in items:
                for c in x["countries"]:
                    named[c] = named.get(c, 0) + 1
            if named:
                r.table(r.t("ob.sec.actor_targets"), [r.t("ob.c.country"), r.t("ob.c.reports")],
                        [[cell(self.geo.country_name(c, lang), obj=("country", c)), n] for c, n in sorted(named.items(), key=lambda x: -x[1])[:15]])
            home = [c for c in (self.s.home_region or []) if c in named]
            if home:
                r.find("medium", "ob.f.actor_home", countries=", ".join(self.geo.country_name(c, lang) for c in home))
            src = self.geo.centroid(a["country"]) if a["country"] else None
            if src:
                r.point({"lat": src[0], "lon": src[1]}, "origin", cname)
            for c, _ in sorted(named.items(), key=lambda x: -x[1])[:6]:
                cen = self.geo.centroid(c)
                if cen:
                    r.point({"lat": cen[0], "lon": cen[1]}, "target", self.geo.country_name(c, lang))
                    if src:
                        r.path([(src[1], src[0]), (cen[1], cen[0])])
                r.rel("country", c)
        if a["refs"]:
            r.items(r.t("ob.sec.actor_refs"), [cell(u.split("/")[2], href=u) for u in a["refs"][:15]])
        if a["country"]:
            r.rel("country", a["country"])
        page = self._page(r, "actor", name, name, cname, {"assets": [], "myip": None}, [])
        page["reports"] = [{"id": x["id"], "title": x["title"], "latest": x["latest"]} for x in reports[:10]]
        return page

    # --- vendor -----------------------------------------------------------------------------------------------------------------------
    def _vendor(self, vendor: str, lang: str) -> dict[str, Any]:
        r = Result("obj", lang, vendor, ("vendor", vendor))
        kev = self.db.query("SELECT k.cve, k.product, k.name, k.date_added, k.ransomware, e.epss FROM kev k LEFT JOIN epss e ON e.cve=k.cve "
                            "WHERE k.vendor = ? COLLATE NOCASE ORDER BY k.date_added DESC", (vendor,))
        d30 = [k for k in kev if (k["date_added"] or "") >= _cutoff(30)[:10]]
        prods = self.db.query("SELECT id, vendor, product FROM products WHERE vendor = ? COLLATE NOCASE", (vendor,))
        r.kv(r.t("ob.sec.facts"), [(r.t("ob.k.vendor"), vendor), (r.t("ob.k.kev_total"), len(kev)), (r.t("ob.k.kev_30d"), len(d30)),
                                   (r.t("ob.k.watched"), r.t("ob.v.yes") if prods else r.t("ob.v.no"))])
        if prods:
            r.items(r.t("ob.k.watched"), [f"{p['vendor']} {p['product']}".strip() for p in prods])
            r.sections[-1]["no_ai"] = True  # the user's own products: Gemini only gets the yes/no above
        r.table(r.t("ob.sec.kev"), ["CVE", r.t("ob.c.product"), r.t("ob.c.date"), "EPSS", r.t("ob.c.ransomware")],
                [[cell(k["cve"], obj=("cve", k["cve"])), k["product"], k["date_added"], f"{k['epss']:.3f}" if k["epss"] is not None else "–",
                  r.t("ob.v.yes") if (k["ransomware"] or "").lower() == "known" else ""] for k in kev[:80]])
        if d30:
            r.find("high" if not prods else "medium", "ob.f.vendor_kev", n=len(d30))
        if prods:
            r.find("info", "ob.f.vendor_watched")
        return self._page(r, "vendor", vendor, vendor, None, {"assets": [], "products": prods, "myip": None}, self._alerts_with(vendor, lang))


# Findings that name the user's own assets, IPs or products. They are not sent to Gemini; only a flag is.
OWN_FINDINGS = {"ob.f.own", "ob.f.typo", "ob.f.typo_ip", "ob.f.family_own", "ob.f.cve_exposed", "ob.f.cve_product",
                "ob.f.group_own", "ob.f.myip", "ob.f.vendor_watched"}


def object_context(page: dict[str, Any]) -> dict[str, Any]:
    """Compact, LLM-ready extract of an object page. The object itself is sent; the user's own assets, IPs, products and
    alerts are reduced to flags, and attacker-controlled free text (leak site titles) is left out."""
    def plain(c: Any) -> Any:
        v = c.get("t") if isinstance(c, dict) else c
        return v[:300] if isinstance(v, str) else v

    secs = []
    for s in page.get("sections") or []:
        if s.get("no_ai"):
            continue
        if s["kind"] == "kv":
            secs.append({"title": s.get("title"), "facts": {str(k): plain(v) for k, v in s["rows"]}})
        elif s["kind"] == "table":
            secs.append({"title": s.get("title"), "columns": [c for c in s.get("columns") or []],
                         "rows": [[plain(c) for c in row] for row in s["rows"][:25]]})
        elif s["kind"] == "text":
            secs.append({"title": s.get("title"), "text": s.get("text", "")[:2000]})
        elif s["kind"] == "chart":
            secs.append({"title": s.get("title"), "labels": s.get("labels"), "series": s.get("series"), "unit": s.get("unit")})
    mine = page.get("mine") or {}
    reasons = page["risk"]["reasons"]
    return {
        "object": {"type": page["type"], "value": page["value"], "title": page.get("title"), "subtitle": page.get("subtitle")},
        "risk": {"level": page["risk"]["sev"],
                 "reasons": [{"severity": f["sev"], "text": f["text"]} for f in reasons if f.get("key") not in OWN_FINDINGS][:15]},
        "sections": secs[:12],
        "relates_to_own_assets": bool(mine.get("assets")) or bool(mine.get("myip")) or bool(mine.get("products"))
        or any(f.get("key") in OWN_FINDINGS for f in reasons),
        "own_alerts": len(page.get("alerts") or []),
    }
