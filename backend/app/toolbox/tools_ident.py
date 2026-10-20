"""Who is behind it: IP information, RDAP, BGP/RPKI, passive DNS, certificates (CT)."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ..tools import ToolError
from .common import Ctx, as_text, asn_cell, cache_get, ip_cell, is_global, loc_text, relate_ip
from .registry import ToolSpec
from .result import Result, cell

RIPESTAT = "https://stat.ripe.net/data/{call}/data.json"
MNEMONIC = "https://api.mnemonic.no/pdns/v3/{q}"
_pdns_calls: list[float] = []


def _fmt_dt(v: Any) -> str:
    if not v:
        return "–"
    return str(v)[:16].replace("T", " ")


# --- IP info ---------------------------------------------------------------------------------------------------------
async def ipinfo(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> dict[str, Any]:
    d = await ctx.tk.ipinfo(ctx.client, target, ctx.lang)
    ip, geo = d["ip"], d.get("geo")
    res = Result("ipinfo", ctx.lang, target, ("ip", ip) if is_global(ip) else None)
    rt = d.get("routing") or {}
    origins = ", ".join(f"AS{a['asn']} {a.get('holder') or ''}".strip() for a in rt.get("asns") or [] if a.get("asn"))
    res.kv(res.t("tb.sec.identity"), [
        (res.t("tb.k.ip"), ip_cell(ip)), ("PTR", d.get("ptr") or "–"), (res.t("tb.k.location_dbip"), loc_text(ctx, geo)),
        (res.t("tb.k.as_dbip"), asn_cell(geo)), (res.t("tb.k.prefix"), rt.get("error") or rt.get("prefix")),
        (res.t("tb.k.announced"), None if rt.get("announced") is None else res.t("common.yes" if rt["announced"] else "common.no")),
        (res.t("tb.k.origin_as"), origins or None)])
    rep = d.get("reputation") or {}
    rows: list[tuple[str, Any]] = []
    if rep:
        drop = rep.get("drop")
        rows.append((res.t("tb.k.drop"), cell(f"{drop['cidr']} ({drop.get('sblid') or 'SBL'})", sev="high") if drop
                     else res.t("tb.v.not_listed")))
        rows.append((res.t("tb.k.tor"), cell(res.t("common.yes"), sev="low") if rep.get("tor") else res.t("common.no")))
        ab = rep.get("abuseipdb") or {}
        if ab.get("status") == "ok":
            score = ab.get("score") or 0
            sev = "high" if score >= 75 else "medium" if score >= 25 else "ok"
            rows.append(("AbuseIPDB", cell(res.t("tb.v.abuse", s=score, r=ab.get("reports") or 0,
                                                   u=", ".join(x for x in (ab.get("usage"), ab.get("isp")) if x) or "–"),
                                            sev=sev, href=ab.get("link"))))
            if score >= 25:
                res.find("high" if score >= 75 else "medium", "tb.f.abuse", s=score, r=ab.get("reports") or 0)
        elif ab.get("status"):
            rows.append(("AbuseIPDB", res.t(f"tb.v.abuse_{ab['status']}") if ab["status"] in ("disabled", "budget", "private", "none")
                         else res.t("tb.v.abuse_error")))
        if drop:
            res.find("high", "tb.f.drop", cidr=drop["cidr"])
        if rep.get("tor"):
            res.find("info", "tb.f.tor")
    res.kv(res.t("tb.sec.reputation"), rows)
    c2 = d.get("c2") or []
    res.table(res.t("tb.sec.c2", n=len(c2)), [res.t("tb.c.malware"), "IOC", res.t("tb.c.first"), res.t("tb.c.source")],
              [[cell(c["malware"] or "?", obj=("malware", c["malware"]) if c["malware"] else None), cell(c["ioc"], mono=True),
                _fmt_dt(c["first_seen"]), cell("abuse.ch", href=c.get("reference"))] for c in c2],
              empty=res.t("tb.v.no_c2"))
    if c2:
        res.find("high", "tb.f.c2", malware=", ".join(sorted({c["malware"] or "?" for c in c2})))
        for c in c2:
            if c["malware"]:
                res.rel("malware", c["malware"])
    iocs = d.get("iocs") or []
    if iocs:
        res.table(res.t("tb.sec.iocs", n=len(iocs)), [res.t("tb.c.threat"), res.t("tb.c.malware"), "IOC", res.t("tb.c.source")],
                  [[i.get("threat_type") or "", i.get("malware") or "", cell(i["ioc"], mono=True), cell("ThreatFox", href=i.get("reference"))]
                   for i in iocs])
        high = any(i.get("threat_type") == "botnet_cc" for i in iocs)
        res.find("high" if high else "medium", "tb.f.ioc", n=len(iocs))
    infra = d.get("infra") or []
    if infra:
        res.table(res.t("tb.sec.infra"), [res.t("tb.c.event"), res.t("tb.c.start"), res.t("tb.c.detail")],
                  [[e["title"], _fmt_dt(e["start_ts"]), e.get("detail") or ""] for e in infra])
    if rt.get("announced") is False:
        res.find("info", "tb.f.not_announced")
    res.point(geo, "target", ip, ip)
    relate_ip(res, ip, geo)
    for a in rt.get("asns") or []:
        if a.get("asn"):
            res.rel("asn", str(a["asn"]), f"AS{a['asn']} {a.get('holder') or ''}".strip())
    summary = ", ".join(x for x in (as_text(geo), loc_text(ctx, geo)) if x) or ip
    return res.done(spec, summary)


# --- RDAP ------------------------------------------------------------------------------------------------------------
def _parse_ts(v: Any) -> datetime | None:
    try:
        dtv = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return dtv if dtv.tzinfo else dtv.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


async def rdap(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> dict[str, Any]:
    d = await ctx.tk.rdap(ctx.client, target)
    kind, q = d["kind"], d["query"]
    obj = {"autnum": ("asn", q), "ip": ("cidr" if "/" in q else "ip", q), "domain": ("domain", q)}.get(kind)
    res = Result("rdap", ctx.lang, target, obj)
    s = d.get("summary") or {}
    res.kv(res.t("tb.sec.registration"), [
        (res.t("tb.k.query"), f"{kind}: {q}"), (res.t("tb.k.object"), s.get("object")), (res.t("tb.k.handle"), s.get("handle")),
        (res.t("tb.k.name"), s.get("name")), (res.t("tb.k.type"), s.get("type")),
        (res.t("tb.k.country"), ctx.geo.country_name(s["country"], ctx.lang) if s.get("country") else None),
        (res.t("tb.k.range"), " – ".join(str(x) for x in s["range"]) if s.get("range") else None),
        (res.t("tb.k.as_range"), " – ".join(str(x) for x in s["autnum"]) if s.get("autnum") else None),
        (res.t("tb.k.status"), ", ".join(s.get("status") or [])), (res.t("tb.k.nameservers"), ", ".join(x for x in s.get("nameservers") or [] if x)),
        ("port43", s.get("port43"))])
    events = s.get("events") or []
    res.table(res.t("tb.sec.events"), [res.t("tb.c.event"), res.t("tb.c.date")], [[e.get("action") or "", _fmt_dt(e.get("date"))] for e in events])
    ents = s.get("entities") or []
    res.table(res.t("tb.sec.contacts"), [res.t("tb.c.role"), res.t("tb.c.name"), "E-Mail"],
              [[", ".join(e.get("roles") or []), ", ".join(x for x in (e.get("fn"), e.get("org")) if x) or e.get("handle") or "–",
                e.get("email") or ""] for e in ents])
    now = datetime.now(timezone.utc)
    if kind == "domain":
        for e in events:
            ts = _parse_ts(e.get("date"))
            if not ts:
                continue
            if e.get("action") == "registration" and (now - ts).days < 30:
                res.find("medium", "tb.f.domain_young", "tb.fd.domain_young", days=(now - ts).days)
            elif e.get("action") == "registration" and (now - ts).days < 180:
                res.find("info", "tb.f.domain_recent", days=(now - ts).days)
            if e.get("action") == "expiration" and 0 <= (ts - now).days < 30:
                res.find("low", "tb.f.domain_expiring", days=(ts - now).days)
        for st in s.get("status") or []:
            if "hold" in str(st).lower():
                res.find("medium", "tb.f.domain_hold", status=st)
    res.raw = d.get("raw")
    return res.done(spec, s.get("name") or s.get("handle") or q)


# --- BGP / RPKI --------------------------------------------------------------------------------------------------------
async def _ripestat(ctx: Ctx, call: str, **params: str) -> dict[str, Any]:
    try:
        r = await ctx.client.get(RIPESTAT.format(call=call), params={**params, "sourceapp": "emberwatch"}, timeout=20)
    except httpx.HTTPError as exc:
        raise ToolError("err.tool.upstream", detail=exc.__class__.__name__) from exc
    if r.status_code != 200:
        raise ToolError("err.tb.http", service="RIPEstat", status=r.status_code)
    try:
        return (r.json() or {}).get("data") or {}
    except ValueError as exc:
        raise ToolError("err.tool.upstream", detail="json") from exc


RPKI_SEV = {"valid": "ok", "unknown": "low", "invalid": "high", "invalid_asn": "high", "invalid_length": "high"}


async def _rpki(ctx: Ctx, asn: int, prefix: str) -> str:
    try:
        d = await _ripestat(ctx, "rpki-validation", resource=str(asn), prefix=prefix)
    except ToolError:
        return "error"
    st = str(d.get("status") or "").lower()
    return st if st in RPKI_SEV else "error"


async def bgp(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> dict[str, Any]:
    res = Result("bgp", ctx.lang, target, (kind, target))
    rows: list[list[Any]] = []
    if kind == "asn":
        asn = int(target)
        d = await _ripestat(ctx, "announced-prefixes", resource=f"AS{asn}")
        prefixes = [p.get("prefix") for p in d.get("prefixes") or [] if isinstance(p, dict) and p.get("prefix")]
        res.kv(res.t("tb.sec.asn"), [("ASN", f"AS{asn}"), (res.t("tb.k.prefixes"), len(prefixes))])
        if not prefixes:
            res.find("info", "tb.f.asn_no_prefix")
        sem = asyncio.Semaphore(4)

        async def one(p: str) -> tuple[list[Any], str]:
            async with sem:
                st = await _rpki(ctx, asn, p)
            return [cell(p, obj=("cidr", p), mono=True), f"AS{asn}", cell(res.t(f"tb.rpki.{st}"), sev=RPKI_SEV.get(st))], st

        checked = prefixes[:15]
        done = await asyncio.gather(*(one(p) for p in checked))
        rows = [r for r, _ in done]
        sts = [st for _, st in done]
        res.table(res.t("tb.sec.prefixes"), [res.t("tb.c.prefix"), res.t("tb.c.origin"), "RPKI"], rows,
                  note=res.t("tb.n.bgp_first", n=len(checked), total=len(prefixes)) if len(prefixes) > len(checked) else None)
        bad = [x for x in sts if x in ("invalid", "invalid_asn", "invalid_length")]
        if bad:
            res.find("high", "tb.f.rpki_invalid_n", n=len(bad))
        if "unknown" in sts:
            res.find("low", "tb.f.rpki_unknown_n", n=sts.count("unknown"))
        summary = res.t("tb.s.bgp_asn", n=len(prefixes))
    else:
        d = await _ripestat(ctx, "prefix-overview", resource=target)
        prefix = d.get("resource") or target
        asns = [a for a in d.get("asns") or [] if isinstance(a, dict) and a.get("asn")]
        res.kv(res.t("tb.sec.routing"), [
            (res.t("tb.k.query"), target), (res.t("tb.k.prefix"), cell(prefix, obj=("cidr", prefix), mono=True)),
            (res.t("tb.k.announced"), res.t("common.yes" if d.get("announced") else "common.no")),
            (res.t("tb.k.less_specific"), res.t("common.yes") if d.get("is_less_specific") else None)])
        if not d.get("announced"):
            res.find("info", "tb.f.not_announced")
        if len(asns) > 1:
            res.find("medium", "tb.f.moas", "tb.fd.moas", n=len(asns))
        for a in asns[:5]:
            st = await _rpki(ctx, int(a["asn"]), prefix)
            rows.append([cell(prefix, mono=True), cell(f"AS{a['asn']} {a.get('holder') or ''}".strip(), obj=("asn", str(a["asn"]))),
                         cell(res.t(f"tb.rpki.{st}"), sev=RPKI_SEV.get(st))])
            res.rel("asn", str(a["asn"]), f"AS{a['asn']} {a.get('holder') or ''}".strip())
            if st in ("invalid", "invalid_asn", "invalid_length"):
                res.find("high", "tb.f.rpki_invalid", "tb.fd.rpki_invalid", asn=a["asn"], prefix=prefix, status=st)
            elif st == "unknown":
                res.find("low", "tb.f.rpki_unknown", "tb.fd.rpki_unknown", asn=a["asn"], prefix=prefix)
        res.table(res.t("tb.sec.origins"), [res.t("tb.c.prefix"), res.t("tb.c.origin"), "RPKI"], rows)
        summary = res.t("tb.s.bgp_prefix", prefix=prefix, n=len(asns))
    return res.done(spec, summary)


# --- passive DNS (mnemonic) -----------------------------------------------------------------------------------------
async def pdns(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> dict[str, Any]:
    res = Result("pdns", ctx.lang, target, (kind, target))
    key = f"pdns:{target}"
    data = cache_get(ctx.db, key, 86400)
    if data is None:
        now = time.time()
        _pdns_calls[:] = [t for t in _pdns_calls if now - t < 60]
        if len(_pdns_calls) >= 9:  # public limit: 10 requests per minute
            raise ToolError("err.tb.rate", service="mnemonic", seconds=int(60 - (now - _pdns_calls[0])) + 1)
        _pdns_calls.append(now)
        try:
            r = await ctx.client.get(MNEMONIC.format(q=target), params={"limit": 300},
                                     headers={"User-Agent": ctx.s.user_agent, "Accept": "application/json"}, timeout=20)
        except httpx.HTTPError as exc:
            raise ToolError("err.tool.upstream", detail=exc.__class__.__name__) from exc
        if r.status_code == 402:
            raise ToolError("err.tb.quota", service="mnemonic")
        if r.status_code != 200:
            raise ToolError("err.tb.http", service="mnemonic", status=r.status_code)
        try:
            body = r.json() or {}
        except ValueError as exc:
            raise ToolError("err.tool.upstream", detail="json") from exc
        data = [x for x in body.get("data") or [] if isinstance(x, dict)][:300]
        ctx.db.kv_set(key, data)
    ctx.matcher.ensure()
    rows = []
    bad = []
    for x in sorted(data, key=lambda x: -(x.get("lastSeenTimestamp") or 0)):
        q = str(x.get("query") or "").rstrip(".")
        a = str(x.get("answer") or "").rstrip(".")
        rr = str(x.get("rrtype") or "").upper()
        first = _ms(x.get("firstSeenTimestamp"))
        last = _ms(x.get("lastSeenTimestamp"))
        acell: Any = a
        if rr in ("A", "AAAA") and is_global(a):
            hits = ctx.matcher.match("ip", a)
            sev = "high" if any(h["kind"] in ("c2", "ioc") for h in hits) else None
            if sev:
                bad.append(a)
            acell = ip_cell(a, sev=sev)
            res.rel("ip", a)
        elif rr in ("CNAME", "MX", "NS", "PTR") and a:
            acell = cell(a, obj=("domain", a))
        qcell: Any = cell(q, obj=("domain", q)) if q and kind == "ip" else q
        if kind == "ip" and q:
            res.rel("domain", q)
        rows.append([rr, qcell, acell, first, last, x.get("times") or ""])
    res.table(res.t("tb.sec.pdns", n=len(rows)), [res.t("tb.c.type"), res.t("tb.c.query"), res.t("tb.c.answer"),
                                                  res.t("tb.c.first"), res.t("tb.c.last"), res.t("tb.c.times")],
              rows[:300], note=res.t("tb.n.pdns"), empty=res.t("tb.v.pdns_none"))
    if bad:
        res.find("medium", "tb.f.pdns_bad", "tb.fd.pdns_bad", ips=", ".join(sorted(set(bad))[:5]))
    return res.done(spec, res.t("tb.s.pdns", n=len(rows)))


def _ms(v: Any) -> str:
    try:
        return datetime.fromtimestamp(int(v) / 1000, timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OverflowError, OSError):
        return "–"


# --- certificate transparency --------------------------------------------------------------------------------------------
async def ct(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> dict[str, Any]:
    res = Result("ct", ctx.lang, target, ("domain", target))
    try:
        items = await ctx.domains.issuances(ctx.client, target, pages=2)
    except httpx.HTTPError as exc:
        raise ToolError("err.tool.upstream", detail=exc.__class__.__name__) from exc
    if items is None:
        raise ToolError("err.tb.rate", service="Cert Spotter", seconds=3600)
    names: dict[str, int] = {}
    issuers: dict[str, int] = {}
    rows = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for it in items:
        dns_names = [str(n).lower() for n in it.get("dns_names") or [] if isinstance(n, str)]
        iss = it.get("issuer") or {}
        issuer = str(iss.get("friendly_name") or iss.get("name") or "?")[:120] if isinstance(iss, dict) else "?"
        issuers[issuer] = issuers.get(issuer, 0) + 1
        for n in dns_names:
            names[n] = names.get(n, 0) + 1
        na = str(it.get("not_after") or "")[:10]
        rows.append([str(it.get("not_before") or "")[:10], cell(na, sev="low" if na and na < now else None),
                     ", ".join(dns_names[:6]) + (" …" if len(dns_names) > 6 else ""), issuer])
    rows.sort(key=lambda r: r[0], reverse=True)
    res.kv(res.t("tb.sec.overview"), [(res.t("tb.k.certs"), len(items)), (res.t("tb.k.names"), len(names)),
                                     (res.t("tb.k.issuers"), ", ".join(f"{k} ({v})" for k, v in sorted(issuers.items(), key=lambda x: -x[1])[:6]))])
    subs = sorted(n for n in names if not n.startswith("*."))
    res.items(res.t("tb.sec.names", n=len(names)), [cell(n, obj=("domain", n)) for n in subs[:200]] +
              [n for n in sorted(names) if n.startswith("*.")][:50])
    res.table(res.t("tb.sec.certs"), [res.t("tb.c.from"), res.t("tb.c.until"), res.t("tb.c.names"), res.t("tb.c.issuer")],
              rows[:100], note=res.t("tb.n.ct"))
    if len(issuers) > 2:
        res.find("info", "tb.f.ct_issuers", n=len(issuers))
    if any(n.startswith("*.") for n in names):
        res.find("info", "tb.f.ct_wildcard")
    return res.done(spec, res.t("tb.s.ct", n=len(items), names=len(names)))

