"""Is it dangerous: local threat data (C2, ThreatFox, DROP, Tor), GreyNoise, MalwareBazaar, look-alike domains."""
from __future__ import annotations

from typing import Any

import httpx

from ..logs import _norm_url, severity
from ..tools import ToolError
from .common import Ctx, cache_get, ip_cell
from .detect import url_host
from .registry import ToolSpec
from .result import Result, cell

GREYNOISE = "https://api.greynoise.io/v3/community/{ip}"
MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1/"
MATCH_LABEL = {"c2": "Feodo Tracker (C2)", "ioc": "ThreatFox", "tor": "Tor", "drop": "Spamhaus DROP"}


def _match_rows(res: Result, matches: list[dict[str, Any]]) -> list[list[Any]]:
    rows = []
    for m in matches:
        kind = m.get("kind")
        sev = "high" if kind == "c2" or m.get("threat") == "botnet_cc" else "medium" if kind in ("ioc", "drop") else "info"
        detail = m.get("cidr") and f"{m['cidr']} ({m.get('sblid') or 'SBL'})"
        rows.append([cell(MATCH_LABEL.get(kind, kind), sev=sev),
                     cell(m.get("malware") or "", obj=("malware", m["malware"]) if m.get("malware") else None),
                     m.get("threat") or detail or "", cell("↗", href=m.get("reference")) if m.get("reference") else ""])
    return rows


async def ioc(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> dict[str, Any]:
    res = Result("ioc", ctx.lang, target, (kind, target))
    ctx.matcher.ensure()
    matches: list[dict[str, Any]] = []
    if kind == "ip":
        matches = ctx.matcher.match("ip", target)
    elif kind == "domain":
        matches = ctx.matcher.match("domain", target)
    elif kind == "url":
        n = _norm_url(target)
        matches = ctx.matcher.match("url", n) if n else []
        host = url_host(target)
        if host:
            dom = ctx.matcher.match("domain", host)
            matches += [{**m, "via": host} for m in dom]
            if host.replace(".", "").isdigit() or ":" in host:
                matches += ctx.matcher.match("ip", host)
    res.table(res.t("tb.sec.matches"), [res.t("tb.c.source"), res.t("tb.c.malware"), res.t("tb.c.threat"), ""],
              _match_rows(res, matches), empty=res.t("tb.v.no_match"))
    for m in matches:
        if m.get("malware"):
            res.rel("malware", m["malware"])
    if matches:
        sev = severity(matches)
        if all(m.get("kind") == "tor" for m in matches):
            sev = "info"
        res.find(sev, "tb.f.ioc_hit", n=len(matches))
    # look-alike of an own asset?
    if kind in ("domain", "url"):
        host = target if kind == "domain" else (url_host(target) or "")
        lk = ctx.db.query("SELECT domain, technique, mx FROM typo WHERE candidate=? AND registered=1", (host,))
        for row in lk:
            res.find("high" if row["mx"] else "medium", "tb.f.lookalike_of", domain=row["domain"], technique=row["technique"])
        own = ctx.db.query("SELECT id, value FROM watchlist WHERE kind='domain' AND (value=? OR ? LIKE '%.' || value)", (host, host))
        if own:
            res.find("info", "tb.f.own_asset", value=own[0]["value"])
    elif kind == "ip":
        own = ctx.db.query("SELECT id, value FROM watchlist WHERE kind='ip' AND value=?", (target,))
        if own:
            res.find("info", "tb.f.own_asset", value=own[0]["value"])
    sources = ctx.matcher.size
    res.kv(res.t("tb.sec.basis"), [(res.t("tb.k.index"), res.t("tb.v.index", **sources))])
    summary = res.t("tb.s.ioc_hit", n=len(matches)) if matches else res.t("tb.s.ioc_none")
    return res.done(spec, summary)


async def greynoise(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> dict[str, Any]:
    res = Result("greynoise", ctx.lang, target, ("ip", target))
    key = f"gn:{target}"
    data = cache_get(ctx.db, key, 86400)
    if data is None:
        headers = {"User-Agent": ctx.s.user_agent, "Accept": "application/json"}
        if ctx.s.greynoise_api_key:
            headers["key"] = ctx.s.greynoise_api_key
        try:
            r = await ctx.client.get(GREYNOISE.format(ip=target), headers=headers, timeout=15)
        except httpx.HTTPError as exc:
            raise ToolError("err.tool.upstream", detail=exc.__class__.__name__) from exc
        if r.status_code == 429:
            raise ToolError("err.tb.quota", service="GreyNoise")
        if r.status_code == 404:
            data = {"not_observed": True}
        elif r.status_code == 200:
            try:
                body = r.json() or {}
            except ValueError as exc:
                raise ToolError("err.tool.upstream", detail="json") from exc
            data = {k: body.get(k) for k in ("noise", "riot", "classification", "name", "link", "last_seen", "message")}
        else:
            raise ToolError("err.tb.http", service="GreyNoise", status=r.status_code)
        ctx.db.kv_set(key, data)
    if data.get("not_observed"):
        res.kv(res.t("tb.sec.greynoise"), [(res.t("tb.k.ip"), ip_cell(target)), (res.t("tb.k.status"), res.t("tb.v.gn_unseen"))])
        res.find("info", "tb.f.gn_unseen")
        return res.done(spec, res.t("tb.v.gn_unseen"))
    cls = str(data.get("classification") or "unknown")
    sev = {"malicious": "high", "benign": "info", "unknown": "low"}.get(cls, "low")
    res.kv(res.t("tb.sec.greynoise"), [
        (res.t("tb.k.ip"), ip_cell(target)),
        (res.t("tb.k.scanner"), res.t("common.yes") if data.get("noise") else res.t("common.no")),
        (res.t("tb.k.riot"), res.t("common.yes") if data.get("riot") else res.t("common.no")),
        (res.t("tb.k.classification"), cell(res.t(f"tb.gn.{cls}") if cls in ("malicious", "benign", "unknown") else cls, sev=sev)),
        (res.t("tb.k.name"), data.get("name")), (res.t("tb.k.last"), data.get("last_seen")),
        (res.t("tb.k.link"), cell("viz.greynoise.io", href=data.get("link")) if data.get("link") else None)])
    if data.get("noise") and cls == "malicious":
        res.find("high", "tb.f.gn_malicious", name=data.get("name") or "?")
    elif data.get("noise") and cls == "benign":
        res.find("info", "tb.f.gn_benign", name=data.get("name") or "?")
    elif data.get("noise"):
        res.find("low", "tb.f.gn_scanner")
    if data.get("riot"):
        res.find("info", "tb.f.gn_riot", name=data.get("name") or "?")
    return res.done(spec, res.t(f"tb.gn.{cls}") if cls in ("malicious", "benign", "unknown") else cls)


async def mb_lookup(ctx: Ctx, h: str) -> dict[str, Any]:
    """MalwareBazaar get_info (cached 24 h). Returns {"status": ok|not_found|error, "data": {...}}."""
    key = f"mb:{h}"
    cached = cache_get(ctx.db, key, 86400)
    if cached is not None:
        return cached
    try:
        r = await ctx.client.post(MALWAREBAZAAR, data={"query": "get_info", "hash": h},
                                  headers={"Auth-Key": ctx.s.abusech_auth_key, "User-Agent": ctx.s.user_agent}, timeout=20)
    except httpx.HTTPError as exc:
        raise ToolError("err.tool.upstream", detail=exc.__class__.__name__) from exc
    if r.status_code in (401, 403):
        raise ToolError("err.tb.auth", service="MalwareBazaar")
    if r.status_code != 200:
        raise ToolError("err.tb.http", service="MalwareBazaar", status=r.status_code)
    try:
        body = r.json() or {}
    except ValueError as exc:
        raise ToolError("err.tool.upstream", detail="json") from exc
    qs = body.get("query_status")
    if qs == "ok" and isinstance(body.get("data"), list) and body["data"]:
        d = body["data"][0]
        out = {"status": "ok", "data": {k: d.get(k) for k in (
            "sha256_hash", "sha1_hash", "md5_hash", "first_seen", "last_seen", "file_name", "file_size", "file_type",
            "file_type_mime", "signature", "tags", "reporter", "origin_country", "delivery_method")}}
        out["data"]["vendor_intel"] = sorted((d.get("vendor_intel") or {}).keys())[:20] if isinstance(d.get("vendor_intel"), dict) else []
    elif qs == "hash_not_found":
        out = {"status": "not_found"}
    else:
        raise ToolError("err.tb.mb_status", status=str(qs)[:60])
    ctx.db.kv_set(key, out)
    return out


async def hash_lookup(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> dict[str, Any]:
    res = Result("hash", ctx.lang, target, ("hash", target))
    mb = await mb_lookup(ctx, target)
    if mb["status"] != "ok":
        res.kv(res.t("tb.sec.sample"), [(res.t("tb.k.hash"), cell(target, mono=True)), (res.t("tb.k.status"), res.t("tb.v.mb_unknown"))])
        res.find("info", "tb.f.mb_unknown", "tb.fd.mb_unknown")
        return res.done(spec, res.t("tb.v.mb_unknown"))
    d = mb["data"]
    sha = d.get("sha256_hash") or ""
    link = f"https://bazaar.abuse.ch/sample/{sha}/" if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha) else None
    res.kv(res.t("tb.sec.sample"), [
        ("SHA-256", cell(sha, mono=True)), ("SHA-1", cell(d.get("sha1_hash") or "", mono=True)), ("MD5", cell(d.get("md5_hash") or "", mono=True)),
        (res.t("tb.k.file"), d.get("file_name")), (res.t("tb.k.type"), " / ".join(x for x in (d.get("file_type"), d.get("file_type_mime")) if x)),
        (res.t("tb.k.size"), d.get("file_size")),
        (res.t("tb.k.signature"), cell(d["signature"], sev="high", obj=("malware", d["signature"])) if d.get("signature") else None),
        (res.t("tb.k.tags"), ", ".join(str(x) for x in d.get("tags") or [])), (res.t("tb.k.first"), d.get("first_seen")),
        (res.t("tb.k.last"), d.get("last_seen")), (res.t("tb.k.delivery"), d.get("delivery_method")),
        (res.t("tb.k.origin_country"), ctx.geo.country_name(d["origin_country"], ctx.lang) if d.get("origin_country") else None),
        (res.t("tb.k.vendor_intel"), ", ".join(d.get("vendor_intel") or [])),
        (res.t("tb.k.link"), cell("MalwareBazaar", href=link) if link else None)])
    res.find("high", "tb.f.mb_known", sig=d.get("signature") or d.get("file_type") or "?")
    if d.get("signature"):
        res.rel("malware", d["signature"])
    return res.done(spec, res.t("tb.s.mb", sig=d.get("signature") or "?"))


async def lookalike(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> dict[str, Any]:
    res = Result("lookalike", ctx.lang, target, ("domain", target))
    d = await ctx.domains.lookalikes(target, min(ctx.s.typo_max, 400))
    reg = d["registered"]
    ctx.matcher.ensure()
    rows = []
    for x in reg:
        bad = ctx.matcher.match("domain", x["candidate"])
        rows.append([cell(x["candidate"], obj=("domain", x["candidate"]), sev="high" if bad else None), x["technique"],
                     cell(res.t("common.yes"), sev="medium") if x["mx"] else res.t("common.no"),
                     ", ".join(x["ips"][:3])])
        if bad:
            res.find("high", "tb.f.lookalike_ioc", domain=x["candidate"])
    res.kv(res.t("tb.sec.overview"), [(res.t("tb.k.base"), d["base"]), (res.t("tb.k.checked"), d["checked"]),
                                     (res.t("tb.k.registered"), len(reg)),
                                     (res.t("tb.k.wildcard"), ", ".join(d["wildcard"]) or None)])
    res.table(res.t("tb.sec.lookalikes"), [res.t("tb.c.domain"), res.t("tb.c.technique"), "MX", "IP"], rows,
              note=res.t("tb.n.lookalike"), empty=res.t("tb.v.lookalike_none"))
    with_mx = sum(1 for x in reg if x["mx"])
    if with_mx:
        res.find("medium", "tb.f.lookalike_mx", n=with_mx)
    elif reg:
        res.find("low", "tb.f.lookalike_n", n=len(reg))
    return res.done(spec, res.t("tb.s.lookalike", n=len(reg), checked=d["checked"]))
