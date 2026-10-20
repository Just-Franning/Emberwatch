"""Shared context and small helpers for the tools."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..config import Settings
from ..db import DB
from ..geo import Geo
from .result import Result, cell


@dataclass
class Ctx:
    s: Settings
    db: DB
    geo: Geo
    rep: Any          # reputation.Reputation
    tk: Any           # tools.ToolKit
    matcher: Any      # logs.Matcher
    domains: Any      # domains.Domains
    surface: Any      # surface.Surface
    client: httpx.AsyncClient
    lang: str


def is_global(ip: str | None) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def obj_for(host: str, ip: str | None) -> tuple[str, str] | None:
    """Object a host-based result belongs to: the domain for hostnames, the IP for (global) IP literals."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return ("domain", host)
    return ("ip", ip or host) if is_global(ip or host) else None


def loc_text(ctx: Ctx, g: dict[str, Any] | None) -> str | None:
    if not g:
        return None
    parts = [g.get("city"), ctx.geo.country_name(g.get("country"), ctx.lang) if g.get("country") else None]
    return ", ".join(p for p in parts if p) or None


def as_text(g: dict[str, Any] | None) -> str | None:
    if not g or not g.get("asn"):
        return None
    return f"AS{g['asn']} {g.get('as_name') or ''}".strip()


def ip_cell(ip: str | None, sev: str | None = None) -> Any:
    if not ip:
        return "*"
    return cell(ip, sev=sev, obj=("ip", ip) if is_global(ip) else None, mono=True)


def asn_cell(g: dict[str, Any] | None) -> Any:
    txt = as_text(g)
    if not txt:
        return None
    return cell(txt, obj=("asn", str(g["asn"])))


def geo_of(ctx: Ctx, ip: str) -> dict[str, Any] | None:
    g = ctx.geo.lookup(ip)
    if not g:
        return None
    return {k: g.get(k) for k in ("country", "city", "lat", "lon", "asn", "as_name")}


def relate_ip(res: Result, ip: str | None, g: dict[str, Any] | None) -> None:
    if ip and is_global(ip):
        res.rel("ip", ip)
    if g and g.get("asn"):
        res.rel("asn", str(g["asn"]), as_text(g))
    if g and g.get("country"):
        res.rel("country", g["country"])


CACHE_PREFIXES = ("pdns:", "gn:", "mb:")


def cache_get(db: DB, key: str, max_age_s: int) -> Any:
    """Cached third-party answer from the kv table (None if missing or older than max_age_s)."""
    payload, fetched = db.kv_get(key)
    if payload is None or not fetched:
        return None
    try:
        age = (datetime.now(timezone.utc) - datetime.strptime(fetched, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)).total_seconds()
    except ValueError:
        return None
    return payload if age < max_age_s else None


def cache_prune(db: DB, days: int = 7) -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for prefix in CACHE_PREFIXES:
        db.execute("DELETE FROM kv WHERE key LIKE ? AND fetched_at < ?", (prefix + "%", cutoff))


def c2_hits(ctx: Ctx, ip: str) -> list[dict[str, Any]]:
    return ctx.db.query("SELECT malware, source, ioc, first_seen, last_seen, reference FROM c2 WHERE ip=? "
                        "ORDER BY first_seen DESC LIMIT 20", (ip,))
