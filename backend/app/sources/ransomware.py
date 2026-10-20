"""ransomware.live – victims published on leak sites.

Prefers the PRO API (free key, X-API-KEY), otherwise the legacy API v2.
Per the terms: credit "Source: Ransomware.live" with a link, data is cached for 30 min,
do not poll more often, do not republish raw data.

Note: victim and group names come from extortion sites and are attacker-controlled text.
They are only displayed escaped and never passed to the LLM.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..db import DB

log = logging.getLogger("ransomware")

PRO_URL = "https://api-pro.ransomware.live/victims/recent"
PRO_MONTH_URL = "https://api-pro.ransomware.live/victims/"
LEGACY_URL = "https://api.ransomware.live/v2/recentvictims"
LEGACY_MONTH_URL = "https://api.ransomware.live/v2/victims/{year}/{month}"


def _iso(v: Any) -> str | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _items(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, list):
        return [x for x in body if isinstance(x, dict)]
    if isinstance(body, dict):
        for k in ("victims", "data", "results", "items"):
            if isinstance(body.get(k), list):
                return [x for x in body[k] if isinstance(x, dict)]
    return []


def _rows(items: list[dict[str, Any]]) -> list[tuple]:
    rows = []
    for v in items:
        victim = str(v.get("victim") or v.get("post_title") or "")[:300]
        grp = str(v.get("group") or v.get("group_name") or "")[:100]
        if not victim or not grp:
            continue
        # key from group + victim: stable across the recent and the monthly endpoint
        vid = hashlib.sha1(f"{grp.lower()}|{victim.lower()}".encode()).hexdigest()
        cc = (v.get("country") or "").strip().upper()[:2] or None
        rows.append((
            vid, victim, grp, cc, (v.get("activity") or v.get("sector") or None),
            _iso(v.get("discovered")), _iso(v.get("attackdate")), v.get("permalink"),
        ))
    return rows


def _store(db: DB, rows: list[tuple]) -> None:
    db.execmany(
        "INSERT INTO victims(id, victim, grp, country, activity, discovered, attackdate, permalink) "
        "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET country=COALESCE(excluded.country, victims.country), "
        "activity=COALESCE(excluded.activity, victims.activity), permalink=COALESCE(excluded.permalink, victims.permalink)",
        rows,
    )


def _headers(ua: str, key: str) -> dict[str, str]:
    h = {"User-Agent": ua, "Accept": "application/json"}
    if key:
        h["X-API-KEY"] = key
    return h


async def collect(client: httpx.AsyncClient, db: DB, ua: str, key: str) -> None:
    url = PRO_URL if key else LEGACY_URL
    try:
        r = await client.get(url, headers=_headers(ua, key), timeout=60)
        r.raise_for_status()
        rows = _rows(_items(r.json()))
    except Exception as exc:
        db.status("ransomware_live", False, str(exc), code="api_pro" if key else "api_legacy")
        return
    _store(db, rows)
    db.status("ransomware_live", True, "", len(rows), code="api_pro" if key else "api_legacy")


async def backfill(client: httpx.AsyncClient, db: DB, ua: str, key: str) -> None:
    """Once: current and previous month, so that week-over-week comparisons work right away."""
    if db.meta_get("ransomware_backfill") == "done":
        return
    today = datetime.now(timezone.utc).date()
    prev = (today.replace(day=1) - timedelta(days=1))
    months = [(prev.year, prev.month), (today.year, today.month)]
    ok = 0
    for i, (y, m) in enumerate(months):
        if key:
            url, params = PRO_MONTH_URL, {"year": y, "month": m}
        else:
            url, params = LEGACY_MONTH_URL.format(year=y, month=m), None
            if i:
                await asyncio.sleep(61)  # legacy API: 1 request per minute and endpoint
        try:
            r = await client.get(url, params=params, headers=_headers(ua, key), timeout=120)
            r.raise_for_status()
            _store(db, _rows(_items(r.json())))
            ok += 1
        except Exception as exc:
            log.warning("Ransomware-Backfill %04d-%02d: %s", y, m, exc)
    if ok == len(months):
        db.meta_set("ransomware_backfill", "done")
