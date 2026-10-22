"""ENISA EU Vulnerability Database (EUVD) – vulnerabilities exploited according to ENISA (3.3, optional,
SOURCES_DISABLE=euvd).

The list complements CISA KEV with ENISA's view and the EUVD identifiers. The API (euvdservices.enisa.europa.eu/api)
is public; its format here follows the documented answers (items with id, aliases "CVE-…\\n", exploitedSince
"Apr 9, 2025, 12:00:00 AM", baseScore, epss, enisaIdVendor/enisaIdProduct). The gateway refuses some default HTTP
client user agents, so Emberwatch sends its own. ENISA: "Reproduction ... is authorized, provided the source is
acknowledged."
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime
from typing import Any

import httpx

from ..db import DB, utcnow

API = "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities"
PAGE = 100
MAX_PAGES = 30
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
EUVD_RE = re.compile(r"^EUVD-\d{4}-\d{1,8}$")
DATE_FORMATS = ("%b %d, %Y, %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")


def _date(raw: Any) -> str | None:
    s = str(raw or "").strip().replace(" ", " ")
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(s[:30], fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


def _num(raw: Any, lo: float, hi: float) -> float | None:
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def _first_name(items: Any, key: str) -> str | None:
    for x in items if isinstance(items, list) else []:
        name = ((x or {}).get(key) or {}).get("name") if isinstance(x, dict) else None
        if name:
            return str(name)[:120]
    return None


def parse(body: Any) -> list[tuple[Any, ...]]:
    """(cve, euvd_id, exploited_since, score, epss, vendor, product, published) for each CVE of each item."""
    items = body.get("items") if isinstance(body, dict) else body if isinstance(body, list) else None
    out = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            continue
        eid = str(it.get("id") or "").strip()
        if not EUVD_RE.match(eid):
            continue
        for cve in dict.fromkeys(CVE_RE.findall(str(it.get("aliases") or ""))):
            out.append((cve, eid, _date(it.get("exploitedSince")), _num(it.get("baseScore"), 0, 10),
                        _num(it.get("epss"), 0, 100),  # stored as given; Emberwatch shows FIRST's EPSS
                        _first_name(it.get("enisaIdVendor"), "vendor"), _first_name(it.get("enisaIdProduct"), "product"),
                        _date(it.get("datePublished"))))
    return out


async def collect(client: httpx.AsyncClient, db: DB, ua: str) -> None:
    rows: list[tuple[Any, ...]] = []
    try:
        for page in range(MAX_PAGES):
            r = await client.get(API, params={"page": page, "size": PAGE}, headers={"User-Agent": ua, "Accept": "application/json"},
                                 timeout=45)
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code}")
            body = r.json()
            got = parse(body)
            rows += got
            items = body.get("items") if isinstance(body, dict) else None
            if not isinstance(items, list) or len(items) < PAGE:
                break
            await asyncio.sleep(1)
    except (httpx.HTTPError, ValueError) as exc:
        if not rows:
            db.status("euvd", False, f"{exc.__class__.__name__}: {str(exc)[:160]}")
            return
    now = utcnow()
    db.execmany("INSERT INTO euvd(cve, euvd_id, exploited_since, score, epss, vendor, product, published, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(cve) DO UPDATE SET euvd_id=excluded.euvd_id, "
                "exploited_since=excluded.exploited_since, score=excluded.score, epss=excluded.epss, vendor=excluded.vendor, "
                "product=excluded.product, published=excluded.published, updated_at=excluded.updated_at",
                [(*r, now) for r in rows])
    db.status("euvd", True, "", db.query("SELECT COUNT(*) AS n FROM euvd")[0]["n"])
