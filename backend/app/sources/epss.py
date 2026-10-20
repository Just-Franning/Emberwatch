"""FIRST EPSS – probability of exploitation in the next 30 days.

API: https://api.first.org/data/v1/epss?cve=A,B,... (public, no key).
Values arrive as strings; the default page size is 100, so 100 CVEs per request.
Scored CVEs: CISA KEV plus every CVE that concerns the user (watched products, attack surface).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re

import httpx

from ..db import DB

log = logging.getLogger("epss")
URL = "https://api.first.org/data/v1/epss"
BATCH = 100
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
UPSERT = ("INSERT INTO epss(cve, epss, percentile, date) VALUES(?,?,?,?) "
          "ON CONFLICT(cve) DO UPDATE SET epss=excluded.epss, percentile=excluded.percentile, date=excluded.date")


async def fetch(client: httpx.AsyncClient, ua: str, cves: list[str]) -> tuple[list[tuple], int]:
    """Returns (rows, failed_batches) for the given CVE ids."""
    cves = [c.upper() for c in dict.fromkeys(cves) if CVE_RE.match(str(c).upper())]
    rows: list[tuple] = []
    errors = 0
    for i in range(0, len(cves), BATCH):
        batch = cves[i:i + BATCH]
        try:
            r = await client.get(URL, params={"cve": ",".join(batch), "limit": BATCH},
                                 headers={"User-Agent": ua, "Accept": "application/json"}, timeout=60)
            r.raise_for_status()
            for d in r.json().get("data") or []:
                try:
                    rows.append((str(d["cve"]).upper(), float(d["epss"]), float(d["percentile"]), d.get("date")))
                except (KeyError, TypeError, ValueError):
                    continue
        except Exception as exc:
            errors += 1
            log.warning("EPSS batch %d: %s", i // BATCH, exc)
        await asyncio.sleep(0.2)
    return rows, errors


def own_cves(db: DB) -> list[str]:
    """CVEs of watched products and of the attack surface (InternetDB)."""
    cves = [r["cve"] for r in db.query("SELECT DISTINCT cve FROM product_cves")]
    for r in db.query("SELECT vulns FROM surface"):
        try:
            cves += [str(v) for v in json.loads(r["vulns"] or "[]")]
        except ValueError:
            continue
    return cves


async def collect(client: httpx.AsyncClient, db: DB, ua: str) -> None:
    kev = [r["cve"] for r in db.query("SELECT cve FROM kev ORDER BY date_added DESC")]
    if not kev:
        db.status("epss", False, code="no_kev")
        return
    rows, errors = await fetch(client, ua, kev + own_cves(db))
    db.execmany(UPSERT, rows)
    db.status("epss", errors == 0 or bool(rows), "", len(rows),
              code="batches_failed" if errors else None, params={"count": errors} if errors else None)


async def ensure(client: httpx.AsyncClient, db: DB, ua: str, cves: list[str]) -> None:
    """Fetches scores for CVEs that have none yet (e.g. right after a product was added)."""
    have = {r["cve"] for r in db.query("SELECT cve FROM epss")}
    missing = [c for c in cves if c.upper() not in have]
    if missing:
        rows, _ = await fetch(client, ua, missing[:1000])
        db.execmany(UPSERT, rows)
