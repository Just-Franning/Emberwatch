"""CISA Known Exploited Vulnerabilities (public, no key, CC0).

Two official sources with identical content:
- GitHub repo cisagov/kev-data: according to its README synchronised minutes after cisa.gov and explicitly
  meant for machine consumption.
- cisa.gov: the canonical source, but it rejects requests from some servers with 403.
The first source that returns a valid catalogue wins.
"""
from __future__ import annotations

import httpx

from ..db import DB

SOURCES = [
    ("GitHub cisagov/kev-data", "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"),
    ("cisa.gov", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
]


async def _fetch(client: httpx.AsyncClient, url: str, ua: str) -> list[dict]:
    r = await client.get(url, headers={"User-Agent": ua, "Accept": "application/json"}, timeout=60)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise ValueError("response contains no KEV catalogue")
    return vulns


async def collect(client: httpx.AsyncClient, db: DB, ua: str) -> bool:
    """Loads the catalogue. Returns True if one source worked."""
    errors = []
    vulns: list[dict] = []
    used = ""
    for name, url in SOURCES:
        try:
            vulns = await _fetch(client, url, ua)
            used = name
            break
        except Exception as exc:
            errors.append(f"{name}: {exc}".split("\n")[0])
    if not vulns:
        db.status("cisa_kev", False, " | ".join(errors))
        return False
    rows = [
        (
            v.get("cveID"), v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"),
            v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"),
        )
        for v in vulns
        if isinstance(v, dict) and v.get("cveID")
    ]
    db.execmany(
        "INSERT INTO kev(cve, vendor, product, name, date_added, due_date, ransomware) VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(cve) DO UPDATE SET ransomware=excluded.ransomware, due_date=excluded.due_date",
        rows,
    )
    if errors:
        db.status("cisa_kev", True, "", len(rows), code="kev_source_fallback", params={"source": used, "failed": "; ".join(errors)})
    else:
        db.status("cisa_kev", True, "", len(rows), code="kev_source", params={"source": used})
    return True
