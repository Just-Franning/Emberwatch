"""abuse.ch – reported botnet C2 servers and network IOCs.

- Feodo Tracker IP blocklist (JSON): C2 of banking trojans/loaders including country and AS
- ThreatFox get_iocs (Auth-Key required): IOCs with threat_type "botnet_cc" go to the C2 map;
  all network IOCs (ip:port, domain, url) also go to the "iocs" table used for log analysis.

Coordinates come from DB-IP (approximate, city/region level).
"""
from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..db import DB, utcnow
from ..geo import Geo
from .fetch import get_capped

log = logging.getLogger("abusech")

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
URLHAUS_MAX_BYTES = 25 * 1024 * 1024

UPSERT = """
INSERT INTO c2(id, source, ioc, ip, port, malware, threat_type, status, confidence, first_seen, last_seen,
               country, city, lat, lon, geo_precision, asn, as_name, reference, updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
  status=excluded.status, last_seen=COALESCE(excluded.last_seen, c2.last_seen),
  malware=excluded.malware, confidence=excluded.confidence,
  country=COALESCE(excluded.country, c2.country), city=COALESCE(excluded.city, c2.city),
  lat=COALESCE(excluded.lat, c2.lat), lon=COALESCE(excluded.lon, c2.lon),
  geo_precision=COALESCE(excluded.geo_precision, c2.geo_precision),
  asn=COALESCE(excluded.asn, c2.asn), as_name=COALESCE(excluded.as_name, c2.as_name),
  updated_at=excluded.updated_at
"""

IOC_UPSERT = """
INSERT INTO iocs(id, ioc, ioc_type, ip, host, port, threat_type, malware, confidence, first_seen, last_seen, reference, updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
  last_seen=COALESCE(excluded.last_seen, iocs.last_seen), malware=excluded.malware,
  confidence=excluded.confidence, threat_type=excluded.threat_type, updated_at=excluded.updated_at
"""


def _place(geo: Geo, ip: str | None, source_cc: str | None) -> dict[str, Any]:
    g = geo.lookup(ip) or {}
    out: dict[str, Any] = {
        "country": (source_cc or g.get("country") or None),
        "city": g.get("city"),
        "lat": g.get("lat"),
        "lon": g.get("lon"),
        "precision": "city" if g.get("lat") is not None else None,
        "asn": g.get("asn"),
        "as_name": g.get("as_name"),
    }
    if out["lat"] is None and out["country"]:
        c = geo.centroid(out["country"])
        if c:
            out["lat"], out["lon"], out["precision"] = c[0], c[1], "country"
    return out


def _norm_ts(v: Any) -> str | None:
    """'2026-10-18 12:00:00 UTC' / '2026-10-18 12:00:00' / '2026-10-18' -> ISO UTC."""
    if not v:
        return None
    s = str(v).replace(" UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


async def collect_feodo(client: httpx.AsyncClient, db: DB, geo: Geo, ua: str, key: str = "") -> None:
    headers = {"User-Agent": ua}
    if key:  # abuse.ch requires authentication for API data since 2025-06-30; the header does not hurt downloads
        headers["Auth-Key"] = key
    try:
        r = await client.get(FEODO_URL, headers=headers, timeout=60)
        r.raise_for_status()
        entries = r.json()
        if not isinstance(entries, list):
            raise ValueError("unexpected format")
    except Exception as exc:
        db.status("feodo", False, str(exc))
        return
    now = utcnow()
    rows = []
    for e in entries:
        ip = e.get("ip_address")
        if not ip:
            continue
        port = e.get("port")
        p = _place(geo, ip, e.get("country"))
        rows.append((
            f"feodo:{ip}:{port}", "feodo", f"{ip}:{port}", ip, port, e.get("malware") or "unknown", "botnet_cc",
            e.get("status"), None, _norm_ts(e.get("first_seen")), _norm_ts(e.get("last_online")),
            p["country"], p["city"], p["lat"], p["lon"], p["precision"],
            e.get("as_number") or p["asn"], e.get("as_name") or p["as_name"],
            f"https://feodotracker.abuse.ch/browse/host/{ip}/", now,
        ))
    db.execmany(UPSERT, rows)
    db.status("feodo", True, "", len(rows))


async def collect_threatfox(client: httpx.AsyncClient, db: DB, geo: Geo, ua: str, key: str) -> None:
    if not key:
        db.status("threatfox", False, code="missing_key", params={"var": "ABUSECH_AUTH_KEY"})
        return
    have = db.query("SELECT (SELECT COUNT(*) FROM c2 WHERE source='threatfox') + "
                    "(SELECT COUNT(*) FROM iocs WHERE id NOT LIKE 'urlhaus:%') AS n")[0]["n"]  # URLhaus rows are not ThreatFox data
    days = 1 if have else 7  # initial fill with 7 days (API maximum)
    try:
        r = await client.post(
            THREATFOX_URL,
            json={"query": "get_iocs", "days": days},
            headers={"Auth-Key": key, "User-Agent": ua},
            timeout=90,
        )
        r.raise_for_status()
        body = r.json()
        if body.get("query_status") not in ("ok", "no_result"):
            raise ValueError(f"query_status={body.get('query_status')}")
        data = body.get("data") or []
        if not isinstance(data, list):
            data = []
    except Exception as exc:
        db.status("threatfox", False, str(exc))
        return
    now = utcnow()
    rows, ioc_rows = [], []
    for e in data:
        ioc = str(e.get("ioc") or "")[:2000]
        ioc_type = e.get("ioc_type")
        ip, port, host = None, None, None
        if ioc_type == "ip:port" and ":" in ioc:
            h, _, prt = ioc.rpartition(":")
            h = h.strip("[]")
            try:
                ip = str(ipaddress.ip_address(h))
                port = int(prt) if prt.isdigit() else None
            except ValueError:
                pass
        elif ioc_type in ("domain", "url"):
            host = ioc_host(ioc)
            if host:
                try:
                    ip = str(ipaddress.ip_address(host))
                    host = None
                except ValueError:
                    pass
        try:
            conf = int(e.get("confidence_level")) if e.get("confidence_level") is not None else None
        except (TypeError, ValueError):
            conf = None
        malware = e.get("malware_printable") or e.get("malware") or "unknown"
        if ioc_type in ("ip:port", "domain", "url") and (ip or host):
            ioc_rows.append((
                f"threatfox:{e.get('id')}", ioc, ioc_type, ip, host, port, e.get("threat_type"), malware, conf,
                _norm_ts(e.get("first_seen")), _norm_ts(e.get("last_seen")),
                f"https://threatfox.abuse.ch/ioc/{e.get('id')}/", now,
            ))
        if e.get("threat_type") != "botnet_cc":
            continue
        p = _place(geo, ip, None) if ip else {k: None for k in ("country", "city", "lat", "lon", "precision", "asn", "as_name")}
        rows.append((
            f"threatfox:{e.get('id')}", "threatfox", ioc, ip, port, malware, ioc_type, "reported", conf,
            _norm_ts(e.get("first_seen")), _norm_ts(e.get("last_seen")),
            p["country"], p["city"], p["lat"], p["lon"], p["precision"], p["asn"], p["as_name"],
            f"https://threatfox.abuse.ch/ioc/{e.get('id')}/", now,
        ))
    db.execmany(UPSERT, rows)
    db.execmany(IOC_UPSERT, ioc_rows)
    db.status("threatfox", True, "", len(rows))
    db.status("threatfox_iocs", True, "", db.query("SELECT COUNT(*) AS n FROM iocs")[0]["n"])


async def collect_urlhaus(client: httpx.AsyncClient, db: DB, ua: str, key: str) -> None:
    """URLhaus (3.3): URLs that distribute malware, added in the last days (API v1 urls/recent, Auth-Key).
    They go to the "iocs" table (type url): log analysis, the IOC match and the watchlist (your domains and networks)
    use them like ThreatFox IOCs."""
    if not key:
        db.status("urlhaus", False, code="missing_key", params={"var": "ABUSECH_AUTH_KEY"})
        return
    try:
        status, _, raw = await get_capped(client, URLHAUS_RECENT, max_bytes=URLHAUS_MAX_BYTES, timeout=90,
                                          headers={"Auth-Key": key, "User-Agent": ua})
        if status != 200:
            raise ValueError(f"HTTP {status}")
        body = json.loads(raw)
        if not isinstance(body, dict) or body.get("query_status") not in ("ok", "no_results"):
            raise ValueError(f"query_status={body.get('query_status') if isinstance(body, dict) else '?'}")
        data = body.get("urls") or []
        if not isinstance(data, list):
            data = []
    except Exception as exc:
        db.status("urlhaus", False, f"{exc.__class__.__name__}: {str(exc)[:160]}")
        return
    now = utcnow()
    rows = []
    for e in data[:5000]:
        if not isinstance(e, dict) or not e.get("id"):
            continue
        url = str(e.get("url") or "")[:2000]
        host = ioc_host(url)
        if not url or not host:
            continue
        ip = None
        try:
            ip = str(ipaddress.ip_address(host))
            host = None
        except ValueError:
            pass
        tags = [str(t)[:40] for t in (e.get("tags") or []) if t] if isinstance(e.get("tags"), list) else []
        ref = str(e.get("urlhaus_reference") or "")
        rows.append((
            f"urlhaus:{e.get('id')}", url, "url", ip, host, None, str(e.get("threat") or "malware_download")[:40],
            tags[0] if tags else "unknown", None, _norm_ts(e.get("date_added")), _norm_ts(e.get("date_added")),
            ref if ref.startswith("https://urlhaus.abuse.ch/") else f"https://urlhaus.abuse.ch/url/{e.get('id')}/", now,
        ))
    db.execmany(IOC_UPSERT, rows)
    db.status("urlhaus", True, "", db.query("SELECT COUNT(*) AS n FROM iocs WHERE id LIKE 'urlhaus:%'")[0]["n"])


def ioc_host(ioc: str) -> str | None:
    """Host part of a ThreatFox domain/URL IOC, lower case, without port and trailing dot."""
    s = (ioc or "").strip().lower()
    if "://" in s:
        try:
            s = urlsplit(s).hostname or ""
        except ValueError:
            return None
    else:
        s = s.split("/", 1)[0]
        if s.count(":") == 1:
            s = s.split(":", 1)[0]
    s = s.strip("[]").rstrip(".")
    return s[:253] or None


def prune(db: DB, retention_days: int, ioc_retention_days: int | None = None) -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute("DELETE FROM c2 WHERE updated_at < ?", (cutoff,))
    if ioc_retention_days:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=ioc_retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        db.execute("DELETE FROM iocs WHERE COALESCE(last_seen, first_seen, updated_at) < ?", (cutoff,))
