"""Infrastructure events from Cloudflare Radar (same token, CC BY-NC 4.0).

- Internet outages (annotations/outages) with cause, e.g. CABLE_CUT, POWER_OUTAGE
- BGP hijacks and route leaks
- Traffic anomalies per country or AS

All events are stored normalised in infra_events: countries/asns as JSON lists, start/end as ISO UTC,
plus a language-neutral "meta" object that i18n.py renders into German or English text.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .. import i18n
from ..db import DB, utcnow

log = logging.getLogger("infra")
BASE = "https://api.cloudflare.com/client/v4/radar"

UPSERT = """
INSERT INTO infra_events(id, kind, start_ts, end_ts, countries, asns, title, detail, cause, scope, confidence, url, updated_at, prefixes, meta)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET end_ts=excluded.end_ts, countries=excluded.countries, asns=excluded.asns, prefixes=excluded.prefixes,
  title=excluded.title, detail=excluded.detail, cause=excluded.cause, scope=excluded.scope,
  confidence=excluded.confidence, url=excluded.url, updated_at=excluded.updated_at, meta=excluded.meta
"""


def _iso(v: Any) -> str | None:
    if not v:
        return None
    s = str(v).strip()
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cc(v: Any) -> str | None:
    s = str(v or "").strip().upper()
    return s if len(s) == 2 and s.isalpha() else None


def _row(eid: str, kind: str, start: str | None, end: str | None, countries: list[str], asns: list[int],
         meta: dict[str, Any], cause: str | None, scope: str | None, conf: int | None, url: str | None,
         now: str, prefixes: list[str]) -> tuple:
    """DB row. title/detail are stored in English for readability; the API renders them per language from meta."""
    meta = {**meta, "kind": kind}
    return (eid, kind, start, end, json.dumps(countries), json.dumps(asns),
            i18n.render_infra_title(kind, meta, "en"), i18n.render_infra_detail(meta, "en"),
            cause, scope, conf, url if url and str(url).startswith("https://") else None, now,
            json.dumps(prefixes), json.dumps(meta, ensure_ascii=False))


async def _get(client: httpx.AsyncClient, token: str, path: str, params: dict[str, Any]) -> dict[str, Any]:
    q = dict(params)
    q["format"] = "json"
    r = await client.get(BASE + path, params=q, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    body = r.json()
    if not body.get("success", False):
        raise RuntimeError(f"API error: {body.get('errors')}")
    return body.get("result") or {}


def _outages(result: dict[str, Any], now: str) -> list[tuple]:
    rows = []
    for a in result.get("annotations") or []:
        if not a.get("id"):
            continue
        outage = a.get("outage") or {}
        cause = str(outage.get("outageCause") or "UNKNOWN").upper()
        countries = sorted({c for c in (_cc(x) for x in a.get("locations") or []) if c})
        asns = sorted({int(x) for x in a.get("asns") or [] if str(x).isdigit()})
        meta = {
            "cause": cause,
            "description": str(a.get("description") or "")[:300] or None,
            "locations": [str(d.get("name"))[:80] for d in a.get("locationsDetails") or [] if d and d.get("name")][:10],
            "nets": [str(d.get("name"))[:80] for d in a.get("asnsDetails") or [] if d and d.get("name")][:10],
        }
        scope = a.get("scope") or outage.get("outageType")
        rows.append(_row(f"outage:{a['id']}", "outage", _iso(a.get("startDate")), _iso(a.get("endDate")),
                         countries, asns, meta, cause, scope, None, a.get("linkedUrl"), now, []))
    return rows


def _hijacks(result: dict[str, Any], now: str) -> list[tuple]:
    rows = []
    info = {int(x["asn"]): x for x in result.get("asn_info") or [] if str(x.get("asn", "")).isdigit()}
    for e in result.get("events") or []:
        if e.get("id") is None:
            continue
        hij = e.get("hijacker_asn")
        hij_asn = int(hij) if str(hij).isdigit() else None
        victims = [int(v) for v in e.get("victim_asns") or [] if str(v).isdigit()]
        countries = {c for c in (_cc(x) for x in (e.get("victim_countries") or []) + [e.get("hijacker_country")]) if c}
        asns = sorted(set(victims + ([hij_asn] if hij_asn is not None else [])))
        prefixes = [str(x) for x in e.get("prefixes") or []][:200]
        meta = {
            "asn": hij_asn, "name": str((info.get(hij_asn) or {}).get("org_name", ""))[:80] if hij_asn is not None else "",
            "cc": _cc(e.get("hijacker_country")),
            "victims": [[v, str((info.get(v) or {}).get("org_name", ""))[:80]] for v in victims[:10]],
            "prefixes": prefixes[:20],
        }
        try:
            conf = int(e.get("confidence_score"))
        except (TypeError, ValueError):
            conf = None
        rows.append(_row(f"hijack:{e['id']}", "hijack", _iso(e.get("min_hijack_ts")), _iso(e.get("max_hijack_ts")),
                         sorted(countries), asns, meta, None, None, conf, None, now, prefixes))
    return rows


def _leaks(result: dict[str, Any], now: str) -> list[tuple]:
    rows = []
    info = {int(x["asn"]): x for x in result.get("asn_info") or [] if str(x.get("asn", "")).isdigit()}
    for e in result.get("events") or []:
        if e.get("id") is None:
            continue
        leak = e.get("leak_asn")
        leak_asn = int(leak) if str(leak).isdigit() else None
        seg = [int(v) for v in e.get("leak_seg") or [] if str(v).isdigit()]
        asns = sorted(set(seg + ([leak_asn] if leak_asn is not None else [])))
        countries = sorted({c for c in (_cc(x) for x in e.get("countries") or []) if c})
        meta = {
            "asn": leak_asn, "name": str((info.get(leak_asn) or {}).get("org_name", ""))[:80] if leak_asn is not None else "",
            "prefix_count": e.get("prefix_count"), "origin_count": e.get("origin_count"), "peer_count": e.get("peer_count"),
            "seg": seg[:10],
        }
        rows.append(_row(f"leak:{e['id']}", "leak", _iso(e.get("min_ts")), _iso(e.get("max_ts")) if e.get("finished") else None,
                         countries, asns, meta, None, None, None, None, now, []))
    return rows


def _anomalies(result: dict[str, Any], now: str) -> list[tuple]:
    rows = []
    for a in result.get("trafficAnomalies") or []:
        if not a.get("uuid"):
            continue
        asn_d = a.get("asnDetails") or {}
        loc_d = a.get("locationDetails") or {}
        cc = _cc(loc_d.get("code")) or _cc((asn_d.get("location") or {}).get("code"))
        asn = int(asn_d["asn"]) if str(asn_d.get("asn", "")).isdigit() else None
        where = (f"AS{asn} {asn_d.get('name')}" if asn and asn_d.get("name") else loc_d.get("name") or cc or "?")
        meta = {"where": str(where)[:120], "type": str(a.get("type") or "")[:40] or None,
                "status": str(a.get("status") or "")[:40] or None}
        rows.append(_row(f"anomaly:{a['uuid']}", "anomaly", _iso(a.get("startDate")), _iso(a.get("endDate")),
                         [cc] if cc else [], [asn] if asn else [], meta, None, a.get("type"), None, None, now, []))
    return rows


def _note_outage_run(db: DB) -> None:
    """Days with a successful outage run: each run reads the 7 days before it, so a missing outage on a day that such
    a run covered is meaningful (corroborate.py). Kept for 70 days."""
    today = datetime.now(timezone.utc).date()
    try:
        days = json.loads(db.meta_get("outage_runs") or "[]")
    except ValueError:
        days = []
    keep = (today - timedelta(days=70)).isoformat()
    days = sorted({d for d in days if isinstance(d, str) and d >= keep} | {today.isoformat()})
    db.meta_set("outage_runs", json.dumps(days))


async def collect(client: httpx.AsyncClient, db: DB, token: str) -> None:
    if not token:
        db.status("radar_infra", False, code="missing_key", params={"var": "CF_API_TOKEN"})
        return
    now = utcnow()
    calls = [
        ("outages", "/annotations/outages", {"dateRange": "7d", "limit": 100}, _outages),
        ("hijacks", "/bgp/hijacks/events", {"dateRange": "7d", "per_page": 100, "sortBy": "TIME", "sortOrder": "DESC"}, _hijacks),
        ("leaks", "/bgp/leaks/events", {"dateRange": "7d", "per_page": 100, "sortBy": "TIME", "sortOrder": "DESC"}, _leaks),
        ("anomalies", "/traffic_anomalies", {"dateRange": "7d", "limit": 100}, _anomalies),
    ]
    errors, total = [], 0
    for name, path, params, parse in calls:
        try:
            rows = parse(await _get(client, token, path, params), now)
            db.execmany(UPSERT, rows)
            total += len(rows)
            if name == "outages":
                _note_outage_run(db)
        except Exception as exc:
            errors.append(f"{name}: {exc}")
            log.warning("Radar-Infra %s: %s", name, exc)
        await asyncio.sleep(0.3)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute("DELETE FROM infra_events WHERE COALESCE(end_ts, start_ts, updated_at) < ?", (cutoff,))
    db.status("radar_infra", len(errors) < len(calls), "; ".join(errors)[:500], total)
