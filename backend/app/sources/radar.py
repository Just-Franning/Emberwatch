"""Cloudflare Radar – DDoS (layer 3) and application layer attacks (layer 7).

Licence of the API data: CC BY-NC 4.0 (attribution required, non-commercial).
All values are shares in percent, not absolute attack counts.
Origin = location of the attacking IP or of the Cloudflare data centre that was hit,
not the location of the perpetrator. L7 target = billing address of the attacked zone.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..db import DB

log = logging.getLogger("radar")
BASE = "https://api.cloudflare.com/client/v4/radar"

# key -> (path, parameters)
METRICS: dict[str, tuple[str, dict[str, Any]]] = {
    "l7_pairs_1d": ("/attacks/layer7/top/attacks", {"dateRange": "1d", "limit": 30}),
    "l7_target_1d": ("/attacks/layer7/top/locations/target", {"dateRange": "1d", "limit": 25}),
    "l7_target_7d": ("/attacks/layer7/top/locations/target", {"dateRange": "7d", "limit": 25}),
    "l7_origin_1d": ("/attacks/layer7/top/locations/origin", {"dateRange": "1d", "limit": 25}),
    "l7_origin_7d": ("/attacks/layer7/top/locations/origin", {"dateRange": "7d", "limit": 25}),
    "l3_target_1d": ("/attacks/layer3/top/locations/target", {"dateRange": "1d", "limit": 25}),
    "l3_target_7d": ("/attacks/layer3/top/locations/target", {"dateRange": "7d", "limit": 25}),
    "l3_origin_1d": ("/attacks/layer3/top/locations/origin", {"dateRange": "1d", "limit": 25}),
    "l3_origin_7d": ("/attacks/layer3/top/locations/origin", {"dateRange": "7d", "limit": 25}),
    "l3_vector_1d": ("/attacks/layer3/summary/VECTOR", {"dateRange": "1d"}),
    "l3_vector_7d": ("/attacks/layer3/summary/VECTOR", {"dateRange": "7d"}),
    "l3_protocol_1d": ("/attacks/layer3/summary/PROTOCOL", {"dateRange": "1d"}),
    "l7_rules_1d": ("/attacks/layer7/summary/MANAGED_RULES", {"dateRange": "1d"}),
    "l7_rules_7d": ("/attacks/layer7/summary/MANAGED_RULES", {"dateRange": "7d"}),
    "l7_product_1d": ("/attacks/layer7/summary/MITIGATION_PRODUCT", {"dateRange": "1d"}),
    "l7_industry_1d": ("/attacks/layer7/summary/INDUSTRY", {"dateRange": "1d"}),
    "l3_vector_ts_7d": ("/attacks/layer3/timeseries_groups/VECTOR", {"dateRange": "7d", "aggInterval": "1h"}),
    "l7_rules_ts_7d": ("/attacks/layer7/timeseries_groups/MANAGED_RULES", {"dateRange": "7d", "aggInterval": "1h"}),
}

# Metrics that are additionally stored per day (timeline, trends).
# A day D = calendar day UTC [D 00:00, D+1 00:00). The current day is provisionally filled with the
# rolling 24 h value (final=False) and loaded exactly on the following day.
HISTORIZE = ("l7_target_1d", "l7_origin_1d", "l3_target_1d", "l3_origin_1d", "l3_vector_1d", "l7_rules_1d", "l7_pairs_1d")


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


def _normalize(key: str, result: dict[str, Any]) -> dict[str, Any]:
    meta = result.get("meta") or {}
    out: dict[str, Any] = {"lastUpdated": meta.get("lastUpdated"), "dateRange": meta.get("dateRange")}
    anns = ((meta.get("confidenceInfo") or {}).get("annotations")) or []
    out["annotations"] = [
        {k: a.get(k) for k in ("description", "eventType", "startDate", "endDate", "linkedUrl")} for a in anns[:10]
    ]
    if "top_0" in result:
        rows = []
        for it in result["top_0"]:
            try:
                val = float(it.get("value"))
            except (TypeError, ValueError):
                continue
            rows.append({
                "origin": it.get("originCountryAlpha2"),
                "origin_name": it.get("originCountryName"),
                "target": it.get("targetCountryAlpha2"),
                "target_name": it.get("targetCountryName"),
                "value": val,
            })
        out["rows"] = rows
    elif "summary_0" in result:
        out["summary"] = {k: float(v) for k, v in (result["summary_0"] or {}).items() if _isnum(v)}
    elif "serie_0" in result:
        s = result["serie_0"] or {}
        ts = s.get("timestamps") or []
        series = {k: [float(x) if _isnum(x) else None for x in v] for k, v in s.items() if k != "timestamps" and isinstance(v, list)}
        out["timestamps"] = ts
        out["series"] = series
    return out


def _isnum(v: Any) -> bool:
    try:
        float(v)
        return True
    except (TypeError, ValueError):
        return False


async def collect(client: httpx.AsyncClient, db: DB, token: str) -> None:
    if not token:
        db.status("cloudflare_radar", False, code="missing_key", params={"var": "CF_API_TOKEN"})
        return
    errors: list[str] = []
    ok = 0
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    for key, (path, params) in METRICS.items():
        try:
            data = _normalize(key, await _get(client, token, path, params))
            db.kv_set(f"radar:{key}", data)
            if key in HISTORIZE:
                db.hist_set(key, day, {**data, "final": False})
            ok += 1
        except Exception as exc:
            errors.append(f"{key}: {exc}")
            log.warning("Radar %s: %s", key, exc)
        await asyncio.sleep(0.3)
    db.status("cloudflare_radar", ok > 0, "; ".join(errors)[:500] if errors else "", ok)


async def country_drilldown(client: httpx.AsyncClient, token: str, cc: str) -> dict[str, Any]:
    """L3 vectors with this country as target or origin, L7 rules with origin in this country."""
    if not token:
        return {}
    out: dict[str, Any] = {}
    calls = {
        "l3_vector_target_1d": ("/attacks/layer3/summary/VECTOR", {"dateRange": "1d", "location": cc, "direction": "TARGET"}),
        "l3_vector_origin_1d": ("/attacks/layer3/summary/VECTOR", {"dateRange": "1d", "location": cc, "direction": "ORIGIN"}),
        "l7_rules_origin_1d": ("/attacks/layer7/summary/MANAGED_RULES", {"dateRange": "1d", "location": cc}),
    }
    for key, (path, params) in calls.items():
        try:
            out[key] = _normalize(key, await _get(client, token, path, params))
        except Exception as exc:
            out[key] = {"error": str(exc)[:200]}
    return out


async def backfill(client: httpx.AsyncClient, db: DB, token: str, days: int) -> int:
    """Loads missing or provisional calendar days of the historised metrics exactly."""
    if not token or days <= 0:
        return 0
    today = datetime.now(timezone.utc).date()
    wanted = [(today - timedelta(days=i)).isoformat() for i in range(1, days + 1)]
    loaded = 0
    for key in HISTORIZE:
        path, params = METRICS[key]
        final = {
            r["day"] for r in db.query(
                "SELECT day FROM radar_hist WHERE metric=? AND json_extract(payload, '$.final') = 1", (key,))
        }
        for day in wanted:
            if day in final:
                continue
            q = {k: v for k, v in params.items() if k != "dateRange"}
            start = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
            q["dateStart"] = start.strftime("%Y-%m-%dT%H:%M:%SZ")
            q["dateEnd"] = (start + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            try:
                data = _normalize(key, await _get(client, token, path, q))
                db.hist_set(key, day, {**data, "final": True})
                loaded += 1
            except Exception as exc:
                log.warning("Radar-Backfill %s %s: %s", key, day, exc)
            await asyncio.sleep(0.4)
    if loaded:
        log.info("Radar backfill: %d daily values loaded", loaded)
    return loaded
