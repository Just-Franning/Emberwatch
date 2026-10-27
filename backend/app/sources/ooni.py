"""OONI – measurements of internet censorship per country (3.3, optional, SOURCES_DISABLE=ooni).

Volunteers run OONI Probe; its measurements show whether websites and messengers are reachable. The aggregation API
(api.ooni.io/api/v1/aggregation, public, rate limited per IP) gives per country and day:
measurement_count, anomaly_count (a possible block, can be a false positive), confirmed_count (a block page that OONI
recognises: confirmed blocking) and failure_count. Emberwatch reads two groups per run:

- "web": web_connectivity (websites)
- "im": whatsapp, telegram, signal, facebook_messenger (messengers)

Data licence: CC BY-NC-SA 4.0, © OONI (https://ooni.org/about/data-policy). Only the daily counts are stored.
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..db import DB
from .fetch import get_capped

API = "https://api.ooni.io/api/v1/aggregation"
GROUPS = (("web", "web_connectivity"), ("im", "whatsapp,telegram,signal,facebook_messenger"))
KEEP_DAYS = 35
FIRST_DAYS = 30   # first run
UPDATE_DAYS = 4   # later runs: the last days again (probes upload late)
MAX_BYTES = 8 * 1024 * 1024
CC_RE = re.compile(r"^[A-Z]{2}$")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse(body: Any) -> list[tuple[str, str, int, int, int, int]]:
    """(cc, day, measurements, anomalies, confirmed, failures) per row; malformed rows are skipped."""
    rows = body.get("result") if isinstance(body, dict) else None
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        cc, day = str(r.get("probe_cc") or "").upper(), str(r.get("measurement_start_day") or "")[:10]
        if not CC_RE.match(cc) or cc == "ZZ" or not DAY_RE.match(day):
            continue
        try:
            nums = [max(0, int(r.get(k) or 0)) for k in ("measurement_count", "anomaly_count", "confirmed_count", "failure_count")]
        except (TypeError, ValueError):
            continue
        out.append((cc, day, *nums))
    return out


async def collect(client: httpx.AsyncClient, db: DB, ua: str) -> None:
    today = datetime.now(timezone.utc).date()
    have = db.query("SELECT 1 FROM ooni LIMIT 1")
    since = today - timedelta(days=UPDATE_DAYS if have else FIRST_DAYS)
    until = today + timedelta(days=1)
    total, errors = 0, []
    for i, (test, names) in enumerate(GROUPS):
        if i:
            await asyncio.sleep(2)
        params = {"test_name": names, "since": since.isoformat(), "until": until.isoformat(),
                  "axis_x": "measurement_start_day", "axis_y": "probe_cc", "time_grain": "day", "format": "JSON"}
        try:
            status, _, body = await get_capped(client, API, max_bytes=MAX_BYTES, params=params, timeout=90,
                                               headers={"User-Agent": ua, "Accept": "application/json"})
            if status != 200:
                raise ValueError(f"HTTP {status}")
            rows = parse(json.loads(body))
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"{test}: {exc.__class__.__name__}")
            continue
        db.execmany("INSERT INTO ooni(cc, day, test, measurements, anomalies, confirmed, failures) VALUES(?,?,?,?,?,?,?) "
                    "ON CONFLICT(cc, day, test) DO UPDATE SET measurements=excluded.measurements, anomalies=excluded.anomalies, "
                    "confirmed=excluded.confirmed, failures=excluded.failures",
                    [(cc, day, test, m, a, c, f) for cc, day, m, a, c, f in rows])
        total += len(rows)
    db.execute("DELETE FROM ooni WHERE day < ?", ((today - timedelta(days=KEEP_DAYS)).isoformat(),))
    if errors and len(errors) == len(GROUPS):
        db.status("ooni", False, "; ".join(errors))
    else:
        db.status("ooni", True, "; ".join(errors), db.query("SELECT COUNT(DISTINCT cc) AS n FROM ooni")[0]["n"])


def summary(db: DB, days: int = 7) -> list[dict[str, Any]]:
    """Per country for the last `days` and the period before: measurements, anomalies, confirmed blocking."""
    today = datetime.now(timezone.utc).date()
    cur_from = (today - timedelta(days=days - 1)).isoformat()
    prev_from = (today - timedelta(days=2 * days - 1)).isoformat()
    by: dict[str, dict[str, Any]] = {}
    for r in db.query("SELECT cc, day, test, measurements, anomalies, confirmed FROM ooni WHERE day >= ?", (prev_from,)):
        e = by.setdefault(r["cc"], {"cc": r["cc"], "web": [0, 0, 0], "im": [0, 0, 0], "web_prev": [0, 0, 0]})
        key = r["test"] if r["day"] >= cur_from else ("web_prev" if r["test"] == "web" else None)
        if key:
            e[key] = [e[key][0] + r["measurements"], e[key][1] + r["anomalies"], e[key][2] + r["confirmed"]]
    prev_kept = 2 * days <= KEEP_DAYS  # the period before is only comparable if it is stored completely
    out = []
    for e in by.values():
        w, im, wp = e["web"], e["im"], e["web_prev"]
        if not prev_kept:
            wp = [0, 0, 0]
        if w[0] + im[0] == 0:
            continue
        out.append({
            "cc": e["cc"], "measurements": w[0], "anomalies": w[1], "confirmed": w[2],
            "anomaly_pct": round(100 * w[1] / w[0], 1) if w[0] else None,
            "confirmed_prev": wp[2] if prev_kept else None, "anomaly_pct_prev": round(100 * wp[1] / wp[0], 1) if wp[0] else None,
            "im_measurements": im[0], "im_anomaly_pct": round(100 * im[1] / im[0], 1) if im[0] else None,
            "im_confirmed": im[2],
        })
    out.sort(key=lambda x: (-x["confirmed"], -(x["anomaly_pct"] or 0)))
    return out
