"""Unified alert feed for everything that concerns the user's own assets and watched products.

An alert is stored language-neutral (key + params) and deduplicated by (source, ref).
Matrix delivery happens in notify.py; every alert is delivered at most once.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from . import i18n
from .db import DB, utcnow

SOURCES = ("watch", "surface", "scan", "product", "ct", "typo", "bgp", "syslog", "rep", "legacy")
SEVERITIES = ("high", "medium", "low")
SEV_RANK = {"high": 0, "medium": 1, "low": 2}


def add(db: DB, source: str, severity: str, key: str, params: dict[str, Any], ref: str, *,
        asset_id: int | None = None, product_id: int | None = None, url: str | None = None) -> bool:
    """Stores an alert. Returns True if it is new (False if (source, ref) already existed)."""
    if source not in SOURCES or severity not in SEVERITIES:
        raise ValueError(f"invalid alert {source}/{severity}")
    if url is not None and not str(url).startswith("https://"):
        url = None
    new_id = db.insert(
        "INSERT OR IGNORE INTO alerts(created_at, source, severity, key, params, ref, asset_id, product_id, url) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (utcnow(), source, severity, key, json.dumps(params, ensure_ascii=False, default=str), ref[:500],
         asset_id, product_id, url),
    )
    return new_id > 0


def render(row: dict[str, Any], lang: str) -> dict[str, Any]:
    try:
        params = json.loads(row.get("params") or "{}")
    except ValueError:
        params = {}
    title, detail = i18n.render_alert(row, params, lang)
    return {
        "id": row["id"], "created_at": row["created_at"], "source": row["source"], "severity": row["severity"],
        "key": row["key"], "asset_id": row.get("asset_id"), "product_id": row.get("product_id"), "url": row.get("url"),
        "title": title, "detail": detail,
    }


def listing(db: DB, lang: str, *, limit: int = 100, source: str | None = None, asset_id: int | None = None,
            product_id: int | None = None, min_severity: str = "low") -> list[dict[str, Any]]:
    sql = "SELECT * FROM alerts WHERE 1=1"
    params: list[Any] = []
    if source:
        sql += " AND source = ?"
        params.append(source)
    if asset_id is not None:
        sql += " AND asset_id = ?"
        params.append(asset_id)
    if product_id is not None:
        sql += " AND product_id = ?"
        params.append(product_id)
    allowed = [s for s in SEVERITIES if SEV_RANK[s] <= SEV_RANK.get(min_severity, 2)]
    sql += f" AND severity IN ({','.join('?' * len(allowed))}) ORDER BY id DESC LIMIT ?"
    params += [*allowed, limit]
    return [render(r, lang) for r in db.query(sql, params)]


def stats(db: DB) -> dict[str, Any]:
    d7 = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = db.query("SELECT severity, COUNT(*) AS n FROM alerts WHERE created_at >= ? GROUP BY severity", (d7,))
    by = {r["severity"]: r["n"] for r in rows}
    return {"total_7d": sum(by.values()), "high_7d": by.get("high", 0), "medium_7d": by.get("medium", 0),
            "low_7d": by.get("low", 0), "total": db.query("SELECT COUNT(*) AS n FROM alerts")[0]["n"]}


def pending(db: DB, min_severity: str, limit: int = 50) -> list[dict[str, Any]]:
    """Undelivered alerts at or above min_severity. Lower ones are marked as handled so they are never sent."""
    allowed = [s for s in SEVERITIES if SEV_RANK[s] <= SEV_RANK.get(min_severity, 0)]
    skipped = [s for s in SEVERITIES if s not in allowed]
    if skipped:
        db.execute(f"UPDATE alerts SET notified=2 WHERE notified=0 AND severity IN ({','.join('?' * len(skipped))})", skipped)
    # Never flood a room with a backlog (e.g. after Matrix was configured later): only the last 24 h are delivered
    day_ago = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute("UPDATE alerts SET notified=2 WHERE notified=0 AND created_at < ?", (day_ago,))
    return db.query(
        f"SELECT * FROM alerts WHERE notified=0 AND severity IN ({','.join('?' * len(allowed))}) ORDER BY id LIMIT ?",
        (*allowed, limit),
    )


def mark_notified(db: DB, ids: list[int]) -> None:
    if ids:
        db.execute(f"UPDATE alerts SET notified=1 WHERE id IN ({','.join('?' * len(ids))})", ids)


def prune(db: DB, retention_days: int) -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute("DELETE FROM alerts WHERE created_at < ?", (cutoff,))
