"""Addresses to coordinates with Nominatim (OpenStreetMap). Usage policy of the public instance: at most one request
per second, an identifying User-Agent, results cached - here 90 days (no result: 7 days). NOMINATIM_URL selects
another instance, "off" switches geocoding off. Data © OpenStreetMap contributors, ODbL."""
from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..config import Settings
from ..db import DB, utcnow

KEEP_DAYS = 90
KEEP_NONE_DAYS = 7
MIN_GAP_S = 1.1


class Geocoder:
    def __init__(self, s: Settings, db: DB) -> None:
        self.base = s.nominatim_url
        self.ua = s.user_agent
        self.db = db
        self._lock = asyncio.Lock()
        self._last = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self.base)

    def _cached(self, key: str) -> tuple[bool, dict[str, Any] | None]:
        rows = self.db.query("SELECT fetched_at, payload FROM web_cache WHERE key=?", (key,))
        if not rows:
            return False, None
        try:
            payload = json.loads(rows[0]["payload"])
            age = datetime.now(timezone.utc) - datetime.fromisoformat(rows[0]["fetched_at"].replace("Z", "+00:00"))
        except ValueError:
            return False, None
        keep = KEEP_DAYS if payload else KEEP_NONE_DAYS
        return (True, payload or None) if age < timedelta(days=keep) else (False, None)

    async def search(self, client: httpx.AsyncClient, query: str, country: str | None = None) -> dict[str, Any] | None:
        """First match: {"lat", "lon", "label", "kind"} or None."""
        q = re.sub(r"\s+", " ", (query or "").replace("\n", ", ")).strip(" ,")[:200]
        cc = country.lower() if country and re.fullmatch(r"[A-Za-z]{2}", country) else None
        if not self.enabled or len(q) < 3:
            return None
        key = f"geo:{cc or ''}:{q.lower()}"
        hit, payload = self._cached(key)
        if hit:
            return payload
        params: dict[str, Any] = {"q": q, "format": "jsonv2", "limit": 1}
        if cc:
            params["countrycodes"] = cc
        async with self._lock:  # one request at a time, at least MIN_GAP_S apart
            wait = MIN_GAP_S - (time.monotonic() - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                r = await client.get(f"{self.base}/search", params=params, timeout=10,
                                     headers={"User-Agent": self.ua, "Accept-Language": "de,en"})
            except httpx.HTTPError:
                return None
            finally:
                self._last = time.monotonic()
        if r.status_code != 200:
            return None
        try:
            items = r.json()
            first = items[0] if isinstance(items, list) and items else None
            out = None if first is None else {
                "lat": round(float(first["lat"]), 6), "lon": round(float(first["lon"]), 6),
                "label": str(first.get("display_name") or "")[:240], "kind": str(first.get("addresstype") or first.get("type") or "")[:40]}
        except (ValueError, KeyError, TypeError):
            return None
        if out and not (-90 <= out["lat"] <= 90 and -180 <= out["lon"] <= 180):
            out = None
        self.db.execute("INSERT INTO web_cache(key, fetched_at, payload) VALUES(?,?,?) "
                        "ON CONFLICT(key) DO UPDATE SET fetched_at=excluded.fetched_at, payload=excluded.payload",
                        (key, utcnow(), json.dumps(out)))
        return out
