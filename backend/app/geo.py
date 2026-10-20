"""IP geolocation and ASN lookup with DB-IP Lite (CC BY 4.0, updated monthly).

- City Lite: country, city, approximate coordinates
- ASN Lite:  AS number and organisation

The databases are loaded at start-up and renewed every 30 days.
Without the city database, positions fall back to the country centroid
(only possible if the source itself provides a country).
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import shutil
import time
from datetime import date
from pathlib import Path
from typing import Any

import httpx
import maxminddb

log = logging.getLogger("geo")

DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"
MAX_AGE_S = 30 * 86400


def _months_to_try() -> list[str]:
    today = date.today()
    cur = f"{today.year:04d}-{today.month:02d}"
    prev_y, prev_m = (today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12)
    return [cur, f"{prev_y:04d}-{prev_m:02d}"]


class _Mmdb:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.reader: maxminddb.Reader | None = None
        self.build: str | None = None
        self.open()

    def open(self) -> None:
        if not self.path.exists():
            return
        try:
            old = self.reader
            self.reader = maxminddb.open_database(str(self.path), maxminddb.MODE_MMAP)
            self.build = time.strftime("%Y-%m", time.gmtime(self.reader.metadata().build_epoch))
            if old is not None:
                old.close()
        except Exception as exc:
            log.error("%s not readable: %s", self.path.name, exc)
            self.reader = None

    def fresh(self) -> bool:
        return self.reader is not None and (time.time() - self.path.stat().st_mtime) < MAX_AGE_S

    def get(self, ip: str) -> Any:
        if self.reader is None:
            return None
        try:
            return self.reader.get(ip)
        except Exception:
            return None


class Geo:
    def __init__(self, data_dir: Path, centroids_path: Path, user_agent: str) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.user_agent = user_agent
        self.city = _Mmdb(data_dir / "dbip-city-lite.mmdb")
        self.asn = _Mmdb(data_dir / "dbip-asn-lite.mmdb")
        self.centroids: dict[str, dict[str, Any]] = json.loads(centroids_path.read_text(encoding="utf-8"))

    @property
    def available(self) -> bool:
        return self.city.reader is not None

    def info(self) -> dict[str, Any]:
        return {"city_db": self.city.build, "asn_db": self.asn.build}

    async def ensure(self, client: httpx.AsyncClient) -> None:
        for kind, db in (("city", self.city), ("asn", self.asn)):
            if not db.fresh():
                await self._download(client, kind, db)

    async def _download(self, client: httpx.AsyncClient, kind: str, db: _Mmdb) -> None:
        tmp_gz = db.path.with_suffix(".gz.part")
        tmp_db = db.path.with_suffix(".part")
        for ym in _months_to_try():
            url = DBIP_URL.format(kind=kind, ym=ym)
            try:
                async with client.stream("GET", url, headers={"User-Agent": self.user_agent}, timeout=600) as r:
                    if r.status_code != 200:
                        log.info("DB-IP %s %s: HTTP %s", kind, ym, r.status_code)
                        continue
                    with tmp_gz.open("wb") as fh:
                        async for chunk in r.aiter_bytes(1 << 20):
                            fh.write(chunk)
                with gzip.open(tmp_gz, "rb") as src, tmp_db.open("wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                with maxminddb.open_database(str(tmp_db)) as probe:  # integrity probe
                    sample = probe.get("8.8.8.8")
                log.info("DB-IP %s-lite %s loaded, probe 8.8.8.8: %s", kind, ym, _short(sample))
                tmp_db.replace(db.path)
                db.open()
                return
            except Exception as exc:
                log.warning("DB-IP %s %s failed: %s", kind, ym, exc)
            finally:
                tmp_gz.unlink(missing_ok=True)
                tmp_db.unlink(missing_ok=True)

    # --- lookup ----------------------------------------------------------
    @staticmethod
    def _global_ip(ip: str | None) -> str | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return str(addr) if addr.is_global else None

    def lookup(self, ip: str | None) -> dict[str, Any] | None:
        ip = self._global_ip(ip)
        if ip is None:
            return None
        out: dict[str, Any] = {}
        rec = self.city.get(ip)
        if isinstance(rec, dict):
            loc = rec.get("location") or {}
            out["country"] = (rec.get("country") or {}).get("iso_code")
            out["city"] = ((rec.get("city") or {}).get("names") or {}).get("en")
            if loc.get("latitude") is not None and loc.get("longitude") is not None:
                out["lat"] = float(loc["latitude"])
                out["lon"] = float(loc["longitude"])
        arec = self.asn.get(ip)
        if isinstance(arec, dict):
            # MaxMind-compatible keys; DB-IP states that its format is compatible
            asn = arec.get("autonomous_system_number")
            org = arec.get("autonomous_system_organization")
            if asn is not None:
                out["asn"] = int(asn)
            if org:
                out["as_name"] = str(org)
        return out or None

    def centroid(self, cc: str | None) -> tuple[float, float] | None:
        c = self.centroids.get((cc or "").upper())
        return (c["lat"], c["lon"]) if c else None

    def country_name(self, cc: str | None, lang: str = "de") -> str:
        c = self.centroids.get((cc or "").upper())
        if not c:
            return cc or "?"
        if lang == "en":
            return c.get("name_en") or c["name"]
        return c["name"]


def _short(rec: Any) -> str:
    if not isinstance(rec, dict):
        return repr(rec)[:120]
    return repr({k: rec[k] for k in list(rec)[:3]})[:200]
