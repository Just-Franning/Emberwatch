"""IP reputation: Spamhaus DROP, Tor exit nodes, AbuseIPDB.

- Spamhaus DROP/DROPv6 (JSON lines, free with attribution): netblocks hijacked or leased by criminals.
  Fetched at most once a day, as Spamhaus asks (no more than once per hour).
- Tor bulk exit list (check.torproject.org): one IPv4 per line, refreshed every 6 hours.
- AbuseIPDB v2 /check (optional key, free tier 1,000 checks/day): cached 24 h per IP, daily budget enforced here.

Lookups against DROP use sorted integer intervals with a running maximum, so nested blocks are found too.
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from . import alerts, watchlist
from .config import Settings
from .db import DB, utcnow

log = logging.getLogger("reputation")

DROP_URLS = ("https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json")
TOR_URL = "https://check.torproject.org/torbulkexitlist"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_DAILY_BUDGET = 900  # free tier: 1,000 checks per day; keep headroom for manual lookups elsewhere
CACHE_S = 24 * 3600
SBL_RE = re.compile(r"SBL\d{1,10}")


class _Intervals:
    """Non-overlapping or nested IP intervals with O(log n) containment checks."""

    def __init__(self, items: list[tuple[int, int, str, str]]) -> None:
        items.sort()
        self.items = items
        self.starts = [i[0] for i in items]
        self.maxend: list[int] = []
        m = -1
        for i in items:
            m = max(m, i[1])
            self.maxend.append(m)

    def overlapping(self, lo: int, hi: int, limit: int = 5) -> list[tuple[int, int, str, str]]:
        out = []
        idx = bisect.bisect_right(self.starts, hi) - 1
        while idx >= 0 and self.maxend[idx] >= lo and len(out) < limit:
            it = self.items[idx]
            if it[1] >= lo:
                out.append(it)
            idx -= 1
        return out


class Reputation:
    def __init__(self, s: Settings, db: DB) -> None:
        self.s = s
        self.db = db
        self._v4 = _Intervals([])
        self._v6 = _Intervals([])
        self._tor: set[str] = set()
        self._budget_day = ""
        self._budget_used = 0
        self.version = 0  # increases whenever lists change (used by the log matcher cache)
        self._load()

    # --- loading -------------------------------------------------------------------
    def _load(self) -> None:
        v4, v6 = [], []
        for r in self.db.query("SELECT cidr, sblid FROM rep_drop"):
            try:
                net = ipaddress.ip_network(r["cidr"], strict=False)
            except ValueError:
                continue
            item = (int(net.network_address), int(net.broadcast_address), str(net), r["sblid"] or "")
            (v4 if net.version == 4 else v6).append(item)
        self._v4, self._v6 = _Intervals(v4), _Intervals(v6)
        self._tor = {r["ip"] for r in self.db.query("SELECT ip FROM rep_tor")}
        self.version += 1

    @property
    def drop_count(self) -> int:
        return len(self._v4.items) + len(self._v6.items)

    @property
    def tor_count(self) -> int:
        return len(self._tor)

    def _due(self, key: str, seconds: int) -> bool:
        last = self.db.meta_get(key)
        if not last:
            return True
        try:
            ts = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return True
        return datetime.now(timezone.utc) - ts >= timedelta(seconds=seconds)

    async def refresh(self, client: httpx.AsyncClient) -> None:
        changed = False
        if self._due("rep_drop_at", 24 * 3600):
            changed |= await self._refresh_drop(client)
        if self._due("rep_tor_at", 6 * 3600):
            changed |= await self._refresh_tor(client)
        if changed:
            self._load()

    async def _refresh_drop(self, client: httpx.AsyncClient) -> bool:
        rows: list[tuple[str, str | None, str | None]] = []
        try:
            for url in DROP_URLS:
                r = await client.get(url, headers={"User-Agent": self.s.user_agent}, timeout=60)
                r.raise_for_status()
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(rec, dict) or "type" in rec or not rec.get("cidr"):
                        continue  # the last line is metadata
                    try:
                        cidr = str(ipaddress.ip_network(str(rec["cidr"]), strict=False))
                    except ValueError:
                        continue
                    rows.append((cidr, str(rec.get("sblid") or "")[:20] or None, str(rec.get("rir") or "")[:10] or None))
            if len(rows) < 50:  # protects against wiping the list with an error page
                raise ValueError(f"only {len(rows)} entries")
        except Exception as exc:
            self.db.status("spamhaus_drop", False, f"{exc.__class__.__name__}: {exc}"[:300])
            self.db.meta_set("rep_drop_at", utcnow())  # retry tomorrow, not every minute
            return False
        self.db.transaction([("DELETE FROM rep_drop", ())] +
                            [("INSERT OR REPLACE INTO rep_drop(cidr, sblid, rir) VALUES(?,?,?)", r) for r in rows])
        self.db.meta_set("rep_drop_at", utcnow())
        self.db.status("spamhaus_drop", True, "", len(rows))
        return True

    async def _refresh_tor(self, client: httpx.AsyncClient) -> bool:
        try:
            r = await client.get(TOR_URL, headers={"User-Agent": self.s.user_agent}, timeout=60)
            r.raise_for_status()
            ips = set()
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ips.add(str(ipaddress.ip_address(line)))
                except ValueError:
                    continue
            if len(ips) < 50:
                raise ValueError(f"only {len(ips)} entries")
        except Exception as exc:
            self.db.status("tor_exits", False, f"{exc.__class__.__name__}: {exc}"[:300])
            self.db.meta_set("rep_tor_at", utcnow())
            return False
        self.db.transaction([("DELETE FROM rep_tor", ())] + [("INSERT INTO rep_tor(ip) VALUES(?)", (ip,)) for ip in ips])
        self.db.meta_set("rep_tor_at", utcnow())
        self.db.status("tor_exits", True, "", len(ips))
        return True

    # --- lookups ---------------------------------------------------------------------
    def drop_for(self, value: str) -> dict[str, str] | None:
        """DROP entry containing an IP or overlapping a network."""
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        idx = self._v4 if net.version == 4 else self._v6
        hits = idx.overlapping(int(net.network_address), int(net.broadcast_address), 1)
        return {"cidr": hits[0][2], "sblid": hits[0][3]} if hits else None

    def is_tor(self, ip: str) -> bool:
        return ip in self._tor

    def flags(self, ip: str) -> dict[str, Any]:
        return {"drop": self.drop_for(ip), "tor": self.is_tor(ip)}

    async def abuseipdb(self, client: httpx.AsyncClient, ip: str, force_cache_only: bool = False) -> dict[str, Any]:
        """Returns {"status": ok|disabled|budget|error|private, ...data}."""
        if not self.s.abuseipdb_api_key:
            return {"status": "disabled"}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"status": "error"}
        if not addr.is_global:
            return {"status": "private"}
        ip = str(addr)
        rows = self.db.query("SELECT payload, fetched_at FROM abuseipdb_cache WHERE ip=?", (ip,))
        if rows:
            fetched = datetime.strptime(rows[0]["fetched_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - fetched).total_seconds() < CACHE_S or force_cache_only:
                return {"status": "ok", "cached": True, **json.loads(rows[0]["payload"])}
        elif force_cache_only:
            return {"status": "none"}
        today = time.strftime("%Y-%m-%d", time.gmtime())
        if self._budget_day != today:
            self._budget_day, self._budget_used = today, 0
        if self._budget_used >= ABUSEIPDB_DAILY_BUDGET:
            return {"status": "budget"}
        self._budget_used += 1
        try:
            r = await client.get(ABUSEIPDB_URL, params={"ipAddress": ip, "maxAgeInDays": 90},
                                 headers={"Key": self.s.abuseipdb_api_key, "Accept": "application/json",
                                          "User-Agent": self.s.user_agent}, timeout=20)
            if r.status_code == 429:
                self._budget_used = ABUSEIPDB_DAILY_BUDGET
                return {"status": "budget"}
            r.raise_for_status()
            d = r.json().get("data") or {}
        except Exception as exc:
            log.warning("AbuseIPDB %s: %s", ip, exc.__class__.__name__)
            return {"status": "error"}
        data = {
            "score": _int(d.get("abuseConfidenceScore")), "reports": _int(d.get("totalReports")),
            "users": _int(d.get("numDistinctUsers")), "last_reported": d.get("lastReportedAt"),
            "usage": str(d.get("usageType") or "")[:80], "isp": str(d.get("isp") or "")[:120],
            "domain": str(d.get("domain") or "")[:120], "country": str(d.get("countryCode") or "")[:2],
            "is_tor": bool(d.get("isTor")), "whitelisted": bool(d.get("isWhitelisted")),
            "link": f"https://www.abuseipdb.com/check/{ip}",
        }
        self.db.execute(
            "INSERT INTO abuseipdb_cache(ip, score, reports, payload, fetched_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(ip) DO UPDATE SET score=excluded.score, reports=excluded.reports, payload=excluded.payload, "
            "fetched_at=excluded.fetched_at",
            (ip, data["score"], data["reports"], json.dumps(data), utcnow()),
        )
        return {"status": "ok", "cached": False, **data}

    async def check(self, client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
        return {**self.flags(ip), "abuseipdb": await self.abuseipdb(client, ip)}

    # --- own assets ----------------------------------------------------------------------
    async def scan_assets(self, client: httpx.AsyncClient) -> int:
        """DROP listing of own networks and AbuseIPDB reputation of own single IPs. Returns new alerts."""
        new = 0
        week = datetime.now(timezone.utc).strftime("%G-W%V")
        for w in self.db.query("SELECT id, kind, value, label FROM watchlist WHERE kind IN ('ip','cidr')"):
            hit = self.drop_for(w["value"])
            if hit:
                new += alerts.add(self.db, "rep", "high", "rep.drop",
                                  {"ip": w["value"], "cidr": hit["cidr"], "sblid": hit["sblid"], "asset": watchlist.asset_label(w)},
                                  f"{w['id']}:drop:{hit['cidr']}", asset_id=w["id"],
                                  url=f"https://www.spamhaus.org/sbl/query/{hit['sblid']}" if SBL_RE.fullmatch(hit["sblid"]) else None)
            if w["kind"] == "ip" and self.s.abuseipdb_api_key:
                res = await self.abuseipdb(client, w["value"])
                if res.get("status") == "ok" and (res.get("score") or 0) >= self.s.abuseipdb_min_score and not res.get("whitelisted"):
                    sev = "high" if res["score"] >= 75 else "medium"
                    new += alerts.add(self.db, "rep", sev, "rep.abuseipdb",
                                      {"ip": w["value"], "score": res["score"], "reports": res.get("reports"),
                                       "asset": watchlist.asset_label(w)},
                                      f"{w['id']}:abuseipdb:{week}", asset_id=w["id"], url=res.get("link"))
        return new


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
