"""Live BGP monitoring of your own prefixes via RIPE NCC RIS Live (WebSocket, no key).

What is watched:
- IP and network assets: the covering announced prefix (RIPEstat prefix-overview) with all more-specifics,
  filtered to announcements that overlap the asset. Expected origins = origins RIPEstat currently sees.
- ASN assets: the prefixes the AS announces (RIPEstat announced-prefixes, up to 100 per AS); expected origin = that AS.

Alerts (heuristics, verify before acting):
- bgp.origin: the watched prefix itself is announced by an unexpected origin AS (possible origin hijack, or a
  legitimate change such as a new upstream or DDoS mitigation service).
- bgp.more_specific: a more specific prefix overlapping your asset is announced by an unexpected origin.
- bgp.withdrawn: at least WITHDRAW_PEERS RIS peers withdrew the watched prefix within 5 minutes.
Less specific announcements are ignored: they do not attract traffic away from a more specific route.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

import httpx

from . import alerts, watchlist
from .config import Settings
from .db import DB

log = logging.getLogger("bgp")

RIS_URL = "wss://ris-live.ripe.net/v1/ws/?client=emberwatch"
RIPESTAT = "https://stat.ripe.net/data/{name}/data.json"
MAX_SUBSCRIPTIONS = 500
MAX_PER_ASN = 100
WITHDRAW_PEERS = 25
WITHDRAW_WINDOW_S = 300
PLAN_REFRESH_S = 6 * 3600

Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def _net(v: str) -> Net | None:
    try:
        return ipaddress.ip_network(v, strict=False)
    except ValueError:
        return None


def origin_of(path: list[Any]) -> set[int]:
    """Origin AS(es) of an AS path. A trailing AS_SET (list) yields all its members."""
    if not path:
        return set()
    last = path[-1]
    try:
        if isinstance(last, list):
            return {int(a) for a in last}
        return {int(last)}
    except (TypeError, ValueError):
        return set()


class Watch:
    """One subscription: prefix + expected origins + the assets it protects."""

    def __init__(self, prefix: Net, expected: set[int], assets: list[tuple[dict[str, Any], Net | None]]) -> None:
        self.prefix = prefix
        self.expected = expected
        self.assets = assets  # (watchlist entry, asset network or None for ASN assets)


class BgpMonitor:
    def __init__(self, s: Settings, db: DB) -> None:
        self.s = s
        self.db = db
        self.watches: dict[str, Watch] = {}
        self.events: deque[dict[str, Any]] = deque(maxlen=200)
        self.stats: dict[str, Any] = {"connected": False, "since": None, "messages": 0, "relevant": 0, "alerts": 0,
                                      "reconnects": 0, "last_message": None, "error": None, "plan_at": None}
        self._withdrawn: dict[str, dict[str, float]] = {}
        self._plan_sig = ""
        self._task: asyncio.Task | None = None
        self._replan = asyncio.Event()

    # --- plan --------------------------------------------------------------------------------
    async def _ripestat(self, client: httpx.AsyncClient, name: str, resource: str) -> dict[str, Any]:
        r = await client.get(RIPESTAT.format(name=name), params={"resource": resource, "sourceapp": "emberwatch"},
                             headers={"User-Agent": self.s.user_agent}, timeout=30)
        r.raise_for_status()
        d = (r.json() or {}).get("data")
        return d if isinstance(d, dict) else {}

    async def plan(self, client: httpx.AsyncClient) -> dict[str, Watch]:
        watches: dict[str, Watch] = {}

        def put(prefix: Net, expected: set[int], entry: dict[str, Any], asset: Net | None) -> None:
            key = str(prefix)
            if key in watches:
                watches[key].expected |= expected
                watches[key].assets.append((entry, asset))
            elif len(watches) < MAX_SUBSCRIPTIONS:
                watches[key] = Watch(prefix, set(expected), [(entry, asset)])

        for w in self.db.query("SELECT id, kind, value, label FROM watchlist WHERE kind IN ('ip','cidr','asn') ORDER BY id"):
            try:
                if w["kind"] == "asn":
                    asn = int(w["value"])
                    d = await self._ripestat(client, "announced-prefixes", f"AS{asn}")
                    for p in (d.get("prefixes") or [])[:MAX_PER_ASN]:
                        net = _net(str(p.get("prefix") if isinstance(p, dict) else p))
                        if net is not None and net.is_global:
                            put(net, {asn}, w, None)
                    continue
                asset = _net(w["value"])
                if asset is None or not asset.is_global:
                    continue
                d = await self._ripestat(client, "prefix-overview", str(asset))
                expected = set()
                for a in d.get("asns") or []:
                    try:
                        expected.add(int(a.get("asn")))
                    except (TypeError, ValueError, AttributeError):
                        continue
                covering = _net(str(d.get("resource") or ""))
                if not d.get("announced") or covering is None or covering.version != asset.version:
                    covering = asset
                elif not (asset.subnet_of(covering) or covering.subnet_of(asset)):  # type: ignore[arg-type]
                    covering = asset
                put(covering, expected, w, asset)
            except Exception as exc:
                log.info("BGP plan for %s %s failed: %s", w["kind"], w["value"], exc.__class__.__name__)
            await asyncio.sleep(0.3)
        return watches

    # --- message handling ------------------------------------------------------------------------
    def _alert(self, watch: Watch, key: str, sev: str, params: dict[str, Any], ref: str) -> None:
        entry = watch.assets[0][0]
        if alerts.add(self.db, "bgp", sev, key, {**params, "asset": watchlist.asset_label(entry)}, ref,
                      asset_id=entry["id"], url=f"https://bgp.tools/prefix/{params.get('prefix')}"):
            self.stats["alerts"] += 1

    def _find(self, prefix: Net) -> list[Watch]:
        out = []
        for w in self.watches.values():
            if w.prefix.version == prefix.version and prefix.subnet_of(w.prefix):  # type: ignore[arg-type]
                out.append(w)
        return out

    def handle(self, msg: dict[str, Any]) -> None:
        if msg.get("type") == "ris_error":
            self.stats["error"] = str((msg.get("data") or {}).get("message") or "ris_error")[:200]
            return
        if msg.get("type") != "ris_message":
            return
        d = msg.get("data") or {}
        if d.get("type") != "UPDATE":
            return
        self.stats["messages"] += 1
        self.stats["last_message"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        peer = str(d.get("peer") or "")[:64]
        try:
            peer_asn = int(d.get("peer_asn"))
        except (TypeError, ValueError):
            peer_asn = None
        host = str(d.get("host") or "")[:20]
        path = d.get("path") if isinstance(d.get("path"), list) else []
        origins = origin_of(path)
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        now = time.time()
        for ann in d.get("announcements") or []:
            for p in (ann.get("prefixes") or []) if isinstance(ann, dict) else []:
                net = _net(str(p))
                if net is None:
                    continue
                for w in self._find(net):
                    if net == w.prefix:
                        self._withdrawn.get(str(w.prefix), {}).pop(peer, None)  # re-announced by this peer
                    if not any(a is None or a.overlaps(net) for _, a in w.assets):
                        continue
                    self.stats["relevant"] += 1
                    if not origins:
                        bad: list[int] = []
                    elif w.expected:
                        bad = sorted(origins - w.expected)
                    else:  # prefix was not announced when the plan was made: every origin is unexpected
                        bad = sorted(origins)
                    verdict = "unexpected" if bad else "ok"
                    self.events.appendleft({"ts": self.stats["last_message"], "type": "announce", "prefix": str(net),
                                            "watched": str(w.prefix), "origin": sorted(origins), "path": path[-6:],
                                            "peer_asn": peer_asn, "host": host, "verdict": verdict})
                    if not bad:
                        continue
                    params = {"prefix": str(net), "watched": str(w.prefix), "origin": bad[0], "expected": sorted(w.expected),
                              "peer_asn": peer_asn, "host": host}
                    if net == w.prefix:
                        self._alert(w, "bgp.origin", "high", params, f"{net}|{bad[0]}|{day}")
                    else:
                        self._alert(w, "bgp.more_specific", "high", params, f"{net}|{bad[0]}|{day}")
        for p in d.get("withdrawals") or []:
            net = _net(str(p))
            if net is None:
                continue
            key = str(net)
            w = self.watches.get(key)
            if not w:
                continue
            self.stats["relevant"] += 1
            peers = self._withdrawn.setdefault(key, {})
            peers[peer] = now
            for k in [k for k, t in peers.items() if now - t > WITHDRAW_WINDOW_S]:
                peers.pop(k, None)
            self.events.appendleft({"ts": self.stats["last_message"], "type": "withdraw", "prefix": key, "watched": key,
                                    "peer_asn": peer_asn, "host": host, "verdict": f"{len(peers)} peers"})
            if len(peers) >= WITHDRAW_PEERS:
                hour = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
                self._alert(w, "bgp.withdrawn", "medium", {"prefix": key, "peers": len(peers)}, f"{key}|withdrawn|{hour}")

    # --- connection ---------------------------------------------------------------------------------
    def replan(self) -> None:
        self._replan.set()

    async def run(self, client: httpx.AsyncClient) -> None:
        from websockets.asyncio.client import connect

        backoff = 5.0
        while True:
            try:
                self.watches = await self.plan(client)
                self.stats["plan_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                self._replan.clear()
                if not self.watches:
                    self.db.status("ris_live", True, code="no_assets")
                    self.stats["connected"] = False
                    try:
                        await asyncio.wait_for(self._replan.wait(), timeout=PLAN_REFRESH_S)
                    except asyncio.TimeoutError:
                        pass
                    continue
                async with connect(RIS_URL, user_agent_header=self.s.user_agent, open_timeout=20, ping_interval=30,
                                   ping_timeout=30, max_size=2 ** 22) as ws:
                    for w in self.watches.values():
                        await ws.send(json.dumps({"type": "ris_subscribe", "data": {
                            "prefix": str(w.prefix), "moreSpecific": True, "lessSpecific": False, "type": "UPDATE",
                            "socketOptions": {"includeRaw": False}}}))
                    self.stats.update(connected=True, since=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), error=None)
                    self.db.status("ris_live", True, "", len(self.watches))
                    backoff = 5.0
                    started = time.time()
                    replan = asyncio.create_task(self._replan.wait())
                    try:
                        while True:
                            recv = asyncio.create_task(ws.recv())
                            done, _ = await asyncio.wait({recv, replan}, timeout=max(1.0, PLAN_REFRESH_S - (time.time() - started)),
                                                         return_when=asyncio.FIRST_COMPLETED)
                            if recv not in done:
                                recv.cancel()
                                break  # replan requested or periodic refresh
                            raw = recv.result()
                            try:
                                msg = json.loads(raw)
                            except (TypeError, ValueError):
                                continue
                            if isinstance(msg, dict):
                                self.handle(msg)
                    finally:
                        replan.cancel()
                self.stats["connected"] = False
            except asyncio.CancelledError:
                self.stats["connected"] = False
                raise
            except Exception as exc:
                self.stats.update(connected=False, error=f"{exc.__class__.__name__}: {exc}"[:200])
                self.stats["reconnects"] += 1
                self.db.status("ris_live", False, self.stats["error"])
                log.info("RIS Live disconnected (%s), retry in %.0f s", exc.__class__.__name__, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 300.0)

    def info(self) -> dict[str, Any]:
        return {
            "enabled": self.s.bgp_live, **self.stats,
            "watches": [{"prefix": k, "expected": sorted(w.expected),
                         "assets": [watchlist.asset_label(e) for e, _ in w.assets][:5],
                         "asset_ids": sorted({e["id"] for e, _ in w.assets})} for k, w in list(self.watches.items())[:500]],
            "events": list(self.events)[:100],
        }
