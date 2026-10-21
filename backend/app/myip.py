"""Own public IP addresses: the home connection and this server.

Home IP sources (any combination):
- visits: the address the web interface is opened from (via the reverse proxy). It is taken over after a confirmation,
  or automatically when the visit comes from the AS of the home connection (opt-in, avoids mobile networks);
- DynDNS: a host name that points to the home connection, resolved every few minutes;
- reporter: a device at home calls POST /api/myip/report with a token (curl, cron), or a router/DynDNS client uses the
  dyndns2 protocol (GET /nic/update with the token as password).
Server IP: the egress address of this server (Cloudflare trace endpoint).

On every change a history entry and an alert are written; the current addresses are checked against Spamhaus DROP, Tor,
the C2/ThreatFox data, AbuseIPDB (if configured) and Shodan InternetDB (open ports as seen from the internet).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

import dns.asyncresolver
import dns.exception
import httpx

from . import alerts
from .config import Settings
from .db import DB, utcnow
from .geo import Geo
from .i18n import AppError
from .surface import RISKY_PORTS
from .toolbox.detect import is_domain, norm_host

KINDS = ("home", "server")
HISTORY_KEEP = 200
SIGHTINGS_DAYS = 90


def _public(ip: str | None) -> bool:
    if not ip or "%" in ip:  # IPv6 zone IDs (fe80::1%eth0) are local by definition and would be stored as free text
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def _same(ip: str, known: list[str]) -> bool:
    """True if ip is one of the known addresses. IPv6 compares the /64: devices behind one connection use changing
    (privacy) addresses from the same prefix."""
    if ip in known:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version != 6:
        return False
    net = ipaddress.ip_network(f"{a}/64", strict=False)
    for k in known:
        try:
            b = ipaddress.ip_address(k)
        except ValueError:
            continue
        if b.version == 6 and b in net:
            return True
    return False


def _family(ip: str) -> int:
    return ipaddress.ip_address(ip).version


class MyIP:
    def __init__(self, s: Settings, db: DB, geo: Geo, rep: Any, matcher: Any, surface: Any, toolkit: Any) -> None:
        self.s = s
        self.db = db
        self.geo = geo
        self.rep = rep
        self.matcher = matcher
        self.surface = surface
        self.toolkit = toolkit
        self._fails: dict[str, deque[float]] = {}
        self._last_report: dict[int, float] = {}
        for k in KINDS:
            self.db.execute("INSERT OR IGNORE INTO myip(kind, config) VALUES(?, '{}')", (k,))

    # --- state ---------------------------------------------------------------------------------------------------------
    def _row(self, kind: str) -> dict[str, Any]:
        rows = self.db.query("SELECT * FROM myip WHERE kind=?", (kind,))
        return rows[0] if rows else {"kind": kind, "config": "{}"}

    def _config(self, kind: str = "home") -> dict[str, Any]:
        try:
            return json.loads(self._row(kind).get("config") or "{}")
        except ValueError:
            return {}

    def _save_config(self, cfg: dict[str, Any], kind: str = "home") -> None:
        self.db.execute("UPDATE myip SET config=? WHERE kind=?", (json.dumps(cfg), kind))

    def current(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for k in KINDS:
            r = self._row(k)
            out[k] = [x for x in (r.get("ip"), r.get("ip6")) if x]
        return out

    def match(self, ip: str) -> str | None:
        for k, ips in self.current().items():
            if _same(ip, ips):
                return k
        return None

    def state(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k in KINDS:
            r = self._row(k)
            cfg = self._config(k)
            try:
                checks = json.loads(r.get("check_payload") or "{}")
            except ValueError:
                checks = {}
            out[k] = {
                "ip": r.get("ip"), "ip6": r.get("ip6"), "source": r.get("source"), "updated_at": r.get("updated_at"),
                "checked_at": r.get("checked_at"), "checks": checks,
                "geo": {ip: self._geo(ip) for ip in (r.get("ip"), r.get("ip6")) if ip},
                "history": self.history(k, 20),
            }
            if k == "home":
                out[k]["config"] = {"dyndns": cfg.get("dyndns") or "", "auto_asn": cfg.get("auto_asn"),
                                    "token_set": bool(cfg.get("token_hash")), "token_created": cfg.get("token_created")}
        return out

    def _geo(self, ip: str) -> dict[str, Any]:
        g = self.geo.lookup(ip) or {}
        return {k: g.get(k) for k in ("country", "city", "asn", "as_name", "lat", "lon")}

    def history(self, kind: str, limit: int = 50) -> list[dict[str, Any]]:
        return self.db.query("SELECT ip, family, first_seen, last_seen, source, asn, as_name, country FROM myip_history "
                             "WHERE kind=? ORDER BY last_seen DESC, id DESC LIMIT ?", (kind, limit))

    # --- changes --------------------------------------------------------------------------------------------------------
    def set_ip(self, kind: str, ip: str, source: str) -> bool:
        """Records the address (v4 or v6 slot). Returns True if it changed."""
        if kind not in KINDS or not _public(ip):
            raise AppError("err.myip.invalid")
        ip = str(ipaddress.ip_address(ip))
        col = "ip" if _family(ip) == 4 else "ip6"
        r = self._row(kind)
        now = utcnow()
        old = r.get(col)
        g = self._geo(ip)
        last = self.db.query("SELECT id, ip FROM myip_history WHERE kind=? AND family=? ORDER BY id DESC LIMIT 1", (kind, _family(ip)))
        if last and last[0]["ip"] == ip:
            self.db.execute("UPDATE myip_history SET last_seen=?, source=? WHERE id=?", (now, source, last[0]["id"]))
        else:
            self.db.insert("INSERT INTO myip_history(kind, ip, family, first_seen, last_seen, source, asn, as_name, country) "
                           "VALUES(?,?,?,?,?,?,?,?,?)", (kind, ip, _family(ip), now, now, source, g.get("asn"), g.get("as_name"), g.get("country")))
            self.db.execute("DELETE FROM myip_history WHERE kind=? AND id NOT IN (SELECT id FROM myip_history WHERE kind=? "
                            "ORDER BY id DESC LIMIT ?)", (kind, kind, HISTORY_KEEP))
        if old == ip:
            self.db.execute("UPDATE myip SET source=? WHERE kind=?", (source, kind))
            return False
        self.db.execute(f"UPDATE myip SET {col}=?, source=?, updated_at=? WHERE kind=?", (ip, source, now, kind))
        if old:
            alerts.add(self.db, "myip", "low", "myip.changed", {"kind": kind, "old": old, "new": ip, "source": source},
                       f"{kind}:changed:{old}>{ip}:{now[:13]}")
        return True

    # --- sources: visits --------------------------------------------------------------------------------------------------
    def visit(self, client_ip: str | None) -> dict[str, Any]:
        """Called when the web interface is opened. Records the sighting and applies the home IP if the AS matches."""
        if not client_ip or not _public(client_ip):
            return {"ip": client_ip, "public": False}
        ip = str(ipaddress.ip_address(client_ip))
        g = self._geo(ip)
        now = utcnow()
        self.db.execute("INSERT INTO myip_sightings(ip, first_seen, last_seen, count, asn, as_name, country) VALUES(?,?,?,1,?,?,?) "
                        "ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, count=count+1", (ip, now, now, g.get("asn"),
                                                                                                      g.get("as_name"), g.get("country")))
        cfg = self._config()
        changed = False
        # automatic take-over only for IPv4: over IPv6 the browser shows the device's own (often temporary) address
        if cfg.get("auto_asn") and g.get("asn") == cfg["auto_asn"] and _family(ip) == 4 and not _same(ip, self.current()["home"]):
            changed = self.set_ip("home", ip, "visit")
        home = _same(ip, self.current()["home"])
        return {"ip": ip, "public": True, "geo": g, "is_home": home, "auto_applied": changed,
                "home_asn": cfg.get("auto_asn"), "suggest": not home}

    def peek(self, client_ip: str | None) -> dict[str, Any]:
        """The address the current request comes from, without recording anything."""
        if not client_ip or not _public(client_ip):
            return {"ip": client_ip, "public": False}
        ip = str(ipaddress.ip_address(client_ip))
        cfg = self._config()
        return {"ip": ip, "public": True, "geo": self._geo(ip), "is_home": _same(ip, self.current()["home"]),
                "home_asn": cfg.get("auto_asn")}

    def needs_check(self, kind: str, max_age_h: float = 6) -> bool:
        """True if the kind has an address that was never checked, changed since the last check or was checked too long ago."""
        r = self._row(kind)
        if not (r.get("ip") or r.get("ip6")):
            return False
        last = r.get("checked_at")
        if not last or (r.get("updated_at") or "") > last:
            return True
        return last < (datetime.now(timezone.utc) - timedelta(hours=max_age_h)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def confirm(self, client_ip: str | None, auto: bool) -> dict[str, Any]:
        if not client_ip or not _public(client_ip):
            raise AppError("err.myip.private")
        ip = str(ipaddress.ip_address(client_ip))
        asn = self._geo(ip).get("asn")
        if auto and not asn:
            raise AppError("err.myip.no_asn")
        changed = self.set_ip("home", ip, "confirmed")
        cfg = self._config()
        if auto:
            cfg["auto_asn"] = int(asn)
        else:
            cfg.pop("auto_asn", None)
        self._save_config(cfg)
        return {"ip": ip, "changed": changed}

    def sightings(self, limit: int = 30) -> list[dict[str, Any]]:
        return self.db.query("SELECT ip, first_seen, last_seen, count, asn, as_name, country FROM myip_sightings "
                             "ORDER BY last_seen DESC LIMIT ?", (limit,))

    # --- configuration ---------------------------------------------------------------------------------------------------
    def configure(self, dyndns: str | None, auto_asn: bool | None) -> dict[str, Any]:
        cfg = self._config()
        if dyndns is not None:
            v = dyndns.strip()
            if v:
                host = norm_host(v)
                if not host or not is_domain(host):
                    raise AppError("err.myip.dyndns")
                cfg["dyndns"] = host
            else:
                cfg.pop("dyndns", None)
        if auto_asn is not None:
            if auto_asn:
                ip = self._row("home").get("ip") or self._row("home").get("ip6")
                if not ip:
                    raise AppError("err.myip.no_home")
                asn = self._geo(ip).get("asn")
                if not asn:
                    raise AppError("err.myip.no_asn")
                cfg["auto_asn"] = int(asn)
            else:
                cfg.pop("auto_asn", None)
        self._save_config(cfg)
        return self.state()["home"]["config"]

    def new_token(self) -> str:
        token = secrets.token_urlsafe(32)
        cfg = self._config()
        cfg["token_hash"] = hashlib.sha256(token.encode()).hexdigest()
        cfg["token_created"] = utcnow()
        self._save_config(cfg)
        return token

    def revoke_token(self) -> None:
        cfg = self._config()
        cfg.pop("token_hash", None)
        cfg.pop("token_created", None)
        self._save_config(cfg)

    def clear(self, kind: str) -> None:
        if kind not in KINDS:
            raise AppError("err.myip.invalid")
        self.db.execute("UPDATE myip SET ip=NULL, ip6=NULL, source=NULL, updated_at=NULL, checked_at=NULL, check_payload=NULL WHERE kind=?",
                        (kind,))

    # --- sources: reporter (token) -----------------------------------------------------------------------------------------
    def _locked(self, client: str) -> bool:
        now = time.time()
        q = self._fails.setdefault(client, deque())
        while q and now - q[0] > 600:
            q.popleft()
        if len(self._fails) > 5000:
            self._fails.clear()
        return len(q) >= 10

    def report(self, token: str | None, client_ip: str | None, claimed: list[str] | None = None) -> tuple[str, list[str]]:
        """Token-authenticated update. claimed: addresses sent by the client (at most one per family); without them the
        connecting address is used. Returns (status, ips) with status ok|nochg|badauth|locked|noip|wait.
        The token is checked first: a valid token is never rejected, so nobody can lock out the router by sending bad
        requests in its name. Failures only change the answer (locked after 10 within 10 minutes per client); the token
        has 256 bits, guessing is not a practical attack. A change is accepted at most every 20 seconds per address family,
        so a leaked token cannot flood the history and the alerts."""
        client = client_ip or "?"
        want = self._config().get("token_hash")
        got = hashlib.sha256((token or "").encode()).hexdigest()
        if not want or not token or not hmac.compare_digest(want, got):
            if self._locked(client):
                return "locked", []
            self._fails.setdefault(client, deque()).append(time.time())
            return "badauth", []
        ips: dict[int, str] = {}
        for v in (claimed or [client_ip]):
            if v and _public(v.strip()):
                ip = str(ipaddress.ip_address(v.strip()))
                ips.setdefault(_family(ip), ip)
        if not ips:
            return "noip", []
        cur = self.current()["home"]
        new = [ip for ip in ips.values() if ip not in cur]
        now = time.time()
        if any(now - self._last_report.get(_family(ip), 0.0) < 20 for ip in new):
            return "wait", list(ips.values())
        for ip in new:
            self._last_report[_family(ip)] = now
        changed = False
        for ip in ips.values():
            changed = self.set_ip("home", ip, "report") or changed
        return ("ok" if changed else "nochg"), list(ips.values())

    # --- jobs -------------------------------------------------------------------------------------------------------------
    async def refresh(self, client: httpx.AsyncClient) -> list[str]:
        """DynDNS resolution and server egress address. Returns the kinds whose address changed."""
        changed: list[str] = []
        host = self._config().get("dyndns")
        if host:
            res = dns.asyncresolver.Resolver()
            res.lifetime = 5.0
            for rtype in ("A", "AAAA"):
                try:
                    ans = await res.resolve(host, rtype)
                except dns.exception.DNSException:
                    continue
                ip = next((r.to_text() for r in ans if _public(r.to_text())), None)
                if ip and self.set_ip("home", ip, "dyndns"):
                    changed.append("home")
        try:
            o = await self.toolkit.origin(client, max_age=3000)
        except Exception:
            o = {}
        if o.get("ip") and _public(o["ip"]) and self.set_ip("server", o["ip"], "egress"):
            changed.append("server")
        self.db.execute("DELETE FROM myip_sightings WHERE last_seen < ?",
                        ((datetime.now(timezone.utc) - timedelta(days=SIGHTINGS_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ"),))
        return sorted(set(changed))

    async def check(self, client: httpx.AsyncClient, kind: str) -> dict[str, Any]:
        """Threat data and exposure of the current addresses; raises alerts for listings and risky open ports."""
        r = self._row(kind)
        self.matcher.ensure()
        out: dict[str, Any] = {}
        week = datetime.now(timezone.utc).strftime("%G-W%V")
        for ip in [x for x in (r.get("ip"), r.get("ip6")) if x]:
            res: dict[str, Any] = {}
            try:
                rep = await self.rep.check(client, ip)
            except Exception:
                rep = self.rep.flags(ip)
            res["drop"] = rep.get("drop")
            res["tor"] = bool(rep.get("tor"))
            ab = rep.get("abuseipdb") or {}
            res["abuseipdb"] = {"status": ab.get("status"), "score": ab.get("score"), "reports": ab.get("reports"), "link": ab.get("link")}
            hits = self.matcher.match("ip", ip)
            res["threats"] = [{"kind": h["kind"], "malware": h.get("malware"), "threat": h.get("threat")} for h in hits
                              if h["kind"] in ("c2", "ioc")]
            try:
                idb = await self.surface._internetdb(client, ip)
            except Exception as exc:
                idb = {"status": "error", "error": exc.__class__.__name__}
            res["internetdb"] = idb
            out[ip] = res
            label = {"kind": kind, "ip": ip}
            if res["drop"]:
                alerts.add(self.db, "myip", "high", "myip.listed", {**label, "list": f"Spamhaus DROP {res['drop']['cidr']}"}, f"{kind}:{ip}:drop:{week}")
            if res["threats"]:
                names = ", ".join(sorted({t["malware"] or t["kind"] for t in res["threats"]}))
                alerts.add(self.db, "myip", "high", "myip.listed", {**label, "list": f"C2/IOC ({names})"}, f"{kind}:{ip}:ioc:{week}")
            if res["tor"]:
                alerts.add(self.db, "myip", "medium", "myip.listed", {**label, "list": "Tor exit"}, f"{kind}:{ip}:tor:{week}")
            if (ab.get("score") or 0) >= self.s.abuseipdb_min_score:
                alerts.add(self.db, "myip", "high" if ab["score"] >= 75 else "medium", "myip.listed",
                           {**label, "list": f"AbuseIPDB {ab['score']}"}, f"{kind}:{ip}:abuseipdb:{week}", url=ab.get("link"))
            risky = sorted(p for p in (idb.get("ports") or []) if p in RISKY_PORTS)
            if idb.get("status") == "ok" and risky:
                alerts.add(self.db, "myip", "medium", "myip.ports", {**label, "ports": ", ".join(str(p) for p in risky)},
                           f"{kind}:{ip}:ports:{','.join(str(p) for p in risky)}")
        self.db.execute("UPDATE myip SET checked_at=?, check_payload=? WHERE kind=?", (utcnow(), json.dumps(out), kind))
        return out
