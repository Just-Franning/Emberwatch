"""Attack surface of your own assets (watchlist entries of type IP, network and domain).

Passive: Shodan InternetDB (free for non-commercial use, weekly updated, no key) per public IP:
open ports, CPEs, hostnames, tags and CVEs. Changes against the previous fetch become alerts.

Active: TCP connect scan of SCAN_PORTS, only for assets explicitly enabled for scanning AND confirmed by the user
("I am authorised to scan this asset"). For open ports: TLS certificate, HTTP status/server header or the
service banner. Limits: SCAN_MAX_HOSTS addresses per asset, SCAN_CONCURRENCY parallel connects, SCAN_TIMEOUT_S
per connect. Private targets only with TOOLS_ALLOW_PRIVATE. One scan at a time.

The first fetch/scan of an asset is a baseline without alerts (certificate expiry is always checked).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from . import alerts, watchlist
from .config import Settings
from .db import DB, utcnow
from .geo import Geo
from .i18n import AppError
from .tools import http_head, is_public, tcp_probe, tls_details

log = logging.getLogger("surface")

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
# Ports that should rarely be reachable from the internet: new exposure is "high"
RISKY_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200,
               10250, 11211, 27017, 50000, 4786, 1883, 5601, 8086, 9092, 15672, 5672, 111, 873}
TLS_PORTS = {443, 465, 563, 636, 853, 990, 992, 993, 994, 995, 2083, 2087, 3269, 4443, 5061, 5986, 6443, 7443, 8443,
             8883, 9443, 10250}
HTTP_PORTS = {80, 81, 3000, 5000, 5001, 8000, 8008, 8080, 8081, 8086, 8088, 8880, 8888, 9000, 9001, 9090, 9200, 10000,
              5601, 15672, 32400, 2082, 2086, 7001}
SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
            135: "msrpc", 139: "netbios", 143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "rsh",
            587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
            1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2375: "docker",
            2376: "docker-tls", 3306: "mysql", 3389: "rdp", 4786: "cisco-smi", 5060: "sip", 5432: "postgresql",
            5601: "kibana", 5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "kubernetes",
            8080: "http-alt", 8443: "https-alt", 9092: "kafka", 9200: "elasticsearch", 10250: "kubelet",
            11211: "memcached", 15672: "rabbitmq", 25565: "minecraft", 27017: "mongodb", 32400: "plex"}
PRINTABLE_RE = re.compile(r"[^\x20-\x7e]+")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _banner_text(raw: bytes) -> str:
    return PRINTABLE_RE.sub(" ", raw.decode("latin-1")).strip()[:200]


def guess_service(port: int, banner: str | None, tls: dict[str, Any] | None, http: dict[str, Any] | None) -> str:
    b = (banner or "")
    if b.startswith("SSH-"):
        return "ssh"
    if http and http.get("status", "").startswith("HTTP/"):
        return "https" if tls and not tls.get("error") else "http"
    if b.startswith("220") and "ftp" in b.lower():
        return "ftp"
    if b.startswith("220"):
        return "smtp"
    if b.startswith("+OK"):
        return "pop3"
    if b.startswith("* OK"):
        return "imap"
    return SERVICES.get(port, "tls" if tls and not tls.get("error") else "")


class Surface:
    def __init__(self, s: Settings, db: DB, geo: Geo) -> None:
        self.s = s
        self.db = db
        self.geo = geo
        self.scan_lock = asyncio.Lock()
        self.current: dict[str, Any] | None = None  # running scan (asset_id, run_id, progress)

    # --- targets ---------------------------------------------------------------------------
    async def _resolve(self, host: str) -> list[str]:
        res = dns.asyncresolver.Resolver()
        res.lifetime = 4.0
        out: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                ans = await res.resolve(host, rtype)
                out += [r.to_text() for r in ans]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
        return list(dict.fromkeys(out))[:16]

    def _allowed(self, ip: str, active: bool) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if a.is_multicast or a.is_unspecified or a.is_reserved or a.is_link_local:
            return False
        if is_public(a):
            return True
        return active and self.s.tools_allow_private

    async def targets(self, entry: dict[str, Any], limit: int, active: bool = False) -> list[str]:
        """Addresses of an asset (up to limit). Raises AppError for networks larger than the limit."""
        kind, value = entry["kind"], entry["value"]
        if kind == "ip":
            ips = [value]
        elif kind == "cidr":
            net = ipaddress.ip_network(value, strict=False)
            if net.num_addresses > limit + 2:
                raise AppError("err.scan_too_big", count=net.num_addresses, max=limit)
            ips = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
        elif kind == "domain":
            ips = await self._resolve(value)
        else:
            raise AppError("err.scan_kind")
        return [ip for ip in ips if self._allowed(ip, active)][:limit]

    # --- passive: InternetDB -------------------------------------------------------------------
    async def _internetdb(self, client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
        r = await client.get(INTERNETDB_URL.format(ip=ip), headers={"User-Agent": self.s.user_agent,
                                                                    "Accept": "application/json"}, timeout=20)
        if r.status_code == 404:
            return {"status": "none"}
        r.raise_for_status()
        d = r.json()
        if not isinstance(d, dict):
            raise ValueError("unexpected format")

        def lst(key: str, cast: Any = str, n: int = 200) -> list[Any]:
            out = []
            for v in (d.get(key) or [])[:n]:
                try:
                    out.append(cast(v))
                except (TypeError, ValueError):
                    continue
            return out

        return {"status": "ok", "ports": sorted(set(lst("ports", int))), "cpes": lst("cpes"), "hostnames": lst("hostnames"),
                "tags": lst("tags"), "vulns": sorted({v.upper() for v in lst("vulns") if v.upper().startswith("CVE-")})}

    async def asset_ips(self) -> dict[str, list[dict[str, Any]]]:
        """Public IPs of all IP/network/domain assets -> owning watchlist entries."""
        owners: dict[str, list[dict[str, Any]]] = {}
        for w in self.db.query("SELECT id, kind, value, label FROM watchlist WHERE kind IN ('ip','cidr','domain') ORDER BY id"):
            try:
                ips = await self.targets(w, self.s.surface_max_ips)
            except AppError:
                continue  # network too large for enumeration
            for ip in ips:
                if len(owners) >= self.s.surface_max_ips and ip not in owners:
                    break
                owners.setdefault(ip, []).append(w)
        return owners

    async def passive(self, client: httpx.AsyncClient, force: bool = False) -> int:
        owners = await self.asset_ips()
        by_asset: dict[int, list[str]] = {}
        for ip, ws in owners.items():
            for w in ws:
                by_asset.setdefault(w["id"], []).append(ip)
        self.db.execute("DELETE FROM meta WHERE key LIKE 'surface_ips:%'")
        for aid, ips in by_asset.items():
            self.db.meta_set(f"surface_ips:{aid}", json.dumps(ips[:1024]))
        if not owners:
            self.db.status("internetdb", True, code="no_assets")
            self.db.execute("DELETE FROM surface")
            return 0
        prev = {r["ip"]: r for r in self.db.query("SELECT * FROM surface")}
        due = _iso(_now() - timedelta(hours=self.s.surface_interval_h))
        sem = asyncio.Semaphore(3)
        new = 0
        errors = 0
        kev = {r["cve"] for r in self.db.query("SELECT cve FROM kev")}
        epss = {r["cve"]: r["epss"] for r in self.db.query("SELECT cve, epss FROM epss")}
        day = _now().strftime("%Y-%m-%d")

        async def one(ip: str) -> None:
            nonlocal new, errors
            old = prev.get(ip)
            if old and not force and old["fetched_at"] >= due and old["status"] != "error":
                return
            async with sem:
                try:
                    d = await self._internetdb(client, ip)
                except Exception as exc:
                    errors += 1
                    log.info("InternetDB %s: %s", ip, exc.__class__.__name__)
                    if not old:
                        self.db.execute("INSERT OR REPLACE INTO surface(ip, status, fetched_at) VALUES(?,?,?)", (ip, "error", utcnow()))
                    return
                finally:
                    await asyncio.sleep(0.5)
            self.db.execute(
                "INSERT INTO surface(ip, status, ports, cpes, hostnames, tags, vulns, fetched_at) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET status=excluded.status, ports=excluded.ports, cpes=excluded.cpes, "
                "hostnames=excluded.hostnames, tags=excluded.tags, vulns=excluded.vulns, fetched_at=excluded.fetched_at",
                (ip, d["status"], json.dumps(d.get("ports", [])), json.dumps(d.get("cpes", [])), json.dumps(d.get("hostnames", [])),
                 json.dumps(d.get("tags", [])), json.dumps(d.get("vulns", [])), utcnow()))
            if not old or old["status"] == "error":
                return  # baseline
            w = owners[ip][0]
            label = watchlist.asset_label(w)
            old_ports = set(json.loads(old["ports"] or "[]"))
            old_vulns = set(json.loads(old["vulns"] or "[]"))
            for port in sorted(set(d.get("ports", [])) - old_ports):
                new += alerts.add(self.db, "surface", "high" if port in RISKY_PORTS else "medium", "surface.new_port",
                                  {"ip": ip, "port": port, "asset": label}, f"{ip}:new:{port}:{day}", asset_id=w["id"],
                                  url=f"https://www.shodan.io/host/{ip}")
            for port in sorted(old_ports - set(d.get("ports", []))) if d["status"] == "ok" else []:
                new += alerts.add(self.db, "surface", "low", "surface.closed_port",
                                  {"ip": ip, "port": port, "asset": label}, f"{ip}:closed:{port}:{day}", asset_id=w["id"])
            for cve in sorted(set(d.get("vulns", [])) - old_vulns):
                new += alerts.add(self.db, "surface", "high" if cve in kev else "medium", "surface.new_vuln",
                                  {"ip": ip, "cve": cve, "kev": cve in kev, "epss_v": epss.get(cve), "asset": label},
                                  f"{ip}:vuln:{cve}", asset_id=w["id"], url=f"https://nvd.nist.gov/vuln/detail/{cve}")

        await asyncio.gather(*(one(ip) for ip in owners))
        stale = [ip for ip in prev if ip not in owners]
        for ip in stale:
            self.db.execute("DELETE FROM surface WHERE ip=?", (ip,))
        self.db.status("internetdb", errors < max(1, len(owners)), "", len(owners),
                       code="batches_failed" if errors else None, params={"count": errors} if errors else None)
        return new

    def ips_of(self, entry: dict[str, Any]) -> list[str]:
        """Addresses of an asset as of the last passive run (an IP asset is always itself)."""
        if entry["kind"] == "ip":
            return [entry["value"]]
        raw = self.db.meta_get(f"surface_ips:{entry['id']}")
        try:
            return json.loads(raw) if raw else []
        except ValueError:
            return []

    def surface_for(self, ips: list[str]) -> list[dict[str, Any]]:
        if not ips:
            return []
        rows = self.db.query(f"SELECT * FROM surface WHERE ip IN ({','.join('?' * len(ips))})", ips)
        kev = {r["cve"] for r in self.db.query("SELECT cve FROM kev")}
        out = []
        for r in rows:
            item = {"ip": r["ip"], "status": r["status"], "fetched_at": r["fetched_at"]}
            for k in ("ports", "cpes", "hostnames", "tags", "vulns"):
                item[k] = json.loads(r[k] or "[]")
            item["kev"] = [v for v in item["vulns"] if v in kev]
            g = self.geo.lookup(r["ip"]) or {}
            for k in ("asn", "as_name", "country", "lat", "lon"):
                item[k] = g.get(k)
            out.append(item)
        return out

    # --- active scan ----------------------------------------------------------------------------
    async def _service(self, ip: str, port: int, host: str | None) -> dict[str, Any]:
        tls = http = None
        banner = ""
        t = self.s.scan_timeout_s + 2
        if port in TLS_PORTS:
            tls = await tls_details(ip, port, host, "en", timeout=t + 2)
            if tls.get("error"):
                tls = {"error": tls["error"][:200]}
            else:
                tls = {k: tls.get(k) for k in ("version", "subject", "issuer", "not_after", "days_left", "sha256", "valid",
                                               "validation", "san")}
                tls["san"] = (tls.get("san") or [])[:10]
        if tls and not tls.get("error") and port not in (465, 636, 993, 995, 563, 990, 992, 994, 853, 5061, 8883, 3269):
            http = await http_head(ip, port, host or ip, "/", True, "en", timeout=t + 2)
        if not tls or tls.get("error"):
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=t)
                try:
                    banner = _banner_text(await asyncio.wait_for(r.read(512), timeout=2.5))
                except (asyncio.TimeoutError, ConnectionError, OSError):
                    banner = ""
                w.close()
            except (asyncio.TimeoutError, OSError):
                banner = ""
            if not banner and port in HTTP_PORTS:
                http = await http_head(ip, port, host or ip, "/", False, "en", timeout=t + 2)
        hinfo = None
        if http and not http.get("error"):
            hdrs = {k.lower(): v for k, v in http.get("headers") or []}
            hinfo = {"status": http.get("status", "")[:100], "server": (hdrs.get("server") or "")[:120],
                     "powered_by": (hdrs.get("x-powered-by") or "")[:120], "location": (hdrs.get("location") or "")[:200]}
        return {"banner": banner, "tls": tls, "http": hinfo, "service": guess_service(port, banner, tls, hinfo)}

    async def scan_asset(self, asset_id: int, trigger: str = "manual") -> int:
        w = (self.db.query("SELECT id, kind, value, label, scan, scan_ack FROM watchlist WHERE id=?", (asset_id,)) or [None])[0]
        if not w:
            raise AppError("err.not_found", 404)
        if not self.s.scan_enabled:
            raise AppError("err.scan_disabled", 403)
        if not w["scan"] or not w["scan_ack"]:
            raise AppError("err.scan_ack")
        if self.scan_lock.locked():
            raise AppError("err.busy", 409)
        async with self.scan_lock:
            ips = await self.targets(w, self.s.scan_max_hosts, active=True)
            if not ips:
                raise AppError("err.scan_no_targets")
            run_id = self.db.insert(
                "INSERT INTO scan_runs(asset_id, started_at, status, trigger, targets) VALUES(?,?,?,?,?)",
                (asset_id, utcnow(), "running", trigger, len(ips)))
            self.current = {"asset_id": asset_id, "run_id": run_id, "done": 0, "total": len(ips) * len(self.s.scan_ports)}
            try:
                found = await self._scan(ips, w)
            except Exception as exc:
                log.exception("scan of asset %s failed", asset_id)
                self.db.execute("UPDATE scan_runs SET status='error', finished_at=?, error=? WHERE id=?",
                                (utcnow(), exc.__class__.__name__, run_id))
                self.current = None
                raise
            rows = [(run_id, ip, port, d["banner"] or None, json.dumps(d["tls"]) if d["tls"] else None,
                     json.dumps({**(d["http"] or {}), "service": d["service"]})) for (ip, port), d in found.items()]
            self.db.execmany("INSERT OR REPLACE INTO scan_ports(run_id, ip, port, banner, tls, http) VALUES(?,?,?,?,?,?)", rows)
            self.db.execute("UPDATE scan_runs SET status='done', finished_at=?, open_ports=? WHERE id=?",
                            (utcnow(), len(found), run_id))
            self.current = None
            self._diff(w, run_id)
            self.db.execute("DELETE FROM scan_ports WHERE run_id IN (SELECT id FROM scan_runs WHERE asset_id=? AND id NOT IN "
                            "(SELECT id FROM scan_runs WHERE asset_id=? ORDER BY id DESC LIMIT 10))", (asset_id, asset_id))
            self.db.execute("DELETE FROM scan_runs WHERE asset_id=? AND id NOT IN "
                            "(SELECT id FROM scan_runs WHERE asset_id=? ORDER BY id DESC LIMIT 10)", (asset_id, asset_id))
            return run_id

    async def _scan(self, ips: list[str], w: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
        sem = asyncio.Semaphore(self.s.scan_concurrency)
        open_ports: list[tuple[str, int]] = []

        async def probe(ip: str, port: int) -> None:
            async with sem:
                state, _, _ = await tcp_probe(ip, port, self.s.scan_timeout_s)
            if self.current is not None:
                self.current["done"] += 1
            if state == "open":
                open_ports.append((ip, port))

        await asyncio.gather(*(probe(ip, p) for ip in ips for p in self.s.scan_ports))
        host = w["value"] if w["kind"] == "domain" else None
        dsem = asyncio.Semaphore(8)
        found: dict[tuple[str, int], dict[str, Any]] = {}

        async def detail(ip: str, port: int) -> None:
            async with dsem:
                try:
                    found[(ip, port)] = await asyncio.wait_for(self._service(ip, port, host), timeout=30)
                except Exception:
                    found[(ip, port)] = {"banner": "", "tls": None, "http": None, "service": SERVICES.get(port, "")}

        await asyncio.gather(*(detail(ip, p) for ip, p in open_ports[:2000]))
        return found

    def _ports_of(self, run_id: int) -> dict[tuple[str, int], dict[str, Any]]:
        out = {}
        for r in self.db.query("SELECT ip, port, banner, tls, http FROM scan_ports WHERE run_id=?", (run_id,)):
            out[(r["ip"], r["port"])] = {"banner": r["banner"] or "", "tls": json.loads(r["tls"]) if r["tls"] else None,
                                         "http": json.loads(r["http"]) if r["http"] else None}
        return out

    def _diff(self, w: dict[str, Any], run_id: int) -> int:
        label = watchlist.asset_label(w)
        cur = self._ports_of(run_id)
        prev_run = self.db.query("SELECT id FROM scan_runs WHERE asset_id=? AND status='done' AND id < ? ORDER BY id DESC LIMIT 1",
                                 (w["id"], run_id))
        new = 0
        aid = w["id"]
        for (ip, port), d in cur.items():  # certificate expiry: always
            tls = d["tls"] or {}
            days = tls.get("days_left")
            if isinstance(days, int) and days <= 14:
                sev, tier = ("high", "3") if days <= 3 else ("medium", "14")
                new += alerts.add(self.db, "scan", sev, "scan.cert_expiring",
                                  {"ip": ip, "port": port, "days": days, "subject": tls.get("subject") or "?", "asset": label},
                                  f"{ip}:{port}:{tls.get('sha256')}:{tier}", asset_id=aid)
        if not prev_run:
            return new
        prev = self._ports_of(prev_run[0]["id"])
        for (ip, port), d in cur.items():
            if (ip, port) not in prev:
                svc = (d["http"] or {}).get("service") or ""
                new += alerts.add(self.db, "scan", "high" if port in RISKY_PORTS else "medium", "scan.new_port",
                                  {"ip": ip, "port": port, "service": svc, "banner": d["banner"][:80], "asset": label},
                                  f"{run_id}:{ip}:{port}:open", asset_id=aid)
                continue
            old = prev[(ip, port)]
            t_new, t_old = (d["tls"] or {}), (old["tls"] or {})
            if t_new.get("sha256") and t_old.get("sha256") and t_new["sha256"] != t_old["sha256"]:
                new += alerts.add(self.db, "scan", "low", "scan.cert_changed",
                                  {"ip": ip, "port": port, "issuer": t_new.get("issuer") or "?",
                                   "not_after": (t_new.get("not_after") or "")[:10], "asset": label},
                                  f"{ip}:{port}:{t_new['sha256']}", asset_id=aid)
            b_new = d["banner"] or (d["http"] or {}).get("server") or ""
            b_old = old["banner"] or (old["http"] or {}).get("server") or ""
            if b_new and b_old and b_new.split("\n")[0][:80] != b_old.split("\n")[0][:80]:
                new += alerts.add(self.db, "scan", "low", "scan.banner_changed",
                                  {"ip": ip, "port": port, "old": b_old[:80], "new": b_new[:80], "asset": label},
                                  f"{run_id}:{ip}:{port}:banner", asset_id=aid)
        for (ip, port) in prev.keys() - cur.keys():
            new += alerts.add(self.db, "scan", "low", "scan.closed_port", {"ip": ip, "port": port, "asset": label},
                              f"{run_id}:{ip}:{port}:closed", asset_id=aid)
        return new

    async def scheduled(self) -> int:
        """Runs due scans one after another. Returns the number of scans."""
        if not self.s.scan_enabled:
            return 0
        due = _iso(_now() - timedelta(hours=self.s.scan_interval_h))
        n = 0
        for w in self.db.query("SELECT id FROM watchlist WHERE scan=1 AND scan_ack IS NOT NULL ORDER BY id"):
            last = self.db.query("SELECT started_at FROM scan_runs WHERE asset_id=? AND status IN ('done','running') "
                                 "ORDER BY id DESC LIMIT 1", (w["id"],))
            if last and last[0]["started_at"] >= due:
                continue
            try:
                await self.scan_asset(w["id"], "schedule")
                n += 1
            except AppError as exc:
                log.info("scheduled scan of asset %s skipped: %s", w["id"], exc.key)
        return n

    def last_scan(self, asset_id: int) -> dict[str, Any] | None:
        runs = self.db.query("SELECT * FROM scan_runs WHERE asset_id=? ORDER BY id DESC LIMIT 1", (asset_id,))
        if not runs:
            return None
        run = runs[0]
        done = run
        if run["status"] != "done":
            prev = self.db.query("SELECT * FROM scan_runs WHERE asset_id=? AND status='done' ORDER BY id DESC LIMIT 1", (asset_id,))
            done = prev[0] if prev else None
        ports = []
        if done:
            for (ip, port), d in sorted(self._ports_of(done["id"]).items(), key=lambda x: (x[0][0], x[0][1])):
                ports.append({"ip": ip, "port": port, "banner": d["banner"], "tls": d["tls"], "http": d["http"],
                              "service": (d["http"] or {}).get("service") or SERVICES.get(port, ""),
                              "risky": port in RISKY_PORTS})
        progress = None
        if self.current and self.current["asset_id"] == asset_id:
            progress = {"done": self.current["done"], "total": self.current["total"]}
        return {"run": run, "result_run": done, "ports": ports, "progress": progress}
