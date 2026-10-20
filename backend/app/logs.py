"""Log analysis: find known-bad indicators in log files and in a live syslog stream.

Indicators (IPv4, IPv6, domains, URLs) are extracted with conservative regular expressions and matched against
- abuse.ch Feodo Tracker C2 IPs,
- ThreatFox network IOCs (ip:port, domain, URL; kept for IOC_RETENTION_DAYS),
- Tor exit nodes and Spamhaus DROP (see reputation.py).

Uploaded files are processed in a worker thread, line by line, and are never stored: only the result goes back
to the browser. Domains match exactly or as a subdomain of an IOC domain; URL IOCs match only as full URLs,
because their hosts are often shared hosting or code platforms.
"""
from __future__ import annotations

import asyncio
import gzip
import ipaddress
import logging
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import IO, Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from . import alerts
from .config import Settings
from .db import DB
from .geo import Geo
from .reputation import Reputation

log = logging.getLogger("logs")

IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d]|\.\d)")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![\w-])", re.I)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>`\\\])}]{3,2000}", re.I)
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
MAX_HITS = 500
SAMPLE_LEN = 300
# File extensions that look like domains in logs; never treated as domains
NOT_TLDS = {"exe", "dll", "sys", "log", "txt", "json", "xml", "conf", "cfg", "ini", "tmp", "bak", "jpg", "png", "gif",
            "css", "js", "php", "asp", "aspx", "jsp", "html", "htm", "py", "sh", "ps1", "bat", "cmd", "zip", "gz",
            "tar", "rar", "pdf", "doc", "docx", "xls", "xlsx", "csv", "service", "socket", "target", "mount", "local",
            "lan", "internal", "localdomain", "arpa", "home", "corp", "so", "o", "c", "h", "md", "yml", "yaml"}
HIGH_THREATS = {"botnet_cc"}


def _norm_url(u: str) -> str | None:
    u = u.rstrip(".,;:!?'\")")
    try:
        p = urlsplit(u)
        host = (p.hostname or "").rstrip(".").lower()
        if not host:
            return None
        netloc = host if p.port is None else f"{host}:{p.port}"
        return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))
    except ValueError:
        return None


def extract(line: str) -> dict[str, set[str]]:
    """Indicators in one line (normalized). IPs are returned only if they are globally routable."""
    out: dict[str, set[str]] = {"ip": set(), "domain": set(), "url": set()}
    for m in IPV4_RE.findall(line):
        try:
            a = ipaddress.IPv4Address(m)
        except ValueError:
            continue
        if a.is_global:
            out["ip"].add(str(a))
    if line.count(":") >= 2:
        for m in IPV6_RE.findall(line):
            if m.count(":") < 2 or len(m) < 3:
                continue
            try:
                a6 = ipaddress.IPv6Address(m)
            except ValueError:
                continue
            if a6.is_global:
                out["ip"].add(str(a6))
    if "://" in line:
        for m in URL_RE.findall(line):
            n = _norm_url(m)
            if n:
                out["url"].add(n)
    if "." in line:
        for m in DOMAIN_RE.findall(line):
            d = m.lower().rstrip(".")
            tld = d.rsplit(".", 1)[-1]
            if tld in NOT_TLDS or tld.isdigit():
                continue
            out["domain"].add(d)
    return out


class Matcher:
    """In-memory indexes of the threat data, rebuilt after feed updates (invalidate()) or every 15 minutes."""

    def __init__(self, db: DB, rep: Reputation) -> None:
        self.db = db
        self.rep = rep
        self._built = 0.0
        self._rep_version = -1
        self.ip: dict[str, list[dict[str, Any]]] = {}
        self.host: dict[str, list[dict[str, Any]]] = {}
        self.url: dict[str, list[dict[str, Any]]] = {}

    def invalidate(self) -> None:
        self._built = 0.0

    def ensure(self) -> None:
        if time.time() - self._built < 900 and self._rep_version == self.rep.version:
            return
        ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
        host: dict[str, list[dict[str, Any]]] = defaultdict(list)
        url: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in self.db.query("SELECT ip, malware, source, reference FROM c2 WHERE ip IS NOT NULL AND source='feodo'"):
            if len(ip[r["ip"]]) < 3:
                ip[r["ip"]].append({"kind": "c2", "malware": r["malware"], "source": "Feodo Tracker",
                                    "threat": "botnet_cc", "reference": r["reference"]})
        for r in self.db.query("SELECT ioc, ioc_type, ip, host, threat_type, malware, reference FROM iocs"):
            m = {"kind": "ioc", "malware": r["malware"], "threat": r["threat_type"], "reference": r["reference"]}
            if r["ip"]:
                if len(ip[r["ip"]]) < 3:
                    ip[r["ip"]].append(m)
            elif r["ioc_type"] == "domain" and r["host"]:
                if len(host[r["host"]]) < 3:
                    host[r["host"]].append(m)
            elif r["ioc_type"] == "url":
                n = _norm_url(r["ioc"])
                if n and len(url[n]) < 3:
                    url[n].append(m)
        self.ip, self.host, self.url = dict(ip), dict(host), dict(url)
        self._built = time.time()
        self._rep_version = self.rep.version

    @property
    def size(self) -> dict[str, int]:
        return {"ips": len(self.ip), "domains": len(self.host), "urls": len(self.url),
                "drop": self.rep.drop_count, "tor": self.rep.tor_count}

    def match(self, kind: str, value: str) -> list[dict[str, Any]]:
        if kind == "ip":
            out = list(self.ip.get(value, []))
            if self.rep.is_tor(value):
                out.append({"kind": "tor"})
            d = self.rep.drop_for(value)
            if d:
                out.append({"kind": "drop", "cidr": d["cidr"], "sblid": d["sblid"]})
            return out
        if kind == "domain":
            labels = value.split(".")
            for i in range(len(labels) - 1):  # exact or parent domain (never the bare TLD)
                hit = self.host.get(".".join(labels[i:]))
                if hit:
                    return list(hit)
            return []
        if kind == "url":
            return list(self.url.get(value, []))
        return []


def severity(matches: list[dict[str, Any]]) -> str:
    if any(m["kind"] == "c2" or (m["kind"] == "ioc" and m.get("threat") in HIGH_THREATS) for m in matches):
        return "high"
    if any(m["kind"] in ("ioc", "drop") for m in matches):
        return "medium"
    return "low"


def _clean(line: str) -> str:
    return CTRL_RE.sub(" ", line.strip())[:SAMPLE_LEN]


def _lines(fh: IO[bytes]) -> Iterable[str]:
    """Lines of at most 16 KiB (longer lines are split), so a file without newlines cannot exhaust memory."""
    while True:
        raw = fh.readline(16384)
        if not raw:
            return
        yield raw.decode("utf-8", errors="replace")


UNIQUE_CAP = 200_000  # distinct indicators counted per type; hits are always kept


def analyze_file(path: str, matcher: Matcher, geo: Geo, max_lines: int = 5_000_000) -> dict[str, Any]:
    """Scans a (possibly gzip-compressed) text file. Runs in a worker thread."""
    t0 = time.perf_counter()
    with open(path, "rb") as probe:
        gz = probe.read(2) == b"\x1f\x8b"
    opener = gzip.open if gz else open
    ip_count: Counter = Counter()
    uniq: dict[str, set[str]] = {"domain": set(), "url": set()}
    capped = False
    nohit: set[tuple[str, str]] = set()
    hits: dict[tuple[str, str], dict[str, Any]] = {}
    n = 0
    truncated = False
    with opener(path, "rb") as fh:  # type: ignore[operator]
        for n, line in enumerate(_lines(fh), 1):
            if n > max_lines:
                truncated = True
                n -= 1
                break
            for kind, vals in extract(line).items():
                for v in vals:
                    key = (kind, v)
                    h = hits.get(key)
                    if h is not None:
                        h["count"] += 1
                    elif key not in nohit:
                        ms = matcher.match(kind, v)
                        if ms:
                            hits[key] = {"indicator": v, "type": kind, "count": 1, "line": n, "sample": _clean(line),
                                         "matches": ms, "severity": severity(ms)}
                        elif len(nohit) < UNIQUE_CAP * 3:
                            nohit.add(key)
                        else:
                            capped = True
                    if kind == "ip":
                        if v in ip_count or len(ip_count) < UNIQUE_CAP:
                            ip_count[v] += 1
                        else:
                            capped = True
                    elif len(uniq[kind]) < UNIQUE_CAP:
                        uniq[kind].add(v)
                    else:
                        capped = True
    out_hits = list(hits.values())
    for h in out_hits:
        if h["type"] == "ip":
            h["geo"] = geo.lookup(h["indicator"])
    order = {"high": 0, "medium": 1, "low": 2}
    out_hits.sort(key=lambda h: (order[h["severity"]], -h["count"], h["indicator"]))
    top_ips = [{"ip": ip, "count": cnt, "geo": geo.lookup(ip), "hit": ("ip", ip) in hits}
               for ip, cnt in ip_count.most_common(25)]
    return {
        "lines": n, "gzip": gz, "truncated": truncated, "capped": capped,
        "duration_ms": round((time.perf_counter() - t0) * 1000),
        "unique": {"ips": len(ip_count), "domains": len(uniq["domain"]), "urls": len(uniq["url"])},
        "hits_total": len(out_hits), "hits": out_hits[:MAX_HITS], "top_ips": top_ips, "indexes": matcher.size,
    }


# ---------------------------------------------------------------------------------------------------------
# Syslog receiver (RFC 3164/5424 over UDP and newline-delimited TCP)

class _Bucket:
    def __init__(self, rate: int) -> None:
        self.rate = rate
        self.tokens = float(rate)
        self.t = time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.rate, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class SyslogServer:
    MAX_LINE = 8192
    MAX_TCP = 20

    def __init__(self, s: Settings, db: DB, matcher: Matcher) -> None:
        self.s = s
        self.db = db
        self.matcher = matcher
        self.bucket = _Bucket(s.syslog_max_rate)
        self.stats: dict[str, Any] = {"received": 0, "dropped_rate": 0, "rejected": 0, "matched": 0, "alerts": 0,
                                      "last_at": None, "senders": Counter()}
        self._udp: asyncio.DatagramTransport | None = None
        self._tcp: asyncio.base_events.Server | None = None
        self._tcp_conns = 0
        self.error: str | None = None

    def allowed(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            return False
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr.version == n.version and addr in n for n in self.s.syslog_allow)

    def handle(self, line: str, sender: str) -> None:
        self.stats["received"] += 1
        if not self.bucket.take():
            self.stats["dropped_rate"] += 1
            return
        line = line.strip()
        if not line:
            return
        m = re.match(r"^\d{1,5} (<\d{1,3}>.*)$", line)  # RFC 6587 octet counting prefix
        if m:
            line = m.group(1)
        self.stats["last_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if len(self.stats["senders"]) < 1000 or sender in self.stats["senders"]:
            self.stats["senders"][sender] += 1
        self.matcher.ensure()
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for kind, vals in extract(line[:self.MAX_LINE]).items():
            for v in vals:
                ms = self.matcher.match(kind, v)
                if not ms:
                    continue
                self.stats["matched"] += 1
                sev = severity(ms)
                if alerts.add(self.db, "syslog", sev, "syslog.hit",
                              {"indicator": v, "matches": ms[:3], "source": sender, "line": _clean(line)[:200]},
                              f"{v}:{day}", url=next((m.get("reference") for m in ms if m.get("reference")), None)):
                    self.stats["alerts"] += 1

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        server = self

        class Udp(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple) -> None:
                if not server.allowed(addr[0]):
                    server.stats["rejected"] += 1
                    return
                for ln in data[:65535].decode("utf-8", errors="replace").splitlines():
                    server.handle(ln, addr[0])

        async def tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peer = (writer.get_extra_info("peername") or ("?",))[0]
            if not self.allowed(peer) or self._tcp_conns >= self.MAX_TCP:
                self.stats["rejected"] += 1
                writer.close()
                return
            self._tcp_conns += 1
            try:
                while True:
                    try:
                        raw = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=300)
                    except asyncio.LimitOverrunError as exc:
                        await reader.readexactly(exc.consumed)  # skip an over-long line
                        continue
                    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
                        break
                    self.handle(raw[:self.MAX_LINE].decode("utf-8", errors="replace"), peer)
            finally:
                self._tcp_conns -= 1
                writer.close()

        try:
            self._udp, _ = await loop.create_datagram_endpoint(Udp, local_addr=("0.0.0.0", self.s.syslog_port))
            self._tcp = await asyncio.start_server(tcp_client, "0.0.0.0", self.s.syslog_port, limit=self.MAX_LINE * 2)
            log.info("Syslog receiver listening on UDP/TCP %d", self.s.syslog_port)
        except OSError as exc:
            self.error = f"{exc.__class__.__name__}: {exc}"[:200]
            log.error("Syslog receiver could not start: %s", exc)

    async def stop(self) -> None:
        if self._udp:
            self._udp.close()
        if self._tcp:
            self._tcp.close()
            await self._tcp.wait_closed()

    def info(self) -> dict[str, Any]:
        st = dict(self.stats)
        st["senders"] = [{"ip": k, "lines": v} for k, v in self.stats["senders"].most_common(10)]
        return {"enabled": True, "port": self.s.syslog_port, "error": self.error,
                "allow": [str(n) for n in self.s.syslog_allow], **st}
