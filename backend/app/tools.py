"""Network tools: ping, traceroute, DNS, RDAP, IP info, port check, HTTP/TLS.

Security design:
- Inputs are strictly validated (IP literal or hostname per RFC 1123, no options, no whitespace).
  External programs run without a shell with an argument list; the target is always passed as the
  resolved IP, never as the user-supplied string.
- SSRF protection: targets must be public (globally routable) addresses unless TOOLS_ALLOW_PRIVATE is set.
  Hostnames are resolved once and every further connection goes to exactly these IPs (no DNS rebinding).
- Limited concurrency, hard time limits, limited output sizes.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import ssl
import time
from datetime import datetime, timezone
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.resolver
import dns.reversename
import httpx

from . import __version__, i18n
from .config import Settings
from .db import DB
from .geo import Geo
from .i18n import AppError

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9_-]{1,63}(?<!-)\.)*[a-z0-9-]{1,63}(?<!-)$")
DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
RESOLVERS = {"system": None, "cloudflare": ["1.1.1.1"], "google": ["8.8.8.8"], "quad9": ["9.9.9.9"]}
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
                    "referrer-policy", "permissions-policy", "cross-origin-opener-policy")

_proc_sem = asyncio.Semaphore(3)


class _Skip(Exception):
    """Internal: a lookup is left out on purpose."""


class ToolError(AppError):
    def __init__(self, key: str, **params: Any) -> None:
        super().__init__(key, 400, **params)


# --- validation & resolution ---------------------------------------------------------
# IPv6 ranges that embed IPv4 addresses (IPv4-compatible, NAT64, 6to4): Python's is_global does not look inside them
_EMBEDDED_V4 = (ipaddress.ip_network("::/96"), ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


def is_public(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Globally routable and not an IPv6 wrapper around a (possibly private) IPv4 address."""
    if not addr.is_global or addr.is_multicast:
        return False
    if addr.version == 6:
        if any(addr in n for n in _EMBEDDED_V4):
            return False
        if addr.sixtofour is not None and not addr.sixtofour.is_global:
            return False
    return True


def check_ip(ip: str, allow_private: bool) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ToolError("err.tool.ip") from exc
    if getattr(addr, "scope_id", None) is not None:  # fe80::1%eth0
        raise ToolError("err.tool.ip")
    if addr.is_multicast or addr.is_unspecified:
        raise ToolError("err.tool.multicast")
    if not allow_private and not is_public(addr):
        raise ToolError("err.tool.private", addr=str(addr))
    return str(addr)


def parse_host(raw: str) -> tuple[str, bool]:
    """Returns (normalized host, is_ip)."""
    s = (raw or "").strip()
    if not s or len(s) > 253 or any(c.isspace() for c in s) or s.startswith("-"):
        raise ToolError("err.tool.target")
    s = s.strip("[]")
    if "%" in s:  # IPv6 zone ID
        raise ToolError("err.tool.target")
    try:
        return str(ipaddress.ip_address(s)), True
    except ValueError:
        pass
    try:
        host = s.lower().rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ToolError("err.tool.hostname") from exc
    if not HOST_RE.match(host):
        raise ToolError("err.tool.hostname")
    return host, False


async def resolve(host: str, allow_private: bool, family: str = "any") -> list[str]:
    host_n, is_ip = parse_host(host)
    if is_ip:
        return [check_ip(host_n, allow_private)]
    res = dns.asyncresolver.Resolver()
    res.lifetime = 4.0
    ips: list[str] = []
    for rtype in (("A",) if family == "4" else ("AAAA",) if family == "6" else ("A", "AAAA")):
        try:
            ans = await res.resolve(host_n, rtype)
            ips += [r.to_text() for r in ans]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
    if not ips:
        raise ToolError("err.tool.resolve", host=host_n)
    return [check_ip(ip, allow_private) for ip in ips]  # every address must be allowed


async def ptr(ip: str, timeout: float = 1.5) -> str | None:
    res = dns.asyncresolver.Resolver()
    res.lifetime = timeout
    try:
        ans = await res.resolve(dns.reversename.from_address(ip), "PTR")
        return ans[0].to_text().rstrip(".")
    except Exception:
        return None


def geo_of(geo: Geo, ip: str) -> dict[str, Any] | None:
    g = geo.lookup(ip)
    if not g or g.get("lat") is None:
        return g
    return {k: g.get(k) for k in ("country", "city", "lat", "lon", "asn", "as_name")}


class ToolKit:
    def __init__(self, s: Settings, db: DB, geo: Geo, reputation: Any = None) -> None:
        self.s = s
        self.db = db
        self.geo = geo
        self.reputation = reputation
        self._origin: tuple[float, dict[str, Any]] | None = None
        self._rdap_calls: list[float] = []

    # --- server location (start of the traceroute) --------------------------------
    async def origin(self, client: httpx.AsyncClient, max_age: float = 6 * 3600) -> dict[str, Any]:
        """Public egress address of this server (via Cloudflare's trace endpoint), cached for max_age seconds."""
        if self._origin and time.time() - self._origin[0] < (max_age if self._origin[1].get("ip") else 600):
            return self._origin[1]
        info: dict[str, Any] = {"ip": None}
        try:
            r = await client.get("https://1.1.1.1/cdn-cgi/trace", timeout=5)
            kv = dict(line.split("=", 1) for line in r.text.splitlines() if "=" in line)
            ip = kv.get("ip")
            if ip:
                ipaddress.ip_address(ip)
                info = {"ip": ip, **(geo_of(self.geo, ip) or {})}
        except Exception:
            pass
        self._origin = (time.time(), info)
        return info

    # --- ping ---------------------------------------------------------------------
    async def ping(self, target: str, count: int) -> AsyncIterator[dict[str, Any]]:
        ips = await resolve(target, self.s.tools_allow_private)
        ip = ips[0]
        yield {"type": "start", "tool": "ping", "target": target, "ip": ip, "geo": geo_of(self.geo, ip)}
        replies = 0
        rtts: list[float] = []
        fallback = False
        async with _proc_sem:
            try:
                fam = "-6" if ":" in ip else "-4"
                proc = await asyncio.create_subprocess_exec(
                    self.s.ping_bin, fam, "-n", "-O", "-c", str(count), "-i", "0.5", "-W", "2", ip,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            except (FileNotFoundError, PermissionError, OSError) as exc:
                fallback = True
                yield {"type": "info", "key": "tool.icmp_unavailable", "params": {"detail": exc.__class__.__name__}}
            if not fallback:
                deadline = time.time() + count * 2.5 + 5
                errtext: list[str] = []
                try:
                    while True:
                        try:
                            line = await asyncio.wait_for(proc.stdout.readline(), timeout=max(0.1, deadline - time.time()))
                        except asyncio.TimeoutError:
                            break
                        if not line:
                            break
                        text = line.decode(errors="replace").strip()
                        m = re.search(r"icmp_seq=(\d+)\s+ttl=(\d+)\s+time=([\d.]+)\s*ms", text)
                        if m:
                            replies += 1
                            rtts.append(float(m.group(3)))
                            yield {"type": "reply", "seq": int(m.group(1)), "ttl": int(m.group(2)), "rtt": float(m.group(3)), "method": "icmp"}
                            continue
                        m = re.search(r"no answer yet for icmp_seq=(\d+)", text)
                        if m:
                            yield {"type": "timeout", "seq": int(m.group(1))}
                            continue
                        if re.search(r"socket|not permitted|not supported|Permission denied", text, re.I):
                            errtext.append(text)
                finally:
                    if proc.returncode is None:
                        proc.kill()
                    await proc.wait()
                if replies == 0 and errtext:
                    fallback = True
                    yield {"type": "info", "key": "tool.icmp_failed", "params": {"detail": errtext[0][:120]}}
        if fallback:
            async for ev in self._tcp_ping(ip, count):
                if ev["type"] == "reply":
                    replies += 1
                    rtts.append(ev["rtt"])
                yield ev
        yield {"type": "done", "sent": count, "received": replies,
               "loss_pct": round(100 * (count - replies) / count, 1) if count else 0,
               "min": min(rtts) if rtts else None, "avg": round(sum(rtts) / len(rtts), 2) if rtts else None,
               "max": max(rtts) if rtts else None}

    async def _tcp_ping(self, ip: str, count: int) -> AsyncIterator[dict[str, Any]]:
        port = None
        for p in (443, 80):
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, p), timeout=3)
                w.close()
                port = p
                break
            except Exception:
                continue
        if port is None:
            yield {"type": "info", "key": "tool.tcp_unreachable", "params": {}}
            return
        for seq in range(1, count + 1):
            t0 = time.perf_counter()
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3)
                rtt = (time.perf_counter() - t0) * 1000
                w.close()
                yield {"type": "reply", "seq": seq, "ttl": None, "rtt": round(rtt, 2), "method": f"tcp/{port}"}
            except Exception:
                yield {"type": "timeout", "seq": seq}
            await asyncio.sleep(0.5)

    # --- traceroute -----------------------------------------------------------------
    async def traceroute(self, client: httpx.AsyncClient, target: str, max_hops: int) -> AsyncIterator[dict[str, Any]]:
        ips = await resolve(target, self.s.tools_allow_private)
        ip = ips[0]
        yield {"type": "start", "tool": "traceroute", "target": target, "ip": ip, "geo": geo_of(self.geo, ip),
               "origin": await self.origin(client)}
        reached = False
        async with _proc_sem:
            fam = "-6" if ":" in ip else "-4"
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.s.traceroute_bin, fam, "-n", "-q", "1", "-w", "2", "-m", str(max_hops), ip,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            except (FileNotFoundError, PermissionError, OSError) as exc:
                raise ToolError("err.tool.traceroute_missing", detail=exc.__class__.__name__) from exc
            deadline = time.time() + max_hops * 3 + 10
            try:
                while True:
                    try:
                        line = await asyncio.wait_for(proc.stdout.readline(), timeout=max(0.1, deadline - time.time()))
                    except asyncio.TimeoutError:
                        yield {"type": "info", "key": "tool.trace_timeout", "params": {}}
                        break
                    if not line:
                        break
                    hop = parse_trace_line(line.decode(errors="replace").rstrip())
                    if hop is None:
                        continue
                    if hop["type"] == "info":
                        yield hop
                        continue
                    if hop["ip"]:
                        addr = ipaddress.ip_address(hop["ip"])
                        hop["private"] = not addr.is_global
                        if addr.is_global:
                            hop["geo"] = geo_of(self.geo, hop["ip"])
                            hop["ptr"] = await ptr(hop["ip"])
                            c2 = self.db.query("SELECT malware, source FROM c2 WHERE ip=? LIMIT 3", (hop["ip"],))
                            if c2:
                                hop["c2"] = c2
                        if hop["ip"] == ip:
                            reached = True
                    yield hop
            finally:
                if proc.returncode is None:
                    proc.kill()
                await proc.wait()
        yield {"type": "done", "reached": reached}

    # --- DNS --------------------------------------------------------------------------
    async def dns_lookup(self, target: str, resolver: str, lang: str) -> dict[str, Any]:
        host, is_ip = parse_host(target)
        if resolver not in RESOLVERS:
            raise ToolError("err.tool.resolver")
        res = dns.asyncresolver.Resolver(configure=RESOLVERS[resolver] is None)
        if RESOLVERS[resolver]:
            res.nameservers = RESOLVERS[resolver]
        res.lifetime = 5.0
        res.use_edns(0, dns.flags.DO, 1232)
        out: dict[str, Any] = {"target": host, "resolver": resolver, "records": {}, "ad_flag": None, "geo": []}
        if is_ip:
            name = dns.reversename.from_address(host)
            try:
                ans = await res.resolve(name, "PTR")
                out["records"]["PTR"] = [{"value": r.to_text(), "ttl": ans.rrset.ttl} for r in ans]
            except Exception as exc:
                out["records"]["PTR"] = [{"error": dns_err(exc, lang)}]
            return out
        for rtype in DNS_TYPES:
            try:
                ans = await res.resolve(host, rtype)
                out["records"][rtype] = [{"value": r.to_text()[:1000], "ttl": ans.rrset.ttl} for r in ans]
                if rtype == "A" and ans.response is not None:
                    out["ad_flag"] = bool(ans.response.flags & dns.flags.AD)
            except dns.resolver.NoAnswer:
                continue
            except Exception as exc:
                out["records"][rtype] = [{"error": dns_err(exc, lang)}]
        try:
            ans = await res.resolve(f"_dmarc.{host}", "TXT")
            out["records"]["DMARC"] = [{"value": r.to_text()[:1000], "ttl": ans.rrset.ttl} for r in ans]
        except Exception:
            pass
        spf = [r["value"] for r in out["records"].get("TXT", []) if "value" in r and "v=spf1" in r["value"].lower()]
        out["mail_security"] = {"spf": spf, "dmarc": [r.get("value") for r in out["records"].get("DMARC", [])]}
        for rtype in ("A", "AAAA"):
            for r in out["records"].get(rtype, []):
                if "value" in r:
                    g = geo_of(self.geo, r["value"])
                    if g and g.get("lat") is not None:
                        out["geo"].append({"ip": r["value"], **g})
        return out

    # --- RDAP ---------------------------------------------------------------------------
    async def rdap(self, client: httpx.AsyncClient, target: str) -> dict[str, Any]:
        q = (target or "").strip()
        m = re.fullmatch(r"(?i)as(\d{1,10})", q)
        if m:
            kind, obj = "autnum", m.group(1)
        else:
            try:
                kind, obj = "ip", str(ipaddress.ip_network(q, strict=False)) if "/" in q else str(ipaddress.ip_address(q))
            except ValueError:
                host, _ = parse_host(q)
                kind, obj = "domain", host
        now = time.time()
        self._rdap_calls = [t for t in self._rdap_calls if now - t < 10]
        if len(self._rdap_calls) >= 8:  # rdap.org allows 10 requests / 10 s
            raise ToolError("err.tool.rdap_rate")
        self._rdap_calls.append(now)
        url = f"https://rdap.org/{kind}/{obj}"
        body = await self._safe_get_json(client, url)
        return {"query": obj, "kind": kind, "summary": _rdap_summary(body), "raw": body}

    async def _safe_get_json(self, client: httpx.AsyncClient, url: str, hops: int = 4) -> dict[str, Any]:
        for _ in range(hops):
            parts = urlsplit(url)
            if parts.scheme != "https" or not parts.hostname:
                raise ToolError("err.tool.rdap_redirect")
            await resolve(parts.hostname, False)  # redirect targets must be public
            try:
                r = await client.get(url, follow_redirects=False, timeout=15,
                                     headers={"Accept": "application/rdap+json, application/json"})
            except httpx.HTTPError as exc:
                raise ToolError("err.tool.upstream", detail=exc.__class__.__name__) from exc
            if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                url = str(httpx.URL(url).join(r.headers["location"]))
                continue
            if r.status_code == 404:
                raise ToolError("err.tool.rdap_none")
            if r.status_code == 429:
                raise ToolError("err.tool.rdap_429")
            if r.status_code != 200:
                raise ToolError("err.tool.rdap_http", status=r.status_code)
            if len(r.content) > 2_000_000:
                raise ToolError("err.tool.rdap_big")
            try:
                return r.json()
            except ValueError as exc:
                raise ToolError("err.tool.rdap_json") from exc
        raise ToolError("err.tool.rdap_loops")

    # --- IP info --------------------------------------------------------------------------
    async def ipinfo(self, client: httpx.AsyncClient, target: str, lang: str) -> dict[str, Any]:
        ips = await resolve(target, True)  # lookups only, no connection to the target
        ip = ips[0]
        out: dict[str, Any] = {"target": target, "ip": ip, "geo": geo_of(self.geo, ip), "ptr": await ptr(ip)}
        try:
            if not is_public(ipaddress.ip_address(ip)):  # private addresses are not sent to RIPEstat
                raise _Skip
            r = await client.get("https://stat.ripe.net/data/prefix-overview/data.json",
                                 params={"resource": ip, "sourceapp": "emberwatch"}, timeout=15)
            d = (r.json() or {}).get("data") or {}
            out["routing"] = {
                "prefix": d.get("resource"), "announced": d.get("announced"),
                "asns": [{"asn": a.get("asn"), "holder": a.get("holder")} for a in d.get("asns") or []],
                "is_less_specific": d.get("is_less_specific"),
            }
        except _Skip:
            out["routing"] = {"error": i18n.t(lang, "ob.v.private")}
        except Exception as exc:
            out["routing"] = {"error": i18n.t(lang, "tool.ripestat_failed", detail=exc.__class__.__name__)}
        out["c2"] = self.db.query(
            "SELECT malware, source, ioc, first_seen, last_seen, reference FROM c2 WHERE ip=? ORDER BY first_seen DESC LIMIT 20", (ip,))
        out["iocs"] = self.db.query(
            "SELECT malware, threat_type, ioc, first_seen, reference FROM iocs WHERE ip=? ORDER BY first_seen DESC LIMIT 20", (ip,))
        asn = (out["geo"] or {}).get("asn") or next((a["asn"] for a in (out.get("routing") or {}).get("asns", []) if a.get("asn")), None)
        out["infra"] = []
        if asn:
            for e in self.db.query("SELECT kind, start_ts, asns, meta FROM infra_events ORDER BY start_ts DESC LIMIT 500"):
                if int(asn) in json.loads(e["asns"] or "[]"):
                    try:
                        meta = json.loads(e["meta"] or "{}")
                    except ValueError:
                        meta = {}
                    meta["kind"] = e["kind"]
                    out["infra"].append({"kind": e["kind"], "start_ts": e["start_ts"],
                                         "title": i18n.render_infra_title(e["kind"], meta, lang),
                                         "detail": i18n.render_infra_detail(meta, lang)})
        out["infra"] = out["infra"][:10]
        if self.reputation is not None:
            out["reputation"] = await self.reputation.check(client, ip)
        return out

    # --- port check ---------------------------------------------------------------------
    async def portcheck(self, target: str, ports: list[int], lang: str) -> dict[str, Any]:
        ips = await resolve(target, self.s.tools_allow_private)
        ip = ips[0]
        results = []
        for port in ports:
            state, ms, detail = await tcp_probe(ip, port, 3.0)
            label = i18n.t(lang, f"tool.port.{state}", detail=detail or "")
            results.append({"port": port, "state": state, "label": label, "ms": ms})
            await asyncio.sleep(0.2)
        return {"target": target, "ip": ip, "geo": geo_of(self.geo, ip), "results": results}

    # --- HTTP / TLS ------------------------------------------------------------------------
    async def http_tls(self, target: str, lang: str) -> dict[str, Any]:
        raw = (target or "").strip()
        if "://" not in raw:
            raw = "https://" + raw
        parts = urlsplit(raw)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ToolError("err.tool.scheme")
        host, _ = parse_host(parts.hostname)
        try:
            port = parts.port or (443 if parts.scheme == "https" else 80)
        except ValueError as exc:
            raise ToolError("err.tool.port", port="?") from exc
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        if any(c in path for c in "\r\n ") or len(path) > 2000:
            raise ToolError("err.tool.path")
        ip = (await resolve(host, self.s.tools_allow_private))[0]
        out: dict[str, Any] = {"url": f"{parts.scheme}://{host}:{port}{path}", "ip": ip, "geo": geo_of(self.geo, ip)}
        if parts.scheme == "https":
            out["tls"] = await tls_details(ip, port, host, lang)
        out["http"] = await http_head(ip, port, host, path, parts.scheme == "https", lang)
        hdrs = {k.lower(): v for k, v in (out["http"].get("headers") or [])}
        out["security_headers"] = {h: hdrs.get(h) for h in SECURITY_HEADERS}
        out["disclosure"] = {h: hdrs[h] for h in ("server", "x-powered-by", "x-aspnet-version") if h in hdrs}
        return out


async def tcp_probe(ip: str, port: int, timeout: float) -> tuple[str, float | None, str | None]:
    """TCP connect test. Returns (state, ms, detail) with state open|closed|filtered|error."""
    t0 = time.perf_counter()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        w.close()
        return "open", round((time.perf_counter() - t0) * 1000, 1), None
    except ConnectionRefusedError:
        return "closed", round((time.perf_counter() - t0) * 1000, 1), None
    except asyncio.TimeoutError:
        return "filtered", None, None
    except OSError as exc:
        return "error", None, str(exc.strerror or exc)[:120]


def dns_err(exc: Exception, lang: str) -> str:
    if isinstance(exc, dns.resolver.NoAnswer):
        return i18n.t(lang, "tool.dns.none")
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return i18n.t(lang, "tool.dns.nxdomain")
    if isinstance(exc, dns.exception.Timeout):
        return i18n.t(lang, "tool.dns.timeout")
    if isinstance(exc, dns.resolver.NoNameservers):
        return i18n.t(lang, "tool.dns.servfail")
    return exc.__class__.__name__


def _vcard(entity: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    arr = entity.get("vcardArray")
    if isinstance(arr, list) and len(arr) == 2 and isinstance(arr[1], list):
        for item in arr[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue
            if item[0] in ("fn", "email", "tel", "org") and isinstance(item[3], str):
                out.setdefault(item[0], item[3])
            if item[0] == "adr" and isinstance(item[1], dict) and item[1].get("label"):
                out.setdefault("adr", str(item[1]["label"])[:200])
    return out


def _rdap_summary(b: dict[str, Any]) -> dict[str, Any]:
    ents = []

    def walk(lst: list[Any], depth: int = 0) -> None:
        for e in lst or []:
            if not isinstance(e, dict) or depth > 2:
                continue
            ents.append({"handle": e.get("handle"), "roles": e.get("roles"), **_vcard(e)})
            walk(e.get("entities"), depth + 1)

    walk(b.get("entities"))
    return {
        "object": b.get("objectClassName"), "handle": b.get("handle"), "name": b.get("name") or b.get("ldhName"),
        "type": b.get("type"), "country": b.get("country"),
        "range": [b.get("startAddress"), b.get("endAddress")] if b.get("startAddress") else None,
        "autnum": [b.get("startAutnum"), b.get("endAutnum")] if b.get("startAutnum") else None,
        "status": b.get("status"),
        "events": [{"action": e.get("eventAction"), "date": e.get("eventDate")} for e in b.get("events") or [] if isinstance(e, dict)],
        "nameservers": [n.get("ldhName") for n in b.get("nameservers") or [] if isinstance(n, dict)],
        "entities": ents[:15],
        "port43": b.get("port43"),
    }


def cert_info(der: bytes) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    pk = cert.public_key()
    key = (f"RSA {pk.key_size}" if isinstance(pk, rsa.RSAPublicKey) else
           f"EC {pk.curve.name}" if isinstance(pk, ec.EllipticCurvePublicKey) else pk.__class__.__name__)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    return {
        "subject": cert.subject.rfc4514_string()[:300], "issuer": cert.issuer.rfc4514_string()[:300],
        "san": san[:50], "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "days_left": (na - datetime.now(timezone.utc)).days,
        "signature": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "key": key, "serial": format(cert.serial_number, "x"), "sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


async def tls_details(ip: str, port: int, host: str | None, lang: str, timeout: float = 8.0) -> dict[str, Any]:
    info: dict[str, Any] = {}
    # 1) fetch the certificate without verification (works for invalid certificates too)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host), timeout=timeout)
        so = w.get_extra_info("ssl_object")
        info["version"] = so.version()
        info["cipher"] = so.cipher()[0] if so.cipher() else None
        der = so.getpeercert(binary_form=True)
        w.close()
    except Exception as exc:
        return {"error": i18n.t(lang, "tool.tls_connect_failed", detail=f"{exc.__class__.__name__}: {exc}"[:200])}
    if der:
        try:
            info.update(cert_info(der))
        except Exception as exc:  # malformed certificate
            info["cert_error"] = exc.__class__.__name__
    # 2) validity with standard verification (chain, period and hostname - or the IP address if there is no name)
    try:
        vctx = ssl.create_default_context()
        _, w2 = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=vctx, server_hostname=host or ip), timeout=timeout)
        w2.close()
        info["valid"] = True
        info["validation"] = i18n.t(lang, "tool.tls_ok")
    except ssl.SSLCertVerificationError as exc:
        info["valid"] = False
        info["validation"] = exc.verify_message or str(exc)
    except Exception as exc:
        info["valid"] = None
        info["validation"] = i18n.t(lang, "tool.tls_check_failed", detail=exc.__class__.__name__)
    return info


async def http_head(ip: str, port: int, host: str, path: str, use_tls: bool, lang: str, timeout: float = 8.0) -> dict[str, Any]:
    ctx = None
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t0 = time.perf_counter()
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host if use_tls else None), timeout=timeout)
        hostport = host if port in (80, 443) else f"{host}:{port}"
        w.write((f"HEAD {path} HTTP/1.1\r\nHost: {hostport}\r\nUser-Agent: emberwatch-tools/{__version__}\r\n"
                 f"Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii", "strict"))
        await w.drain()
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = await asyncio.wait_for(r.read(4096), timeout=timeout)
            if not chunk:
                break
            data += chunk
        w.close()
    except Exception as exc:
        return {"error": i18n.t(lang, "tool.http_failed", detail=f"{exc.__class__.__name__}: {exc}"[:200])}
    ms = round((time.perf_counter() - t0) * 1000, 1)
    head = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    lines = head.split("\r\n")
    status = lines[0] if lines else ""
    headers = []
    for ln in lines[1:60]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers.append([k.strip()[:100], v.strip()[:500]])
    return {"status": status[:200], "headers": headers, "ms": ms}


def parse_trace_line(text: str) -> dict[str, Any] | None:
    """Parses one line of `traceroute -n -q 1`. Returns a hop or info event, or None."""
    m = re.match(r"^\s*(\d+)\s+(.*)$", text)
    if not m:
        if not text or text.startswith("traceroute to"):
            return None
        return {"type": "info", "text": text[:200]}
    rest = m.group(2).strip()
    hop: dict[str, Any] = {"type": "hop", "n": int(m.group(1)), "ip": None, "rtt": None, "note": None}
    tok = rest.split()
    if tok and tok[0] != "*":
        try:
            hop["ip"] = str(ipaddress.ip_address(tok[0]))
        except ValueError:
            pass
    rm = re.search(r"([\d.]+)\s*ms", rest)
    if rm:
        hop["rtt"] = float(rm.group(1))
    nm = re.search(r"!\w+", rest)
    if nm:
        hop["note"] = nm.group(0)
    return hop


def parse_ports(raw: str) -> list[int]:
    ports = []
    for tok in (raw or "").replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if not tok.isdigit() or not (1 <= int(tok) <= 65535):
            raise ToolError("err.tool.port", port=tok[:10])
        ports.append(int(tok))
    ports = list(dict.fromkeys(ports))
    if not ports:
        raise ToolError("err.tool.no_ports")
    if len(ports) > 10:
        raise ToolError("err.tool.max_ports")
    return ports
