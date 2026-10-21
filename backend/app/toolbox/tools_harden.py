"""How well is it secured: ports, TLS in depth, HTTP security headers, SSH algorithms, DNS/DNSSEC (+ zone transfer),
mail security of a domain (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, DNSSEC, optional STARTTLS)."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
import warnings
from typing import Any
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.xfr

from ..domains import registrable
from ..surface import RISKY_PORTS, SERVICES
from ..tools import RESOLVERS, ToolError, cert_info, check_ip, is_public, parse_host, parse_ports, resolve, tls_details
from . import net
from .common import Ctx, asn_cell, geo_of, ip_cell, is_global, loc_text, obj_for, relate_ip
from .detect import internal_name, norm_host, url_host
from .registry import ToolSpec
from .result import Result, cell

CRITICAL_PORTS = {23, 445, 2375, 3389, 5900, 6379, 9200, 11211, 27017, 5985, 10250}


def _target_host(target: str, kind: str) -> tuple[str, int | None]:
    """Host and optional port for host-based tools (URLs give their host and port)."""
    if kind == "url":
        p = urlsplit(target)
        try:
            return p.hostname or "", p.port
        except ValueError as exc:
            raise ToolError("err.tool.port", port="?") from exc
    return target, None


# --- ports -------------------------------------------------------------------------------------------------------------
async def ports(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> dict[str, Any]:
    host, _ = _target_host(target, kind)
    plist = parse_ports(params["ports"])
    d = await ctx.tk.portcheck(host, plist, ctx.lang)
    ip, geo = d["ip"], d.get("geo")
    res = Result("ports", ctx.lang, host, obj_for(host, ip))
    rows = []
    open_ports = []
    for x in d["results"]:
        svc = SERVICES.get(x["port"], "")
        sev = None
        if x["state"] == "open":
            open_ports.append(x["port"])
            sev = "high" if x["port"] in CRITICAL_PORTS else "medium" if x["port"] in RISKY_PORTS else "ok"
        rows.append([x["port"], svc, cell(x["label"] or x["state"], sev=sev), f"{x['ms']} ms" if x.get("ms") is not None else "–"])
        if x["state"] == "open" and x["port"] in RISKY_PORTS:
            res.find("high" if x["port"] in CRITICAL_PORTS else "medium", "tb.f.port_risky", port=x["port"], svc=svc or "?")
    res.kv(res.t("tb.sec.target"), [(res.t("tb.k.target"), host), (res.t("tb.k.ip"), ip_cell(ip)),
                                    (res.t("tb.k.location"), loc_text(ctx, geo)), (res.t("tb.k.as"), asn_cell(geo))])
    res.table(res.t("tb.sec.ports"), [res.t("tb.c.port"), res.t("tb.c.service"), res.t("tb.c.status"), res.t("tb.c.time")], rows,
              note=res.t("tb.n.ports"))
    res.point(geo, "target", host, ip)
    relate_ip(res, ip, geo)
    return res.done(spec, res.t("tb.s.ports", open=len(open_ports), n=len(plist)))


# --- TLS in depth --------------------------------------------------------------------------------------------------------
VERSIONS = (("TLSv1.0", "TLSv1"), ("TLSv1.1", "TLSv1_1"), ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3"))
CIPHER_CHECKS = (
    ("null", "eNULL:aNULL:@SECLEVEL=0", "high"),
    ("3des", "DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:@SECLEVEL=0", "high"),
    ("rc4", "RC4:@SECLEVEL=0", "high"),
    ("nofs", "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256", "medium"),
    ("cbc", "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:"
            "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:AES128-SHA:AES256-SHA:"
            "AES128-SHA256:AES256-SHA256", "low"),
)


async def _handshake(ip: str, port: int, sni: str | None, version: str | None = None, ciphers: str | None = None,
                     timeout: float = 6.0) -> dict[str, Any]:
    """One TLS handshake. Returns {"ok": True, "version", "cipher"} | {"ok": False} (refused by the server) |
    {"ok": None, "why": "local"|"net"} (not testable with the local OpenSSL / network error)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            if version:
                v = getattr(ssl.TLSVersion, version)
                ctx.minimum_version = v
                ctx.maximum_version = v
                if version in ("TLSv1", "TLSv1_1"):
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
            if ciphers:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # TLS 1.3 suites are not configurable this way
                ctx.set_ciphers(ciphers)
    except (ValueError, ssl.SSLError, AttributeError):
        return {"ok": None, "why": "local"}
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni), timeout=timeout)
    except ssl.SSLError as exc:
        if getattr(exc, "reason", "") in ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "NO_SUITABLE_SIGNATURE_ALGORITHM"):
            return {"ok": None, "why": "local"}
        return {"ok": False}
    except (ConnectionResetError, asyncio.IncompleteReadError, EOFError):
        return {"ok": False}
    except (asyncio.TimeoutError, OSError):
        return {"ok": None, "why": "net"}
    so = w.get_extra_info("ssl_object")
    out = {"ok": True, "version": so.version() if so else None, "cipher": (so.cipher() or [None])[0] if so else None}
    w.close()
    return out


async def tls(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> dict[str, Any]:
    host, uport = _target_host(target, kind)
    port = uport or params["port"]
    h, is_ip = parse_host(host)
    ip = (await resolve(h, ctx.s.tools_allow_private))[0]
    sni = None if is_ip else h
    res = Result("tls", ctx.lang, f"{h}:{port}", obj_for(h, ip))
    info = await tls_details(ip, port, sni, ctx.lang)
    if info.get("error"):
        raise ToolError("err.tb.tls_connect", detail=info["error"])
    vers = await asyncio.gather(*(_handshake(ip, port, sni, version=v) for _, v in VERSIONS))
    rows = []
    supported = []
    for (label, _), r in zip(VERSIONS, vers):
        if r["ok"] is True:
            supported.append(label)
            sev = "medium" if label in ("TLSv1.0", "TLSv1.1") else "ok"
            rows.append([label, cell(res.t("tb.v.supported"), sev=sev), r.get("cipher") or ""])
        elif r["ok"] is False:
            rows.append([label, res.t("tb.v.not_supported"), ""])
        else:
            rows.append([label, cell(res.t("tb.v.untestable_" + r["why"]), sev="info"), ""])
    checks = await asyncio.gather(*(_handshake(ip, port, sni, ciphers=c) for _, c, _ in CIPHER_CHECKS))
    crow = []
    for (cid, _, sev), r in zip(CIPHER_CHECKS, checks):
        if r["ok"] is True:
            crow.append([res.t(f"tb.cipher.{cid}"), cell(res.t("tb.v.accepted"), sev=sev), r.get("cipher") or ""])
            res.find(sev, f"tb.f.cipher_{cid}", cipher=r.get("cipher") or "?")
        elif r["ok"] is False:
            crow.append([res.t(f"tb.cipher.{cid}"), cell(res.t("tb.v.rejected"), sev="ok"), ""])
        else:
            crow.append([res.t(f"tb.cipher.{cid}"), cell(res.t("tb.v.untestable_" + r["why"]), sev="info"), ""])
    days = info.get("days_left")
    res.kv(res.t("tb.sec.certificate"), [
        (res.t("tb.k.validity"), cell(info.get("validation"), sev="ok" if info.get("valid") else "high" if info.get("valid") is False else "info")),
        (res.t("tb.k.subject"), info.get("subject")), (res.t("tb.k.issuer"), info.get("issuer")),
        ("SAN", ", ".join((info.get("san") or [])[:20]) + (" …" if len(info.get("san") or []) > 20 else "")),
        (res.t("tb.k.valid_until"), cell(f"{(info.get('not_after') or '')[:10]} ({days} d)" if days is not None else None,
                                          sev="high" if days is not None and days < 0 else "medium" if days is not None and days <= 14
                                          else "low" if days is not None and days <= 30 else None)),
        (res.t("tb.k.key"), info.get("key")), (res.t("tb.k.signature"), info.get("signature")),
        ("SHA-256", cell(info.get("sha256") or "", mono=True)),
        (res.t("tb.k.negotiated"), f"{info.get('version') or '–'} / {info.get('cipher') or '–'}")])
    res.table(res.t("tb.sec.versions"), [res.t("tb.c.version"), res.t("tb.c.status"), res.t("tb.c.cipher")], rows)
    res.table(res.t("tb.sec.ciphers"), [res.t("tb.c.check"), res.t("tb.c.status"), res.t("tb.c.cipher")], crow,
              note=res.t("tb.n.ciphers"))
    if info.get("valid") is False:
        res.find("high", "tb.f.cert_invalid", reason=info.get("validation") or "?")
    if days is not None:
        if days < 0:
            res.find("high", "tb.f.cert_expired", days=-days)
        elif days <= 14:
            res.find("medium", "tb.f.cert_expiring", days=days)
        elif days <= 30:
            res.find("low", "tb.f.cert_expiring", days=days)
    key = info.get("key") or ""
    m = re.match(r"RSA (\d+)", key)
    if m and int(m.group(1)) < 2048:
        res.find("high", "tb.f.weak_key", key=key)
    if (info.get("signature") or "").lower() in ("md5", "sha1"):
        res.find("high", "tb.f.weak_sig", sig=info["signature"])
    old = [v for v in supported if v in ("TLSv1.0", "TLSv1.1")]
    if old:
        res.find("medium", "tb.f.tls_old", versions=", ".join(old))
    if supported and "TLSv1.3" not in supported and vers[3]["ok"] is False:
        res.find("low", "tb.f.no_tls13")
    best = supported[-1] if supported else info.get("version")
    return res.done(spec, res.t("tb.s.tls", best=best or "?", days=days if days is not None else "?"))


# --- HTTP security headers -------------------------------------------------------------------------------------------------
SEC_HEADERS = ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options",
               "referrer-policy", "permissions-policy", "cross-origin-opener-policy")


async def _chain(ctx: Ctx, url: str, max_hops: int = 8) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    hops: list[dict[str, Any]] = []
    seen: set[str] = set()
    cur = url
    for _ in range(max_hops):
        if cur in seen:
            hops.append({"url": cur, "loop": True})
            return hops, None
        seen.add(cur)
        r = await net.fetch(cur, allow_private=ctx.s.tools_allow_private, max_bytes=64 * 1024)
        hops.append(r)
        if r.get("error"):
            return hops, None
        loc = net.header(r, "location")
        if r["status"] in (301, 302, 303, 307, 308) and loc:
            nxt = net.join_location(cur, loc)
            if not nxt or not nxt.startswith(("http://", "https://")):
                return hops, r
            cur = nxt
            continue
        return hops, r
    return hops, hops[-1] if hops and not hops[-1].get("error") else None


def _cookie_flags(v: str) -> dict[str, Any]:
    parts = [p.strip() for p in v.split(";")]
    name = parts[0].split("=", 1)[0][:60] if parts else "?"
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else True) for p in parts[1:] if p}
    return {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": str(attrs.get("samesite")) if attrs.get("samesite") not in (None, True) else None}


async def http(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> dict[str, Any]:
    if kind == "url":
        starts = [target]
        host = url_host(target) or target
    else:
        h, is_ip = parse_host(target)
        host = h
        hh = f"[{h}]" if ":" in h else h
        starts = [f"http://{hh}/", f"https://{hh}/"]
    res = Result("http", ctx.lang, starts[-1], obj_for(host, None))
    chains = []
    finals = []
    for s0 in starts:
        hops, final = await _chain(ctx, s0)
        chains.append((s0, hops))
        finals.append(final)
    rows = []
    for s0, hops in chains:
        for i, hp in enumerate(hops):
            if hp.get("loop"):
                rows.append([s0 if i == 0 else "", cell(hp["url"], mono=True), cell(res.t("tb.v.loop"), sev="medium"), "", ""])
                continue
            status = cell(hp.get("error"), sev="medium") if hp.get("error") else f"{hp['status']} {hp.get('reason') or ''}".strip()
            rows.append([res.t("tb.v.start") if i == 0 else "↳", cell(hp["url"], mono=True), status,
                         net.header(hp, "location") or "", f"{hp.get('ms', '–')} ms" if hp.get("ms") is not None else ""])
    res.table(res.t("tb.sec.redirects"), ["", "URL", res.t("tb.c.status"), "Location", res.t("tb.c.time")], rows)
    final = None
    for f in reversed(finals):
        if f is not None and str(f.get("url", "")).startswith("https://"):
            final = f
            break
    if final is None:
        final = next((f for f in finals if f is not None), None)
    if kind != "url":
        http_final = finals[0]
        if http_final is not None and not str(http_final.get("url", "")).startswith("https://") and finals[1] is not None:
            res.find("medium", "tb.f.no_https_redirect")
        if finals[1] is None:
            err = chains[1][1][-1].get("error") if chains[1][1] else None
            res.find("high" if finals[0] is not None else "medium", "tb.f.no_https", detail=err or "?")
    if final is None:
        res.find("medium", "tb.f.http_failed")
        return res.done(spec, res.t("tb.f.http_failed"))
    hdr = {k.lower(): v for k, v in final.get("headers") or []}
    https = str(final["url"]).startswith("https://")
    hrows = []

    def rate(name: str, sev: str, note_key: str, **p: Any) -> None:
        hrows.append([name, cell(hdr.get(name) or res.t("tb.v.missing"), sev=sev, mono=bool(hdr.get(name))), res.t(note_key, **p)])

    hsts = hdr.get("strict-transport-security")
    if https:
        if not hsts:
            rate("strict-transport-security", "medium", "tb.h.hsts_missing")
            res.find("medium", "tb.f.hsts_missing")
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:
                rate("strict-transport-security", "low", "tb.h.hsts_short", days=age // 86400)
                res.find("low", "tb.f.hsts_short", days=age // 86400)
            else:
                rate("strict-transport-security", "ok", "tb.h.hsts_ok", days=age // 86400)
    csp = hdr.get("content-security-policy")
    if not csp:
        rate("content-security-policy", "medium", "tb.h.csp_missing")
        res.find("medium", "tb.f.csp_missing")
    else:
        weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'") if re.search(r"(script-src|default-src)[^;]*" + re.escape(w), csp, re.I)]
        if weak:
            rate("content-security-policy", "low", "tb.h.csp_weak", w=", ".join(weak))
            res.find("low", "tb.f.csp_weak", w=", ".join(weak))
        else:
            rate("content-security-policy", "ok", "tb.h.ok")
    if (hdr.get("x-content-type-options") or "").lower().strip() != "nosniff":
        rate("x-content-type-options", "low", "tb.h.nosniff")
        res.find("low", "tb.f.nosniff")
    else:
        rate("x-content-type-options", "ok", "tb.h.ok")
    frame_ok = bool(hdr.get("x-frame-options")) or bool(csp and re.search(r"frame-ancestors", csp, re.I))
    rate("x-frame-options", "ok" if frame_ok else "low", "tb.h.ok" if frame_ok else "tb.h.frame")
    if not frame_ok:
        res.find("low", "tb.f.frame")
    rate("referrer-policy", "ok" if hdr.get("referrer-policy") else "info", "tb.h.ok" if hdr.get("referrer-policy") else "tb.h.referrer")
    rate("permissions-policy", "ok" if hdr.get("permissions-policy") else "info", "tb.h.ok" if hdr.get("permissions-policy") else "tb.h.permissions")
    rate("cross-origin-opener-policy", "ok" if hdr.get("cross-origin-opener-policy") else "info",
         "tb.h.ok" if hdr.get("cross-origin-opener-policy") else "tb.h.coop")
    res.table(res.t("tb.sec.headers"), ["Header", res.t("tb.c.value"), res.t("tb.c.rating")], hrows)
    crows = []
    for v in net.headers_all(final, "set-cookie")[:30]:
        c = _cookie_flags(v)
        problems = []
        if https and not c["secure"]:
            problems.append("Secure")
        if not c["httponly"]:
            problems.append("HttpOnly")
        if not c["samesite"]:
            problems.append("SameSite")
        crows.append([cell(c["name"], mono=True), "✓" if c["secure"] else "–", "✓" if c["httponly"] else "–", c["samesite"] or "–",
                      cell(", ".join(problems) or res.t("tb.v.ok"), sev="medium" if "Secure" in problems else "low" if problems else "ok")])
        if https and not c["secure"]:
            res.find("medium", "tb.f.cookie_secure", name=c["name"])
        elif problems:
            res.find("low", "tb.f.cookie_flags", name=c["name"], flags=", ".join(problems))
    res.table(res.t("tb.sec.cookies"), ["Cookie", "Secure", "HttpOnly", "SameSite", res.t("tb.c.rating")], crows)
    disc = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if hdr.get(name):
            versioned = bool(re.search(r"\d+\.\d+", hdr[name]))
            disc.append([name, cell(hdr[name], mono=True, sev="low" if versioned or name != "server" else "info")])
            if versioned or name != "server":
                res.find("low", "tb.f.disclosure", name=name, value=hdr[name][:80])
    res.table(res.t("tb.sec.disclosure"), ["Header", res.t("tb.c.value")], disc)
    aco, acc = hdr.get("access-control-allow-origin"), hdr.get("access-control-allow-credentials")
    if aco == "*" and (acc or "").lower() == "true":
        res.find("medium", "tb.f.cors")
    res.kv(res.t("tb.sec.final"), [("URL", cell(final["url"], mono=True)), (res.t("tb.k.status"), f"{final['status']} {final.get('reason') or ''}"),
                                   ("HTTP", final.get("http_version")), ("TLS", final.get("tls_version")),
                                   (res.t("tb.k.ip"), ip_cell(final.get("ip")))])
    res.table(res.t("tb.sec.all_headers"), ["Header", res.t("tb.c.value")],
              [[k, cell(v, mono=True)] for k, v in (final.get("headers") or [])[:80]])
    g = geo_of(ctx, final["ip"]) if is_global(final.get("ip")) else None
    relate_ip(res, final.get("ip"), g)
    return res.done(spec, res.t("tb.s.http", status=final["status"], n=len(res.findings)))


# --- SSH -----------------------------------------------------------------------------------------------------------------
SSH_WEAK = {
    "kex": {"diffie-hellman-group1-sha1": "high", "rsa1024-sha1": "high", "diffie-hellman-group14-sha1": "medium",
            "diffie-hellman-group-exchange-sha1": "medium"},
    "hostkey": {"ssh-dss": "high", "ssh-rsa": "low"},
    "cipher": {"3des-cbc": "high", "arcfour": "high", "arcfour128": "high", "arcfour256": "high", "blowfish-cbc": "high",
               "cast128-cbc": "high", "des-cbc": "high", "aes128-cbc": "low", "aes192-cbc": "low", "aes256-cbc": "low",
               "rijndael-cbc@lysator.liu.se": "low"},
    "mac": {"hmac-md5": "high", "hmac-md5-96": "high", "hmac-md5-etm@openssh.com": "high", "hmac-md5-96-etm@openssh.com": "high",
            "hmac-sha1": "low", "hmac-sha1-96": "low", "hmac-sha1-etm@openssh.com": "low", "hmac-sha1-96-etm@openssh.com": "low",
            "umac-64@openssh.com": "low", "umac-64-etm@openssh.com": "low", "hmac-ripemd160": "low",
            "hmac-ripemd160@openssh.com": "low"},
}
NAMELISTS = ("kex", "hostkey", "cipher_c2s", "cipher_s2c", "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c")


def parse_kexinit(payload: bytes) -> dict[str, list[str]]:
    """SSH_MSG_KEXINIT (RFC 4253, 7.1): byte 20, 16-byte cookie, 10 name-lists, boolean, uint32."""
    if not payload or payload[0] != 20:
        raise ValueError("not KEXINIT")
    pos = 17
    out: dict[str, list[str]] = {}
    for name in NAMELISTS:
        if pos + 4 > len(payload):
            raise ValueError("truncated")
        ln = int.from_bytes(payload[pos:pos + 4], "big")
        pos += 4
        if ln > 10000 or pos + ln > len(payload):
            raise ValueError("bad length")
        raw = payload[pos:pos + ln].decode("ascii", errors="replace")
        pos += ln
        out[name] = [x for x in raw.split(",") if x][:100]
    return out


async def ssh_kex(ip: str, port: int, timeout: float = 8.0) -> dict[str, Any]:
    r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    try:
        banner = ""
        for _ in range(20):  # the server may send other lines before its identification (RFC 4253, 4.2)
            line = await asyncio.wait_for(r.readline(), timeout=timeout)
            if not line:
                raise ValueError("closed")
            text = line[:255].decode("ascii", errors="replace").rstrip("\r\n")
            if text.startswith("SSH-"):
                banner = text
                break
        if not banner:
            raise ValueError("no banner")
        w.write(b"SSH-2.0-Emberwatch_check\r\n")
        await w.drain()
        hdr = await asyncio.wait_for(r.readexactly(5), timeout=timeout)
        plen = int.from_bytes(hdr[:4], "big")
        pad = hdr[4]
        if plen < 6 or plen > 35000 or pad >= plen:
            raise ValueError("bad packet")
        body = await asyncio.wait_for(r.readexactly(plen - 1), timeout=timeout)
        payload = body[: plen - 1 - pad]
        return {"banner": banner, "algos": parse_kexinit(payload)}
    finally:
        w.close()


def _openssh_version(banner: str) -> tuple[int, int, int] | None:
    m = re.search(r"OpenSSH_(\d+)\.(\d+)(?:p(\d+))?", banner)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


async def ssh(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> dict[str, Any]:
    host, _ = _target_host(target, kind)
    ip = (await resolve(host, ctx.s.tools_allow_private))[0]
    port = params["port"]
    res = Result("ssh", ctx.lang, f"{host}:{port}", obj_for(host, ip))
    try:
        d = await ssh_kex(ip, port)
    except (asyncio.TimeoutError, OSError, asyncio.IncompleteReadError) as exc:
        raise ToolError("err.tb.ssh_connect", detail=exc.__class__.__name__) from exc
    except ValueError as exc:
        raise ToolError("err.tb.ssh_proto", detail=str(exc)) from exc
    banner, al = d["banner"], d["algos"]
    proto = banner.split("-", 2)[1] if banner.count("-") >= 2 else "?"
    res.kv(res.t("tb.sec.server"), [(res.t("tb.k.target"), f"{host}:{port}"), (res.t("tb.k.ip"), ip_cell(ip)),
                                    ("Banner", cell(banner, mono=True)), (res.t("tb.k.protocol"), proto)])
    if proto in ("1.5", "1.99", "1.0"):
        res.find("high", "tb.f.ssh_v1", proto=proto)
    rows = []
    for cat, names in (("kex", al.get("kex", [])), ("hostkey", al.get("hostkey", [])),
                       ("cipher", list(dict.fromkeys(al.get("cipher_s2c", []) + al.get("cipher_c2s", [])))),
                       ("mac", list(dict.fromkeys(al.get("mac_s2c", []) + al.get("mac_c2s", []))))):
        for n in names:
            sev = SSH_WEAK[cat].get(n)
            rows.append([res.t(f"tb.ssh.{cat}"), cell(n, mono=True, sev=sev or "ok"), res.t(f"tb.ssh.why.{sev}") if sev else ""])
            if sev:
                res.find(sev, "tb.f.ssh_weak", cat=res.t(f"tb.ssh.{cat}"), name=n)
    res.table(res.t("tb.sec.algorithms"), [res.t("tb.c.category"), res.t("tb.c.algorithm"), res.t("tb.c.rating")], rows,
              note=res.t("tb.n.ssh"))
    if "none" in al.get("cipher_s2c", []) or "none" in al.get("mac_s2c", []):
        res.find("high", "tb.f.ssh_none")
    # Terrapin (CVE-2023-48795): ChaCha20-Poly1305 or an EtM MAC without strict key exchange
    vuln_mode = "chacha20-poly1305@openssh.com" in al.get("cipher_s2c", []) or any(m.endswith("-etm@openssh.com") for m in al.get("mac_s2c", []))
    strict = "kex-strict-s-v00@openssh.com" in al.get("kex", [])
    if vuln_mode and not strict:
        res.find("medium", "tb.f.terrapin", "tb.fd.terrapin")
    v = _openssh_version(banner)
    if v and (8, 5, 1) <= v < (9, 8, 1):
        res.find("medium", "tb.f.regresshion", "tb.fd.regresshion", ver=f"{v[0]}.{v[1]}p{v[2]}")
    if "zlib" in al.get("comp_s2c", []):
        res.find("info", "tb.f.ssh_zlib")
    g = geo_of(ctx, ip) if is_global(ip) else None
    relate_ip(res, ip, g)
    return res.done(spec, res.t("tb.s.ssh", banner=banner[:60]))


# --- DNS / DNSSEC / zone transfer -------------------------------------------------------------------------------------------
def _resolver(name: str) -> dns.asyncresolver.Resolver:
    res = dns.asyncresolver.Resolver(configure=RESOLVERS[name] is None)
    if RESOLVERS[name]:
        res.nameservers = RESOLVERS[name]
    res.lifetime = 5.0
    res.use_edns(0, dns.flags.DO, 1232)
    return res


def _axfr_sync(ip: str, zone: str) -> dict[str, Any]:
    count = 0
    sample: list[str] = []
    soa_seen = False
    try:
        for msg in dns.query.xfr(ip, zone, timeout=5, lifetime=15, relativize=False):
            for rrset in msg.answer:
                if rrset.rdtype == dns.rdatatype.SOA:
                    if soa_seen:  # the closing SOA ends the transfer and is not a record of its own
                        continue
                    soa_seen = True
                for rd in rrset:
                    count += 1
                    if len(sample) < 40:
                        sample.append(f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)} {rd.to_text()[:120]}")
            if count > 5000:
                break
    except dns.xfr.TransferError as exc:
        return {"ok": False, "why": dns.rcode.to_text(exc.rcode) if hasattr(exc, "rcode") else "refused"}
    except (dns.exception.DNSException, OSError, EOFError) as exc:
        return {"ok": False, "why": exc.__class__.__name__}
    return {"ok": count > 0, "count": count, "sample": sample, "why": None if count else "empty"}


DNS_PARTY = {"cloudflare": "Cloudflare DNS (1.1.1.1)", "google": "Google Public DNS (8.8.8.8)", "quad9": "Quad9 DNS (9.9.9.9)"}


async def dnsdeep(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> dict[str, Any]:
    party = DNS_PARTY.get(params["resolver"])
    if party:  # internal names and private addresses only go to the system resolver
        try:
            private = kind == "ip" and not is_public(ipaddress.ip_address(target))
        except ValueError:
            private = False
        if private or (kind == "domain" and internal_name(target)):
            raise ToolError("err.tb.third_private_dns", addr=target, party=party)
    d = await ctx.tk.dns_lookup(target, params["resolver"], ctx.lang)
    host = d["target"]
    res = Result("dns", ctx.lang, host, ("ip" if kind == "ip" else "domain", host))
    res.third_party = party or ""  # system resolver: your own infrastructure
    rows = []
    for rtype, recs in d["records"].items():
        for x in recs:
            v = x.get("error") or x.get("value")
            if rtype in ("A", "AAAA") and x.get("value"):
                v = ip_cell(x["value"])
            elif rtype in ("CNAME", "NS", "MX", "PTR") and x.get("value"):
                tgt = x["value"].split()[-1].rstrip(".")
                v = cell(x["value"], obj=("domain", tgt) if norm_host(tgt) else None, mono=True)
            elif x.get("error"):
                v = cell(x["error"], sev="info")
            else:
                v = cell(v, mono=True)
            rows.append([rtype, v, x.get("ttl", "")])
    if kind == "domain":
        r = _resolver(params["resolver"])
        for rtype in ("DS", "DNSKEY"):
            try:
                ans = await r.resolve(host, rtype)
                for rd in ans:
                    rows.append([rtype, cell(rd.to_text()[:200], mono=True), ans.rrset.ttl])
                d["records"][rtype] = [{"value": rd.to_text()} for rd in ans]
            except dns.exception.DNSException:
                continue
    res.table(res.t("tb.sec.records"), [res.t("tb.c.type"), res.t("tb.c.value"), "TTL"], rows)
    resolver_name = params["resolver"]
    res.kv(res.t("tb.sec.dnssec"), [(res.t("tb.k.resolver"), resolver_name),
                                    ("AD", None if d.get("ad_flag") is None else res.t("common.yes" if d["ad_flag"] else "common.no")),
                                    ("DS", res.t("common.yes") if d["records"].get("DS") else res.t("common.no"))])
    if kind == "domain":
        if resolver_name == "system":
            res.find("info", "tb.f.dnssec_system")
        elif d.get("ad_flag"):
            pass
        elif d["records"].get("DS"):
            res.find("medium", "tb.f.dnssec_unvalidated")
        else:
            res.find("low", "tb.f.dnssec_off", "tb.fd.dnssec_off")
        if not any("value" in x for x in d["records"].get("CAA", [])):
            res.find("low", "tb.f.no_caa", "tb.fd.no_caa")
        if not d["records"].get("MX"):
            res.find("info", "tb.f.no_mx")
    for g in d.get("geo") or []:
        res.point(g, "target", g["ip"], g["ip"])
        relate_ip(res, g["ip"], g)
    if params.get("axfr") and kind == "domain":
        res.level = "intrusive"
        res.target_sees = True
        ns = [x["value"].rstrip(".") for x in d["records"].get("NS", []) if x.get("value")][:4]
        arows = []
        for n in ns:
            try:
                ips = await resolve(n, ctx.s.tools_allow_private)
            except ToolError:
                arows.append([n, "–", cell(res.t("tb.v.ns_unresolvable"), sev="info")])
                continue
            for ip in ips[:2]:
                check_ip(ip, ctx.s.tools_allow_private)
                out = await asyncio.to_thread(_axfr_sync, ip, host)
                if out["ok"]:
                    arows.append([n, ip_cell(ip), cell(res.t("tb.v.axfr_open", n=out["count"]), sev="high")])
                    res.find("high", "tb.f.axfr_open", "tb.fd.axfr_open", ns=n, n=out["count"])
                    res.text(res.t("tb.sec.axfr_sample", ns=n), "\n".join(out["sample"]), mono=True)
                else:
                    arows.append([n, ip_cell(ip), cell(res.t("tb.v.axfr_refused", why=out["why"] or "?"), sev="ok")])
        res.table(res.t("tb.sec.axfr"), [res.t("tb.c.nameserver"), res.t("tb.k.ip"), res.t("tb.c.result")], arows)
    summary = res.t("tb.s.dns", n=len(rows), dnssec=res.t("common.yes") if d.get("ad_flag") else res.t("common.no"))
    return res.done(spec, summary)


# --- mail security of a domain -----------------------------------------------------------------------------------------------
DKIM_SELECTORS = ("default", "selector1", "selector2", "google", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp", "key1",
                  "mxvault", "zoho", "protonmail", "protonmail2", "fm1", "fm2", "sig1", "everlytickey1", "mandrill", "amazonses")


async def _txt(r: dns.asyncresolver.Resolver, name: str) -> tuple[list[str], bool]:
    """TXT strings of a name (joined per record) and the AD flag."""
    try:
        ans = await r.resolve(name, "TXT")
    except dns.exception.DNSException:
        return [], False
    out = []
    for rd in ans:
        out.append(b"".join(rd.strings).decode("utf-8", errors="replace"))
    return out, bool(ans.response.flags & dns.flags.AD) if ans.response is not None else False


async def spf_lookups(r: dns.asyncresolver.Resolver, record: str, depth: int = 0, seen: set[str] | None = None) -> int:
    """DNS lookups an SPF evaluation needs (RFC 7208, 4.6.4: include, a, mx, ptr, exists, redirect), recursive."""
    seen = seen if seen is not None else set()
    n = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        mech = re.split(r"[:=/]", t, maxsplit=1)[0]
        if mech in ("a", "mx", "ptr", "exists"):
            n += 1
        elif mech in ("include", "redirect"):
            n += 1
            dom = t.split(":", 1)[1] if mech == "include" and ":" in t else t.split("=", 1)[1] if "=" in t else ""
            if dom and dom not in seen and depth < 10 and "%" not in dom:
                seen.add(dom)
                txts, _ = await _txt(r, dom)
                sub = next((x for x in txts if x.lower().startswith("v=spf1")), None)
                if sub:
                    n += await spf_lookups(r, sub, depth + 1, seen)
        if n > 30:
            break
    return n


def _tags(rec: str) -> dict[str, str]:
    out = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def _mx_match(mx: str, pattern: str) -> bool:
    mx, pattern = mx.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return mx.endswith(pattern[1:]) and mx.count(".") == pattern.count(".")
    return mx == pattern


async def _starttls(ctx: Ctx, mx: str) -> dict[str, Any]:
    ip = (await resolve(mx, ctx.s.tools_allow_private))[0]
    out: dict[str, Any] = {"ip": ip}
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, 25), timeout=8)
    except (asyncio.TimeoutError, OSError) as exc:
        return {**out, "error": "connect", "detail": exc.__class__.__name__}

    async def reply() -> tuple[int, list[str]]:
        lines = []
        while True:
            ln = (await asyncio.wait_for(r.readline(), timeout=10)).decode("utf-8", errors="replace").rstrip("\r\n")
            if not ln:
                raise ConnectionError("closed")
            lines.append(ln[:300])
            if len(ln) < 4 or ln[3] != "-" or len(lines) > 60:
                return int(ln[:3]) if ln[:3].isdigit() else 0, lines
    try:
        code, lines = await reply()
        out["banner"] = lines[0][4:] if lines else ""
        w.write(b"EHLO emberwatch.invalid\r\n")
        await w.drain()
        code, lines = await reply()
        caps = [x[4:].upper() for x in lines]
        out["starttls"] = any(c.startswith("STARTTLS") for c in caps)
        if not out["starttls"]:
            w.write(b"QUIT\r\n")
            return out
        w.write(b"STARTTLS\r\n")
        await w.drain()
        code, lines = await reply()
        if code != 220:
            out["starttls_error"] = lines[-1] if lines else str(code)
            return out
        sctx = ssl.create_default_context()
        sctx.check_hostname = False
        sctx.verify_mode = ssl.CERT_NONE
        await asyncio.wait_for(w.start_tls(sctx, server_hostname=mx), timeout=10)
        so = w.get_extra_info("ssl_object")
        out["tls_version"] = so.version() if so else None
        der = so.getpeercert(binary_form=True) if so else None
        if der:
            out["cert"] = cert_info(der)
        try:
            w.write(b"QUIT\r\n")
            await w.drain()
        except (OSError, ConnectionError):
            pass
    except (asyncio.TimeoutError, OSError, ConnectionError, ValueError, ssl.SSLError) as exc:
        out.setdefault("error", "protocol")
        out["detail"] = exc.__class__.__name__
    finally:
        w.close()
    return out


async def mailsec(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> dict[str, Any]:
    dom = target.split("@", 1)[1] if kind == "email" else target
    dom = norm_host(dom) or dom
    res = Result("mailsec", ctx.lang, dom, ("domain", dom))
    r = _resolver("cloudflare")
    ad_any = False
    # MX
    mx: list[tuple[int, str]] = []
    try:
        ans = await r.resolve(dom, "MX")
        mx = sorted((rd.preference, rd.exchange.to_text().rstrip(".")) for rd in ans)
        ad_any = bool(ans.response.flags & dns.flags.AD) if ans.response is not None else False
    except dns.resolver.NXDOMAIN as exc:
        raise ToolError("err.tool.resolve", host=dom) from exc
    except dns.exception.DNSException:
        mx = []
    null_mx = len(mx) == 1 and mx[0][1] in ("", ".")
    res.table(res.t("tb.sec.mx"), [res.t("tb.c.pref"), res.t("tb.c.host")],
              [[p, cell(h or ".", obj=("domain", h) if h else None, mono=True)] for p, h in mx], empty=res.t("tb.v.no_mx"))
    if not mx:
        res.find("info", "tb.f.no_mx")
    elif null_mx:
        res.find("info", "tb.f.null_mx")
    # SPF
    txts, ad = await _txt(r, dom)
    ad_any = ad_any or ad
    spf = [x for x in txts if x.lower().startswith("v=spf1")]
    rows: list[list[Any]] = []
    if not spf:
        rows.append(["SPF", cell(res.t("tb.v.missing"), sev="medium"), res.t("tb.m.spf_missing")])
        res.find("medium", "tb.f.spf_missing", "tb.fd.spf_missing")
    elif len(spf) > 1:
        rows.append(["SPF", cell(" | ".join(spf)[:400], sev="high", mono=True), res.t("tb.m.spf_multi")])
        res.find("high", "tb.f.spf_multi")
    else:
        rec = spf[0]
        terms = rec.lower().split()
        all_q = next((tm[0] if tm[0] in "+-~?" else "+" for tm in terms if tm.lstrip("+-~?") == "all"), None)
        lookups = await spf_lookups(r, rec)
        sev, note = {"-": ("ok", "tb.m.spf_fail"), "~": ("low", "tb.m.spf_soft"), "?": ("medium", "tb.m.spf_neutral"),
                     "+": ("high", "tb.m.spf_pass_all")}.get(all_q or "", ("medium", "tb.m.spf_no_all"))
        if all_q is None and any(tm.startswith("redirect=") for tm in terms):
            sev, note = "info", "tb.m.spf_redirect"
        rows.append(["SPF", cell(rec[:400], sev=sev, mono=True), res.t(note) + " " + res.t("tb.m.spf_lookups", n=lookups)])
        if sev in ("low", "medium", "high"):
            res.find(sev, "tb.f.spf_" + {"~": "soft", "?": "neutral", "+": "all"}.get(all_q or "", "noall"))
        if lookups > 10:
            res.find("high", "tb.f.spf_lookups", n=lookups)
        if any(tm.lstrip("+-~?").startswith("ptr") for tm in terms):
            res.find("low", "tb.f.spf_ptr")
    # DMARC (falls back to the organisational domain)
    dm, _ = await _txt(r, f"_dmarc.{dom}")
    dmarc = [x for x in dm if x.lower().startswith("v=dmarc1")]
    org = ".".join(x for x in registrable(dom) if x)
    via_org = False
    if not dmarc and org and org != dom:
        dm2, _ = await _txt(r, f"_dmarc.{org}")
        dmarc = [x for x in dm2 if x.lower().startswith("v=dmarc1")]
        via_org = bool(dmarc)
    if not dmarc:
        rows.append(["DMARC", cell(res.t("tb.v.missing"), sev="medium"), res.t("tb.m.dmarc_missing")])
        res.find("medium", "tb.f.dmarc_missing", "tb.fd.dmarc_missing")
    else:
        tg = _tags(dmarc[0])
        pol = (tg.get("sp") if via_org and tg.get("sp") else tg.get("p") or "").lower()
        sev = {"reject": "ok", "quarantine": "ok", "none": "medium"}.get(pol, "medium")
        note = res.t(f"tb.m.dmarc_{pol}" if pol in ("reject", "quarantine", "none") else "tb.m.dmarc_bad")
        if via_org:
            note += " " + res.t("tb.m.dmarc_org", org=org)
        rows.append(["DMARC", cell(dmarc[0][:400], sev=sev, mono=True), note])
        if pol == "none":
            res.find("medium", "tb.f.dmarc_none", "tb.fd.dmarc_none")
        elif pol not in ("reject", "quarantine"):
            res.find("medium", "tb.f.dmarc_bad")
        try:
            pct = int(tg.get("pct", "100"))
        except ValueError:
            pct = 100
        if pct < 100:
            res.find("low", "tb.f.dmarc_pct", pct=pct)
        if not tg.get("rua"):
            res.find("info", "tb.f.dmarc_rua")
    # DKIM (common selectors)
    found = []
    sem = asyncio.Semaphore(8)

    async def sel(s: str) -> None:
        async with sem:
            txt, _ = await _txt(r, f"{s}._domainkey.{dom}")
        rec = next((x for x in txt if "p=" in x.replace(" ", "")), None)
        if rec:
            found.append((s, rec))
    await asyncio.gather(*(sel(s) for s in DKIM_SELECTORS))
    if found:
        for s, rec in sorted(found):
            revoked = re.search(r"(^|;)\s*p=\s*(;|$)", rec) is not None
            rows.append([f"DKIM ({s})", cell(rec[:160] + ("…" if len(rec) > 160 else ""), mono=True, sev="info" if revoked else "ok"),
                         res.t("tb.m.dkim_revoked") if revoked else res.t("tb.m.dkim_found")])
    else:
        rows.append(["DKIM", cell(res.t("tb.v.not_found"), sev="info"), res.t("tb.m.dkim_none")])
        if mx and not null_mx:
            res.find("info", "tb.f.dkim_none")
    # MTA-STS and TLS-RPT
    sts, _ = await _txt(r, f"_mta-sts.{dom}")
    sts = [x for x in sts if x.lower().startswith("v=stsv1")]
    if sts:
        pol = await net.fetch(f"https://mta-sts.{dom}/.well-known/mta-sts.txt", allow_private=ctx.s.tools_allow_private,
                              verify=True, max_bytes=64 * 1024)
        if pol.get("error") or pol.get("status") != 200:
            rows.append(["MTA-STS", cell(sts[0], sev="medium", mono=True), res.t("tb.m.sts_policy_failed", detail=pol.get("error") or pol.get("status"))])
            res.find("medium", "tb.f.sts_policy_failed")
        else:
            body = pol["body"].decode("utf-8", errors="replace")
            kv = {}
            mxs = []
            for ln in body.splitlines():
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    if k.strip().lower() == "mx":
                        mxs.append(v.strip())
                    else:
                        kv[k.strip().lower()] = v.strip()
            mode = kv.get("mode", "?").lower()
            unmatched = [h for _, h in mx if h and not any(_mx_match(h, p) for p in mxs)]
            sev = "ok" if mode == "enforce" and not unmatched else "medium" if unmatched else "info"
            rows.append(["MTA-STS", cell(f"mode={mode}; mx={', '.join(mxs)}; max_age={kv.get('max_age', '?')}", sev=sev, mono=True),
                         res.t("tb.m.sts_" + ("unmatched" if unmatched else mode if mode in ("enforce", "testing", "none") else "bad"),
                               hosts=", ".join(unmatched))])
            if unmatched:
                res.find("medium", "tb.f.sts_unmatched", hosts=", ".join(unmatched))
            elif mode == "testing":
                res.find("info", "tb.f.sts_testing")
    else:
        rows.append(["MTA-STS", cell(res.t("tb.v.missing"), sev="info"), res.t("tb.m.sts_missing")])
        if mx and not null_mx:
            res.find("info", "tb.f.sts_missing")
    rpt, _ = await _txt(r, f"_smtp._tls.{dom}")
    rpt = [x for x in rpt if x.lower().startswith("v=tlsrptv1")]
    rows.append(["TLS-RPT", cell(rpt[0] if rpt else res.t("tb.v.missing"), sev="ok" if rpt else "info", mono=bool(rpt)),
                 res.t("tb.m.rpt_ok" if rpt else "tb.m.rpt_missing")])
    rows.append(["DNSSEC", cell(res.t("tb.v.validated") if ad_any else res.t("tb.v.not_validated"), sev="ok" if ad_any else "low"),
                 res.t("tb.m.dnssec_ok" if ad_any else "tb.m.dnssec_off")])
    if not ad_any:
        res.find("low", "tb.f.dnssec_off", "tb.fd.dnssec_off")
    res.table(res.t("tb.sec.mailsec"), [res.t("tb.c.check"), res.t("tb.c.value"), res.t("tb.c.rating")], rows)
    if params.get("starttls") and mx and not null_mx:
        st = await _starttls(ctx, mx[0][1])
        if st.get("error") == "connect":
            res.kv(res.t("tb.sec.starttls"), [(res.t("tb.k.host"), mx[0][1]), (res.t("tb.k.status"), cell(res.t("tb.v.port25_closed"), sev="info"))])
            res.find("info", "tb.f.port25", "tb.fd.port25", host=mx[0][1])
        else:
            cert = st.get("cert") or {}
            res.kv(res.t("tb.sec.starttls"), [
                (res.t("tb.k.host"), mx[0][1]), (res.t("tb.k.ip"), ip_cell(st.get("ip"))), ("Banner", cell(st.get("banner") or "", mono=True)),
                ("STARTTLS", cell(res.t("common.yes") if st.get("starttls") else res.t("common.no"), sev="ok" if st.get("starttls") else "high")),
                ("TLS", st.get("tls_version")), (res.t("tb.k.subject"), cert.get("subject")),
                (res.t("tb.k.valid_until"), f"{(cert.get('not_after') or '')[:10]} ({cert.get('days_left')} d)" if cert else None),
                (res.t("tb.k.error"), st.get("starttls_error") or st.get("detail"))])
            if st.get("starttls") is False:
                res.find("high", "tb.f.no_starttls", host=mx[0][1])
            if st.get("tls_version") in ("TLSv1", "TLSv1.1"):
                res.find("medium", "tb.f.tls_old", versions=st["tls_version"])
            if cert and isinstance(cert.get("days_left"), int) and cert["days_left"] < 0:
                res.find("medium", "tb.f.cert_expired", days=-cert["days_left"])
    return res.done(spec, res.t("tb.s.mailsec", n=len([f for f in res.findings if f["sev"] in ("medium", "high")])))

