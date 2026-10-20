"""Recognises what a user entered: IP, network, AS number, domain, URL, e-mail address, hash, CVE or mail headers.

Defanged indicators (hxxp://, example[.]com, 1.2.3[.]4) are refanged first. The result is the single source of truth
for the web interface (type badge, applicable tools) and for the server (tool input validation).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9_-]{1,63}(?<!-)\.)*[a-z0-9-]{1,63}(?<!-)$")
HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
ASN_RE = re.compile(r"^AS(?:N)?\s?(\d{1,10})$", re.I)
EMAIL_RE = re.compile(r"^([^@\s<>\"]{1,64})@([^@\s<>\"]{1,253})$")
SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]{1,15}://", re.I)
HEADER_LINE_RE = re.compile(
    r"^(received|from|to|cc|subject|date|message-id|return-path|reply-to|authentication-results|arc-[\w-]+|"
    r"dkim-signature|received-spf|mime-version|content-type|x-[\w-]+)\s*:", re.I | re.M)
HASH_KIND = {32: "md5", 40: "sha1", 64: "sha256"}
TYPES = ("ip", "cidr", "asn", "domain", "url", "email", "hash", "cve", "mailhdr", "text")
MAX_LINE = 2048


def refang(s: str) -> tuple[str, bool]:
    out = s
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."), ("[:]", ":"),
                 ("[@]", "@"), ("[at]", "@"), ("[://]", "://")):
        out = out.replace(a, b)
    out = re.sub(r"^hxxp(s?)://", r"http\1://", out, flags=re.I)
    out = re.sub(r"^fxp://", "ftp://", out, flags=re.I)
    return out, out != s


def norm_host(raw: str) -> str | None:
    """Lower-case IDNA hostname without trailing dot, or None if it is not a valid hostname."""
    s = (raw or "").strip().rstrip(".")
    if not s or len(s) > 253 or any(c.isspace() for c in s) or s.startswith("-"):
        return None
    try:
        host = s.lower().encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return host if HOST_RE.match(host) else None


def is_domain(host: str | None) -> bool:
    """A hostname with at least one dot and a plausible top-level label (letters or an IDNA label)."""
    if not host or "." not in host:
        return False
    tld = host.rsplit(".", 1)[1]
    return (tld.isalpha() and len(tld) >= 2) or (tld.startswith("xn--") and len(tld) > 4)


def norm_url(raw: str) -> str | None:
    try:
        p = urlsplit(raw)
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        return None
    try:
        port = p.port
    except ValueError:
        return None
    host = p.hostname
    try:
        host = str(ipaddress.ip_address(host))
        netloc_host = f"[{host}]" if ":" in host else host
    except ValueError:
        h = norm_host(host)
        if not h:
            return None
        netloc_host = h
    netloc = netloc_host if port is None else f"{netloc_host}:{port}"
    path = p.path or "/"
    if any(c in path + p.query for c in "\r\n\t "):
        return None
    return urlunsplit((p.scheme.lower(), netloc, path, p.query, ""))


def url_host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def detect(q: str | None) -> dict[str, Any]:
    raw = (q or "").strip()
    if not raw:
        return {"type": "empty", "value": ""}
    if "\n" in raw:
        if len(HEADER_LINE_RE.findall(raw[:200_000])) >= 2:
            return {"type": "mailhdr", "value": "", "display": f"{len(raw.splitlines())} lines", "length": len(raw)}
        return {"type": "text", "value": raw[:MAX_LINE], "display": raw.splitlines()[0][:80]}
    if len(raw) > MAX_LINE:
        return {"type": "text", "value": raw[:MAX_LINE], "display": raw[:80]}
    s, refanged = refang(raw)
    base: dict[str, Any] = {"refanged": refanged}
    # IP address (also [v6] and IPv6 zone-less)
    try:
        ip = ipaddress.ip_address(s.strip("[]"))
        return {**base, "type": "ip", "value": str(ip), "display": str(ip), "sub": f"v{ip.version}"}
    except ValueError:
        pass
    if "/" in s and "://" not in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
            return {**base, "type": "cidr", "value": str(net), "display": str(net), "sub": f"v{net.version}"}
        except ValueError:
            pass
    m = ASN_RE.match(s)
    if m and 0 < int(m.group(1)) < 4_294_967_296:
        return {**base, "type": "asn", "value": str(int(m.group(1))), "display": f"AS{int(m.group(1))}"}
    if CVE_RE.match(s.upper()):
        return {**base, "type": "cve", "value": s.upper(), "display": s.upper()}
    if HASH_RE.match(s.lower()):
        return {**base, "type": "hash", "value": s.lower(), "display": s.lower(), "sub": HASH_KIND[len(s)]}
    if SCHEME_RE.match(s):
        u = norm_url(s)
        if u:
            return {**base, "type": "url", "value": u, "display": u, "host": url_host(u)}
        return {**base, "type": "text", "value": s, "display": s[:80]}
    m = EMAIL_RE.match(s)
    if m:
        dom = norm_host(m.group(2))
        if dom and is_domain(dom):
            addr = f"{m.group(1)}@{dom}"
            return {**base, "type": "email", "value": addr.lower(), "display": addr, "domain": dom}
    host = norm_host(s)
    if host and is_domain(host):
        return {**base, "type": "domain", "value": host, "display": host}
    return {**base, "type": "text", "value": s, "display": s[:80]}
