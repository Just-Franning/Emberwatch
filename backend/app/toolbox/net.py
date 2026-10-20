"""Network helpers for tools that talk to a target: HTTP(S) requests pinned to the resolved IP address.

The hostname is resolved once (every address must pass the SSRF check), the connection goes to exactly that IP, and the
certificate is validated against the hostname via SNI. Redirects are never followed automatically; callers follow them
hop by hop so every new host is checked again. Responses are read up to a size limit.
"""
from __future__ import annotations

import ssl
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .. import __version__
from ..tools import ToolError, parse_host, resolve

UA = f"Mozilla/5.0 (compatible; Emberwatch/{__version__}; security check)"


async def fetch(url: str, *, allow_private: bool, method: str = "GET", max_bytes: int = 256 * 1024,
                verify: bool = False, timeout: float = 10.0, headers: dict[str, str] | None = None) -> dict[str, Any]:
    """One HTTP request without redirects. Returns status, headers (list of pairs), body (bytes, truncated), ip, ms.
    Raises ToolError for invalid targets; network errors are returned as {"error": ...}."""
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ToolError("err.tool.scheme")
    host, is_ip = parse_host(p.hostname)
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError as exc:
        raise ToolError("err.tool.port", port="?") from exc
    path = p.path or "/"
    if any(c in path + p.query for c in "\r\n\t ") or len(path) + len(p.query) > 2000:
        raise ToolError("err.tool.path")
    ip = (await resolve(host, allow_private))[0]
    ip_host = f"[{ip}]" if ":" in ip else ip
    pinned = urlunsplit((p.scheme, f"{ip_host}:{port}", path, p.query, ""))
    host_hdr = host if is_ip is False else (f"[{host}]" if ":" in host else host)
    if port not in (80, 443):
        host_hdr = f"{host_hdr}:{port}"
    hdrs = {"Host": host_hdr, "User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"}
    hdrs.update(headers or {})
    if verify:
        ctx: ssl.SSLContext | bool = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ext: dict[str, Any] = {"sni_hostname": host} if p.scheme == "https" and not is_ip else {}
    t0 = time.perf_counter()
    out: dict[str, Any] = {"url": urlunsplit((p.scheme, p.netloc, path, p.query, "")), "ip": ip, "host": host}
    try:
        async with httpx.AsyncClient(verify=ctx, trust_env=False, follow_redirects=False, timeout=timeout) as c:
            req = c.build_request(method, pinned, headers=hdrs, extensions=ext)
            r = await c.send(req, stream=True)
            try:
                body = b""
                truncated = False
                if method != "HEAD":
                    async for chunk in r.aiter_raw():
                        body += chunk
                        if len(body) >= max_bytes:
                            body = body[:max_bytes]
                            truncated = True
                            break
                so = r.extensions.get("network_stream")
                sslobj = so.get_extra_info("ssl_object") if so is not None else None
                out.update({
                    "status": r.status_code, "reason": r.reason_phrase, "http_version": r.http_version,
                    "headers": [[k.decode("latin-1")[:100], v.decode("latin-1")[:2000]] for k, v in r.headers.raw[:120]],
                    "body": body, "truncated": truncated, "ms": round((time.perf_counter() - t0) * 1000, 1),
                    "tls_version": sslobj.version() if sslobj is not None else None,
                })
            finally:
                await r.aclose()
    except ssl.SSLCertVerificationError as exc:
        out["error"] = f"TLS: {exc.verify_message or exc}"[:300]
        out["cert_error"] = True
    except httpx.ConnectError as exc:
        cause = exc.__cause__ or exc.__context__
        if isinstance(cause, ssl.SSLCertVerificationError):
            out["error"] = f"TLS: {cause.verify_message or cause}"[:300]
            out["cert_error"] = True
        else:
            out["error"] = f"{exc.__class__.__name__}: {exc}"[:300]
    except (httpx.HTTPError, OSError) as exc:
        out["error"] = f"{exc.__class__.__name__}: {exc}"[:300]
    return out


def header(resp: dict[str, Any], name: str) -> str | None:
    """First value of a response header (case-insensitive)."""
    n = name.lower()
    for k, v in resp.get("headers") or []:
        if k.lower() == n:
            return v
    return None


def headers_all(resp: dict[str, Any], name: str) -> list[str]:
    n = name.lower()
    return [v for k, v in resp.get("headers") or [] if k.lower() == n]


def join_location(base: str, location: str) -> str | None:
    try:
        return str(httpx.URL(base).join(location))
    except (httpx.InvalidURL, ValueError):
        return None


def tool_error(exc: Exception) -> ToolError:
    return exc if isinstance(exc, ToolError) else ToolError("err.tool.upstream", detail=exc.__class__.__name__)
