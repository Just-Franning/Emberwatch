"""Requests to websites of third parties: company imprints ("who owns this IP"), profile pages and site checks of the
people search, previews of public Telegram channels.

The targets come from foreign data (names in certificates and DNS, links in profiles, downloaded site lists), so two
protections keep these requests out of the own network (SSRF):
1. The connection layer resolves the name itself, refuses the connection unless every address is public, and then
   connects to the checked address - there is no second DNS lookup between check and connect (no DNS rebinding).
2. Redirects are followed by hand, at most MAX_HOPS, only to http/https; every hop passes check 1 again.
Bodies are read while they stream and cut (or refused) at a size limit.

With an HTTP proxy in the environment (HTTPS_PROXY, ...) the proxy opens the connections; then each hop's name is
resolved and checked before the request instead (check 1 without the pinning).
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx

from .tools import is_public

MAX_HOPS = 3
BLOCKED = "blocked: the name resolves to a non-public address"
PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
_CHARSET_RE = re.compile(rb"""<meta[^>]{0,200}charset\s*=\s*["']?\s*([A-Za-z0-9_.:-]{2,40})""", re.I)


def _public(addr: str) -> bool:
    try:
        return is_public(ipaddress.ip_address(addr.split("%", 1)[0]))
    except ValueError:
        return False


def proxied() -> bool:
    return any(os.environ.get(k) for k in PROXY_VARS)


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """TCP connections only to public addresses, and exactly to the address that was checked."""

    def __init__(self) -> None:
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None,
                          socket_options: Any = None) -> httpcore.AsyncNetworkStream:
        try:
            infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                                           timeout or 10.0)
        except (OSError, UnicodeError, asyncio.TimeoutError) as exc:
            raise httpcore.ConnectError(f"cannot resolve {host}") from exc
        addrs = list(dict.fromkeys(str(i[4][0]) for i in infos))
        if not addrs or not all(_public(a) for a in addrs):
            raise httpcore.ConnectError(BLOCKED)
        err: Exception | None = None
        for addr in addrs[:4]:
            try:
                return await self._inner.connect_tcp(addr, port, timeout=timeout, local_address=local_address,
                                                     socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                err = exc
        raise err or httpcore.ConnectError(f"cannot connect to {host}")

    async def connect_unix_socket(self, path: str, timeout: float | None = None, socket_options: Any = None) -> Any:
        raise httpcore.ConnectError("unix sockets are not used")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    def __init__(self) -> None:
        super().__init__(trust_env=False)
        # httpx has no parameter for the network backend: the connection pool is replaced by one that uses it
        # (httpx is pinned; test_v4_owner.py checks that the guard is active)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False), max_connections=60, max_keepalive_connections=20,
            keepalive_expiry=5.0, http1=True, http2=False, network_backend=GuardedBackend())


def make_client(user_agent: str) -> httpx.AsyncClient:
    headers = {"User-Agent": user_agent, "Accept-Language": "de,en;q=0.8"}
    if proxied():
        return httpx.AsyncClient(headers=headers, follow_redirects=False, trust_env=True)
    return httpx.AsyncClient(headers=headers, follow_redirects=False, transport=GuardedTransport())


class FetchError(Exception):
    """code: blocked | network | timeout | redirect | scheme | too_large"""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass
class Page:
    status: int
    url: str  # final URL after redirects
    first_status: int  # status of the first answer (a redirect, if one was followed)
    headers: httpx.Headers
    body: bytes
    truncated: bool = False
    hops: list[str] = field(default_factory=list)

    @property
    def ctype(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def html(self) -> bool:
        return self.ctype in ("text/html", "application/xhtml+xml", "")

    def text(self) -> str:
        """Body as text: charset of the header, else of a <meta> tag, else UTF-8 (invalid bytes replaced)."""
        cs = None
        m = re.search(r"charset\s*=\s*\"?([A-Za-z0-9_.:-]{2,40})", self.headers.get("content-type", ""), re.I)
        if m:
            cs = m.group(1)
        else:
            mm = _CHARSET_RE.search(self.body[:4096])
            cs = mm.group(1).decode("ascii", "ignore") if mm else None
        try:
            return self.body.decode(cs or "utf-8", errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


async def check_host(host: str) -> None:
    """Name check before a request when a proxy opens the connections (see module doc)."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise FetchError("network", f"cannot resolve {host}") from exc
    addrs = {str(i[4][0]) for i in infos}
    if not addrs or not all(_public(a) for a in addrs):
        raise FetchError("blocked", host)


async def fetch(client: httpx.AsyncClient, url: str, *, method: str = "GET", headers: dict[str, str] | None = None,
                content: bytes | None = None, max_bytes: int = 1_000_000, follow: bool = True, max_hops: int = MAX_HOPS,
                timeout: float = 10.0, cut: bool = True) -> Page:
    """One request with manual redirects. follow=False returns the first answer (a redirect included).
    cut=True cuts a body beyond max_bytes (parsers need the beginning), cut=False refuses it (FetchError too_large)."""
    first = 0
    hops: list[str] = []
    for _hop in range(max_hops + 1):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise FetchError("scheme", parts.scheme)
        if proxied():
            await check_host(parts.hostname)
        try:
            req = client.build_request(method, url, headers=headers, content=content, timeout=timeout)
            r = await client.send(req, stream=True)
        except httpx.TimeoutException as exc:
            raise FetchError("timeout", exc.__class__.__name__) from exc
        except httpx.ConnectError as exc:
            raise FetchError("blocked" if BLOCKED in str(exc) else "network", str(exc)[:120]) from exc
        except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
            raise FetchError("network", exc.__class__.__name__) from exc
        try:
            if follow and r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                first = first or r.status_code
                try:
                    url = str(req.url.join(r.headers["location"]))
                except (httpx.InvalidURL, ValueError) as exc:
                    raise FetchError("redirect", "bad location") from exc
                hops.append(url)
                if r.status_code in (301, 302, 303) and method == "POST":
                    method, content = "GET", None
                continue
            buf = bytearray()
            truncated = False
            if method != "HEAD":
                try:
                    async for chunk in r.aiter_bytes():
                        buf.extend(chunk)
                        if len(buf) > max_bytes:
                            if not cut:
                                raise FetchError("too_large", str(max_bytes))
                            truncated = True
                            del buf[max_bytes:]
                            break
                except httpx.TimeoutException as exc:
                    raise FetchError("timeout", "body") from exc
                except httpx.HTTPError as exc:
                    raise FetchError("network", exc.__class__.__name__) from exc
            return Page(r.status_code, str(r.url), first or r.status_code, r.headers, bytes(buf), truncated, hops)
        finally:
            await r.aclose()
    raise FetchError("redirect", "too many redirects")
