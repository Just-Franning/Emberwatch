"""Size-limited GET for the 3.3 collectors (GDELT, OONI, EUVD, URLhaus).

The configured URL is a fixed https constant; a redirect is followed only to https and to a host that resolves to
public addresses (the same rule as for news feeds), at most three times. The body is read while it streams and the
download stops as soon as it exceeds the limit, so an oversized answer is never loaded whole.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from ..i18n import AppError
from ..tools import resolve

MAX_HOPS = 3


class FetchError(ValueError):
    pass


async def get_capped(client: httpx.AsyncClient, url: str, *, max_bytes: int, headers: dict[str, str] | None = None,
                     params: dict[str, Any] | None = None, timeout: float = 60.0) -> tuple[int, httpx.Headers, bytes]:
    """(status, headers, body). The body is only read for status 200; other statuses come back with an empty body."""
    for hop in range(MAX_HOPS + 1):
        if hop:
            if not url.startswith("https://"):
                raise FetchError("redirect to http")
            try:
                await resolve(urlsplit(url).hostname or "", False)
            except AppError as exc:
                raise FetchError("redirect to a non-public address") from exc
        req = client.build_request("GET", url, params=params if not hop else None, headers=headers, timeout=timeout)
        r = await client.send(req, stream=True, follow_redirects=False)
        try:
            if r.status_code in (301, 302, 303, 307, 308):
                nxt = r.headers.get("location") or ""
                if not nxt:
                    raise FetchError("redirect without a target")
                url = str(req.url.join(nxt))
                continue
            if r.status_code != 200:
                return r.status_code, r.headers, b""
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise FetchError("answer too large")
            return r.status_code, r.headers, bytes(buf)
        finally:
            await r.aclose()
    raise FetchError("too many redirects")
