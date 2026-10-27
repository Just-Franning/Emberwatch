"""Checks one user name on every site of the lists.

Decision per site (no code of Sherlock or WhatsMyName is run; their published rules are applied):
- WhatsMyName: the answer to uri_check without following redirects. Found: status e_code and e_string in the body.
  Not found: status m_code and m_string in the body (or no m_string). Anything else stays "unsure".
- Sherlock: "message" (an error text in the page means not found), "status_code" (2xx means found unless the status
  is one of errorCode), "response_url" (without redirects: 2xx means found). Stricter than Sherlock: a page without
  the error text but without a 2xx status is "unsure", not "found".
- Pages of bot protection (Cloudflare, AWS WAF, PerimeterX: fingerprints of Sherlock) and 403/429/503 are "unsure".

Requests: through webfetch (public addresses only, redirects checked), at most CONCURRENCY at once and one at a time
per host, TIMEOUT each, bodies cut at MAX_BODY, the whole search within BUDGET_S.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Awaitable, Callable
from urllib.parse import quote, urlsplit

import httpx

from .. import webfetch
from .sites import Site

CONCURRENCY = 24
TIMEOUT = 10.0
MAX_BODY = 1_000_000
KEEP_BODY = 400_000  # beginning of a found profile page, kept for reading the profile
BUDGET_S = 240.0
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
PROTECTED = (403, 429, 503)
WAF_MARKS = (
    ".loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}",  # Cloudflare (Sherlock 2024-05)
    '<span id="challenge-error-text">',  # Cloudflare error page (Sherlock 2024-11)
    "AwsWafIntegration.forceRefreshToken",  # AWS WAF (Sherlock 2024-11)
    '{return l.onPageView}}),Object.defineProperty(r,"perimeterxIdentifiers",{enumerable:',  # PerimeterX (Sherlock 2024-04)
    "/cdn-cgi/challenge-platform/",  # Cloudflare challenge script
    "<title>Just a moment...</title>",
)


@dataclass
class Check:
    site: Site
    status: str  # found | unsure | missing | error | skipped
    http: int | None
    url: str  # profile URL
    reason: str = ""  # waf | protected | unclear | regex | timeout | blocked | network | budget | ...
    body: bytes = b""
    ctype: str = ""


def fill(template: str, name: str) -> str:
    return template.replace("{u}", quote(name, safe=""))


def headers_for(site: Site) -> dict[str, str]:
    h = {"User-Agent": webfetch.BROWSER_UA,
         "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"}
    h.update(dict(site.headers))
    return h


def decide(site: Site, status: int, text: str) -> tuple[str, str]:
    """(status, reason) from an answer."""
    if any(m in text for m in WAF_MARKS):
        return "unsure", "waf"
    if site.source == "wmn":
        if status == site.e_code and (not site.e_string or site.e_string in text):
            return "found", ""
        if status == site.m_code and (not site.m_string or site.m_string in text):
            return "missing", ""
        return "unsure", "protected" if status in PROTECTED else "unclear"
    ok = 200 <= status < 300
    if site.error_type == "message":
        if any(m in text for m in site.error_msgs):
            return "missing", ""
        return ("found", "") if ok else ("unsure", "protected" if status in PROTECTED else "unclear")
    if status in PROTECTED and status not in site.error_codes:
        return "unsure", "protected"
    if site.error_type == "status_code":
        return ("missing", "") if status in site.error_codes or not ok else ("found", "")
    return ("found", "") if ok else ("missing", "")  # response_url


async def check(web: httpx.AsyncClient, site: Site, name: str) -> Check:
    n = "".join(c for c in name if c not in site.strip) if site.strip else name
    url = fill(site.url, n)
    if site.regex:
        try:
            if re.search(site.regex, n) is None:
                return Check(site, "skipped", None, url, "regex")
        except re.error:
            pass
    probe = fill(site.probe, n)
    content = site.body.replace("{u}", n).encode("utf-8") if site.body is not None else None
    headers = headers_for(site)
    if content is not None and site.json_body:
        headers.setdefault("Content-Type", "application/json")
    # WhatsMyName and Sherlock's response_url judge the first answer; the other Sherlock rules follow redirects
    follow = site.source == "sherlock" and site.error_type != "response_url"
    method = site.method
    try:
        page = await webfetch.fetch(web, probe, method=method, headers=headers, content=content, max_bytes=MAX_BODY,
                                    follow=follow, timeout=TIMEOUT)
        if method == "HEAD" and page.status in (405, 501):  # HEAD not supported: once more with GET
            page = await webfetch.fetch(web, probe, method="GET", headers=headers, max_bytes=MAX_BODY, follow=follow, timeout=TIMEOUT)
    except webfetch.FetchError as exc:
        return Check(site, "error", None, url, exc.code)
    text = page.text() if page.body else ""
    status, reason = decide(site, page.status, text)
    keep = page.body[:KEEP_BODY] if status == "found" and probe == url else b""
    return Check(site, status, page.status, url, reason, keep, page.ctype)


async def run(web: httpx.AsyncClient, sites: list[Site], name: str, done: Callable[[Check], Awaitable[None]],
              concurrency: int = CONCURRENCY, budget_s: float = BUDGET_S) -> None:
    """Checks all sites; done() is called for every result (in the order they finish)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget_s
    sem = asyncio.Semaphore(concurrency)
    locks: dict[str, asyncio.Lock] = {}

    async def one(site: Site) -> None:
        host = (urlsplit(fill(site.probe, "x")).hostname or "").lower()
        lock = locks.setdefault(host, asyncio.Lock())
        async with sem, lock:
            if loop.time() > deadline:
                res = Check(site, "error", None, fill(site.url, name), "budget")
            else:
                try:
                    res = await asyncio.wait_for(check(web, site, name), timeout=TIMEOUT * 3)
                except asyncio.TimeoutError:
                    res = Check(site, "error", None, fill(site.url, name), "timeout")
        await done(res)

    await asyncio.gather(*(one(s) for s in sites))
