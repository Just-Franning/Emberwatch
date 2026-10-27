"""Reading HTML of third parties (BeautifulSoup with Python's own html.parser). Only strings are taken out - visible
text lines, links, meta data, JSON-LD - and cut to sane lengths; nothing of it is ever rendered as HTML.
Parsing large pages costs CPU time: callers run these functions in a worker thread."""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

NOISE = ("script", "style", "noscript", "svg", "template", "iframe", "object")
LAYOUT = ("nav", "header", "footer", "aside")
_WS = re.compile(r"[ \t  -​  　]+")


def soup(html: str | bytes) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def text_lines(s: BeautifulSoup, *, layout: bool = False, limit: int = 4000) -> list[str]:
    """Visible text, one entry per line; layout=True keeps navigation, header and footer."""
    for tag in s(list(NOISE) + ([] if layout else list(LAYOUT))):
        tag.decompose()
    for br in s.find_all("br"):
        br.replace_with("\n")
    out = []
    for line in s.get_text("\n").splitlines():
        line = _WS.sub(" ", line).strip()
        if line:
            out.append(line[:500])
            if len(out) >= limit:
                break
    return out


def links(s: BeautifulSoup, base: str, limit: int = 400) -> list[dict[str, Any]]:
    """Absolute http(s) links: {"url", "label", "rel"}; mailto/tel links as {"url": "mailto:..."}."""
    out = []
    for a in s.find_all(["a", "link"], href=True):
        href = str(a.get("href") or "").strip()
        if not href or href.startswith(("#", "javascript:", "data:")):
            continue
        rel = [str(x).lower() for x in (a.get("rel") or [])]
        if href.lower().startswith(("mailto:", "tel:")):
            out.append({"url": href[:300], "label": " ".join(a.get_text(" ").split())[:120], "rel": rel})
            continue
        try:
            url = urljoin(base, href)
            parts = urlsplit(url)
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        out.append({"url": url[:500], "label": " ".join(a.get_text(" ").split())[:120], "rel": rel})
        if len(out) >= limit:
            break
    return out


def meta(s: BeautifulSoup) -> dict[str, str]:
    """<title> and the usual meta tags (Open Graph, Twitter, description, profile:username)."""
    out: dict[str, str] = {}
    if s.title and s.title.string:
        out["title"] = " ".join(s.title.string.split())[:300]
    for m in s.find_all("meta"):
        key = str(m.get("property") or m.get("name") or "").strip().lower()
        val = m.get("content")
        if key and isinstance(val, str) and val.strip() and (key.startswith(("og:", "twitter:", "profile:")) or key in (
                "description", "author")):
            out.setdefault(key, " ".join(val.split())[:1000])
    return out


def json_ld(s: BeautifulSoup, limit: int = 30) -> list[dict[str, Any]]:
    """schema.org objects from <script type="application/ld+json"> (with @graph flattened)."""
    out: list[dict[str, Any]] = []

    def add(x: Any, depth: int = 0) -> None:
        if len(out) >= limit or depth > 3:
            return
        if isinstance(x, list):
            for y in x:
                add(y, depth + 1)
        elif isinstance(x, dict):
            if "@graph" in x:
                add(x["@graph"], depth + 1)
            if "@type" in x:
                out.append(x)

    for tag in s.find_all("script", attrs={"type": re.compile(r"application/ld\+json", re.I)}):
        raw = tag.string or tag.get_text() or ""
        if not raw.strip() or len(raw) > 300_000:
            continue
        try:
            add(json.loads(raw))
        except ValueError:
            continue
    return out


def ld_types(obj: dict[str, Any]) -> set[str]:
    t = obj.get("@type")
    return {str(x) for x in (t if isinstance(t, list) else [t]) if x}


def ld_str(v: Any, n: int = 300) -> str | None:
    """A schema.org value as text (strings, numbers, or {"name": ...})."""
    if isinstance(v, (str, int, float)) and str(v).strip():
        return " ".join(str(v).split())[:n]
    if isinstance(v, dict):
        return ld_str(v.get("name") or v.get("@id"), n)
    if isinstance(v, list) and v:
        return ld_str(v[0], n)
    return None
