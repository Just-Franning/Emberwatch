"""Site lists of the people search, downloaded at runtime (not part of the repository):

- Sherlock (https://github.com/sherlock-project/sherlock, MIT): sherlock_project/resources/data.json
- WhatsMyName (https://github.com/WebBreacher/WhatsMyName, CC BY-SA 4.0): wmn-data.json
  "Uses data from the WhatsMyName project (CC BY-SA 4.0)."

Both are stored under DATA_DIR/osint and refreshed weekly (ETag). The entries are third-party data and validated
strictly: http(s) URLs with the user name placeholder and a host name, bounded strings, simple regular expressions
only, no Host header. Left out: adult content, dating, health and political sites (categories of WhatsMyName,
isNSFW of Sherlock, a word list for Sherlock entries). A site that both lists know is taken from WhatsMyName (it
describes the found and the not-found answer).
"""
from __future__ import annotations

import json
import logging
import re
import time
from re import _parser as sre_parse  # the parser of the re module (Python 3.11+): structure of untrusted patterns
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..sources.fetch import FetchError, get_capped

log = logging.getLogger("personen")

SOURCES = {
    "sherlock": "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json",
    "wmn": "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
}
MAX_BYTES = 8 * 1024 * 1024
REFRESH_S = 7 * 24 * 3600
EXCLUDED_CATS = {"xx nsfw xx", "dating", "health", "political"}
EXCLUDED_WORDS = re.compile(r"porn|xxx|\bsex|nsfw|dating|escort|\bfap|hentai|onlyfans|\bcams?\b|webcam|nude|fetish|bdsm|erotic|"
                            r"adult|hookup|swinger|tinder|xhamster|xvideos|chaturbate|motherless|redtube|youporn|tnaflix", re.I)
HOST_RE = re.compile(r"^(?=.{3,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,40}$")
DROP_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer"}
CATS = ("social", "coding", "tech", "gaming", "hobby", "music", "art", "images", "video", "blog", "business", "finance",
        "shopping", "news", "misc", "archived")


@dataclass(frozen=True)
class Site:
    name: str
    source: str  # "wmn" | "sherlock"
    cat: str
    url: str  # profile URL, "{u}" for the user name
    probe: str  # requested URL
    host: str  # host of the profile URL (without "www."), key for duplicates and the operator list
    method: str = "GET"
    body: str | None = None  # template with {u}
    json_body: bool = False
    headers: tuple[tuple[str, str], ...] = ()
    # WhatsMyName
    e_code: int | None = None
    e_string: str = ""
    m_code: int | None = None
    m_string: str = ""
    strip: str = ""
    # Sherlock
    error_type: str = ""
    error_msgs: tuple[str, ...] = ()
    error_codes: tuple[int, ...] = ()
    regex: str | None = None
    protection: tuple[str, ...] = field(default=())


def _str(v: Any, n: int) -> str:
    return v[:n] if isinstance(v, str) else ""


def _url(v: Any, mark: str) -> str | None:
    """A URL template from the list: http(s), a valid host name (no IP literal), the placeholder."""
    if not isinstance(v, str) or len(v) > 300 or mark not in v:
        return None
    try:
        parts = urlsplit(v.replace(mark, "x"))
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not HOST_RE.match(host) or re.fullmatch(r"[\d.]+", host) or host == "localhost":
        return None
    if parts.username or parts.password:
        return None
    return v.replace(mark, "{u}")


def _host(url: str) -> str:
    h = (urlsplit(url.replace("{u}", "x")).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _headers(v: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(v, dict):
        return ()
    out = []
    for k, val in list(v.items())[:10]:
        if isinstance(k, str) and isinstance(val, str) and HEADER_NAME.match(k) and k.lower() not in DROP_HEADERS and len(val) <= 400 \
                and "\n" not in val and "\r" not in val:
            out.append((k, val))
    return tuple(out)


def _subpatterns(av: Any) -> Any:
    """The parsed sub-patterns inside the argument of one node (groups, branches, assertions)."""
    if isinstance(av, sre_parse.SubPattern):
        yield av
    elif isinstance(av, (list, tuple)):
        for x in av:
            yield from _subpatterns(x)


def _backtracks(p: Any, repeated: bool = False) -> bool:
    """True if a repeated part repeats or branches itself - (a+)+, (a|ab)*, (?:x?y*){2,} -: such patterns can take
    exponential time. Patterns of the site lists are third-party data and run in the server process."""
    for op, av in p:
        name = str(op)
        if "REPEAT" in name:
            _lo, hi, sub = av
            if hi > 1 and (repeated or _backtracks(sub, True)):
                return True
            if hi <= 1 and _backtracks(sub, repeated):
                return True
        elif name == "BRANCH" and repeated:
            return True
        elif any(_backtracks(sub, repeated) for sub in _subpatterns(av)):
            return True
    return False


def _repeats(p: Any) -> int:
    """Number of parts that may repeat; a row of them (\\w*\\w*\\w*...) also backtracks polynomially."""
    n = 0
    for op, av in p:
        if "REPEAT" in str(op):
            n += int(av[1] > 1) + _repeats(av[2])
        else:
            n += sum(_repeats(sub) for sub in _subpatterns(av))
    return n


def _regex(v: Any) -> str | None:
    """Sherlock's regexCheck (which user names a site allows): only short patterns without nested repetition and with
    at most three repeated parts; a refused pattern only means that the site is checked for every name."""
    if not isinstance(v, str) or not v or len(v) > 200:
        return None
    try:
        re.compile(v)
        tree = sre_parse.parse(v)
        if _backtracks(tree) or _repeats(tree) > 3:
            return None
    except (re.error, RecursionError, ValueError, TypeError):
        return None
    return v


def _code(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and 100 <= v <= 599 else None


def parse_wmn(data: Any) -> list[Site]:
    out = []
    for e in (data or {}).get("sites", []) if isinstance(data, dict) else []:
        if not isinstance(e, dict) or e.get("valid") is False:
            continue
        name = _str(e.get("name"), 80).strip()
        cat = _str(e.get("cat"), 40).strip().lower()
        if not name or cat in EXCLUDED_CATS or EXCLUDED_WORDS.search(name):
            continue
        body = e.get("post_body")
        raw = e.get("uri_check") if isinstance(e.get("uri_check"), str) else ""
        if body:  # POST: the name is in the body; the URL may lack the placeholder
            if not isinstance(body, str) or len(body) > 2000 or "{account}" not in body:
                continue
            probe = _url(raw, "{account}") if "{account}" in raw else _url(raw + "{account}", "{account}")
            if probe and "{account}" not in raw:
                probe = probe[: -len("{u}")]
        else:
            probe = _url(raw, "{account}")
        pretty = _url(e.get("uri_pretty"), "{account}") if e.get("uri_pretty") else None
        url = pretty or (probe if not body else None)
        e_code, m_code = _code(e.get("e_code")), _code(e.get("m_code"))
        if not probe or not url or e_code is None or m_code is None:
            continue
        out.append(Site(
            name=name, source="wmn", cat=cat if cat in CATS else "misc", url=url, probe=probe, host=_host(url),
            method="POST" if body else "GET", body=body.replace("{account}", "{u}") if body else None,
            headers=_headers(e.get("headers")), e_code=e_code, e_string=_str(e.get("e_string"), 500),
            m_code=m_code, m_string=_str(e.get("m_string"), 500), strip=_str(e.get("strip_bad_char"), 10),
            protection=tuple(str(x)[:20] for x in (e.get("protection") or [])[:4] if isinstance(x, str)),
        ))
    return out


def _interp(v: Any, depth: int = 0) -> Any:
    """Sherlock request payloads: "{}" -> "{u}" in all strings."""
    if depth > 4:
        return None
    if isinstance(v, str):
        return v[:300].replace("{}", "{u}")
    if isinstance(v, dict):
        return {str(k)[:50]: _interp(x, depth + 1) for k, x in list(v.items())[:10]}
    if isinstance(v, list):
        return [_interp(x, depth + 1) for x in v[:10]]
    return v if isinstance(v, (int, float, bool)) or v is None else None


def parse_sherlock(data: Any) -> list[Site]:
    out = []
    for name, e in (data or {}).items() if isinstance(data, dict) else []:
        if not isinstance(e, dict) or name.startswith("$") or e.get("isNSFW") or EXCLUDED_WORDS.search(name):
            continue
        url = _url(e.get("url"), "{}")
        probe = _url(e.get("urlProbe"), "{}") if e.get("urlProbe") else url
        etype = e.get("errorType")
        etype = etype if isinstance(etype, str) else (etype[0] if isinstance(etype, list) and etype and isinstance(etype[0], str) else "")
        if not url or not probe or etype not in ("message", "status_code", "response_url") or EXCLUDED_WORDS.search(url):
            continue
        msgs = e.get("errorMsg")
        msgs = (msgs,) if isinstance(msgs, str) else tuple(m for m in (msgs or []) if isinstance(m, str))
        if etype == "message" and not msgs:
            continue
        codes = e.get("errorCode")
        codes = (codes,) if isinstance(codes, int) else tuple(c for c in (codes or []) if isinstance(c, int))
        method = str(e.get("request_method") or ("HEAD" if etype == "status_code" else "GET")).upper()
        if method not in ("GET", "HEAD", "POST"):
            continue
        payload = e.get("request_payload")
        body = json.dumps(_interp(payload)) if payload is not None else None
        out.append(Site(
            name=str(name)[:80], source="sherlock", cat="misc", url=url, probe=probe, host=_host(url), method=method,
            body=body, json_body=body is not None, headers=_headers(e.get("headers")), error_type=etype,
            error_msgs=tuple(m[:500] for m in msgs[:6]), error_codes=tuple(c for c in codes if 100 <= c <= 599)[:6],
            regex=_regex(e.get("regexCheck")),
        ))
    return out


def merge(wmn: list[Site], sherlock: list[Site]) -> list[Site]:
    """WhatsMyName first; a Sherlock site only if no WhatsMyName entry has the same host."""
    hosts = {s.host for s in wmn}
    seen: set[tuple[str, str]] = set()
    out = []
    for s in wmn + [x for x in sherlock if x.host not in hosts]:
        key = (s.host, s.url.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


class SiteList:
    def __init__(self, data_dir: Path, user_agent: str) -> None:
        self.dir = data_dir / "osint"
        self.ua = user_agent
        self.sites: list[Site] = []
        self.meta: dict[str, Any] = {}
        self.load()

    def _meta_path(self) -> Path:
        return self.dir / "lists.json"

    def load(self) -> None:
        try:
            self.meta = json.loads(self._meta_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.meta = {}
        parsed: dict[str, list[Site]] = {}
        for name, fn in (("wmn", parse_wmn), ("sherlock", parse_sherlock)):
            try:
                parsed[name] = fn(json.loads((self.dir / f"{name}.json").read_text(encoding="utf-8")))
            except (OSError, ValueError):
                parsed[name] = []
        self.sites = merge(parsed["wmn"], parsed["sherlock"])
        self.meta["counts"] = {"wmn": len(parsed["wmn"]), "sherlock": len(parsed["sherlock"]), "total": len(self.sites)}

    def info(self) -> dict[str, Any]:
        return {"total": len(self.sites), "counts": self.meta.get("counts", {}),
                "fetched": {k: (self.meta.get(k) or {}).get("fetched_at") for k in SOURCES},
                "errors": {k: (self.meta.get(k) or {}).get("error") for k in SOURCES if (self.meta.get(k) or {}).get("error")},
                "cats": sorted({s.cat for s in self.sites})}

    def due(self) -> bool:
        return not self.sites or any(time.time() - float((self.meta.get(k) or {}).get("checked", 0)) > REFRESH_S for k in SOURCES)

    async def refresh(self, client: httpx.AsyncClient, force: bool = False) -> bool:
        """Downloads both lists (conditional with the ETag). Returns True if something changed."""
        self.dir.mkdir(parents=True, exist_ok=True)
        changed = False
        for name, url in SOURCES.items():
            m = dict(self.meta.get(name) or {})
            if not force and time.time() - float(m.get("checked", 0)) < REFRESH_S and (self.dir / f"{name}.json").exists():
                continue
            headers = {"User-Agent": self.ua}
            if m.get("etag") and (self.dir / f"{name}.json").exists() and not force:
                headers["If-None-Match"] = m["etag"]
            try:
                status, hdrs, body = await get_capped(client, url, max_bytes=MAX_BYTES, headers=headers, timeout=60)
                if status == 200:
                    data = json.loads(body)
                    n = len(parse_wmn(data) if name == "wmn" else parse_sherlock(data))
                    if n < 50:  # an empty or broken list does not replace a working one
                        raise ValueError(f"only {n} usable entries")
                    tmp = self.dir / f"{name}.json.tmp"
                    tmp.write_bytes(body)
                    tmp.replace(self.dir / f"{name}.json")
                    m.update(etag=hdrs.get("etag"), fetched_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), error=None)
                    changed = True
                elif status != 304:
                    m["error"] = f"HTTP {status}"
                else:
                    m["error"] = None
            except (FetchError, httpx.HTTPError, ValueError) as exc:
                m["error"] = str(exc)[:200] or exc.__class__.__name__
                log.warning("site list %s: %s", name, m["error"])
            m["checked"] = time.time()
            self.meta[name] = m
        self._meta_path().write_text(json.dumps({k: v for k, v in self.meta.items() if k in SOURCES}), encoding="utf-8")
        self.load()
        return changed
