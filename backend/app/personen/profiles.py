"""Public profile data of found accounts - only what the profile itself shows: display name, short text, place, links,
the platforms' own proofs. Read from the public API of the platform where there is one, else from the profile page
(Open Graph data, rel="me" links, links that contain the user name). Places are reduced to the country.
Pictures are not loaded. Everything goes through webfetch (public addresses only, size limits)."""
from __future__ import annotations

import asyncio
import json
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlsplit

import httpx

from .. import htmlparse, nlp, webfetch
from .check import Check

MAX_PAGE = 500_000
MAX_LINKS = 20
MASTODON_HOSTS = {"mastodon.social", "mastodon.online", "chaos.social", "infosec.exchange", "fosstodon.org", "hachyderm.io",
                  "mstdn.social", "mas.to", "social.tchncs.de", "troet.cafe", "ioc.exchange", "mastodon.world"}
SKIP_LINK_HOSTS = ("googletagmanager.com", "google-analytics.com", "doubleclick.net", "gstatic.com", "googleapis.com",
                   "cloudflare.com", "cdn.", "static.", "apps.apple.com", "play.google.com")
DE_CITIES = {"münchen": "DE", "köln": "DE", "nürnberg": "DE", "düsseldorf": "DE", "wien": "AT", "zürich": "CH", "genf": "CH",
             "mailand": "IT", "rom": "IT", "moskau": "RU", "warschau": "PL", "prag": "CZ", "kopenhagen": "DK", "brüssel": "BE"}


@dataclass
class Profile:
    source: str = "page"  # page | api
    name: str | None = None
    bio: str | None = None
    location: str | None = None
    country: str | None = None
    company: str | None = None
    created: str | None = None
    links: list[str] = field(default_factory=list)
    verified: list[str] = field(default_factory=list)  # links the platform itself confirmed (proofs, verified fields)
    emails: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, [], "")}

    def empty(self) -> bool:
        return not any((self.name, self.bio, self.location, self.company, self.created, self.links, self.verified, self.emails))


def clip(v: Any, n: int = 300) -> str | None:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        v = str(v)
    if not isinstance(v, str):
        return None
    s = " ".join(v.split())
    return s[:n] or None


def html_text(v: Any, n: int = 300) -> str | None:
    if not isinstance(v, str) or not v.strip():
        return None
    return clip(htmlparse.soup(v).get_text(" "), n)


def url_ok(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    s = v.strip()
    if s and "://" not in s and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", s, re.I):
        s = "https://" + s
    try:
        p = urlsplit(s)
    except ValueError:
        return None
    return s[:300] if p.scheme in ("http", "https") and p.hostname and "." in p.hostname else None


def norm_url(u: str) -> str:
    """Comparable form of a profile URL: lower-case host without www., no query, no trailing slash."""
    try:
        p = urlsplit(u.strip())
    except ValueError:
        return u.strip().lower()
    host = (p.hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    return f"{host}{p.path.rstrip('/')}".lower()


def iso(ts: Any) -> str | None:
    try:
        if isinstance(ts, (int, float)) and not isinstance(ts, bool):
            t = ts / 1000 if ts > 10 ** 11 else ts
            return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d")
        if isinstance(ts, str) and re.match(r"^\d{4}-\d{2}-\d{2}", ts):
            return ts[:10]
    except (OverflowError, OSError, ValueError):
        return None
    return None


class Locator:
    """Free-text place of a profile -> ISO country (country names in German and English, flag emoji, large cities)."""

    def __init__(self, centroids: Path | None, places: Path | None) -> None:
        self.places = nlp.load_places(centroids)
        self.cities: dict[str, str] = dict(DE_CITIES)
        seen: dict[str, set[str]] = {}
        try:
            rows = json.loads(places.read_text(encoding="utf-8")).get("places", []) if places else []
        except (OSError, ValueError):
            rows = []
        for r in rows:
            if isinstance(r, list) and len(r) >= 7 and isinstance(r[6], (int, float)) and r[6] >= 1_000_000:
                for nm in {str(r[0]).lower(), str(r[1]).lower()}:
                    seen.setdefault(nm, set()).add(str(r[2]))
        for nm, ccs in seen.items():
            if len(ccs) == 1 and len(nm) >= 3:
                self.cities.setdefault(nm, next(iter(ccs)))

    def country(self, text: str | None) -> str | None:
        if not text:
            return None
        flags = [c for c in text if 0x1F1E6 <= ord(c) <= 0x1F1FF]
        if len(flags) >= 2:
            return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in flags[:2])
        origin, mentioned = nlp.countries(unicodedata.normalize("NFC", text)[:200], self.places)
        if origin or mentioned:
            return origin or mentioned[0]
        for part in re.split(r"[,;/|·()\-]", text.lower()):
            cc = self.cities.get(part.strip())
            if cc:
                return cc
        return None


# --- platform APIs ------------------------------------------------------------------------------------------------
def _github(d: dict[str, Any], p: Profile) -> None:
    p.name, p.bio, p.location, p.company = clip(d.get("name"), 120), clip(d.get("bio")), clip(d.get("location"), 120), clip(d.get("company"), 120)
    p.created = iso(d.get("created_at"))
    p.links = [x for x in (url_ok(d.get("blog")), f"https://x.com/{d['twitter_username']}" if isinstance(d.get("twitter_username"), str) else None) if x]
    if isinstance(d.get("email"), str) and "@" in d["email"]:
        p.emails = [d["email"][:254]]


def _keybase(d: dict[str, Any], p: Profile) -> None:
    them = (d.get("them") or [None])[0] if isinstance(d.get("them"), list) else None
    if not isinstance(them, dict):
        return
    prof = them.get("profile") or {}
    p.name, p.bio, p.location = clip(prof.get("full_name"), 120), clip(prof.get("bio")), clip(prof.get("location"), 120)
    p.created = iso((them.get("basics") or {}).get("ctime"))
    for proof in ((them.get("proofs_summary") or {}).get("all") or [])[:30]:
        u = url_ok((proof or {}).get("service_url"))
        if u:
            p.verified.append(u)


def _mastodon(d: dict[str, Any], p: Profile) -> None:
    p.name, p.bio, p.created = clip(d.get("display_name"), 120), html_text(d.get("note")), iso(d.get("created_at"))
    for f in (d.get("fields") or [])[:10]:
        if not isinstance(f, dict):
            continue
        val = html_text(f.get("value"), 300) or ""
        link = url_ok(val.split()[0]) if val else None
        if link:
            (p.verified if f.get("verified_at") else p.links).append(link)
        elif re.search(r"ort|location|place|wohnort", str(f.get("name") or ""), re.I):
            p.location = clip(val, 120)


def _hackernews(d: dict[str, Any], p: Profile) -> None:
    p.bio, p.created = html_text(d.get("about")), iso(d.get("created"))
    p.links = [x for x in (url_ok(w) for w in re.findall(r"https?://[^\s<>\"']+", str(d.get("about") or ""))[:5]) if x]


def _docker(d: dict[str, Any], p: Profile) -> None:
    p.name, p.location, p.company = clip(d.get("full_name"), 120), clip(d.get("location"), 120), clip(d.get("company"), 120)
    p.created = iso(d.get("date_joined"))
    p.links = [x for x in (url_ok(d.get("profile_url")),) if x]


def _gitea(d: dict[str, Any], p: Profile) -> None:
    p.name, p.bio, p.location = clip(d.get("full_name"), 120), clip(d.get("description")), clip(d.get("location"), 120)
    p.created = iso(d.get("created"))
    p.links = [x for x in (url_ok(d.get("website")),) if x]


def _devto(d: dict[str, Any], p: Profile) -> None:
    p.name, p.bio, p.location = clip(d.get("name"), 120), clip(d.get("summary")), clip(d.get("location"), 120)
    p.created = iso(d.get("joined_at"))
    p.links = [x for x in (url_ok(d.get("website_url")),
                           f"https://github.com/{d['github_username']}" if isinstance(d.get("github_username"), str) else None,
                           f"https://x.com/{d['twitter_username']}" if isinstance(d.get("twitter_username"), str) else None) if x]


def _lichess(d: dict[str, Any], p: Profile) -> None:
    prof = d.get("profile") or {}
    p.name = clip(prof.get("realName"), 120)
    p.bio, p.location, p.created = clip(prof.get("bio")), clip(prof.get("location"), 120), iso(d.get("createdAt"))
    flag = prof.get("flag") or prof.get("country")
    if isinstance(flag, str) and re.fullmatch(r"[A-Z]{2}", flag):
        p.country = flag
    p.links = [x for x in (url_ok(w) for w in str(prof.get("links") or "").split()[:8]) if x]


def _chesscom(d: dict[str, Any], p: Profile) -> None:
    p.name, p.location, p.created = clip(d.get("name"), 120), clip(d.get("location"), 120), iso(d.get("joined"))
    m = re.search(r"/country/([A-Z]{2})$", str(d.get("country") or ""))
    if m:
        p.country = m.group(1)


def _reddit(d: dict[str, Any], p: Profile) -> None:
    data = d.get("data") or {}
    sub = data.get("subreddit") or {}
    p.name, p.bio, p.created = clip(sub.get("title"), 120), clip(sub.get("public_description")), iso(data.get("created_utc"))


Api = tuple[Callable[[str, str], str], Callable[[dict[str, Any], Profile], None]]
APIS: dict[str, Api] = {
    "github.com": (lambda h, u: f"https://api.github.com/users/{u}", _github),
    "keybase.io": (lambda h, u: f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}&fields=basics,profile,proofs_summary", _keybase),
    "news.ycombinator.com": (lambda h, u: f"https://hacker-news.firebaseio.com/v0/user/{u}.json", _hackernews),
    "hub.docker.com": (lambda h, u: f"https://hub.docker.com/v2/users/{u}/", _docker),
    "codeberg.org": (lambda h, u: f"https://codeberg.org/api/v1/users/{u}", _gitea),
    "dev.to": (lambda h, u: f"https://dev.to/api/users/by_username?url={u}", _devto),
    "lichess.org": (lambda h, u: f"https://lichess.org/api/user/{u}", _lichess),
    "chess.com": (lambda h, u: f"https://api.chess.com/pub/player/{u.lower()}", _chesscom),
    "reddit.com": (lambda h, u: f"https://www.reddit.com/user/{u}/about.json", _reddit),
}
MASTODON: Api = (lambda h, u: f"https://{h}/api/v1/accounts/lookup?acct={u}", _mastodon)


def api_for(host: str, site_name: str) -> Api | None:
    h = host[4:] if host.startswith("www.") else host
    if h in APIS:
        return APIS[h]
    if h in MASTODON_HOSTS or "mastodon" in site_name.lower():
        return MASTODON
    return None


def from_page(body: bytes, base: str, name: str) -> Profile:
    """Profile page: Open Graph data, rel="me" links and links that contain the user name (other hosts only)."""
    s = htmlparse.soup(body)
    meta = htmlparse.meta(s)
    p = Profile(source="page")
    p.name = clip(meta.get("og:title") or meta.get("twitter:title") or meta.get("title"), 120)
    p.bio = clip(meta.get("og:description") or meta.get("description") or meta.get("twitter:description"))
    own = (urlsplit(base).hostname or "").lower()
    low = name.lower()
    out: list[str] = []
    for ln in htmlparse.links(s, base, limit=600):
        u = ln["url"]
        if u.startswith(("mailto:", "tel:")):
            continue
        host = (urlsplit(u).hostname or "").lower()
        if not host or host == own or host.endswith("." + own) or any(x in host for x in SKIP_LINK_HOSTS):
            continue
        if "me" in ln["rel"] or (len(low) >= 3 and low in u.lower()):
            if u not in out:
                out.append(u[:300])
        if len(out) >= MAX_LINKS:
            break
    p.links = out
    return p


async def read(web: httpx.AsyncClient, c: Check, name: str, locator: Locator) -> Profile | None:
    """Profile of a found account (None if nothing could be read)."""
    host = (urlsplit(c.url).hostname or "").lower()
    api = api_for(host, c.site.name)
    p: Profile | None = None
    if api:
        try:
            page = await webfetch.fetch(web, api[0](host, quote(name, safe="")), headers={"User-Agent": webfetch.BROWSER_UA,
                                        "Accept": "application/json"}, max_bytes=MAX_PAGE, timeout=10)
            if page.status == 200:
                data = json.loads(page.body)
                if isinstance(data, dict):
                    p = Profile(source="api")
                    api[1](data, p)
        except (webfetch.FetchError, ValueError):
            p = None
    if p is None or p.empty():
        body = c.body if c.body and "html" in (c.ctype or "text/html") else b""
        if not body:
            try:
                page = await webfetch.fetch(web, c.url, headers={"User-Agent": webfetch.BROWSER_UA, "Accept": "text/html"},
                                            max_bytes=MAX_PAGE, timeout=10)
                body = page.body if page.status == 200 and page.html else b""
            except webfetch.FetchError:
                body = b""
        if body:
            p = await asyncio.to_thread(from_page, body, c.url, name)
    if p is None or p.empty():
        return None
    p.links = [x for x in dict.fromkeys(p.links) if norm_url(x) != norm_url(c.url)][:MAX_LINKS]
    p.verified = list(dict.fromkeys(p.verified))[:MAX_LINKS]
    if not p.country:
        p.country = locator.country(p.location)
    return p


async def gravatar(web: httpx.AsyncClient, email: str, key: str, locator: Locator) -> tuple[str, Profile] | None:
    """Gravatar profile of an e-mail address (REST API v3, needs GRAVATAR_API_KEY): (profile URL, profile)."""
    import hashlib

    h = hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()
    try:
        page = await webfetch.fetch(web, f"https://api.gravatar.com/v3/profiles/{h}", max_bytes=200_000, timeout=10,
                                    headers={"Authorization": f"Bearer {key}", "Accept": "application/json"})
        d = json.loads(page.body) if page.status == 200 else None
    except (webfetch.FetchError, ValueError):
        return None
    if not isinstance(d, dict):
        return None
    url = url_ok(d.get("profile_url")) or f"https://gravatar.com/{h}"
    p = Profile(source="api", name=clip(d.get("display_name"), 120), bio=clip(d.get("description")),
                location=clip(d.get("location"), 120), company=clip(d.get("company"), 120))
    for acc in (d.get("verified_accounts") or [])[:30]:
        u = url_ok((acc or {}).get("url")) if isinstance(acc, dict) else None
        if u:
            p.verified.append(u)
    p.country = locator.country(p.location)
    return url, p
