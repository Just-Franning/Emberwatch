"""Weltlage: IT security news from curated feeds of authorities and specialist media.

Per item Emberwatch stores the headline, a short teaser (at most 260 characters), the link, the publication time and
the address of a preview image. Images are not copied: the browser loads them from the publisher (NEWS_IMAGES).
Headlines and teasers are third-party text: they are shown as text only, analysed with linear algorithms (nlp.py) and
never interpreted as markup or instructions.
"""
from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from defusedxml import DefusedXmlException
from defusedxml import ElementTree as DET

from . import alerts, nlp
from .actors import Actors
from .db import DB, utcnow
from .domains import registrable
from .tools import ToolError, resolve

log = logging.getLogger("emberwatch.news")

MAX_FEED_BYTES = 5 * 1024 * 1024
MAX_PAGE_BYTES = 400 * 1024
MAX_ITEMS_PER_FEED = 120
KEEP_DAYS_ON_FETCH = 30
OG_PER_RUN = 24
CLUSTER_HOURS = 72
TIERS = ("gov", "press")
FEED_ID_RE = re.compile(r"^[a-z0-9_]{2,30}$")
TAG_RE = re.compile(r"<[^<>]*>")
IMG_RE = re.compile(r"<img\b[^<>]*>", re.I)
META_RE = re.compile(r"<meta\b[^<>]*>", re.I)
ATTR_RE = re.compile(r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`=]+))""")
AD_RE = re.compile(r"^\s*\[?(anzeige|sponsored|advertisement|promoted|partner content|werbung)\b", re.I)
TRACKER_RE = re.compile(r"(pixel|track|beacon|counter|stats\.|cpx\.|/1x1|spacer|feeds\.feedburner)", re.I)
NS_CONTENT = "http://purl.org/rss/1.0/modules/content/"
NS_MEDIA = "http://search.yahoo.com/mrss/"
DROP_PARAMS = re.compile(r"^(utm_|mc_|fbclid$|gclid$|ref$|source$|cmpid$|wt_)", re.I)


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    tier: str      # gov = authority, press = specialist media
    lang: str
    home: str      # country of the publisher
    domains: tuple[str, ...]  # registrable domains of the articles (preview images are only read there)


# Verified feeds (format and availability checked when they were added). Additional feeds: NEWS_FEEDS.
DEFAULT_SOURCES: tuple[Source, ...] = (
    Source("ncsc_uk", "NCSC (UK)", "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml", "gov", "en", "GB",
           ("ncsc.gov.uk",)),
    Source("bsi", "BSI", "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_Presse_Veranstaltungen.xml"
           "?nn=910128", "gov", "de", "DE", ("bsi.bund.de",)),
    Source("therecord", "The Record", "https://therecord.media/feed/", "press", "en", "US", ("therecord.media",)),
    Source("bleepingcomputer", "BleepingComputer", "https://www.bleepingcomputer.com/feed/", "press", "en", "US",
           ("bleepingcomputer.com",)),
    Source("securityweek", "SecurityWeek", "https://www.securityweek.com/feed/", "press", "en", "US", ("securityweek.com",)),
    Source("krebs", "Krebs on Security", "https://krebsonsecurity.com/feed/", "press", "en", "US", ("krebsonsecurity.com",)),
    Source("golem", "Golem.de Security", "https://rss.golem.de/rss.php?tp=sec&feed=RSS2.0", "press", "de", "DE", ("golem.de",)),
)


def parse_extra(raw: str) -> list[Source]:
    """NEWS_FEEDS: entries "id|Name|https://feed[|gov|lang]" separated by ";" or line breaks."""
    out = []
    for part in re.split(r"[;\n]+", raw or ""):
        f = [x.strip() for x in part.split("|")]
        if len(f) < 3 or not FEED_ID_RE.match(f[0]) or not f[1]:
            continue
        try:
            u = urlsplit(f[2])
        except ValueError:
            continue
        if u.scheme != "https" or not u.hostname or u.username or u.password:
            continue
        tier = f[3] if len(f) > 3 and f[3] in TIERS else "press"
        lang = f[4][:2].lower() if len(f) > 4 and f[4] else "en"
        name, sfx = registrable(u.hostname)
        out.append(Source(f[0], f[1][:60], f[2], tier, lang, "", (f"{name}.{sfx}" if sfx else u.hostname,)))
    return out


# --- parsing ------------------------------------------------------------------------------------------------------------
def _local(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _ns(tag: Any) -> str:
    return tag[1:tag.index("}")] if isinstance(tag, str) and tag.startswith("{") and "}" in tag else ""


def _inner(el: Any) -> str:
    return "".join(el.itertext()) if len(el) else (el.text or "")


def strip_html(s: str, limit: int = 20000) -> str:
    """Text of an HTML snippet (linear, bounded)."""
    t = TAG_RE.sub(" ", (s or "")[:limit])
    return " ".join(html.unescape(t).split())


def clean_url(raw: str | None, *, image: bool = False) -> str | None:
    """https URL without credentials, tracking parameters and fragment; http is upgraded."""
    s = html.unescape((raw or "").strip())
    if not s or len(s) > 1500 or any(c.isspace() for c in s):
        return None
    if s.startswith("//"):
        s = "https:" + s
    try:
        u = urlsplit(s)
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        return None
    query = u.query
    if not image and query:
        pairs = parse_qsl(query, keep_blank_values=True)
        if any(DROP_PARAMS.match(k) for k, _ in pairs):  # rebuilt only when tracking parameters are present
            query = urlencode([(k, v) for k, v in pairs if not DROP_PARAMS.match(k)])
    try:
        port = u.port
    except ValueError:
        return None
    netloc = u.hostname + (f":{port}" if port and port != 443 and port != 80 else "")
    return urlunsplit(("https", netloc, u.path or "/", query, ""))


def _attrs(tag: str) -> dict[str, str]:
    """Attributes of one HTML tag; findall yields "" for the quote styles that did not match."""
    return {m[0].lower(): m[1] or m[2] or m[3] for m in ATTR_RE.findall(tag)}


def _img_from_html(fragment: str) -> str | None:
    for tag in IMG_RE.findall((fragment or "")[:200000]):
        attrs = _attrs(tag)
        src = attrs.get("src") or attrs.get("data-src")
        if not src or TRACKER_RE.search(src):
            continue
        try:
            if int(attrs.get("width") or 99) <= 2 or int(attrs.get("height") or 99) <= 2:
                continue
        except ValueError:
            pass
        url = clean_url(src, image=True)
        if url:
            return url
    return None


def _date(raw: str) -> datetime | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        d = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        try:
            d = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def parse_feed(data: bytes) -> list[dict[str, Any]]:
    """Items of an RSS 2.0, RSS 1.0 (RDF) or Atom feed. Entity declarations and external references are refused."""
    root = DET.fromstring(data, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    out = []
    for it in (el for el in root.iter() if _local(el.tag) in ("item", "entry")):
        f: dict[str, Any] = {"title": "", "link": "", "date": None, "desc": "", "content": "", "image": None}
        guid = ""
        for ch in it:
            name, ns = _local(ch.tag), _ns(ch.tag)
            if name == "title" and not f["title"]:
                f["title"] = _inner(ch)
            elif name == "link" and not f["link"]:
                href = ch.get("href")
                if href and ch.get("rel", "alternate") == "alternate":
                    f["link"] = href
                elif not href and (ch.text or "").strip():
                    f["link"] = ch.text.strip()
            elif name == "guid" and (ch.get("isPermaLink") or "true") == "true":
                guid = (ch.text or "").strip()
            elif name in ("pubDate", "published", "date", "issued", "updated") and f["date"] is None:
                f["date"] = _date(ch.text or "")
            elif name in ("description", "summary") and not f["desc"]:
                f["desc"] = _inner(ch)
            elif (name == "encoded" and ns == NS_CONTENT) or (name == "content" and ns != NS_MEDIA):
                f["content"] = _inner(ch)
            elif name == "enclosure" and (ch.get("type") or "").lower().startswith("image/") and not f["image"]:
                f["image"] = clean_url(ch.get("url"), image=True)
            elif ns == NS_MEDIA and name in ("content", "thumbnail") and not f["image"]:
                typ = (ch.get("type") or ch.get("medium") or "image").lower()
                if name == "thumbnail" or typ.startswith("image"):
                    f["image"] = clean_url(ch.get("url"), image=True)
        if not f["link"] and guid.startswith(("http://", "https://")):
            f["link"] = guid
        f["image"] = f["image"] or _img_from_html(f["content"]) or _img_from_html(f["desc"])
        out.append(f)
        if len(out) >= MAX_ITEMS_PER_FEED:
            break
    return out


def og_image(page: str) -> str | None:
    """og:image or twitter:image of an HTML page (only the head part is looked at)."""
    head = page[:MAX_PAGE_BYTES]
    end = head.lower().find("</head>")
    if end > 0:
        head = head[:end]
    found: dict[str, str] = {}
    for tag in META_RE.findall(head):
        attrs = _attrs(tag)
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key in ("og:image", "og:image:url", "og:image:secure_url", "twitter:image") and attrs.get("content"):
            found.setdefault(key, attrs["content"])
    for key in ("og:image:secure_url", "og:image", "og:image:url", "twitter:image"):
        if key in found:
            url = clean_url(found[key], image=True)
            if url:
                return url
    return None


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def _cutoff(days: float) -> str:
    return _iso(datetime.now(timezone.utc) - timedelta(days=days))


# --- collector ----------------------------------------------------------------------------------------------------------
class News:
    def __init__(self, s: Any, db: DB, actors: Actors, centroids: Path | None = None) -> None:
        self.s = s
        self.db = db
        self.actors = actors
        self.places = nlp.load_places(centroids)
        self.sources = self._sources()
        self.by_id = {x.id: x for x in self.sources}

    def _sources(self) -> list[Source]:
        off = {x.strip() for x in (getattr(self.s, "news_disable", "") or "").split(",") if x.strip()}
        out = [x for x in DEFAULT_SOURCES if x.id not in off]
        known = {x.id for x in out}
        for x in parse_extra(getattr(self.s, "news_feeds", "") or ""):
            if x.id not in known and x.id not in off:
                out.append(x)
                known.add(x.id)
        return out

    @property
    def enabled(self) -> bool:
        return bool(getattr(self.s, "news_enabled", True)) and bool(self.sources)

    # --- fetching --------------------------------------------------------------------------------------------------------
    async def _fetch(self, client: httpx.AsyncClient, src: Source) -> bytes | None:
        """Feed body, or None if unchanged (conditional GET with ETag / Last-Modified)."""
        headers = {"User-Agent": self.s.user_agent,
                   "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, */*;q=0.3"}
        etag = self.db.meta_get(f"news_etag:{src.id}")
        lastmod = self.db.meta_get(f"news_lastmod:{src.id}")
        if etag:
            headers["If-None-Match"] = etag
        if lastmod:
            headers["If-Modified-Since"] = lastmod
        url = src.url
        for hop in range(4):
            if hop:  # the configured URL is trusted; redirect targets must be https and public
                if not url.startswith("https://"):
                    raise ValueError("redirect to a non-https URL")
                await resolve(urlsplit(url).hostname or "", False)
            r = await client.send(client.build_request("GET", url, headers=headers, timeout=25), stream=True,
                                  follow_redirects=False)
            try:
                if r.status_code in (301, 302, 303, 307, 308):
                    nxt = r.headers.get("location") or ""
                    if not nxt:
                        raise ValueError("redirect without location")
                    url = str(httpx.URL(url).join(nxt))
                    continue
                if r.status_code == 304:
                    return None
                if r.status_code != 200:
                    raise httpx.HTTPStatusError(f"HTTP {r.status_code}", request=r.request, response=r)
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf.extend(chunk)
                    if len(buf) > MAX_FEED_BYTES:
                        raise ValueError("feed too large")
            finally:
                await r.aclose()
            if r.headers.get("etag"):
                self.db.meta_set(f"news_etag:{src.id}", r.headers["etag"][:200])
            if r.headers.get("last-modified"):
                self.db.meta_set(f"news_lastmod:{src.id}", r.headers["last-modified"][:100])
            return bytes(buf)
        raise ValueError("too many redirects")

    async def collect(self, client: httpx.AsyncClient) -> int:
        """Fetches all feeds, stores new items with their recognition, creates alerts. Returns the number of new items."""
        if not self.enabled:
            self.db.status("news", True, code="disabled")
            return 0
        sem = asyncio.Semaphore(3)

        async def one(src: Source) -> tuple[Source, list[dict[str, Any]] | None, str | None]:
            async with sem:
                try:
                    data = await self._fetch(client, src)
                    if data is None:
                        return src, [], None
                    return src, await asyncio.to_thread(parse_feed, data), None
                except (httpx.HTTPError, ValueError, SyntaxError) as exc:  # ParseError and defusedxml errors are ValueErrors/SyntaxErrors
                    return src, None, f"{exc.__class__.__name__}: {str(exc)[:160]}"
                except ToolError as exc:  # redirect to a private address or unresolvable host
                    return src, None, f"redirect refused: {exc.key}"
                except Exception as exc:  # defusedxml.DefusedXmlException (entities refused) and anything unexpected
                    log.warning("feed %s: %s", src.id, exc.__class__.__name__, exc_info=not isinstance(exc, DefusedXmlException))
                    return src, None, exc.__class__.__name__

        results = await asyncio.gather(*(one(x) for x in self.sources))
        ctx = self._context()
        new_total = 0
        failed = []
        for src, items, err in results:
            if err is not None:
                failed.append(src.name)
                self._source_status(src, False, err)
                continue
            n = 0
            for raw in items or []:
                if self._store(src, raw, ctx):
                    n += 1
            new_total += n
            self._source_status(src, True, "", n)
        if self.s.news_images:
            await self._og_images(client)
        self._prune()
        ok = len(self.sources) - len(failed)
        total = self.db.query("SELECT COUNT(*) AS n FROM news")[0]["n"]
        self.db.meta_set("news_rev", utcnow())  # invalidates cached overviews (main.welt_overview)
        self.db.status("news", ok > 0, ", ".join(failed)[:300] if failed else "", total,
                       code="news_partial" if failed and ok else None, params={"failed": ", ".join(failed)} if failed and ok else None)
        return new_total

    def _source_status(self, src: Source, ok: bool, message: str, new: int = 0) -> None:
        prev = json.loads(self.db.meta_get(f"news_src:{src.id}") or "{}")
        now = utcnow()
        self.db.meta_set(f"news_src:{src.id}", json.dumps({
            "ok": ok, "last_run": now, "last_ok": now if ok else prev.get("last_ok"), "message": message[:200],
            "new": new}))

    def source_list(self) -> list[dict[str, Any]]:
        counts = {r["source"]: r["n"] for r in self.db.query("SELECT source, COUNT(*) AS n FROM news WHERE published >= ? GROUP BY source",
                                                             (_cutoff(7),))}
        out = []
        for x in self.sources:
            st = json.loads(self.db.meta_get(f"news_src:{x.id}") or "{}")
            out.append({"id": x.id, "name": x.name, "tier": x.tier, "lang": x.lang, "home": x.home or None,
                        "ok": st.get("ok"), "last_ok": st.get("last_ok"), "message": st.get("message") or "",
                        "items_7d": counts.get(x.id, 0)})
        return out

    # --- recognition and storage --------------------------------------------------------------------------------------
    def _context(self) -> dict[str, Any]:
        """Per run: name indexes, the user's products and domains, recent titles for grouping."""
        malware = nlp.NameIndex()
        for r in self.db.query("SELECT DISTINCT malware AS m FROM c2 WHERE malware IS NOT NULL UNION "
                               "SELECT DISTINCT malware AS m FROM iocs WHERE malware IS NOT NULL"):
            name = str(r["m"] or "").strip()
            if name and not name.lower().startswith(("unknown", "win.", "elf.", "apk.", "osx.", "js.")):
                malware.add(name, name)
        prods = self.db.query("SELECT id, vendor, product FROM products")
        prod_phrase = {}
        for p in prods:
            phrase = (p["product"] or p["vendor"] or "").strip()
            if phrase:
                prod_phrase[phrase.lower()] = p
        vendors = {(p["vendor"] or "").strip().lower(): p for p in prods if (p["vendor"] or "").strip()}
        doms = {}
        for w in self.db.query("SELECT id, value FROM watchlist WHERE kind = 'domain'"):
            doms[w["value"].lower()] = w["id"]
        prod_cves: dict[str, int] = {}
        for r in self.db.query("SELECT product_id, cve FROM product_cves"):
            prod_cves.setdefault(r["cve"], r["product_id"])
        recent = []
        for r in self.db.query("SELECT id, title, cluster, cves, published FROM news WHERE published >= ? ORDER BY id DESC LIMIT 2000",
                               (_cutoff(CLUSTER_HOURS / 24),)):
            recent.append({"id": r["id"], "tok": nlp.title_tokens(r["title"]), "cluster": r["cluster"] or r["id"],
                           "cves": set(nlp.as_list(r["cves"])), "published": r["published"]})
        return {
            "actors": self.actors.index(), "malware": malware,
            "prod_rx": nlp.word_matcher(prod_phrase), "prod": prod_phrase,
            "vendor_rx": nlp.word_matcher(vendors), "vendors": vendors,
            "dom_rx": nlp.word_matcher(doms, domains=True), "doms": doms, "prod_cves": prod_cves, "recent": recent,
        }

    def analyse(self, title: str, text: str, ctx: dict[str, Any]) -> dict[str, Any]:
        """Recognition on headline + teaser. Pure function of the text and the indexes."""
        body = f"{title}. {text}"
        origin, mentioned = nlp.countries(body, self.places)
        origin_by = "text" if origin else None
        acts = ctx["actors"].find(body, 5, surface=True)  # names as written in the report
        if acts and origin is None:
            a = self.actors.get(acts[0])
            if a and a.get("country"):
                origin, origin_by = a["country"], "actor"
                if origin in mentioned:
                    mentioned.remove(origin)
        cves = nlp.cves(body)
        mine: list[dict[str, Any]] = []
        if ctx["prod_rx"]:
            for m in dict.fromkeys(x.lower() for x in ctx["prod_rx"].findall(body)):
                p = ctx["prod"].get(m)
                if p:
                    mine.append({"type": "product", "id": p["id"], "label": f"{p['vendor']} {p['product']}".strip()})
        if ctx["vendor_rx"]:
            seen = {x.get("id") for x in mine}
            for m in dict.fromkeys(x.lower() for x in ctx["vendor_rx"].findall(body)):
                p = ctx["vendors"].get(m)
                if p and p["id"] not in seen:
                    mine.append({"type": "vendor", "id": p["id"], "label": p["vendor"]})
        for c in cves:
            if c in ctx["prod_cves"]:
                mine.append({"type": "cve", "id": ctx["prod_cves"][c], "label": c})
        if ctx["dom_rx"]:
            for m in dict.fromkeys(x.lower() for x in ctx["dom_rx"].findall(body)):
                if m in ctx["doms"]:
                    mine.append({"type": "domain", "id": ctx["doms"][m], "label": m})
        return {
            "origin": origin, "origin_by": origin_by, "countries": mentioned, "actors": acts, "cves": cves,
            "malware": ctx["malware"].find(body, 5), "kinds": nlp.kinds(body), "mine": mine[:10],
        }

    def _store(self, src: Source, raw: dict[str, Any], ctx: dict[str, Any]) -> bool:
        title = strip_html(raw.get("title") or "")[:300]
        link = clean_url(raw.get("link"))
        if not title or not link or AD_RE.match(title):
            return False
        now = datetime.now(timezone.utc)
        pub = raw.get("date") or now
        if pub > now + timedelta(hours=1):
            pub = now
        if pub < now - timedelta(days=KEEP_DAYS_ON_FETCH):
            return False
        text = strip_html(raw.get("desc") or raw.get("content") or "")
        if text.lower().startswith(title.lower()):
            text = text[len(title):].lstrip(" .:-–")
        teaser = nlp.summary(text, 260)
        found = self.analyse(title, text[:1500], ctx)
        new_id = self.db.insert(
            "INSERT OR IGNORE INTO news(source, url, title, summary, image, published, fetched_at, lang, tier, origin, origin_by, "
            "countries, actors, cves, malware, kinds, mine) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (src.id, link, title, teaser or None, raw.get("image"), _iso(pub), utcnow(), src.lang, src.tier, found["origin"],
             found["origin_by"], json.dumps(found["countries"]), json.dumps(found["actors"]), json.dumps(found["cves"]),
             json.dumps(found["malware"]), json.dumps(found["kinds"]), json.dumps(found["mine"])))
        if not new_id:
            return False
        tok = nlp.title_tokens(title)
        cves = set(found["cves"])
        cluster = new_id
        for r in ctx["recent"]:
            if nlp.similar(tok, r["tok"]) or (cves and cves & r["cves"]):
                cluster = r["cluster"]
                break
        self.db.execute("UPDATE news SET cluster = ? WHERE id = ?", (cluster, new_id))
        ctx["recent"].insert(0, {"id": new_id, "tok": tok, "cluster": cluster, "cves": cves, "published": _iso(pub)})
        self._alerts(src, new_id, cluster, title, link, found["mine"])
        return True

    def _alerts(self, src: Source, item_id: int, cluster: int, title: str, link: str, mine: list[dict[str, Any]]) -> None:
        for m in mine:
            if m["type"] == "vendor":
                continue  # a vendor alone (e.g. "Microsoft") is shown on the item, not alerted
            sev = "high" if m["type"] == "domain" else "medium"
            alerts.add(self.db, "news", sev, f"news.{m['type']}", {"title": title[:200], "match": m["label"], "source": src.name},
                       f"{cluster}:{m['type']}:{m['label'].lower()}", url=link,
                       asset_id=m["id"] if m["type"] == "domain" else None,
                       product_id=m["id"] if m["type"] in ("product", "cve") else None)

    def reanalyse(self, days: int = 30) -> int:
        """Runs the recognition again on stored items (after the actor list or the user's products changed).
        Creates no alerts: those are only raised for new items."""
        ctx = self._context()
        rows = self.db.query("SELECT id, title, summary FROM news WHERE published >= ?", (_cutoff(days),))
        upd = []
        for r in rows:
            f = self.analyse(r["title"], r["summary"] or "", ctx)
            upd.append((f["origin"], f["origin_by"], json.dumps(f["countries"]), json.dumps(f["actors"]), json.dumps(f["cves"]),
                        json.dumps(f["malware"]), json.dumps(f["kinds"]), json.dumps(f["mine"]), r["id"]))
        self.db.execmany("UPDATE news SET origin=?, origin_by=?, countries=?, actors=?, cves=?, malware=?, kinds=?, mine=? "
                         "WHERE id=?", upd)
        self.db.meta_set("news_rev", utcnow())
        return len(rows)

    def _fingerprint(self) -> str:
        """Changes when the actor list, the watched products, their CVEs or the watched domains change."""
        p = self.db.query("SELECT COUNT(*) AS n, COALESCE(SUM(id), 0) AS s, COALESCE(GROUP_CONCAT(vendor || '/' || product, '|'), '') "
                          "AS v FROM (SELECT id, vendor, product FROM products ORDER BY id)")[0]
        c = self.db.query("SELECT COUNT(*) AS n, COALESCE(SUM(product_id), 0) AS s FROM product_cves")[0]
        d = self.db.query("SELECT COALESCE(GROUP_CONCAT(value, '|'), '') AS v FROM (SELECT value FROM watchlist "
                          "WHERE kind = 'domain' ORDER BY value)")[0]
        raw = "\n".join([self.db.meta_get("actors_loaded_at") or "", f"{p['n']}:{p['s']}:{p['v']}", f"{c['n']}:{c['s']}", d["v"]])
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def refresh_mine(self) -> bool:
        """Re-runs the recognition of the last 30 days if actors, products or domains changed since the last run."""
        fp = self._fingerprint()
        if fp == self.db.meta_get("news_fp"):
            return False
        self.reanalyse(30)
        self.db.meta_set("news_fp", fp)
        return True

    # --- preview images -------------------------------------------------------------------------------------------------
    async def _og_images(self, client: httpx.AsyncClient) -> None:
        rows = self.db.query("SELECT id, source, url FROM news WHERE image IS NULL AND og_tried = 0 AND published >= ? "
                             "ORDER BY id DESC LIMIT ?", (_cutoff(3), OG_PER_RUN))
        for r in rows:
            self.db.execute("UPDATE news SET og_tried = 1 WHERE id = ?", (r["id"],))
            src = self.by_id.get(r["source"])
            if not src:
                continue
            try:
                img = await self._og_fetch(client, r["url"], src)
            except (httpx.HTTPError, ToolError, ValueError, UnicodeError):
                img = None
            if img:
                self.db.execute("UPDATE news SET image = ? WHERE id = ?", (img, r["id"]))
            await asyncio.sleep(0.3)

    def _allowed(self, url: str, src: Source) -> bool:
        """The host is one of the source's domains or a subdomain of one (www.bsi.bund.de for bsi.bund.de)."""
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except ValueError:
            return False
        return bool(host) and any(host == d or host.endswith("." + d) for d in src.domains)

    async def _og_fetch(self, client: httpx.AsyncClient, url: str, src: Source) -> str | None:
        """Reads the head of the article page for its preview image. Only https pages of the source's own domain that
        resolve to public addresses; at most 3 redirects, each checked again; at most 400 KB."""
        for _ in range(4):
            if not url.startswith("https://") or not self._allowed(url, src):
                return None
            await resolve(urlsplit(url).hostname or "", False)
            req = client.build_request("GET", url, headers={"User-Agent": self.s.user_agent, "Accept": "text/html"}, timeout=12)
            r = await client.send(req, stream=True, follow_redirects=False)
            try:
                if r.status_code in (301, 302, 303, 307, 308):
                    nxt = r.headers.get("location") or ""
                    url = str(httpx.URL(url).join(nxt)) if nxt else ""
                    continue
                if r.status_code != 200 or "html" not in (r.headers.get("content-type") or "").lower():
                    return None
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf.extend(chunk)
                    if len(buf) >= MAX_PAGE_BYTES or b"</head>" in buf[-4096:]:
                        break
            finally:
                await r.aclose()
            return og_image(bytes(buf).decode(r.encoding or "utf-8", errors="replace"))
        return None

    def _prune(self) -> None:
        days = getattr(self.s, "news_retention_days", 90)
        self.db.execute("DELETE FROM news WHERE published < ?", (_cutoff(days),))
        self.db.execute("DELETE FROM news WHERE id NOT IN (SELECT id FROM news ORDER BY id DESC LIMIT 20000)")

    # --- queries ---------------------------------------------------------------------------------------------------------
    def _rows(self, days: float, *, tier: str | None = None, source: str | None = None, q: str | None = None,
              limit: int = 5000) -> list[dict[str, Any]]:
        sql = "SELECT * FROM news WHERE published >= ?"
        args: list[Any] = [_cutoff(days)]
        if tier in TIERS:
            sql += " AND tier = ?"
            args.append(tier)
        if source and source in self.by_id:
            sql += " AND source = ?"
            args.append(source)
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            sql += " AND (title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\')"
            args += [like, like]
        sql += " ORDER BY published DESC LIMIT ?"
        args.append(limit)
        rows = self.db.query(sql, args)
        for r in rows:
            for k in ("countries", "actors", "cves", "malware", "kinds", "mine"):
                r[k] = nlp.as_list(r[k])
        return rows

    def _item(self, head: dict[str, Any], members: list[dict[str, Any]]) -> dict[str, Any]:
        """A cluster (the same event reported by several sources) as one entry; recognition is merged over the members."""
        def union(key: str, limit: int = 10) -> list[Any]:
            out: list[Any] = []
            for m in members:
                for v in m[key]:
                    if v not in out:
                        out.append(v)
            return out[:limit]
        origin = head["origin"] or next((m["origin"] for m in members if m["origin"]), None)
        origin_by = head["origin_by"] if head["origin"] else next((m["origin_by"] for m in members if m["origin"]), None)
        countries = [c for c in union("countries") if c != origin]
        src_names = list(dict.fromkeys(self.by_id[m["source"]].name if m["source"] in self.by_id else m["source"] for m in members))
        image = head["image"] or next((m["image"] for m in members if m["image"]), None)
        mine, seen = [], set()
        for m in members:
            for x in m["mine"]:
                key = (x.get("type"), x.get("label"))
                if key not in seen:
                    seen.add(key)
                    mine.append(x)
        acts, canon = [], set()
        for a in union("actors", 12):  # "Fancy Bear" in one report and "APT28" in another are one actor
            c = self.actors.canonical(a) or a
            if c not in canon:
                canon.add(c)
                acts.append(a)
        src = self.by_id.get(head["source"])
        return {
            "id": head["id"], "cluster": head["cluster"] or head["id"], "title": head["title"], "summary": head["summary"],
            "url": head["url"], "image": image if self.s.news_images else None, "published": head["published"],
            "first": min(m["published"] for m in members), "latest": max(m["published"] for m in members),
            "source": {"id": head["source"], "name": src.name if src else head["source"], "tier": head["tier"]},
            "lang": head["lang"], "n": len(members), "sources": src_names, "origin": origin, "origin_by": origin_by,
            "countries": countries, "actors": acts[:6], "cves": union("cves"), "malware": union("malware", 6),
            "kinds": union("kinds"), "mine": mine[:10],
        }

    def clusters(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by: dict[int, list[dict[str, Any]]] = {}
        for r in rows:
            by.setdefault(r["cluster"] or r["id"], []).append(r)
        out = []
        for members in by.values():
            head = sorted(members, key=lambda r: (r["tier"] != "gov", r["published"]))[0]  # authority first, then earliest
            out.append(self._item(head, members))
        out.sort(key=lambda x: x["latest"], reverse=True)
        return out

    def matches(self, it: dict[str, Any], *, kind: str | None = None, country: str | None = None, origin: str | None = None,
                target: str | None = None, actor: str | None = None, mine: bool = False) -> bool:
        if kind and kind not in it["kinds"]:
            return False
        if country and country != it["origin"] and country not in it["countries"]:
            return False
        if origin and origin != it["origin"]:
            return False
        if target and target not in it["countries"]:
            return False
        if actor:
            want = self.actors.canonical(actor) or actor
            if not any((self.actors.canonical(a) or a) == want for a in it["actors"]):
                return False
        if mine and not any(x.get("type") != "vendor" for x in it["mine"]):
            return False
        return True

    def overview(self, days: float, home: list[str], **flt: Any) -> dict[str, Any]:
        rows = self._rows(days, tier=flt.pop("tier", None), source=flt.pop("source", None), q=flt.pop("q", None))
        items = [x for x in self.clusters(rows) if self.matches(x, **flt)]
        pairs: dict[tuple[str, str], int] = {}
        mentioned: dict[str, int] = {}
        origins: dict[str, int] = {}
        actors: dict[str, int] = {}
        alias_n: dict[tuple[str, str], int] = {}
        kinds: dict[str, int] = {}
        for it in items:
            if it["origin"]:
                origins[it["origin"]] = origins.get(it["origin"], 0) + 1
                for c in it["countries"][:3]:
                    pairs[(it["origin"], c)] = pairs.get((it["origin"], c), 0) + 1
            for c in it["countries"]:
                mentioned[c] = mentioned.get(c, 0) + 1
            for canon in dict.fromkeys(self.actors.canonical(a) or a for a in it["actors"]):
                actors[canon] = actors.get(canon, 0) + 1
            for a in it["actors"]:
                key = (self.actors.canonical(a) or a, a)
                alias_n[key] = alias_n.get(key, 0) + 1
            for k in it["kinds"]:
                kinds[k] = kinds.get(k, 0) + 1
        acts = []
        for canon, n in sorted(actors.items(), key=lambda x: -x[1])[:20]:
            a = self.actors.get(canon) or {}
            shown = max((k[1] for k in alias_n if k[0] == canon), key=lambda x: alias_n[(canon, x)])  # most used name
            acts.append({"name": shown, "canonical": canon, "n": n, "country": a.get("country")})
        home_set = set(home or ["DE"])
        return {
            "days": days,
            "kpis": {
                "events": len(items), "items": sum(x["n"] for x in items), "pairs": len(pairs),
                "home": sum(1 for x in items if home_set & ({x["origin"]} | set(x["countries"]))),
                "mine": sum(1 for x in items if any(m.get("type") != "vendor" for m in x["mine"])),
                "vendor": sum(1 for x in items if x["mine"]),
            },
            "home": sorted(home_set),
            "pairs": [{"origin": o, "target": t, "n": n} for (o, t), n in sorted(pairs.items(), key=lambda x: -x[1])[:60]],
            "countries": mentioned, "origins": origins, "actors": acts,
            "kinds": dict(sorted(kinds.items(), key=lambda x: -x[1])),
            "items": items[:80], "sources": self.source_list(), "images": bool(self.s.news_images),
        }

    def listing(self, days: float, offset: int = 0, limit: int = 40, **flt: Any) -> dict[str, Any]:
        rows = self._rows(days, tier=flt.pop("tier", None), source=flt.pop("source", None), q=flt.pop("q", None))
        items = [x for x in self.clusters(rows) if self.matches(x, **flt)]
        return {"total": len(items), "items": items[offset:offset + limit]}

    def detail(self, item_id: int) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM news WHERE id = ?", (item_id,))
        if not rows:
            return None
        cluster = rows[0]["cluster"] or rows[0]["id"]
        members = self.db.query("SELECT * FROM news WHERE cluster = ? OR id = ? ORDER BY published", (cluster, cluster))
        for r in members:
            for k in ("countries", "actors", "cves", "malware", "kinds", "mine"):
                r[k] = nlp.as_list(r[k])
        head = next(r for r in members if r["id"] == item_id) if any(r["id"] == item_id for r in members) else members[0]
        it = self._item(head, members)
        it["members"] = [{"id": m["id"], "title": m["title"], "url": m["url"], "published": m["published"], "lang": m["lang"],
                          "source": self.by_id[m["source"]].name if m["source"] in self.by_id else m["source"],
                          "tier": m["tier"]} for m in members]
        it["source_countries"] = sorted({self.by_id[m["source"]].home for m in members
                                         if m["source"] in self.by_id and self.by_id[m["source"]].home})
        # what the local data say about the recognised entities
        acts = []
        for name in it["actors"]:
            a = self.actors.get(name)
            if a:
                acts.append({"name": name, "canonical": a["name"], "country": a["country"], "sponsor": a["sponsor"],
                             "confidence": a["confidence"], "incident": a["incident"],
                             "synonyms": [x for x in [a["name"], *a["synonyms"]] if x.lower() != name.lower()][:6]})
        it["actor_info"] = acts
        cve_info = []
        for c in it["cves"]:
            kev = self.db.query("SELECT date_added, ransomware FROM kev WHERE cve = ?", (c,))
            ep = self.db.query("SELECT epss FROM epss WHERE cve = ?", (c,))
            cve_info.append({"cve": c, "kev": bool(kev), "kev_added": kev[0]["date_added"] if kev else None,
                             "ransomware": bool(kev and (kev[0]["ransomware"] or "").lower() == "known"),
                             "epss": ep[0]["epss"] if ep else None})
        it["cve_info"] = cve_info
        it["malware_info"] = [{"name": m, "c2_30d": self.db.query(
            "SELECT COUNT(*) AS n FROM c2 WHERE malware = ? AND COALESCE(last_seen, first_seen) >= ?", (m, _cutoff(30)))[0]["n"]}
            for m in it["malware"]]
        it["pair"] = self._pair(it["origin"], it["countries"][0]) if it["origin"] and it["countries"] else None
        return it

    def _pair(self, origin: str, target: str, days: int = 14) -> dict[str, Any]:
        """Daily series for a country pair: reports in the news and Cloudflare Radar's L7 share for origin -> target."""
        today = datetime.now(timezone.utc).date()
        labels = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
        news = dict.fromkeys(labels, 0)
        for r in self._rows(days):
            if r["origin"] == origin and target in r["countries"]:
                d = r["published"][:10]
                if d in news:
                    news[d] += 1
        radar = dict.fromkeys(labels)
        for h in self.db.hist_get("l7_pairs_1d", days + 2):
            if h["day"] in radar:
                for row in (h["data"] or {}).get("rows", []) if isinstance(h["data"], dict) else []:
                    if row.get("origin") == origin and row.get("target") == target:
                        radar[h["day"]] = row.get("value")
        return {"origin": origin, "target": target, "labels": labels, "news": [news[d] for d in labels],
                "radar": [radar[d] for d in labels]}

    # --- Gemini contexts (no own data except a flag; third-party text is passed as data) ----------------------------
    def ai_item(self, it: dict[str, Any]) -> dict[str, Any]:
        return {
            "article": {"title": it["title"], "teaser": it["summary"], "source": it["source"]["name"],
                        "source_type": "authority" if it["source"]["tier"] == "gov" else "specialist media",
                        "published": it["published"]},
            "same_event_reported_by": [{"source": m["source"], "title": m["title"], "published": m["published"]}
                                       for m in it.get("members", [])[:10]],
            "source_countries": it.get("source_countries", []),
            "recognised_automatically": {
                "kinds": it["kinds"], "origin_country": it["origin"],
                "origin_basis": {"text": "named in the text", "actor": "country of the recognised actor (MISP Galaxy)"}.get(
                    it["origin_by"] or "", None),
                "other_countries": it["countries"], "actors": it.get("actor_info", []), "malware": it.get("malware_info", []),
                "cves": it.get("cve_info", []),
            },
            "country_pair_series": it.get("pair"),
            "relates_to_own_assets": any(m.get("type") != "vendor" for m in it["mine"]),
        }

    def ai_overview(self, ov: dict[str, Any]) -> dict[str, Any]:
        return {
            "period_days": ov["days"], "events_total": ov["kpis"]["events"], "reports_total": ov["kpis"]["items"],
            "events": [{"title": x["title"], "sources": x["sources"][:5], "published": x["latest"], "kinds": x["kinds"],
                        "origin_country": x["origin"], "other_countries": x["countries"][:5], "actors": x["actors"][:3]}
                       for x in ov["items"][:30]],
            "country_pairs": ov["pairs"][:12], "kinds": ov["kinds"], "actors": ov["actors"][:10],
            "home_region": ov["home"], "home_region_events": ov["kpis"]["home"],
            "relates_to_own_assets": ov["kpis"]["mine"],
        }
