"""Public Telegram channels of hacktivist groups in the Weltlage.

- Channels are chosen by an administrator (no defaults); at most MAX_CHANNELS. Only public channels with a web
  preview (t.me/s/<channel>) can be read; no account, no API key, no login.
- Every TELEGRAM_INTERVAL_MIN the newest page of each channel is read (on the first run also one older page).
  Stored: text, time, views, forward source, links. Pictures and files are not loaded.
- Recognised automatically from the text: countries (German and English names, common Russian and Ukrainian
  spellings), kinds of incident, target domains and addresses, proof links (check-host.net reports).
- Claimed DDoS attacks on a country are compared with Cloudflare Radar (same rule as the Weltlage: corroborate.ddos).
  A post is a claim of the group; a rise in attack traffic is consistent with it, not proof.
- Translation into the interface language on request (Gemini), stored with the post.
Posts are removed after TELEGRAM_RETENTION_DAYS.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from .. import nlp, webfetch
from ..corroborate import Evidence
from ..db import DB, utcnow
from ..i18n import AppError
from .parse import Page, channel_name, parse

log = logging.getLogger("telegram")

MAX_CHANNELS = 30
MAX_PAGE = 2_000_000
PAUSE_S = 2.0
CHECK_DAYS = 3
# common Russian and Ukrainian country stems (start of a word, any case ending): targets of hacktivist posts
RU_STEMS = {
    "германи": "DE", "німеччин": "DE", "франци": "FR", "франці": "FR", "польш": "PL", "польщ": "PL", "литв": "LT",
    "латви": "LV", "латві": "LV", "эстони": "EE", "естоні": "EE", "украин": "UA", "україн": "UA", "итали": "IT",
    "італі": "IT", "чехи": "CZ", "чехі": "CZ", "нидерланд": "NL", "нідерланд": "NL", "бельги": "BE", "бельгі": "BE",
    "финлянд": "FI", "фінлянд": "FI", "швеци": "SE", "швеці": "SE", "норвеги": "NO", "норвегі": "NO", "испани": "ES",
    "іспані": "ES", "великобритани": "GB", "британи": "GB", "британі": "GB", "сша": "US", "америк": "US", "канад": "CA",
    "япони": "JP", "японі": "JP", "израил": "IL", "ізраїл": "IL", "румыни": "RO", "румуні": "RO", "болгари": "BG",
    "болгарі": "BG", "словаки": "SK", "словаччин": "SK", "австри": "AT", "австрі": "AT", "швейцари": "CH",
    "швейцарі": "CH", "венгри": "HU", "угорщин": "HU", "молдов": "MD", "грузи": "GE", "армени": "AM", "португали": "PT",
    "греци": "GR", "греці": "GR", "дани": "DK", "росси": "RU", "росі": "RU", "белорус": "BY",
    "білорус": "BY", "турци": "TR", "туреччин": "TR", "индии": "IN", "индия": "IN",
}
_RU_WORD = re.compile(r"[А-Яа-яЁёІіЇїЄєҐґ]{3,}")
KIND_EXTRA = {
    "ddos": ("ддос", "ddos-атак", "дудос"),
    "breach": ("утечк", "слив", "взлом", "витік", "злам"),
    "ransomware": ("шифровальщик", "вымогател"),
    "sabotage": ("вайпер",),
}
HOST_RE = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.|\[\.\]|\(\.\)))+(?:[a-z]{2,24}))(?![\w-])", re.I)
IP_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
IGNORE_HOSTS = ("t.me", "telegram.me", "telegram.org", "telegra.ph", "youtube.com", "youtu.be", "x.com", "twitter.com",
                "instagram.com", "facebook.com", "vk.com", "tiktok.com", "google.com", "check-host.net", "web.archive.org")
FILE_ENDINGS = (".jpg", ".png", ".gif", ".mp4", ".pdf", ".zip", ".rar", ".txt", ".exe", ".html", ".php", ".js", ".css")


def _ignored(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in IGNORE_HOSTS) or host.endswith(FILE_ENDINGS)


def analyse(text: str, links: list[str], places: nlp.Places) -> dict[str, Any]:
    """Countries, kinds of incident, targets (domains, IPv4) and proof links of a post."""
    origin, mentioned = nlp.countries(text, places)
    ccs = [c for c in [origin, *mentioned] if c]
    for word in _RU_WORD.findall(text[:nlp.MAX_TEXT]):
        w = word.lower()
        for stem, cc in RU_STEMS.items():
            if w.startswith(stem) and cc not in ccs:
                ccs.append(cc)
                break
    low = text.lower()
    kinds = nlp.kinds(text)
    for kind, words in KIND_EXTRA.items():
        if kind not in kinds and any(x in low for x in words):
            kinds.append(kind)
    targets: list[dict[str, str]] = []
    seen: set[str] = set()
    for m in HOST_RE.finditer(text[:nlp.MAX_TEXT]):
        host = re.sub(r"\[\.\]|\(\.\)", ".", m.group(1)).lower().rstrip(".")
        if host in seen or _ignored(host) or host.replace(".", "").isdigit():
            continue
        seen.add(host)
        targets.append({"kind": "domain", "value": host})
    for u in links:
        host = (urlsplit(u).hostname or "").lower()
        if host and host not in seen and not _ignored(host):
            seen.add(host)
            targets.append({"kind": "domain", "value": host})
    for m in IP_RE.finditer(text[:nlp.MAX_TEXT]):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            targets.append({"kind": "ip", "value": m.group(1)})
    proofs = [u for u in links if (urlsplit(u).hostname or "").lower().endswith("check-host.net")][:10]
    return {"countries": ccs[:8], "kinds": kinds[:6], "targets": targets[:25], "proofs": proofs}


class Telegram:
    def __init__(self, db: DB, centroids: Path | None, retention_days: int) -> None:
        self.db = db
        self.places = nlp.load_places(centroids)
        self.retention_days = retention_days
        self._busy = asyncio.Lock()

    # --- channels ----------------------------------------------------------------------------------------------------
    def channels(self) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT c.*, (SELECT COUNT(*) FROM tg_posts p WHERE p.channel = c.name) AS posts, "
                             "(SELECT MAX(date) FROM tg_posts p WHERE p.channel = c.name) AS latest FROM tg_channels c ORDER BY c.name")
        return rows

    def add(self, raw: str, note: str | None, by: str | None) -> dict[str, Any]:
        name = channel_name(raw)
        if not name:
            raise AppError("err.tg.name")
        if self.db.query("SELECT 1 FROM tg_channels WHERE name=?", (name,)):
            raise AppError("err.tg.exists", 409)
        if self.db.query("SELECT COUNT(*) AS n FROM tg_channels")[0]["n"] >= MAX_CHANNELS:
            raise AppError("err.tg.limit", max=MAX_CHANNELS)
        self.db.insert("INSERT INTO tg_channels(name, note, added_at, added_by) VALUES(?,?,?,?)", (name, note, utcnow(), by))
        return self.db.query("SELECT * FROM tg_channels WHERE name=?", (name,))[0]

    def remove(self, name: str) -> None:
        if not self.db.query("SELECT 1 FROM tg_channels WHERE name=?", (name,)):
            raise AppError("err.tg.unknown", 404)
        self.db.transaction([("DELETE FROM tg_posts WHERE channel=?", (name,)), ("DELETE FROM tg_channels WHERE name=?", (name,))])

    # --- reading -------------------------------------------------------------------------------------------------------
    async def _page(self, web: httpx.AsyncClient, name: str, before: int | None = None) -> Page:
        url = f"https://t.me/s/{name}" + (f"?before={before}" if before else "")
        page = await webfetch.fetch(web, url, headers={"User-Agent": webfetch.BROWSER_UA, "Accept": "text/html"},
                                    max_bytes=MAX_PAGE, timeout=20)
        if page.status != 200:
            raise AppError("err.tg.http", status=page.status)
        if "/s/" not in urlsplit(page.url).path:  # no public preview: t.me sends to the channel page instead
            raise AppError("err.tg.no_preview")
        return await asyncio.to_thread(parse, page.body, name, page.url)

    async def fetch(self, web: httpx.AsyncClient, name: str, ev: Evidence | None = None) -> int:
        """Reads one channel; returns the number of new posts. Errors are stored with the channel."""
        rows = self.db.query("SELECT last_post FROM tg_channels WHERE name=?", (name,))
        if not rows:
            raise AppError("err.tg.unknown", 404)
        first = not rows[0]["last_post"]
        now = utcnow()
        try:
            page = await self._page(web, name)
            posts = list(page.posts)
            if first and page.before:
                await asyncio.sleep(PAUSE_S)
                posts += (await self._page(web, name, page.before)).posts
        except (AppError, webfetch.FetchError) as exc:
            err = exc.key if isinstance(exc, AppError) else f"fetch:{exc.code}"
            self.db.execute("UPDATE tg_channels SET last_fetch=?, error=? WHERE name=?", (now, err, name))
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        ev = ev or await asyncio.to_thread(Evidence, self.db)
        new = 0
        for p in posts:
            if p.date < cutoff:
                continue
            a = analyse(p.text, p.links, self.places)
            n = self.db.insert(
                "INSERT OR IGNORE INTO tg_posts(channel, post_id, date, text, views, fwd, links, countries, targets, kinds, proofs, "
                "checks, fetched_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (name, p.post_id, p.date, p.text, p.views, p.fwd, json.dumps(p.links), json.dumps(a["countries"]),
                 json.dumps(a["targets"]), json.dumps(a["kinds"]), json.dumps(a["proofs"]),
                 json.dumps(self._checks(ev, p.date, a)), now))
            if n:
                new += 1
            elif p.views is not None:
                self.db.execute("UPDATE tg_posts SET views=? WHERE channel=? AND post_id=?", (p.views, name, p.post_id))
        last = max([p.post_id for p in posts] + [rows[0]["last_post"] or 0])
        self.db.execute("UPDATE tg_channels SET title=COALESCE(?, title), last_fetch=?, last_ok=?, error=NULL, last_post=? WHERE name=?",
                        (page.title, now, now, last, name))
        return new

    @staticmethod
    def _checks(ev: Evidence, date: str, a: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Claimed DDoS on a country: Cloudflare Radar shares around the day of the post (corroborate.ddos)."""
        if "ddos" not in a["kinds"] or not a["countries"]:
            return None
        try:
            d = datetime.strptime(date[:10], "%Y-%m-%d").date()
        except ValueError:
            return None
        return [ev.ddos(cc, d) for cc in a["countries"][:3]]

    async def collect(self, web: httpx.AsyncClient) -> None:
        """All channels, one after another, and the comparison of the last days again (measurements arrive later)."""
        if self._busy.locked():
            return
        async with self._busy:
            names = [r["name"] for r in self.db.query("SELECT name FROM tg_channels ORDER BY COALESCE(last_fetch, '')")]
            ev = await asyncio.to_thread(Evidence, self.db) if names else None
            for i, name in enumerate(names):
                if i:
                    await asyncio.sleep(PAUSE_S)
                try:
                    await self.fetch(web, name, ev)
                except Exception:  # one broken page must not stop the other channels
                    log.exception("telegram channel %s", name)
            if ev is not None:
                await asyncio.to_thread(self._recheck, ev)

    def _recheck(self, ev: Evidence) -> None:
        since = (datetime.now(timezone.utc) - timedelta(days=CHECK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for r in self.db.query("SELECT channel, post_id, date, countries, kinds FROM tg_posts WHERE date >= ? AND kinds LIKE '%\"ddos\"%'",
                               (since,)):
            try:
                a = {"countries": json.loads(r["countries"] or "[]"), "kinds": json.loads(r["kinds"] or "[]")}
            except ValueError:
                continue
            self.db.execute("UPDATE tg_posts SET checks=? WHERE channel=? AND post_id=?",
                            (json.dumps(self._checks(ev, r["date"], a)), r["channel"], r["post_id"]))

    # --- listing -------------------------------------------------------------------------------------------------------
    def listing(self, days: int, channel: str | None, country: str | None, q: str | None, limit: int, offset: int) -> dict[str, Any]:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        sql = " FROM tg_posts WHERE date >= ?"
        params: list[Any] = [since]
        if channel:
            sql += " AND channel = ?"
            params.append(channel)
        if country:
            sql += " AND countries LIKE ?"
            params.append(f'%"{country}"%')
        if q:
            sql += " AND (text LIKE ? ESCAPE '\\' OR targets LIKE ? ESCAPE '\\')"
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            params += [like, like]
        total = self.db.query("SELECT COUNT(*) AS n" + sql, params)[0]["n"]
        rows = self.db.query("SELECT channel, post_id, date, text, views, fwd, links, countries, targets, kinds, proofs, checks, "
                             "translation, translated_to" + sql + " ORDER BY date DESC, post_id DESC LIMIT ? OFFSET ?",
                             (*params, limit, offset))
        for r in rows:
            for k in ("links", "countries", "targets", "kinds", "proofs", "checks"):
                try:
                    r[k] = json.loads(r[k]) if r[k] else ([] if k != "checks" else None)
                except ValueError:
                    r[k] = [] if k != "checks" else None
            r["url"] = f"https://t.me/{r['channel']}/{r['post_id']}"
        counts: dict[str, int] = {}
        for r in self.db.query("SELECT countries FROM tg_posts WHERE date >= ?" + (" AND channel = ?" if channel else ""),
                               (since, channel) if channel else (since,)):
            try:
                for cc in json.loads(r["countries"] or "[]"):
                    counts[cc] = counts.get(cc, 0) + 1
            except ValueError:
                continue
        return {"total": total, "posts": rows, "countries": counts}

    def post(self, channel: str, post_id: int) -> dict[str, Any]:
        rows = self.db.query("SELECT * FROM tg_posts WHERE channel=? AND post_id=?", (channel, post_id))
        if not rows:
            raise AppError("err.tg.post", 404)
        return rows[0]

    def set_translation(self, channel: str, post_id: int, text: str, lang: str) -> None:
        self.db.execute("UPDATE tg_posts SET translation=?, translated_to=? WHERE channel=? AND post_id=?", (text, lang, channel, post_id))

    def prune(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.db.execute("DELETE FROM tg_posts WHERE date < ?", (cutoff,))
