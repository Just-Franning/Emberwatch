"""Reading the public web preview of a Telegram channel (https://t.me/s/<channel>): posts with id, time, text, views,
forward source and links, the channel title and the link to older posts. The markup is the one snscrape reads
(div.tgme_widget_message[data-post], a.tgme_widget_message_date time[datetime], div.tgme_widget_message_text,
a.tme_messages_more[data-before]). Only text is taken; pictures, videos and stickers are not loaded."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from .. import htmlparse

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
MAX_TEXT = 4000
MAX_LINKS = 20
_VIEWS = re.compile(r"^([\d.,]+)\s*([KMB]?)$", re.I)


@dataclass
class Post:
    post_id: int
    date: str  # ISO 8601 UTC
    text: str
    views: int | None = None
    fwd: str | None = None
    links: list[str] = field(default_factory=list)


@dataclass
class Page:
    title: str | None = None
    description: str | None = None
    posts: list[Post] = field(default_factory=list)
    before: int | None = None  # id for the next older page


def channel_name(raw: str) -> str | None:
    """'@name', 'name', 't.me/name', 'https://t.me/s/name' -> 'name' (lower case) or None."""
    s = (raw or "").strip()
    m = re.match(r"^(?:https?://)?(?:www\.)?t(?:elegram)?\.me/(?:s/)?([A-Za-z0-9_]+)/?$", s)
    if m:
        s = m.group(1)
    s = s.lstrip("@")
    return s.lower() if NAME_RE.match(s) else None


def views(raw: str | None) -> int | None:
    m = _VIEWS.match((raw or "").strip())
    if not m:
        return None
    num = float(m.group(1).replace(",", "."))
    return int(num * {"": 1, "K": 1_000, "M": 1_000_000, "B": 1_000_000_000}[m.group(2).upper()])


def _iso(raw: str | None) -> str | None:
    try:
        d = datetime.fromisoformat((raw or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(node: object) -> str:
    for br in node.find_all("br"):  # type: ignore[attr-defined]
        br.replace_with("\n")
    lines = [re.sub(r"[ \t ]+", " ", x).strip() for x in node.get_text().splitlines()]  # type: ignore[attr-defined]
    out = "\n".join(x for x in lines if x)
    return out[:MAX_TEXT]


def parse(html: str | bytes, channel: str, base: str = "https://t.me/") -> Page:
    s = htmlparse.soup(html)
    page = Page()
    info = s.find("div", class_="tgme_channel_info")
    if info:
        title = info.find("div", class_="tgme_channel_info_header_title")
        if title:
            page.title = " ".join(title.get_text(" ").split())[:120] or None
        desc = info.find("div", class_="tgme_channel_info_description")
        if desc:
            page.description = _text(desc)[:500] or None
    for node in s.find_all("div", attrs={"class": "tgme_widget_message", "data-post": True}):
        ref = str(node.get("data-post") or "")
        owner, _, num = ref.partition("/")
        if owner.lower() != channel.lower() or not num.isdigit():
            continue  # a post of another channel embedded in the page
        date_a = node.find("a", class_="tgme_widget_message_date")
        t = date_a.find("time") if date_a else None
        date = _iso(t.get("datetime") if t else None)
        if not date:
            continue
        msg = node.find("div", class_="tgme_widget_message_text")
        links: list[str] = []
        for a in (msg.find_all("a", href=True) if msg else []):
            href = urljoin(base, str(a["href"]))
            if urlsplit(href).scheme in ("http", "https") and href not in links:
                links.append(href[:500])
        prev = node.find("a", class_="tgme_widget_message_link_preview", href=True)
        if prev:
            href = urljoin(base, str(prev["href"]))
            if urlsplit(href).scheme in ("http", "https") and href not in links:
                links.append(href[:500])
        fwd = node.find(class_="tgme_widget_message_forwarded_from_name")
        v = node.find("span", class_="tgme_widget_message_views")
        page.posts.append(Post(
            post_id=int(num), date=date, text=_text(msg) if msg else "", views=views(v.get_text() if v else None),
            fwd=" ".join(fwd.get_text(" ").split())[:120] if fwd else None, links=links[:MAX_LINKS]))
    more = s.find("a", attrs={"class": "tme_messages_more", "data-before": True})
    if more and str(more.get("data-before")).isdigit():
        page.before = int(str(more["data-before"]))
    return page
