"""GDELT DOC 2.0 API – worldwide press about cyber attacks (3.3, optional, SOURCES_DISABLE=gdelt).

GDELT monitors news worldwide; the DOC API returns matching articles (headline, link, time, language, publisher
country). Emberwatch asks for English and German articles of the last hours, recognises countries, actors and kinds in
the headline (no article text is read) and stores them as tier "web": shown only when "worldwide press" is chosen,
never mixed into the curated reports, never raising alerts. Terms: free for any use, with a citation and link to the
GDELT Project (https://www.gdeltproject.org/).

Response: {"articles": [{"url", "url_mobile", "title", "seendate": "YYYYMMDDTHHMMSSZ", "socialimage", "domain",
"language", "sourcecountry"}]}. An invalid query is answered with status 200 and an HTML page; the JSON can contain
control characters (parsed with strict=False).
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import httpx

API = "https://api.gdeltproject.org/api/v2/doc/doc"
QUERIES = (
    ("en", '(cyberattack OR "cyber attack" OR ransomware OR hackers OR ddos OR "data breach" OR malware OR "zero-day") '
           "sourcelang:english"),
    ("de", "(cyberangriff OR hackerangriff OR ransomware OR datenleck OR ddos OR schadsoftware OR hacker) sourcelang:german"),
)
MAX_RECORDS = 150
MAX_BYTES = 3 * 1024 * 1024
LANGS = {"english": "en", "german": "de"}
PAUSE_S = 6


def parse(data: bytes, lang: str) -> list[dict[str, Any]]:
    """Articles as raw items for News._store (title, link, date, lang). Broken entries are skipped."""
    try:
        body = json.loads(data.decode("utf-8", errors="replace"), strict=False)
    except ValueError as exc:
        raise ValueError("no JSON (GDELT answers invalid queries with an HTML page)") from exc
    arts = body.get("articles") if isinstance(body, dict) else None
    out = []
    for a in arts if isinstance(arts, list) else []:
        if not isinstance(a, dict):
            continue
        title, url = str(a.get("title") or "").strip(), str(a.get("url") or "").strip()
        if not title or not url:
            continue
        try:
            d = datetime.strptime(str(a.get("seendate") or ""), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            d = None
        out.append({"title": title[:300], "link": url, "date": d, "desc": "", "content": "", "image": None,
                    "lang": LANGS.get(str(a.get("language") or "").lower(), lang)})
    return out


async def fetch(client: httpx.AsyncClient, ua: str, timespan: str = "3h") -> list[dict[str, Any]]:
    """Both queries; one failing query does not stop the other. Raises only if both fail."""
    items: list[dict[str, Any]] = []
    errors = []
    for i, (lang, query) in enumerate(QUERIES):
        if i:
            await asyncio.sleep(PAUSE_S)  # GDELT asks for at most one request every few seconds
        params = {"query": query, "mode": "artlist", "format": "json", "maxrecords": str(MAX_RECORDS),
                  "timespan": timespan, "sort": "datedesc"}
        try:
            r = await client.get(API, params=params, headers={"User-Agent": ua, "Accept": "application/json"}, timeout=40)
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code}")
            if len(r.content) > MAX_BYTES:
                raise ValueError("answer too large")
            if "html" in (r.headers.get("content-type") or "").lower():
                raise ValueError("GDELT rejected the query")
            items += parse(r.content, lang)
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"{lang}: {exc.__class__.__name__}")
    if errors and not items and len(errors) == len(QUERIES):
        raise ValueError("; ".join(errors))
    return items
