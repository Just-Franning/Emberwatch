"""Threat actors from the MISP Galaxy (cluster "threat-actor", CC0 1.0 / BSD 2-Clause, https://github.com/MISP/misp-galaxy).

Names, synonyms, suspected country and state sponsor, suspected victims, target categories and references. The list
is used to recognise actor names in news and for the object pages of actors. It is loaded once a week.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .db import DB, utcnow
from .nlp import NameIndex

log = logging.getLogger("emberwatch.actors")

GALAXY_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
MAX_BYTES = 8 * 1024 * 1024
HTTPS_RE = re.compile(r"^https://[^\s\"'<>]{4,500}$")
CC_RE = re.compile(r"^[A-Z]{2}$")
SPONSOR_CC = {  # CFR names of state sponsors -> ISO
    "russian federation": "RU", "russia": "RU", "china": "CN", "iran (islamic republic of)": "IR", "iran": "IR",
    "korea (democratic people's republic of)": "KP", "north korea": "KP", "korea (republic of)": "KR",
    "united states": "US", "united kingdom": "GB", "israel": "IL", "viet nam": "VN", "vietnam": "VN", "pakistan": "PK",
    "india": "IN", "belarus": "BY", "turkey": "TR", "lebanon": "LB", "syrian arab republic": "SY", "ukraine": "UA",
}


def _list(v: Any, limit: int = 40) -> list[str]:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return []
    return [str(x).strip()[:120] for x in v if isinstance(x, (str, int)) and str(x).strip()][:limit]


def parse(data: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    values = data.get("values") if isinstance(data, dict) else None
    for v in values if isinstance(values, list) else []:
        if not isinstance(v, dict):
            continue
        name = str(v.get("value") or "").strip()[:120]
        if not name:
            continue
        m = v.get("meta") if isinstance(v.get("meta"), dict) else {}
        syn = _list(m.get("synonyms"), 60)
        for na in _list(m.get("name-attribution"), 40):  # "Name:uuid of the naming vendor"
            n = na.split(":", 1)[0].strip()
            if n and n != name and n not in syn:
                syn.append(n)
        cc = str(m.get("country") or "").strip().upper()
        sponsor = str(m.get("cfr-suspected-state-sponsor") or "").strip()[:80]
        if not CC_RE.match(cc):
            cc = SPONSOR_CC.get(sponsor.lower(), "")
        out.append({
            "name": name, "country": cc or None, "sponsor": sponsor or None, "synonyms": syn[:80],
            "victims": _list(m.get("cfr-suspected-victims"), 30), "targets": _list(m.get("cfr-target-category"), 20),
            "sectors": _list(m.get("targeted-sector"), 20), "incident": ", ".join(_list(m.get("cfr-type-of-incident"), 5)) or None,
            "confidence": str(m.get("attribution-confidence") or "").strip()[:10] or None,
            "description": str(v.get("description") or "").strip()[:1500] or None,
            "refs": [r for r in _list(m.get("refs"), 30) if HTTPS_RE.match(r)][:20],
        })
    return out


class Actors:
    def __init__(self, db: DB) -> None:
        self.db = db
        self._index: NameIndex | None = None

    def count(self) -> int:
        return self.db.query("SELECT COUNT(*) AS n FROM actors")[0]["n"]

    async def collect(self, client: httpx.AsyncClient, ua: str) -> int:
        """Loads the galaxy if the stored copy is older than 7 days. Returns the number of actors."""
        last = self.db.meta_get("actors_loaded_at") or ""
        if last and self.count() and last > _days_ago(7):
            return self.count()
        try:
            async with client.stream("GET", GALAXY_URL, headers={"User-Agent": ua, "Accept": "application/json"}, timeout=60) as r:
                r.raise_for_status()
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf.extend(chunk)
                    if len(buf) > MAX_BYTES:
                        raise ValueError("galaxy file too large")
            rows = parse(json.loads(bytes(buf)))
        except (httpx.HTTPError, ValueError) as exc:
            self.db.status("misp_actors", False, f"{exc.__class__.__name__}: {str(exc)[:200]}")
            return self.count()
        if len(rows) < 100:  # an empty or truncated file must not wipe the list
            self.db.status("misp_actors", False, "unexpected content")
            return self.count()
        now = utcnow()
        self.db.transaction([("DELETE FROM actors", ())] + [(
            "INSERT OR REPLACE INTO actors(name, country, sponsor, synonyms, victims, targets, sectors, incident, confidence, "
            "description, refs, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (a["name"], a["country"], a["sponsor"], json.dumps(a["synonyms"]), json.dumps(a["victims"]),
             json.dumps(a["targets"]), json.dumps(a["sectors"]), a["incident"], a["confidence"], a["description"],
             json.dumps(a["refs"]), now)) for a in rows])
        self.db.meta_set("actors_loaded_at", now)
        self.db.status("misp_actors", True, "", len(rows))
        self._index = None
        return len(rows)

    def index(self) -> NameIndex:
        if self._index is None:
            idx = NameIndex()
            for r in self.db.query("SELECT name, synonyms FROM actors"):
                idx.add(r["name"], r["name"])
                for s in json.loads(r["synonyms"] or "[]"):
                    idx.add(s, r["name"])
            self._index = idx
        return self._index

    def canonical(self, name: str) -> str | None:
        """Main name of an actor for any of its names (case-insensitive)."""
        return self.index().canonical(name) or next(
            (r["name"] for r in self.db.query("SELECT name FROM actors WHERE name = ? COLLATE NOCASE", (name,))), None)

    def get(self, name: str) -> dict[str, Any] | None:
        """Actor by name or synonym (case-insensitive)."""
        rows = self.db.query("SELECT * FROM actors WHERE name = ? COLLATE NOCASE", (name,))
        if not rows:
            canonical = self.index().phrases.get(" ".join(name.lower().split()))
            if canonical:
                rows = self.db.query("SELECT * FROM actors WHERE name = ?", (canonical,))
        if not rows:
            return None
        r = dict(rows[0])
        for k in ("synonyms", "victims", "targets", "sectors", "refs"):
            r[k] = json.loads(r[k] or "[]")
        return r

    def search(self, q: str, limit: int = 8) -> list[dict[str, Any]]:
        q = q.strip()
        if len(q) < 3:
            return []
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        return self.db.query("SELECT name, country FROM actors WHERE name LIKE ? ESCAPE '\\' OR synonyms LIKE ? ESCAPE '\\' "
                             "ORDER BY length(name) LIMIT ?", (like, like, limit))


def _days_ago(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%SZ")
