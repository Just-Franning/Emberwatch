"""MITRE ATT&CK Enterprise (3.3, optional, SOURCES_DISABLE=attack).

Groups (intrusion sets), techniques, software and which group or software uses which technique, from MITRE's STIX
bundle on GitHub (mitre-attack/attack-stix-data, about 55 MB). The bundle is read object by object (a few MB of memory
instead of several hundred) and only when it changed (ETag). Revoked and deprecated objects are left out.

Licence: royalty-free, also commercially; every copy must carry MITRE's copyright and licence:
"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

Groups are linked to the actors of the MISP Galaxy and software to the malware names of the local data by name and
alias (case-insensitive).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any, Iterator, TextIO

import httpx

from .db import DB, utcnow

log = logging.getLogger("emberwatch.attack")

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MAX_BYTES = 150 * 1024 * 1024
CHUNK = 1 << 20
NOTICE = "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
KINDS = {"intrusion-set": "group", "attack-pattern": "technique", "malware": "software", "tool": "software",
         "x-mitre-tactic": "tactic"}
EXT_RE = re.compile(r"^(G\d{4}|T\d{4}(?:\.\d{3})?|S\d{4}|TA\d{4})$")


def iter_objects(fh: TextIO) -> Iterator[dict[str, Any]]:
    """The objects of a STIX bundle {"type": "bundle", ..., "objects": [ ... ]}, one at a time."""
    dec = json.JSONDecoder()
    buf = ""
    pos = -1
    while pos < 0:  # find the start of the objects array
        chunk = fh.read(CHUNK)
        if not chunk:
            return
        buf += chunk
        m = re.search(r'"objects"\s*:\s*\[', buf)
        if m:
            pos = m.end()
        elif len(buf) > 4 * CHUNK:
            raise ValueError("no objects array")
    eof = False
    while True:
        while pos < len(buf) and buf[pos] in " \t\r\n,":
            pos += 1
        if pos < len(buf) and buf[pos] == "]":
            return
        try:
            if pos >= len(buf):
                raise ValueError("need more")
            obj, end = dec.raw_decode(buf, pos)
        except ValueError:
            if eof:
                raise ValueError("truncated bundle") from None
            chunk = fh.read(CHUNK)
            if not chunk:
                eof = True
            buf = buf[pos:] + chunk
            pos = 0
            continue
        if isinstance(obj, dict):
            yield obj
        pos = end
        if pos > CHUNK:  # drop what was read
            buf = buf[pos:]
            pos = 0


def _ext(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            eid = str(ref.get("external_id") or "")
            url = str(ref.get("url") or "")
            return (eid if EXT_RE.match(eid) else None), (url if url.startswith("https://attack.mitre.org/") else None)
    return None, None


def parse(fh: TextIO) -> tuple[list[tuple], list[tuple[str, str]], str | None, list[str]]:
    """(objects, uses relations, ATT&CK version, tactic order) of the bundle."""
    objs: dict[str, tuple] = {}
    uses: list[tuple[str, str]] = []
    version = None
    order: list[str] = []
    for o in iter_objects(fh):
        t = o.get("type")
        if t == "x-mitre-collection":
            version = str(o.get("x_mitre_version") or "")[:10] or None
            continue
        if t == "x-mitre-matrix":
            order = [str(x) for x in o.get("tactic_refs") or []]
            continue
        if t == "relationship":
            if o.get("relationship_type") == "uses" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
                s, d = str(o.get("source_ref") or ""), str(o.get("target_ref") or "")
                if s.startswith(("intrusion-set--", "malware--", "tool--")) and d.startswith(("attack-pattern--", "malware--", "tool--")):
                    uses.append((s, d))
            continue
        kind = KINDS.get(t or "")
        if not kind or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        eid, url = _ext(o)
        name = str(o.get("name") or "").strip()[:200]
        if not eid or not name:
            continue
        aliases = [str(a)[:120] for a in (o.get("aliases") or o.get("x_mitre_aliases") or []) if str(a).strip() and str(a) != name][:30]
        tactics = [str(p.get("phase_name"))[:60] for p in o.get("kill_chain_phases") or []
                   if isinstance(p, dict) and p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")]
        if kind == "tactic":
            aliases = [str(o.get("x_mitre_shortname") or "")[:60]]
        objs[o["id"]] = (o["id"], kind, eid, name, json.dumps(aliases), json.dumps(tactics),
                         int(bool(o.get("x_mitre_is_subtechnique"))), t if kind == "software" else None, 0, url)
    ids = set(objs)
    uses = [(s, d) for s, d in dict.fromkeys(uses) if s in ids and d in ids]
    rows = []
    for sid, row in objs.items():
        ord_ = order.index(sid) + 1 if sid in order else 0
        rows.append(row[:8] + (ord_,) + row[9:])
    return rows, uses, version, order


class Attack:
    def __init__(self, db: DB, data_dir: Path) -> None:
        self.db = db
        self.data_dir = data_dir
        self._index: dict[str, str] | None = None  # lower-case name/alias of a group -> stix id
        self._sw: dict[str, str] | None = None

    @property
    def loaded(self) -> bool:
        return bool(self.db.query("SELECT 1 FROM attack_objects LIMIT 1"))

    async def collect(self, client: httpx.AsyncClient, ua: str) -> bool:
        """Downloads the bundle if it changed (ETag) and replaces the stored data. Returns True if it was loaded."""
        headers = {"User-Agent": ua}
        etag = self.db.meta_get("attack_etag")
        if etag and self.loaded:
            headers["If-None-Match"] = etag
        tmp = self.data_dir / "attack.download"
        try:
            async with client.stream("GET", URL, headers=headers, timeout=180) as r:
                if r.status_code == 304:
                    self.db.status("mitre_attack", True, "", self._count())
                    return False
                if r.status_code != 200:
                    raise ValueError(f"HTTP {r.status_code}")
                size = 0
                with tmp.open("wb") as fh:
                    async for chunk in r.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_BYTES:
                            raise ValueError("bundle too large")
                        fh.write(chunk)
                new_etag = r.headers.get("etag")
            rows, uses, version, _ = await asyncio.to_thread(self._parse_file, tmp)
            if len(rows) < 500:  # a truncated or foreign file must not replace good data
                raise ValueError(f"only {len(rows)} objects")
            await asyncio.to_thread(self._store, rows, uses)
            if new_etag:
                self.db.meta_set("attack_etag", new_etag[:200])
            self.db.meta_set("attack_version", version or "")
            self.db.meta_set("attack_loaded_at", utcnow())
            self._index = self._sw = None
            self.db.status("mitre_attack", True, "", self._count())
            return True
        except Exception as exc:  # network, format: the previous data stay
            log.warning("ATT&CK: %s", exc.__class__.__name__)
            self.db.status("mitre_attack", False, f"{exc.__class__.__name__}: {str(exc)[:160]}")
            return False
        finally:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _parse_file(path: Path) -> tuple[list[tuple], list[tuple[str, str]], str | None, list[str]]:
        with path.open("r", encoding="utf-8") as fh:
            return parse(fh)

    def _store(self, rows: list[tuple], uses: list[tuple[str, str]]) -> None:
        self.db.replace([
            ("DELETE FROM attack_uses", [()]),
            ("DELETE FROM attack_objects", [()]),
            ("INSERT INTO attack_objects(stix_id, kind, ext_id, name, aliases, tactics, sub, sw_type, ord, url) "
             "VALUES(?,?,?,?,?,?,?,?,?,?)", rows),
            ("INSERT OR IGNORE INTO attack_uses(src, dst) VALUES(?,?)", uses),
        ])

    def _count(self) -> int:
        return self.db.query("SELECT COUNT(*) AS n FROM attack_objects WHERE kind = 'group'")[0]["n"]

    # --- lookups ----------------------------------------------------------------------------------------------------
    def _names(self, kind: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for r in self.db.query("SELECT stix_id, name, aliases FROM attack_objects WHERE kind = ?", (kind,)):
            for n in [r["name"], *json.loads(r["aliases"] or "[]")]:
                out.setdefault(str(n).strip().lower(), r["stix_id"])
        return out

    def group_for(self, names: list[str]) -> dict[str, Any] | None:
        """The ATT&CK group of an actor, by its name or one of its aliases."""
        if self._index is None:
            self._index = self._names("group")
        sid = next((self._index[n.strip().lower()] for n in names if n and n.strip().lower() in self._index), None)
        return self._object(sid) if sid else None

    def software_for(self, name: str) -> dict[str, Any] | None:
        if self._sw is None:
            self._sw = self._names("software")
        sid = self._sw.get((name or "").strip().lower())
        return self._object(sid) if sid else None

    def _object(self, sid: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM attack_objects WHERE stix_id = ?", (sid,))
        if not rows:
            return None
        r = dict(rows[0])
        r["aliases"] = json.loads(r["aliases"] or "[]")
        r["tactics"] = json.loads(r["tactics"] or "[]")
        return r

    def used_by(self, sid: str) -> dict[str, list[dict[str, Any]]]:
        """Techniques (with their tactics, in matrix order) and software an object uses."""
        rows = self.db.query("SELECT o.* FROM attack_uses u JOIN attack_objects o ON o.stix_id = u.dst WHERE u.src = ?", (sid,))
        tactics = {r["aliases"] and json.loads(r["aliases"])[0]: (r["ord"], r["name"], r["ext_id"])
                   for r in self.db.query("SELECT name, ext_id, aliases, ord FROM attack_objects WHERE kind = 'tactic'")}
        techniques, software = [], []
        for r in rows:
            if r["kind"] == "technique":
                tac = [t for t in json.loads(r["tactics"] or "[]") if t in tactics]
                tac.sort(key=lambda t: tactics[t][0] or 99)
                techniques.append({"id": r["ext_id"], "name": r["name"], "url": r["url"], "sub": bool(r["sub"]),
                                   "tactics": [{"short": t, "name": tactics[t][1], "id": tactics[t][2]} for t in tac]})
            elif r["kind"] == "software":
                software.append({"id": r["ext_id"], "name": r["name"], "url": r["url"], "type": r["sw_type"]})
        techniques.sort(key=lambda x: ((tactics[x["tactics"][0]["short"]][0] if x["tactics"] else 99), x["id"]))
        software.sort(key=lambda x: x["name"].lower())
        return {"techniques": techniques, "software": software}

    def users_of(self, sid: str) -> list[dict[str, Any]]:
        """Groups that use a piece of software."""
        return [{"id": r["ext_id"], "name": r["name"], "url": r["url"]} for r in self.db.query(
            "SELECT o.ext_id, o.name, o.url FROM attack_uses u JOIN attack_objects o ON o.stix_id = u.src "
            "WHERE u.dst = ? AND o.kind = 'group' ORDER BY o.name", (sid,))]

    def version(self) -> str | None:
        return self.db.meta_get("attack_version") or None
