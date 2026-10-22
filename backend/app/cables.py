"""Submarine cables from the bundled TeleGeography dataset (as of 2021-06, CC BY-NC-SA 3.0).

- per country: the cables landing there (country cards)
- by name: cables named in a report (3.3). Names are matched as whole words, case-insensitive; the short forms in
  brackets ("AAE-1", "EESF-2", "ACE") only as written, because they are often ordinary words in lower case. The
  caller only looks for names in reports about submarine cables (kind "cable"), so "Dunant" or "Apollo" elsewhere
  are not taken for cables.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

PAREN_RE = re.compile(r"^(.*?)\s*\(([^()]{2,20})\)\s*$")
_B = r"(?<![0-9A-Za-zÀ-ÖØ-öø-ÿ-])"   # no letter, digit or hyphen before
_A = r"(?![0-9A-Za-zÀ-ÖØ-öø-ÿ-])"    # nor after
MIN_NAME = 4
MAX_FOUND = 5


class Cables:
    def __init__(self, data_dir: Path) -> None:
        self.by_country: dict[str, dict[str, Any]] = defaultdict(lambda: {"cables": set(), "landing_points": []})
        self.meta: dict[str, Any] = {}
        self.cables: dict[str, dict[str, Any]] = {}
        self._names: dict[str, str] = {}  # lower-case full name -> id
        self._short: dict[str, str] = {}  # short form as written -> id
        self._rx: re.Pattern[str] | None = None
        self._rx_short: re.Pattern[str] | None = None
        path = data_dir / "landing-points.geojson"
        if path.exists():
            fc = json.loads(path.read_text(encoding="utf-8"))
            self.meta = fc.get("meta") or {}
            for f in fc.get("features") or []:
                p = f.get("properties") or {}
                cc = p.get("cc")
                if not cc:
                    continue
                entry = self.by_country[cc]
                entry["cables"].update(p.get("cables") or [])
                entry["landing_points"].append(p.get("name"))
        path = data_dir / "cables.geojson"
        if path.exists():
            self._load_names(json.loads(path.read_text(encoding="utf-8")))

    def _load_names(self, fc: dict[str, Any]) -> None:
        for f in fc.get("features") or []:
            p = f.get("properties") or {}
            cid, name = str(p.get("id") or ""), str(p.get("name") or "").strip()
            if not cid or not name:
                continue
            self.cables[cid] = {"id": cid, "name": name, "countries": list(p.get("countries") or []), "rfs": p.get("rfs")}
            m = PAREN_RE.match(name)
            full, short = (m.group(1).strip(), m.group(2).strip()) if m else (name, "")
            for n in {name, full}:
                if len(n) >= MIN_NAME:
                    self._names.setdefault(n.lower(), cid)
            if short and any(c.isupper() or c.isdigit() for c in short):
                self._short.setdefault(short, cid)
        if self._names:
            alts = sorted(self._names, key=len, reverse=True)
            self._rx = re.compile(_B + "(" + "|".join(re.escape(n) for n in alts) + ")" + _A, re.I)
        if self._short:
            alts = sorted(self._short, key=len, reverse=True)
            self._rx_short = re.compile(_B + "(" + "|".join(re.escape(n) for n in alts) + ")" + _A)

    def for_country(self, cc: str) -> dict[str, Any]:
        e = self.by_country.get(cc)
        if not e:
            return {"cables": [], "landing_points": [], "snapshot": self.meta.get("snapshot")}
        return {"cables": sorted(e["cables"]), "landing_points": sorted(e["landing_points"]), "snapshot": self.meta.get("snapshot")}

    def find(self, text: str) -> list[str]:
        """Ids of the cables named in a text (at most five, in order of appearance)."""
        t = (text or "")[:5000]
        hits: list[tuple[int, str]] = []
        if self._rx is not None:
            hits += [(m.start(), self._names[m.group(1).lower()]) for m in self._rx.finditer(t)]
        if self._rx_short is not None:
            hits += [(m.start(), self._short[m.group(1)]) for m in self._rx_short.finditer(t)]
        out: list[str] = []
        for _, cid in sorted(hits):
            if cid not in out:
                out.append(cid)
        return out[:MAX_FOUND]

    def info(self, ids: list[str]) -> list[dict[str, Any]]:
        return [dict(self.cables[i]) for i in ids if i in self.cables]
