"""Submarine cables per country from the bundled TeleGeography dataset (as of 2021-06, CC BY-NC-SA 3.0)."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


class Cables:
    def __init__(self, data_dir: Path) -> None:
        self.by_country: dict[str, dict[str, Any]] = defaultdict(lambda: {"cables": set(), "landing_points": []})
        self.meta: dict[str, Any] = {}
        path = data_dir / "landing-points.geojson"
        if not path.exists():
            return
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

    def for_country(self, cc: str) -> dict[str, Any]:
        e = self.by_country.get(cc)
        if not e:
            return {"cables": [], "landing_points": [], "snapshot": self.meta.get("snapshot")}
        return {"cables": sorted(e["cables"]), "landing_points": sorted(e["landing_points"]), "snapshot": self.meta.get("snapshot")}
