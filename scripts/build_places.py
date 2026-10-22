"""Builds frontend/data/places.json: populated places for placing cloud regions and data centers on the map (3.3).

Source: Natural Earth 1:10m populated places (public domain), github.com/nvkelso/natural-earth-vector.
Each entry: [name, ascii name, ISO-3166 alpha-2, first-level division, latitude, longitude, population].

Usage:
  curl -sSo /tmp/ne_places.geojson \
    https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_10m_populated_places_simple.geojson
  python3 scripts/build_places.py /tmp/ne_places.geojson
"""
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "frontend" / "data" / "places.json"


def main(src: str) -> None:
    fc = json.loads(Path(src).read_text(encoding="utf-8"))
    rows = []
    for f in fc["features"]:
        p = f["properties"]
        cc = str(p.get("iso_a2") or "").upper()
        if len(cc) != 2 or not cc.isalpha():
            continue
        try:
            lat, lon = round(float(p["latitude"]), 4), round(float(p["longitude"]), 4)
            pop = int(p.get("pop_max") or 0)
        except (TypeError, ValueError, KeyError):
            continue
        name = str(p.get("name") or "").strip()
        if not name:
            continue
        rows.append([name, str(p.get("nameascii") or name).strip(), cc, str(p.get("adm1name") or "").strip(), lat, lon, pop])
    rows.sort(key=lambda r: (r[2], -r[6], r[0]))
    meta = {"source": "Natural Earth 1:10m populated places", "license": "public domain", "fields":
            ["name", "ascii", "cc", "adm1", "lat", "lon", "pop"]}
    OUT.write_text(json.dumps({"meta": meta, "places": rows}, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"{len(rows)} places -> {OUT}")


if __name__ == "__main__":
    main(sys.argv[1])
