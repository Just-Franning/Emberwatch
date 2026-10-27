"""Builds frontend/data/cables.geojson and landing-points.geojson from the TeleGeography dataset.

Source: repository "www.submarinecablemap.com" by TeleGeography (as of June 2021),
licence CC BY-NC-SA 3.0 (see the repository README). The original repository is offline;
the data is available e.g. in the fork github.com/stealthscooty/www.submarinecablemap.com.

Usage:
  pip install shapely
  git clone --depth 1 https://github.com/stealthscooty/www.submarinecablemap.com.git /tmp/tg
  python3 scripts/build_cables.py /tmp/tg/public/api/v2

Landing points get an ISO country code via point-in-polygon (Natural Earth 50m),
cables the list of countries of their landing points.
"""
import json
import sys
import urllib.request
from pathlib import Path

from shapely.geometry import Point, shape
from shapely.strtree import STRtree

OUT = Path(__file__).resolve().parent.parent / "frontend" / "data"
NE50 = "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_admin_0_countries.geojson"


def rnd(c):
    if isinstance(c[0], (int, float)):
        return [round(c[0], 3), round(c[1], 3)]
    return [rnd(x) for x in c]


def main(src: Path) -> None:
    with urllib.request.urlopen(NE50, timeout=120) as r:
        ne = json.load(r)
    polys, isos, by_name = [], [], {}
    feats_ne = [f for f in ne["features"] if f["properties"].get("ISO_A2_EH") not in ("-99", None)]
    for f in feats_ne:
        polys.append(shape(f["geometry"]))
        isos.append(f["properties"]["ISO_A2_EH"])
    # The country's own names first; the sovereign state only as a fallback, otherwise "Finland" would match
    # Åland (SOVEREIGNT "Finland") and "Denmark" Greenland, depending on the order of the features.
    for keys in (("NAME", "NAME_LONG", "ADMIN", "NAME_EN"), ("SOVEREIGNT",)):
        for f in feats_ne:
            for key in keys:
                if f["properties"].get(key):
                    by_name.setdefault(f["properties"][key].lower(), f["properties"]["ISO_A2_EH"])
    tree = STRtree(polys)

    def country(lon: float, lat: float, name: str) -> str | None:
        # 1) country name from "place, country" (TeleGeography spelling), 2) polygon, 3) nearest polygon <= 0.5°
        tail = name.rsplit(",", 1)[-1].strip().lower()
        if tail in by_name:
            return by_name[tail]
        p = Point(lon, lat)
        for i in tree.query(p, predicate="intersects"):
            return isos[int(i)]
        i = tree.nearest(p)  # coastal points are often just outside the 50m polygons
        if i is not None and polys[int(i)].distance(p) <= 0.5:
            return isos[int(i)]
        return None

    lp_geo = json.loads((src / "landing-point" / "landing-point-geo.json").read_text())
    lps = {}
    for f in lp_geo["features"]:
        lon, lat = f["geometry"]["coordinates"]
        lps[f["properties"]["id"]] = {
            "name": f["properties"]["name"],
            "cc": country(lon, lat, f["properties"]["name"]),
            "coords": [round(lon, 4), round(lat, 4)],
            "cables": [],
        }

    cable_geo = json.loads((src / "cable" / "cable-geo.json").read_text())
    feats = []
    unmatched = 0
    for f in cable_geo["features"]:
        slug = f["properties"]["slug"]
        detail_path = src / "cable" / f"{slug}.json"
        detail = json.loads(detail_path.read_text()) if detail_path.exists() else {}
        countries = set()
        for lp in detail.get("landing_points", []):
            rec = lps.get(lp.get("landing_point_id"))
            if rec is None:
                unmatched += 1
                continue
            rec["cables"].append(detail.get("name") or slug)
            if rec["cc"]:
                countries.add(rec["cc"])
        feats.append({
            "type": "Feature",
            "properties": {
                "id": slug,
                "name": detail.get("name") or slug,
                "rfs": detail.get("rfs"),
                "length": detail.get("length"),
                "owners": (detail.get("owners") or "").replace(",  ", ", "),
                "countries": sorted(countries),
            },
            "geometry": {"type": f["geometry"]["type"], "coordinates": rnd(f["geometry"]["coordinates"])},
        })

    OUT.mkdir(parents=True, exist_ok=True)
    meta = {"source": "TeleGeography Submarine Cable Map", "snapshot": "2021-06", "license": "CC BY-NC-SA 3.0"}
    (OUT / "cables.geojson").write_text(json.dumps({"type": "FeatureCollection", "meta": meta, "features": feats}, ensure_ascii=False, separators=(",", ":")))
    lp_feats = [
        {"type": "Feature", "geometry": {"type": "Point", "coordinates": v["coords"]},
         "properties": {"id": k, "name": v["name"], "cc": v["cc"], "cables": sorted(set(v["cables"]))}}
        for k, v in lps.items() if v["cables"]
    ]
    (OUT / "landing-points.geojson").write_text(json.dumps({"type": "FeatureCollection", "meta": meta, "features": lp_feats}, ensure_ascii=False, separators=(",", ":")))
    no_cc = sum(1 for f in lp_feats if not f["properties"]["cc"])
    print(f"{len(feats)} Kabel, {len(lp_feats)} Landepunkte, {no_cc} ohne Land, {unmatched} unbekannte Landepunkt-Referenzen")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
