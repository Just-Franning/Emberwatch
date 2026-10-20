"""Builds frontend/data/countries.geojson and centroids.json from Natural Earth (public domain).

Usage: python3 scripts/build_geodata.py   (needs access to raw.githubusercontent.com)

centroids.json maps ISO 3166-1 alpha-2 codes to {"name": German name, "name_en": English name, "lon", "lat"}.
"""
import json
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/"
OUT = Path(__file__).resolve().parent.parent / "frontend" / "data"
# Common short names instead of Natural Earth's formal names
NAME_OVERRIDES = {"TW": {"name": "Taiwan"}, "US": {"name_en": "United States"}}


def load(name):
    with urllib.request.urlopen(BASE + name, timeout=120) as r:
        return json.load(r)


def rnd(c):
    if isinstance(c[0], (int, float)):
        return [round(c[0], 2), round(c[1], 2)]
    return [rnd(x) for x in c]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    d110 = load("ne_110m_admin_0_countries.geojson")
    feats = []
    for f in d110["features"]:
        p = f["properties"]
        iso = p["ISO_A2_EH"] if p["ISO_A2_EH"] != "-99" else p["ADM0_A3"]
        feats.append({"type": "Feature",
                      "properties": {"iso": iso, "name": p["NAME_DE"] or p["NAME"], "name_en": p["NAME_EN"] or p["NAME"]},
                      "geometry": {"type": f["geometry"]["type"], "coordinates": rnd(f["geometry"]["coordinates"])}})
    (OUT / "countries.geojson").write_text(json.dumps({"type": "FeatureCollection", "features": feats}, separators=(",", ":")))

    # Centroids from 50m (includes small states such as SG, HK, MT); for duplicate ISO codes the most populous area wins
    d50 = load("ne_50m_admin_0_countries.geojson")
    cent, pop = {}, {}
    for f in d50["features"]:
        p = f["properties"]
        iso = p["ISO_A2_EH"]
        if iso in ("-99", None) or pop.get(iso, -1) >= (p["POP_EST"] or 0):
            continue
        pop[iso] = p["POP_EST"] or 0
        cent[iso] = {"name": p["NAME_DE"] or p["NAME"], "name_en": p["NAME_EN"] or p["NAME"],
                     "lon": round(p["LABEL_X"], 3), "lat": round(p["LABEL_Y"], 3)}
    for iso, names in NAME_OVERRIDES.items():
        if iso in cent:
            cent[iso].update(names)
    (OUT / "centroids.json").write_text(json.dumps(cent, ensure_ascii=False, separators=(",", ":")))
    print(f"{len(feats)} polygons, {len(cent)} centroids")


if __name__ == "__main__":
    main()
