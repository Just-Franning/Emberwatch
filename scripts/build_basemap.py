"""Builds frontend/data/basemap-style.json: a dark style with red accents based on OpenFreeMap "dark".

Source: github.com/hyperknot/openfreemap-styles (MIT), style derived from Positron/CartoDB basemaps
(code BSD-3-Clause, design CC BY 4.0 or CC BY 3.0). Map data: © OpenMapTiles, © OpenStreetMap contributors.

Usage:
  git clone --depth 1 https://github.com/hyperknot/openfreemap-styles.git /tmp/ofm
  python3 scripts/build_basemap.py /tmp/ofm/styles/dark/style.json
"""
import json
import sys
from pathlib import Path

DOMAIN = "tiles.openfreemap.org"
OUT = Path(__file__).resolve().parent.parent / "frontend" / "data" / "basemap-style.json"

LAND = "#101012"
WATER = "#060607"
LABEL = "#8c8c8c"
LABEL_COUNTRY = "#b9a8a8"
HALO = "#060607"

OVERRIDES = {
    "background": {"background-color": LAND},
    "water": {"fill-color": WATER},
    "waterway": {"line-color": WATER},
    "landcover_ice_shelf": {"fill-color": LAND},
    "water_name": {"text-color": "#3a3a40", "text-halo-color": HALO},
    "boundary_country_z0-4": {"line-color": "rgba(170, 38, 38, 0.75)"},
    "boundary_country_z5-": {"line-color": "rgba(170, 38, 38, 0.85)"},
    "boundary_state": {"line-color": "#2b1a1a"},
    "place_country_major": {"text-color": LABEL_COUNTRY, "text-halo-color": HALO},
    "place_country_minor": {"text-color": LABEL_COUNTRY, "text-halo-color": HALO},
    "place_country_other": {"text-color": LABEL_COUNTRY, "text-halo-color": HALO},
    "place_state": {"text-color": "#6f6262", "text-halo-color": HALO},
}
for lid in ("place_other", "place_suburb", "place_village", "place_town", "place_city", "place_city_large"):
    OVERRIDES[lid] = {"text-color": LABEL, "text-halo-color": HALO}


def main(src: Path) -> None:
    style = json.loads(src.read_text())
    text = json.dumps(style).replace("__TILEJSON_DOMAIN__", DOMAIN)
    style = json.loads(text)
    style["name"] = "Emberwatch Dark Red (OpenFreeMap dark)"
    style["sources"] = {"openmaptiles": {"type": "vector", "url": f"https://{DOMAIN}/planet"}}
    style["glyphs"] = f"https://{DOMAIN}/fonts/{{fontstack}}/{{range}}.pbf"
    style["sprite"] = f"https://{DOMAIN}/sprites/ofm_f384/ofm"
    layers = []
    for layer in style["layers"]:
        if layer.get("source") not in (None, "openmaptiles"):
            continue
        layer.setdefault("paint", {}).update(OVERRIDES.get(layer["id"], {}))
        layers.append(layer)
    style["layers"] = layers
    style.pop("center", None)
    style.pop("zoom", None)
    style["metadata"] = {
        "emberwatch:source": "OpenFreeMap dark (github.com/hyperknot/openfreemap-styles, MIT); Design CC BY 4.0",
        "emberwatch:attribution": "OpenFreeMap © OpenMapTiles Data from OpenStreetMap",
    }
    OUT.write_text(json.dumps(style, ensure_ascii=False, separators=(",", ":")))
    print(f"{len(layers)} Ebenen -> {OUT}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
