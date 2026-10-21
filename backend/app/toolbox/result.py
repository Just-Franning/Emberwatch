"""Unified tool result. Every tool and every object page uses the same structure, so the web interface renders all of
them with one renderer and exports them the same way.

    {"tool", "title", "target", "object": {"type", "value"} | None, "started_at", "ms",
     "level", "target_sees", "third_party",
     "verdict": {"sev", "text"}, "findings": [{"sev", "text", "detail"}],
     "sections": [{"kind": "kv" | "table" | "text" | "list" | "chart", "title", ...}],
     "map": {"points": [...], "paths": [...]} | None, "related": [{"type", "value", "label"}], "raw": ...}

Cells in kv/table/list sections are plain values or {"t": text, "sev"?, "href"? (https only), "obj"? {type, value},
"mono"?}. Severities: ok < info < low < medium < high.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from .. import i18n

SEV_ORDER = {"ok": 0, "info": 1, "low": 2, "medium": 3, "high": 4}
SEVS = tuple(SEV_ORDER)
HTTPS_RE = re.compile(r"^https://[^\s\"'<>]+$")
MAX_RAW = 60_000


def max_sev(*sevs: str | None) -> str:
    best = "ok"
    for s in sevs:
        if s in SEV_ORDER and SEV_ORDER[s] > SEV_ORDER[best]:
            best = s
    return best


def cell(t: Any, sev: str | None = None, href: str | None = None, obj: tuple[str, str] | None = None,
         mono: bool = False) -> Any:
    if sev is None and href is None and obj is None and not mono:
        return t
    c: dict[str, Any] = {"t": "" if t is None else str(t)}
    if sev in SEV_ORDER:
        c["sev"] = sev
    if href and HTTPS_RE.match(href):
        c["href"] = href
    if obj:
        c["obj"] = {"type": obj[0], "value": str(obj[1])}
    if mono:
        c["mono"] = True
    return c


class Result:
    def __init__(self, tool: str, lang: str, target: str, obj: tuple[str, str] | None = None) -> None:
        self.tool = tool
        self.lang = lang
        self.target = target
        self.obj = obj
        self.t0 = time.perf_counter()
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.findings: list[dict[str, Any]] = []
        self.sections: list[dict[str, Any]] = []
        self.points: list[dict[str, Any]] = []
        self.paths: list[dict[str, Any]] = []
        self.related: list[dict[str, Any]] = []
        self._rel: set[tuple[str, str]] = set()
        self.raw: Any = None
        # per-run overrides of the registry flags (e.g. DNS with zone transfer becomes intrusive)
        self.level: str | None = None
        self.target_sees: bool | None = None
        self.third_party: str | None = None

    # --- texts ------------------------------------------------------------------------------------------------
    def t(self, key: str, **params: Any) -> str:
        return i18n.t(self.lang, key, **params)

    def find(self, sev: str, key: str, detail: str | None = None, **params: Any) -> None:
        """Adds a finding. key and detail are text keys; detail may also be a ready text (prefix '=')."""
        text = self.t(key, **params)
        det = None
        if detail:
            det = detail[1:] if detail.startswith("=") else self.t(detail, **params)
        self.findings.append({"sev": sev if sev in SEV_ORDER else "info", "text": text, "detail": det, "key": key})

    # --- sections ---------------------------------------------------------------------------------------------
    def kv(self, title: str | None, rows: list[tuple[str, Any]]) -> None:
        rows = [[k, v] for k, v in rows if v is not None and v != "" and v != []]
        if rows:
            self.sections.append({"kind": "kv", "title": title, "rows": rows})

    def table(self, title: str | None, columns: list[str], rows: list[list[Any]], note: str | None = None,
              empty: str | None = None) -> None:
        if not rows and empty is None:
            return
        self.sections.append({"kind": "table", "title": title, "columns": columns, "rows": rows, "note": note,
                              "empty": empty})

    def text(self, title: str | None, text: str, mono: bool = False) -> None:
        if text:
            self.sections.append({"kind": "text", "title": title, "text": text[:20000], "mono": mono})

    def items(self, title: str | None, items: list[Any], note: str | None = None) -> None:
        if items:
            self.sections.append({"kind": "list", "title": title, "items": items, "note": note})

    def chart(self, title: str, ctype: str, labels: list[str], series: list[dict[str, Any]], unit: str = "") -> None:
        if labels and series:
            self.sections.append({"kind": "chart", "title": title, "type": ctype, "labels": labels, "series": series,
                                  "unit": unit})

    # --- map and related objects --------------------------------------------------------------------------------
    def point(self, geo: dict[str, Any] | None, kind: str, label: str | None = None, ip: str | None = None,
              sev: str | None = None) -> bool:
        if not geo or geo.get("lat") is None or geo.get("lon") is None:
            return False
        p: dict[str, Any] = {"lon": round(float(geo["lon"]), 4), "lat": round(float(geo["lat"]), 4), "kind": kind}
        if label:
            p["label"] = str(label)[:40]
        if ip:
            p["ip"] = ip
        if sev:
            p["sev"] = sev
        self.points.append(p)
        return True

    def path(self, coords: list[tuple[float, float]], sev: str | None = None) -> None:
        pts = [[round(lon, 4), round(lat, 4)] for lon, lat in coords]
        if len(pts) >= 2:
            self.paths.append({"coords": pts, **({"sev": sev} if sev else {})})

    def rel(self, otype: str, value: Any, label: str | None = None) -> None:
        if value is None or value == "":
            return
        key = (otype, str(value))
        if key in self._rel or len(self.related) >= 60:
            return
        self._rel.add(key)
        self.related.append({"type": otype, "value": str(value), "label": label})

    # --- final -------------------------------------------------------------------------------------------------
    def done(self, spec: Any, summary: str | None = None) -> dict[str, Any]:
        sev = max_sev(*(f["sev"] for f in self.findings))
        order = sorted(self.findings, key=lambda f: -SEV_ORDER[f["sev"]])
        raw = self.raw
        if raw is not None:
            enc = json.dumps(raw, ensure_ascii=False, default=str)
            if len(enc) > MAX_RAW:
                raw = {"truncated": True, "text": enc[:MAX_RAW]}
        return {
            "tool": self.tool, "title": self.t(f"tb.tool.{self.tool}"), "target": self.target,
            "object": {"type": self.obj[0], "value": self.obj[1]} if self.obj else None,
            "started_at": self.started_at, "ms": round((time.perf_counter() - self.t0) * 1000),
            "level": self.level or spec.level,
            "target_sees": spec.target_sees if self.target_sees is None else self.target_sees,
            "third_party": self.third_party if self.third_party is not None else spec.third_party,
            "verdict": {"sev": sev, "text": summary or self.t(f"tb.verdict.{sev}")},
            "findings": order, "sections": self.sections,
            "map": {"points": self.points, "paths": self.paths} if (self.points or self.paths) else None,
            "related": self.related, "raw": raw,
        }
