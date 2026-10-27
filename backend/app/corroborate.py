"""Reports against measurements (3.3).

For a report Emberwatch checks whether its own, independent data show what the report says. Every check is
deterministic and explained; the interface renders it from the stored parameters (wl.chk.*).

- ddos + target country: Cloudflare Radar share of the country as attack target (L7 and L3, daily history) on the day
  of the report and the day before, against the median of the 14 days before that. "Supported" if the share rose to at
  least 1.5 times the median and by at least 0.5 percentage points (a country that was mostly not among the top 25
  before has a median of 0 and is marked as such, but also needs the 0.5 points).
  A country outside Cloudflare's top 25 cannot be judged ("unclear"), which is not the same as "not supported".
- ransomware + group: posts of the group on leak sites (ransomware.live) from 14 days before to 3 days after. The group
  name must match exactly, or as the only group whose name starts with it (or it with that name).
- cable / shutdown + country: internet outages Cloudflare reports for the country that overlap the period from 3 days
  before to 1 day after (an outage that is still going on counts until today). "Not supported" needs successful outage
  runs covering every day of the period; otherwise "unclear".
- shutdown + country: OONI web measurements of the country in the 7 days up to the report against the 28 days before:
  "supported" if the share of anomalous measurements rose to 1.5 times and by at least 5 points, or the share of
  confirmed blocking to 1.5 times and by at least 0.5 points. Permanent censorship without a change is not supported.
- CVE: listed as exploited by CISA KEV or ENISA (EUVD) – added only when it supports the report.
- malware: active C2 servers of the malware in the 30 days up to the report – added only when it supports the report.

Result of a report: "supported" if any check supports it, "not_supported" if checks were conclusive and none supports
it, "unclear" if no check was conclusive; None if no check applies. Measurements show traffic, posts and outages, not
who is behind them: a supported report is consistent with the data, not proven.
"""
from __future__ import annotations

import json
import re
import statistics
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

from .db import DB

SUPPORTED, NOT_SUPPORTED, UNCLEAR = "supported", "not_supported", "unclear"
RANK = {SUPPORTED: 3, NOT_SUPPORTED: 2, UNCLEAR: 1}
DDOS_FACTOR = 1.5
DDOS_MIN_PP = 0.5
BASELINE_DAYS = 14
MIN_BASELINE = 7
MAX_TARGETS = 3
OONI_MIN_MEASUREMENTS = 50
OONI_MIN_BASELINE = 100
OONI_WINDOW = 7
OONI_BASE_DAYS = 28
OUTAGE_RUN_COVERS = 7  # each successful outage run reads the 7 days before it (sources/infra.py)
OUTAGE_KINDS = ("cable", "shutdown")
GROUP_RE = re.compile(r"[^a-z0-9]")


def _day(s: str | None) -> date | None:
    try:
        return datetime.strptime((s or "")[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _norm(name: str) -> str:
    return GROUP_RE.sub("", (name or "").lower())


def _days(start: date, end: date) -> Iterable[date]:
    d = start
    while d <= end:
        yield d
        d += timedelta(days=1)


class Evidence:
    """Indexes of the local data, built once per run (only reads)."""

    def __init__(self, db: DB, today: date | None = None) -> None:
        self.today = today or datetime.now(timezone.utc).date()
        horizon = (self.today - timedelta(days=130)).isoformat()
        self.share: dict[str, dict[str, dict[str, float]]] = {"l7": {}, "l3": {}}
        for key, metric in (("l7", "l7_target_1d"), ("l3", "l3_target_1d")):
            for h in db.hist_get(metric, 130):
                data = h["data"] if isinstance(h["data"], dict) else {}
                vals: dict[str, float] = {}
                for r in data.get("rows") or []:
                    try:
                        if r.get("target"):
                            vals[str(r["target"])] = float(r["value"])
                    except (TypeError, ValueError):
                        continue
                self.share[key][h["day"]] = vals
        self.victims: dict[str, list[tuple[date, str | None]]] = {}
        for r in db.query("SELECT grp, country, discovered FROM victims WHERE discovered >= ?", (horizon,)):
            d = _day(r["discovered"])
            g = _norm(r["grp"] or "")
            if d and len(g) >= 4:
                self.victims.setdefault(g, []).append((d, (r["country"] or "").upper() or None))
        self.outages: list[tuple[date, date, list[str], str]] = []  # (first day, last day or today, countries, cause)
        for r in db.query("SELECT start_ts, end_ts, countries, cause FROM infra_events WHERE kind = 'outage' "
                          "AND COALESCE(end_ts, start_ts) >= ?", (horizon,)):
            d = _day(r["start_ts"])
            e = _day(r["end_ts"]) or self.today  # still going on
            try:
                ccs = [str(c).upper() for c in json.loads(r["countries"] or "[]")]
            except ValueError:
                ccs = []
            if d:
                self.outages.append((d, max(d, e), ccs, r["cause"] or "UNKNOWN"))
        try:
            runs = json.loads(db.meta_get("outage_runs") or "[]")
        except ValueError:
            runs = []
        self.outage_runs = {x for x in (_day(str(r)) for r in runs if isinstance(r, str)) if x}
        self.ooni: dict[tuple[str, str], tuple[int, int, int]] = {}
        for r in db.query("SELECT cc, day, measurements, anomalies, confirmed FROM ooni WHERE test = 'web'"):
            self.ooni[(r["cc"], r["day"])] = (r["measurements"], r["anomalies"], r["confirmed"])
        self.kev = {r["cve"]: r["date_added"] for r in db.query("SELECT cve, date_added FROM kev")}
        self.euvd = {r["cve"]: r["exploited_since"] for r in db.query("SELECT cve, exploited_since FROM euvd")}
        self.c2: dict[str, list[date]] = {}
        for r in db.query("SELECT malware, COALESCE(last_seen, first_seen) AS seen FROM c2 WHERE malware IS NOT NULL"):
            d = _day(r["seen"])
            if d:
                self.c2.setdefault(str(r["malware"]).lower(), []).append(d)

    # --- single checks ----------------------------------------------------------------------------------------------
    def ddos(self, cc: str, d: date) -> dict[str, Any]:
        params: dict[str, Any] = {}
        results = []
        for key in ("l7", "l3"):
            hist = self.share[key]
            event_days = [x.isoformat() for x in (d - timedelta(days=1), d) if x.isoformat() in hist]
            base_days = [x.isoformat() for x in _days(d - timedelta(days=BASELINE_DAYS + 1), d - timedelta(days=2))
                         if x.isoformat() in hist]
            if not event_days or len(base_days) < MIN_BASELINE:
                results.append(UNCLEAR)
                params[key] = {"reason": "no_data"}
                continue
            seen = [hist[x][cc] for x in event_days if cc in hist[x]]
            if not seen:  # outside Cloudflare's top 25 targets on those days: too small to judge
                results.append(UNCLEAR)
                params[key] = {"reason": "not_visible"}
                continue
            value = max(seen)
            base = statistics.median([hist[x].get(cc, 0.0) for x in base_days])
            ok = value >= base * DDOS_FACTOR and value - base >= DDOS_MIN_PP
            results.append(SUPPORTED if ok else NOT_SUPPORTED)
            params[key] = {"value": round(value, 2), "baseline": round(base, 2), "entered": base == 0}
        return {"type": "ddos", "subject": cc, "result": _combine(results), "params": params}

    def ransomware(self, groups: list[str], d: date, countries: list[str]) -> dict[str, Any] | None:
        start, end = d - timedelta(days=14), d + timedelta(days=3)
        for cand in groups:
            c = _norm(cand)
            if len(c) < 4:
                continue
            match = c if c in self.victims else None
            if match is None:  # a longer or shorter spelling ("lockbit3" / "lockbit"), only if it is the only one
                near = [g for g in self.victims if len(g) >= 4 and (g.startswith(c) or c.startswith(g))]
                match = near[0] if len(near) == 1 else None
            if not match:
                continue
            posts = [x for x in self.victims[match] if start <= x[0] <= end]
            if posts:
                in_cc = sum(1 for x in posts if x[1] and x[1] in countries)
                return {"type": "ransomware", "subject": cand, "result": SUPPORTED,
                        "params": {"posts": len(posts), "in_countries": in_cc}}
            active = any(d - timedelta(days=60) <= x[0] < start for x in self.victims[match])
            done = end <= self.today
            return {"type": "ransomware", "subject": cand, "result": NOT_SUPPORTED if active and done else UNCLEAR,
                    "params": {"posts": 0}}
        return None

    def _covered(self, start: date, end: date) -> bool:
        """Every day of the period was read by a successful outage run (a run reads the 7 days before it)."""
        return end <= self.today and all(any(x + timedelta(days=k) in self.outage_runs for k in range(OUTAGE_RUN_COVERS))
                                         for x in _days(start, end))

    def outage(self, cc: str, d: date) -> dict[str, Any]:
        start, end = d - timedelta(days=3), d + timedelta(days=1)
        hits = [o for o in self.outages if o[0] <= end and o[1] >= start and cc in o[2]]  # overlaps the period
        if hits:
            causes = sorted({o[3] for o in hits})
            return {"type": "outage", "subject": cc, "result": SUPPORTED, "params": {"events": len(hits), "causes": causes}}
        return {"type": "outage", "subject": cc, "result": NOT_SUPPORTED if self._covered(start, end) else UNCLEAR,
                "params": {"events": 0}}

    def _ooni_sum(self, cc: str, first: date, last: date) -> tuple[int, int, int]:
        m = a = c = 0
        for x in _days(first, last):
            v = self.ooni.get((cc, x.isoformat()))
            if v:
                m, a, c = m + v[0], a + v[1], c + v[2]
        return m, a, c

    def ooni_check(self, cc: str, d: date) -> dict[str, Any]:
        """A change against the 28 days before, not the level: permanent censorship alone does not support a report."""
        m, a, c = self._ooni_sum(cc, d - timedelta(days=OONI_WINDOW - 1), d)
        bm, ba, bc = self._ooni_sum(cc, d - timedelta(days=OONI_WINDOW + OONI_BASE_DAYS - 1), d - timedelta(days=OONI_WINDOW))
        if m < OONI_MIN_MEASUREMENTS or bm < OONI_MIN_BASELINE:
            return {"type": "ooni", "subject": cc, "result": UNCLEAR, "params": {"measurements": m, "baseline": bm}}
        ap, bap = 100 * a / m, 100 * ba / bm
        cp, bcp = 100 * c / m, 100 * bc / bm
        rose = (ap >= 1.5 * bap and ap - bap >= 5.0) or (cp >= 1.5 * bcp and cp - bcp >= 0.5)
        return {"type": "ooni", "subject": cc, "result": SUPPORTED if rose else NOT_SUPPORTED,
                "params": {"measurements": m, "confirmed": c, "anomaly_pct": round(ap, 1), "anomaly_pct_before": round(bap, 1),
                           "confirmed_pct": round(cp, 2), "confirmed_pct_before": round(bcp, 2)}}

    def cve(self, cve: str) -> dict[str, Any] | None:
        if cve in self.kev:
            return {"type": "cve", "subject": cve, "result": SUPPORTED, "params": {"by": "kev", "since": self.kev[cve]}}
        if cve in self.euvd:
            return {"type": "cve", "subject": cve, "result": SUPPORTED, "params": {"by": "euvd", "since": self.euvd[cve]}}
        return None

    def malware(self, name: str, d: date) -> dict[str, Any] | None:
        seen = [x for x in self.c2.get(name.lower(), []) if d - timedelta(days=30) <= x <= d]
        if seen:
            return {"type": "malware", "subject": name, "result": SUPPORTED, "params": {"c2": len(seen)}}
        return None

    # --- a report ---------------------------------------------------------------------------------------------------
    def check(self, r: dict[str, Any]) -> dict[str, Any] | None:
        d = _day(r.get("published"))
        if d is None:
            return None
        kinds = set(r.get("kinds") or [])
        origin = r.get("origin")
        countries = [c for c in (r.get("countries") or []) if c and c != origin]
        out: list[dict[str, Any]] = []
        if "ddos" in kinds:
            for cc in countries[:MAX_TARGETS]:
                out.append(self.ddos(cc, d))
        if "ransomware" in kinds:
            groups = list(dict.fromkeys([*(r.get("actors") or []), *(r.get("malware") or [])]))
            groups += [g for g in _title_groups(r.get("title") or "", self.victims) if g not in groups]
            res = self.ransomware(groups, d, countries + ([origin] if origin else []))
            if res:
                out.append(res)
        if kinds & set(OUTAGE_KINDS):
            for cc in (countries or ([origin] if origin else []))[:MAX_TARGETS]:
                out.append(self.outage(cc, d))
        if "shutdown" in kinds:
            for cc in (countries or ([origin] if origin else []))[:MAX_TARGETS]:
                out.append(self.ooni_check(cc, d))
        for c in (r.get("cves") or [])[:5]:
            res = self.cve(c)
            if res:
                out.append(res)
        for m in (r.get("malware") or [])[:3]:
            res = self.malware(m, d)
            if res:
                out.append(res)
        if not out:
            return None
        return {"verdict": _verdict([x["result"] for x in out]), "checks": out}


def _title_groups(title: str, victims: dict[str, Any]) -> list[str]:
    """Ransomware group names in a headline (only names of at least five letters: "play" or "akira"-like short words
    are too common to count without the actor recognition)."""
    out = []
    for w in re.findall(r"[A-Za-z][A-Za-z0-9]{4,30}", title):
        if _norm(w) in victims:
            out.append(w)
    return out[:3]


def _combine(results: list[str]) -> str:
    if SUPPORTED in results:
        return SUPPORTED
    if NOT_SUPPORTED in results:
        return NOT_SUPPORTED
    return UNCLEAR


def _verdict(results: list[str]) -> str:
    return _combine(results)


def merge(items: list[dict[str, Any] | None]) -> dict[str, Any] | None:
    """Checks of the reports of one event: the checks of all members (each subject once, the strongest result)."""
    by: dict[tuple[str, str], dict[str, Any]] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        for c in it.get("checks") or []:
            if not isinstance(c, dict) or c.get("result") not in RANK:
                continue
            key = (str(c.get("type")), str(c.get("subject")))
            if key not in by or RANK[c["result"]] > RANK[by[key]["result"]]:
                by[key] = c
    if not by:
        return None
    checks = list(by.values())
    return {"verdict": _verdict([c["result"] for c in checks]), "checks": checks[:12]}
