"""Aggregation and rule-based pattern detection.

All patterns are deterministic and traceable (thresholds below).
They describe correlations in the data, not causation or attribution.
"""
from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from . import alerts as alerts_mod
from .db import DB
from .geo import Geo

RADAR_KEYS = (
    "l7_pairs_1d", "l7_target_1d", "l7_target_7d", "l7_origin_1d", "l7_origin_7d",
    "l3_target_1d", "l3_target_7d", "l3_origin_1d", "l3_origin_7d",
    "l3_vector_1d", "l3_vector_7d", "l3_protocol_1d", "l7_rules_1d", "l7_rules_7d",
    "l7_product_1d", "l7_industry_1d", "l3_vector_ts_7d", "l7_rules_ts_7d",
)

# Pattern detection thresholds
SHARE_DELTA_PP = 3.0        # country share shift (percentage points)
SHARE_REL = 0.5             # ... and at least +50 % relative
VECTOR_DELTA_PP = 5.0       # shift of an attack vector / L7 category
SPIKE_Z = 3.0               # time series spike (z-score last 24 h vs. the days before)
ASN_CONCENTRATION = 0.15    # share of one AS among geolocated C2
NEW_FAMILY_MIN = 5          # new C2 of a previously unseen family within 24 h
RANSOM_MIN = 5              # minimum victims for a country/group increase
RANSOM_FACTOR = 2.0         # 7 days vs. the previous 7 days
KEV_VENDOR_MIN = 3          # new KEV entries of the same vendor within 14 days
EPSS_HIGH = 0.5             # EPSS threshold (probability of exploitation within 30 days)
HIJACK_COUNTRY_MIN = 3      # BGP hijack events per country within 24 h
CRITICAL_CAUSES = {"CYBERATTACK": "high", "CABLE_CUT": "medium", "GOVERNMENT_DIRECTED": "medium", "MILITARY_ACTION": "medium"}


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _top(counter: Counter, n: int) -> list[dict[str, Any]]:
    return [{"key": k, "count": c} for k, c in counter.most_common(n)]


def radar(db: DB) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k in RADAR_KEYS:
        data, fetched = db.kv_get(f"radar:{k}")
        if data is not None:
            data["fetched_at"] = fetched
            out[k] = data
    return out


def _share_map(block: dict[str, Any] | None, field: str) -> dict[str, float]:
    if not block:
        return {}
    return {r[field]: r["value"] for r in block.get("rows", []) if r.get(field)}


def c2_stats(db: DB) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    d1, d7 = _iso(now - timedelta(days=1)), _iso(now - timedelta(days=7))
    rows = db.query(
        "SELECT source, malware, country, asn, as_name, status, first_seen, last_seen, lat FROM c2"
    )
    by_country, by_malware, by_asn, new24_family = Counter(), Counter(), Counter(), Counter()
    as_names: dict[int, str] = {}
    families_before: set[str] = set()
    geolocated = online = new24 = new7 = 0
    for r in rows:
        fam = r["malware"] or "unknown"
        by_malware[fam] += 1
        if r["country"]:
            by_country[r["country"]] += 1
        if r["asn"]:
            by_asn[r["asn"]] += 1
            if r["as_name"]:
                as_names[r["asn"]] = r["as_name"]
        if r["lat"] is not None:
            geolocated += 1
        if (r["status"] or "").lower() == "online":
            online += 1
        fs = r["first_seen"] or ""
        if fs >= d1:
            new24 += 1
            new24_family[fam] += 1
        else:
            families_before.add(fam)
        if fs >= d7:
            new7 += 1
    return {
        "total": len(rows),
        "geolocated": geolocated,
        "feodo_online": online,
        "new_24h": new24,
        "new_7d": new7,
        "by_country": _top(by_country, 20),
        "by_malware": _top(by_malware, 20),
        "by_asn": [{"key": a, "name": as_names.get(a, ""), "count": c} for a, c in by_asn.most_common(15)],
        "new_24h_by_malware": _top(new24_family, 10),
        "_families_before": families_before,
    }


def ransomware_stats(db: DB) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    d7, d14, d30 = (_iso(now - timedelta(days=n)) for n in (7, 14, 30))
    rows = db.query("SELECT grp, country, activity, discovered FROM victims WHERE discovered >= ?", (d30,))
    cur_c, prev_c, cur_g, prev_g, sector, pair = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    total30 = len(rows)
    for r in rows:
        disc = r["discovered"] or ""
        cc = r["country"] or "??"
        if disc >= d7:
            cur_c[cc] += 1
            cur_g[r["grp"]] += 1
            sector[r["activity"] or ""] += 1  # "" = unknown (rendered by the frontend)
            pair[(r["grp"], cc)] += 1
        elif disc >= d14:
            prev_c[cc] += 1
            prev_g[r["grp"]] += 1
    first = db.query("SELECT MIN(discovered) AS m FROM victims")[0]["m"]
    return {
        "prev_window_complete": bool(first and first <= d14),
        "total_7d": sum(cur_c.values()),
        "total_prev_7d": sum(prev_c.values()),
        "total_30d": total30,
        "history_since": first,
        "by_country": _top(cur_c, 20),
        "by_group": _top(cur_g, 15),
        "by_sector": _top(sector, 12),
        "group_country": [{"group": g, "country": c, "count": n} for (g, c), n in pair.most_common(10)],
        "_prev_country": dict(prev_c),
        "_prev_group": dict(prev_g),
    }


def kev_stats(db: DB) -> dict[str, Any]:
    today = datetime.now(timezone.utc).date()
    d14, d30 = (today - timedelta(days=14)).isoformat(), (today - timedelta(days=30)).isoformat()
    recent = db.query(
        "SELECT k.cve, k.vendor, k.product, k.name, k.date_added, k.due_date, k.ransomware, e.epss, e.percentile "
        "FROM kev k LEFT JOIN epss e ON e.cve = k.cve "
        "WHERE k.date_added >= ? ORDER BY k.date_added DESC, k.cve DESC",
        (d30,),
    )
    vendors14 = Counter(r["vendor"] for r in recent if (r["date_added"] or "") >= d14)
    total = db.query("SELECT COUNT(*) AS n FROM kev")[0]["n"]
    top_epss = db.query(
        "SELECT k.cve, k.vendor, k.product, k.date_added, k.ransomware, e.epss, e.percentile "
        "FROM kev k JOIN epss e ON e.cve = k.cve WHERE k.date_added >= ? ORDER BY e.epss DESC LIMIT 10",
        ((today - timedelta(days=90)).isoformat(),),
    )
    return {
        "total": total,
        "added_30d": len(recent),
        "added_14d": sum(vendors14.values()),
        "ransomware_known_30d": sum(1 for r in recent if (r["ransomware"] or "").lower() == "known"),
        "epss_high_14d": sum(1 for r in recent if (r["date_added"] or "") >= d14 and (r["epss"] or 0) >= EPSS_HIGH),
        "epss_available": bool(db.query("SELECT 1 FROM epss LIMIT 1")),
        "latest": recent[:20],
        "top_epss_90d": top_epss,
        "vendors_14d": _top(vendors14, 10),
    }


def infra_stats(db: DB) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    d1, d7 = _iso(now - timedelta(days=1)), _iso(now - timedelta(days=7))
    rows = db.query(
        "SELECT id, kind, start_ts, end_ts, countries, asns, cause, scope, confidence, url, meta FROM infra_events "
        "WHERE COALESCE(end_ts, ?) >= ? ORDER BY start_ts DESC",
        (_iso(now), d7),
    )
    by_kind: Counter = Counter()
    outage_cc, outage_cause, hijack_cc, anomaly_cc = Counter(), Counter(), Counter(), Counter()
    events = []
    for r in rows:
        r["countries"] = json.loads(r["countries"] or "[]")
        r["asns"] = json.loads(r["asns"] or "[]")
        try:
            r["meta"] = json.loads(r["meta"] or "{}")
        except ValueError:
            r["meta"] = {}
        r["meta"]["kind"] = r["kind"]
        r["ongoing"] = r["end_ts"] is None and r["kind"] in ("outage", "leak", "anomaly")
        r["last_24h"] = (r["start_ts"] or "") >= d1
        by_kind[r["kind"]] += 1
        for cc in r["countries"]:
            if r["kind"] == "outage":
                outage_cc[cc] += 1
            elif r["kind"] == "hijack":
                hijack_cc[cc] += 1
            elif r["kind"] == "anomaly":
                anomaly_cc[cc] += 1
        if r["kind"] == "outage":
            outage_cause[r["cause"] or "UNKNOWN"] += 1
        events.append(r)
    return {
        "counts_7d": dict(by_kind),
        "outages_by_country": _top(outage_cc, 20),
        "outages_by_cause": _top(outage_cause, 12),
        "hijacks_by_country": _top(hijack_cc, 20),
        "anomalies_by_country": _top(anomaly_cc, 20),
        "events": events[:300],
    }


def watch_stats(db: DB) -> dict[str, Any]:
    st = alerts_mod.stats(db)
    return {
        "entries": db.query("SELECT COUNT(*) AS n FROM watchlist")[0]["n"],
        "products": db.query("SELECT COUNT(*) AS n FROM products")[0]["n"],
        "hits_7d": st["total_7d"],
        "high_7d": st["high_7d"],
        "hits_total": st["total"],
    }


def country_metrics(rad: dict[str, Any], c2: dict[str, Any], rw: dict[str, Any], infra: dict[str, Any] | None = None) -> dict[str, dict[str, float]]:
    m: dict[str, dict[str, float]] = defaultdict(dict)
    for key, field, name in (
        ("l7_target_1d", "target", "l7_target"), ("l7_origin_1d", "origin", "l7_origin"),
        ("l3_target_1d", "target", "l3_target"), ("l3_origin_1d", "origin", "l3_origin"),
    ):
        for cc, v in _share_map(rad.get(key), field).items():
            m[cc][name] = v
    for it in c2["by_country"]:
        m[it["key"]]["c2"] = it["count"]
    for it in rw["by_country"]:
        if it["key"] != "??":
            m[it["key"]]["ransomware_7d"] = it["count"]
    if infra:
        for it in infra["outages_by_country"]:
            m[it["key"]]["outages_7d"] = it["count"]
        for it in infra["hijacks_by_country"]:
            m[it["key"]]["hijacks_7d"] = it["count"]
    return dict(m)


# --- Patterns ------------------------------------------------------------------
# A pattern is language-neutral: key + params. i18n.render_pattern() turns it into title/detail.
# "ident" identifies the finding independent of changing numbers (used for notification de-duplication).

def _p(sev: str, cat: str, key: str, params: dict[str, Any], ident: str, cc: str | None = None) -> dict[str, Any]:
    return {"severity": sev, "category": cat, "key": key, "params": params, "ident": f"{key}|{ident}", "country": cc}


def detect(geo: Geo, rad: dict[str, Any], c2: dict[str, Any], rw: dict[str, Any], kev: dict[str, Any],
           infra: dict[str, Any] | None = None, watch: dict[str, Any] | None = None, cables: Any = None) -> list[dict[str, Any]]:
    pats: list[dict[str, Any]] = []
    r1 = lambda v: round(float(v), 2)  # noqa: E731

    # 1) Country share shifts (Radar, 24 h vs. 7 days)
    for layer in ("l7", "l3"):
        for direction in ("target", "origin"):
            cur = _share_map(rad.get(f"{layer}_{direction}_1d"), direction)
            base = _share_map(rad.get(f"{layer}_{direction}_7d"), direction)
            if not cur or not base:
                continue
            base_min = min(base.values())
            for cc, v in cur.items():
                b = base.get(cc)
                if b is None:
                    if v >= SHARE_DELTA_PP:
                        pats.append(_p("medium", "region", "region.new_top",
                                       {"cc": cc, "layer": layer, "dir": direction, "v": r1(v), "base_min": r1(base_min)},
                                       f"{cc}|{layer}|{direction}", cc))
                    continue
                d = v - b
                if d >= SHARE_DELTA_PP and b > 0 and d / b >= SHARE_REL:
                    sev = "high" if d >= 2 * SHARE_DELTA_PP else "medium"
                    pats.append(_p(sev, "region", "region.rise",
                                   {"cc": cc, "layer": layer, "dir": direction, "v": r1(v), "b": r1(b), "d": r1(d)},
                                   f"{cc}|{layer}|{direction}", cc))

    # 2) Vector / category shifts
    for k1, k7, kind in (("l3_vector_1d", "l3_vector_7d", "l3_vector"), ("l7_rules_1d", "l7_rules_7d", "l7_rule")):
        s1 = (rad.get(k1) or {}).get("summary") or {}
        s7 = (rad.get(k7) or {}).get("summary") or {}
        for vec, v in s1.items():
            b = s7.get(vec, 0.0)
            d = v - b
            if d >= VECTOR_DELTA_PP:
                pats.append(_p("medium", "vector", "vector.rise",
                               {"kind": kind, "name": vec, "v": r1(v), "b": r1(b), "d": r1(d)}, f"{kind}|{vec}"))

    # 3) Time-series spikes (last 24 h vs. previous hours)
    for key, kind in (("l3_vector_ts_7d", "l3_vector"), ("l7_rules_ts_7d", "l7_rule")):
        series = (rad.get(key) or {}).get("series") or {}
        for name, vals in series.items():
            xs = [x for x in vals if x is not None]
            if len(xs) < 72:
                continue
            recent, hist = xs[-24:], xs[:-24]
            mu, sd = statistics.fmean(hist), statistics.pstdev(hist)
            peak = max(recent)
            if sd > 0 and (peak - mu) / sd >= SPIKE_Z and peak >= 5:
                z = (peak - mu) / sd
                pats.append(_p("high" if z >= 2 * SPIKE_Z else "medium", "spike", "spike",
                               {"kind": kind, "name": name, "peak": r1(peak), "mu": r1(mu), "sd": r1(sd), "z": r1(z)},
                               f"{kind}|{name}"))

    # 4) C2 infrastructure
    if c2["total"] and c2["by_asn"]:
        top = c2["by_asn"][0]
        share = top["count"] / max(c2["total"], 1)
        if share >= ASN_CONCENTRATION and top["count"] >= 10:
            pats.append(_p("medium", "c2", "c2.asn_concentration",
                           {"asn": top["key"], "name": top["name"], "count": top["count"], "total": c2["total"],
                            "share": round(share * 100, 1)}, str(top["key"])))
    for it in c2["new_24h_by_malware"]:
        if it["count"] >= NEW_FAMILY_MIN and it["key"] not in c2["_families_before"]:
            pats.append(_p("high", "c2", "c2.new_family", {"family": it["key"], "count": it["count"]}, it["key"]))

    # 5) Ransomware increases (7 days vs. previous 7 days) – only if the previous week is fully recorded
    for it in (rw["by_country"] if rw["prev_window_complete"] else []):
        cc, cur = it["key"], it["count"]
        prev = rw["_prev_country"].get(cc, 0)
        if cc != "??" and cur >= RANSOM_MIN and cur >= RANSOM_FACTOR * max(prev, 1):
            pats.append(_p("high" if cur >= 3 * max(prev, 1) else "medium", "ransomware", "ransom.country_rise",
                           {"cc": cc, "cur": cur, "prev": prev}, cc, cc))
    for it in (rw["by_group"] if rw["prev_window_complete"] else []):
        g, cur = it["key"], it["count"]
        prev = rw["_prev_group"].get(g, 0)
        if cur >= 2 * RANSOM_MIN and cur >= RANSOM_FACTOR * max(prev, 1):
            pats.append(_p("medium", "ransomware", "ransom.group_rise", {"group": g, "cur": cur, "prev": prev}, g))

    # 6) Hotspots: top 10 in all three target rankings at the same time (correlation across sources)
    l7t = set(list(_share_map(rad.get("l7_target_1d"), "target"))[:10])
    l3t = set(list(_share_map(rad.get("l3_target_1d"), "target"))[:10])
    rwt = {i["key"] for i in rw["by_country"][:10] if i["key"] != "??"}
    hot = sorted(l7t & l3t & rwt)
    if hot and l7t and l3t:
        pats.append(_p("low", "correlation", "corr.hotspots", {"ccs": hot}, ",".join(hot),
                       hot[0] if len(hot) == 1 else None))

    # 7) Vulnerabilities
    for it in kev["vendors_14d"]:
        if it["count"] >= KEV_VENDOR_MIN:
            pats.append(_p("medium", "vuln", "vuln.kev_vendor", {"vendor": it["key"], "count": it["count"]}, it["key"]))
    if kev["ransomware_known_30d"]:
        pats.append(_p("medium", "vuln", "vuln.kev_ransom", {"count": kev["ransomware_known_30d"]}, "kev_ransom"))
    if kev.get("epss_high_14d"):
        pats.append(_p("medium", "vuln", "vuln.kev_epss", {"count": kev["epss_high_14d"], "thr": EPSS_HIGH}, "kev_epss"))

    # 8) Infrastructure: critical outage causes, clusters of hijacks
    if infra:
        seen: set[tuple[str, str]] = set()
        for e in infra["events"]:
            if e["kind"] != "outage" or e["cause"] not in CRITICAL_CAUSES:
                continue
            for cc in e["countries"] or [None]:
                if (cc or "", e["cause"]) in seen:
                    continue
                seen.add((cc or "", e["cause"]))
                params: dict[str, Any] = {"cc": cc, "cause": e["cause"], "ongoing": e["ongoing"], "event": e["meta"]}
                if e["cause"] == "CABLE_CUT" and cc and cables is not None:
                    cab = cables.for_country(cc)
                    if cab["cables"]:
                        params["cables"] = {"count": len(cab["cables"]), "snapshot": cab["snapshot"], "names": cab["cables"][:4]}
                pats.append(_p(CRITICAL_CAUSES[e["cause"]], "infra", "infra.critical", params,
                               f"{e['id']}|{cc or ''}", cc))
        hij24 = Counter(cc for e in infra["events"] if e["kind"] == "hijack" and e["last_24h"] for cc in e["countries"])
        for cc, cnt in hij24.most_common():
            if cnt >= HIJACK_COUNTRY_MIN:
                pats.append(_p("medium", "infra", "infra.hijack_cluster", {"cc": cc, "count": cnt}, cc, cc))

        # 9) Correlation: infrastructure disruption and rising attack pressure in the same country
        disturbed = {cc for e in infra["events"] if e["kind"] in ("outage", "hijack") for cc in e["countries"]}
        rising = {p["country"] for p in pats if p["key"] in ("region.rise", "region.new_top")
                  and p["params"].get("dir") == "target" and p.get("country")}
        for cc in sorted(disturbed & rising):
            pats.append(_p("medium", "correlation", "corr.disturbed_rising", {"cc": cc}, cc, cc))

    # 10) Alerts for own assets and watched products
    if watch and watch.get("hits_7d"):
        pats.append(_p("high" if watch.get("high_7d") else "medium", "alerts", "alerts.summary",
                       {"count": watch["hits_7d"]}, "alerts"))

    order = {"high": 0, "medium": 1, "low": 2}
    pats.sort(key=lambda p: (order[p["severity"]], p["category"], p["ident"]))
    return pats


def build(db: DB, geo: Geo, cables: Any = None) -> dict[str, Any]:
    rad = radar(db)
    c2 = c2_stats(db)
    rw = ransomware_stats(db)
    kev = kev_stats(db)
    infra = infra_stats(db)
    watch = watch_stats(db)
    pats = detect(geo, rad, c2, rw, kev, infra, watch, cables)
    countries = country_metrics(rad, c2, rw, infra)
    for d in (c2, rw):
        for k in [k for k in d if k.startswith("_")]:
            d.pop(k)
    return {
        "generated_at": _iso(datetime.now(timezone.utc)),
        "radar": rad,
        "c2": c2,
        "ransomware": rw,
        "kev": kev,
        "infra": infra,
        "watch": watch,
        "countries": countries,
        "patterns": pats,
    }


# --- timeline and trends -------------------------------------------------------
TIMELINE_METRICS = (("l7_target_1d", "target", "l7_target"), ("l7_origin_1d", "origin", "l7_origin"),
                    ("l3_target_1d", "target", "l3_target"), ("l3_origin_1d", "origin", "l3_origin"))


def timeline_days(db: DB) -> list[str]:
    rows = db.query("SELECT DISTINCT day FROM radar_hist ORDER BY day")
    days = {r["day"] for r in rows}
    first = db.query("SELECT MIN(discovered) AS m FROM victims")[0]["m"]
    if first:
        start = datetime.fromisoformat(first[:10]).date()
        today = datetime.now(timezone.utc).date()
        days |= {(start + timedelta(days=i)).isoformat() for i in range((today - start).days + 1)}
    return sorted(days)[-90:]


def timeline_day(db: DB, day: str) -> dict[str, Any]:
    """Map state for one calendar day (UTC)."""
    d0 = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
    d1 = d0 + timedelta(days=1)
    s0, s1, s7 = _iso(d0), _iso(d1), _iso(d1 - timedelta(days=7))
    countries: dict[str, dict[str, float]] = defaultdict(dict)
    final = True
    for key, field, name in TIMELINE_METRICS:
        snap = db.hist_on(key, day)
        if snap is None:
            continue
        final = final and bool(snap.get("final"))
        for r in snap.get("rows", []):
            if r.get(field):
                countries[r[field]][name] = r["value"]
    for r in db.query("SELECT country, COUNT(*) AS n FROM victims WHERE discovered >= ? AND discovered < ? "
                      "AND country IS NOT NULL GROUP BY country", (s7, s1)):
        countries[r["country"]]["ransomware_7d"] = r["n"]
    for r in db.query("SELECT country, COUNT(*) AS n FROM c2 WHERE country IS NOT NULL AND first_seen < ? "
                      "AND COALESCE(last_seen, first_seen) >= ? GROUP BY country", (s1, s7)):
        countries[r["country"]]["c2"] = r["n"]
    outages = db.query("SELECT countries FROM infra_events WHERE kind='outage' AND start_ts < ? AND COALESCE(end_ts, ?) >= ?",
                       (s1, s1, s0))
    for o in outages:
        for cc in json.loads(o["countries"] or "[]"):
            countries[cc]["outages_7d"] = countries[cc].get("outages_7d", 0) + 1
    pairs = db.hist_on("l7_pairs_1d", day)
    return {
        "day": day,
        "final": final,
        "countries": dict(countries),
        "pairs": (pairs or {}).get("rows", []),
        "c2_window": [s7, s1],
    }


def trends(db: DB, cc: str, days: int = 30) -> dict[str, Any]:
    today = datetime.now(timezone.utc).date()
    labels = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    series: dict[str, list[float | None]] = {}
    for key, field, name in TIMELINE_METRICS:
        by_day = {}
        for r in db.query("SELECT day, payload FROM radar_hist WHERE metric=? AND day >= ?", (key, labels[0])):
            rows = json.loads(r["payload"]).get("rows", [])
            by_day[r["day"]] = next((x["value"] for x in rows if x.get(field) == cc), None)  # None = not in the top 25
        series[name] = [by_day.get(d) for d in labels]
    rw = {r["d"]: r["n"] for r in db.query(
        "SELECT substr(discovered, 1, 10) AS d, COUNT(*) AS n FROM victims WHERE country=? AND discovered >= ? GROUP BY d",
        (cc, labels[0]))}
    series["ransomware"] = [rw.get(d, 0) for d in labels]
    c2n = {r["d"]: r["n"] for r in db.query(
        "SELECT substr(first_seen, 1, 10) AS d, COUNT(*) AS n FROM c2 WHERE country=? AND first_seen >= ? GROUP BY d",
        (cc, labels[0]))}
    series["c2_new"] = [c2n.get(d, 0) for d in labels]
    return {"cc": cc, "labels": labels, "series": series}
