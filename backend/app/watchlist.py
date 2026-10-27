"""Watchlist of own assets: IP, CIDR, ASN, domain.

Matching against threat feeds (runs after every feed update):
- C2 inventory (Feodo, ThreatFox): IP in network, AS number, domain/URL host
- Infrastructure events (Cloudflare Radar): involved ASNs, for hijacks also affected prefixes
- Ransomware victims: victim name equals the domain or a subdomain of it
- Further network IOCs (3.3: ThreatFox payload/IOC URLs and domains, URLhaus malware URLs): host on the domain or a
  subdomain of it, IP in the network (C2 entries are matched above and not twice)
New hits become alerts (alerts.py); each hit is stored exactly once.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlsplit

from . import alerts
from .db import DB
from .i18n import AppError

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{0,62}(?<!-)$")
ASN_RE = re.compile(r"^(?:as)?(\d{1,10})$", re.I)
MAX_ENTRIES = 500


def normalize(value: str, kind: str | None = None) -> tuple[str, str]:
    """Detects the type and normalizes the value. Returns (kind, value)."""
    v = (value or "").strip()
    if not v or len(v) > 260:
        raise AppError("err.watch_empty")
    if kind in (None, "", "auto"):
        if "/" in v:
            kind = "cidr"
        elif ASN_RE.match(v):  # "AS3320" or a plain number
            kind = "asn"
        else:
            try:
                ipaddress.ip_address(v)
                kind = "ip"
            except ValueError:
                kind = "domain"
    if kind == "ip":
        try:
            return "ip", str(ipaddress.ip_address(v))
        except ValueError as exc:
            raise AppError("err.watch_ip") from exc
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise AppError("err.watch_cidr") from exc
        if net.prefixlen < (8 if net.version == 4 else 16):
            raise AppError("err.watch_cidr_big")
        return "cidr", str(net)
    if kind == "asn":
        m = ASN_RE.match(v)
        if not m or not (0 < int(m.group(1)) < 4294967296):
            raise AppError("err.watch_asn")
        return "asn", str(int(m.group(1)))
    if kind == "domain":
        try:
            d = v.lower().rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise AppError("err.watch_domain") from exc
        if not DOMAIN_RE.match(d):
            raise AppError("err.watch_domain")
        return "domain", d
    raise AppError("err.watch_kind")


def host_of(ioc: str) -> str | None:
    s = (ioc or "").strip().lower()
    if not s:
        return None
    if "://" in s:
        try:
            return (urlsplit(s).hostname or "").rstrip(".") or None
        except ValueError:
            return None
    if s.startswith("["):  # [IPv6]:port
        return s[1:s.find("]")] if "]" in s else None
    if s.count(":") == 1:  # host:port
        return s.split(":")[0].rstrip(".")
    return s.rstrip(".")


def domain_match(host: str | None, domain: str) -> bool:
    return bool(host) and (host == domain or host.endswith("." + domain))


def network_of(entry: dict[str, Any]) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if entry["kind"] == "ip":
        return ipaddress.ip_network(entry["value"])
    return ipaddress.ip_network(entry["value"], strict=False)


def asset_label(entry: dict[str, Any]) -> str:
    v = f"AS{entry['value']}" if entry["kind"] == "asn" else entry["value"]
    return f"{v} ({entry['label']})" if entry.get("label") else v


def scan(db: DB) -> list[int]:
    """Matches all watchlist entries against the feeds. Returns the ids of new alerts' assets (for logging)."""
    entries = db.query("SELECT id, kind, value, label FROM watchlist")
    if not entries:
        return []
    c2 = db.query("SELECT id, source, ioc, ip, port, malware, threat_type, asn, as_name, reference FROM c2")
    infra = db.query("SELECT id, kind, asns, prefixes, meta, url FROM infra_events")
    victims = db.query("SELECT id, victim, grp, permalink FROM victims")
    iocs = db.query("SELECT id, ioc, ip, host, threat_type, malware, reference FROM iocs "
                    "WHERE threat_type IS NULL OR threat_type != 'botnet_cc'")
    by_host: dict[str, list[dict[str, Any]]] = {}
    with_ip: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, dict[str, Any]]] = []
    for r in iocs:
        if r["host"]:
            by_host.setdefault(r["host"].lower().rstrip("."), []).append(r)
        if r["ip"]:
            try:
                with_ip.append((ipaddress.ip_address(r["ip"]), r))
            except ValueError:
                pass
    # IOC hosts per watched domain (each host is walked up its parent domains once)
    watched = {w["value"] for w in entries if w["kind"] == "domain"}
    on_domain: dict[str, list[dict[str, Any]]] = {}
    for h, rs in by_host.items():
        labels = h.split(".")
        for i in range(len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in watched:
                on_domain.setdefault(parent, []).extend(rs)
    new: list[int] = []

    def hit(w: dict[str, Any], sev: str, key: str, params: dict[str, Any], ref: str, url: str | None) -> None:
        if alerts.add(db, "watch", sev, key, {"asset": asset_label(w), **params}, f"{w['id']}:{ref}",
                      asset_id=w["id"], url=url):
            new.append(w["id"])

    def ioc_hits(w: dict[str, Any], key: str, rows: list[dict[str, Any]]) -> None:
        """Malware indicators (ThreatFox, URLhaus) of one asset: one alert for all new ones of a run, not one per URL
        (a compromised host often serves a file per CPU architecture)."""
        if not rows:
            return
        seen: set[str] = set()
        for a in db.query("SELECT params FROM alerts WHERE source = 'watch' AND asset_id = ? AND key IN ('watch.ioc_ip', "
                          "'watch.ioc_domain')", (w["id"],)):
            try:
                seen.update(str(x) for x in json.loads(a["params"] or "{}").get("ids") or [])
            except (ValueError, AttributeError):
                continue
        fresh = [r for r in dict((str(r["id"]), r) for r in rows).values() if str(r["id"]) not in seen]
        if not fresh:
            return
        first = fresh[0]
        hit(w, "high", key, {"ioc": first["ioc"][:300], "threat": first["threat_type"] or "ioc", "malware": first["malware"],
                             "n": len(fresh), "ids": [str(r["id"]) for r in fresh][:500]},
            f"ioc:{first['id']}", first["reference"])

    for w in entries:
        kind, val = w["kind"], w["value"]
        if kind in ("ip", "cidr"):
            net = network_of(w)
            for r in c2:
                try:
                    if r["ip"] and ipaddress.ip_address(r["ip"]) in net:
                        hit(w, "high", "watch.c2_ip", {"malware": r["malware"], "ioc": r["ioc"]}, f"c2:{r['id']}", r["reference"])
                except ValueError:
                    continue
            for e in infra:
                for pfx in json.loads(e["prefixes"] or "[]"):
                    try:
                        if ipaddress.ip_network(pfx, strict=False).overlaps(net):
                            hit(w, "high", "watch.infra_prefix",
                                {"event_kind": e["kind"], "event_meta": _meta(e), "prefix": pfx}, f"infra:{e['id']}", e["url"])
                            break
                    except (ValueError, TypeError):
                        continue
            ioc_hits(w, "watch.ioc_ip", [r for addr, r in with_ip if addr in net])
        elif kind == "asn":
            asn = int(val)
            for r in c2:
                if r["asn"] == asn:
                    hit(w, "medium", "watch.c2_asn", {"asn": asn, "malware": r["malware"], "ioc": r["ioc"]},
                        f"c2:{r['id']}", r["reference"])
            for e in infra:
                if asn in json.loads(e["asns"] or "[]"):
                    hit(w, "medium", "watch.infra_asn", {"asn": asn, "event_kind": e["kind"], "event_meta": _meta(e)},
                        f"infra:{e['id']}", e["url"])
        elif kind == "domain":
            for r in c2:
                if r["threat_type"] in ("domain", "url") and domain_match(host_of(r["ioc"]), val):
                    hit(w, "high", "watch.c2_domain", {"malware": r["malware"], "ioc": r["ioc"]}, f"c2:{r['id']}", r["reference"])
            for v in victims:
                if domain_match(host_of(v["victim"]), val):
                    hit(w, "high", "watch.leak_victim", {"group": v["grp"], "victim": v["victim"]}, f"rw:{v['id']}", v["permalink"])
            ioc_hits(w, "watch.ioc_domain", on_domain.get(val, []))
    return new


def _meta(e: dict[str, Any]) -> dict[str, Any]:
    try:
        m = json.loads(e.get("meta") or "{}")
    except ValueError:
        m = {}
    m["kind"] = e["kind"]
    return m
