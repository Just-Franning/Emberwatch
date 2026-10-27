"""Outages of large cloud and CDN platforms (3.3, optional, SOURCES_DISABLE=cloud_status).

Read from the providers' public status feeds (only what they publish publicly):
- AWS Health Dashboard RSS (status.aws.amazon.com/rss/all.rss)
- Azure status RSS (azure.status.microsoft/en-us/status/feed/) – Microsoft lists only incidents with wide impact
  there; everything else goes to affected customers through Azure Service Health.
- Google Cloud Service Health Atom feed (status.cloud.google.com/en/feed.atom)
- Cloudflare status page (Statuspage API v2, www.cloudflarestatus.com/api/v2/incidents.json)

Regions are recognised in the text (AWS/GCP region codes, Azure region names, "City, Country" for Cloudflare data
centers) and placed on the map at the location the provider documents for the region (a city, or – where the provider
names only a state or country – the largest city there, or the country centre). The precision is stored with each
location. Feeds are parsed with entity expansion and external references disabled (defusedxml).

"Used" platforms (Mein Netz) raise an alert for each new active incident.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from defusedxml import ElementTree as DET

from . import alerts
from .db import DB, utcnow
from .geo import Geo
from .news import _date, strip_html

log = logging.getLogger("emberwatch.platforms")

MAX_BYTES = 4 * 1024 * 1024
KEEP_DAYS = 30
STALE_HOURS = 48  # an incident without news for two days is no longer shown as active

PROVIDERS: dict[str, dict[str, str]] = {
    "aws": {"name": "AWS", "feed": "https://status.aws.amazon.com/rss/all.rss", "kind": "rss",
            "page": "https://health.aws.amazon.com/health/status"},
    "azure": {"name": "Microsoft Azure", "feed": "https://azure.status.microsoft/en-us/status/feed/", "kind": "rss",
              "page": "https://azure.status.microsoft/en-us/status"},
    "gcp": {"name": "Google Cloud", "feed": "https://status.cloud.google.com/en/feed.atom", "kind": "atom",
            "page": "https://status.cloud.google.com/"},
    "cloudflare": {"name": "Cloudflare", "feed": "https://www.cloudflarestatus.com/api/v2/incidents.json", "kind": "statuspage",
                   "page": "https://www.cloudflarestatus.com/"},
}

# Regions with the location the provider documents (code, name, place, first-level division, country).
# AWS: docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html; Google Cloud: product location
# pages (city per region); Azure: learn.microsoft.com/azure/reliability/regions-list ("physical location").
REGIONS: dict[str, list[tuple[str, str, str, str, str]]] = {
    "aws": [
        ("us-east-1", "US East (N. Virginia)", "", "Virginia", "US"), ("us-east-2", "US East (Ohio)", "", "Ohio", "US"),
        ("us-west-1", "US West (N. California)", "", "California", "US"), ("us-west-2", "US West (Oregon)", "", "Oregon", "US"),
        ("af-south-1", "Africa (Cape Town)", "Cape Town", "", "ZA"), ("ap-east-1", "Asia Pacific (Hong Kong)", "Hong Kong", "", "HK"),
        ("ap-east-2", "Asia Pacific (Taipei)", "Taipei", "", "TW"), ("ap-south-1", "Asia Pacific (Mumbai)", "Mumbai", "", "IN"),
        ("ap-south-2", "Asia Pacific (Hyderabad)", "Hyderabad", "", "IN"),
        ("ap-southeast-1", "Asia Pacific (Singapore)", "Singapore", "", "SG"),
        ("ap-southeast-2", "Asia Pacific (Sydney)", "Sydney", "", "AU"),
        ("ap-southeast-3", "Asia Pacific (Jakarta)", "Jakarta", "", "ID"),
        ("ap-southeast-4", "Asia Pacific (Melbourne)", "Melbourne", "", "AU"),
        ("ap-southeast-5", "Asia Pacific (Malaysia)", "", "", "MY"), ("ap-southeast-6", "Asia Pacific (New Zealand)", "", "", "NZ"),
        ("ap-southeast-7", "Asia Pacific (Thailand)", "", "", "TH"),
        ("ap-northeast-1", "Asia Pacific (Tokyo)", "Tokyo", "", "JP"), ("ap-northeast-2", "Asia Pacific (Seoul)", "Seoul", "", "KR"),
        ("ap-northeast-3", "Asia Pacific (Osaka)", "Osaka", "", "JP"), ("ca-central-1", "Canada (Central)", "", "", "CA"),
        ("ca-west-1", "Canada West (Calgary)", "Calgary", "", "CA"), ("eu-central-1", "Europe (Frankfurt)", "Frankfurt", "", "DE"),
        ("eu-central-2", "Europe (Zurich)", "Zurich", "", "CH"), ("eu-west-1", "Europe (Ireland)", "", "", "IE"),
        ("eu-west-2", "Europe (London)", "London", "", "GB"), ("eu-west-3", "Europe (Paris)", "Paris", "", "FR"),
        ("eu-south-1", "Europe (Milan)", "Milan", "", "IT"), ("eu-south-2", "Europe (Spain)", "", "", "ES"),
        ("eu-north-1", "Europe (Stockholm)", "Stockholm", "", "SE"), ("il-central-1", "Israel (Tel Aviv)", "Tel Aviv", "", "IL"),
        ("mx-central-1", "Mexico (Central)", "", "", "MX"), ("me-south-1", "Middle East (Bahrain)", "", "", "BH"),
        ("me-central-1", "Middle East (UAE)", "", "", "AE"), ("sa-east-1", "South America (São Paulo)", "São Paulo", "", "BR"),
    ],
    "gcp": [
        ("asia-east1", "Changhua County, Taiwan", "Changhua", "", "TW"), ("asia-east2", "Hong Kong", "Hong Kong", "", "HK"),
        ("asia-northeast1", "Tokyo", "Tokyo", "", "JP"), ("asia-northeast2", "Osaka", "Osaka", "", "JP"),
        ("asia-northeast3", "Seoul", "Seoul", "", "KR"), ("asia-south1", "Mumbai", "Mumbai", "", "IN"),
        ("asia-south2", "Delhi", "Delhi", "", "IN"), ("asia-southeast1", "Jurong West, Singapore", "Singapore", "", "SG"),
        ("asia-southeast2", "Jakarta", "Jakarta", "", "ID"), ("australia-southeast1", "Sydney", "Sydney", "", "AU"),
        ("australia-southeast2", "Melbourne", "Melbourne", "", "AU"), ("europe-central2", "Warsaw, Poland", "Warsaw", "", "PL"),
        ("europe-north1", "Hamina, Finland", "", "", "FI"), ("europe-north2", "Stockholm, Sweden", "Stockholm", "", "SE"),
        ("europe-southwest1", "Madrid, Spain", "Madrid", "", "ES"), ("europe-west1", "St. Ghislain, Belgium", "", "Hainaut", "BE"),
        ("europe-west2", "London, United Kingdom", "London", "", "GB"), ("europe-west3", "Frankfurt, Germany", "Frankfurt", "", "DE"),
        ("europe-west4", "Eemshaven, Netherlands", "", "Groningen", "NL"), ("europe-west6", "Zurich, Switzerland", "Zurich", "", "CH"),
        ("europe-west8", "Milan, Italy", "Milan", "", "IT"), ("europe-west9", "Paris, France", "Paris", "", "FR"),
        ("europe-west12", "Turin, Italy", "Turin", "", "IT"), ("me-central1", "Doha, Qatar", "Doha", "", "QA"),
        ("me-central2", "Dammam, Saudi Arabia", "Dammam", "", "SA"), ("me-west1", "Tel Aviv, Israel", "Tel Aviv", "", "IL"),
        ("northamerica-northeast1", "Montréal, Québec", "Montréal", "", "CA"),
        ("northamerica-northeast2", "Toronto, Ontario", "Toronto", "", "CA"),
        ("southamerica-east1", "Osasco, São Paulo, Brazil", "", "São Paulo", "BR"),
        ("southamerica-west1", "Santiago, Chile", "Santiago", "", "CL"),
        ("us-central1", "Council Bluffs, Iowa", "Council Bluffs", "Iowa", "US"),
        ("us-east1", "Moncks Corner, South Carolina", "", "South Carolina", "US"),
        ("us-east4", "Ashburn, Virginia", "", "Virginia", "US"), ("us-east5", "Columbus, Ohio", "Columbus", "Ohio", "US"),
        ("us-west1", "The Dalles, Oregon", "", "Oregon", "US"), ("us-west2", "Los Angeles", "Los Angeles", "California", "US"),
        ("us-west3", "Salt Lake City", "Salt Lake City", "Utah", "US"), ("us-west4", "Las Vegas, Nevada", "Las Vegas", "Nevada", "US"),
    ],
    "azure": [
        ("australiacentral", "Australia Central", "Canberra", "", "AU"), ("australiacentral2", "Australia Central 2", "Canberra", "", "AU"),
        ("australiaeast", "Australia East", "", "New South Wales", "AU"),
        ("australiasoutheast", "Australia Southeast", "", "Victoria", "AU"), ("austriaeast", "Austria East", "Vienna", "", "AT"),
        ("belgiumcentral", "Belgium Central", "Brussels", "", "BE"), ("brazilsouth", "Brazil South", "", "São Paulo", "BR"),
        ("brazilsoutheast", "Brazil Southeast", "Rio de Janeiro", "", "BR"), ("canadacentral", "Canada Central", "Toronto", "", "CA"),
        ("canadaeast", "Canada East", "Québec", "", "CA"), ("centralindia", "Central India", "Pune", "", "IN"),
        ("centralus", "Central US", "", "Iowa", "US"), ("chilecentral", "Chile Central", "Santiago", "", "CL"),
        ("denmarkeast", "Denmark East", "Copenhagen", "", "DK"), ("eastasia", "East Asia", "Hong Kong", "", "HK"),
        ("eastus", "East US", "", "Virginia", "US"), ("eastus2", "East US 2", "", "Virginia", "US"),
        ("francecentral", "France Central", "Paris", "", "FR"), ("francesouth", "France South", "Marseille", "", "FR"),
        ("germanynorth", "Germany North", "Berlin", "", "DE"), ("germanywestcentral", "Germany West Central", "Frankfurt", "", "DE"),
        ("indiasouthcentral", "India South Central", "Hyderabad", "", "IN"),
        ("indonesiacentral", "Indonesia Central", "Jakarta", "", "ID"), ("israelcentral", "Israel Central", "", "", "IL"),
        ("italynorth", "Italy North", "Milan", "", "IT"), ("japaneast", "Japan East", "Tokyo", "", "JP"),
        ("japanwest", "Japan West", "Osaka", "", "JP"), ("koreacentral", "Korea Central", "Seoul", "", "KR"),
        ("koreasouth", "Korea South", "Busan", "", "KR"), ("malaysiawest", "Malaysia West", "Kuala Lumpur", "", "MY"),
        ("mexicocentral", "Mexico Central", "", "Querétaro", "MX"), ("newzealandnorth", "New Zealand North", "Auckland", "", "NZ"),
        ("northcentralus", "North Central US", "", "Illinois", "US"), ("northeurope", "North Europe", "", "", "IE"),
        ("norwayeast", "Norway East", "", "", "NO"), ("norwaywest", "Norway West", "", "", "NO"),
        ("polandcentral", "Poland Central", "Warsaw", "", "PL"), ("qatarcentral", "Qatar Central", "Doha", "", "QA"),
        ("southafricanorth", "South Africa North", "Johannesburg", "", "ZA"),
        ("southafricawest", "South Africa West", "Cape Town", "", "ZA"), ("southcentralus", "South Central US", "", "Texas", "US"),
        ("southindia", "South India", "Chennai", "", "IN"), ("southeastasia", "Southeast Asia", "Singapore", "", "SG"),
        ("spaincentral", "Spain Central", "Madrid", "", "ES"), ("swedencentral", "Sweden Central", "Gävle", "", "SE"),
        ("switzerlandnorth", "Switzerland North", "Zurich", "", "CH"), ("switzerlandwest", "Switzerland West", "Geneva", "", "CH"),
        ("taiwannorth", "Taiwan North", "Taipei", "", "TW"), ("uaecentral", "UAE Central", "Abu Dhabi", "", "AE"),
        ("uaenorth", "UAE North", "Dubai", "", "AE"), ("uksouth", "UK South", "London", "", "GB"),
        ("ukwest", "UK West", "Cardiff", "", "GB"), ("westcentralus", "West Central US", "", "Wyoming", "US"),
        ("westeurope", "West Europe", "", "", "NL"), ("westindia", "West India", "Mumbai", "", "IN"),
        ("westus", "West US", "", "California", "US"), ("westus2", "West US 2", "", "Washington", "US"),
        ("westus3", "West US 3", "Phoenix", "", "US"),
    ],
}
PLACE_ALIASES = {"copenhagen": "københavn", "zurich": "zürich", "tel aviv": "tel aviv-yafo"}
AWS_CODE_RE = re.compile(r"\b((?:us-gov|us|eu|ap|sa|ca|me|af|il|mx)-(?:north|south|east|west|central|northeast|southeast|"
                         r"southwest|northwest)-\d{1,2})\b", re.I)  # AWS writes "US-EAST-1" in its texts
GCP_CODE_RE = re.compile(r"\b((?:asia|australia|europe|me|northamerica|southamerica|us|africa)-[a-z]+\d{1,2})\b")
CITY_RE = re.compile(r"([A-ZÀ-Ý][\w.'À-ÿ -]{1,40}?),\s+([A-Z][A-Za-z .'-]{2,40}?)(?=\s*(?:-|\(|,|$|\.|\s{2}))")
AWS_RESOLVED_RE = re.compile(r"^\s*service is operating normally|\[resolved\]|^\s*resolved\b", re.I)
AZURE_RESOLVED_RE = re.compile(r"\b(mitigated|resolved|mitigation (?:is |has been )?complete)\b", re.I)
PREFIX_RE = re.compile(r"^\s*(?:service is operating normally|informational message|service impact|performance issues|"
                       r"service disruption|resolved|update|mitigated|active|investigating)\s*[:\-–]\s*", re.I)


class Places:
    """City coordinates (Natural Earth, public domain) for the regions and data centers."""

    def __init__(self, path: Path, geo: Geo | None) -> None:
        self.geo = geo
        self.by_name: dict[tuple[str, str], list[list[Any]]] = {}
        self.by_adm1: dict[tuple[str, str], list[Any]] = {}
        self.countries: dict[str, str] = {}
        if path.exists():
            for row in json.loads(path.read_text(encoding="utf-8")).get("places", []):
                name, ascii_, cc, adm1 = row[0], row[1], row[2], row[3]
                for n in {name.lower(), ascii_.lower()}:
                    self.by_name.setdefault((n, cc), []).append(row)
                key = (adm1.lower(), cc)
                if adm1 and (key not in self.by_adm1 or row[6] > self.by_adm1[key][6]):
                    self.by_adm1[key] = row
        if geo is not None:
            for cc, c in geo.centroids.items():
                for n in (c.get("name_en"), c.get("name")):
                    if n:
                        self.countries[str(n).lower()] = cc

    def locate(self, place: str, adm1: str, cc: str) -> dict[str, Any] | None:
        if place:
            key = PLACE_ALIASES.get(place.lower(), place.lower())
            rows = self.by_name.get((key, cc)) or []
            if adm1:
                rows = [r for r in rows if r[3].lower() == adm1.lower()] or rows
            if rows:
                r = max(rows, key=lambda x: x[6])
                return {"lat": r[4], "lon": r[5], "precision": "city", "place": r[0]}
        if adm1 and (adm1.lower(), cc) in self.by_adm1:
            r = self.by_adm1[(adm1.lower(), cc)]
            return {"lat": r[4], "lon": r[5], "precision": "region", "place": adm1}
        c = self.geo.centroid(cc) if self.geo is not None else None
        if c:
            return {"lat": c[0], "lon": c[1], "precision": "country", "place": None}
        return None

    def city(self, text: str) -> list[tuple[str, str]]:
        """("City", "CC") pairs written as "City, Country" in a text."""
        out = []
        for m in CITY_RE.finditer(text[:3000]):
            city, country = m.group(1).strip(), m.group(2).strip().lower()
            cc = self.countries.get(country)
            if not cc:
                continue
            key = PLACE_ALIASES.get(city.lower(), city.lower())
            if (key, cc) in self.by_name:
                out.append((city, cc))
        return list(dict.fromkeys(out))[:10]


# --- parsing ------------------------------------------------------------------------------------------------------------
def _local(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _text(el: Any) -> str:
    return "".join(el.itertext()) if len(el) else (el.text or "")


def parse_feed(data: bytes) -> list[dict[str, Any]]:
    """Items of an RSS 2.0 or Atom status feed: title, link, guid, date, text."""
    root = DET.fromstring(data, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    out = []
    for it in (el for el in root.iter() if _local(el.tag) in ("item", "entry")):
        f: dict[str, Any] = {"title": "", "link": "", "guid": "", "date": None, "text": ""}
        for ch in it:
            name = _local(ch.tag)
            if name == "title" and not f["title"]:
                f["title"] = strip_html(_text(ch))[:300]
            elif name == "link" and not f["link"]:
                f["link"] = (ch.get("href") or (ch.text or "")).strip()
            elif name in ("guid", "id") and not f["guid"]:
                f["guid"] = (ch.text or "").strip()[:300]
            elif name in ("pubDate", "updated", "published") and f["date"] is None:
                f["date"] = _date(ch.text or "")
            elif name in ("description", "summary", "content") and not f["text"]:
                f["text"] = strip_html(_text(ch), 40000)[:4000]
        if f["title"]:
            out.append(f)
        if len(out) >= 300:
            break
    return out


def _key_title(title: str) -> str:
    t = PREFIX_RE.sub("", title)
    t = re.sub(r"\[(?:resolved|update|mitigated)\]\s*", "", t, flags=re.I)
    return re.sub(r"\s+", " ", t).strip().lower()[:200]


def incidents_from_feed(provider: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Groups the updates of a feed into incidents (one per key, oldest update = start, newest = state)."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for it in items:
        if it["date"] is None:
            continue
        if provider == "aws":
            frag = it["guid"].split("#", 1)[1] if "#" in it["guid"] else ""
            key = re.sub(r"_\d+$", "", frag)[:120] if frag else _key_title(it["title"])
        elif provider == "gcp":
            m = re.search(r"/incidents/([A-Za-z0-9]{6,40})", it["link"] or it["guid"])
            key = m.group(1) if m else _key_title(it["title"])
        else:
            key = _key_title(it["title"])
        groups.setdefault(key, []).append(it)
    def is_resolved(u: dict[str, Any]) -> bool:
        if provider == "aws":
            return bool(AWS_RESOLVED_RE.search(u["title"]))
        if provider == "gcp":
            return u["title"].strip().upper().startswith("RESOLVED")
        return bool(AZURE_RESOLVED_RE.search(u["title"] + " " + u["text"][:600]))

    out = []
    for key, ups in groups.items():
        ups.sort(key=lambda x: x["date"])
        # AWS and Azure reuse the same key for later incidents of the same service and region (or title): a new
        # incident starts after a resolved update or after two days without news
        runs: list[list[dict[str, Any]]] = []
        for u in ups:
            if not runs or is_resolved(runs[-1][-1]) or u["date"] - runs[-1][-1]["date"] > timedelta(hours=STALE_HOURS):
                runs.append([u])
            else:
                runs[-1].append(u)
        base = key or _key_title(ups[-1]["title"])
        for run in runs:
            last = run[-1]
            link = next((u["link"] for u in reversed(run) if (u["link"] or "").startswith("https://")), "")
            out.append({
                # the start time makes the key unique per incident (alerts are de-duplicated by it)
                "key": f"{base}@{run[0]['date'].astimezone(timezone.utc).strftime('%Y%m%d%H%M')}"[:200],
                "title": PREFIX_RE.sub("", last["title"]).strip() or last["title"],
                "resolved": is_resolved(last), "started": run[0]["date"], "updated": last["date"],
                "text": " ".join(u["title"] + " " + u["text"] for u in run)[:8000], "summary": last["text"][:600], "url": link,
                "impact": None,
            })
    return out


def incidents_from_statuspage(body: Any) -> list[dict[str, Any]]:
    out = []
    for inc in (body.get("incidents") if isinstance(body, dict) else None) or []:
        if not isinstance(inc, dict) or not inc.get("id"):
            continue
        ups = [u for u in inc.get("incident_updates") or [] if isinstance(u, dict)]
        texts = " ".join(str(u.get("body") or "") for u in ups)
        started = _date(str(inc.get("started_at") or inc.get("created_at") or ""))
        updated = _date(str(inc.get("updated_at") or "")) or started
        if started is None:
            continue
        link = str(inc.get("shortlink") or "")
        out.append({
            "key": str(inc["id"])[:60], "title": str(inc.get("name") or "")[:300],
            "resolved": str(inc.get("status") or "") in ("resolved", "postmortem", "completed"),
            "started": started, "updated": updated, "text": (str(inc.get("name") or "") + " " + texts)[:8000],
            "summary": strip_html(str(ups[0].get("body") or ""))[:600] if ups else "",
            "url": link if link.startswith("https://") else "", "impact": str(inc.get("impact") or "")[:20] or None,
        })
    return out


# --- collector ----------------------------------------------------------------------------------------------------------
class Platforms:
    def __init__(self, db: DB, geo: Geo | None, data_dir: Path) -> None:
        self.db = db
        self.places = Places(data_dir / "places.json", geo)
        self.regions: dict[str, dict[str, dict[str, Any]]] = {}
        for prov, rows in REGIONS.items():
            self.regions[prov] = {}
            for code, name, place, adm1, cc in rows:
                loc = self.places.locate(place, adm1, cc) or {}
                self.regions[prov][code] = {"code": code, "name": name, "cc": cc, **loc}
        self._azure_rx = re.compile("(" + "|".join(re.escape(r[1]) for r in sorted(REGIONS["azure"], key=lambda r: -len(r[1])))
                                    + r")(?![0-9A-Za-z])")
        self._aws_names = {r[1].split("(", 1)[1].rstrip(")").lower(): r[0] for r in REGIONS["aws"] if "(" in r[1]}

    def locations(self, provider: str, text: str) -> list[dict[str, Any]]:
        """Regions or places named in an incident, each with its map position (if known)."""
        codes: list[str] = []
        if provider == "aws":
            codes = [c.lower() for c in AWS_CODE_RE.findall(text)]
            for name, code in self._aws_names.items():
                if f"({name})" in text.lower():
                    codes.append(code)
        elif provider == "gcp":
            codes = GCP_CODE_RE.findall(text)
        elif provider == "azure":
            names = {r[1]: r[0] for r in REGIONS["azure"]}
            codes = [names[m] for m in self._azure_rx.findall(text)]
        out = []
        for code in dict.fromkeys(codes):
            reg = self.regions.get(provider, {}).get(code)
            out.append(dict(reg) if reg else {"code": code, "name": code})
        if provider == "cloudflare":
            for city, cc in self.places.city(text):
                loc = self.places.locate(city, "", cc) or {}
                out.append({"code": None, "name": f"{city}, {cc}", "cc": cc, **loc})
        return out[:12]

    async def _fetch(self, client: httpx.AsyncClient, prov: str, ua: str) -> bytes | None:
        p = PROVIDERS[prov]
        headers = {"User-Agent": ua}
        self.db.meta_set(f"status_etag:{prov}:new", "")  # never take over the validator of an earlier, failed fetch
        etag = self.db.meta_get(f"status_etag:{prov}")
        if etag:
            headers["If-None-Match"] = etag
        async with client.stream("GET", p["feed"], headers=headers, timeout=30) as r:
            if r.status_code == 304:
                return None
            if r.status_code != 200:
                raise ValueError(f"HTTP {r.status_code}")
            buf = bytearray()
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > MAX_BYTES:
                    raise ValueError("feed too large")
            if r.headers.get("etag"):
                self.db.meta_set(f"status_etag:{prov}:new", r.headers["etag"][:200])
        return bytes(buf)

    async def collect(self, client: httpx.AsyncClient, ua: str) -> int:
        """Reads all four feeds. Returns the number of new alerts."""
        new_alerts = 0
        for prov in PROVIDERS:
            try:
                data = await self._fetch(client, prov, ua)
                if data is not None:
                    incs = (incidents_from_statuspage(json.loads(data)) if PROVIDERS[prov]["kind"] == "statuspage"
                            else incidents_from_feed(prov, await asyncio.to_thread(parse_feed, data)))
                    new_alerts += self._store(prov, incs)
                    tag = self.db.meta_get(f"status_etag:{prov}:new")
                    if tag:
                        self.db.meta_set(f"status_etag:{prov}", tag)
                n = self.db.query("SELECT COUNT(*) AS n FROM platform_incidents WHERE provider = ? AND status = 'active'",
                                  (prov,))[0]["n"]
                self.db.status(f"status_{prov}", True, "", n)
            except Exception as exc:  # one provider must not stop the others
                log.warning("status feed %s: %s", prov, exc.__class__.__name__)
                self.db.status(f"status_{prov}", False, f"{exc.__class__.__name__}: {str(exc)[:160]}")
            await asyncio.sleep(0.5)
        now = datetime.now(timezone.utc)
        # also without new feed data (304): an incident without news for two days no longer counts as active
        self.db.execute("UPDATE platform_incidents SET status = 'resolved', resolved = updated WHERE status = 'active' AND updated < ?",
                        (_iso(now - timedelta(hours=STALE_HOURS)),))
        self.db.execute("DELETE FROM platform_incidents WHERE updated < ?", (_iso(now - timedelta(days=KEEP_DAYS)),))
        return new_alerts

    def _store(self, prov: str, incs: list[dict[str, Any]]) -> int:
        now = datetime.now(timezone.utc)
        used = set(self.used())
        new_alerts = 0
        for inc in incs:
            iid = self._incident_id(prov, inc)
            stale = now - inc["updated"] > timedelta(hours=STALE_HOURS)
            status = "resolved" if inc["resolved"] or stale else "active"
            # AWS names the region in the GUID of an update ("…#ec2-us-east-1_1700000000"), not always in the text
            regions = self.locations(prov, (inc["key"].split("@", 1)[0] + " " if prov == "aws" else "") + inc["text"])
            prev = self.db.query("SELECT status FROM platform_incidents WHERE id = ?", (iid,))
            self.db.execute(
                "INSERT INTO platform_incidents(id, provider, title, status, impact, started, updated, resolved, regions, url, "
                "summary, fetched_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title, "
                "status=excluded.status, impact=excluded.impact, updated=excluded.updated, resolved=excluded.resolved, "
                "regions=excluded.regions, url=excluded.url, summary=excluded.summary, fetched_at=excluded.fetched_at",
                (iid, prov, inc["title"][:300], status, inc["impact"], _iso(inc["started"]), _iso(inc["updated"]),
                 _iso(inc["updated"]) if status == "resolved" else None, json.dumps(regions, ensure_ascii=False),
                 inc["url"] or None, inc["summary"][:600] or None, utcnow()))
            quiet = (inc.get("impact") or "") in ("none", "maintenance")  # Cloudflare: no customer impact
            if status == "active" and prov in used and not quiet and not (prev and prev[0]["status"] == "active"):
                if alerts.add(self.db, "platform", "medium", "platform.incident",
                              {"provider": PROVIDERS[prov]["name"], "title": inc["title"][:200],
                               "regions": ", ".join(r["name"] for r in regions[:4])},
                              f"{iid}", url=inc["url"] or PROVIDERS[prov]["page"]):
                    new_alerts += 1
        return new_alerts

    def _incident_id(self, prov: str, inc: dict[str, Any]) -> str:
        """Id of an incident. Feed keys carry the start time ("ec2-us-east-1@202610221055"); when the first updates of a
        long incident have dropped out of the feed, its start moves: the open incident of the same key continues."""
        iid = f"{prov}:{inc['key']}"
        if "@" not in inc["key"] or self.db.query("SELECT 1 FROM platform_incidents WHERE id = ?", (iid,)):
            return iid
        base = f"{prov}:{inc['key'].split('@', 1)[0]}@"
        like = base.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        rows = self.db.query("SELECT id, started, updated FROM platform_incidents WHERE id LIKE ? ESCAPE '\\' "
                             "AND status = 'active' ORDER BY started DESC LIMIT 1", (like,))
        if rows:
            started, updated = _parse(rows[0]["started"]), _parse(rows[0]["updated"])
            if started and updated and started <= inc["started"] <= updated + timedelta(hours=STALE_HOURS):
                return rows[0]["id"]
        return iid

    # --- settings and queries -----------------------------------------------------------------------------------------
    def used(self) -> list[str]:
        try:
            v = json.loads(self.db.meta_get("platforms_used") or "[]")
        except ValueError:
            v = []
        return [p for p in v if p in PROVIDERS] if isinstance(v, list) else []

    def set_used(self, providers: list[str]) -> list[str]:
        keep = [p for p in PROVIDERS if p in set(providers)]
        self.db.meta_set("platforms_used", json.dumps(keep))
        return keep

    def listing(self, days: int = 7, active_only: bool = False) -> list[dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        sql = "SELECT * FROM platform_incidents WHERE updated >= ?" + (" AND status = 'active'" if active_only else "")
        out = []
        used = set(self.used())
        for r in self.db.query(sql + " ORDER BY (status = 'active') DESC, updated DESC LIMIT 300", (cutoff,)):
            try:
                regions = json.loads(r["regions"] or "[]")
            except ValueError:
                regions = []
            out.append({"id": r["id"], "provider": r["provider"], "provider_name": PROVIDERS.get(r["provider"], {}).get("name"),
                        "title": r["title"], "status": r["status"], "impact": r["impact"], "started": r["started"],
                        "updated": r["updated"], "resolved": r["resolved"], "regions": regions, "summary": r["summary"],
                        "url": r["url"] or PROVIDERS.get(r["provider"], {}).get("page"), "used": r["provider"] in used})
        return out

    def providers(self) -> list[dict[str, Any]]:
        used = set(self.used())
        return [{"id": k, "name": v["name"], "page": v["page"], "used": k in used} for k, v in PROVIDERS.items()]


def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str | None) -> datetime | None:
    try:
        return datetime.strptime(s or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
