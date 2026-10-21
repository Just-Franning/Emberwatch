"""Product watch: vendors/products you run, matched against CISA KEV and the NVD.

- KEV: local match on vendorProject/product/name (whole words, case-insensitive).
- NVD CVE API 2.0: keyword search ("vendor product", all words must appear in the description) over the
  modification window since the last check, so CVEs that get scored days after publication are caught too.
  Rate limits: 5 requests per rolling 30 s without key, 50 with NVD_API_KEY. One global request gate.

The first check of a new product is a silent baseline; alerts are only raised for later findings.
NVD alerts require CVSS >= PRODUCT_MIN_CVSS and publication within the last 90 days (old CVEs that are merely
re-analysed are listed but not alerted).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from . import alerts
from .config import Settings
from .db import DB, utcnow
from .i18n import AppError

log = logging.getLogger("products")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_PRODUCTS = 100
WINDOW_DAYS = 120  # NVD maximum for date ranges
ALERT_MAX_AGE_DAYS = 90
SEARCH_CACHE_S = 6 * 3600
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def norm(s: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _words_in(needle: str, hay: str) -> bool:
    return bool(needle) and f" {needle} " in f" {hay} "


def kev_match(vendor: str, product: str, row: dict[str, Any]) -> bool:
    v, p = norm(vendor), norm(product)
    kv = norm(row.get("vendor"))
    if not (v == kv or (len(v) >= 3 and (_words_in(v, kv) or _words_in(kv, v)))):
        return False
    return not p or _words_in(p, norm(f"{row.get('product') or ''} {row.get('name') or ''}"))


def validate(vendor: str, product: str) -> tuple[str, str]:
    v = re.sub(r"\s+", " ", (vendor or "").strip())[:60]
    p = re.sub(r"\s+", " ", (product or "").strip())[:80]
    if len(norm(v)) < 2:
        raise AppError("err.product_empty")
    if any(c in v + p for c in "<>\"'`\\"):
        raise AppError("err.bad_request")
    return v, p


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")  # NVD: no offset = UTC


def _cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """(score, severity, version) preferring CVSS 3.1 primary, then 4.0, 3.0, 2.0."""
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        items = metrics.get(key) or []
        if not items:
            continue
        items = sorted(items, key=lambda m: 0 if m.get("type") == "Primary" else 1)
        d = items[0].get("cvssData") or {}
        try:
            score = float(d.get("baseScore"))
        except (TypeError, ValueError):
            continue
        sev = d.get("baseSeverity") or items[0].get("baseSeverity")
        return score, (str(sev).upper() if sev else None), ver
    return None, None, None


def parse_cve(item: dict[str, Any]) -> dict[str, Any] | None:
    c = item.get("cve") or {}
    cid = str(c.get("id") or "").upper()
    if not CVE_RE.match(cid):
        return None
    desc = next((d.get("value") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "") or ""
    score, sev, ver = _cvss(c.get("metrics") or {})
    return {"cve": cid, "published": str(c.get("published") or "")[:19] + "Z" if c.get("published") else None,
            "last_modified": str(c.get("lastModified") or "")[:19] + "Z" if c.get("lastModified") else None,
            "cvss": score, "severity": sev, "cvss_version": ver, "status": str(c.get("vulnStatus") or "")[:40],
            "summary": re.sub(r"\s+", " ", desc).strip()[:600]}


class Products:
    def __init__(self, s: Settings, db: DB) -> None:
        self.s = s
        self.db = db
        self._gate = asyncio.Lock()
        self._last_req = 0.0
        self._gap = 0.8 if s.nvd_api_key else 6.5

    # --- NVD client ----------------------------------------------------------------------
    async def _nvd(self, client: httpx.AsyncClient, params: dict[str, Any]) -> dict[str, Any]:
        async with self._gate:
            wait = self._gap - (time.monotonic() - self._last_req)
            if wait > 0:
                await asyncio.sleep(wait)
            headers = {"User-Agent": self.s.user_agent, "Accept": "application/json"}
            if self.s.nvd_api_key:
                headers["apiKey"] = self.s.nvd_api_key
            try:
                r = await client.get(NVD_URL, params=params, headers=headers, timeout=60)
            except httpx.HTTPError as exc:
                raise AppError("err.nvd", 502, detail=exc.__class__.__name__) from exc
            finally:
                self._last_req = time.monotonic()
        if r.status_code != 200:
            msg = r.headers.get("message") or r.text[:120]
            raise AppError("err.nvd", 502, detail=f"HTTP {r.status_code} {msg}".strip()[:200])
        try:
            body = r.json()
        except ValueError as exc:
            raise AppError("err.nvd", 502, detail="invalid JSON") from exc
        return body if isinstance(body, dict) else {}

    async def nvd_search(self, client: httpx.AsyncClient, keyword: str, *, mod_start: datetime | None = None,
                         pub_start: datetime | None = None, max_pages: int = 5) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        params: dict[str, Any] = {"keywordSearch": keyword, "resultsPerPage": 2000, "startIndex": 0}
        if mod_start is not None:
            params.update(lastModStartDate=_fmt(max(mod_start, now - timedelta(days=WINDOW_DAYS - 1))), lastModEndDate=_fmt(now))
        if pub_start is not None:
            params.update(pubStartDate=_fmt(max(pub_start, now - timedelta(days=WINDOW_DAYS - 1))), pubEndDate=_fmt(now))
        out: list[dict[str, Any]] = []
        for _ in range(max_pages):
            body = await self._nvd(client, params)
            vulns = body.get("vulnerabilities") or []
            out += [c for c in (parse_cve(v) for v in vulns if isinstance(v, dict)) if c]
            total = int(body.get("totalResults") or 0)
            params["startIndex"] += len(vulns)
            if not vulns or params["startIndex"] >= total:
                break
        return out

    def _store_cves(self, cves: list[dict[str, Any]]) -> None:
        now = utcnow()
        self.db.execmany(
            "INSERT INTO nvd_cve(cve, published, last_modified, cvss, severity, summary, fetched_at) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(cve) DO UPDATE SET last_modified=excluded.last_modified, cvss=excluded.cvss, "
            "severity=excluded.severity, summary=excluded.summary, fetched_at=excluded.fetched_at",
            [(c["cve"], c["published"], c["last_modified"], c["cvss"], c["severity"], c["summary"], now) for c in cves],
        )

    async def cve_detail(self, client: httpx.AsyncClient, cve: str) -> dict[str, Any] | None:
        """One CVE from NVD (cached for a day). None if NVD does not know it."""
        cve = cve.upper()
        if not CVE_RE.match(cve):
            return None
        rows = self.db.query("SELECT cve, published, last_modified, cvss, severity, summary, fetched_at FROM nvd_cve WHERE cve=?", (cve,))
        if rows:
            ts = datetime.strptime(rows[0]["fetched_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - ts).total_seconds() < 86400:
                return rows[0]
        body = await self._nvd(client, {"cveId": cve})
        found = [c for c in (parse_cve(v) for v in body.get("vulnerabilities") or [] if isinstance(v, dict)) if c]
        if not found:
            return None
        self._store_cves(found[:1])
        return {**found[0], "fetched_at": utcnow()}

    # --- search integration --------------------------------------------------------------
    async def search(self, client: httpx.AsyncClient, q: str) -> dict[str, Any]:
        """Recent NVD CVEs (published within 120 days) for a free-text vendor/product query, cached 6 h."""
        key = norm(q)
        if len(key) < 3:
            return {"query": q, "cves": [], "cached": False}
        rows = self.db.query("SELECT payload, fetched_at FROM nvd_search_cache WHERE q=?", (key,))
        if rows:
            ts = datetime.strptime(rows[0]["fetched_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - ts).total_seconds() < SEARCH_CACHE_S:
                return {"query": q, "cves": json.loads(rows[0]["payload"]), "cached": True, "fetched_at": rows[0]["fetched_at"]}
        cves = await self.nvd_search(client, key, pub_start=datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS), max_pages=1)
        cves.sort(key=lambda c: c["published"] or "", reverse=True)
        cves = cves[:100]
        self._store_cves(cves)
        self.db.execute("INSERT INTO nvd_search_cache(q, fetched_at, payload) VALUES(?,?,?) "
                        "ON CONFLICT(q) DO UPDATE SET fetched_at=excluded.fetched_at, payload=excluded.payload",
                        (key, utcnow(), json.dumps(cves)))
        self.db.execute("DELETE FROM nvd_search_cache WHERE fetched_at < ?",
                        ((datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),))
        return {"query": q, "cves": cves, "cached": False, "fetched_at": utcnow()}

    # --- CRUD ------------------------------------------------------------------------------
    def add(self, vendor: str, product: str) -> int:
        v, p = validate(vendor, product)
        if self.db.query("SELECT 1 FROM products WHERE lower(vendor)=lower(?) AND lower(product)=lower(?)", (v, p)):
            raise AppError("err.product_exists", 409)
        if self.db.query("SELECT COUNT(*) AS n FROM products")[0]["n"] >= MAX_PRODUCTS:
            raise AppError("err.product_limit", max=MAX_PRODUCTS)
        return self.db.insert("INSERT INTO products(vendor, product, created_at) VALUES(?,?,?)", (v, p, utcnow()))

    def delete(self, pid: int) -> bool:
        self.db.execute("DELETE FROM product_cves WHERE product_id=?", (pid,))
        self.db.execute("DELETE FROM meta WHERE key IN (?,?,?)",
                        (f"product_baseline:{pid}", f"product_kevbase:{pid}", f"product_nvd:{pid}"))
        return self.db.execute("DELETE FROM products WHERE id=?", (pid,)) > 0

    def listing(self) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT id, vendor, product, created_at FROM products ORDER BY lower(vendor), lower(product)")
        for r in rows:
            c = self.db.query(
                "SELECT SUM(pc.source='kev') AS kev, SUM(pc.source='nvd') AS nvd, "
                "SUM(pc.source='nvd' AND n.cvss >= ?) AS critical FROM product_cves pc "
                "LEFT JOIN nvd_cve n ON n.cve = pc.cve WHERE pc.product_id=?", (self.s.product_min_cvss, r["id"]))[0]
            r.update({"kev": c["kev"] or 0, "nvd": c["nvd"] or 0, "critical": c["critical"] or 0,
                      "checked_at": self.db.meta_get(f"product_nvd:{r['id']}"),
                      "baseline": self.db.meta_get(f"product_baseline:{r['id']}") == "done"})
        return rows

    def cves(self, pid: int, limit: int = 300) -> list[dict[str, Any]]:
        return self.db.query(
            "SELECT pc.cve, pc.source, pc.first_seen, n.published, n.cvss, n.severity, n.summary, "
            "k.vendor AS kev_vendor, k.product AS kev_product, k.name AS kev_name, k.date_added AS kev_added, "
            "k.ransomware AS kev_ransomware, e.epss, e.percentile FROM product_cves pc "
            "LEFT JOIN nvd_cve n ON n.cve = pc.cve LEFT JOIN kev k ON k.cve = pc.cve LEFT JOIN epss e ON e.cve = pc.cve "
            "WHERE pc.product_id=? ORDER BY (k.cve IS NOT NULL) DESC, COALESCE(k.date_added, n.published) DESC LIMIT ?",
            (pid, limit))

    # --- periodic check ------------------------------------------------------------------------
    def _label(self, p: dict[str, Any]) -> str:
        return f"{p['vendor']} {p['product']}".strip()

    def check_kev(self, p: dict[str, Any], baseline: bool) -> int:
        have = {r["cve"] for r in self.db.query("SELECT cve FROM product_cves WHERE product_id=? AND source='kev'", (p["id"],))}
        new = 0
        now = utcnow()
        for k in self.db.query("SELECT k.cve, k.vendor, k.product, k.name, k.date_added, e.epss FROM kev k "
                               "LEFT JOIN epss e ON e.cve = k.cve"):
            if k["cve"] in have or not kev_match(p["vendor"], p["product"], k):
                continue
            self.db.execute("INSERT OR IGNORE INTO product_cves(product_id, cve, source, first_seen) VALUES(?,?,?,?)",
                            (p["id"], k["cve"], "kev", now))
            if not baseline:
                new += alerts.add(self.db, "product", "high", "product.kev",
                                  {"cve": k["cve"], "product": self._label(p), "vendor": k["vendor"], "kev_product": k["product"],
                                   "name": k["name"], "epss_v": k["epss"]},
                                  f"{p['id']}:{k['cve']}", product_id=p["id"],
                                  url=f"https://nvd.nist.gov/vuln/detail/{k['cve']}")
        return new

    async def check_nvd(self, client: httpx.AsyncClient, p: dict[str, Any], baseline: bool) -> int:
        last = self.db.meta_get(f"product_nvd:{p['id']}")
        now = datetime.now(timezone.utc)
        start = (datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - timedelta(hours=1)
                 if last else now - timedelta(days=30))
        cves = await self.nvd_search(client, self._label(p), mod_start=start)
        self._store_cves(cves)
        new = 0
        recent = (now - timedelta(days=ALERT_MAX_AGE_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        epss = {r["cve"]: r["epss"] for r in self.db.query("SELECT cve, epss FROM epss")} if cves else {}
        for c in cves:
            self.db.execute("INSERT OR IGNORE INTO product_cves(product_id, cve, source, first_seen) VALUES(?,?,?,?)",
                            (p["id"], c["cve"], "nvd", utcnow()))
            if baseline or c["cvss"] is None or c["cvss"] < self.s.product_min_cvss or (c["published"] or "") < recent:
                continue
            new += alerts.add(self.db, "product", "high" if c["cvss"] >= 9.0 else "medium", "product.cve",
                              {"cve": c["cve"], "product": self._label(p), "cvss": c["cvss"], "summary": c["summary"][:300],
                               "epss_v": epss.get(c["cve"])},
                              f"{p['id']}:{c['cve']}", product_id=p["id"], url=f"https://nvd.nist.gov/vuln/detail/{c['cve']}")
        self.db.meta_set(f"product_nvd:{p['id']}", now.strftime("%Y-%m-%dT%H:%M:%SZ"))
        return new

    async def check(self, client: httpx.AsyncClient, only: int | None = None, force: bool = False) -> int:
        """KEV + NVD check of all products (or one). Returns the number of new alerts."""
        rows = self.db.query("SELECT id, vendor, product FROM products" + (" WHERE id=?" if only else ""),
                             (only,) if only else ())
        if not rows:
            self.db.status("nvd", True, code="no_assets")
            return 0
        new, errors = 0, []
        due_before = (datetime.now(timezone.utc) - timedelta(hours=self.s.product_interval_h)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for p in rows:
            kev_base = self.db.meta_get(f"product_kevbase:{p['id']}") != "done"
            new += self.check_kev(p, kev_base)
            if kev_base:
                self.db.meta_set(f"product_kevbase:{p['id']}", "done")
            baseline = self.db.meta_get(f"product_baseline:{p['id']}") != "done"
            last = self.db.meta_get(f"product_nvd:{p['id']}")
            if force or baseline or not last or last < due_before:
                try:
                    new += await self.check_nvd(client, p, baseline)
                except AppError as exc:
                    errors.append(exc.params.get("detail", exc.key))
                    continue
                except httpx.HTTPError as exc:
                    errors.append(exc.__class__.__name__)
                    continue
            if baseline:
                self.db.meta_set(f"product_baseline:{p['id']}", "done")
        if errors:
            self.db.status("nvd", False, "; ".join(dict.fromkeys(errors))[:300])
        else:
            self.db.status("nvd", True, "", self.db.query("SELECT COUNT(*) AS n FROM nvd_cve")[0]["n"])
        return new
