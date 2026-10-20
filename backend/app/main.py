"""Emberwatch – FastAPI app with background collectors, alerting, attack surface, log analysis and network tools."""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import logging
import os
import re
import tempfile
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Awaitable, Callable
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import httpx
from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import alerts, analytics, i18n, watchlist
from .ai import TASKS, Gemini, build_context
from .auth import COOKIE, Auth
from .bgp import BgpMonitor
from .cables import Cables
from .config import load
from .db import DB, open_path, utcnow
from .domains import Domains
from .geo import Geo
from .i18n import AppError, t
from .logs import Matcher, SyslogServer, analyze_file
from .notify import Notifier
from .products import Products
from .reputation import Reputation
from .sources import abusech, epss, infra, kev, radar, ransomware
from .surface import Surface
from .tools import ToolKit, parse_ports

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("websockets").setLevel(logging.WARNING)
log = logging.getLogger("emberwatch")

S = load()
db = DB(open_path(S.data_dir))
geo = Geo(S.data_dir, S.static_dir / "data" / "centroids.json", S.user_agent)
cables = Cables(S.static_dir / "data")
ai = Gemini(S.gemini_api_key, S.gemini_model, S.ai_min_interval_s)
notifier = Notifier(S, db, geo.country_name)
reputation = Reputation(S, db)
toolkit = ToolKit(S, db, geo, reputation)
products = Products(S, db)
surface = Surface(S, db, geo)
domains = Domains(S, db)
bgp = BgpMonitor(S, db)
matcher = Matcher(db, reputation)
syslog = SyslogServer(S, db, matcher) if S.syslog_enabled else None
auth = Auth(S)
try:
    TZ = ZoneInfo(S.timezone)
except Exception:
    TZ = ZoneInfo("Europe/Berlin")

CC_RE = re.compile(r"^[A-Z]{2}$")
DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_overview_cache: dict[str, Any] = {"t": 0.0, "data": None}
_country_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_bg: set[asyncio.Task] = set()
_jobs: dict[str, dict[str, Any]] = {}
_log_lock = asyncio.Lock()


# --- helpers ---------------------------------------------------------------------------------------------
def overview(force: bool = False) -> dict[str, Any]:
    if force or _overview_cache["data"] is None or time.time() - _overview_cache["t"] > 60:
        _overview_cache["data"] = analytics.build(db, geo, cables)
        _overview_cache["t"] = time.time()
    return _overview_cache["data"]


def _invalidate() -> None:
    _overview_cache["data"] = None
    _country_cache.clear()


def _event(e: dict[str, Any], lang: str) -> dict[str, Any]:
    meta = e.get("meta") or {}
    return {**e, "title": i18n.render_infra_title(e["kind"], meta, lang), "detail": i18n.render_infra_detail(meta, lang)}


def localized(ov: dict[str, Any], lang: str) -> dict[str, Any]:
    out = dict(ov)
    out["patterns"] = [i18n.render_pattern(p, lang, geo.country_name) for p in ov["patterns"]]
    inf = dict(ov["infra"])
    inf["events"] = [_event(e, lang) for e in ov["infra"]["events"]]
    out["infra"] = inf
    return out


def _cutoff(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lang(request: Request) -> str:
    return getattr(request.state, "lang", S.language)


def detect_lang(request: Request) -> str:
    c = request.cookies.get("ew_lang")
    if c in i18n.LANGS:
        return c
    for part in request.headers.get("accept-language", "").split(","):
        code = part.split(";")[0].strip().lower()[:2]
        if code in i18n.LANGS:
            return code
    return S.language


def _spawn(coro: Awaitable[Any]) -> asyncio.Task:
    task = asyncio.ensure_future(coro)
    _bg.add(task)
    task.add_done_callback(_bg.discard)
    task.add_done_callback(_report)
    return task


def _report(task: asyncio.Task) -> None:
    """Background tasks must not fail silently."""
    if task.cancelled():
        return
    exc = task.exception()
    if isinstance(exc, AppError):
        log.info("background task: %s", exc.key)
    elif exc is not None:
        log.error("background task failed: %s", exc.__class__.__name__, exc_info=exc)


def kick(name: str, fn: Callable[[], Awaitable[Any]]) -> None:
    """Runs a job in the background now. If it is already running, it runs once more afterwards.
    Must be called from the event loop thread (async endpoints and jobs only)."""
    st = _jobs.setdefault(name, {"running": False, "again": False})
    if st["running"]:
        st["again"] = True
        return

    async def runner() -> None:
        st["running"] = True
        try:
            while True:
                st["again"] = False
                try:
                    await fn()
                except AppError as exc:
                    log.info("job %s: %s", name, exc.key)
                except Exception:
                    log.exception("job %s failed", name)
                if not st["again"]:
                    break
        finally:
            st["running"] = False

    _spawn(runner())


async def _loop(name: str, minutes: float, fn: Callable[[], Awaitable[None]], delay: float = 0) -> None:
    await asyncio.sleep(delay)
    while True:
        started = time.time()
        try:
            await fn()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("job %s failed", name)
        await asyncio.sleep(max(30.0, minutes * 60 - (time.time() - started)))


async def _after_update() -> None:
    """After every feed update: drop caches and match the watchlist against the feeds."""
    _invalidate()
    matcher.invalidate()
    if watchlist.scan(db):
        _invalidate()


async def _daily_report(client: httpx.AsyncClient) -> None:
    if not S.daily_report_time:
        return
    now = datetime.now(TZ)
    today = now.date().isoformat()
    if now.strftime("%H:%M") < S.daily_report_time or db.meta_get("daily_report_last") == today:
        return
    ov = overview(force=True)
    lang = S.language
    if ai.enabled:
        try:
            ctx = build_context(ov, geo.country_name, lang, region=S.home_region)
            result = await ai.analyze(client, TASKS[lang]["daily"], ctx, lang)
        except AppError as exc:
            log.warning("daily report postponed: %s", exc.render("en"))
            return  # next attempt in one minute
        result["id"] = db.insert("INSERT INTO ai_reports(created_at, scope, model, payload) VALUES(?,?,?,?)",
                                 (utcnow(), "daily", result["model"], json.dumps(result)))
        if notifier.enabled:
            ok, msg = await notifier.report(client, result)
            if not ok:
                log.warning("daily report not delivered to Matrix: %s", msg)
    elif notifier.enabled:
        pats = [i18n.render_pattern(p, lang, geo.country_name) for p in ov["patterns"][:10]]
        await notifier.report(client, {
            "title": t(lang, "notify.daily_fallback_title", date=today), "summary": t(lang, "notify.daily_fallback_summary"),
            "findings": [{"severity": p["severity"], "title": p["title"], "detail": p["detail"]} for p in pats],
        })
    db.meta_set("daily_report_last", today)


# --- jobs ----------------------------------------------------------------------------------------------------
class _ClientRef:
    """Late-bound HTTP client, so jobs always use app.state.client (replaceable in tests)."""

    def __getattr__(self, name: str) -> Any:
        return getattr(app.state.client, name)


def job_fns(client: Any) -> dict[str, Callable[[], Awaitable[None]]]:
    async def c2_job() -> None:
        await geo.ensure(client)  # downloads only when missing or older than 30 days
        await abusech.collect_feodo(client, db, geo, S.user_agent, S.abusech_auth_key)
        await abusech.collect_threatfox(client, db, geo, S.user_agent, S.abusech_auth_key)
        abusech.prune(db, S.c2_retention_days, S.ioc_retention_days)
        await _after_update()

    async def radar_job() -> None:
        await radar.collect(client, db, S.cf_api_token)
        _invalidate()

    async def backfill_job() -> None:
        if await radar.backfill(client, db, S.cf_api_token, S.backfill_days):
            _invalidate()

    async def infra_job() -> None:
        await infra.collect(client, db, S.cf_api_token)
        await _after_update()

    async def ransomware_job() -> None:
        await ransomware.backfill(client, db, S.user_agent, S.ransomware_live_api_key)
        await ransomware.collect(client, db, S.user_agent, S.ransomware_live_api_key)
        await _after_update()

    async def kev_job() -> None:
        ok = await kev.collect(client, db, S.user_agent)
        if ok and not db.query("SELECT 1 FROM epss LIMIT 1"):
            await epss.collect(client, db, S.user_agent)
        _invalidate()
        if ok:
            kick("products", products_job)

    async def epss_job() -> None:
        await epss.collect(client, db, S.user_agent)
        _invalidate()

    async def products_job() -> None:
        await products.check(client)
        cves = [r["cve"] for r in db.query("SELECT DISTINCT cve FROM product_cves")]
        await epss.ensure(client, db, S.user_agent, cves)
        _invalidate()

    async def reputation_job() -> None:
        await reputation.refresh(client)
        await reputation.scan_assets(client)

    async def surface_job() -> None:
        await surface.passive(client)
        await epss.ensure(client, db, S.user_agent, epss.own_cves(db))
        _invalidate()

    async def scan_job() -> None:
        await surface.scheduled()

    async def ct_job() -> None:
        await domains.ct(client)

    async def typo_job() -> None:
        await domains.typos()

    async def alerts_job() -> None:
        if notifier.enabled:
            await notifier.alerts(client)

    async def patterns_job() -> None:
        if notifier.enabled:
            await notifier.patterns(client, overview()["patterns"])

    async def daily_job() -> None:
        await _daily_report(client)

    async def maintenance_job() -> None:
        alerts.prune(db, S.alert_retention_days)
        db.execute("DELETE FROM nvd_cve WHERE cve NOT IN (SELECT cve FROM product_cves) AND fetched_at < ?", (_cutoff(7),))
        db.execute("DELETE FROM abuseipdb_cache WHERE fetched_at < ?", (_cutoff(7),))

    return {
        "c2": c2_job, "radar": radar_job, "backfill": backfill_job, "infra": infra_job, "ransomware": ransomware_job,
        "kev": kev_job, "epss": epss_job, "products": products_job, "reputation": reputation_job, "surface": surface_job,
        "scan": scan_job, "ct": ct_job, "typo": typo_job, "alerts": alerts_job, "patterns": patterns_job,
        "daily": daily_job, "maintenance": maintenance_job,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = httpx.AsyncClient(follow_redirects=True, http2=False)
    app.state.client = client
    app.state.jobs = jobs = job_fns(_ClientRef())
    tasks: list[asyncio.Task] = []
    if S.collectors:
        plan = [
            ("c2", S.c2_interval, 1), ("radar", S.radar_interval, 2), ("backfill", 6 * 60, 60),
            ("infra", S.infra_interval, 20), ("ransomware", S.ransomware_interval, 10), ("kev", S.kev_interval, 15),
            ("epss", S.epss_interval, 120), ("products", 60, 180), ("reputation", 30, 40), ("surface", 60, 90),
            ("scan", 60, 600), ("ct", S.ct_interval_h * 60, 150), ("typo", S.typo_interval_h * 60, 240),
            ("alerts", 2, 120), ("patterns", 10, 300), ("daily", 1, 90), ("maintenance", 24 * 60, 900),
        ]
        tasks = [asyncio.create_task(_loop(name, minutes, jobs[name], delay)) for name, minutes, delay in plan]
        if S.bgp_live:
            tasks.append(asyncio.create_task(bgp.run(_ClientRef())))
    if syslog is not None:
        await syslog.start()
    log.info("Emberwatch %s started. Auth: %s, language: %s, Gemini: %s, Matrix: %s, tools: %s, scans: %s, syslog: %s, BGP live: %s",
             S.version, S.auth_mode, S.language, "on" if ai.enabled else "off", "on" if notifier.enabled else "off",
             "on" if S.tools_enabled else "off", "on" if S.scan_enabled else "off", "on" if syslog else "off",
             "on" if S.bgp_live else "off")
    try:
        yield
    finally:
        for task in tasks + list(_bg):
            task.cancel()
        if syslog is not None:
            await syslog.stop()
        await client.aclose()


app = FastAPI(title="Emberwatch", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

BASEMAP_HOST = "https://tiles.openfreemap.org"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
    f"worker-src 'self'; connect-src 'self' {BASEMAP_HOST}; font-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
PUBLIC_PATHS = {"/healthz", "/login", "/login.html", "/api/auth/login", "/api/auth/status", "/favicon.svg",
                "/styles.css", "/js/login.js", "/js/i18n.js", "/js/boot.js"}
PUBLIC_PREFIXES = ("/vendor/fonts/",)


def _hostport(v: str) -> str:
    v = v.strip().lower()
    for suffix in (":443", ":80"):
        if v.endswith(suffix):
            return v[: -len(suffix)]
    return v


def origin_ok(request: Request) -> bool:
    """Same-origin check for state-changing requests (defence in depth on top of SameSite=Strict)."""
    origin = request.headers.get("origin")
    if not origin:
        return request.headers.get("sec-fetch-site") in (None, "same-origin", "none")
    if origin == "null":
        return False
    host = _hostport(urlsplit(origin).netloc)
    allowed = {_hostport(request.headers.get("host", ""))}
    xfh = request.headers.get("x-forwarded-host")
    if xfh:
        allowed.add(_hostport(xfh.split(",")[0]))
    allowed.update(_hostport(o) for o in S.trusted_origins)
    return host in allowed


def _secure(request: Request) -> bool:
    if S.cookie_secure in ("1", "0"):
        return S.cookie_secure == "1"
    return request.url.scheme == "https"


@app.middleware("http")
async def guard(request: Request, call_next):
    lang = detect_lang(request)
    request.state.lang = lang
    path = request.url.path
    resp: Response
    if path.startswith("/api/") and (
        request.headers.get("sec-fetch-site") not in (None, "same-origin", "none")
        or (request.method not in ("GET", "HEAD", "OPTIONS") and not origin_ok(request))
    ):
        resp = JSONResponse({"detail": t(lang, "err.csrf"), "key": "err.csrf"}, 403)
    elif auth.enabled and not (".." not in path and (path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES))) \
            and not auth.valid(request.cookies.get(COOKIE)):
        if path.startswith("/api/"):
            resp = JSONResponse({"detail": t(lang, "err.auth_required"), "key": "err.auth_required"}, 401)
        elif request.method in ("GET", "HEAD") and path in ("/", "/index.html"):
            resp = RedirectResponse("/login", 303)
        else:
            resp = PlainTextResponse("401 Unauthorized", 401)
    else:
        resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    if path.startswith("/api/") or path in ("/", "/index.html", "/login"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.exception_handler(AppError)
async def app_error(request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse({"detail": exc.render(_lang(request)), "key": exc.key}, exc.status)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse({"detail": t(_lang(request), "err.bad_request"), "key": "err.bad_request"}, 422)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled error on %s: %s", request.url.path, exc.__class__.__name__, exc_info=exc)
    return JSONResponse({"detail": t(_lang(request), "err.internal", detail=exc.__class__.__name__), "key": "err.internal"}, 500)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
    if not request.url.path.startswith("/api/"):
        return PlainTextResponse(str(exc.detail), exc.status_code)
    key = {404: "err.not_found", 403: "err.forbidden", 405: "err.bad_request"}.get(exc.status_code, "err.bad_request")
    return JSONResponse({"detail": t(_lang(request), key), "key": key}, exc.status_code)


# --- auth ------------------------------------------------------------------------------------------------
class LoginIn(BaseModel):
    password: str = Field(..., min_length=1, max_length=1024)


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(S.static_dir / "login.html", media_type="text/html")


@app.get("/api/auth/status")
def api_auth_status(request: Request) -> dict[str, Any]:
    return {"mode": S.auth_mode, "authenticated": auth.valid(request.cookies.get(COOKIE)), "version": S.version}


@app.post("/api/auth/login")
async def api_login(request: Request, body: LoginIn) -> JSONResponse:
    if not auth.enabled:
        return JSONResponse({"ok": True})
    client = request.client.host if request.client else "?"
    wait = auth.locked_for(client)
    if wait:
        raise AppError("err.login_locked", 429, seconds=wait)
    if not await asyncio.to_thread(auth.verify, body.password, client):
        await asyncio.sleep(0.4)
        raise AppError("err.login_failed", 401)
    resp = JSONResponse({"ok": True})
    resp.set_cookie(COOKIE, auth.issue(), max_age=S.session_hours * 3600, httponly=True, samesite="strict",
                    secure=_secure(request), path="/")
    return resp


@app.post("/api/auth/logout")
def api_logout(request: Request) -> JSONResponse:
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict", secure=_secure(request))
    return resp


# --- base data -------------------------------------------------------------------------------------------
@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/overview")
def api_overview(request: Request) -> dict[str, Any]:
    return localized(overview(), _lang(request))


@app.get("/api/status")
def api_status(request: Request) -> dict[str, Any]:
    lang = _lang(request)
    final_days = db.query("SELECT COUNT(DISTINCT day) AS n FROM radar_hist WHERE json_extract(payload, '$.final') = 1")[0]["n"]
    sources = []
    for r in db.statuses():
        sources.append({**{k: r[k] for k in ("source", "ok", "last_run", "last_ok", "count")}, "message": i18n.render_status(r, lang)})
    return {
        "version": S.version,
        "language": S.language,
        "auth": {"mode": S.auth_mode},
        "sources": sources,
        "geo": {"available": geo.available, **geo.info()},
        "ai": {"enabled": ai.enabled, "model": S.gemini_model},
        "matrix": {"enabled": notifier.enabled, "min_severity": S.matrix_min_severity},
        "daily_report": {"time": S.daily_report_time or None, "timezone": S.timezone, "last": db.meta_get("daily_report_last")},
        "tools": {"enabled": S.tools_enabled, "allow_private": S.tools_allow_private},
        "scan": {"enabled": S.scan_enabled, "interval_h": S.scan_interval_h, "ports": len(S.scan_ports),
                 "max_hosts": S.scan_max_hosts, "running": surface.current},
        "region": {"codes": list(S.home_region), "name": S.home_region_name or t(lang, "region.default_name")},
        "syslog": syslog.info() if syslog else {"enabled": False},
        "bgp": {"enabled": S.bgp_live, "connected": bgp.stats["connected"], "watches": len(bgp.watches)},
        "logs": {"max_mb": S.log_max_mb},
        "history": {"radar_days_final": final_days, "backfill_target": S.backfill_days,
                    "ransomware_backfill": db.meta_get("ransomware_backfill") == "done"},
        "cables": cables.meta,
        "keys": {
            "cloudflare": bool(S.cf_api_token), "abusech": bool(S.abusech_auth_key),
            "ransomware_live": bool(S.ransomware_live_api_key), "gemini": bool(S.gemini_api_key),
            "abuseipdb": bool(S.abuseipdb_api_key), "nvd": bool(S.nvd_api_key), "certspotter": bool(S.certspotter_api_key),
        },
    }


@app.get("/api/c2")
def api_c2(days: int = Query(30, ge=1, le=365), source: str = Query("all", pattern="^(all|feodo|threatfox)$")) -> JSONResponse:
    sql = ("SELECT id, source, ioc, ip, port, malware, status, confidence, first_seen, last_seen, country, city, "
           "lat, lon, geo_precision, asn, as_name, reference FROM c2 WHERE lat IS NOT NULL "
           "AND COALESCE(last_seen, first_seen, updated_at) >= ?")
    params: list[Any] = [_cutoff(days)]
    if source != "all":
        sql += " AND source = ?"
        params.append(source)
    feats = []
    for r in db.query(sql, params):
        lat, lon = r.pop("lat"), r.pop("lon")
        feats.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [lon, lat]}, "properties": r})
    return JSONResponse({"type": "FeatureCollection", "features": feats})


@app.get("/api/victims")
def api_victims(days: int = Query(7, ge=1, le=90), limit: int = Query(200, ge=1, le=1000)) -> list[dict[str, Any]]:
    return db.query(
        "SELECT victim, grp, country, activity, discovered, attackdate, permalink FROM victims "
        "WHERE discovered >= ? ORDER BY discovered DESC LIMIT ?",
        (_cutoff(days), limit),
    )


# --- timeline & trends -----------------------------------------------------------------------------------------
@app.get("/api/timeline/days")
def api_timeline_days() -> list[str]:
    return analytics.timeline_days(db)


@app.get("/api/timeline")
def api_timeline(day: str = Query(..., min_length=10, max_length=10)) -> dict[str, Any]:
    if not DAY_RE.match(day):
        raise AppError("err.invalid_date")
    try:
        datetime.fromisoformat(day)
    except ValueError as exc:
        raise AppError("err.invalid_date") from exc
    return analytics.timeline_day(db, day)


def _cc(cc: str | None) -> str:
    v = (cc or "").upper()
    if not CC_RE.match(v):
        raise AppError("err.invalid_country")
    return v


@app.get("/api/trends/{cc}")
def api_trends(cc: str, days: int = Query(30, ge=7, le=90)) -> dict[str, Any]:
    return analytics.trends(db, _cc(cc), days)


# --- country view ---------------------------------------------------------------------------------------------
async def country_data(request: Request, cc: str) -> dict[str, Any]:
    """Language-neutral country data (cached 30 min)."""
    cached = _country_cache.get(cc)
    if cached and time.time() - cached[0] < 1800:
        return cached[1]
    ov = overview()
    rad = ov["radar"]

    def share(key: str, field: str) -> float | None:
        for r in (rad.get(key) or {}).get("rows", []):
            if r.get(field) == cc:
                return r["value"]
        return None

    def top(d: dict[str, int], n: int = 10) -> list[dict[str, Any]]:
        return [{"key": k, "count": c} for k, c in sorted(d.items(), key=lambda x: -x[1])[:n]]

    c2_rows = db.query("SELECT malware, asn, as_name FROM c2 WHERE country=?", (cc,))
    fam: dict[str, int] = {}
    asns: dict[str, int] = {}
    for r in c2_rows:
        fam[r["malware"] or "unknown"] = fam.get(r["malware"] or "unknown", 0) + 1
        if r["asn"]:
            k = f"AS{r['asn']} {r['as_name'] or ''}".strip()
            asns[k] = asns.get(k, 0) + 1
    vic = db.query("SELECT grp, activity FROM victims WHERE country=? AND discovered >= ?", (cc, _cutoff(7)))
    grp: dict[str, int] = {}
    sec: dict[str, int] = {}
    for v in vic:
        grp[v["grp"]] = grp.get(v["grp"], 0) + 1
        sec[v["activity"] or ""] = sec.get(v["activity"] or "", 0) + 1
    data = {
        "cc": cc,
        "radar_shares_pct": {
            "l7_target_1d": share("l7_target_1d", "target"), "l7_target_7d": share("l7_target_7d", "target"),
            "l7_origin_1d": share("l7_origin_1d", "origin"), "l7_origin_7d": share("l7_origin_7d", "origin"),
            "l3_target_1d": share("l3_target_1d", "target"), "l3_target_7d": share("l3_target_7d", "target"),
            "l3_origin_1d": share("l3_origin_1d", "origin"), "l3_origin_7d": share("l3_origin_7d", "origin"),
        },
        "l7_pairs_1d": [r for r in (rad.get("l7_pairs_1d") or {}).get("rows", []) if cc in (r.get("origin"), r.get("target"))],
        "radar_drilldown": await radar.country_drilldown(request.app.state.client, S.cf_api_token, cc),
        "c2": {"total": len(c2_rows), "by_malware": top(fam), "by_asn": top(asns)},
        "ransomware_7d": {"total": len(vic), "by_group": top(grp), "by_sector": top(sec)},
        "infra_events": [e for e in ov["infra"]["events"] if cc in e["countries"]][:20],
        "cables": cables.for_country(cc),
        "patterns": [p for p in ov["patterns"] if p.get("country") == cc],
    }
    _country_cache[cc] = (time.time(), data)
    return data


def country_localized(data: dict[str, Any], lang: str) -> dict[str, Any]:
    return {**data, "name": geo.country_name(data["cc"], lang),
            "infra_events": [_event(e, lang) for e in data["infra_events"]],
            "patterns": [i18n.render_pattern(p, lang, geo.country_name) for p in data["patterns"]]}


@app.get("/api/country/{cc}")
async def api_country(request: Request, cc: str) -> dict[str, Any]:
    return country_localized(await country_data(request, _cc(cc)), _lang(request))


# --- search ----------------------------------------------------------------------------------------------------
def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _in_net(ip: str, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


KEV_COLS = ("k.cve, k.vendor, k.product, k.name, k.date_added, k.ransomware, e.epss, e.percentile FROM kev k "
            "LEFT JOIN epss e ON e.cve = k.cve")


@app.get("/api/search")
def api_search(request: Request, q: str = Query(..., min_length=2, max_length=100)) -> dict[str, Any]:
    lang = _lang(request)
    q = q.strip()
    out: dict[str, Any] = {"query": q, "type": "text", "c2": [], "iocs": [], "kev": [], "victims": [], "infra": [],
                           "countries": [], "vendors": [], "products": [], "assets": []}
    c2_cols = "id, source, ioc, ip, malware, country, asn, as_name, first_seen, lat, lon, reference"
    ioc_cols = "ioc, ioc_type, ip, host, threat_type, malware, confidence, first_seen, reference"
    try:
        ip = str(ipaddress.ip_address(q))
        out["type"] = "ip"
        out["c2"] = db.query(f"SELECT {c2_cols} FROM c2 WHERE ip=? LIMIT 50", (ip,))
        out["iocs"] = db.query(f"SELECT {ioc_cols} FROM iocs WHERE ip=? LIMIT 50", (ip,))
        out["reputation"] = reputation.flags(ip)
        return out
    except ValueError:
        pass
    if "/" in q:
        try:
            net = ipaddress.ip_network(q, strict=False)
            out["type"] = "cidr"
            if net.prefixlen >= (8 if net.version == 4 else 16):
                rows = db.query(f"SELECT {c2_cols} FROM c2 WHERE ip IS NOT NULL")
                out["c2"] = [r for r in rows if _in_net(r["ip"], net)][:100]
                out["reputation"] = {"drop": reputation.drop_for(str(net))}
            return out
        except ValueError:
            pass
    m = re.fullmatch(r"(?i)as(\d{1,10})", q)
    if m:
        asn = int(m.group(1))
        out["type"] = "asn"
        out["c2"] = db.query(f"SELECT {c2_cols} FROM c2 WHERE asn=? LIMIT 100", (asn,))
        out["infra"] = [_event(e, lang) for e in overview()["infra"]["events"] if asn in e["asns"]][:30]
        return out
    if re.fullmatch(r"(?i)cve-\d{4}-\d{4,7}", q):
        out["type"] = "cve"
        cve = q.upper()
        out["kev"] = db.query(f"SELECT {KEV_COLS} WHERE k.cve = ?", (cve,))
        out["nvd"] = db.query("SELECT n.cve, n.published, n.cvss, n.severity, n.summary, e.epss FROM nvd_cve n "
                              "LEFT JOIN epss e ON e.cve = n.cve WHERE n.cve = ?", (cve,))
        return out
    like = _like(q)
    host = q.lower().rstrip(".")
    out["c2"] = db.query(f"SELECT {c2_cols} FROM c2 WHERE malware LIKE ? ESCAPE '\\' OR ioc LIKE ? ESCAPE '\\' "
                         "OR as_name LIKE ? ESCAPE '\\' ORDER BY first_seen DESC LIMIT 50", (like, like, like))
    if "." in host:
        out["type"] = "domain"
        out["iocs"] = db.query(f"SELECT {ioc_cols} FROM iocs WHERE host = ? OR host LIKE ? ESCAPE '\\' "
                               "ORDER BY first_seen DESC LIMIT 50", (host, "%." + host.replace("%", "").replace("_", "\\_")))
    out["kev"] = db.query(f"SELECT {KEV_COLS} WHERE k.vendor LIKE ? ESCAPE '\\' OR k.product LIKE ? ESCAPE '\\' "
                          "OR k.name LIKE ? ESCAPE '\\' ORDER BY k.date_added DESC LIMIT 50", (like, like, like))
    out["vendors"] = db.query("SELECT vendor, COUNT(*) AS n, MAX(date_added) AS latest FROM kev WHERE vendor LIKE ? ESCAPE '\\' "
                              "GROUP BY vendor ORDER BY n DESC LIMIT 6", (like,))
    out["products"] = db.query("SELECT id, vendor, product FROM products WHERE vendor LIKE ? ESCAPE '\\' "
                               "OR product LIKE ? ESCAPE '\\' LIMIT 10", (like, like))
    out["assets"] = db.query("SELECT id, kind, value, label FROM watchlist WHERE value LIKE ? ESCAPE '\\' "
                             "OR label LIKE ? ESCAPE '\\' LIMIT 10", (like, like))
    out["victims"] = db.query("SELECT victim, grp, country, activity, discovered, permalink FROM victims "
                              "WHERE victim LIKE ? ESCAPE '\\' OR grp LIKE ? ESCAPE '\\' ORDER BY discovered DESC LIMIT 30",
                              (like, like))
    ql = q.lower()
    out["countries"] = [{"cc": cc, "name": geo.country_name(cc, lang)} for cc, c in geo.centroids.items()
                        if ql == cc.lower() or ql in c["name"].lower() or ql in (c.get("name_en") or "").lower()][:10]
    return out


@app.get("/api/search/nvd")
async def api_search_nvd(request: Request, q: str = Query(..., min_length=3, max_length=100)) -> dict[str, Any]:
    res = await products.search(request.app.state.client, q.strip())
    cves = [c["cve"] for c in res["cves"]]
    if cves:
        await epss.ensure(request.app.state.client, db, S.user_agent, cves)
        marks = ",".join("?" * len(cves))
        ep = {r["cve"]: r for r in db.query(f"SELECT cve, epss, percentile FROM epss WHERE cve IN ({marks})", cves)}
        kv = {r["cve"] for r in db.query(f"SELECT cve FROM kev WHERE cve IN ({marks})", cves)}
        for c in res["cves"]:
            c["epss"] = (ep.get(c["cve"]) or {}).get("epss")
            c["kev"] = c["cve"] in kv
    return res


# --- exports ---------------------------------------------------------------------------------------------------
@app.get("/api/export/c2")
def api_export_c2(
    request: Request,
    fmt: str = Query("txt", pattern="^(txt|csv)$"),
    days: int = Query(30, ge=1, le=365),
    source: str = Query("all", pattern="^(all|feodo|threatfox)$"),
    family: str | None = Query(None, max_length=100),
    min_confidence: int = Query(0, ge=0, le=100),
    online_only: bool = Query(False),
) -> Response:
    lang = _lang(request)
    sql = ("SELECT source, ioc, ip, port, malware, status, confidence, first_seen, last_seen, country, asn, as_name, reference "
           "FROM c2 WHERE COALESCE(last_seen, first_seen, updated_at) >= ?")
    params: list[Any] = [_cutoff(days)]
    if source != "all":
        sql += " AND source = ?"
        params.append(source)
    if family:
        sql += " AND malware = ?"
        params.append(family)
    if min_confidence:
        sql += " AND (confidence IS NULL OR confidence >= ?)"
        params.append(min_confidence)
    if online_only:
        sql += " AND (source != 'feodo' OR status = 'online')"
    rows = db.query(sql + " ORDER BY first_seen DESC", params)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    if fmt == "txt":
        ips = sorted({r["ip"] for r in rows if r["ip"]}, key=lambda x: (":" in x, x))
        fam = (family or t(lang, "export.all")).replace("\n", " ").replace("\r", " ")
        header = (f"# {t(lang, 'export.header', ts=utcnow())}\n"
                  f"# {t(lang, 'export.source', days=days, source=source, family=fam, conf=min_confidence)}\n"
                  f"# {t(lang, 'export.count', count=len(ips))}\n")
        return PlainTextResponse(header + "\n".join(ips) + "\n", headers={
            "Content-Disposition": f'attachment; filename="emberwatch-c2-{stamp}.txt"'})
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["source", "ioc", "ip", "port", "malware", "status", "confidence", "first_seen", "last_seen", "country", "asn",
            "as_name", "reference"]
    w.writerow(cols)
    for r in rows:
        # CSV injection: neutralise fields that start with formula characters
        w.writerow([("'" + str(r[c])) if isinstance(r[c], str) and r[c][:1] in ("=", "+", "-", "@", "\t", "\r") else r[c]
                    for c in cols])
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="emberwatch-c2-{stamp}.csv"'})


# --- watchlist / assets -----------------------------------------------------------------------------------------
class WatchIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=260)
    kind: str | None = Field(None, pattern="^(auto|ip|cidr|asn|domain)$")
    label: str | None = Field(None, max_length=80)
    scan: bool = False
    scan_ack: bool = False


class WatchPatch(BaseModel):
    label: str | None = Field(None, max_length=80)
    scan: bool | None = None
    scan_ack: bool | None = None


def _clean_label(v: str | None) -> str | None:
    s = re.sub(r"[\x00-\x1f\x7f]", "", (v or "")).strip()
    return s[:80] or None


def _entry(wid: int) -> dict[str, Any]:
    rows = db.query("SELECT id, kind, value, label, created_at, scan, scan_ack FROM watchlist WHERE id=?", (wid,))
    if not rows:
        raise AppError("err.not_found", 404)
    return rows[0]


def _asset_jobs(request: Request, w: dict[str, Any]) -> None:
    jobs = request.app.state.jobs
    client = request.app.state.client
    if w["kind"] in ("ip", "cidr", "domain"):
        kick("surface", jobs["surface"])
    if w["kind"] in ("ip", "cidr"):
        kick("reputation", jobs["reputation"])
    if w["kind"] == "domain":
        kick(f"ct:{w['id']}", lambda: domains.ct(client, only=w["id"]))
        kick(f"typo:{w['id']}", lambda: domains.typos(only=w["id"]))
    if w["kind"] in ("ip", "cidr", "asn"):
        bgp.replan()


def asset_summary(w: dict[str, Any]) -> dict[str, Any]:
    d7 = _cutoff(7)
    a = db.query("SELECT COUNT(*) AS n, SUM(severity='high') AS high FROM alerts WHERE asset_id=? AND created_at >= ?",
                 (w["id"], d7))[0]
    out: dict[str, Any] = {**w, "scan": bool(w["scan"]), "scan_ack": w["scan_ack"],
                           "alerts_7d": a["n"] or 0, "high_7d": a["high"] or 0,
                           "alerts_total": db.query("SELECT COUNT(*) AS n FROM alerts WHERE asset_id=?", (w["id"],))[0]["n"]}
    if w["kind"] in ("ip", "cidr", "domain"):
        ips = surface.ips_of(w)
        rows = surface.surface_for(ips[:256])
        out["surface"] = {"ips": len(ips), "fetched": len(rows), "ports": sorted({p for r in rows for p in r["ports"]})[:50],
                          "vulns": len({v for r in rows for v in r["vulns"]}), "kev": len({v for r in rows for v in r["kev"]})}
        ls = surface.last_scan(w["id"])
        out["scan_last"] = None if not ls else {"status": ls["run"]["status"], "started_at": ls["run"]["started_at"],
                                                "finished_at": ls["run"]["finished_at"], "open_ports": len(ls["ports"]),
                                                "progress": ls["progress"]}
    if w["kind"] in ("ip", "cidr"):
        out["reputation"] = {"drop": reputation.drop_for(w["value"]),
                             "tor": reputation.is_tor(w["value"]) if w["kind"] == "ip" else False}
    if w["kind"] == "domain":
        info = domains.listing(w["value"])
        out["domain"] = {"ct_total": info["ct_total"], "typos": len(info["typos"]), "typo_checked": info["typo_checked"]}
    if w["kind"] in ("ip", "cidr", "asn"):
        out["bgp"] = {"watches": sum(1 for x in bgp.watches.values() if any(e["id"] == w["id"] for e, _ in x.assets))}
    return out


@app.get("/api/watchlist")
def api_watchlist() -> dict[str, Any]:
    rows = db.query("SELECT id, kind, value, label, created_at, scan, scan_ack FROM watchlist ORDER BY id DESC")
    return {"entries": [asset_summary(w) for w in rows], "max": watchlist.MAX_ENTRIES,
            "scan_enabled": S.scan_enabled}


@app.post("/api/watchlist")
async def api_watch_add(request: Request, body: WatchIn) -> dict[str, Any]:
    kind, value = watchlist.normalize(body.value, body.kind)
    if db.query("SELECT 1 FROM watchlist WHERE kind=? AND value=?", (kind, value)):
        raise AppError("err.watch_exists", 409)
    if db.query("SELECT COUNT(*) AS n FROM watchlist")[0]["n"] >= watchlist.MAX_ENTRIES:
        raise AppError("err.watch_limit", max=watchlist.MAX_ENTRIES)
    scan = bool(body.scan) and kind in ("ip", "cidr", "domain")
    if scan and not body.scan_ack:
        raise AppError("err.scan_ack")
    wid = db.insert("INSERT INTO watchlist(kind, value, label, created_at, scan, scan_ack) VALUES(?,?,?,?,?,?)",
                    (kind, value, _clean_label(body.label), utcnow(), int(scan), utcnow() if scan else None))
    new = watchlist.scan(db)
    _invalidate()
    _asset_jobs(request, _entry(wid))
    return {"id": wid, "kind": kind, "value": value, "new_alerts": len(new)}


@app.patch("/api/watchlist/{wid}")
def api_watch_patch(request: Request, wid: int, body: WatchPatch) -> dict[str, Any]:
    w = _entry(wid)
    if body.label is not None:
        db.execute("UPDATE watchlist SET label=? WHERE id=?", (_clean_label(body.label), wid))
    if body.scan is not None:
        if body.scan:
            if w["kind"] not in ("ip", "cidr", "domain"):
                raise AppError("err.scan_kind")
            if not body.scan_ack:
                raise AppError("err.scan_ack")
            db.execute("UPDATE watchlist SET scan=1, scan_ack=? WHERE id=?", (utcnow(), wid))
        else:
            db.execute("UPDATE watchlist SET scan=0, scan_ack=NULL WHERE id=?", (wid,))
    return asset_summary(_entry(wid))


@app.delete("/api/watchlist/{wid}")
async def api_watch_delete(wid: int) -> dict[str, Any]:
    w = _entry(wid)
    if surface.current and surface.current.get("asset_id") == wid:
        raise AppError("err.busy", 409)
    stmts: list[tuple[str, tuple]] = [
        ("DELETE FROM alerts WHERE asset_id=?", (wid,)),
        ("DELETE FROM scan_ports WHERE run_id IN (SELECT id FROM scan_runs WHERE asset_id=?)", (wid,)),
        ("DELETE FROM scan_runs WHERE asset_id=?", (wid,)),
        ("DELETE FROM meta WHERE key=?", (f"surface_ips:{wid}",)),
        ("DELETE FROM watchlist WHERE id=?", (wid,)),
    ]
    if w["kind"] == "domain":
        stmts += [("DELETE FROM ct_certs WHERE domain=?", (w["value"],)),
                  ("DELETE FROM meta WHERE key IN (?,?)", (f"ct_after:{w['value']}", f"ct_baseline:{w['value']}"))]
    db.transaction(stmts)
    _invalidate()
    bgp.replan()
    return {"deleted": wid}


@app.get("/api/assets/{wid}")
def api_asset(request: Request, wid: int) -> dict[str, Any]:
    lang = _lang(request)
    w = _entry(wid)
    out = asset_summary(w)
    if w["kind"] in ("ip", "cidr", "domain"):
        ips = surface.ips_of(w)
        out["surface_rows"] = surface.surface_for(ips[:256])
        for r in out["surface_rows"]:
            r["reputation"] = reputation.flags(r["ip"])
        out["scan_detail"] = surface.last_scan(wid)
        out["scan_history"] = db.query("SELECT id, started_at, finished_at, status, trigger, targets, open_ports, error "
                                       "FROM scan_runs WHERE asset_id=? ORDER BY id DESC LIMIT 10", (wid,))
    if w["kind"] == "domain":
        out["domain_detail"] = domains.listing(w["value"])
    if w["kind"] in ("ip", "cidr", "asn"):
        info = bgp.info()
        mine = {x["prefix"] for x in info["watches"] if wid in x["asset_ids"]}
        out["bgp_detail"] = {"connected": info["connected"], "enabled": info["enabled"],
                             "watches": [x for x in info["watches"] if x["prefix"] in mine],
                             "events": [e for e in info["events"] if e.get("watched") in mine][:50]}
    out["alerts"] = alerts.listing(db, lang, limit=100, asset_id=wid)
    return out


@app.post("/api/assets/{wid}/scan")
async def api_asset_scan(wid: int) -> dict[str, Any]:
    w = _entry(wid)
    if not S.scan_enabled:
        raise AppError("err.scan_disabled", 403)
    if w["kind"] not in ("ip", "cidr", "domain"):
        raise AppError("err.scan_kind")
    if not w["scan"] or not w["scan_ack"]:
        raise AppError("err.scan_ack")
    if surface.scan_lock.locked():
        raise AppError("err.busy", 409)
    ips = await surface.targets(w, S.scan_max_hosts, active=True)  # validates size before starting
    if not ips:
        raise AppError("err.scan_no_targets")
    _spawn(surface.scan_asset(wid, "manual"))
    return {"started": True, "targets": len(ips), "ports": len(S.scan_ports)}


_manual: dict[str, float] = {}


def _throttle(name: str, seconds: int) -> None:
    last = _manual.get(name, 0.0)
    if time.time() - last < seconds:
        raise AppError("err.refresh_wait", 429, seconds=int(seconds - (time.time() - last)) + 1)
    _manual[name] = time.time()


@app.post("/api/assets/refresh")
async def api_assets_refresh(request: Request) -> dict[str, Any]:
    _throttle("assets", 300)
    jobs = request.app.state.jobs
    client = request.app.state.client
    kick("surface-force", lambda: surface.passive(client, force=True))
    kick("reputation", jobs["reputation"])
    kick("ct", jobs["ct"])
    bgp.replan()
    return {"ok": True}


# --- products ---------------------------------------------------------------------------------------------------
class ProductIn(BaseModel):
    vendor: str = Field(..., min_length=1, max_length=60)
    product: str = Field("", max_length=80)


@app.get("/api/products")
def api_products() -> dict[str, Any]:
    return {"products": products.listing(), "min_cvss": S.product_min_cvss, "nvd_key": bool(S.nvd_api_key)}


@app.post("/api/products")
async def api_product_add(request: Request, body: ProductIn) -> dict[str, Any]:
    pid = products.add(body.vendor, body.product)
    client = request.app.state.client
    kick(f"product:{pid}", lambda: products.check(client, only=pid))
    return {"id": pid}


@app.delete("/api/products/{pid}")
def api_product_delete(pid: int) -> dict[str, Any]:
    if not products.delete(pid):
        raise AppError("err.not_found", 404)
    db.execute("DELETE FROM alerts WHERE product_id=?", (pid,))
    return {"deleted": pid}


@app.get("/api/products/{pid}/cves")
def api_product_cves(pid: int) -> dict[str, Any]:
    if not db.query("SELECT 1 FROM products WHERE id=?", (pid,)):
        raise AppError("err.not_found", 404)
    return {"cves": products.cves(pid)}


@app.post("/api/products/{pid}/check")
async def api_product_check(request: Request, pid: int) -> dict[str, Any]:
    if not db.query("SELECT 1 FROM products WHERE id=?", (pid,)):
        raise AppError("err.not_found", 404)
    _throttle(f"product:{pid}", 120)
    client = request.app.state.client
    kick(f"product:{pid}", lambda: products.check(client, only=pid, force=True))
    return {"ok": True}


# --- alerts ------------------------------------------------------------------------------------------------------
@app.get("/api/alerts")
def api_alerts(request: Request, source: str | None = Query(None, pattern="^(" + "|".join(alerts.SOURCES) + ")$"),
               asset_id: int | None = None, product_id: int | None = None,
               min_severity: str = Query("low", pattern="^(high|medium|low)$"),
               limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    return {"alerts": alerts.listing(db, _lang(request), limit=limit, source=source, asset_id=asset_id,
                                     product_id=product_id, min_severity=min_severity),
            "stats": alerts.stats(db)}


# --- log analysis ---------------------------------------------------------------------------------------------------
@app.post("/api/logs/analyze")
async def api_logs_analyze(request: Request) -> dict[str, Any]:
    lang = _lang(request)
    limit = S.log_max_mb * 1024 * 1024
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise AppError("err.too_large", 413, mb=S.log_max_mb)
    if _log_lock.locked():
        raise AppError("err.busy", 409)
    async with _log_lock:
        tmp_dir = S.data_dir / "tmp"
        tmp_dir.mkdir(exist_ok=True)
        fd, path = tempfile.mkstemp(dir=tmp_dir, prefix="log-", suffix=".part")
        size = 0
        try:
            with os.fdopen(fd, "wb") as fh:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > limit:
                        raise AppError("err.too_large", 413, mb=S.log_max_mb)
                    fh.write(chunk)
            if size == 0:
                raise AppError("err.empty")
            matcher.ensure()
            res = await asyncio.to_thread(analyze_file, path, matcher, geo)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    res["bytes"] = size
    for h in res["hits"]:
        h["labels"] = [i18n.render_match(m, lang) for m in h["matches"]]
    return res


@app.get("/api/logs/status")
def api_logs_status() -> dict[str, Any]:
    matcher.ensure()
    return {"indexes": matcher.size, "max_mb": S.log_max_mb, "syslog": syslog.info() if syslog else {"enabled": False}}


@app.get("/api/bgp")
def api_bgp() -> dict[str, Any]:
    return bgp.info()


@app.post("/api/notify/test")
async def api_notify_test(request: Request) -> dict[str, Any]:
    ok, msg = await notifier.test(request.app.state.client)
    if not ok:
        raise AppError("err.matrix_failed", 503, detail=msg)
    return {"ok": True}


# --- Gemini ------------------------------------------------------------------------------------------------------------
class AnalyzeIn(BaseModel):
    scope: str = Field("global", pattern="^(global|country|region|dach|question)$")
    country: str | None = Field(None, max_length=2)
    question: str | None = Field(None, max_length=600)


@app.post("/api/ai/analyze")
async def api_analyze(request: Request, body: AnalyzeIn) -> dict[str, Any]:
    lang = _lang(request)
    ov = overview()
    cc = _cc(body.country) if body.country else None
    scope = "region" if body.scope == "dach" else body.scope
    if scope == "country" and not cc:
        raise AppError("err.country_missing")
    if scope == "region" and not S.home_region:
        raise AppError("err.region_missing")
    country = country_localized(await country_data(request, cc), lang) if cc else None
    if scope == "question":
        q = (body.question or "").strip()
        if not q:
            raise AppError("err.question_missing")
        task = TASKS[lang]["question"] + q
    else:
        task = TASKS[lang][scope]
    ctx = build_context(ov, geo.country_name, lang, cc, country, S.home_region)
    result = await ai.analyze(request.app.state.client, task, ctx, lang)
    scope_label = scope + (f":{cc}" if cc else "")
    if not result.get("cached"):
        result["id"] = db.insert("INSERT INTO ai_reports(created_at, scope, model, payload) VALUES(?,?,?,?)",
                                 (utcnow(), scope_label, result["model"], json.dumps({**result, "question": body.question})))
    return {**result, "scope": scope_label, "question": body.question}


@app.get("/api/ai/reports")
def api_reports(limit: int = Query(20, ge=1, le=100)) -> list[dict[str, Any]]:
    rows = db.query("SELECT id, created_at, scope, model, payload FROM ai_reports ORDER BY id DESC LIMIT ?", (limit,))
    return [{**json.loads(r["payload"]), "id": r["id"], "created_at": r["created_at"], "scope": r["scope"], "model": r["model"]}
            for r in rows]


@app.get("/api/ai/reports/{rid}/thread")
def api_thread(rid: int) -> list[dict[str, Any]]:
    rows = db.query("SELECT id, created_at, question, payload FROM ai_threads WHERE report_id=? ORDER BY id", (rid,))
    return [{"id": r["id"], "created_at": r["created_at"], "question": r["question"], **json.loads(r["payload"])} for r in rows]


class FollowupIn(BaseModel):
    report_id: int
    question: str = Field(..., min_length=2, max_length=600)


@app.post("/api/ai/followup")
async def api_followup(request: Request, body: FollowupIn) -> dict[str, Any]:
    lang = _lang(request)
    rows = db.query("SELECT scope, payload FROM ai_reports WHERE id=?", (body.report_id,))
    if not rows:
        raise AppError("err.report_not_found", 404)
    report = json.loads(rows[0]["payload"])
    thread = api_thread(body.report_id)
    scope = rows[0]["scope"]
    cc = scope.split(":", 1)[1] if ":" in scope else None
    country = country_localized(await country_data(request, cc), lang) if cc and CC_RE.match(cc) else None
    ctx = build_context(overview(), geo.country_name, lang, cc, country, S.home_region)
    ans = await ai.followup(request.app.state.client, report, thread, body.question.strip(), ctx, lang)
    tid = db.insert("INSERT INTO ai_threads(report_id, created_at, question, payload) VALUES(?,?,?,?)",
                    (body.report_id, utcnow(), body.question.strip(), json.dumps(ans)))
    return {"id": tid, "question": body.question.strip(), **ans}


# --- network tools -------------------------------------------------------------------------------------------------------
def _tools_on() -> None:
    if not S.tools_enabled:
        raise AppError("err.tools_disabled", 403)


def _sse(request: Request, gen: AsyncIterator[dict[str, Any]]) -> StreamingResponse:
    lang = _lang(request)

    def enc(ev: dict[str, Any]) -> bytes:
        if "key" in ev and ev.get("type") == "info":
            ev = {**ev, "text": t(lang, ev["key"], **(ev.get("params") or {}))}
        return f"event: {ev.get('type', 'message')}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n".encode()

    async def body() -> AsyncIterator[bytes]:
        try:
            async for ev in gen:
                if await request.is_disconnected():
                    break
                yield enc(ev)
        except AppError as exc:
            yield enc({"type": "error", "text": exc.render(lang)})
        except Exception as exc:  # unexpected: report briefly, do not crash
            log.exception("tool stream failed")
            yield enc({"type": "error", "text": t(lang, "err.internal", detail=exc.__class__.__name__)})
        finally:
            await gen.aclose()
        yield b"event: end\ndata: {}\n\n"

    return StreamingResponse(body(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


async def _tool(coro: Awaitable[dict[str, Any]]) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(coro, timeout=60)
    except asyncio.TimeoutError as exc:
        raise AppError("err.timeout", 504) from exc


@app.get("/api/tools/ping")
async def api_ping(request: Request, target: str = Query(..., min_length=1, max_length=253), count: int = Query(5, ge=1, le=20)):
    _tools_on()
    return _sse(request, toolkit.ping(target, count))


@app.get("/api/tools/traceroute")
async def api_traceroute(request: Request, target: str = Query(..., min_length=1, max_length=253),
                         max_hops: int = Query(30, ge=1, le=40)):
    _tools_on()
    return _sse(request, toolkit.traceroute(request.app.state.client, target, max_hops))


@app.get("/api/tools/dns")
async def api_dns(request: Request, target: str = Query(..., min_length=1, max_length=253),
                  resolver: str = Query("cloudflare", pattern="^(system|cloudflare|google|quad9)$")) -> dict[str, Any]:
    _tools_on()
    return await _tool(toolkit.dns_lookup(target, resolver, _lang(request)))


@app.get("/api/tools/rdap")
async def api_rdap(request: Request, target: str = Query(..., min_length=1, max_length=253)) -> dict[str, Any]:
    _tools_on()
    return await _tool(toolkit.rdap(request.app.state.client, target))


@app.get("/api/tools/ipinfo")
async def api_ipinfo(request: Request, target: str = Query(..., min_length=1, max_length=253)) -> dict[str, Any]:
    _tools_on()
    return await _tool(toolkit.ipinfo(request.app.state.client, target, _lang(request)))


@app.get("/api/tools/ports")
async def api_ports(request: Request, target: str = Query(..., min_length=1, max_length=253),
                    ports: str = Query(..., max_length=80)) -> dict[str, Any]:
    _tools_on()
    return await _tool(toolkit.portcheck(target, parse_ports(ports), _lang(request)))


@app.get("/api/tools/http")
async def api_http(request: Request, target: str = Query(..., min_length=1, max_length=500)) -> dict[str, Any]:
    _tools_on()
    return await _tool(toolkit.http_tls(target, _lang(request)))


app.mount("/", StaticFiles(directory=str(S.static_dir), html=True), name="static")
