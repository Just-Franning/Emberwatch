"""Emberwatch – FastAPI app with background collectors, alerting, attack surface, log analysis and network tools."""
from __future__ import annotations

import asyncio
import base64
import binascii
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
from fastapi import Path as FPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import alerts, analytics, api_account, i18n, nlp, watchlist, webfetch
from .actors import Actors
from .ai import TASKS, Gemini, build_context
from .attack import Attack
from .auth import COOKIE, Auth, allowed
from .bgp import BgpMonitor
from .cables import Cables
from .config import OPTIONAL_SOURCES, load
from .db import DB, open_path, utcnow
from .domains import Domains
from .geo import Geo
from .i18n import AppError, t
from .logs import Matcher, SyslogServer, analyze_file
from .myip import KINDS as MYIP_KINDS
from .myip import MyIP
from .news import News
from .notify import Notifier
from .objects import TYPES as OBJ_TYPES
from .objects import Objects, object_context
from .owner import api as owner_api
from .personen import api as personen_api
from .personen.profiles import Locator
from .personen.runner import Searcher
from .personen.sites import SiteList
from .personen.store import Store as OsintStore
from .owner.geocode import Geocoder
from .owner.lookup import Owner
from .platforms import Platforms
from .products import Products
from .reputation import Reputation
from .sources import abusech, epss, euvd, exploits, infra, kev, ooni, radar, ransomware
from .surface import Surface
from .tools import ToolKit
from .toolbox import registry as tbreg
from .toolbox import runner as tbrun
from .toolbox.common import Ctx, cache_prune
from .toolbox.detect import detect as tb_detect

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
auth = Auth(S, db)
myip = MyIP(S, db, geo, reputation, matcher, surface, toolkit)
actors = Actors(db)
news = News(S, db, actors, S.static_dir / "data" / "centroids.json", cables)
attack = Attack(db, S.data_dir)
platforms = Platforms(db, geo, S.static_dir / "data")
objects = Objects(S, db, geo, reputation, matcher, products, domains, surface, myip, actors, news, attack)
geocoder = Geocoder(S, db)
owner = Owner(db, geo, toolkit, geocoder)
osint_sites = SiteList(S.data_dir, S.user_agent)
osint_store = OsintStore(db, S.osint_retention_days)
searcher = Searcher(S, osint_store, osint_sites, Locator(S.static_dir / "data" / "centroids.json",
                                                        S.static_dir / "data" / "places.json"))
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
        if S.source_on("urlhaus"):
            await abusech.collect_urlhaus(client, db, S.user_agent, S.abusech_auth_key)
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

    async def myip_job() -> None:
        await myip.refresh(client)
        for kind in MYIP_KINDS:
            if myip.needs_check(kind):
                await myip.check(client, kind)

    async def news_job() -> None:
        try:
            await actors.collect(client, S.user_agent)
        except Exception:  # the reports do not depend on a fresh actor list
            log.exception("actor list")
        await asyncio.to_thread(news.refresh_mine)  # new actor list, products or domains: recognise again
        await news.collect(client)
        if news.web_enabled:
            await news.collect_web(client)
        await asyncio.to_thread(news.refresh_checks)  # compare with the measurements (they keep arriving)

    async def ooni_job() -> None:
        await ooni.collect(client, db, S.user_agent)

    async def attack_job() -> None:
        await attack.collect(client, S.user_agent)

    async def euvd_job() -> None:
        await euvd.collect(client, db, S.user_agent)

    async def exploits_job() -> None:
        await exploits.collect(client, db, S.user_agent)

    async def platforms_job() -> None:
        await platforms.collect(client, S.user_agent)

    async def osint_lists_job() -> None:
        if osint_sites.due() and not searcher.running():
            await osint_sites.refresh(client)

    async def maintenance_job() -> None:
        alerts.prune(db, S.alert_retention_days)
        auth.prune()  # expired sessions, audit entries beyond AUDIT_RETENTION_DAYS
        owner.prune()  # owner lookups after 7 days, cached imprints and coordinates after 90 days
        for case in osint_store.prune():  # people search: cases without changes for OSINT_RETENTION_DAYS
            auth.audit("osint_case_expired", target=case["name"])
        db.execute("DELETE FROM nvd_cve WHERE cve NOT IN (SELECT cve FROM product_cves) AND fetched_at < ?", (_cutoff(7),))
        db.execute("DELETE FROM abuseipdb_cache WHERE fetched_at < ?", (_cutoff(7),))
        tbrun.prune(db)
        cache_prune(db)
        # Gemini analyses (one per object page analysis since 3.1): same retention as alerts, at most 2000
        db.execute("DELETE FROM ai_reports WHERE created_at < ?", (_cutoff(S.alert_retention_days),))
        db.execute("DELETE FROM ai_reports WHERE id NOT IN (SELECT id FROM ai_reports ORDER BY id DESC LIMIT 2000)")
        db.execute("DELETE FROM ai_threads WHERE report_id NOT IN (SELECT id FROM ai_reports)")  # their follow-ups

    return {
        "c2": c2_job, "radar": radar_job, "backfill": backfill_job, "infra": infra_job, "ransomware": ransomware_job,
        "kev": kev_job, "epss": epss_job, "products": products_job, "reputation": reputation_job, "surface": surface_job,
        "scan": scan_job, "ct": ct_job, "typo": typo_job, "alerts": alerts_job, "patterns": patterns_job,
        "daily": daily_job, "maintenance": maintenance_job, "myip": myip_job, "news": news_job,
        "ooni": ooni_job, "attack": attack_job, "euvd": euvd_job, "exploits": exploits_job, "platforms": platforms_job,
        "osint_lists": osint_lists_job,
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = httpx.AsyncClient(follow_redirects=True, http2=False)
    app.state.client = client
    # websites of third parties (imprints, people search, Telegram): only public addresses, see webfetch.py
    app.state.web = webfetch.make_client(S.user_agent)
    app.state.jobs = jobs = job_fns(_ClientRef())
    tasks: list[asyncio.Task] = []
    if S.collectors:
        plan = [
            ("c2", S.c2_interval, 1), ("radar", S.radar_interval, 2), ("backfill", 6 * 60, 60),
            ("infra", S.infra_interval, 20), ("ransomware", S.ransomware_interval, 10), ("kev", S.kev_interval, 15),
            ("epss", S.epss_interval, 120), ("products", 60, 180), ("reputation", 30, 40), ("surface", 60, 90),
            ("scan", 60, 600), ("ct", S.ct_interval_h * 60, 150), ("typo", S.typo_interval_h * 60, 240),
            ("alerts", 2, 120), ("patterns", 10, 300), ("daily", 1, 90), ("maintenance", 24 * 60, 900),
            ("myip", 10, 45),
        ]
        if news.enabled:
            plan.append(("news", S.news_interval, 30))
        if S.osint_enabled:
            plan.append(("osint_lists", 24 * 60, 480))  # downloads the site lists when they are a week old
        optional = (("ooni", 6 * 60, 200), ("attack", 7 * 24 * 60, 400), ("euvd", 12 * 60, 260),
                    ("exploits", 24 * 60, 330), ("cloud_status", 10, 70))
        for name, minutes, delay in optional:
            if S.source_on(name):
                plan.append(("platforms" if name == "cloud_status" else name, minutes, delay))
        tasks = [asyncio.create_task(_loop(name, minutes, jobs[name], delay)) for name, minutes, delay in plan]
        if S.bgp_live:
            tasks.append(asyncio.create_task(bgp.run(_ClientRef())))
    if syslog is not None:
        await syslog.start()
    log.info("Emberwatch %s started. Auth: %s, language: %s, Gemini: %s, Matrix: %s, tools: %s, scans: %s, syslog: %s, BGP live: %s",
             S.version, f"{S.auth_mode} ({db.query('SELECT COUNT(*) AS n FROM users')[0]['n']} accounts)" if auth.enabled else S.auth_mode,
             S.language, "on" if ai.enabled else "off", "on" if notifier.enabled else "off",
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
        await app.state.web.aclose()


app = FastAPI(title="Emberwatch", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


class BodyLimit:
    """Counts the bytes of request bodies while they are read, so bodies without Content-Length (chunked) are limited
    too; declared lengths are already refused in guard(). The log upload streams to a file with its own limit."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("path") == "/api/logs/analyze":
            await self.inner(scope, receive, send)
            return
        seen = 0

        async def limited() -> dict[str, Any]:
            nonlocal seen
            msg = await receive()
            if msg.get("type") == "http.request":
                seen += len(msg.get("body", b""))
                if seen > MAX_BODY:
                    raise StarletteHTTPException(413)  # FastAPI passes it through body parsing; see http_error()
            return msg

        await self.inner(scope, limited, send)


app.add_middleware(BodyLimit)

BASEMAP_HOST = "https://tiles.openfreemap.org"
# NEWS_IMAGES: preview images of news are loaded by the browser from the publisher (https only)
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    f"img-src 'self' data: blob:{' https:' if S.news_images else ''}; "
    f"worker-src 'self'; connect-src 'self' {BASEMAP_HOST}; font-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
PUBLIC_PATHS = {"/healthz", "/login", "/login.html", "/favicon.svg", "/styles.css",
                # sign-in steps (each checks its ticket; the session cookie is only set after the second factor)
                "/api/auth/login", "/api/auth/status", "/api/auth/password", "/api/auth/enroll", "/api/auth/enroll/confirm",
                "/api/auth/totp",
                # the login page and the modules it imports (i18n.js loads all text catalogues)
                "/js/login.js", "/js/i18n.js", "/js/texts.js", "/js/texts_welt.js", "/js/texts_33.js", "/js/texts_v4.js",
                "/js/boot.js",
                "/api/myip/report", "/nic/update"}  # the last two authenticate with their own token
PUBLIC_PREFIXES = ("/vendor/fonts/",)
MAX_BODY = 20 * 1024 * 1024  # JSON requests: mail analysis takes up to 15 MB of text (+ JSON escaping)
MAX_BODY_PUBLIC = 64 * 1024  # requests without a session (login, reporter)


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
    public = ".." not in path and (path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES))
    too_large = False
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and path != "/api/logs/analyze":  # the upload checks itself
        limit = MAX_BODY_PUBLIC if public else MAX_BODY
        declared = request.headers.get("content-length")
        if declared is not None:
            too_large = not declared.isdigit() or int(declared) > limit
        elif public:  # without a session only bodies of declared length (no unbounded chunked uploads)
            too_large = "chunked" in request.headers.get("transfer-encoding", "").lower()
    if too_large:
        resp = JSONResponse({"detail": t(lang, "err.body_too_large"), "key": "err.body_too_large"}, 413)
    elif path.startswith("/api/") and (
        request.headers.get("sec-fetch-site") not in (None, "same-origin", "none")
        or (request.method not in ("GET", "HEAD", "OPTIONS") and not origin_ok(request))
    ):
        resp = JSONResponse({"detail": t(lang, "err.csrf"), "key": "err.csrf"}, 403)
    else:
        user = None if public else auth.session_user(request.cookies.get(COOKIE))  # AUTH_MODE=none: the proxy account
        request.state.user = user
        if not public and user is None:
            if path.startswith("/api/"):
                resp = JSONResponse({"detail": t(lang, "err.auth_required"), "key": "err.auth_required"}, 401)
            elif request.method in ("GET", "HEAD") and path in ("/", "/index.html"):
                resp = RedirectResponse("/login", 303)
            else:
                resp = PlainTextResponse("401 Unauthorized", 401)
        elif user is not None and not allowed(user["role"], request.method, path):
            resp = JSONResponse({"detail": t(lang, "err.role"), "key": "err.role"}, 403)
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
    elif path.endswith((".js", ".css", ".html", ".json", ".svg")):
        # Scripts, styles and pages are revalidated on every load (ETag, usually 304). Without this header browsers cache
        # them heuristically and mix the scripts of an older version with the page of a new one after an update.
        resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.exception_handler(AppError)
async def app_error(request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse({"detail": exc.render(_lang(request)), "key": exc.key}, exc.status)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse({"detail": t(_lang(request), "err.bad_request"), "key": "err.bad_request"}, 422)


@app.exception_handler(OverflowError)
async def overflow_error(request: Request, exc: OverflowError) -> JSONResponse:
    """An id beyond SQLite's 64-bit integers (/api/assets/99999999999999999999): a bad request, not a server error."""
    return JSONResponse({"detail": t(_lang(request), "err.bad_request"), "key": "err.bad_request"}, 400)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    log.error("unhandled error on %s: %s", request.url.path, exc.__class__.__name__, exc_info=exc)
    return JSONResponse({"detail": t(_lang(request), "err.internal", detail=exc.__class__.__name__), "key": "err.internal"}, 500)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
    if not request.url.path.startswith("/api/"):
        return PlainTextResponse(str(exc.detail), exc.status_code)
    key = {404: "err.not_found", 403: "err.forbidden", 405: "err.bad_request", 413: "err.body_too_large"}.get(
        exc.status_code, "err.bad_request")
    return JSONResponse({"detail": t(_lang(request), key), "key": key}, exc.status_code)


# --- accounts: sign-in steps, own account, user administration (api_account.py) ----------------------------
@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(S.static_dir / "login.html", media_type="text/html")


app.include_router(api_account.make_router(S, auth, _secure))


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
        "news": {"enabled": news.enabled, "images": S.news_images, "sources": len(news.sources), "actors": actors.count(),
                 "web": news.web_enabled},
        "optional": {name: S.source_on(name) for name in OPTIONAL_SOURCES},
        "attack": {"version": attack.version()},
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
                           "countries": [], "vendors": [], "products": [], "assets": [], "actors": [], "news": []}
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
        out["news"] = _search_news(cve=cve)
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
    out["actors"] = actors.search(q)
    out["news"] = _search_news(q=q)
    return out


def _search_news(*, q: str | None = None, cve: str | None = None) -> list[dict[str, Any]]:
    if not news.enabled:
        return []
    if cve:
        rows = db.query("SELECT id, source, title, published FROM news WHERE cves LIKE ? AND tier IN ('gov', 'press') "
                        "ORDER BY published DESC LIMIT 10", (f'%"{cve}"%',))
    elif q and len(q) >= 3:
        rows = news._rows(90, q=q, limit=10)
    else:
        return []
    return [{"id": r["id"], "title": r["title"], "published": r["published"],
             "source": news.by_id[r["source"]].name if r["source"] in news.by_id else r["source"]} for r in rows]


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
    if kind == "domain":
        kick("news_mine", _news_mine)
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
    if w["kind"] == "domain":
        kick("news_mine", _news_mine)
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


async def _news_mine() -> None:
    """Marks reports that concern the user's products and domains again (Weltlage: "concerns you")."""
    if news.enabled:
        await asyncio.to_thread(news.refresh_mine)


@app.post("/api/products")
async def api_product_add(request: Request, body: ProductIn) -> dict[str, Any]:
    pid = products.add(body.vendor, body.product)
    client = request.app.state.client

    async def check_then_news() -> None:
        await products.check(client, only=pid)
        await _news_mine()

    kick(f"product:{pid}", check_then_news)
    return {"id": pid}


@app.delete("/api/products/{pid}")
async def api_product_delete(pid: int) -> dict[str, Any]:
    if not products.delete(pid):
        raise AppError("err.not_found", 404)
    db.execute("DELETE FROM alerts WHERE product_id=?", (pid,))
    kick("news_mine", _news_mine)
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
def api_reports(limit: int = Query(20, ge=1, le=100), scope: str | None = Query(None, max_length=320)) -> list[dict[str, Any]]:
    if scope:
        rows = db.query("SELECT id, created_at, scope, model, payload FROM ai_reports WHERE scope=? ORDER BY id DESC LIMIT ?",
                        (scope, limit))
    else:
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
    if scope.startswith("obj:") and scope.count(":") >= 2:
        _, otype, value = scope.split(":", 2)
        page = await object_page(request, otype, value)
        if page.get("private"):
            raise AppError("err.tb.third_private", addr=page["value"], party="Gemini (Google)")
        ctx = obj_ai_context(page, lang)
    elif scope.startswith("news:"):
        ctx = news_ai_context(_news_item(_int_or_404(scope[5:])))
    elif scope.startswith("welt:"):
        ctx = await asyncio.to_thread(welt_ai_context, _int_or_404(scope[5:]))
    else:
        cc = scope.split(":", 1)[1] if ":" in scope else None
        country = country_localized(await country_data(request, cc), lang) if cc and CC_RE.match(cc) else None
        ctx = build_context(overview(), geo.country_name, lang, cc, country, S.home_region)
    ans = await ai.followup(request.app.state.client, report, thread, body.question.strip(), ctx, lang)
    tid = db.insert("INSERT INTO ai_threads(report_id, created_at, question, payload) VALUES(?,?,?,?)",
                    (body.report_id, utcnow(), body.question.strip(), json.dumps(ans)))
    return {"id": tid, "question": body.question.strip(), **ans}


# --- Weltlage (news) --------------------------------------------------------------------------------------------------
WELT_DAYS = (1, 7, 30, 90)
SQLITE_MAX_INT = 2**63 - 1


def _int_or_404(v: str) -> int:
    if not v.isdigit() or len(v) > 12:
        raise AppError("err.report_not_found", 404)
    return int(v)


def _welt_filters(tier: str | None, source: str | None, kind: str | None, country: str | None, origin: str | None,
                  target: str | None, actor: str | None, mine: bool, q: str | None, confirmed: bool = False,
                  supported: bool = False) -> dict[str, Any]:
    if not news.enabled:
        raise AppError("err.news.disabled", 404)
    kinds = [k for k in (kind or "").split(",") if k]
    if any(k not in nlp.KINDS for k in kinds) or len(kinds) > 5:
        raise AppError("err.bad_request")
    if source and source not in news.by_id:
        raise AppError("err.bad_request")
    if (tier == "web" or source == "gdelt") and not news.web_enabled:
        raise AppError("err.bad_request")
    if (country or "").strip() == "region":  # the home region, however many countries HOME_REGION lists
        ccs = list(S.home_region)
    else:  # a country or a short list ("DE,AT,CH")
        ccs = [_cc(c) for c in (country or "").split(",") if c.strip()]
        if len(ccs) > 12:
            raise AppError("err.bad_request")
    return {"tier": tier, "source": source, "kind": ",".join(kinds) or None, "country": ",".join(ccs) or None, "confirmed": confirmed,
            "supported": supported,
            "origin": _cc(origin) if origin else None, "target": _cc(target) if target else None,
            "actor": (actor or "").strip() or None, "mine": mine, "q": (q or "").strip() or None}


_welt_cache: dict[tuple[Any, ...], tuple[float, dict[str, Any]]] = {}


def welt_overview(days: int, flt: dict[str, Any]) -> dict[str, Any]:
    """Overview of the reports (cached 60 s per filter set; new items arrive at most every 15 minutes)."""
    key = (days, *sorted(flt.items()), db.meta_get("news_rev"))
    hit = _welt_cache.get(key)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    data = news.overview(days, list(S.home_region), **dict(flt))
    if len(_welt_cache) > 64:
        _welt_cache.clear()
    _welt_cache[key] = (time.time(), data)
    return data


@app.get("/api/welt")
def api_welt(days: int = Query(7), tier: str | None = Query(None, pattern="^(gov|press|web)$"),
             source: str | None = Query(None, pattern="^[a-z0-9_]{2,30}$"), kind: str | None = Query(None, max_length=80),
             country: str | None = Query(None, max_length=40), origin: str | None = Query(None, max_length=2),
             target: str | None = Query(None, max_length=2), actor: str | None = Query(None, max_length=120),
             mine: bool = False, confirmed: bool = False, supported: bool = False,
             q: str | None = Query(None, max_length=100)) -> dict[str, Any]:
    if days not in WELT_DAYS:
        raise AppError("err.bad_request")
    return welt_overview(days, _welt_filters(tier, source, kind, country, origin, target, actor, mine, q, confirmed, supported))


@app.get("/api/news")
def api_news(days: int = Query(7), offset: int = Query(0, ge=0, le=20000), limit: int = Query(40, ge=1, le=100),
             tier: str | None = Query(None, pattern="^(gov|press|web)$"), source: str | None = Query(None, pattern="^[a-z0-9_]{2,30}$"),
             kind: str | None = Query(None, max_length=80), country: str | None = Query(None, max_length=40),
             origin: str | None = Query(None, max_length=2), target: str | None = Query(None, max_length=2),
             actor: str | None = Query(None, max_length=120), mine: bool = False, confirmed: bool = False,
             supported: bool = False, q: str | None = Query(None, max_length=100)) -> dict[str, Any]:
    if days not in WELT_DAYS:
        raise AppError("err.bad_request")
    flt = _welt_filters(tier, source, kind, country, origin, target, actor, mine, q, confirmed, supported)
    return news.listing(days, offset, limit, **flt)


def _news_item(item_id: int) -> dict[str, Any]:
    if not news.enabled:
        raise AppError("err.news.disabled", 404)
    it = news.detail(item_id)
    if it is None:
        raise AppError("err.news.not_found", 404)
    return it


@app.get("/api/news/{item_id}")
def api_news_item(item_id: int = FPath(..., ge=1, le=SQLITE_MAX_INT)) -> dict[str, Any]:
    return _news_item(item_id)


def news_ai_context(it: dict[str, Any]) -> dict[str, Any]:
    ctx = news.ai_item(it)
    ctx["as_of_utc"] = utcnow()[:15] + "0:00Z"
    return ctx


def welt_ai_context(days: int) -> dict[str, Any]:
    if days not in WELT_DAYS:
        raise AppError("err.bad_request")
    ctx = news.ai_overview(welt_overview(days, _welt_filters(None, None, None, None, None, None, None, False, None)))
    ctx["as_of_utc"] = utcnow()[:15] + "0:00Z"
    return ctx


class NewsAiIn(BaseModel):
    id: int = Field(..., ge=1, le=SQLITE_MAX_INT)
    question: str | None = Field(None, max_length=600)


class WeltAiIn(BaseModel):
    days: int = 7
    question: str | None = Field(None, max_length=600)


async def _ai_report(request: Request, task: str, ctx: dict[str, Any], scope_label: str, q: str, lang: str) -> dict[str, Any]:
    result = await ai.analyze(request.app.state.client, task, ctx, lang)
    if not result.get("cached"):
        result["id"] = db.insert("INSERT INTO ai_reports(created_at, scope, model, payload) VALUES(?,?,?,?)",
                                 (utcnow(), scope_label, result["model"], json.dumps({**result, "question": q or None})))
    return {**result, "scope": scope_label, "question": q or None}


@app.post("/api/ai/news")
async def api_ai_news(request: Request, body: NewsAiIn) -> dict[str, Any]:
    """Gemini assessment of one report in its context. Sends headline, teaser, sources and the recognised public
    entities; own products and domains only as a flag."""
    lang = _lang(request)
    it = _news_item(body.id)
    q = (body.question or "").strip()
    task = TASKS[lang]["news_question"] + q if q else TASKS[lang]["news"]
    return await _ai_report(request, task, news_ai_context(it), f"news:{it['id']}", q, lang)


@app.post("/api/ai/welt")
async def api_ai_welt(request: Request, body: WeltAiIn) -> dict[str, Any]:
    lang = _lang(request)
    ctx = await asyncio.to_thread(welt_ai_context, body.days)  # reads up to 90 days of reports: not on the event loop
    q = (body.question or "").strip()
    task = TASKS[lang]["welt_question"] + q if q else TASKS[lang]["welt"]
    return await _ai_report(request, task, ctx, f"welt:{body.days}", q, lang)


# --- 3.3: internet blocking (OONI, government-directed outages) and platform outages ---------------------------------
@app.get("/api/welt/blocking")
def api_welt_blocking(days: int = Query(7)) -> dict[str, Any]:
    """Per country: OONI measurements (websites, messengers) and the outages Cloudflare attributes to a government."""
    if not news.enabled:
        raise AppError("err.news.disabled", 404)
    if days not in WELT_DAYS:
        raise AppError("err.bad_request")
    d = min(days, 30)  # OONI counts are kept for 35 days
    rows = ooni.summary(db, max(d, 7)) if S.source_on("ooni") else []
    shut = []
    for r in db.query("SELECT id, start_ts, end_ts, countries, cause, scope, url FROM infra_events WHERE kind = 'outage' "
                      "AND cause IN ('GOVERNMENT_DIRECTED', 'BLOCKING') AND COALESCE(end_ts, start_ts) >= ? "
                      "ORDER BY start_ts DESC LIMIT 100", (_cutoff(days),)):
        try:
            ccs = [c for c in json.loads(r["countries"] or "[]") if CC_RE.match(str(c))]
        except ValueError:
            ccs = []
        shut.append({"id": r["id"], "start": r["start_ts"], "end": r["end_ts"], "countries": ccs, "cause": r["cause"],
                     "scope": r["scope"], "url": r["url"]})
    return {"enabled": S.source_on("ooni"), "days": days, "ooni_days": max(d, 7), "countries": rows[:250], "shutdowns": shut}


class PlatformsIn(BaseModel):
    providers: list[str] = Field(default_factory=list, max_length=10)


@app.get("/api/platforms")
def api_platforms(days: int = Query(7, ge=1, le=30), active: bool = False) -> dict[str, Any]:
    return {"enabled": S.source_on("cloud_status"), "providers": platforms.providers(),
            "incidents": platforms.listing(days, active)}


@app.post("/api/platforms/used")
def api_platforms_used(body: PlatformsIn) -> dict[str, Any]:
    return {"providers": platforms.set_used([str(p)[:20] for p in body.providers])}


# --- "today": the few things that matter most right now ----------------------------------------------------------
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@app.get("/api/today")
def api_today(request: Request, limit: int = Query(5, ge=1, le=12)) -> dict[str, Any]:
    """Own alerts (48 h), detected patterns and big reports of the last 24 h, ranked by severity, then kind, then time."""
    lang = _lang(request)
    out: list[dict[str, Any]] = []
    since = _cutoff(2)
    for a in alerts.listing(db, lang, limit=40, min_severity="medium"):
        if a["created_at"] < since:
            break
        out.append({"kind": "alert", "severity": a["severity"], "title": a["title"], "detail": a["detail"], "time": a["created_at"],
                    "ref": {"alert": a["id"], "source": a["source"], "asset_id": a["asset_id"], "product_id": a["product_id"],
                            "url": a["url"]}})
    for p in localized(overview(), lang)["patterns"]:
        if p["severity"] in ("high", "medium") and p["category"] != "alerts":  # the alerts themselves are listed above
            out.append({"kind": "pattern", "severity": p["severity"], "title": p["title"], "detail": p["detail"], "time": None,
                        "ref": {"country": p.get("country"), "category": p["category"]}})
    if news.enabled:
        home = set(S.home_region) or {"DE"}
        for it in welt_overview(1, _welt_filters(None, None, None, None, None, None, None, False, None))["items"]:
            # three independent sources, or an authority about the home region
            big = len(it["sources"]) >= 3 or (it["source"]["tier"] == "gov" and bool(home & ({it["origin"]} | set(it["countries"]))))
            if big:
                out.append({"kind": "news", "severity": "info", "title": it["title"],
                            "detail": " · ".join(it["sources"][:3]), "time": it["latest"],
                            "ref": {"news": it["id"], "n": it["n"], "url": it["url"]}})
    rank = {"alert": 0, "pattern": 1, "news": 2}
    out.sort(key=lambda x: x["time"] or "", reverse=True)  # newest first; the sort below is stable
    out.sort(key=lambda x: (SEV_ORDER[x["severity"]], rank[x["kind"]]))
    return {"items": out[:limit], "total": len(out)}


# --- tool box ------------------------------------------------------------------------------------------------------------
def tb_ctx(request: Request) -> Ctx:
    return Ctx(S, db, geo, reputation, toolkit, matcher, domains, surface, request.app.state.client, _lang(request))


def _ndjson(request: Request, gen: AsyncIterator[dict[str, Any]]) -> StreamingResponse:
    async def body() -> AsyncIterator[bytes]:
        try:
            async for ev in gen:
                yield tbrun.ndjson(ev)
                if await request.is_disconnected():
                    break
        finally:
            await gen.aclose()

    return StreamingResponse(body(), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/tb/registry")
def api_tb_registry(request: Request) -> dict[str, Any]:
    lang = _lang(request)
    return {"tools": [tbreg.describe(t, S, lang) for t in tbreg.TOOLS],
            "recipes": [tbreg.recipe_info(r, lang) for r in tbreg.RECIPES],
            "groups": list(tbreg.GROUPS), "cyberchef_url": S.cyberchef_url, "enabled": S.tools_enabled}


@app.get("/api/tb/detect")
def api_tb_detect(q: str = Query("", max_length=4096)) -> dict[str, Any]:
    d = tb_detect(q)
    if d["type"] == "empty":
        return {**d, "tools": [], "recipes": []}
    # tools that would refuse the target (private address or internal name for a third party) are not suggested
    return {**d, "tools": tbrun.fitting_tools(d), "recipes": tbreg.recipes_for(d)}


class RunIn(BaseModel):
    tool: str = Field(..., min_length=1, max_length=40)
    target: str = Field("", max_length=4096)
    params: dict[str, Any] = Field(default_factory=dict)
    consent: bool = False


@app.post("/api/tb/run")
async def api_tb_run(request: Request, body: RunIn) -> StreamingResponse:
    spec = tbreg.BY_ID.get(body.tool)
    if spec is None:
        raise AppError("err.not_found", 404)
    ctx = tb_ctx(request)
    tbrun.check_available(spec, ctx)
    target, kind, params = tbrun.prepare(spec, body.target, body.params, body.consent)
    return _ndjson(request, tbrun.run_tool(ctx, spec, target, kind, params))


class RecipeIn(BaseModel):
    recipe: str = Field(..., min_length=1, max_length=20)
    target: str = Field(..., min_length=1, max_length=15 * 1024 * 1024)


@app.post("/api/tb/recipe")
async def api_tb_recipe(request: Request, body: RecipeIn) -> StreamingResponse:
    if not S.tools_enabled:
        raise AppError("err.tools_disabled", 403)
    target, kind = tbrun.prepare_recipe(body.recipe, body.target)
    return _ndjson(request, tbrun.run_recipe(tb_ctx(request), body.recipe, target, kind))


@app.get("/api/tb/history")
def api_tb_history(type: str | None = Query(None, max_length=20), value: str | None = Query(None, max_length=2048),
                   limit: int = Query(50, ge=1, le=500)) -> dict[str, Any]:
    return {"runs": tbrun.history(db, type, value, limit)}


@app.get("/api/tb/history/{rid}")
def api_tb_history_get(rid: int) -> dict[str, Any]:
    r = tbrun.get_run(db, rid)
    if r is None:
        raise AppError("err.not_found", 404)
    return r


@app.delete("/api/tb/history/{rid}")
def api_tb_history_delete(rid: int) -> dict[str, Any]:
    if not db.execute("DELETE FROM tool_runs WHERE id=?", (rid,)):
        raise AppError("err.not_found", 404)
    return {"deleted": rid}


# --- objects (analysis area) -------------------------------------------------------------------------------------------
async def object_page(request: Request, otype: str, value: str) -> dict[str, Any]:
    lang = _lang(request)
    if otype not in OBJ_TYPES:
        raise AppError("err.obj.invalid")
    client = request.app.state.client
    if otype == "country":
        cc = _cc(value)
        country = country_localized(await country_data(request, cc), lang)
        return await objects.build("country", cc, lang, client, country=country, trends=analytics.trends(db, cc, 30))
    return await objects.build(otype, value, lang, client)


def obj_ai_context(page: dict[str, Any], lang: str) -> dict[str, Any]:
    ctx = object_context(page)
    ctx["as_of_utc"] = utcnow()[:15] + "0:00Z"  # 10-minute steps: repeated questions hit the answer cache (ai.py, 600 s)
    ctx["available_tools"] = [i18n.t(lang, f"tb.tool.{tid}") for tid in page.get("tools") or [] if tid != "cyberchef"]
    return ctx


@app.get("/api/obj")
async def api_obj(request: Request, type: str = Query(..., max_length=10),
                  value: str = Query(..., min_length=1, max_length=2048)) -> dict[str, Any]:
    return await object_page(request, type, value)  # URLs up to 2048 characters, other types up to 300 (objects.normalize)


class ObjAiIn(BaseModel):
    type: str = Field(..., max_length=10)
    value: str = Field(..., min_length=1, max_length=2048)
    question: str | None = Field(None, max_length=600)


@app.post("/api/ai/object")
async def api_ai_object(request: Request, body: ObjAiIn) -> dict[str, Any]:
    """Gemini assessment of one object. The object value is sent to Google; own assets only as a flag (objects.object_context)."""
    lang = _lang(request)
    page = await object_page(request, body.type, body.value)
    if page.get("private"):
        raise AppError("err.tb.third_private", addr=page["value"], party="Gemini (Google)")
    q = (body.question or "").strip()
    task = TASKS[lang]["object_question"] + q if q else TASKS[lang]["object"]
    result = await ai.analyze(request.app.state.client, task, obj_ai_context(page, lang), lang)
    scope_label = f"obj:{page['type']}:{page['value']}"
    if not result.get("cached"):
        result["id"] = db.insert("INSERT INTO ai_reports(created_at, scope, model, payload) VALUES(?,?,?,?)",
                                 (utcnow(), scope_label, result["model"], json.dumps({**result, "question": q or None})))
    return {**result, "scope": scope_label, "question": q or None}


# --- deep views ---------------------------------------------------------------------------------------------------------
@app.get("/api/kev")
def api_kev(q: str | None = Query(None, max_length=100), vendor: str | None = Query(None, max_length=80),
            days: int = Query(0, ge=0, le=3650), ransomware: bool = False, min_epss: float = Query(0.0, ge=0.0, le=1.0),
            mine: bool = False, sort: str = Query("date", pattern="^(date|epss)$"),
            catalog: str = Query("kev", pattern="^(kev|euvd)$"), exploit: bool = False,
            limit: int = Query(300, ge=1, le=2000)) -> dict[str, Any]:
    """Exploited vulnerabilities with EPSS, filterable.
    catalog "kev": CISA KEV; "euvd": exploited according to ENISA (EUVD) but not (yet) in CISA KEV.
    'mine' = only CVEs of watched products or seen on own IPs (InternetDB); 'exploit' = only with public exploit code."""
    exposed: set[str] = set()
    for r in db.query("SELECT vulns FROM surface"):
        try:
            exposed.update(json.loads(r["vulns"] or "[]"))
        except ValueError:
            continue
    watched = {r["cve"] for r in db.query("SELECT DISTINCT cve FROM product_cves")}
    if catalog == "kev":
        sql = ("SELECT k.cve, k.vendor, k.product, k.name, k.date_added, k.due_date, k.ransomware, e.epss, e.percentile, "
               "u.euvd_id AS euvd FROM kev k LEFT JOIN epss e ON e.cve = k.cve LEFT JOIN euvd u ON u.cve = k.cve WHERE 1=1")
    else:  # same columns, so filters and sorting below apply to both catalogues
        sql = ("SELECT k.cve, k.vendor, k.product, NULL AS name, k.exploited_since AS date_added, NULL AS due_date, "
               "NULL AS ransomware, e.epss, e.percentile, k.euvd_id AS euvd FROM euvd k LEFT JOIN epss e ON e.cve = k.cve "
               "WHERE k.cve NOT IN (SELECT cve FROM kev)")
    params: list[Any] = []
    added = "k.date_added" if catalog == "kev" else "k.exploited_since"  # fixed column names, not user input
    if q and q.strip():
        name = "k.name" if catalog == "kev" else "k.euvd_id"
        sql += (" AND (k.cve LIKE ? ESCAPE '\\' OR k.vendor LIKE ? ESCAPE '\\' OR k.product LIKE ? ESCAPE '\\' "
                f"OR {name} LIKE ? ESCAPE '\\')")
        params += [_like(q.strip())] * 4
    if vendor:
        sql += " AND k.vendor = ? COLLATE NOCASE"
        params.append(vendor.strip())
    if days:
        sql += f" AND {added} >= ?"
        params.append(_cutoff(days)[:10])
    if ransomware and catalog == "kev":
        sql += " AND lower(k.ransomware) = 'known'"
    if min_epss > 0:
        sql += " AND e.epss >= ?"
        params.append(min_epss)
    sql += " ORDER BY " + (f"COALESCE(e.epss, -1) DESC, {added} DESC" if sort == "epss" else f"{added} DESC, k.cve DESC")
    rows = db.query(sql, params)
    xp: dict[str, list[str]] = {}
    for r in db.query("SELECT DISTINCT cve, source FROM exploits ORDER BY source"):
        xp.setdefault(r["cve"], []).append(r["source"])
    for r in rows:
        r["watched"] = r["cve"] in watched
        r["exposed"] = r["cve"] in exposed
        r["exploits"] = xp.get(r["cve"], [])
    if mine:
        rows = [r for r in rows if r["watched"] or r["exposed"]]
    if exploit:
        rows = [r for r in rows if r["exploits"]]
    vendors: dict[str, int] = {}
    for r in rows:
        vendors[r["vendor"] or "?"] = vendors.get(r["vendor"] or "?", 0) + 1
    return {"total": len(rows), "rows": rows[:limit],
            "vendors": [{"key": k, "count": v} for k, v in sorted(vendors.items(), key=lambda x: -x[1])[:25]],
            "catalog": db.query("SELECT COUNT(*) AS n FROM kev")[0]["n"] if catalog == "kev" else
            db.query("SELECT COUNT(*) AS n FROM euvd WHERE cve NOT IN (SELECT cve FROM kev)")[0]["n"],
            "euvd": S.source_on("euvd"), "exploits": S.source_on("exploits")}


@app.get("/api/infra")
def api_infra(request: Request, days: int = Query(30, ge=1, le=60),
              kind: str | None = Query(None, pattern="^(outage|hijack|leak|anomaly)$"),
              cc: str | None = Query(None, max_length=2), limit: int = Query(500, ge=1, le=2000)) -> dict[str, Any]:
    """Infrastructure events (Cloudflare Radar: outages, BGP hijacks and leaks, traffic anomalies); stored for 60 days."""
    lang = _lang(request)
    sql = ("SELECT id, kind, start_ts, end_ts, countries, asns, prefixes, cause, scope, confidence, url, meta FROM infra_events "
           "WHERE COALESCE(end_ts, start_ts, updated_at) >= ?")
    params: list[Any] = [_cutoff(days)]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    rows = db.query(sql + " ORDER BY start_ts DESC", params)
    want = _cc(cc) if cc else None
    out = []
    counts: dict[str, int] = {}
    for r in rows:
        try:
            r["countries"] = json.loads(r["countries"] or "[]")
            r["asns"] = json.loads(r["asns"] or "[]")
            r["prefixes"] = json.loads(r["prefixes"] or "[]")
            r["meta"] = json.loads(r["meta"] or "{}")
        except ValueError:
            continue
        if want and want not in r["countries"]:
            continue
        r["meta"]["kind"] = r["kind"]
        r["ongoing"] = r["end_ts"] is None and r["kind"] in ("outage", "leak", "anomaly")
        counts[r["kind"]] = counts.get(r["kind"], 0) + 1
        out.append(_event(r, lang))
    return {"total": len(out), "counts": counts, "events": out[:limit]}


# --- own IP and "my network" ----------------------------------------------------------------------------------------------
def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _myip_kick(request: Request) -> None:
    kick("myip", request.app.state.jobs["myip"])


async def _myip_check_all(client: Any) -> None:
    for kind in MYIP_KINDS:
        if myip.current()[kind]:
            await myip.check(client, kind)


@app.get("/api/myip")
def api_myip(request: Request) -> dict[str, Any]:
    return {**myip.state(), "you": myip.peek(_client_ip(request)), "sightings": myip.sightings()}


@app.post("/api/myip/visit")
async def api_myip_visit(request: Request) -> dict[str, Any]:
    res = myip.visit(_client_ip(request))
    if res.get("auto_applied"):
        _myip_kick(request)
    return res


class MyIPConfirmIn(BaseModel):
    auto: bool = False


@app.post("/api/myip/confirm")
async def api_myip_confirm(request: Request, body: MyIPConfirmIn) -> dict[str, Any]:
    res = myip.confirm(_client_ip(request), body.auto)
    _myip_kick(request)
    return res


class MyIPConfigIn(BaseModel):
    dyndns: str | None = Field(None, max_length=253)
    auto_asn: bool | None = None


@app.post("/api/myip/config")
async def api_myip_config(request: Request, body: MyIPConfigIn) -> dict[str, Any]:
    cfg = myip.configure(body.dyndns, body.auto_asn)
    if body.dyndns:
        _myip_kick(request)
    return cfg


@app.post("/api/myip/token")
def api_myip_token() -> dict[str, Any]:
    """Creates a new reporter token (replaces the old one). It is shown once; only its hash is stored."""
    return {"token": myip.new_token()}


@app.delete("/api/myip/token")
def api_myip_token_delete() -> dict[str, Any]:
    myip.revoke_token()
    return {"ok": True}


class MyIPKindIn(BaseModel):
    kind: str = Field(..., pattern="^(home|server)$")


@app.post("/api/myip/clear")
def api_myip_clear(body: MyIPKindIn) -> dict[str, Any]:
    myip.clear(body.kind)
    return {"ok": True}


@app.post("/api/myip/check")
async def api_myip_check(request: Request) -> dict[str, Any]:
    _throttle("myip-check", 60)
    client = request.app.state.client
    kick("myip-check", lambda: _myip_check_all(client))
    return {"ok": True}


def _report_token(request: Request) -> str | None:
    """Bearer token, or the password of HTTP Basic auth (dyndns2 clients); the user name is ignored."""
    scheme, _, cred = (request.headers.get("authorization") or "").partition(" ")
    if scheme.lower() == "bearer":
        return cred.strip() or None
    if scheme.lower() == "basic":
        try:
            dec = base64.b64decode(cred.strip(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return None
        return dec.partition(":")[2] or None
    return None


def _claimed(*vals: str | None) -> list[str] | None:
    out = [x.strip() for v in vals if v for x in v.split(",") if x.strip()]
    return out[:4] or None


@app.post("/api/myip/report")
async def api_myip_report(request: Request, ip: str | None = Query(None, max_length=100)) -> JSONResponse:
    """Reporter for the home IP: a device at home calls this with the token (Authorization: Bearer).
    Without ?ip= the connecting address is used (requires a reverse proxy that sets X-Forwarded-For)."""
    status, ips = myip.report(_report_token(request), _client_ip(request), _claimed(ip))
    if status == "ok":
        _myip_kick(request)
    code = {"ok": 200, "nochg": 200, "badauth": 401, "locked": 429, "noip": 400, "wait": 429}[status]
    return JSONResponse({"status": status, "ips": ips}, code)


@app.get("/nic/update")
async def nic_update(request: Request, myip_q: str | None = Query(None, alias="myip", max_length=100),
                     myipv6: str | None = Query(None, max_length=60)) -> PlainTextResponse:
    """dyndns2-compatible update for routers and DynDNS clients (HTTP Basic auth, password = reporter token)."""
    challenge = {"WWW-Authenticate": 'Basic realm="Emberwatch"'}
    token = _report_token(request)
    if not token:
        return PlainTextResponse("badauth", 401, headers=challenge)
    status, ips = myip.report(token, _client_ip(request), _claimed(myip_q, myipv6))
    if status == "ok":
        _myip_kick(request)
        return PlainTextResponse("good " + " ".join(ips))
    if status == "nochg":
        return PlainTextResponse("nochg " + " ".join(ips))
    if status in ("badauth", "locked"):
        return PlainTextResponse("badauth", 401, headers=challenge)
    return PlainTextResponse("911")  # noip / wait: the client retries later


def _asset_risk(a: dict[str, Any]) -> str:
    sf = a.get("surface") or {}
    rep = a.get("reputation") or {}
    if a.get("high_7d") or rep.get("drop") or sf.get("kev"):
        return "high"
    if a.get("alerts_7d") or sf.get("vulns") or rep.get("tor"):
        return "medium"
    return "ok"


@app.get("/api/netz/overview")
def api_netz_overview(request: Request) -> dict[str, Any]:
    lang = _lang(request)
    st = myip.state()
    entries = []
    for w in db.query("SELECT id, kind, value, label, created_at, scan, scan_ack FROM watchlist ORDER BY id DESC"):
        a = asset_summary(w)
        a["risk"] = _asset_risk(a)
        entries.append(a)
    rank = {"high": 0, "medium": 1, "ok": 2}
    entries.sort(key=lambda a: (rank[a["risk"]], -(a.get("alerts_7d") or 0)))
    prods = products.listing()
    return {
        "myip": {k: {f: st[k].get(f) for f in ("ip", "ip6", "source", "updated_at", "checked_at", "checks", "geo")}
                 for k in MYIP_KINDS},
        "myip_configured": bool(st["home"]["config"].get("dyndns") or st["home"]["config"].get("token_set")
                                or st["home"]["config"].get("auto_asn")),
        "you": myip.peek(_client_ip(request)),
        "assets": {"total": len(entries), "by_risk": {k: sum(1 for a in entries if a["risk"] == k) for k in rank},
                   "top": [{k: a.get(k) for k in ("id", "kind", "value", "label", "risk", "alerts_7d", "high_7d", "surface",
                                                  "reputation")} for a in entries[:8]],
                   "max": watchlist.MAX_ENTRIES},
        "products": {"total": len(prods), "with_kev": sum(1 for p in prods if p["kev"]),
                     "with_critical": sum(1 for p in prods if p["critical"])},
        "alerts": {"stats": alerts.stats(db), "latest": alerts.listing(db, lang, limit=10)},
        "scan": {"enabled": S.scan_enabled, "running": surface.current},
        "syslog": syslog.info() if syslog else {"enabled": False},
    }


# --- 4.0: who owns this IP, people search -------------------------------------------------------------------------------
app.include_router(owner_api.make_router(owner, auth, _ndjson, _lang))
app.include_router(personen_api.make_router(S, osint_store, osint_sites, searcher, auth, _spawn))


app.mount("/", StaticFiles(directory=str(S.static_dir), html=True), name="static")
