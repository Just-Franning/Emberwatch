"""Configuration from environment variables.

All values are read once at start-up. Invalid values fall back to safe defaults;
lower/upper bounds are enforced here so that a typo cannot hammer upstream APIs.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import REPO_URL, __version__

# Default TCP ports for the active scan of your own assets (common remote access, web, mail, DB, IoT services)
DEFAULT_SCAN_PORTS = (
    "21,22,23,25,53,80,81,88,110,111,135,139,143,389,443,445,465,514,587,631,636,873,993,995,1080,1194,1433,1521,"
    "1723,1883,2049,2082,2083,2086,2087,2222,2375,2376,3000,3128,3268,3306,3389,4443,4444,4786,5000,5001,5060,5432,"
    "5601,5672,5900,5985,5986,6379,6443,7001,7443,8000,8008,8080,8081,8086,8088,8443,8880,8888,9000,9001,9090,9092,"
    "9200,9443,10000,10250,11211,15672,25565,27017,32400,50000"
)
DEFAULT_SYSLOG_ALLOW = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7"


def _int(name: str, default: int, lo: int | None = None, hi: int | None = None) -> int:
    raw = os.getenv(name, "").strip()
    try:
        v = int(raw) if raw else default
    except ValueError:
        v = default
    if lo is not None:
        v = max(v, lo)
    if hi is not None:
        v = min(v, hi)
    return v


def _float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.getenv(name, "").strip()
    try:
        v = float(raw) if raw else default
    except ValueError:
        v = default
    return min(max(v, lo), hi)


def _str(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _bin(name: str, default: str, program: str) -> str:
    """Path of a helper binary. If the configured path does not exist, PATH is searched."""
    path = _str(name) or default
    if Path(path).is_file():
        return path
    return shutil.which(program) or path


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on", "ja")


def _ports(raw: str) -> tuple[int, ...]:
    out: list[int] = []
    for tok in raw.replace(";", ",").split(","):
        tok = tok.strip()
        if "-" in tok:
            a, _, b = tok.partition("-")
            if a.isdigit() and b.isdigit() and 1 <= int(a) <= int(b) <= 65535 and int(b) - int(a) <= 1024:
                out.extend(range(int(a), int(b) + 1))
        elif tok.isdigit() and 1 <= int(tok) <= 65535:
            out.append(int(tok))
    return tuple(dict.fromkeys(out))[:1024]


def _nets(raw: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets = []
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _origins(raw: str) -> tuple[str, ...]:
    """'https://a.example, b.example:8443' -> ('a.example', 'b.example:8443')"""
    out = []
    for tok in raw.split(","):
        tok = tok.strip().lower()
        if "://" in tok:
            tok = tok.split("://", 1)[1]
        tok = tok.split("/", 1)[0]
        if tok:
            out.append(tok)
    return tuple(out)


def _cyberchef(raw: str) -> str:
    """Base URL of a CyberChef instance (http/https only, no fragment). Empty or invalid -> the public GCHQ instance."""
    default = "https://gchq.github.io/CyberChef/"
    v = raw.strip()
    if not re.fullmatch(r"https?://[^\s\"'<>#]{3,300}", v):
        return default
    return v


# Sources that SOURCES_DISABLE can switch off (unknown names are ignored)
OPTIONAL_SOURCES = ("ooni", "gdelt", "attack", "euvd", "exploits", "urlhaus", "cloud_status")


def _names(raw: str) -> frozenset[str]:
    return frozenset(x.strip().lower() for x in raw.split(",") if x.strip().lower() in OPTIONAL_SOURCES)


def _region(raw: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(c.strip().upper() for c in raw.split(",") if re.fullmatch(r"\s*[A-Za-z]{2}\s*", c)))


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    static_dir: Path
    version: str
    user_agent: str
    collectors: bool
    language: str  # server-side language for notifications and reports: "de" | "en"

    # Authentication
    auth_mode: str  # "password" | "none"
    auth_password: str
    session_hours: int
    cookie_secure: str  # "auto" | "1" | "0"

    # Data sources
    cf_api_token: str
    abusech_auth_key: str
    ransomware_live_api_key: str
    abuseipdb_api_key: str
    nvd_api_key: str
    certspotter_api_key: str
    gemini_api_key: str
    gemini_model: str

    # Intervals (minutes unless noted)
    radar_interval: int
    infra_interval: int
    c2_interval: int
    ransomware_interval: int
    kev_interval: int
    epss_interval: int
    backfill_days: int
    c2_retention_days: int
    ioc_retention_days: int
    alert_retention_days: int
    ai_min_interval_s: int

    # Matrix notifications and daily report
    matrix_homeserver: str
    matrix_token: str
    matrix_room: str
    matrix_min_severity: str
    timezone: str
    daily_report_time: str  # "HH:MM" or "" = off
    home_region: tuple[str, ...]
    home_region_name: str

    # Network tools
    tools_enabled: bool
    tools_allow_private: bool
    ping_bin: str
    traceroute_bin: str

    # Attack surface
    surface_interval_h: int
    surface_max_ips: int
    scan_enabled: bool
    scan_interval_h: int
    scan_ports: tuple[int, ...]
    scan_concurrency: int
    scan_timeout_s: float
    scan_max_hosts: int

    # Products, domains, BGP, reputation
    product_interval_h: int
    product_min_cvss: float
    ct_interval_h: int
    typo_interval_h: int
    typo_max: int
    bgp_live: bool
    abuseipdb_min_score: int

    # Log analysis
    log_max_mb: int
    syslog_enabled: bool
    syslog_port: int
    syslog_allow: tuple = field(default_factory=tuple)
    syslog_max_rate: int = 2000
    trusted_origins: tuple[str, ...] = ()  # extra host[:port] values accepted in the Origin header

    # Tool box: optional third-party keys and the CyberChef instance used by the browser
    greynoise_api_key: str = ""
    globalping_token: str = ""
    cyberchef_url: str = "https://gchq.github.io/CyberChef/"

    # Weltlage: IT security news from curated feeds
    news_enabled: bool = True
    news_interval: int = 30
    news_images: bool = True
    news_feeds: str = ""
    news_disable: str = ""
    news_retention_days: int = 90

    # 3.3: further public sources, each can be switched off with SOURCES_DISABLE=ooni,gdelt,...
    sources_disable: frozenset[str] = frozenset()

    @property
    def matrix_enabled(self) -> bool:
        return bool(self.matrix_homeserver and self.matrix_token and self.matrix_room)

    def source_on(self, name: str) -> bool:
        return name not in self.sources_disable


def load() -> Settings:
    base = Path(__file__).resolve().parent.parent.parent
    static_dir = Path(_str("STATIC_DIR", str(base / "frontend")))
    contact = _str("CONTACT", "")
    ua = f"emberwatch/{__version__} (+{REPO_URL})" + (f" contact: {contact}" if contact else "")
    daily = _str("DAILY_REPORT_TIME", "07:00")
    if daily and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", daily):
        daily = ""
    sev = _str("MATRIX_MIN_SEVERITY", "high").lower()
    if sev not in ("high", "medium", "low"):
        sev = "high"
    lang = _str("LANGUAGE", "en").lower()[:2]
    if lang not in ("de", "en"):
        lang = "en"
    auth_mode = _str("AUTH_MODE", "password").lower()
    if auth_mode not in ("password", "none"):
        auth_mode = "password"
    cookie_secure = _str("COOKIE_SECURE", "auto").lower()
    if cookie_secure not in ("auto", "1", "0", "true", "false"):
        cookie_secure = "auto"
    cookie_secure = {"true": "1", "false": "0"}.get(cookie_secure, cookie_secure)
    scan_ports = _ports(_str("SCAN_PORTS", DEFAULT_SCAN_PORTS)) or _ports(DEFAULT_SCAN_PORTS)
    return Settings(
        data_dir=Path(_str("DATA_DIR", str(base / "data"))),
        static_dir=static_dir,
        version=__version__,
        user_agent=ua,
        collectors=_str("COLLECTORS", "1") != "0",
        language=lang,
        auth_mode=auth_mode,
        auth_password=os.getenv("AUTH_PASSWORD", ""),
        session_hours=_int("SESSION_HOURS", 12, 1, 24 * 30),
        cookie_secure=cookie_secure,
        cf_api_token=_str("CF_API_TOKEN"),
        abusech_auth_key=_str("ABUSECH_AUTH_KEY"),
        ransomware_live_api_key=_str("RANSOMWARE_LIVE_API_KEY"),
        abuseipdb_api_key=_str("ABUSEIPDB_API_KEY"),
        nvd_api_key=_str("NVD_API_KEY"),
        certspotter_api_key=_str("CERTSPOTTER_API_KEY"),
        gemini_api_key=_str("GEMINI_API_KEY"),
        gemini_model=_str("GEMINI_MODEL", "gemini-3.8-flash"),
        radar_interval=_int("RADAR_INTERVAL_MIN", 30, 15),
        infra_interval=_int("INFRA_INTERVAL_MIN", 30, 15),
        c2_interval=_int("C2_INTERVAL_MIN", 30, 10),
        # ransomware.live caches for 30 min; more frequent polling is unwanted per their terms
        ransomware_interval=_int("RANSOMWARE_INTERVAL_MIN", 60, 30),
        kev_interval=_int("KEV_INTERVAL_MIN", 360, 60),
        epss_interval=_int("EPSS_INTERVAL_MIN", 720, 360),
        backfill_days=_int("BACKFILL_DAYS", 30, 0, 90),
        c2_retention_days=_int("C2_RETENTION_DAYS", 30, 1),
        ioc_retention_days=_int("IOC_RETENTION_DAYS", 30, 1, 365),
        alert_retention_days=_int("ALERT_RETENTION_DAYS", 180, 7),
        ai_min_interval_s=_int("AI_MIN_INTERVAL_S", 15, 0),
        matrix_homeserver=_str("MATRIX_HOMESERVER").rstrip("/"),
        matrix_token=_str("MATRIX_ACCESS_TOKEN"),
        matrix_room=_str("MATRIX_ROOM_ID"),
        matrix_min_severity=sev,
        timezone=_str("TZ", "Europe/Berlin") or "Europe/Berlin",
        daily_report_time=daily,
        home_region=_region(_str("HOME_REGION", "")),
        home_region_name=_str("HOME_REGION_NAME", "")[:40],
        tools_enabled=_bool("TOOLS_ENABLED", True),
        tools_allow_private=_bool("TOOLS_ALLOW_PRIVATE", False),
        # ping: copy without file capabilities (see Dockerfile). If missing, the TCP fallback is used.
        ping_bin=_bin("PING_BIN", "/usr/local/bin/ping", "ping"),
        # Debian installs traceroute via update-alternatives as /usr/bin/traceroute
        traceroute_bin=_bin("TRACEROUTE_BIN", "/usr/bin/traceroute", "traceroute"),
        surface_interval_h=_int("SURFACE_INTERVAL_H", 24, 6),
        surface_max_ips=_int("SURFACE_MAX_IPS", 256, 1, 4096),
        scan_enabled=_bool("SCAN_ENABLED", True),
        scan_interval_h=_int("SCAN_INTERVAL_H", 168, 6),
        scan_ports=scan_ports,
        scan_concurrency=_int("SCAN_CONCURRENCY", 64, 1, 256),
        scan_timeout_s=_float("SCAN_TIMEOUT_S", 1.5, 0.3, 10.0),
        scan_max_hosts=_int("SCAN_MAX_HOSTS", 256, 1, 1024),
        product_interval_h=_int("PRODUCT_INTERVAL_H", 12, 2),
        product_min_cvss=_float("PRODUCT_MIN_CVSS", 9.0, 0.0, 10.0),
        ct_interval_h=_int("CT_INTERVAL_H", 12, 1),
        typo_interval_h=_int("TYPO_INTERVAL_H", 24, 6),
        typo_max=_int("TYPO_MAX", 400, 10, 2000),
        bgp_live=_bool("BGP_LIVE", True),
        abuseipdb_min_score=_int("ABUSEIPDB_MIN_SCORE", 25, 1, 100),
        log_max_mb=_int("LOG_MAX_MB", 25, 1, 500),
        syslog_enabled=_bool("SYSLOG_ENABLED", False),
        syslog_port=_int("SYSLOG_PORT", 5514, 1024, 65535),
        syslog_allow=_nets(_str("SYSLOG_ALLOW", DEFAULT_SYSLOG_ALLOW)),
        syslog_max_rate=_int("SYSLOG_MAX_RATE", 2000, 10, 100000),
        trusted_origins=_origins(_str("TRUSTED_ORIGINS", "")),
        greynoise_api_key=_str("GREYNOISE_API_KEY"),
        globalping_token=_str("GLOBALPING_TOKEN"),
        cyberchef_url=_cyberchef(_str("CYBERCHEF_URL", "https://gchq.github.io/CyberChef/")),
        news_enabled=_bool("NEWS_ENABLED", True),
        news_interval=_int("NEWS_INTERVAL_MIN", 30, 15),
        news_images=_bool("NEWS_IMAGES", True),
        news_feeds=_str("NEWS_FEEDS"),
        news_disable=_str("NEWS_DISABLE"),
        news_retention_days=_int("NEWS_RETENTION_DAYS", 90, 7, 365),
        sources_disable=_names(_str("SOURCES_DISABLE")),
    )
