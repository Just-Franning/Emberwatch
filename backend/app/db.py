"""SQLite storage. One process, one writer: a single lock is enough.

Schema changes are additive: new tables via CREATE TABLE IF NOT EXISTS, new columns via _migrate().
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS radar_hist (
    metric TEXT NOT NULL,
    day TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (metric, day)
);
CREATE TABLE IF NOT EXISTS c2 (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    ioc TEXT NOT NULL,
    ip TEXT,
    port INTEGER,
    malware TEXT,
    threat_type TEXT,
    status TEXT,
    confidence INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    country TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    geo_precision TEXT,
    asn INTEGER,
    as_name TEXT,
    reference TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS c2_country ON c2(country);
CREATE INDEX IF NOT EXISTS c2_first_seen ON c2(first_seen);
CREATE INDEX IF NOT EXISTS c2_ip ON c2(ip);
CREATE TABLE IF NOT EXISTS iocs (
    id TEXT PRIMARY KEY,
    ioc TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    ip TEXT,
    host TEXT,
    port INTEGER,
    threat_type TEXT,
    malware TEXT,
    confidence INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    reference TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS iocs_ip ON iocs(ip);
CREATE INDEX IF NOT EXISTS iocs_host ON iocs(host);
CREATE TABLE IF NOT EXISTS victims (
    id TEXT PRIMARY KEY,
    victim TEXT,
    grp TEXT,
    country TEXT,
    activity TEXT,
    discovered TEXT,
    attackdate TEXT,
    permalink TEXT
);
CREATE INDEX IF NOT EXISTS victims_discovered ON victims(discovered);
CREATE TABLE IF NOT EXISTS kev (
    cve TEXT PRIMARY KEY,
    vendor TEXT,
    product TEXT,
    name TEXT,
    date_added TEXT,
    due_date TEXT,
    ransomware TEXT
);
CREATE TABLE IF NOT EXISTS source_status (
    source TEXT PRIMARY KEY,
    ok INTEGER NOT NULL,
    last_run TEXT,
    last_ok TEXT,
    message TEXT,
    count INTEGER
);
CREATE TABLE IF NOT EXISTS ai_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    scope TEXT NOT NULL,
    model TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    question TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_threads_report ON ai_threads(report_id);
CREATE TABLE IF NOT EXISTS infra_events (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    start_ts TEXT,
    end_ts TEXT,
    countries TEXT NOT NULL,
    asns TEXT NOT NULL,
    title TEXT,
    detail TEXT,
    cause TEXT,
    scope TEXT,
    confidence INTEGER,
    url TEXT,
    prefixes TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS infra_start ON infra_events(start_ts);
CREATE TABLE IF NOT EXISTS epss (
    cve TEXT PRIMARY KEY,
    epss REAL,
    percentile REAL,
    date TEXT
);
CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(kind, value)
);
CREATE TABLE IF NOT EXISTS watch_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    ref TEXT NOT NULL,
    detail TEXT,
    url TEXT,
    first_seen TEXT NOT NULL,
    notified INTEGER NOT NULL DEFAULT 0,
    UNIQUE(watch_id, source, ref)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    key TEXT NOT NULL,
    params TEXT NOT NULL,
    ref TEXT NOT NULL,
    asset_id INTEGER,
    product_id INTEGER,
    url TEXT,
    notified INTEGER NOT NULL DEFAULT 0,
    UNIQUE(source, ref)
);
CREATE INDEX IF NOT EXISTS alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS alerts_asset ON alerts(asset_id);
CREATE TABLE IF NOT EXISTS notifications (
    key TEXT PRIMARY KEY,
    sent_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rep_drop (
    cidr TEXT PRIMARY KEY,
    sblid TEXT,
    rir TEXT
);
CREATE TABLE IF NOT EXISTS rep_tor (
    ip TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS abuseipdb_cache (
    ip TEXT PRIMARY KEY,
    score INTEGER,
    reports INTEGER,
    payload TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS surface (
    ip TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    ports TEXT NOT NULL DEFAULT '[]',
    cpes TEXT NOT NULL DEFAULT '[]',
    hostnames TEXT NOT NULL DEFAULT '[]',
    tags TEXT NOT NULL DEFAULT '[]',
    vulns TEXT NOT NULL DEFAULT '[]',
    fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    trigger TEXT NOT NULL,
    targets INTEGER NOT NULL DEFAULT 0,
    open_ports INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX IF NOT EXISTS scan_runs_asset ON scan_runs(asset_id, id);
CREATE TABLE IF NOT EXISTS scan_ports (
    run_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    banner TEXT,
    tls TEXT,
    http TEXT,
    PRIMARY KEY (run_id, ip, port)
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(vendor, product)
);
CREATE TABLE IF NOT EXISTS nvd_cve (
    cve TEXT PRIMARY KEY,
    published TEXT,
    last_modified TEXT,
    cvss REAL,
    severity TEXT,
    summary TEXT,
    fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS product_cves (
    product_id INTEGER NOT NULL,
    cve TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (product_id, cve)
);
CREATE TABLE IF NOT EXISTS nvd_search_cache (
    q TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ct_certs (
    domain TEXT NOT NULL,
    tbs_sha256 TEXT NOT NULL,
    cert_id TEXT,
    names TEXT NOT NULL DEFAULT '[]',
    issuer TEXT,
    not_before TEXT,
    not_after TEXT,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (domain, tbs_sha256)
);
CREATE TABLE IF NOT EXISTS typo (
    domain TEXT NOT NULL,
    candidate TEXT NOT NULL,
    technique TEXT NOT NULL,
    registered INTEGER NOT NULL DEFAULT 0,
    mx INTEGER NOT NULL DEFAULT 0,
    ips TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT,
    last_checked TEXT NOT NULL,
    PRIMARY KEY (domain, candidate)
);
CREATE TABLE IF NOT EXISTS tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    tool TEXT NOT NULL,
    recipe TEXT,
    obj_type TEXT,
    obj_value TEXT,
    target TEXT,
    sev TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tool_runs_obj ON tool_runs(obj_type, obj_value, id);
CREATE TABLE IF NOT EXISTS myip (
    kind TEXT PRIMARY KEY,
    ip TEXT,
    ip6 TEXT,
    source TEXT,
    updated_at TEXT,
    checked_at TEXT,
    check_payload TEXT,
    config TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS myip_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    family INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT,
    asn INTEGER,
    as_name TEXT,
    country TEXT
);
CREATE INDEX IF NOT EXISTS myip_history_ip ON myip_history(kind, ip);
CREATE TABLE IF NOT EXISTS myip_sightings (
    ip TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    asn INTEGER,
    as_name TEXT,
    country TEXT
);
CREATE TABLE IF NOT EXISTS news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    summary TEXT,
    body TEXT,
    image TEXT,
    published TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    lang TEXT,
    tier TEXT,
    origin TEXT,
    origin_by TEXT,
    countries TEXT,
    actors TEXT,
    cves TEXT,
    malware TEXT,
    kinds TEXT,
    mine TEXT,
    cluster INTEGER,
    og_tried INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS news_published ON news(published);
CREATE INDEX IF NOT EXISTS news_cluster ON news(cluster);
CREATE TABLE IF NOT EXISTS actors (
    name TEXT PRIMARY KEY,
    country TEXT,
    sponsor TEXT,
    synonyms TEXT,
    victims TEXT,
    targets TEXT,
    sectors TEXT,
    incident TEXT,
    confidence TEXT,
    description TEXT,
    refs TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS ooni (
    cc TEXT NOT NULL,
    day TEXT NOT NULL,
    test TEXT NOT NULL,
    measurements INTEGER NOT NULL,
    anomalies INTEGER NOT NULL,
    confirmed INTEGER NOT NULL,
    failures INTEGER NOT NULL,
    PRIMARY KEY (cc, day, test)
);
CREATE TABLE IF NOT EXISTS attack_objects (
    stix_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    ext_id TEXT,
    name TEXT NOT NULL,
    aliases TEXT NOT NULL DEFAULT '[]',
    tactics TEXT NOT NULL DEFAULT '[]',
    sub INTEGER NOT NULL DEFAULT 0,
    sw_type TEXT,
    ord INTEGER NOT NULL DEFAULT 0,
    url TEXT
);
CREATE INDEX IF NOT EXISTS attack_objects_kind ON attack_objects(kind);
CREATE TABLE IF NOT EXISTS attack_uses (
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    PRIMARY KEY (src, dst)
);
CREATE TABLE IF NOT EXISTS euvd (
    cve TEXT PRIMARY KEY,
    euvd_id TEXT,
    exploited_since TEXT,
    score REAL,
    epss REAL,
    vendor TEXT,
    product TEXT,
    published TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exploits (
    cve TEXT NOT NULL,
    source TEXT NOT NULL,
    ref TEXT NOT NULL,
    name TEXT,
    detail TEXT,
    published TEXT,
    PRIMARY KEY (cve, source, ref)
);
CREATE TABLE IF NOT EXISTS platform_incidents (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    impact TEXT,
    started TEXT,
    updated TEXT,
    resolved TEXT,
    regions TEXT NOT NULL DEFAULT '[]',
    url TEXT,
    summary TEXT,
    fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS platform_incidents_updated ON platform_incidents(updated);
-- 4.0: accounts (auth.py). Passwords as scrypt hashes, TOTP secrets encrypted, sessions as SHA-256 of the cookie token
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    pw_changed TEXT NOT NULL,
    must_change INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT,
    totp_last INTEGER NOT NULL DEFAULT 0,
    recovery TEXT NOT NULL DEFAULT '[]',
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    created_by TEXT,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    ua TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    user_id INTEGER,
    user_name TEXT,
    action TEXT NOT NULL,
    target TEXT,
    ip TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
-- 4.0: "who owns this IP" (owner/) and cached web lookups (imprints, geocoding)
CREATE TABLE IF NOT EXISTS owner_cache (
    ip TEXT NOT NULL,
    active INTEGER NOT NULL,
    fetched_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (ip, active)
);
CREATE TABLE IF NOT EXISTS web_cache (
    key TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
-- 4.0: people search (personen/): cases, searches, hits, link graph
CREATE TABLE IF NOT EXISTS osint_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    note TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS osint_searches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES osint_cases(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    query TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    sites INTEGER NOT NULL DEFAULT 0,
    checked INTEGER NOT NULL DEFAULT 0,
    found INTEGER NOT NULL DEFAULT 0,
    unsure INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    created_by TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS osint_searches_case ON osint_searches(case_id);
CREATE TABLE IF NOT EXISTS osint_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    search_id INTEGER NOT NULL REFERENCES osint_searches(id) ON DELETE CASCADE,
    site TEXT NOT NULL,
    host TEXT NOT NULL,
    source TEXT NOT NULL,
    cat TEXT,
    status TEXT NOT NULL,
    url TEXT NOT NULL,
    http_status INTEGER,
    operator_cc TEXT,
    operator_src TEXT,
    profile TEXT,
    checked_at TEXT NOT NULL,
    UNIQUE(search_id, site)
);
CREATE TABLE IF NOT EXISTS osint_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES osint_cases(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    ref TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',
    manual INTEGER NOT NULL DEFAULT 0,
    x REAL,
    y REAL,
    created_at TEXT NOT NULL,
    UNIQUE(case_id, kind, ref)
);
CREATE TABLE IF NOT EXISTS osint_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES osint_cases(id) ON DELETE CASCADE,
    src INTEGER NOT NULL REFERENCES osint_nodes(id) ON DELETE CASCADE,
    dst INTEGER NOT NULL REFERENCES osint_nodes(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    strength TEXT NOT NULL,
    label TEXT,
    evidence TEXT,
    manual INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(case_id, src, dst, kind)
);
-- 4.0: public Telegram channels (telegram/), read from the web preview t.me/s/<channel>
CREATE TABLE IF NOT EXISTS tg_channels (
    name TEXT PRIMARY KEY,
    title TEXT,
    note TEXT,
    added_at TEXT NOT NULL,
    added_by TEXT,
    last_fetch TEXT,
    last_ok TEXT,
    error TEXT,
    last_post INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tg_posts (
    channel TEXT NOT NULL,
    post_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    text TEXT NOT NULL,
    views INTEGER,
    fwd TEXT,
    links TEXT NOT NULL DEFAULT '[]',
    countries TEXT NOT NULL DEFAULT '[]',
    targets TEXT NOT NULL DEFAULT '[]',
    kinds TEXT NOT NULL DEFAULT '[]',
    proofs TEXT NOT NULL DEFAULT '[]',
    checks TEXT,
    translation TEXT,
    translated_to TEXT,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (channel, post_id)
);
CREATE INDEX IF NOT EXISTS tg_posts_date ON tg_posts(date);
"""

# (table, column, declaration) – applied with ALTER TABLE if the column is missing
MIGRATIONS = (
    ("source_status", "code", "TEXT"),
    ("source_status", "params", "TEXT"),
    ("infra_events", "meta", "TEXT NOT NULL DEFAULT '{}'"),
    ("watchlist", "scan", "INTEGER NOT NULL DEFAULT 0"),
    ("watchlist", "scan_ack", "TEXT"),
    ("news", "body", "TEXT"),  # text the recognition ran on (also used when it runs again)
    ("news", "cables", "TEXT"),  # 3.3: submarine cables named in the report (ids of the cable map)
    ("news", "checks", "TEXT"),  # 3.3: comparison with measurements (corroborate.py), refreshed every run
)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def open_path(data_dir: Path) -> Path:
    """Database path. Takes over a database from the previous project name (ThreatMap) once."""
    data_dir.mkdir(parents=True, exist_ok=True)
    new = data_dir / "emberwatch.sqlite"
    old = data_dir / "threatmap.sqlite"
    if not new.exists() and old.exists():
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(old) + suffix)
            if src.exists():
                shutil.move(str(src), str(new) + suffix)
    return new


class DB:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        for table, column, decl in MIGRATIONS:
            cols = {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        # Watchlist hits of version 2 become alerts (text is kept as-is)
        legacy = self._conn.execute("SELECT watch_id, source, ref, detail, url, first_seen FROM watch_hits").fetchall()
        for r in legacy:
            self._conn.execute(
                "INSERT OR IGNORE INTO alerts(created_at, source, severity, key, params, ref, asset_id, url, notified) "
                "VALUES(?,?,?,?,?,?,?,?,1)",
                (r[5], "watch", "medium", "legacy", json.dumps({"detail": r[3] or ""}), f"legacy:{r[0]}:{r[1]}:{r[2]}", r[0], r[4]),
            )
        if legacy:
            self._conn.execute("DELETE FROM watch_hits")

    # --- generic -----------------------------------------------------------
    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def execmany(self, sql: str, rows: list[tuple]) -> None:
        if not rows:
            return
        with self._lock:
            self._conn.executemany(sql, rows)
            self._conn.commit()

    def insert(self, sql: str, params: Iterable[Any] = ()) -> int:
        """Runs an INSERT and returns the new rowid (0 if nothing was inserted)."""
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return int(cur.lastrowid or 0) if cur.rowcount else 0

    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur.rowcount

    def transaction(self, statements: list[tuple[str, Iterable[Any]]]) -> None:
        """Runs several statements atomically."""
        with self._lock:
            try:
                for sql, params in statements:
                    self._conn.execute(sql, tuple(params))
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def replace(self, steps: list[tuple[str, list[tuple[Any, ...]]]]) -> None:
        """Runs executemany for each (sql, rows) atomically – e.g. delete a whole data set and insert the new one."""
        with self._lock:
            try:
                for sql, rows in steps:
                    self._conn.executemany(sql, rows)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # --- key/value snapshots ----------------------------------------------
    def kv_set(self, key: str, payload: Any) -> None:
        self.execute(
            "INSERT INTO kv(key, fetched_at, payload) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET fetched_at=excluded.fetched_at, payload=excluded.payload",
            (key, utcnow(), json.dumps(payload)),
        )

    def kv_get(self, key: str) -> tuple[Any, str | None]:
        rows = self.query("SELECT payload, fetched_at FROM kv WHERE key=?", (key,))
        if not rows:
            return None, None
        return json.loads(rows[0]["payload"]), rows[0]["fetched_at"]

    def hist_set(self, metric: str, day: str, payload: Any) -> None:
        self.execute(
            "INSERT INTO radar_hist(metric, day, payload) VALUES(?,?,?) "
            "ON CONFLICT(metric, day) DO UPDATE SET payload=excluded.payload",
            (metric, day, json.dumps(payload)),
        )

    def hist_get(self, metric: str, limit: int = 30) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT day, payload FROM radar_hist WHERE metric=? ORDER BY day DESC LIMIT ?",
            (metric, limit),
        )
        return [{"day": r["day"], "data": json.loads(r["payload"])} for r in rows]

    def hist_days(self, metric: str) -> set[str]:
        return {r["day"] for r in self.query("SELECT day FROM radar_hist WHERE metric=?", (metric,))}

    def hist_on(self, metric: str, day: str) -> Any:
        rows = self.query("SELECT payload FROM radar_hist WHERE metric=? AND day=?", (metric, day))
        return json.loads(rows[0]["payload"]) if rows else None

    # --- meta (flags, timestamps) -------------------------------------------
    def meta_get(self, key: str, default: str | None = None) -> str | None:
        rows = self.query("SELECT value FROM meta WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    def meta_set(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO meta(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # --- source status -----------------------------------------------------
    def status(self, source: str, ok: bool, message: str = "", count: int | None = None,
               code: str | None = None, params: dict[str, Any] | None = None) -> None:
        """message: free text (e.g. upstream error); code/params: translatable status (see i18n status.*)."""
        now = utcnow()
        self.execute(
            "INSERT INTO source_status(source, ok, last_run, last_ok, message, count, code, params) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(source) DO UPDATE SET ok=excluded.ok, last_run=excluded.last_run, "
            "last_ok=COALESCE(excluded.last_ok, source_status.last_ok), message=excluded.message, "
            "count=COALESCE(excluded.count, source_status.count), code=excluded.code, params=excluded.params",
            (source, int(ok), now, now if ok else None, (message or "")[:500], count, code,
             json.dumps(params) if params else None),
        )

    def statuses(self) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM source_status ORDER BY source")
