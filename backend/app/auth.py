"""Accounts and sign-in.

AUTH_MODE=password (default): named accounts with the roles "admin" and "viewer" (read only) and a mandatory second
factor (TOTP, any authenticator app). AUTH_MODE=none: no sign-in, every request counts as administrator - only for
operation behind an authenticating reverse proxy (Pangolin, Authelia, ...).

Sign-in happens in steps. A correct password never sets a session cookie; it hands out a short-lived ticket for the
next step: "password" (a new password is due) -> "enroll" (set up the authenticator app) or "totp" (enter a code or
a recovery code) -> session. Tickets live in memory for 10 minutes and allow 5 code attempts.

Sessions: a random token in the cookie ew_session (HttpOnly, SameSite=Strict, Secure on HTTPS); the database keeps
only its SHA-256 hash. A session ends after SESSION_HOURS, at sign-out, when the password or the second factor
changes, and when an administrator disables, deletes or signs out the account.

First start of 4.x: the account AUTH_USER ("admin") is created with AUTH_PASSWORD, or with the password of 3.x
(auth.json), or with a generated password (written to /data/initial-password.txt and once to the log; it must be
changed at the first sign-in). After that AUTH_PASSWORD has no effect: passwords are changed in the interface or
with the admin command (python -m app.admincli, see README).

Brute force: 10 failed attempts per client in 10 minutes, 100 in total (passwords and codes); wrong codes also count
per account (10 in 10 minutes), because whoever enters codes already knows the password.

Roles are enforced centrally in main.guard() with allowed(): viewers may read (GET/HEAD) and manage their own account;
everything that changes data, runs tools, scans, people searches or Gemini analyses needs the role "admin".
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import totp
from .config import Settings
from .db import DB, utcnow
from .i18n import AppError

log = logging.getLogger("auth")

COOKIE = "ew_session"
ROLES = ("admin", "viewer")
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
MIN_PASSWORD = 12
MAX_PASSWORD = 256  # for new passwords; sign-in accepts up to 1024 characters (older passwords)
WINDOW_S = 600
MAX_PER_CLIENT = 10
MAX_PER_USER = 10
MAX_GLOBAL = 100
TICKET_TTL = 600
TICKET_TRIES = 5
MAX_TICKETS = 1000
CACHE_S = 30  # a revoked session or a changed role takes effect at once in this process (the cache is cleared)
TOUCH_S = 300
MAX_SESSIONS = 20
PENDING_TTL = 600
PROXY_USER: dict[str, Any] = {"id": 0, "name": "proxy", "role": "admin", "sid": 0}

ADMIN_ONLY = re.compile(r"^/api/(admin|personen)(/|$)")
VIEWER_WRITE = re.compile(r"^/api/(auth/logout|account(/.*)?)$")


def allowed(role: str, method: str, path: str) -> bool:
    """Role check for one request. Admins may do everything. Viewers read (GET/HEAD) and manage their own account;
    the user administration and the people search (personal data) stay closed to them completely."""
    if role == "admin":
        return True
    if role != "viewer" or ADMIN_ONLY.match(path):
        return False
    if method in ("GET", "HEAD", "OPTIONS"):
        return True
    return bool(VIEWER_WRITE.match(path))


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=64 * 1024 * 1024)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = _scrypt(password, salt, **SCRYPT)
    return f"scrypt${SCRYPT['n']}${SCRYPT['r']}${SCRYPT['p']}${_b64(salt)}${_b64(h)}"


def check_password(password: str, stored: str) -> bool:
    """Constant-time check. Runs scrypt (~50 ms): call it in a worker thread."""
    try:
        kind, n, r, p, salt, h = stored.split("$")
        if kind != "scrypt":
            return False
        n_, r_, p_ = int(n), int(r), int(p)
        if not (2 ** 10 <= n_ <= 2 ** 20 and 1 <= r_ <= 32 and 1 <= p_ <= 8):  # parameters from the database: bounded
            return False
        return hmac.compare_digest(_scrypt(password[:1024], _unb64(salt), n_, r_, p_), _unb64(h))
    except (ValueError, TypeError):
        return False


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Ticket:
    user_id: int
    stage: str  # "password" | "enroll" | "totp"
    created: float
    client: str
    tries: int = 0
    pending: str | None = None  # TOTP secret while the authenticator is being set up


class Auth:
    def __init__(self, s: Settings, db: DB) -> None:
        self.s = s
        self.db = db
        self.mode = s.auth_mode
        self.generated = False
        self._lock = threading.RLock()
        self._fail_client: dict[str, deque[float]] = {}
        self._fail_user: dict[str, deque[float]] = {}
        self._fail_all: deque[float] = deque()
        self._tickets: dict[str, Ticket] = {}
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._pending: dict[int, tuple[float, str]] = {}  # session id -> (time, new TOTP secret) while re-enrolling
        key = self._server_key()
        self._k_totp = hmac.new(key, b"emberwatch totp v1", hashlib.sha256).digest()
        self._k_rc = hmac.new(key, b"emberwatch recovery v1", hashlib.sha256).digest()
        self._dummy = ""
        if self.enabled:
            self._dummy = hash_password(secrets.token_urlsafe(16))  # unknown names cost the same time as known ones
            self._bootstrap()

    @property
    def enabled(self) -> bool:
        return self.mode == "password"

    # --- keys and first start ------------------------------------------------------------------------------------
    def _server_key(self) -> bytes:
        """data/session.key: source of the keys for TOTP secrets and recovery codes. Part of every backup:
        without it no second factor can be checked - the sign-in fails closed until an administrator resets the
        second factor (emberwatch-admin reset-2fa), the password alone never suffices."""
        path = self.s.data_dir / "session.key"
        try:
            data = path.read_bytes()
            if len(data) >= 32:
                return data[:64]
        except OSError:
            pass
        self.s.data_dir.mkdir(parents=True, exist_ok=True)
        data = secrets.token_bytes(32)
        _write_private(path, data)
        return data

    def _bootstrap(self) -> None:
        if self.db.query("SELECT 1 FROM users LIMIT 1"):
            if self.s.auth_password:
                log.info("AUTH_PASSWORD is only used to create the first account; it can be removed from the configuration.")
            return
        name = self.s.auth_user
        source = "env"
        must_change = 0
        if self.s.auth_password:
            if len(self.s.auth_password) < MIN_PASSWORD:
                log.warning("AUTH_PASSWORD is shorter than %d characters. Please change it after the first sign-in.", MIN_PASSWORD)
            pw_hash = hash_password(self.s.auth_password)
        else:
            pw_hash = self._legacy_hash()
            source = "3.x"
            if not pw_hash:
                password = secrets.token_urlsafe(18)
                pw_hash = hash_password(password)
                must_change = 1
                source = "generated"
                _write_private(self.s.data_dir / "initial-password.txt", (password + "\n").encode())
                self.generated = True
                log.warning("=" * 72)
                log.warning("Emberwatch: account %r created with the password (generated, shown once): %s", name, password)
                log.warning("Also stored in %s. It must be changed at the first sign-in.", self.s.data_dir / "initial-password.txt")
                log.warning("=" * 72)
        now = utcnow()
        self.db.insert("INSERT INTO users(name, role, pw_hash, pw_changed, must_change, created_at, created_by) "
                       "VALUES(?,?,?,?,?,?,?)", (name, "admin", pw_hash, now, must_change, now, "setup"))
        self.audit("user_created", target=name, detail={"role": "admin", "source": source})
        log.info("Account %r (administrator) created. The second factor is set up at the first sign-in.", name)

    def _legacy_hash(self) -> str:
        """Password hash of 3.x (auth.json: scrypt with the same parameters) - the old password keeps working."""
        try:
            d = json.loads((self.s.data_dir / "auth.json").read_text(encoding="utf-8"))
            return f"scrypt${int(d['n'])}${int(d['r'])}${int(d['p'])}${d['salt']}${d['hash']}"
        except (OSError, ValueError, KeyError, TypeError):
            return ""

    # --- audit log -----------------------------------------------------------------------------------------------
    def audit(self, action: str, *, user: dict[str, Any] | None = None, target: str | None = None,
              ip: str | None = None, detail: dict[str, Any] | None = None) -> None:
        self.db.insert("INSERT INTO audit(ts, user_id, user_name, action, target, ip, detail) VALUES(?,?,?,?,?,?,?)",
                       (utcnow(), (user or {}).get("id"), (user or {}).get("name"), action, (target or "")[:200] or None,
                        (ip or "")[:64] or None, json.dumps(detail, ensure_ascii=False)[:1000] if detail else None))

    def audit_list(self, limit: int = 200, before: int | None = None, user: str | None = None,
                   action: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT id, ts, user_name, action, target, ip, detail FROM audit WHERE 1=1"
        params: list[Any] = []
        if before:
            sql += " AND id < ?"
            params.append(before)
        if user:
            sql += " AND (user_name = ? OR target = ?)"
            params += [user, user]
        if action:
            sql += " AND action = ?"
            params.append(action)
        rows = self.db.query(sql + " ORDER BY id DESC LIMIT ?", (*params, limit))
        for r in rows:
            try:
                r["detail"] = json.loads(r["detail"]) if r["detail"] else None
            except ValueError:
                r["detail"] = None
        return rows

    # --- brute force ---------------------------------------------------------------------------------------------
    def _prune_fails(self, now: float) -> None:
        for book in (self._fail_client, self._fail_user):
            for k in list(book):
                q = book[k]
                while q and now - q[0] > WINDOW_S:
                    q.popleft()
                if not q:
                    del book[k]
        while self._fail_all and now - self._fail_all[0] > WINDOW_S:
            self._fail_all.popleft()

    def locked_for(self, client: str, name: str | None = None) -> int:
        """Seconds until the next attempt is allowed (0 = now)."""
        now = time.time()
        with self._lock:
            self._prune_fails(now)
            waits = []
            q = self._fail_client.get(client)
            if q is not None and len(q) >= MAX_PER_CLIENT:
                waits.append(WINDOW_S - (now - q[0]))
            q = self._fail_user.get(name) if name else None
            if q is not None and len(q) >= MAX_PER_USER:
                waits.append(WINDOW_S - (now - q[0]))
            if len(self._fail_all) >= MAX_GLOBAL:
                waits.append(WINDOW_S - (now - self._fail_all[0]))
            return int(max(waits)) + 1 if waits else 0

    def _failed(self, client: str, name: str | None = None) -> None:
        now = time.time()
        with self._lock:
            if len(self._fail_client) > 10000:
                self._fail_client.clear()
            self._fail_client.setdefault(client, deque()).append(now)
            if name:
                self._fail_user.setdefault(name, deque()).append(now)
            self._fail_all.append(now)

    def _succeeded(self, client: str) -> None:
        with self._lock:
            self._fail_client.pop(client, None)

    # --- users ---------------------------------------------------------------------------------------------------
    def _row(self, uid: int) -> dict[str, Any]:
        rows = self.db.query("SELECT * FROM users WHERE id=?", (uid,))
        if not rows:
            raise AppError("err.acct.not_found", 404)
        return rows[0]

    def _by_name(self, name: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM users WHERE name=?", (name,))
        return rows[0] if rows else None

    def _secret(self, row: dict[str, Any]) -> str | None:
        """Decrypted TOTP secret, None if none is set up or it cannot be decrypted (session.key changed)."""
        sealed = row.get("totp_secret")
        if not sealed:
            return None
        try:
            from cryptography.exceptions import InvalidTag
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            raw = _unb64(sealed.split(".", 1)[1])
            return AESGCM(self._k_totp).decrypt(raw[:12], raw[12:], f"user:{row['id']}".encode()).decode("ascii")
        except (InvalidTag, ValueError, IndexError, UnicodeDecodeError):
            log.warning("The second factor of %r cannot be decrypted (was session.key replaced?). Reset it with "
                        "emberwatch-admin reset-2fa %s.", row.get("name"), row.get("name"))
            return None

    def _seal(self, uid: int, secret: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = secrets.token_bytes(12)
        return "v1." + _b64(nonce + AESGCM(self._k_totp).encrypt(nonce, secret.encode("ascii"), f"user:{uid}".encode()))

    def _store_totp(self, uid: int, secret: str, step: int) -> list[str]:
        """Activates the authenticator and issues ten new recovery codes (shown once)."""
        codes = totp.new_recovery_codes()
        digests = [totp.recovery_digest(self._k_rc, totp.norm_recovery(c) or "") for c in codes]
        self.db.execute("UPDATE users SET totp_secret=?, totp_last=?, recovery=? WHERE id=?",
                        (self._seal(uid, secret), step, json.dumps(digests), uid))
        return codes

    @staticmethod
    def _public(row: dict[str, Any]) -> dict[str, Any]:
        try:
            left = len(json.loads(row.get("recovery") or "[]"))
        except ValueError:
            left = 0
        return {"id": row["id"], "name": row["name"], "role": row["role"], "disabled": bool(row["disabled"]),
                "must_change": bool(row["must_change"]), "totp": bool(row.get("totp_secret")), "recovery_left": left,
                "created_at": row["created_at"], "created_by": row.get("created_by"), "last_login": row.get("last_login"),
                "pw_changed": row.get("pw_changed")}

    def check_new_password(self, name: str, new: str, current_hash: str | None = None) -> None:
        if len(new) < MIN_PASSWORD:
            raise AppError("err.acct.pw_short", min=MIN_PASSWORD)
        if len(new) > MAX_PASSWORD:
            raise AppError("err.acct.pw_long", max=MAX_PASSWORD)
        if new.strip().lower() == name.lower() or len(set(new)) < 4:
            raise AppError("err.acct.pw_weak")
        if current_hash and check_password(new, current_hash):
            raise AppError("err.acct.pw_same")

    # --- sign-in -------------------------------------------------------------------------------------------------
    def _new_ticket(self, uid: int, stage: str, client: str) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            for k in [k for k, t in self._tickets.items() if now - t.created > TICKET_TTL]:
                del self._tickets[k]
            if len(self._tickets) >= MAX_TICKETS:  # many unfinished sign-ins: the oldest go first
                for k in sorted(self._tickets, key=lambda k: self._tickets[k].created)[: MAX_TICKETS // 2]:
                    del self._tickets[k]
            self._tickets[_sha(token)] = Ticket(uid, stage, now, client)
        return token

    def _ticket(self, token: str, stage: str) -> Ticket:
        with self._lock:
            t = self._tickets.get(_sha(token or ""))
            if t is None or time.time() - t.created > TICKET_TTL or t.stage != stage:
                raise AppError("err.login_expired", 401)
            return t

    def _drop(self, token: str) -> None:
        with self._lock:
            self._tickets.pop(_sha(token or ""), None)

    def _next_stage(self, row: dict[str, Any], client: str) -> str:
        if row["must_change"]:
            return "password"
        if not row.get("totp_secret"):
            return "enroll"  # new account, or the second factor was reset by an administrator
        if self._secret(row) is None:
            self._unreadable(row, client)
        return "totp"

    def _unreadable(self, row: dict[str, Any], client: str) -> None:
        """A second factor is set up but cannot be decrypted (session.key replaced or lost). Fail closed: setting up
        a new one with the password alone would turn a lost key file into a way around the second factor."""
        self.audit("totp_unreadable", user=row, ip=client)
        raise AppError("err.totp_unreadable", 409, name=row["name"])

    def begin(self, name: str, password: str, client: str) -> dict[str, Any]:
        """Password step (runs scrypt: call in a worker thread). Returns {"step", "ticket"}."""
        wait = self.locked_for(client)
        if wait:
            raise AppError("err.login_locked", 429, seconds=wait)
        name = (name or "").strip().lower()
        row = self._by_name(name) if NAME_RE.match(name) else None
        ok = check_password(password[:1024], row["pw_hash"] if row else self._dummy) and row is not None
        if not ok:
            self._failed(client)
            self.audit("login_fail", target=name if NAME_RE.match(name) else None, ip=client)
            raise AppError("err.login_failed", 401)
        if row["disabled"]:
            self.audit("login_disabled", user=row, ip=client)
            raise AppError("err.acct.disabled", 403)
        stage = self._next_stage(row, client)
        return {"step": stage, "ticket": self._new_ticket(row["id"], stage, client)}

    def first_password(self, ticket: str, new: str, client: str) -> dict[str, Any]:
        """A new password is due (generated or reset by an administrator). Runs scrypt: worker thread."""
        t = self._ticket(ticket, "password")
        row = self._row(t.user_id)
        self.check_new_password(row["name"], new, row["pw_hash"])
        self.db.execute("UPDATE users SET pw_hash=?, pw_changed=?, must_change=0 WHERE id=?", (hash_password(new), utcnow(), row["id"]))
        self.audit("password_changed", user=row, ip=client)
        row["must_change"] = 0
        stage = self._next_stage(row, client)
        with self._lock:
            t.stage = stage
        return {"step": stage, "ticket": ticket}

    def _enroll_payload(self, secret: str, name: str) -> dict[str, Any]:
        uri = totp.uri(secret, name)
        return {"secret": secret, "uri": uri, "qr": totp.qr_data_uri(uri)}

    def enroll_start(self, ticket: str) -> dict[str, Any]:
        t = self._ticket(ticket, "enroll")
        row = self._row(t.user_id)
        with self._lock:
            if not t.pending:
                t.pending = totp.new_secret()
            secret = t.pending
        return self._enroll_payload(secret, row["name"])

    def _code_failed(self, t: Ticket, ticket: str, row: dict[str, Any], client: str) -> None:
        self._failed(client, row["name"])
        self.audit("totp_fail", user=row, ip=client)
        with self._lock:
            t.tries += 1
            if t.tries >= TICKET_TRIES:
                self._tickets.pop(_sha(ticket), None)

    def _code_lock(self, row: dict[str, Any], client: str) -> None:
        wait = self.locked_for(client, row["name"])
        if wait:
            raise AppError("err.login_locked", 429, seconds=wait)

    def enroll_finish(self, ticket: str, code: str, client: str, ua: str) -> tuple[str, list[str]]:
        t = self._ticket(ticket, "enroll")
        row = self._row(t.user_id)
        self._code_lock(row, client)
        step = totp.verify(t.pending, code, 0) if t.pending else None
        if step is None:
            self._code_failed(t, ticket, row, client)
            raise AppError("err.totp_invalid", 401)
        codes = self._store_totp(row["id"], t.pending or "", step)
        self._drop(ticket)
        self._succeeded(client)
        self.audit("totp_enrolled", user=row, ip=client)
        return self.create_session(row, client, ua), codes  # create_session records the sign-in

    def finish(self, ticket: str, code: str, client: str, ua: str) -> tuple[str, dict[str, Any]]:
        """Second step: a code of the authenticator app or a recovery code."""
        t = self._ticket(ticket, "totp")
        row = self._row(t.user_id)
        self._code_lock(row, client)
        secret = self._secret(row)
        if secret is None:  # reset meanwhile, or the key file changed after the password step
            self._drop(ticket)
            if not row.get("totp_secret"):
                raise AppError("err.login_expired", 401)
            self._unreadable(row, client)
        code = (code or "").strip()
        used_recovery = False
        ok = False
        if totp.CODE_RE.match(code.replace(" ", "")):
            step = totp.verify(secret, code, int(row["totp_last"] or 0))
            # the condition makes a parallel second use of the same code fail (replay protection)
            ok = step is not None and self.db.execute("UPDATE users SET totp_last=? WHERE id=? AND totp_last < ?",
                                                      (step, row["id"], step)) == 1
        else:
            norm = totp.norm_recovery(code)
            if norm:
                digest = totp.recovery_digest(self._k_rc, norm)
                try:
                    stored = json.loads(row["recovery"] or "[]")
                except ValueError:
                    stored = []
                hit = [d for d in stored if hmac.compare_digest(d, digest)]
                if hit:
                    left = [d for d in stored if d != hit[0]]
                    ok = self.db.execute("UPDATE users SET recovery=? WHERE id=? AND recovery=?",
                                         (json.dumps(left), row["id"], row["recovery"])) == 1
                    used_recovery = ok
                    row["recovery"] = json.dumps(left)
        if not ok:
            self._code_failed(t, ticket, row, client)
            raise AppError("err.totp_invalid", 401)
        self._drop(ticket)
        self._succeeded(client)
        if used_recovery:
            self.audit("recovery_used", user=row, ip=client)
        return self.create_session(row, client, ua), {"recovery_left": len(json.loads(row["recovery"] or "[]")),
                                                     "recovery_used": used_recovery}

    # --- sessions ------------------------------------------------------------------------------------------------
    def create_session(self, row: dict[str, Any], ip: str, ua: str) -> str:
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        exp = now + timedelta(hours=self.s.session_hours)
        self.db.transaction([
            ("INSERT INTO sessions(token_hash, user_id, created_at, last_seen, expires_at, ip, ua) VALUES(?,?,?,?,?,?,?)",
             (_sha(token), row["id"], _iso(now), _iso(now), _iso(exp), ip[:64], (ua or "")[:200])),
            # at most MAX_SESSIONS per account: the oldest end
            ("DELETE FROM sessions WHERE user_id=? AND id NOT IN (SELECT id FROM sessions WHERE user_id=? ORDER BY id DESC LIMIT ?)",
             (row["id"], row["id"], MAX_SESSIONS)),
            ("UPDATE users SET last_login=? WHERE id=?", (_iso(now), row["id"])),
        ])
        self.audit("login_ok", user=row, ip=ip)
        return token

    def session_user(self, token: str | None) -> dict[str, Any] | None:
        """The signed-in account of a request: {"id", "name", "role", "sid"} or None."""
        if not self.enabled:
            return dict(PROXY_USER)
        if not token or len(token) > 200:
            return None
        h = _sha(token)
        now = time.time()
        nowiso = utcnow()
        with self._lock:
            hit = self._cache.get(h)
            if hit and now - hit[0] < CACHE_S and hit[1]["expires_at"] > nowiso:
                return hit[1]["user"]
        rows = self.db.query("SELECT s.id AS sid, s.expires_at, s.last_seen, u.id, u.name, u.role, u.disabled "
                             "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash=?", (h,))
        if not rows or rows[0]["disabled"] or rows[0]["expires_at"] <= nowiso or rows[0]["role"] not in ROLES:
            return None
        r = rows[0]
        if (datetime.now(timezone.utc) - datetime.fromisoformat(r["last_seen"].replace("Z", "+00:00"))).total_seconds() > TOUCH_S:
            self.db.execute("UPDATE sessions SET last_seen=? WHERE id=?", (nowiso, r["sid"]))
        user = {"id": r["id"], "name": r["name"], "role": r["role"], "sid": r["sid"]}
        with self._lock:
            if len(self._cache) > 5000:
                self._cache.clear()
            self._cache[h] = (now, {"user": user, "expires_at": r["expires_at"]})
        return user

    def _forget_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def logout(self, token: str | None, user: dict[str, Any] | None, ip: str) -> None:
        if token:
            self.db.execute("DELETE FROM sessions WHERE token_hash=?", (_sha(token),))
        self._forget_cache()
        if user and user.get("id"):
            self.audit("logout", user=user, ip=ip)

    def sessions_of(self, uid: int, current: int | None = None) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT id, created_at, last_seen, expires_at, ip, ua FROM sessions WHERE user_id=? AND expires_at > ? "
                             "ORDER BY last_seen DESC", (uid, utcnow()))
        for r in rows:
            r["current"] = r["id"] == current
        return rows

    def revoke(self, uid: int, sid: int | None = None, keep: int | None = None) -> int:
        """Ends one session (sid), or all sessions of the account except keep."""
        if sid is not None:
            n = self.db.execute("DELETE FROM sessions WHERE id=? AND user_id=?", (sid, uid))
        elif keep is not None:
            n = self.db.execute("DELETE FROM sessions WHERE user_id=? AND id != ?", (uid, keep))
        else:
            n = self.db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        self._forget_cache()
        return n

    # --- own account ---------------------------------------------------------------------------------------------
    def account(self, user: dict[str, Any]) -> dict[str, Any]:
        row = self._row(user["id"])
        return {**self._public(row), "sessions": self.sessions_of(row["id"], user.get("sid"))}

    def _confirm_password(self, row: dict[str, Any], password: str, client: str) -> None:
        wait = self.locked_for(client, row["name"])
        if wait:
            raise AppError("err.login_locked", 429, seconds=wait)
        if not check_password(password[:1024], row["pw_hash"]):
            self._failed(client, row["name"])
            raise AppError("err.acct.pw_wrong", 403)

    def change_password(self, user: dict[str, Any], current: str, new: str, ip: str) -> None:
        """Runs scrypt: worker thread. Ends all other sessions of the account."""
        row = self._row(user["id"])
        self._confirm_password(row, current, ip)
        self.check_new_password(row["name"], new, row["pw_hash"])
        self.db.execute("UPDATE users SET pw_hash=?, pw_changed=?, must_change=0 WHERE id=?", (hash_password(new), utcnow(), row["id"]))
        self.revoke(row["id"], keep=user.get("sid"))
        self.audit("password_changed", user=row, ip=ip)

    def totp_restart(self, user: dict[str, Any], password: str, ip: str) -> dict[str, Any]:
        """Set up a new authenticator (e.g. a new phone). Active only after totp_confirm()."""
        row = self._row(user["id"])
        self._confirm_password(row, password, ip)
        secret = totp.new_secret()
        with self._lock:
            now = time.time()
            for k in [k for k, (ts, _) in self._pending.items() if now - ts > PENDING_TTL]:
                del self._pending[k]
            self._pending[int(user.get("sid") or 0)] = (now, secret)
        return self._enroll_payload(secret, row["name"])

    def totp_confirm(self, user: dict[str, Any], code: str, ip: str) -> list[str]:
        row = self._row(user["id"])
        self._code_lock(row, ip)
        with self._lock:
            pend = self._pending.get(int(user.get("sid") or 0))
        if not pend or time.time() - pend[0] > PENDING_TTL:
            raise AppError("err.acct.enroll_expired", 409)
        step = totp.verify(pend[1], code, 0)
        if step is None:
            self._failed(ip, row["name"])
            self.audit("totp_fail", user=row, ip=ip)
            raise AppError("err.totp_invalid", 401)
        with self._lock:
            self._pending.pop(int(user.get("sid") or 0), None)
        codes = self._store_totp(row["id"], pend[1], step)
        self.revoke(row["id"], keep=user.get("sid"))
        self.audit("totp_enrolled", user=row, ip=ip)
        return codes

    def new_recovery(self, user: dict[str, Any], password: str, ip: str) -> list[str]:
        row = self._row(user["id"])
        self._confirm_password(row, password, ip)
        codes = totp.new_recovery_codes()
        digests = [totp.recovery_digest(self._k_rc, totp.norm_recovery(c) or "") for c in codes]
        self.db.execute("UPDATE users SET recovery=? WHERE id=?", (json.dumps(digests), row["id"]))
        self.audit("recovery_new", user=row, ip=ip)
        return codes

    # --- administration ------------------------------------------------------------------------------------------
    def list_users(self) -> list[dict[str, Any]]:
        counts = {r["user_id"]: r["n"] for r in self.db.query(
            "SELECT user_id, COUNT(*) AS n FROM sessions WHERE expires_at > ? GROUP BY user_id", (utcnow(),))}
        return [{**self._public(r), "sessions": counts.get(r["id"], 0)} for r in self.db.query("SELECT * FROM users ORDER BY name")]

    def _admins_left(self, without: int) -> int:
        return self.db.query("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0 AND id != ?", (without,))[0]["n"]

    @staticmethod
    def _not_self(uid: int, by: dict[str, Any]) -> None:
        if uid == by.get("id"):
            raise AppError("err.acct.self", 409)

    def create_user(self, name: str, role: str, by: dict[str, Any], ip: str) -> tuple[dict[str, Any], str]:
        name = (name or "").strip().lower()
        if not NAME_RE.match(name):
            raise AppError("err.acct.name")
        if role not in ROLES:
            raise AppError("err.acct.role")
        if self._by_name(name):
            raise AppError("err.acct.exists", 409)
        password = secrets.token_urlsafe(12)
        now = utcnow()
        uid = self.db.insert("INSERT INTO users(name, role, pw_hash, pw_changed, must_change, created_at, created_by) "
                             "VALUES(?,?,?,?,?,?,?)", (name, role, hash_password(password), now, 1, now, by.get("name")))
        self.audit("user_created", user=by, target=name, ip=ip, detail={"role": role})
        return self._public(self._row(uid)), password

    def update_user(self, uid: int, by: dict[str, Any], ip: str, role: str | None = None,
                    disabled: bool | None = None) -> dict[str, Any]:
        row = self._row(uid)
        self._not_self(uid, by)
        if role is not None and role not in ROLES:
            raise AppError("err.acct.role")
        demote = role is not None and role != "admin" and row["role"] == "admin"
        if (demote or (disabled and row["role"] == "admin")) and not self._admins_left(uid):
            raise AppError("err.acct.last_admin", 409)
        changes: dict[str, Any] = {}
        if role is not None and role != row["role"]:
            self.db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
            changes["role"] = role
        if disabled is not None and bool(disabled) != bool(row["disabled"]):
            self.db.execute("UPDATE users SET disabled=? WHERE id=?", (int(bool(disabled)), uid))
            changes["disabled"] = bool(disabled)
            if disabled:
                self.revoke(uid)
        self._forget_cache()
        if changes:
            self.audit("user_updated", user=by, target=row["name"], ip=ip, detail=changes)
        return self._public(self._row(uid))

    def reset_password(self, uid: int, by: dict[str, Any], ip: str) -> str:
        row = self._row(uid)
        self._not_self(uid, by)
        password = secrets.token_urlsafe(12)
        self.db.execute("UPDATE users SET pw_hash=?, pw_changed=?, must_change=1 WHERE id=?", (hash_password(password), utcnow(), uid))
        self.revoke(uid)
        self.audit("password_reset", user=by, target=row["name"], ip=ip)
        return password

    def reset_totp(self, uid: int, by: dict[str, Any], ip: str) -> None:
        row = self._row(uid)
        self._not_self(uid, by)
        self.db.execute("UPDATE users SET totp_secret=NULL, totp_last=0, recovery='[]' WHERE id=?", (uid,))
        self.revoke(uid)
        self.audit("totp_reset", user=by, target=row["name"], ip=ip)

    def end_sessions(self, uid: int, by: dict[str, Any], ip: str) -> int:
        row = self._row(uid)
        n = self.revoke(uid, keep=by.get("sid") if uid == by.get("id") else None)
        self.audit("sessions_revoked", user=by, target=row["name"], ip=ip, detail={"n": n})
        return n

    def delete_user(self, uid: int, by: dict[str, Any], ip: str) -> None:
        row = self._row(uid)
        self._not_self(uid, by)
        if row["role"] == "admin" and not self._admins_left(uid):
            raise AppError("err.acct.last_admin", 409)
        self.db.transaction([("DELETE FROM sessions WHERE user_id=?", (uid,)), ("DELETE FROM users WHERE id=?", (uid,))])
        self._forget_cache()
        self.audit("user_deleted", user=by, target=row["name"], ip=ip)

    # --- maintenance ---------------------------------------------------------------------------------------------
    def prune(self) -> None:
        self.db.execute("DELETE FROM sessions WHERE expires_at <= ?", (utcnow(),))
        cutoff = _iso(datetime.now(timezone.utc) - timedelta(days=self.s.audit_retention_days))
        self.db.execute("DELETE FROM audit WHERE ts < ?", (cutoff,))
        self._forget_cache()
