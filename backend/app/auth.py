"""Optional password login (AUTH_MODE=password, the default) and request origin checks.

- Password: AUTH_PASSWORD, or a random password generated on first start. The generated password is written to
  /data/initial-password.txt (mode 0600) and printed once to the log. Only a scrypt hash is kept in /data/auth.json.
  To reset: set AUTH_PASSWORD, or delete auth.json and initial-password.txt and restart.
- Session: HMAC-SHA256 signed cookie (HttpOnly, SameSite=Strict, Secure on HTTPS) with expiry. The key lives in
  /data/session.key; changing the password invalidates all sessions.
- Brute force: per client 10 failures per 10 minutes, globally 100 per 10 minutes.
- AUTH_MODE=none: no login, e.g. when an authenticating reverse proxy (Pangolin, Authelia, ...) is in front.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from collections import deque
from pathlib import Path
from typing import Any

from .config import Settings

log = logging.getLogger("auth")

COOKIE = "ew_session"
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
WINDOW_S = 600
MAX_PER_CLIENT = 10
MAX_GLOBAL = 100


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _hash(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=64 * 1024 * 1024)


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


class Auth:
    def __init__(self, s: Settings) -> None:
        self.s = s
        self.mode = s.auth_mode
        self.generated = False
        self._fail: dict[str, deque[float]] = {}
        self._fail_all: deque[float] = deque()
        key_path = s.data_dir / "session.key"
        if key_path.exists() and len(key_path.read_bytes()) >= 32:
            self._key = key_path.read_bytes()[:64]
        else:
            self._key = secrets.token_bytes(32)
            _write_private(key_path, self._key)
        self._salt = b""
        self._hash = b""
        self._params = dict(SCRYPT)
        if self.mode == "password":
            self._init_password()
        self.tag = hashlib.sha256(self._hash + self._salt).hexdigest()[:16]

    def _init_password(self) -> None:
        store = self.s.data_dir / "auth.json"
        if self.s.auth_password:
            if len(self.s.auth_password) < 10:
                log.warning("AUTH_PASSWORD is shorter than 10 characters. Please use a long random password.")
            # Deterministic salt: the hash only lives in memory, and a stable hash keeps sessions valid across restarts
            self._salt = hashlib.sha256(b"emberwatch-env" + self.s.auth_password.encode()).digest()[:16]
            self._hash = _hash(self.s.auth_password, self._salt, **self._params)
            return
        if store.exists():
            try:
                d = json.loads(store.read_text(encoding="utf-8"))
                self._salt, self._hash = _unb64(d["salt"]), _unb64(d["hash"])
                self._params = {"n": int(d["n"]), "r": int(d["r"]), "p": int(d["p"])}
                return
            except (ValueError, KeyError, TypeError):
                log.error("%s is unreadable, generating a new password", store)
        password = secrets.token_urlsafe(18)
        self._salt = secrets.token_bytes(16)
        self._hash = _hash(password, self._salt, **self._params)
        _write_private(store, json.dumps({"salt": _b64(self._salt), "hash": _b64(self._hash), **self._params}).encode())
        _write_private(self.s.data_dir / "initial-password.txt", (password + "\n").encode())
        self.generated = True
        log.warning("=" * 72)
        log.warning("Emberwatch login password (generated, shown once): %s", password)
        log.warning("Also stored in %s. Set AUTH_PASSWORD to choose your own.", self.s.data_dir / "initial-password.txt")
        log.warning("=" * 72)

    @property
    def enabled(self) -> bool:
        return self.mode == "password"

    # --- password check with brute-force protection ----------------------------------------------------
    def locked_for(self, client: str) -> int:
        now = time.time()
        for q in [self._fail_all, *self._fail.values()]:
            while q and now - q[0] > WINDOW_S:
                q.popleft()
        q = self._fail.get(client)
        if q is not None and len(q) >= MAX_PER_CLIENT:
            return int(WINDOW_S - (now - q[0])) + 1
        if len(self._fail_all) >= MAX_GLOBAL:
            return int(WINDOW_S - (now - self._fail_all[0])) + 1
        return 0

    def verify(self, password: str, client: str) -> bool:
        """Constant-time check. Call locked_for() first. Runs scrypt (~50 ms), so call it in a worker thread."""
        ok = hmac.compare_digest(_hash(password[:1024], self._salt, **self._params), self._hash)
        if not ok:
            now = time.time()
            self._fail.setdefault(client, deque()).append(now)
            self._fail_all.append(now)
            if len(self._fail) > 10000:
                self._fail.clear()
        else:
            self._fail.pop(client, None)
        return ok

    # --- sessions --------------------------------------------------------------------------------------
    def issue(self) -> str:
        payload = json.dumps({"exp": int(time.time()) + self.s.session_hours * 3600, "t": self.tag,
                              "n": secrets.token_hex(8)}, separators=(",", ":")).encode()
        sig = hmac.new(self._key, payload, hashlib.sha256).digest()
        return f"{_b64(payload)}.{_b64(sig)}"

    def valid(self, token: str | None) -> bool:
        if not self.enabled:
            return True
        if not token or token.count(".") != 1 or len(token) > 512:
            return False
        p64, s64 = token.split(".")
        try:
            payload, sig = _unb64(p64), _unb64(s64)
        except (ValueError, TypeError):
            return False
        if not hmac.compare_digest(hmac.new(self._key, payload, hashlib.sha256).digest(), sig):
            return False
        try:
            d: dict[str, Any] = json.loads(payload)
        except ValueError:
            return False
        return d.get("t") == self.tag and isinstance(d.get("exp"), int) and d["exp"] > time.time()
