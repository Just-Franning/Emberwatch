"""Tests for 4.0 accounts: first start and migration, sign-in steps with TOTP, recovery codes, replay and brute-force
protection, sessions, roles (admin/viewer) for every route, user administration, audit log and the admin command."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v3 as v3  # noqa: E402

BASE = "https://ew.example"
SAME = {"Origin": BASE}
PW = "correct horse battery staple"


class Clock:
    """Time of the TOTP check: each sign-in moves on by one 30-second step (codes are single use)."""

    def __init__(self) -> None:
        import time
        self.t = time.time()

    def __call__(self) -> float:
        return self.t

    def tick(self) -> None:
        self.t += 30


CLOCK: list[Clock] = []


@pytest.fixture()
def clock():
    c = Clock()
    CLOCK[:] = [c]
    yield c
    CLOCK.clear()


def load(tmp_path, monkeypatch, **env):
    """Loads the app afresh (new module objects); the TOTP check of the new modules uses the test clock."""
    m = v3.load_app(tmp_path, monkeypatch, **{"AUTH_MODE": "password", **env})
    from app import totp
    if CLOCK:
        monkeypatch.setattr(totp, "_now", CLOCK[0])
    return m, totp


def code(totp, secret, clock):
    return totp.code_at(secret, clock())


def enroll(tc, ticket, totp, clock):
    """Enrollment step: returns (secret, recovery codes) after a successful confirmation."""
    e = tc.post("/api/auth/enroll", json={"ticket": ticket}, headers=SAME)
    assert e.status_code == 200, e.text
    d = e.json()
    assert d["qr"].startswith("data:image/svg+xml") and d["uri"].startswith("otpauth://totp/Emberwatch:")
    ok = tc.post("/api/auth/enroll/confirm", json={"ticket": ticket, "code": code(totp, d["secret"], clock)}, headers=SAME)
    assert ok.status_code == 200, ok.text
    return d["secret"], ok.json()["recovery"]


def first_signin(tc, name, password, totp, clock, new_password=None):
    """Sign-in of a new account: optional new password, authenticator setup. Returns (secret, recovery codes)."""
    r = tc.post("/api/auth/login", json={"user": name, "password": password}, headers=SAME)
    assert r.status_code == 200, r.text
    d = r.json()
    if d["step"] == "password":
        p = tc.post("/api/auth/password", json={"ticket": d["ticket"], "password": new_password}, headers=SAME)
        assert p.status_code == 200, p.text
        d = p.json()
    assert d["step"] == "enroll"
    out = enroll(tc, d["ticket"], totp, clock)
    clock.tick()
    return out


def signin(tc, name, password, secret, totp, clock):
    r = tc.post("/api/auth/login", json={"user": name, "password": password}, headers=SAME)
    assert r.status_code == 200 and r.json()["step"] == "totp", r.text
    ok = tc.post("/api/auth/totp", json={"ticket": r.json()["ticket"], "code": code(totp, secret, clock)}, headers=SAME)
    assert ok.status_code == 200, ok.text
    clock.tick()
    return ok


# --- TOTP ---------------------------------------------------------------------------------------------------------
def test_totp_rfc6238_vectors():
    from app import totp
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32("12345678901234567890"), RFC 6238 appendix B (SHA-1)
    for ts, want in ((59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"), (1234567890, "89005924"),
                     (2000000000, "69279037"), (20000000000, "65353130")):
        assert totp.code_at(secret, ts, digits=8) == want
        assert totp.code_at(secret, ts) == want[-6:]
    # one step of clock drift in both directions; a used step is refused
    c = totp.code_at(secret, 1111111109)
    assert totp.verify(secret, c, 0, now=1111111109) == 1111111109 // 30
    assert totp.verify(secret, c, 0, now=1111111109 + 30) == 1111111109 // 30
    assert totp.verify(secret, c, 0, now=1111111109 - 30) == 1111111109 // 30
    assert totp.verify(secret, c, 0, now=1111111109 + 60) is None
    assert totp.verify(secret, c, 1111111109 // 30, now=1111111109) is None
    assert totp.verify(secret, "12345", 0) is None and totp.verify(secret, "abcdef", 0) is None
    codes = totp.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10 and all(len(x) == 11 and x[5] == "-" for x in codes)
    assert totp.norm_recovery(codes[0].upper().replace("-", " ")) == codes[0].replace("-", "")
    assert totp.norm_recovery("abcde-fghi0") is None  # 0, 1, i, l, o are not in the alphabet


# --- first start, migration -------------------------------------------------------------------------------------
def test_first_start_generated_password(tmp_path, monkeypatch, clock):
    m, totp = load(tmp_path, monkeypatch)
    pw_file = tmp_path / "initial-password.txt"
    assert pw_file.exists() and (pw_file.stat().st_mode & 0o777) == 0o600
    password = pw_file.read_text().strip()
    assert len(password) >= 20
    row = m.db.query("SELECT name, role, must_change, pw_hash FROM users")[0]
    assert row["name"] == "admin" and row["role"] == "admin" and row["must_change"] == 1 and password not in row["pw_hash"]
    with TestClient(m.app, base_url=BASE) as tc:
        assert tc.get("/api/overview").json()["key"] == "err.auth_required"
        assert tc.get("/", follow_redirects=False).headers["location"] == "/login"
        assert tc.get("/js/app.js").status_code == 401
        assert tc.get("/vendor/fonts/%2e%2e/%2e%2e/index.html").status_code == 401  # no bypass via public prefixes
        for path in ("/login", "/styles.css", "/js/login.js", "/js/texts_v4.js", "/js/i18n.js"):
            assert tc.get(path).status_code == 200, path
        st = tc.get("/api/auth/status").json()
        assert st == {"mode": "password", "authenticated": False, "user": None}  # no version without a session
        bad = tc.post("/api/auth/login", json={"user": "admin", "password": "wrong"}, headers=SAME)
        assert bad.status_code == 401 and bad.json()["key"] == "err.login_failed"
        assert tc.post("/api/auth/login", json={"user": "nobody", "password": password}, headers=SAME).json()["key"] == "err.login_failed"
        r = tc.post("/api/auth/login", json={"user": "Admin ", "password": password}, headers=SAME)
        assert r.status_code == 200 and r.json()["step"] == "password" and "set-cookie" not in r.headers
        ticket = r.json()["ticket"]
        # the password step refuses weak passwords and the old one; nothing else works with this ticket
        for pw, key in (("short", "err.acct.pw_short"), ("admin", "err.acct.pw_short"), ("aaaaaaaaaaaaaaaa", "err.acct.pw_weak"),
                        (password, "err.acct.pw_same")):
            x = tc.post("/api/auth/password", json={"ticket": ticket, "password": pw}, headers=SAME)
            assert x.status_code == 400 and x.json()["key"] == key, (pw, x.text)
        assert tc.post("/api/auth/enroll", json={"ticket": ticket}, headers=SAME).json()["key"] == "err.login_expired"
        assert tc.post("/api/auth/totp", json={"ticket": ticket, "code": "123456"}, headers=SAME).json()["key"] == "err.login_expired"
        p = tc.post("/api/auth/password", json={"ticket": ticket, "password": PW}, headers=SAME)
        assert p.json()["step"] == "enroll" and p.json()["ticket"] == ticket
        e = tc.post("/api/auth/enroll", json={"ticket": ticket}, headers=SAME).json()
        assert len(e["secret"]) == 32 and tc.post("/api/auth/enroll", json={"ticket": ticket}, headers=SAME).json()["secret"] == e["secret"]
        wrong = tc.post("/api/auth/enroll/confirm", json={"ticket": ticket, "code": "000000"}, headers=SAME)
        assert wrong.status_code == 401 and wrong.json()["key"] == "err.totp_invalid" and "set-cookie" not in wrong.headers
        ok = tc.post("/api/auth/enroll/confirm", json={"ticket": ticket, "code": code(totp, e["secret"], clock)}, headers=SAME)
        assert ok.status_code == 200 and len(ok.json()["recovery"]) == 10
        cookie = ok.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie and "secure" in cookie and "max-age=43200" in cookie
        assert tc.get("/api/overview").status_code == 200 and tc.get("/js/app.js").status_code == 200
        assert tc.get("/api/auth/status").json()["user"] == {"name": "admin", "role": "admin"}
        # the ticket is used up; the secret is stored encrypted, the recovery codes only as HMAC
        assert tc.post("/api/auth/enroll/confirm", json={"ticket": ticket, "code": "123456"}, headers=SAME).json()["key"] == "err.login_expired"
        row = m.db.query("SELECT totp_secret, recovery, must_change FROM users")[0]
        assert e["secret"] not in row["totp_secret"] and row["totp_secret"].startswith("v1.") and row["must_change"] == 0
        assert not any(c.replace("-", "") in row["recovery"] for c in ok.json()["recovery"])
        # cross-site requests are rejected even with a valid session
        x = tc.post("/api/watchlist", json={"value": "1.1.1.1"}, headers={"Origin": "https://evil.example"})
        assert x.status_code == 403 and x.json()["key"] == "err.csrf"
        assert tc.get("/api/overview", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert tc.post("/api/watchlist", json={"value": "1.1.1.1"}, headers={"Origin": "null"}).status_code == 403
        assert tc.post("/api/watchlist", json={"value": "1.1.1.1"}, headers=SAME).status_code == 200
        fwd = tc.post("/api/watchlist", json={"value": "1.0.0.1"}, headers={"Origin": "https://pub.example", "X-Forwarded-Host": "pub.example"})
        assert fwd.status_code == 200
        # a tampered token is no session
        token = tc.cookies.get("ew_session")
        tc.cookies.set("ew_session", token[:-2] + ("AA" if token[-2:] != "AA" else "BB"), domain="ew.example")
        assert tc.get("/api/overview").status_code == 401
        tc.cookies.set("ew_session", token, domain="ew.example")
        out = tc.post("/api/auth/logout", headers=SAME)
        assert out.status_code == 200 and "ew_session=" in out.headers["set-cookie"]
        tc.cookies.set("ew_session", token, domain="ew.example")
        assert tc.get("/api/overview").status_code == 401  # the session ended on the server, not only in the browser
    actions = [r["action"] for r in m.db.query("SELECT action FROM audit ORDER BY id")]
    assert actions[0] == "user_created" and "login_fail" in actions and "password_changed" in actions
    assert actions.index("totp_enrolled") < actions.index("login_ok") and actions[-1] == "logout"


def test_first_start_from_env_and_from_3x(tmp_path, monkeypatch, clock):
    m, totp = load(tmp_path, monkeypatch, AUTH_PASSWORD=PW, AUTH_USER="Frank")
    assert not (tmp_path / "initial-password.txt").exists()
    assert m.db.query("SELECT name, must_change FROM users") == [{"name": "frank", "must_change": 0}]
    with TestClient(m.app, base_url=BASE) as tc:
        secret, _ = first_signin(tc, "frank", PW, totp, clock)
    # a restart with another AUTH_PASSWORD changes nothing: passwords now live in the database
    m2, _ = load(tmp_path, monkeypatch, AUTH_PASSWORD="another long password")
    with TestClient(m2.app, base_url=BASE) as tc:
        assert tc.post("/api/auth/login", json={"user": "frank", "password": "another long password"}, headers=SAME).status_code == 401
        signin(tc, "frank", PW, secret, totp, clock)
    # 3.x: the generated password (auth.json, scrypt) is taken over for the first account
    d = tmp_path / "old"
    d.mkdir()
    salt = b"0123456789abcdef"
    h = hashlib.scrypt(b"the old 3.x password", salt=salt, n=2 ** 14, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
    import base64
    b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=").decode()  # noqa: E731
    (d / "auth.json").write_text(json.dumps({"salt": b(salt), "hash": b(h), "n": 2 ** 14, "r": 8, "p": 1}))
    m3, _ = load(d, monkeypatch, AUTH_USER="admin")  # (the environment of this test still has AUTH_USER=Frank)
    assert not (d / "initial-password.txt").exists()
    with TestClient(m3.app, base_url=BASE) as tc:
        r = tc.post("/api/auth/login", json={"user": "admin", "password": "the old 3.x password"}, headers=SAME)
        assert r.status_code == 200 and r.json()["step"] == "enroll"


def test_totp_signin_replay_recovery_and_lockout(tmp_path, monkeypatch, clock):
    m, totp = load(tmp_path, monkeypatch, AUTH_PASSWORD=PW)
    with TestClient(m.app, base_url=BASE) as tc:
        secret, recovery = first_signin(tc, "admin", PW, totp, clock)
        tc.post("/api/auth/logout", headers=SAME)
        # a code works once: the same code is refused in a second sign-in (replay)
        c = code(totp, secret, clock)
        r1 = tc.post("/api/auth/login", json={"user": "admin", "password": PW}, headers=SAME).json()
        assert tc.post("/api/auth/totp", json={"ticket": r1["ticket"], "code": c}, headers=SAME).status_code == 200
        r2 = tc.post("/api/auth/login", json={"user": "admin", "password": PW}, headers=SAME).json()
        rep = tc.post("/api/auth/totp", json={"ticket": r2["ticket"], "code": c}, headers=SAME)
        assert rep.status_code == 401 and rep.json()["key"] == "err.totp_invalid"
        # recovery codes: each once, in any spelling
        ok = tc.post("/api/auth/totp", json={"ticket": r2["ticket"], "code": recovery[0].upper().replace("-", " ")}, headers=SAME)
        assert ok.status_code == 200 and ok.json() == {"step": "done", "recovery_left": 9, "recovery_used": True}
        r3 = tc.post("/api/auth/login", json={"user": "admin", "password": PW}, headers=SAME).json()
        assert tc.post("/api/auth/totp", json={"ticket": r3["ticket"], "code": recovery[0]}, headers=SAME).status_code == 401
        # five wrong codes end the ticket
        for _ in range(4):
            assert tc.post("/api/auth/totp", json={"ticket": r3["ticket"], "code": "000000"}, headers=SAME).status_code == 401
        assert tc.post("/api/auth/totp", json={"ticket": r3["ticket"], "code": code(totp, secret, clock)},
                       headers=SAME).json()["key"] == "err.login_expired"
    assert any(r["action"] == "recovery_used" for r in m.db.query("SELECT action FROM audit"))
    # wrong codes also count per account: 10 in 10 minutes lock the second step, whatever the ticket
    m2, totp = load(tmp_path / "b", monkeypatch, AUTH_PASSWORD=PW)
    with TestClient(m2.app, base_url=BASE) as tc:
        secret, _ = first_signin(tc, "admin", PW, totp, clock)
        for _ in range(2):
            t = tc.post("/api/auth/login", json={"user": "admin", "password": PW}, headers=SAME).json()["ticket"]
            for _ in range(5):
                tc.post("/api/auth/totp", json={"ticket": t, "code": "000000"}, headers=SAME)
        m2.auth._fail_client.clear()  # another client: only the account lock is left
        t = tc.post("/api/auth/login", json={"user": "admin", "password": PW}, headers=SAME).json()["ticket"]
        locked = tc.post("/api/auth/totp", json={"ticket": t, "code": code(totp, secret, clock)}, headers=SAME)
        assert locked.status_code == 429 and locked.json()["key"] == "err.login_locked"
    # wrong passwords: 10 per client in 10 minutes
    m3, _ = load(tmp_path / "c", monkeypatch, AUTH_PASSWORD=PW)
    with TestClient(m3.app, base_url=BASE) as tc:
        for _ in range(10):
            assert tc.post("/api/auth/login", json={"user": "admin", "password": "nope"}, headers=SAME).status_code == 401
        locked = tc.post("/api/auth/login", json={"user": "admin", "password": PW}, headers=SAME)
        assert locked.status_code == 429 and locked.json()["key"] == "err.login_locked"


def test_secret_unreadable_after_key_change(tmp_path, monkeypatch, capsys, clock):
    m, totp = load(tmp_path, monkeypatch, AUTH_PASSWORD=PW)
    with TestClient(m.app, base_url=BASE) as tc:
        secret, _ = first_signin(tc, "admin", PW, totp, clock)
        # the key file changes between the password step and the code: no session, no fallback
        t = tc.post("/api/auth/login", json={"user": "admin", "password": PW}, headers=SAME).json()["ticket"]
        m.auth._k_totp = b"y" * 32
        r = tc.post("/api/auth/totp", json={"ticket": t, "code": code(totp, secret, clock)}, headers=SAME)
        assert r.status_code == 409 and r.json()["key"] == "err.totp_unreadable" and "set-cookie" not in r.headers
        assert tc.post("/api/auth/enroll", json={"ticket": t}, headers=SAME).json()["key"] == "err.login_expired"
    (tmp_path / "session.key").write_bytes(b"x" * 32)  # restored without its key: the old secret cannot be decrypted
    m2, totp = load(tmp_path, monkeypatch)
    with TestClient(m2.app, base_url=BASE) as tc:
        # fail closed: the password alone never sets up a new second factor
        r = tc.post("/api/auth/login", json={"user": "admin", "password": PW}, headers=SAME)
        assert r.status_code == 409 and r.json()["key"] == "err.totp_unreadable" and "ticket" not in r.json()
        assert "reset-2fa admin" in r.json()["detail"]
        assert m2.db.query("SELECT COUNT(*) AS n FROM audit WHERE action='totp_unreadable'")[0]["n"] == 2
        # the administrator resets it on the command line; then it is set up again at the sign-in
        from app import admincli
        assert admincli.main(["reset-2fa", "admin"]) == 0
        capsys.readouterr()
        r = tc.post("/api/auth/login", json={"user": "admin", "password": PW}, headers=SAME)
        assert r.status_code == 200 and r.json()["step"] == "enroll"
        enroll(tc, r.json()["ticket"], totp, clock)


# --- roles -------------------------------------------------------------------------------------------------------
def test_viewer_role_and_user_administration(tmp_path, monkeypatch, clock):
    m, totp = load(tmp_path, monkeypatch, AUTH_PASSWORD=PW)
    with TestClient(m.app, base_url=BASE) as admin, TestClient(m.app, base_url=BASE) as viewer:
        first_signin(admin, "admin", PW, totp, clock)
        bad = admin.post("/api/admin/users", json={"name": "Not Valid!", "role": "viewer"}, headers=SAME)
        assert bad.status_code in (400, 422)
        new = admin.post("/api/admin/users", json={"name": "Leser", "role": "viewer"}, headers=SAME)
        assert new.status_code == 200, new.text
        u, temp = new.json()["user"], new.json()["password"]
        assert u["name"] == "leser" and u["role"] == "viewer" and u["must_change"] and not u["totp"] and len(temp) >= 16
        assert admin.post("/api/admin/users", json={"name": "leser", "role": "viewer"}, headers=SAME).json()["key"] == "err.acct.exists"
        vsecret, _ = first_signin(viewer, "leser", temp, totp, clock, new_password="a long viewer password")
        # reading works, changing does not
        for path in ("/api/overview", "/api/status", "/api/watchlist", "/api/welt/blocking", "/api/account"):
            assert viewer.get(path).status_code in (200, 404), path
        for method, path, body in (("post", "/api/watchlist", {"value": "1.1.1.1"}), ("post", "/api/ai/analyze", {"scope": "global"}),
                                   ("post", "/api/tb/run", {"tool": "dns", "target": "example.com"}), ("delete", "/api/products/1", None),
                                   ("post", "/api/myip/visit", None), ("post", "/api/admin/users", {"name": "x1", "role": "admin"})):
            r = viewer.request(method.upper(), path, json=body, headers=SAME)
            assert r.status_code == 403 and r.json()["key"] == "err.role", (path, r.text)
        for path in ("/api/admin/users", "/api/admin/audit", "/api/personen/cases"):
            assert viewer.get(path).json()["key"] == "err.role", path
        assert viewer.get("/api/auth/status").json()["user"] == {"name": "leser", "role": "viewer"}
        # own account: password, sessions
        acc = viewer.get("/api/account").json()
        assert acc["role"] == "viewer" and acc["totp"] and acc["recovery_left"] == 10 and len(acc["sessions"]) == 1 and acc["sessions"][0]["current"]
        wrong = viewer.post("/api/account/password", json={"current": "nope", "new": "something new and long"}, headers=SAME)
        assert wrong.status_code == 403 and wrong.json()["key"] == "err.acct.pw_wrong"
        assert viewer.post("/api/account/password", json={"current": "a long viewer password", "new": "the next viewer password"},
                           headers=SAME).status_code == 200
        codes = viewer.post("/api/account/recovery", json={"password": "the next viewer password"}, headers=SAME)
        assert codes.status_code == 200 and len(codes.json()["recovery"]) == 10
        # a new authenticator: active only after the confirmation
        st = viewer.post("/api/account/totp", json={"password": "the next viewer password"}, headers=SAME).json()
        assert viewer.post("/api/account/totp/confirm", json={"code": "000000"}, headers=SAME).status_code == 401
        cf = viewer.post("/api/account/totp/confirm", json={"code": code(totp, st["secret"], clock)}, headers=SAME)
        assert cf.status_code == 200 and len(cf.json()["recovery"]) == 10, cf.text
        clock.tick()
        # administration: list, role change, self-protection, last admin
        users = {x["name"]: x for x in admin.get("/api/admin/users").json()["users"]}
        assert users["leser"]["sessions"] == 1 and users["leser"]["totp"]
        aid, vid = users["admin"]["id"], users["leser"]["id"]
        for method, path, body in (("patch", f"/api/admin/users/{aid}", {"role": "viewer"}), ("delete", f"/api/admin/users/{aid}", None),
                                   ("post", f"/api/admin/users/{aid}/password", None), ("patch", f"/api/admin/users/{aid}", {"disabled": True})):
            r = admin.request(method.upper(), path, json=body, headers=SAME)
            assert r.status_code == 409 and r.json()["key"] == "err.acct.self", path
        up = admin.patch(f"/api/admin/users/{vid}", json={"role": "admin"}, headers=SAME)
        assert up.json()["role"] == "admin"
        assert viewer.post("/api/watchlist", json={"value": "9.9.9.9"}, headers=SAME).status_code == 200  # the new role counts at once
        admin.patch(f"/api/admin/users/{vid}", json={"role": "viewer"}, headers=SAME)
        # disabling ends the sessions; the account cannot sign in
        assert admin.patch(f"/api/admin/users/{vid}", json={"disabled": True}, headers=SAME).json()["disabled"]
        assert viewer.get("/api/overview").status_code == 401
        d = viewer.post("/api/auth/login", json={"user": "leser", "password": "the next viewer password"}, headers=SAME)
        assert d.status_code == 403 and d.json()["key"] == "err.acct.disabled"
        admin.patch(f"/api/admin/users/{vid}", json={"disabled": False}, headers=SAME)
        # password reset: one-time password, must be changed; 2FA reset: set up again
        temp2 = admin.post(f"/api/admin/users/{vid}/password", headers=SAME).json()["password"]
        assert admin.post(f"/api/admin/users/{vid}/totp", headers=SAME).json() == {"ok": True}
        first_signin(viewer, "leser", temp2, totp, clock, new_password="yet another viewer password")
        assert admin.delete(f"/api/admin/users/{vid}/sessions", headers=SAME).json()["ended"] == 1
        assert viewer.get("/api/overview").status_code == 401
        assert admin.delete(f"/api/admin/users/{vid}", headers=SAME).json() == {"deleted": vid}
        audit = admin.get("/api/admin/audit?limit=500").json()["entries"]
        acts = {e["action"] for e in audit}
        assert {"user_created", "user_updated", "password_reset", "totp_reset", "sessions_revoked", "user_deleted",
                "recovery_new", "totp_enrolled", "password_changed", "login_disabled"} <= acts
        assert all(e["action"] == "user_updated" for e in admin.get("/api/admin/audit?action=user_updated").json()["entries"])
    # the last administrator stays
    a = m.db.query("SELECT id FROM users WHERE name='admin'")[0]["id"]
    from app.i18n import AppError
    with pytest.raises(AppError) as exc:
        m.auth.update_user(a, {"id": 999, "name": "x"}, "t", role="viewer")
    assert exc.value.key == "err.acct.last_admin"
    with pytest.raises(AppError):
        m.auth.delete_user(a, {"id": 999, "name": "x"}, "t")


def api_routes(routes):
    """All endpoints, including those of routers added with include_router (FastAPI keeps them in a wrapper)."""
    from fastapi.routing import APIRoute
    for r in routes:
        if isinstance(r, APIRoute):
            yield r
        elif hasattr(r, "original_router"):
            yield from api_routes(r.original_router.routes)


def test_every_route_has_a_role(tmp_path, monkeypatch):
    """Viewers may change nothing except their own account; administration and people search stay closed.
    New routes are covered automatically: whatever writes is admin only unless it is listed here."""
    m, _ = load(tmp_path, monkeypatch)
    from app.auth import allowed
    viewer_writes, viewer_reads_blocked, routes = set(), set(), 0
    for r in api_routes(m.app.routes):
        for method in r.methods:
            routes += 1
            if method in ("GET", "HEAD"):
                if not allowed("viewer", method, r.path):
                    viewer_reads_blocked.add(r.path)
            elif allowed("viewer", method, r.path):
                viewer_writes.add((method, r.path))
            assert allowed("admin", method, r.path)
    assert routes > 80
    assert viewer_writes == {("POST", "/api/auth/logout"), ("POST", "/api/account/password"), ("POST", "/api/account/totp"),
                             ("POST", "/api/account/totp/confirm"), ("POST", "/api/account/recovery"),
                             ("DELETE", "/api/account/sessions/{sid}")}
    assert viewer_reads_blocked and all(p.startswith(("/api/admin/", "/api/personen")) for p in viewer_reads_blocked)
    assert not allowed("viewer", "GET", "/api/personen") and allowed("viewer", "GET", "/api/adminx")  # exact prefixes
    assert not allowed("guest", "GET", "/api/overview")


def test_sessions_expire_and_none_mode(tmp_path, monkeypatch, clock):
    m, totp = load(tmp_path, monkeypatch, AUTH_PASSWORD=PW, SESSION_HOURS="1")
    with TestClient(m.app, base_url=BASE) as tc:
        first_signin(tc, "admin", PW, totp, clock)
        assert tc.get("/api/overview").status_code == 200
        m.db.execute("UPDATE sessions SET expires_at='2000-01-01T00:00:00Z'")
        m.auth._forget_cache()
        assert tc.get("/api/overview").status_code == 401
        m.auth.prune()
        assert not m.db.query("SELECT 1 FROM sessions")
    m2 = v3.load_app(tmp_path / "n", monkeypatch, AUTH_MODE="none")
    with TestClient(m2.app, base_url=BASE) as tc:
        assert tc.get("/api/overview").status_code == 200
        st = tc.get("/api/auth/status").json()
        assert st["authenticated"] and st["user"] == {"name": "proxy", "role": "admin"}
        assert tc.get("/api/account").json()["key"] == "err.acct.off"
        assert tc.get("/api/admin/users").json()["key"] == "err.acct.off"
        assert tc.post("/api/auth/login", json={"user": "x", "password": "y"}, headers=SAME).json() == {"step": "done"}
        assert tc.post("/api/watchlist", json={"value": "1.1.1.1"}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert not m2.db.query("SELECT 1 FROM users")


def test_admin_command(tmp_path, monkeypatch, capsys, clock):
    m, totp = load(tmp_path, monkeypatch, AUTH_PASSWORD=PW)
    with TestClient(m.app, base_url=BASE) as tc:
        first_signin(tc, "admin", PW, totp, clock)
    from app import admincli
    assert admincli.main(["users"]) == 0
    assert "admin" in capsys.readouterr().out
    assert admincli.main(["reset-2fa", "admin"]) == 0
    assert admincli.main(["create-admin", "notfall"]) == 0
    temp = capsys.readouterr().out.strip().split(": ")[-1]
    assert admincli.main(["disable", "admin"]) == 0
    assert admincli.main(["disable", "notfall"]) == 1  # the last active administrator stays
    assert "last active" in capsys.readouterr().err
    assert admincli.main(["reset-password", "nobody"]) == 1
    m2, totp = load(tmp_path, monkeypatch)
    with TestClient(m2.app, base_url=BASE) as tc:
        first_signin(tc, "notfall", temp, totp, clock, new_password="emergency access password")
        assert tc.get("/api/overview").status_code == 200
    assert {r["user_name"] for r in m2.db.query("SELECT user_name FROM audit WHERE action='user_created'")} >= {"cli"}
