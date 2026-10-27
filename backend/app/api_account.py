"""HTTP interface of the accounts: sign-in steps (/api/auth), own account (/api/account) and the user administration
with the audit log (/api/admin). Roles are checked centrally in main.guard() (auth.allowed); the handlers here take
the signed-in account from request.state.user."""
from __future__ import annotations

import asyncio
from typing import Any, Callable

from fastapi import APIRouter, Query, Request
from fastapi import Path as FPath
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .auth import COOKIE, Auth
from .config import Settings
from .i18n import AppError

FAIL_DELAY_S = 0.4  # a failed attempt answers a little later (on top of the lockout after 10 failures)
AUDIT_ACTIONS = ("login_ok", "login_fail", "login_disabled", "logout", "totp_fail", "totp_unreadable", "totp_enrolled", "totp_reset",
                 "recovery_used", "recovery_new", "password_changed", "password_reset", "user_created", "user_updated",
                 "user_deleted", "sessions_revoked", "session_ended", "osint_search", "osint_case_deleted",
                 "osint_case_expired", "owner_lookup", "tg_channel_added", "tg_channel_removed")


class LoginIn(BaseModel):
    user: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=1024)


class TicketIn(BaseModel):
    ticket: str = Field(..., min_length=20, max_length=100)


class CodeIn(TicketIn):
    code: str = Field(..., min_length=6, max_length=24)


class NewPasswordIn(TicketIn):
    password: str = Field(..., min_length=1, max_length=1024)


class ChangePasswordIn(BaseModel):
    current: str = Field(..., min_length=1, max_length=1024)
    new: str = Field(..., min_length=1, max_length=1024)


class ConfirmIn(BaseModel):
    password: str = Field(..., min_length=1, max_length=1024)


class TotpIn(BaseModel):
    code: str = Field(..., min_length=6, max_length=24)


class UserIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=32)
    role: str = Field(..., pattern="^(admin|viewer)$")


class UserPatch(BaseModel):
    role: str | None = Field(None, pattern="^(admin|viewer)$")
    disabled: bool | None = None


def make_router(S: Settings, auth: Auth, secure: Callable[[Request], bool]) -> APIRouter:
    r = APIRouter()

    def client(request: Request) -> str:
        return request.client.host if request.client else "?"

    def agent(request: Request) -> str:
        return request.headers.get("user-agent", "")[:200]

    def me(request: Request) -> dict[str, Any]:
        user = getattr(request.state, "user", None)
        if not user or not user.get("id"):
            raise AppError("err.acct.off", 404)  # AUTH_MODE=none: there are no accounts
        return user

    def need_accounts() -> None:
        if not auth.enabled:
            raise AppError("err.acct.off", 404)

    def signed_in(body: dict[str, Any], token: str, request: Request) -> JSONResponse:
        resp = JSONResponse(body)
        resp.set_cookie(COOKIE, token, max_age=S.session_hours * 3600, httponly=True, samesite="strict",
                        secure=secure(request), path="/")
        return resp

    async def slow_fail(coro: Any) -> Any:
        try:
            return await coro
        except AppError as exc:
            if exc.status in (401, 403):
                await asyncio.sleep(FAIL_DELAY_S)
            raise

    # --- sign-in ---------------------------------------------------------------------------------------------------
    @r.get("/api/auth/status")
    def api_auth_status(request: Request) -> dict[str, Any]:
        user = auth.session_user(request.cookies.get(COOKIE))
        if user is None:  # reachable without a session: no version (it would only help to pick known flaws)
            return {"mode": S.auth_mode, "authenticated": False, "user": None}
        return {"mode": S.auth_mode, "authenticated": True, "version": S.version,
                "user": {"name": user["name"], "role": user["role"]}}

    @r.post("/api/auth/login")
    async def api_login(request: Request, body: LoginIn) -> dict[str, Any]:
        if not auth.enabled:
            return {"step": "done"}
        return await slow_fail(asyncio.to_thread(auth.begin, body.user, body.password, client(request)))

    @r.post("/api/auth/password")
    async def api_first_password(request: Request, body: NewPasswordIn) -> dict[str, Any]:
        need_accounts()
        return await asyncio.to_thread(auth.first_password, body.ticket, body.password, client(request))

    @r.post("/api/auth/enroll")
    async def api_enroll(body: TicketIn) -> dict[str, Any]:
        need_accounts()
        return auth.enroll_start(body.ticket)

    @r.post("/api/auth/enroll/confirm")
    async def api_enroll_confirm(request: Request, body: CodeIn) -> JSONResponse:
        need_accounts()

        async def run() -> tuple[str, list[str]]:
            return auth.enroll_finish(body.ticket, body.code, client(request), agent(request))

        token, codes = await slow_fail(run())
        return signed_in({"step": "done", "recovery": codes}, token, request)

    @r.post("/api/auth/totp")
    async def api_totp(request: Request, body: CodeIn) -> JSONResponse:
        need_accounts()

        async def run() -> tuple[str, dict[str, Any]]:
            return auth.finish(body.ticket, body.code, client(request), agent(request))

        token, info = await slow_fail(run())
        return signed_in({"step": "done", **info}, token, request)

    @r.post("/api/auth/logout")
    def api_logout(request: Request) -> JSONResponse:
        auth.logout(request.cookies.get(COOKIE), getattr(request.state, "user", None), client(request))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict", secure=secure(request))
        return resp

    # --- own account -----------------------------------------------------------------------------------------------
    @r.get("/api/account")
    def api_account(request: Request) -> dict[str, Any]:
        return auth.account(me(request))

    @r.post("/api/account/password")
    async def api_account_password(request: Request, body: ChangePasswordIn) -> dict[str, Any]:
        await slow_fail(asyncio.to_thread(auth.change_password, me(request), body.current, body.new, client(request)))
        return {"ok": True}

    @r.post("/api/account/totp")
    async def api_account_totp(request: Request, body: ConfirmIn) -> dict[str, Any]:
        return await slow_fail(asyncio.to_thread(auth.totp_restart, me(request), body.password, client(request)))

    @r.post("/api/account/totp/confirm")
    async def api_account_totp_confirm(request: Request, body: TotpIn) -> dict[str, Any]:
        async def run() -> list[str]:
            return auth.totp_confirm(me(request), body.code, client(request))

        return {"recovery": await slow_fail(run())}

    @r.post("/api/account/recovery")
    async def api_account_recovery(request: Request, body: ConfirmIn) -> dict[str, Any]:
        codes = await slow_fail(asyncio.to_thread(auth.new_recovery, me(request), body.password, client(request)))
        return {"recovery": codes}

    @r.delete("/api/account/sessions/{sid}")
    def api_account_session_end(request: Request, sid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        user = me(request)
        if not auth.revoke(user["id"], sid=sid):
            raise AppError("err.not_found", 404)
        auth.audit("session_ended", user=user, ip=client(request))
        return {"ended": sid, "current": sid == user.get("sid")}

    # --- administration (role admin, see auth.allowed) ---------------------------------------------------------------
    @r.get("/api/admin/users")
    def api_users() -> dict[str, Any]:
        need_accounts()
        return {"users": auth.list_users()}

    @r.post("/api/admin/users")
    async def api_user_create(request: Request, body: UserIn) -> dict[str, Any]:
        need_accounts()
        user, password = await asyncio.to_thread(auth.create_user, body.name, body.role, me(request), client(request))
        return {"user": user, "password": password}

    @r.patch("/api/admin/users/{uid}")
    def api_user_patch(request: Request, body: UserPatch, uid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        need_accounts()
        return auth.update_user(uid, me(request), client(request), role=body.role, disabled=body.disabled)

    @r.post("/api/admin/users/{uid}/password")
    async def api_user_password(request: Request, uid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        need_accounts()
        return {"password": await asyncio.to_thread(auth.reset_password, uid, me(request), client(request))}

    @r.post("/api/admin/users/{uid}/totp")
    def api_user_totp(request: Request, uid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        need_accounts()
        auth.reset_totp(uid, me(request), client(request))
        return {"ok": True}

    @r.delete("/api/admin/users/{uid}/sessions")
    def api_user_sessions(request: Request, uid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        need_accounts()
        return {"ended": auth.end_sessions(uid, me(request), client(request))}

    @r.delete("/api/admin/users/{uid}")
    def api_user_delete(request: Request, uid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        need_accounts()
        auth.delete_user(uid, me(request), client(request))
        return {"deleted": uid}

    @r.get("/api/admin/audit")
    def api_audit(limit: int = Query(200, ge=1, le=1000), before: int | None = Query(None, ge=1, le=2**62),
                  user: str | None = Query(None, max_length=40),
                  action: str | None = Query(None, pattern="^[a-z_]{2,40}$")) -> dict[str, Any]:
        return {"entries": auth.audit_list(limit, before, (user or "").strip().lower() or None, action),
                "actions": list(AUDIT_ACTIONS)}

    return r
