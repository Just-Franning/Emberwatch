"""HTTP interface of the Telegram channels (/api/telegram). Reading is open to every signed-in account; adding and
removing channels, reading a channel now and translations (Gemini) need the role admin (auth.allowed)."""
from __future__ import annotations

import time
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Query, Request
from fastapi import Path as FPath
from pydantic import BaseModel, Field

from ..ai import Gemini
from ..auth import Auth
from ..config import Settings
from ..i18n import AppError
from .monitor import Telegram
from .parse import NAME_RE

REFRESH_GAP_S = 60


class ChannelIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    note: str | None = Field(None, max_length=200)


class TranslateIn(BaseModel):
    channel: str = Field(..., min_length=4, max_length=32)
    post_id: int = Field(..., ge=1, le=2**62)


def make_router(S: Settings, tg: Telegram, ai: Gemini, auth: Auth, kick: Callable[[str, Callable[[], Awaitable[Any]]], None],
                lang: Callable[[Request], str]) -> APIRouter:
    r = APIRouter()
    last: dict[str, float] = {}

    def on() -> None:
        if not S.telegram_enabled:
            raise AppError("err.tg.off", 404)

    def chan(name: str) -> str:
        n = name.strip().lower()
        if not NAME_RE.match(n):
            raise AppError("err.tg.name")
        return n

    @r.get("/api/telegram")
    def api_telegram(days: int = Query(7, ge=1, le=90), channel: str | None = Query(None, max_length=32),
                     country: str | None = Query(None, pattern="^[A-Z]{2}$"), q: str | None = Query(None, max_length=100),
                     limit: int = Query(40, ge=1, le=200), offset: int = Query(0, ge=0, le=20000)) -> dict[str, Any]:
        if not S.telegram_enabled:
            return {"enabled": False, "channels": [], "posts": [], "total": 0, "countries": {}}
        data = tg.listing(days, chan(channel) if channel else None, country, (q or "").strip() or None, limit, offset)
        return {"enabled": True, "channels": tg.channels(), "ai": ai.enabled, **data}

    @r.post("/api/telegram/channels")
    async def api_channel_add(request: Request, body: ChannelIn) -> dict[str, Any]:
        on()
        user = getattr(request.state, "user", None)
        row = tg.add(body.name, (body.note or "").strip()[:200] or None, (user or {}).get("name"))
        auth.audit("tg_channel_added", user=user, target=row["name"], ip=request.client.host if request.client else None)
        web = request.app.state.web
        kick(f"tg:{row['name']}", lambda: tg.fetch(web, row["name"]))
        return row

    @r.delete("/api/telegram/channels/{name}")
    def api_channel_remove(request: Request, name: str = FPath(..., min_length=4, max_length=32)) -> dict[str, Any]:
        on()
        n = chan(name)
        tg.remove(n)
        auth.audit("tg_channel_removed", user=getattr(request.state, "user", None), target=n,
                   ip=request.client.host if request.client else None)
        return {"deleted": n}

    @r.post("/api/telegram/channels/{name}/refresh")
    async def api_channel_refresh(request: Request, name: str = FPath(..., min_length=4, max_length=32)) -> dict[str, Any]:
        on()
        n = chan(name)
        if not any(c["name"] == n for c in tg.channels()):
            raise AppError("err.tg.unknown", 404)
        wait = REFRESH_GAP_S - (time.time() - last.get(n, 0.0))
        if wait > 0:
            raise AppError("err.refresh_wait", 429, seconds=int(wait) + 1)
        last[n] = time.time()
        web = request.app.state.web
        kick(f"tg:{n}", lambda: tg.fetch(web, n))
        return {"ok": True}

    @r.post("/api/telegram/translate")
    async def api_translate(request: Request, body: TranslateIn) -> dict[str, Any]:
        on()
        n = chan(body.channel)
        post = tg.post(n, body.post_id)
        language = lang(request)
        if post["translation"] and post["translated_to"] == language:
            return {"text": post["translation"], "lang": language, "cached": True}
        if not post["text"]:
            raise AppError("err.tg.empty")
        out = await ai.translate(request.app.state.client, post["text"], language)
        tg.set_translation(n, body.post_id, out["text"], language)
        return {"text": out["text"], "lang": language, "source_lang": out["source_lang"], "cached": False}

    return r
