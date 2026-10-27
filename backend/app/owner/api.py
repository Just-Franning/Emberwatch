"""HTTP interface of "who owns this IP" (/api/owner). Reading stored results is open to every signed-in account;
a new lookup (POST) needs the role admin, it contacts the address and the company website (auth.allowed)."""
from __future__ import annotations

import logging
from typing import Any, AsyncIterator, Callable

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..auth import Auth
from ..i18n import AppError, t
from .lookup import Owner

log = logging.getLogger("owner")


class OwnerIn(BaseModel):
    ip: str = Field(..., min_length=2, max_length=60)
    active: bool = True
    refresh: bool = False


def make_router(owner: Owner, auth: Auth, stream: Callable[[Request, AsyncIterator[dict[str, Any]]], StreamingResponse],
                lang: Callable[[Request], str]) -> APIRouter:
    r = APIRouter()

    @r.get("/api/owner")
    def api_owner(ip: str = Query(..., min_length=2, max_length=60)) -> dict[str, Any]:
        target = owner.target(ip)
        return {"ip": target, "result": owner.cached(target)}

    @r.post("/api/owner")
    async def api_owner_lookup(request: Request, body: OwnerIn) -> StreamingResponse:
        target = owner.target(body.ip)
        hit = None if body.refresh else owner.cached(target, body.active)
        if hit is None and owner.sem.locked():
            raise AppError("err.busy", 409)
        user = getattr(request.state, "user", None)
        if hit is None:
            auth.audit("owner_lookup", user=user, target=target, ip=request.client.host if request.client else None,
                       detail={"active": body.active})
        client, web = request.app.state.client, request.app.state.web
        language = lang(request)

        async def events() -> AsyncIterator[dict[str, Any]]:
            if hit is not None:
                yield {"type": "result", "result": hit}
                return
            async with owner.sem:
                try:
                    async for ev in owner.lookup(client, web, target, body.active):
                        yield ev
                except AppError as exc:
                    yield {"type": "error", "key": exc.key, "text": exc.render(language)}
                except Exception as exc:  # a broken answer of a third party must not end the stream silently
                    log.exception("owner lookup %s", target)
                    yield {"type": "error", "key": "err.internal", "text": t(language, "err.internal", detail=exc.__class__.__name__)}

        return stream(request, events())

    return r
