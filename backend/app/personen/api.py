"""HTTP interface of the people search (/api/personen). Role admin only (personal data, see auth.allowed); every
search is recorded in the audit log. OSINT_ENABLED=0 switches the whole area off."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Request
from fastapi import Path as FPath
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..auth import Auth
from ..config import Settings
from ..i18n import AppError
from .check import USERNAME_RE
from .runner import Searcher
from .sites import SiteList
from .store import MANUAL_KINDS, Store

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def _text(v: str | None, n: int) -> str | None:
    if v is None:
        return None
    s = re.sub(r"[\x00-\x1f\x7f]", " ", v).strip()
    return s[:n]


class CaseIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    note: str | None = Field(None, max_length=1000)


class CasePatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=80)
    note: str | None = Field(None, max_length=1000)


class SearchIn(BaseModel):
    kind: str = Field(..., pattern="^(username|email)$")
    query: str = Field(..., min_length=1, max_length=254)


class NodeIn(BaseModel):
    kind: str = Field(..., min_length=2, max_length=20)
    label: str = Field(..., min_length=1, max_length=160)
    note: str | None = Field(None, max_length=1000)


class NodePatch(BaseModel):
    label: str | None = Field(None, min_length=1, max_length=160)
    note: str | None = Field(None, max_length=1000)


class EdgeIn(BaseModel):
    src: int = Field(..., ge=1, le=2**62)
    dst: int = Field(..., ge=1, le=2**62)
    strength: str = Field("hint", pattern="^(confirmed|hint)$")
    label: str | None = Field(None, max_length=80)


class EdgePatch(BaseModel):
    strength: str | None = Field(None, pattern="^(confirmed|hint)$")
    label: str | None = Field(None, max_length=80)


class LayoutIn(BaseModel):
    positions: list[tuple[int, float, float]] = Field(default_factory=list, max_length=2000)


def make_router(S: Settings, store: Store, sites: SiteList, searcher: Searcher, auth: Auth,
                spawn: Callable[[Awaitable[Any]], Any]) -> APIRouter:
    r = APIRouter()

    def on() -> None:
        if not S.osint_enabled:
            raise AppError("err.osint.off", 404)

    def who(request: Request) -> dict[str, Any] | None:
        return getattr(request.state, "user", None)

    def ip(request: Request) -> str | None:
        return request.client.host if request.client else None

    def case_view(cid: int) -> dict[str, Any]:
        row = store.case_row(cid)
        searches = store.searches(cid)
        for s in searches:
            s["live"] = searcher.live.get(s["id"]) if s["status"] in ("queued", "running") else None
        return {"case": {**row, "expires": store._expires(row["updated_at"])}, "searches": searches,
                "hits": store.hits(cid=cid), "graph": store.graph(cid)}

    @r.get("/api/personen/status")
    def api_status() -> dict[str, Any]:
        return {"enabled": S.osint_enabled, "lists": sites.info(), "retention_days": S.osint_retention_days,
                "running": searcher.running(), "gravatar": bool(S.gravatar_api_key)}

    @r.post("/api/personen/lists")
    async def api_lists(request: Request) -> dict[str, Any]:
        on()
        if searcher.running():
            raise AppError("err.busy", 409)
        await sites.refresh(request.app.state.client, force=True)
        return sites.info()

    @r.get("/api/personen/cases")
    def api_cases() -> dict[str, Any]:
        on()
        return {"cases": store.cases(), "retention_days": S.osint_retention_days}

    @r.post("/api/personen/cases")
    def api_case_new(request: Request, body: CaseIn) -> dict[str, Any]:
        on()
        name = _text(body.name, 80)
        if not name:
            raise AppError("err.bad_request")
        return store.create_case(name, _text(body.note, 1000) or None, (who(request) or {}).get("name"))

    @r.get("/api/personen/cases/{cid}")
    def api_case(cid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        return case_view(cid)

    @r.patch("/api/personen/cases/{cid}")
    def api_case_patch(body: CasePatch, cid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        return store.update_case(cid, _text(body.name, 80) or None, _text(body.note, 1000))

    @r.delete("/api/personen/cases/{cid}")
    def api_case_delete(request: Request, cid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        if any(store.search(s)["case_id"] == cid for s in searcher.running()):
            raise AppError("err.busy", 409)
        row = store.delete_case(cid)
        auth.audit("osint_case_deleted", user=who(request), target=row["name"], ip=ip(request))
        return {"deleted": cid}

    # starting and stopping run on the event loop (tasks are created and cancelled there)
    @r.post("/api/personen/cases/{cid}/searches")
    async def api_search_new(request: Request, body: SearchIn, cid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        q = body.query.strip()
        if body.kind == "username" and not USERNAME_RE.match(q):
            raise AppError("err.osint.username")
        if body.kind == "email" and not EMAIL_RE.match(q):
            raise AppError("err.osint.email")
        if len([s for s in searcher.running()]) >= 5:
            raise AppError("err.busy", 409)
        row = store.case_row(cid)
        sid = store.add_search(cid, body.kind, q, (who(request) or {}).get("name"))
        auth.audit("osint_search", user=who(request), target=q, ip=ip(request), detail={"case": row["name"], "kind": body.kind})
        searcher.start(spawn, request.app.state.web, request.app.state.client, sid)
        return {"id": sid}

    @r.get("/api/personen/searches/{sid}")
    def api_search(sid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        s = store.search(sid)
        return {"search": s, "live": searcher.live.get(sid), "hits": store.hits(sid=sid)}

    @r.delete("/api/personen/searches/{sid}")
    async def api_search_delete(sid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        store.search(sid)
        if searcher.stop(sid):
            return {"stopped": sid}
        store.delete_search(sid)
        return {"deleted": sid}

    # --- graph ------------------------------------------------------------------------------------------------------
    @r.post("/api/personen/cases/{cid}/nodes")
    def api_node_new(body: NodeIn, cid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        if body.kind not in MANUAL_KINDS:
            raise AppError("err.bad_request")
        label = _text(body.label, 160)
        if not label:
            raise AppError("err.bad_request")
        return {"id": store.add_node(cid, body.kind, label, _text(body.note, 1000) or None)}

    @r.patch("/api/personen/nodes/{nid}")
    def api_node_patch(body: NodePatch, nid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        store.update_node(nid, _text(body.label, 160) or None, _text(body.note, 1000))
        return {"ok": True}

    @r.delete("/api/personen/nodes/{nid}")
    def api_node_delete(nid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        store.delete_node(nid)
        return {"deleted": nid}

    @r.post("/api/personen/cases/{cid}/edges")
    def api_edge_new(body: EdgeIn, cid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        return {"id": store.add_edge(cid, body.src, body.dst, body.strength, _text(body.label, 80))}

    @r.patch("/api/personen/edges/{eid}")
    def api_edge_patch(body: EdgePatch, eid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        store.update_edge(eid, body.strength, _text(body.label, 80))
        return {"ok": True}

    @r.delete("/api/personen/edges/{eid}")
    def api_edge_delete(eid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        store.delete_edge(eid)
        return {"deleted": eid}

    @r.put("/api/personen/cases/{cid}/layout")
    def api_layout(body: LayoutIn, cid: int = FPath(..., ge=1, le=2**62)) -> dict[str, Any]:
        on()
        pos = [(int(n), float(x), float(y)) for n, x, y in body.positions if abs(x) < 1e6 and abs(y) < 1e6]
        return {"saved": store.save_layout(cid, pos)}

    @r.get("/api/personen/cases/{cid}/export")
    def api_export(cid: int = FPath(..., ge=1, le=2**62)) -> Response:
        on()
        data = store.export(cid)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
        return Response(json.dumps(data, ensure_ascii=False, indent=1), media_type="application/json; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="emberwatch-personen-{cid}-{stamp}.json"'})

    return r
