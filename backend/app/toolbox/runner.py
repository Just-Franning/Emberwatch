"""Runs tools and recipes, streams progress as NDJSON events and stores every result in the run history.

Events: {"type": "start"|"row"|"info"|"progress", ...} while a tool runs, {"type": "result", "result": {...}} at the end,
{"type": "error", "text": ...} on failure. Recipes add {"type": "step", "tool", "status"} and {"type": "step_result"}.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Awaitable, Callable

from .. import i18n
from ..db import DB, utcnow
from ..i18n import AppError
from ..tools import is_public, parse_ports
from . import tools_harden, tools_ident, tools_mail, tools_net, tools_threat
from .common import Ctx
from .detect import detect, internal_name, norm_host
from .registry import BY_ID, RECIPES, ToolSpec, available, coerce_params
from .result import SEV_ORDER, max_sev

log = logging.getLogger("toolbox")
_run_sem = asyncio.Semaphore(4)
MAX_PAYLOAD = 512 * 1024
HISTORY_DAYS = 90
HISTORY_MAX = 3000

Gen = AsyncIterator[dict[str, Any]]
HOST_TOOLS = {"ping", "traceroute", "pathq", "ports", "tls", "http", "ssh", "dns"}
# Third-party tools that resolve or handle private targets themselves (ipinfo: local data only, Globalping: resolves
# first, dns: only with a public resolver) or that never send the input to a server (CyberChef: URL fragment in the browser).
THIRD_PARTY_SELF = {"ipinfo", "globalping", "cyberchef", "dns"}  # dns: depends on the chosen resolver


def third_party_block(spec: ToolSpec, value: str, kind: str) -> str | None:
    """The reason (error text key) why a target must not go to the tool's third party, or None. Private addresses,
    private networks and internal names stay on the server."""
    if not spec.third_party or spec.id in THIRD_PARTY_SELF:
        return None
    if kind == "email":
        value, kind = value.rsplit("@", 1)[-1], "domain"
    try:
        if kind == "ip" and not is_public(ipaddress.ip_address(value)):
            return "err.tb.third_private"
        if kind == "cidr":
            net = ipaddress.ip_network(value, strict=False)
            if not is_public(net.network_address) or not is_public(net.broadcast_address):
                return "err.tb.third_private"
    except ValueError:
        return "err.tb.third_private"
    if kind == "domain" and internal_name(value):
        return "err.tb.third_private"
    return None


def _guard(spec: ToolSpec, value: str, kind: str) -> str:
    key = third_party_block(spec, value, kind)
    if key:
        raise AppError(key, addr=value, party=spec.third_party)
    return value


def _single(fn: Callable[..., Awaitable[dict[str, Any]]], with_kind: bool) -> Callable[..., Gen]:
    async def gen(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> Gen:
        res = await (fn(ctx, spec, target, params, kind) if with_kind else fn(ctx, spec, target, params))
        yield {"type": "result", "result": res}
    return gen


def _stream(fn: Callable[..., Gen]) -> Callable[..., Gen]:
    async def gen(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any], kind: str) -> Gen:
        async for ev in fn(ctx, spec, target, params):
            yield ev
    return gen


HANDLERS: dict[str, Callable[..., Gen]] = {
    "ping": _stream(tools_net.ping),
    "traceroute": _stream(tools_net.traceroute),
    "pathq": _stream(tools_net.pathq),
    "globalping": _stream(tools_net.globalping),
    "ipinfo": _single(tools_ident.ipinfo, False),
    "rdap": _single(tools_ident.rdap, False),
    "bgp": _single(tools_ident.bgp, True),
    "pdns": _single(tools_ident.pdns, True),
    "ct": _single(tools_ident.ct, False),
    "ioc": _single(tools_threat.ioc, True),
    "greynoise": _single(tools_threat.greynoise, False),
    "hash": _single(tools_threat.hash_lookup, False),
    "lookalike": _single(tools_threat.lookalike, False),
    "ports": _single(tools_harden.ports, True),
    "tls": _single(tools_harden.tls, True),
    "http": _single(tools_harden.http, True),
    "ssh": _single(tools_harden.ssh, True),
    "dns": _single(tools_harden.dnsdeep, True),
    "mailsec": _single(tools_harden.mailsec, True),
    "mailhdr": _single(tools_mail.mailhdr, False),
}


# --- preparation ---------------------------------------------------------------------------------------------------
def prepare(spec: ToolSpec, raw: str, params: dict[str, Any] | None, consent: bool) -> tuple[str, str, dict[str, Any]]:
    """Validates input and parameters for a tool. Returns (target, kind, params)."""
    if spec.client_only:
        raise AppError("err.tb.client_only")
    try:
        p = coerce_params(spec, params)
    except ValueError as exc:
        raise AppError("err.tb.param", name=str(exc)) from exc
    if spec.consent and p.get(spec.consent) and not consent:
        raise AppError("err.tb.consent")
    if spec.id == "ports":
        parse_ports(p.get("ports") or "")  # invalid lists fail before the stream starts (400 instead of an error event)
    if spec.id == "mailhdr":
        text = p.get("text") or raw or ""
        if not text.strip():
            raise AppError("err.tb.mail_empty")
        p["text"] = text
        return "", "mailhdr", p
    det = detect(raw)
    t = det["type"]
    if t in spec.inputs:
        return _guard(spec, det["value"], t), t, p
    if t == "url" and ("domain" in spec.inputs or "ip" in spec.inputs) and det.get("host"):
        host = det["host"]
        try:
            ipaddress.ip_address(host)
            kind = "ip"
        except ValueError:
            kind = "domain"
        if kind in spec.inputs:
            return _guard(spec, host, kind), kind, p
    if t == "email" and "domain" in spec.inputs:
        return _guard(spec, det["domain"], "domain"), "domain", p
    if t == "text" and spec.id in HOST_TOOLS:
        host = norm_host(raw.strip())
        if host:  # single-label names (e.g. "nas") for tools that connect to a host
            return host, "domain", p
    raise AppError("err.tb.input", tool=spec.id, type=i18n.Key(f"tb.in.{t}"))


def check_available(spec: ToolSpec, ctx: Ctx) -> None:
    ok, why = available(spec, ctx.s)
    if not ok:
        raise AppError("err.tb.unavailable", 403, reason=i18n.t(ctx.lang, why or "tb.na.disabled"))


# --- history -------------------------------------------------------------------------------------------------------
_saves = 0


def save(db: DB, result: dict[str, Any], recipe: str | None = None) -> int:
    global _saves
    _saves += 1
    if _saves % 100 == 0:  # also without the daily maintenance job (COLLECTORS=0) the history stays bounded
        prune(db)
    obj = result.get("object") or {}
    payload = json.dumps(result, ensure_ascii=False, default=str)
    if len(payload) > MAX_PAYLOAD:
        slim = {**result, "raw": None}
        payload = json.dumps(slim, ensure_ascii=False, default=str)
        if len(payload) > MAX_PAYLOAD:
            return 0
    return db.insert(
        "INSERT INTO tool_runs(created_at, tool, recipe, obj_type, obj_value, target, sev, payload) VALUES(?,?,?,?,?,?,?,?)",
        (utcnow(), result.get("tool") or "recipe", recipe, obj.get("type"), obj.get("value"), str(result.get("target") or "")[:300],
         (result.get("verdict") or {}).get("sev"), payload))


def history(db: DB, obj_type: str | None, obj_value: str | None, limit: int) -> list[dict[str, Any]]:
    sql = "SELECT id, created_at, tool, recipe, obj_type, obj_value, target, sev FROM tool_runs"
    args: list[Any] = []
    if obj_type and obj_value:
        sql += " WHERE obj_type=? AND obj_value=?"
        args += [obj_type, obj_value]
    sql += " ORDER BY id DESC LIMIT ?"
    return db.query(sql, (*args, limit))


def get_run(db: DB, rid: int) -> dict[str, Any] | None:
    rows = db.query("SELECT id, created_at, payload FROM tool_runs WHERE id=?", (rid,))
    if not rows:
        return None
    out = json.loads(rows[0]["payload"])
    out["run_id"] = rows[0]["id"]
    out["saved_at"] = rows[0]["created_at"]
    return out


def prune(db: DB) -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=HISTORY_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute("DELETE FROM tool_runs WHERE created_at < ?", (cutoff,))
    db.execute("DELETE FROM tool_runs WHERE id NOT IN (SELECT id FROM tool_runs ORDER BY id DESC LIMIT ?)", (HISTORY_MAX,))


# --- running --------------------------------------------------------------------------------------------------------
async def run_tool(ctx: Ctx, spec: ToolSpec, target: str, kind: str, params: dict[str, Any], *, store: bool = True) -> Gen:
    """Yields the events of one tool run. The final event is {"type": "result"} or {"type": "error"}."""
    if _run_sem.locked():
        yield {"type": "error", "key": "err.busy", "text": i18n.t(ctx.lang, "err.busy")}
        return
    async with _run_sem:
        deadline = time.monotonic() + spec.timeout
        gen = HANDLERS[spec.id](ctx, spec, target, params, kind)
        try:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise asyncio.TimeoutError
                try:
                    ev = await asyncio.wait_for(gen.__anext__(), timeout=left)
                except StopAsyncIteration:
                    break
                if ev.get("type") == "result" and store:
                    try:
                        ev["result"]["run_id"] = save(ctx.db, ev["result"])
                    except Exception:
                        log.exception("could not store tool run")
                yield ev
        except asyncio.TimeoutError:
            yield {"type": "error", "key": "err.timeout", "text": i18n.t(ctx.lang, "err.timeout")}
        except AppError as exc:
            yield {"type": "error", "key": exc.key, "text": exc.render(ctx.lang)}
        except Exception as exc:  # unexpected: report briefly, do not crash the stream
            log.exception("tool %s failed", spec.id)
            yield {"type": "error", "key": "err.internal", "text": i18n.t(ctx.lang, "err.internal", detail=exc.__class__.__name__)}
        finally:
            await gen.aclose()


async def _collect(ctx: Ctx, tool: str, target: str, kind: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs one tool inside a recipe and returns {"tool", "result"} or {"tool", "error"}."""
    spec = BY_ID[tool]
    ok, why = available(spec, ctx.s)
    if not ok:
        return {"tool": tool, "error": i18n.t(ctx.lang, why or "tb.na.disabled")}
    try:
        p = coerce_params(spec, params)
    except ValueError:
        return {"tool": tool, "error": i18n.t(ctx.lang, "err.tb.param", name=tool)}
    blocked = third_party_block(spec, target, kind)
    if blocked:
        return {"tool": tool, "error": i18n.t(ctx.lang, blocked, addr=target, party=spec.third_party)}
    out: dict[str, Any] = {"tool": tool}
    gen = HANDLERS[tool](ctx, spec, target, p, kind)
    try:
        async with asyncio.timeout(spec.timeout):
            async for ev in gen:
                if ev.get("type") == "result":
                    out["result"] = ev["result"]
    except TimeoutError:
        out["error"] = i18n.t(ctx.lang, "err.timeout")
    except AppError as exc:
        out["error"] = exc.render(ctx.lang)
    except Exception as exc:
        log.exception("recipe step %s failed", tool)
        out["error"] = i18n.t(ctx.lang, "err.internal", detail=exc.__class__.__name__)
    finally:
        await gen.aclose()
    if "result" not in out and "error" not in out:
        out["error"] = i18n.t(ctx.lang, "err.internal", detail="no result")
    return out


def prepare_recipe(rid: str, raw: str) -> tuple[str, str]:
    if rid not in RECIPES:
        raise AppError("err.not_found", 404)
    if rid == "mail":
        if not (raw or "").strip():
            raise AppError("err.tb.mail_empty")
        return raw, "mailhdr"
    det = detect(raw)
    t = det["type"]
    if t == "url" and det.get("host"):
        try:
            ipaddress.ip_address(det["host"])
            t, val = "ip", det["host"]
        except ValueError:
            t, val = "domain", det["host"]
    elif t == "email":
        t, val = "domain", det["domain"]
    else:
        val = det.get("value", "")
    if t not in RECIPES[rid]:
        raise AppError("err.tb.recipe_input", type=i18n.Key(f"tb.in.{t}"))
    return val, t


async def run_recipe(ctx: Ctx, rid: str, target: str, kind: str) -> Gen:
    if _run_sem.locked():
        yield {"type": "error", "key": "err.busy", "text": i18n.t(ctx.lang, "err.busy")}
        return
    t0 = time.perf_counter()
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    steps: list[dict[str, Any]] = []
    tasks: list[asyncio.Future[dict[str, Any]]] = []

    async def batch(items: list[tuple[str, dict[str, Any] | None]], tgt: str, knd: str) -> AsyncIterator[dict[str, Any]]:
        for tool, _ in items:
            yield {"type": "step", "tool": tool, "status": "running", "title": i18n.t(ctx.lang, f"tb.tool.{tool}")}
        new = [asyncio.ensure_future(_collect(ctx, tool, tgt, knd, p)) for tool, p in items]
        tasks.extend(new)
        for fut in asyncio.as_completed(new):
            st = await fut
            steps.append(st)
            yield {"type": "step_result", "tool": st["tool"], "result": st.get("result"), "error": st.get("error")}

    async with _run_sem:
        try:
            async with asyncio.timeout(300):
                if rid == "ip":
                    async for ev in batch([("ipinfo", None), ("ioc", None), ("bgp", None), ("greynoise", None), ("pdns", None)], target, "ip"):
                        yield ev
                elif rid == "domain":
                    async for ev in batch([("dns", None), ("mailsec", None), ("tls", None), ("http", None), ("ioc", None),
                                           ("ct", None), ("lookalike", None)], target, "domain"):
                        yield ev
                elif rid == "mail":
                    async for ev in batch([("mailhdr", {"text": target, "lookup": True})], "", "mailhdr"):
                        yield ev
                elif rid == "server":
                    first = [("ipinfo", None), ("ioc", None),
                             ("ports", {"ports": "21,22,23,25,80,443,445,3389,8080,8443"})]
                    async for ev in batch(first, target, kind):
                        yield ev
                    portres = next((s.get("result") for s in steps if s["tool"] == "ports"), None) or {}
                    open_ports = _open_ports(portres)
                    nxt: list[tuple[str, dict[str, Any] | None]] = []
                    tls_port = 443 if 443 in open_ports else 8443 if 8443 in open_ports else None
                    if tls_port:
                        nxt.append(("tls", {"port": tls_port}))
                    if 443 in open_ports or 80 in open_ports:
                        nxt.append(("http", None))
                    if 22 in open_ports:
                        nxt.append(("ssh", {"port": 22}))
                    if nxt:
                        async for ev in batch(nxt, target, kind):
                            yield ev
        except TimeoutError:
            yield {"type": "info", "text": i18n.t(ctx.lang, "err.timeout")}
        finally:
            # Stop, disconnect or timeout: steps still running are cancelled before the run slot is released,
            # so "Stop" really stops probing and the concurrency limit holds.
            pending = [t for t in tasks if not t.done()]
            for t in pending:
                t.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
    result = recipe_result(ctx, rid, target if rid != "mail" else "", steps, started, t0)
    try:
        result["run_id"] = save(ctx.db, result, recipe=rid)
    except Exception:
        log.exception("could not store recipe run")
    yield {"type": "result", "result": result}


def _open_ports(portres: dict[str, Any]) -> set[int]:
    out: set[int] = set()
    for sec in portres.get("sections") or []:
        if sec.get("kind") != "table":
            continue
        for row in sec.get("rows") or []:
            st = row[2] if len(row) > 2 else None
            if isinstance(st, dict) and st.get("sev") in ("ok", "medium", "high") and isinstance(row[0], int):
                out.add(row[0])
    return out


def recipe_result(ctx: Ctx, rid: str, target: str, steps: list[dict[str, Any]], started: str, t0: float) -> dict[str, Any]:
    order = {t: i for i, t in enumerate(BY_ID)}
    steps = sorted(steps, key=lambda s: order.get(s["tool"], 99))
    findings = []
    out_steps = []
    for s in steps:
        r = s.get("result")
        if r:
            out_steps.append({"tool": s["tool"], "title": r.get("title"), "sev": r["verdict"]["sev"], "text": r["verdict"]["text"], "result": r})
            for f in r.get("findings") or []:
                if SEV_ORDER.get(f["sev"], 0) >= SEV_ORDER["low"]:
                    findings.append({**f, "tool": r.get("title")})
        else:
            out_steps.append({"tool": s["tool"], "title": i18n.t(ctx.lang, f"tb.tool.{s['tool']}"), "sev": "info", "error": s.get("error")})
    findings.sort(key=lambda f: -SEV_ORDER[f["sev"]])
    sev = max_sev(*(s["sev"] for s in out_steps if "error" not in s))
    obj = None
    first = next((s["result"].get("object") for s in out_steps if s.get("result") and s["result"].get("object")), None)
    if first:
        obj = first
    counts = {k: sum(1 for f in findings if f["sev"] == k) for k in ("high", "medium", "low")}
    results = [s["result"] for s in out_steps if s.get("result")]
    levels = [r.get("level") for r in results]
    level = next((lv for lv in ("intrusive", "active", "passive") if lv in levels), "passive")
    parties = sorted({p.strip() for r in results for p in (r.get("third_party") or "").split(",") if p.strip()})
    return {
        "tool": "recipe", "recipe": rid, "title": i18n.t(ctx.lang, f"tb.recipe.{rid}"), "target": target or obj and obj.get("value") or "",
        "object": obj, "started_at": started, "ms": round((time.perf_counter() - t0) * 1000),
        "level": level, "target_sees": any(r.get("target_sees") for r in results), "third_party": ", ".join(parties) or None,
        "verdict": {"sev": sev, "text": i18n.t(ctx.lang, "tb.s.recipe", high=counts["high"], medium=counts["medium"], low=counts["low"],
                                               steps=len(out_steps))},
        "findings": findings[:40], "steps": out_steps,
    }


def ndjson(ev: dict[str, Any]) -> bytes:
    return (json.dumps(ev, ensure_ascii=False, default=str) + "\n").encode()
