"""Reachability and path: ping, traceroute, path quality (traceroute with several probes per hop), Globalping."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import statistics
import time
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

import httpx

from ..tools import ToolError, is_public, parse_host, resolve
from .common import Ctx, as_text, asn_cell, geo_of, ip_cell, is_global, loc_text, obj_for, relate_ip
from .detect import internal_name
from .registry import ToolSpec
from .result import Result, cell

_proc_sem = asyncio.Semaphore(3)
GP_API = "https://api.globalping.io/v1/measurements"


def _origin_point(res: Result, origin: dict[str, Any] | None) -> tuple[float, float] | None:
    if origin and res.point(origin, "origin", res.t("tb.map.server"), origin.get("ip")):
        return (origin["lon"], origin["lat"])
    return None


# --- ping -----------------------------------------------------------------------------------------------------------
async def ping(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
    res = Result("ping", ctx.lang, target)
    origin = await ctx.tk.origin(ctx.client)
    rows: list[list[Any]] = []
    method = "icmp"
    ip = None
    geo = None
    stats: dict[str, Any] = {}
    async for ev in ctx.tk.ping(target, params["count"]):
        typ = ev.get("type")
        if typ == "start":
            ip, geo = ev["ip"], ev.get("geo")
            res.obj = obj_for(target, ip)
            yield {"type": "start", "ip": ip, "geo": geo, "origin": origin}
        elif typ == "reply":
            method = ev["method"]
            rows.append([ev["seq"], ev.get("ttl") if ev.get("ttl") is not None else "–", cell(f"{ev['rtt']} ms"), ev["method"]])
            yield {**ev, "type": "row", "kind": "reply"}
        elif typ == "timeout":
            rows.append([ev["seq"], "–", cell(res.t("tb.ping.no_reply"), sev="medium"), ""])
            yield {**ev, "type": "row", "kind": "timeout"}
        elif typ == "info":
            text = res.t(ev["key"], **(ev.get("params") or {}))
            res.find("info", "tb.f.note", note=text)
            yield {"type": "info", "text": text}
        elif typ == "done":
            stats = ev
    res.kv(res.t("tb.sec.target"), [
        (res.t("tb.k.target"), target), (res.t("tb.k.ip"), ip_cell(ip)), (res.t("tb.k.location"), loc_text(ctx, geo)),
        (res.t("tb.k.as"), asn_cell(geo)), (res.t("tb.k.method"), method.upper()),
        (res.t("tb.k.origin"), origin.get("ip") if origin else None)])
    res.table(res.t("tb.sec.replies"), [res.t("tb.c.seq"), "TTL", res.t("tb.c.rtt"), res.t("tb.c.method")], rows)
    sent, recv = stats.get("sent", 0), stats.get("received", 0)
    res.kv(res.t("tb.sec.stats"), [
        (res.t("tb.k.sent_recv"), f"{sent} / {recv}"), (res.t("tb.k.loss"), f"{stats.get('loss_pct', 0)} %"),
        (res.t("tb.k.rtt"), f"{stats['min']} / {stats['avg']} / {stats['max']} ms" if stats.get("avg") is not None else "–")])
    if sent and recv == 0:
        res.find("medium", "tb.f.ping_none", "tb.fd.ping_none")
    elif sent and recv < sent:
        res.find("low", "tb.f.ping_loss", loss=stats.get("loss_pct"))
    if stats.get("avg") is not None and stats["avg"] > 300:
        res.find("info", "tb.f.ping_slow", avg=stats["avg"])
    o = _origin_point(res, origin)
    if res.point(geo, "target", target, ip) and o:
        res.path([o, (geo["lon"], geo["lat"])])
    relate_ip(res, ip, geo)
    summary = res.t("tb.s.ping", recv=recv, sent=sent, avg=stats.get("avg") if stats.get("avg") is not None else "–")
    yield {"type": "result", "result": res.done(spec, summary)}


# --- traceroute -----------------------------------------------------------------------------------------------------
async def traceroute(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
    res = Result("traceroute", ctx.lang, target)
    rows: list[list[Any]] = []
    coords: list[tuple[float, float]] = []
    ip = None
    geo = None
    reached = False
    async for ev in ctx.tk.traceroute(ctx.client, target, params["max_hops"]):
        typ = ev.get("type")
        if typ == "start":
            ip, geo = ev["ip"], ev.get("geo")
            res.obj = obj_for(target, ip)
            o = _origin_point(res, ev.get("origin"))
            if o:
                coords.append(o)
            yield {"type": "start", "ip": ip, "geo": geo, "origin": ev.get("origin")}
        elif typ == "hop":
            hip, g = ev.get("ip"), ev.get("geo")
            host = ip_cell(hip, sev="high" if ev.get("c2") else None)
            where = res.t("tb.v.private") if ev.get("private") else "; ".join(x for x in (loc_text(ctx, g), as_text(g)) if x) or "–"
            rtt = f"{ev['rtt']} ms" if ev.get("rtt") is not None else "–"
            rows.append([ev["n"], host, ev.get("ptr") or "", where, f"{rtt} {ev.get('note') or ''}".strip()])
            if ev.get("c2"):
                res.find("high", "tb.f.hop_c2", ip=hip, malware=", ".join(c["malware"] or "?" for c in ev["c2"]))
            if g and g.get("lat") is not None:
                coords.append((g["lon"], g["lat"]))
                res.point(g, "hop", str(ev["n"]), hip)
            relate_ip(res, hip, g)
            yield {**ev, "type": "row", "kind": "hop"}
        elif typ == "info":
            text = ev.get("text") or res.t(ev["key"], **(ev.get("params") or {}))
            yield {"type": "info", "text": text}
        elif typ == "done":
            reached = bool(ev.get("reached"))
    res.kv(res.t("tb.sec.target"), [(res.t("tb.k.target"), target), (res.t("tb.k.ip"), ip_cell(ip)),
                                    (res.t("tb.k.location"), loc_text(ctx, geo)), (res.t("tb.k.as"), asn_cell(geo)),
                                    (res.t("tb.k.reached"), res.t("common.yes") if reached else res.t("common.no"))])
    res.table(res.t("tb.sec.hops"), ["#", res.t("tb.c.host"), "PTR", res.t("tb.c.loc_as"), res.t("tb.c.rtt")], rows)
    if not reached:
        res.find("info", "tb.f.trace_unreached", "tb.fd.trace_unreached")
    if geo and geo.get("lat") is not None:
        res.point(geo, "target", target, ip)
        if not coords or coords[-1] != (geo["lon"], geo["lat"]):
            coords.append((geo["lon"], geo["lat"]))
    res.path(coords)
    relate_ip(res, ip, geo)
    summary = res.t("tb.s.trace_ok" if reached else "tb.s.trace_no", n=len(rows))
    yield {"type": "result", "result": res.done(spec, summary)}


# --- path quality ---------------------------------------------------------------------------------------------------
_HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


def parse_multi_hop(line: str) -> dict[str, Any] | None:
    """One line of `traceroute -n -q N`: several probes per hop, possibly from different routers (ECMP).
    Returns {"n", "probes": [{"ip", "rtt"}|{"lost": True}], "notes"} or None."""
    m = _HOP_RE.match(line)
    if not m:
        return None
    probes: list[dict[str, Any]] = []
    notes: list[str] = []
    cur = None
    toks = m.group(2).split()
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "*":
            probes.append({"lost": True})
        elif tok.startswith("!"):
            notes.append(tok)
        else:
            try:
                cur = str(ipaddress.ip_address(tok))
            except ValueError:
                try:
                    rtt = float(tok)
                except ValueError:
                    rtt = None
                if rtt is not None and i + 1 < len(toks) and toks[i + 1] == "ms":
                    probes.append({"ip": cur, "rtt": rtt})
                    i += 1
        i += 1
    return {"n": int(m.group(1)), "probes": probes, "notes": notes}


def hop_stats(probes: list[dict[str, Any]], sent: int) -> dict[str, Any]:
    rtts = [p["rtt"] for p in probes if not p.get("lost") and p.get("rtt") is not None]
    ips = list(dict.fromkeys(p["ip"] for p in probes if p.get("ip")))
    recv = len(rtts)
    sent = max(sent, len(probes))
    return {"ips": ips, "sent": sent, "recv": recv, "loss": round(100 * (sent - recv) / sent, 1) if sent else 0.0,
            "best": min(rtts) if rtts else None, "avg": round(sum(rtts) / recv, 2) if rtts else None,
            "worst": max(rtts) if rtts else None, "stdev": round(statistics.pstdev(rtts), 2) if len(rtts) > 1 else 0.0 if rtts else None}


def _num(v: Any) -> str:
    return "–" if v is None else f"{v}"


async def pathq(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
    res = Result("pathq", ctx.lang, target)
    ip = (await resolve(target, ctx.s.tools_allow_private))[0]
    geo = geo_of(ctx, ip)
    res.obj = obj_for(target, ip)
    origin = await ctx.tk.origin(ctx.client)
    yield {"type": "start", "ip": ip, "geo": geo, "origin": origin}
    probes, max_hops = params["probes"], params["max_hops"]
    hops: list[dict[str, Any]] = []
    async with _proc_sem:
        fam = "-6" if ":" in ip else "-4"
        try:
            proc = await asyncio.create_subprocess_exec(
                ctx.s.traceroute_bin, fam, "-n", "-q", str(probes), "-w", "2", "-m", str(max_hops), ip,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise ToolError("err.tool.traceroute_missing", detail=exc.__class__.__name__) from exc
        deadline = time.time() + max_hops * (2 * probes + 2) + 15
        try:
            while True:
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=max(0.1, deadline - time.time()))
                except asyncio.TimeoutError:
                    yield {"type": "info", "text": res.t("tool.trace_timeout")}
                    break
                if not line:
                    break
                hop = parse_multi_hop(line.decode(errors="replace").rstrip())
                if hop is None:
                    continue
                st = hop_stats(hop["probes"], probes)
                st.update({"n": hop["n"], "notes": hop["notes"]})
                main_ip = st["ips"][0] if st["ips"] else None
                st["geo"] = geo_of(ctx, main_ip) if main_ip and is_global(main_ip) else None
                hops.append(st)
                yield {"type": "row", "kind": "hop", "n": st["n"], "ip": main_ip, "ips": st["ips"], "loss": st["loss"],
                       "avg": st["avg"], "geo": st["geo"], "private": bool(main_ip) and not is_global(main_ip)}
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()
    reached = any(ip in h["ips"] for h in hops)
    rows = []
    coords: list[tuple[float, float]] = []
    o = _origin_point(res, origin)
    if o:
        coords.append(o)
    for h in hops:
        main_ip = h["ips"][0] if h["ips"] else None
        sev = "medium" if h["loss"] >= 50 else "low" if h["loss"] > 0 else None
        ips = [ip_cell(x) for x in h["ips"]] or ["*"]
        where = res.t("tb.v.private") if main_ip and not is_global(main_ip) else as_text(h["geo"]) or "–"
        rows.append([h["n"], ips[0] if len(ips) == 1 else cell(", ".join(h["ips"]), mono=True), where,
                     cell(f"{h['loss']} %", sev=sev), _num(h["best"]), _num(h["avg"]), _num(h["worst"]), _num(h["stdev"])])
        if h["geo"] and h["geo"].get("lat") is not None:
            coords.append((h["geo"]["lon"], h["geo"]["lat"]))
            res.point(h["geo"], "hop", f"{h['n']} · {h['loss']} %", main_ip, sev=sev)
        relate_ip(res, main_ip, h["geo"])
    res.kv(res.t("tb.sec.target"), [(res.t("tb.k.target"), target), (res.t("tb.k.ip"), ip_cell(ip)),
                                    (res.t("tb.k.location"), loc_text(ctx, geo)), (res.t("tb.k.as"), asn_cell(geo)),
                                    (res.t("tb.k.probes_hop"), probes),
                                    (res.t("tb.k.reached"), res.t("common.yes") if reached else res.t("common.no"))])
    res.table(res.t("tb.sec.path"), ["#", res.t("tb.c.host"), res.t("tb.c.as"), res.t("tb.c.loss"), res.t("tb.c.best"),
                                     res.t("tb.c.avg"), res.t("tb.c.worst"), res.t("tb.c.stdev")], rows,
              note=res.t("tb.n.pathq"))
    last = hops[-1] if hops else None
    if reached and last is not None:
        if last["loss"] > 0:
            res.find("medium" if last["loss"] >= 20 else "low", "tb.f.pathq_target_loss", loss=last["loss"])
        mid = [h for h in hops[:-1] if h["loss"] > 0 and h["recv"] > 0]
        if mid and last["loss"] == 0:
            res.find("info", "tb.f.pathq_mid_loss", "tb.fd.pathq_mid_loss", n=len(mid))
        if last.get("avg") is not None and last.get("stdev") is not None and last["stdev"] > 30:
            res.find("low", "tb.f.pathq_jitter", stdev=last["stdev"])
    else:
        res.find("info", "tb.f.trace_unreached", "tb.fd.trace_unreached")
    if geo and geo.get("lat") is not None:
        res.point(geo, "target", target, ip)
        if not coords or coords[-1] != (geo["lon"], geo["lat"]):
            coords.append((geo["lon"], geo["lat"]))
    res.path(coords)
    relate_ip(res, ip, geo)
    summary = (res.t("tb.s.pathq", n=len(hops), loss=last["loss"], avg=last["avg"] if last["avg"] is not None else "–")
               if reached and last else res.t("tb.s.trace_no", n=len(hops)))
    yield {"type": "result", "result": res.done(spec, summary)}


# --- Globalping -----------------------------------------------------------------------------------------------------
def _gp_host(target: str) -> str:
    """Host part of a Globalping target: URL, host:port, [v6]:port or a bare host/IP."""
    t = target.strip()
    if "://" in t:
        try:
            host = urlsplit(t).hostname
        except ValueError as exc:
            raise ToolError("err.tool.target") from exc
        if not host:
            raise ToolError("err.tool.target")
        return host
    if t.startswith("[") and "]" in t:
        return t[1:t.index("]")]
    if t.count(":") == 1:  # host:port (IPv6 literals have several colons)
        return t.split(":", 1)[0]
    return t


def _gp_private(host: str, is_ip: bool) -> None:
    """Private addresses and internal names are never sent to Globalping (checked again after resolution)."""
    if (is_ip and not is_public(ipaddress.ip_address(host))) or (not is_ip and internal_name(host)):
        raise ToolError("err.tb.third_private", addr=host, party="Globalping")


def _gp_target(mode: str, target: str) -> tuple[str, dict[str, Any]]:
    """Validated target and measurement options for Globalping. Private targets are never sent to a third party."""
    if mode == "http":
        raw = target if "://" in target else f"https://{target}"
        try:
            p = urlsplit(raw)
            hostname = p.hostname
        except ValueError as exc:
            raise ToolError("err.tool.target") from exc
        if p.scheme not in ("http", "https") or not hostname:
            raise ToolError("err.tool.scheme")
        host, is_ip = parse_host(hostname)
        _gp_private(host, is_ip)
        req: dict[str, Any] = {"method": "HEAD", "path": p.path or "/"}
        if p.query:
            req["query"] = p.query
        opts: dict[str, Any] = {"request": req, "protocol": "HTTPS" if p.scheme == "https" else "HTTP"}
        try:
            if p.port:
                opts["port"] = p.port
        except ValueError as exc:
            raise ToolError("err.tool.port", port="?") from exc
        return host, opts
    host, is_ip = parse_host(_gp_host(target))
    _gp_private(host, is_ip)
    if mode == "dns":
        if is_ip:
            raise ToolError("err.tool.hostname")
        return host, {"query": {"type": "A"}}
    if mode == "ping":
        return host, {"packets": 3}
    if mode == "mtr":
        return host, {"packets": 3, "protocol": "ICMP"}
    return host, {"protocol": "ICMP"}


def _gp_error(r: httpx.Response) -> str:
    try:
        return str((r.json().get("error") or {}).get("message") or "")[:200]
    except ValueError:
        return r.text[:200]


async def globalping(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> AsyncIterator[dict[str, Any]]:
    mode, limit = params["mode"], params["limit"]
    loc = (params.get("location") or "world").strip() or "world"
    if not re.fullmatch(r"[\w .,+\-()]{1,80}", loc):
        raise ToolError("err.tb.param", name="location")
    res = Result("globalping", ctx.lang, target)
    host, opts = _gp_target(mode, target)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # a name is resolved locally first: names that point to private addresses (split horizon, internal zones) stay
        # on the server. Names this server cannot resolve or that a DNS filter blocks (Pi-hole, AdGuard: NXDOMAIN or
        # 0.0.0.0) are still measured: they are not shown to be internal, and malicious domains are a typical target.
        try:
            await resolve(host, False)
        except ToolError as exc:
            if exc.key == "err.tool.private":
                raise ToolError("err.tb.third_private", addr=host, party="Globalping") from exc
            if exc.key not in ("err.tool.resolve", "err.tool.multicast"):
                raise
    res.obj = ("ip", host) if is_global(host) else ("domain", host)
    body: dict[str, Any] = {"type": mode, "target": host, "limit": limit, "measurementOptions": opts}
    if loc.lower() != "world":
        body["locations"] = [{"magic": loc}]
    headers = {"User-Agent": ctx.s.user_agent, "Accept": "application/json", "Content-Type": "application/json"}
    if ctx.s.globalping_token:
        headers["Authorization"] = f"Bearer {ctx.s.globalping_token}"
    try:
        r = await ctx.client.post(GP_API, json=body, headers=headers, timeout=15)
    except httpx.HTTPError as exc:
        raise ToolError("err.tool.upstream", detail=exc.__class__.__name__) from exc
    if r.status_code == 429:
        raise ToolError("err.tb.gp_limit")
    if r.status_code == 422:
        raise ToolError("err.tb.gp_noprobes", detail=_gp_error(r))
    if r.status_code != 202:
        raise ToolError("err.tb.gp_http", status=r.status_code, detail=_gp_error(r))
    mid = str((r.json() or {}).get("id") or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", mid):
        raise ToolError("err.tb.gp_http", status=202, detail="id")
    yield {"type": "info", "text": res.t("tb.gp.started", n=(r.json() or {}).get("probesCount", "?"))}
    data: dict[str, Any] = {}
    deadline = time.time() + 40
    seen = -1
    while time.time() < deadline:
        await asyncio.sleep(0.5)
        try:
            g = await ctx.client.get(f"{GP_API}/{mid}", headers=headers, timeout=10)
        except httpx.HTTPError:
            continue
        if g.status_code != 200:
            continue
        data = g.json() or {}
        done = sum(1 for x in data.get("results") or [] if (x.get("result") or {}).get("status") != "in-progress")
        if done != seen:
            seen = done
            yield {"type": "progress", "done": done, "total": len(data.get("results") or [])}
        if data.get("status") != "in-progress":
            break
    results = data.get("results") or []
    if not results:
        raise ToolError("err.tb.gp_empty")
    rows = []
    failed = 0
    lat_vals: list[float] = []
    tgt_ip = None
    for item in results[:50]:
        pr = item.get("probe") or {}
        rs = item.get("result") or {}
        place = ", ".join(x for x in (pr.get("city"), ctx.geo.country_name(pr.get("country"), ctx.lang)
                                      if pr.get("country") else None) if x)
        net = f"AS{pr.get('asn')} {pr.get('network') or ''}".strip() if pr.get("asn") else (pr.get("network") or "")
        status = rs.get("status")
        val, sev = _gp_value(res, mode, rs)
        if status != "finished":
            failed += 1
            val, sev = res.t("tb.gp.failed", src=rs.get("failureSource") or status or "?"), "medium"
        tgt_ip = tgt_ip or rs.get("resolvedAddress")
        num = _gp_metric(mode, rs)
        if num is not None:
            lat_vals.append(num)
        rows.append([place or "–", net or "–", cell(val, sev=sev)])
        if pr.get("latitude") is not None and pr.get("longitude") is not None:
            res.point({"lat": pr["latitude"], "lon": pr["longitude"]}, "probe",
                      f"{pr.get('city') or pr.get('country') or ''} {_short(mode, rs)}".strip(), None, sev=sev or "ok")
    res.kv(res.t("tb.sec.target"), [(res.t("tb.k.target"), host), (res.t("tb.k.mode"), mode.upper()),
                                    (res.t("tb.k.location_sel"), loc), (res.t("tb.k.probes"), len(results)),
                                    (res.t("tb.k.ip"), ip_cell(tgt_ip) if tgt_ip else None)])
    res.table(res.t("tb.sec.probes"), [res.t("tb.c.place"), res.t("tb.c.network"), res.t("tb.c.result")], rows,
              note=res.t("tb.n.gp"))
    if failed:
        res.find("medium" if failed * 2 >= len(results) else "low", "tb.f.gp_failed", n=failed, total=len(results))
    if lat_vals and mode in ("ping", "mtr", "http"):
        res.kv(res.t("tb.sec.stats"), [(res.t("tb.k.median"), f"{round(statistics.median(lat_vals), 1)} ms"),
                                      (res.t("tb.k.fastest"), f"{round(min(lat_vals), 1)} ms"),
                                      (res.t("tb.k.slowest"), f"{round(max(lat_vals), 1)} ms")])
    if tgt_ip:
        tg = geo_of(ctx, tgt_ip) if is_global(tgt_ip) else None
        res.point(tg, "target", host, tgt_ip)
        relate_ip(res, tgt_ip, tg)
    res.raw = {"id": mid, "results": [{"probe": {k: (i.get("probe") or {}).get(k) for k in ("city", "country", "asn", "network")},
                                       "raw": ((i.get("result") or {}).get("rawOutput") or "")[:3000]} for i in results[:25]]}
    summary = res.t("tb.s.gp", ok=len(results) - failed, total=len(results),
                    median=round(statistics.median(lat_vals), 1) if lat_vals else "–")
    yield {"type": "result", "result": res.done(spec, summary)}


def _gp_metric(mode: str, rs: dict[str, Any]) -> float | None:
    try:
        if mode == "ping":
            return float(rs["stats"]["avg"]) if rs.get("stats", {}).get("avg") is not None else None
        if mode == "mtr":
            last = (rs.get("hops") or [])[-1]
            return float(last["stats"]["avg"]) if last.get("stats", {}).get("avg") is not None else None
        if mode == "http":
            return float(rs["timings"]["total"]) if (rs.get("timings") or {}).get("total") is not None else None
        if mode == "dns":
            return float(rs["timings"]["total"]) if (rs.get("timings") or {}).get("total") is not None else None
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return None


def _short(mode: str, rs: dict[str, Any]) -> str:
    v = _gp_metric(mode, rs)
    return f"{round(v)} ms" if v is not None else ""


def _gp_value(res: Result, mode: str, rs: dict[str, Any]) -> tuple[str, str | None]:
    try:
        if mode == "ping":
            st = rs.get("stats") or {}
            loss = st.get("loss") or 0
            avg = st.get("avg")
            return (res.t("tb.gp.ping", avg=avg if avg is not None else "–", loss=loss),
                    "medium" if loss >= 50 else "low" if loss > 0 else "ok")
        if mode == "traceroute":
            hops = rs.get("hops") or []
            last = hops[-1] if hops else {}
            rtts = [t.get("rtt") for t in last.get("timings") or [] if t.get("rtt") is not None]
            return res.t("tb.gp.trace", n=len(hops), rtt=round(min(rtts), 1) if rtts else "–"), None
        if mode == "mtr":
            hops = rs.get("hops") or []
            st = (hops[-1].get("stats") if hops else {}) or {}
            loss = st.get("loss") or 0
            return (res.t("tb.gp.mtr", n=len(hops), avg=st.get("avg") if st.get("avg") is not None else "–", loss=loss),
                    "medium" if loss >= 50 else "low" if loss > 0 else "ok")
        if mode == "http":
            code = rs.get("statusCode")
            total = (rs.get("timings") or {}).get("total")
            tls = (rs.get("tls") or {}).get("protocol")
            sev = "ok" if code and code < 400 else "medium"
            return res.t("tb.gp.http", code=code or "?", ms=total if total is not None else "–", tls=tls or "–"), sev
        if mode == "dns":
            ans = [a.get("value") for a in rs.get("answers") or [] if a.get("value")]
            return (", ".join(ans[:4]) or res.t("tb.gp.dns_none"),
                    "ok" if ans else "medium")
    except (AttributeError, KeyError, IndexError, TypeError):
        pass
    return "–", None
