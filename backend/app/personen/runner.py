"""Runs searches of the people search one after another in the background: site lists (if due) -> checks of all sites
-> profiles of the found accounts -> graph of the case. Progress is kept in memory (the page polls it), counters and
hits go to the database while the search runs. A search can be stopped; what was found so far is kept."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx

from ..config import Settings
from ..db import utcnow
from . import check, profiles
from .operators import operator
from .sites import SiteList
from .store import Store, local_part

log = logging.getLogger("personen")

MAX_PROFILES = 60  # profiles read per search (found accounts beyond that are listed without profile data)
PROFILE_CONCURRENCY = 6
FLUSH_EVERY = 25


class Searcher:
    def __init__(self, s: Settings, store: Store, sites: SiteList, locator: profiles.Locator) -> None:
        self.s = s
        self.store = store
        self.sites = sites
        self.locator = locator
        self.lock = asyncio.Lock()  # one search at a time: each one already sends many requests in parallel
        self.tasks: dict[int, asyncio.Task] = {}
        self.live: dict[int, dict[str, Any]] = {}

    def running(self) -> list[int]:
        return [sid for sid, t in self.tasks.items() if not t.done()]

    def start(self, spawn: Callable[[Awaitable[Any]], asyncio.Task], web: httpx.AsyncClient, client: httpx.AsyncClient, sid: int) -> None:
        self.live[sid] = {"phase": "queued", "checked": 0, "total": 0, "found": 0, "unsure": 0, "errors": 0}
        self.tasks[sid] = spawn(self._run(web, client, sid))

    def stop(self, sid: int) -> bool:
        t = self.tasks.get(sid)
        if t is None or t.done():
            return False
        t.cancel()
        return True

    async def _run(self, web: httpx.AsyncClient, client: httpx.AsyncClient, sid: int) -> None:
        live = self.live[sid]
        try:
            async with self.lock:
                await self._search(web, client, sid, live)
        except asyncio.CancelledError:
            await self._finish(sid, live, "cancelled")
            raise
        except Exception as exc:
            log.exception("people search %s failed", sid)
            await self._finish(sid, live, "failed", exc.__class__.__name__)
        finally:
            live["done"] = True
            if len(self.live) > 50:  # progress of old searches is in the database
                for k in [k for k in self.live if self.live[k].get("done") and k != sid][:25]:
                    self.live.pop(k, None)

    async def _finish(self, sid: int, live: dict[str, Any], status: str, error: str | None = None) -> None:
        try:
            await asyncio.to_thread(self.store.build, sid)  # what was found so far stays usable
        except Exception:
            log.exception("graph of search %s", sid)
        live["phase"] = status
        self.store.set_search(sid, status=status, finished_at=utcnow(), checked=live["checked"], found=live["found"],
                              unsure=live["unsure"], errors=live["errors"], error=error)

    async def _search(self, web: httpx.AsyncClient, client: httpx.AsyncClient, sid: int, live: dict[str, Any]) -> None:
        s = self.store.search(sid)
        self.store.set_search(sid, status="running")
        if self.sites.due():
            live["phase"] = "lists"
            await self.sites.refresh(client)
        if not self.sites.sites:
            await self._finish(sid, live, "failed", "no_lists")
            return
        found: list[tuple[int, check.Check]] = []
        name = s["query"] if s["kind"] == "username" else local_part(s["query"])
        if s["kind"] == "email" and self.s.gravatar_api_key:
            live["phase"] = "gravatar"
            g = await profiles.gravatar(web, s["query"], self.s.gravatar_api_key, self.locator)
            if g:
                url, prof = g
                cc, how = operator("gravatar.com")
                hid = self.store.add_hit(sid, "Gravatar", "gravatar.com", "gravatar", "social", "found", url, 200, cc, how)
                if hid:
                    self.store.set_profile(hid, prof.to_dict())
                live["found"] += 1
        if name:
            live["phase"] = "checking"
            live["total"] = len(self.sites.sites)
            self.store.set_search(sid, sites=live["total"])

            async def done(c: check.Check) -> None:
                live["checked"] += 1
                if c.status in ("found", "unsure"):
                    host = (urlsplit(c.url).hostname or "").lower()
                    cc, how = operator(host)
                    hid = self.store.add_hit(sid, c.site.name, host, c.site.source, c.site.cat, c.status, c.url, c.http, cc, how)
                    live[c.status] += 1
                    if c.status == "found" and hid:
                        if len(found) >= MAX_PROFILES:
                            c.body = b""
                        found.append((hid, c))
                elif c.status == "error":
                    live["errors"] += 1
                if live["checked"] % FLUSH_EVERY == 0:
                    self.store.set_search(sid, checked=live["checked"], found=live["found"], unsure=live["unsure"], errors=live["errors"])

            await check.run(web, self.sites.sites, name, done)
            live["phase"] = "profiles"
            sem = asyncio.Semaphore(PROFILE_CONCURRENCY)

            async def read(hid: int, c: check.Check) -> None:
                async with sem:
                    try:
                        p = await profiles.read(web, c, name or "", self.locator)
                    except Exception:  # pages of third parties: one broken profile must not stop the others
                        log.debug("profile %s", c.url, exc_info=True)
                        return
                    finally:
                        c.body = b""
                if p is not None:
                    self.store.set_profile(hid, p.to_dict())

            await asyncio.gather(*(read(hid, c) for hid, c in found[:MAX_PROFILES]))
        live["phase"] = "graph"
        await self._finish(sid, live, "done")
