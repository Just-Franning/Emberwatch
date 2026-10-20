"""Notifications via Matrix (client-server API v3, m.notice).

Requirement: a bot account with access token that is a member of the room.
The bot sends unencrypted. In an end-to-end encrypted room the messages arrive unreadable;
use an unencrypted room.
"""
from __future__ import annotations

import html
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote

import httpx

from . import alerts, i18n
from .config import Settings
from .db import DB, utcnow

log = logging.getLogger("notify")
SEV_RANK = {"high": 0, "medium": 1, "low": 2}
PATTERN_COOLDOWN = timedelta(hours=24)


class Notifier:
    def __init__(self, s: Settings, db: DB, cname: Callable[[str | None, str], str]) -> None:
        self.s = s
        self.db = db
        self.cname = cname
        self.lang = s.language

    @property
    def enabled(self) -> bool:
        return self.s.matrix_enabled

    def _t(self, key: str, **kw: Any) -> str:
        return i18n.t(self.lang, key, **kw)

    async def send(self, client: httpx.AsyncClient, text: str, html_body: str | None = None) -> tuple[bool, str]:
        if not self.enabled:
            return False, self._t("err.matrix_off")
        url = (f"{self.s.matrix_homeserver}/_matrix/client/v3/rooms/{quote(self.s.matrix_room, safe='')}"
               f"/send/m.room.message/{uuid.uuid4()}")
        content: dict[str, Any] = {"msgtype": "m.notice", "body": text[:30000]}
        if html_body:
            content["format"] = "org.matrix.custom.html"
            content["formatted_body"] = html_body[:60000]
        try:
            r = await client.put(url, json=content, headers={"Authorization": f"Bearer {self.s.matrix_token}"}, timeout=20)
        except httpx.HTTPError as exc:
            return False, f"{exc.__class__.__name__}: {exc}"[:300]
        if r.status_code != 200:
            try:
                err = r.json().get("error") or r.text[:200]
            except ValueError:
                err = r.text[:200]
            return False, f"HTTP {r.status_code}: {err}"
        return True, "ok"

    async def test(self, client: httpx.AsyncClient) -> tuple[bool, str]:
        msg = self._t("notify.test")
        return await self.send(client, f"Emberwatch: {msg}", f"<p><b>Emberwatch</b>: {html.escape(msg)}</p>")

    def _due(self, key: str) -> bool:
        rows = self.db.query("SELECT sent_at FROM notifications WHERE key=?", (key,))
        if not rows:
            return True
        sent = datetime.strptime(rows[0]["sent_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - sent >= PATTERN_COOLDOWN

    def _mark(self, key: str) -> None:
        self.db.execute(
            "INSERT INTO notifications(key, sent_at) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET sent_at=excluded.sent_at",
            (key, utcnow()),
        )

    def _list(self, heading: str, items: list[tuple[str, str, str]]) -> tuple[str, str]:
        """items: (severity, title, detail) -> (plain text, HTML)"""
        lines = [f"Emberwatch: {heading}"]
        lis = []
        for sev, title, detail in items:
            label = self._t(f"sev.{sev}")
            lines.append(f"- [{label}] {title}: {detail}")
            lis.append(f"<li><b>{html.escape(label)}</b> {html.escape(title)}: {html.escape(detail)}</li>")
        return "\n".join(lines), f"<p><b>Emberwatch</b>: {html.escape(heading)}</p><ul>{''.join(lis)}</ul>"

    async def patterns(self, client: httpx.AsyncClient, patterns: list[dict[str, Any]]) -> None:
        if not self.enabled:
            return
        limit = SEV_RANK[self.s.matrix_min_severity]
        due = []
        for p in patterns:
            if SEV_RANK.get(p.get("severity"), 9) > limit or p.get("category") == "alerts":
                continue  # alerts are delivered individually by alerts()
            key = "pattern:" + p["ident"]
            if self._due(key):
                due.append((key, i18n.render_pattern(p, self.lang, self.cname)))
        if not due:
            return
        text, body = self._list(self._t("notify.patterns", count=len(due)),
                                [(p["severity"], p["title"], p["detail"]) for _, p in due[:15]])
        ok, msg = await self.send(client, text, body)
        if ok:
            for key, _ in due:
                self._mark(key)
        else:
            log.warning("Matrix delivery (patterns) failed: %s", msg)

    async def alerts(self, client: httpx.AsyncClient) -> None:
        if not self.enabled:
            return
        rows = alerts.pending(self.db, self.s.matrix_min_severity)
        if not rows:
            return
        rendered = [alerts.render(r, self.lang) for r in rows]
        text, body = self._list(self._t("notify.alerts", count=len(rendered)),
                                [(a["severity"], a["title"], a["detail"]) for a in rendered[:25]])
        ok, msg = await self.send(client, text, body)
        if ok:
            alerts.mark_notified(self.db, [r["id"] for r in rows])
        else:
            log.warning("Matrix delivery (alerts) failed: %s", msg)

    async def report(self, client: httpx.AsyncClient, report: dict[str, Any]) -> tuple[bool, str]:
        title = report.get("title") or self._t("notify.daily")
        summary = (report.get("summary") or "").replace("**", "")
        findings = report.get("findings") or []
        head = f"Emberwatch {self._t('notify.daily')}: {title}"
        text = "\n".join([head, "", summary, ""] +
                         [f"- [{self._t('sev.' + f['severity'])}] {f['title']}: {f['detail']}" for f in findings[:10]])
        body_html = (f"<p><b>{html.escape(head)}</b></p>"
                     f"<p>{html.escape(summary).replace(chr(10), '<br>')}</p>"
                     + ("<ul>" + "".join(f"<li><b>{html.escape(self._t('sev.' + f['severity']))}</b> "
                                         f"{html.escape(f['title'])}: {html.escape(f['detail'])}</li>" for f in findings[:10]) + "</ul>"
                        if findings else ""))
        return await self.send(client, text, body_html)
