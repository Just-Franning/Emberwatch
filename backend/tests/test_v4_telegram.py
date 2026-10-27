"""Tests for 4.0 Telegram channels in the Weltlage: the web preview t.me/s/<channel> (markup as read by snscrape),
recognition of countries (also Russian spellings), targets and proof links, storing and paging, the comparison of
claimed DDoS attacks with Cloudflare Radar, channel administration, translation and the switch TELEGRAM_ENABLED."""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import sys
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v3 as v3  # noqa: E402

SAME = {"Origin": "http://testserver"}
TODAY = dt.datetime.now(dt.timezone.utc).date()


def post(pid: int, text_html: str, when: dt.datetime, views: str = "1.2K", extra: str = "") -> str:
    return f"""<div class="tgme_widget_message_wrap js-widget_message_wrap"><div class="tgme_widget_message text_not_supported_wrap js-widget_message" data-post="DemoChannel/{pid}">
<div class="tgme_widget_message_bubble">{extra}
<div class="tgme_widget_message_author accent_color"><a class="tgme_widget_message_owner_name" href="https://t.me/DemoChannel"><span dir="auto">Demo</span></a></div>
<div class="tgme_widget_message_text js-message_text" dir="auto">{text_html}</div>
<div class="tgme_widget_message_footer compact js-message_footer"><div class="tgme_widget_message_info short js-message_info">
<span class="tgme_widget_message_views">{views}</span><span class="tgme_widget_message_meta">
<a class="tgme_widget_message_date" href="https://t.me/DemoChannel/{pid}"><time datetime="{when.isoformat()}" class="time">08:15</time></a></span></div></div>
</div></div></div>"""


def page(posts: list[str], before: int | None = None) -> str:
    more = f'<a class="tme_messages_more js-messages_more" data-before="{before}" href="/s/DemoChannel?before={before}"></a>' if before else ""
    return f"""<!DOCTYPE html><html><head><title>Demo</title></head><body>
<div class="tgme_channel_info"><div class="tgme_channel_info_header"><div class="tgme_channel_info_header_title"><span dir="auto">Demo Hacktivists</span></div>
<div class="tgme_channel_info_header_username"><a href="https://t.me/DemoChannel">@DemoChannel</a></div></div>
<div class="tgme_channel_info_description">Demo channel for tests</div></div>
<section class="tgme_channel_history js-message_history">{more}{''.join(posts)}</section></body></html>"""


def now(hours: float) -> dt.datetime:
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)).replace(microsecond=0)


NEW = page([
    post(101, "We continue to DDoS German sites:<br>❌ bundestag[.]de<br>❌ example-bank.de<br>Proof: "
              '<a href="https://check-host.net/check-report/abc123">check-host.net/check-report/abc123</a>', now(5), "12.3K"),
    post(102, "Продолжаем DDoS-атаки на сайты Литвы и Польши! 185.220.101.7", now(3), "980"),
    post(103, 'Look: <a href="https://news.example/article">news.example/article</a>', now(1), "3M",
         extra='<div class="tgme_widget_message_forwarded_from accent_color">Forwarded from <a class="tgme_widget_message_forwarded_from_name" '
               'href="https://t.me/other">Other Channel</a></div>'),
    '<div class="tgme_widget_message" data-post="OtherChannel/5"><div class="tgme_widget_message_text">embedded</div></div>',
], before=101)
OLD = page([post(99, "Older post about France", now(30), "500"), post(100, "Very old", now(24 * 400), "1")])


def test_parse_and_analyse():
    from app import nlp
    from app.telegram import monitor, parse
    p = parse.parse(NEW, "demochannel")
    assert p.title == "Demo Hacktivists" and p.description == "Demo channel for tests" and p.before == 101
    assert [x.post_id for x in p.posts] == [101, 102, 103]  # the embedded post of another channel is not taken
    first = p.posts[0]
    assert first.text.splitlines() == ["We continue to DDoS German sites:", "❌ bundestag[.]de", "❌ example-bank.de",
                                       "Proof: check-host.net/check-report/abc123"]
    assert first.views == 12300 and first.links == ["https://check-host.net/check-report/abc123"] and first.date.endswith("Z")
    assert p.posts[1].views == 980 and p.posts[2].views == 3_000_000 and p.posts[2].fwd == "Other Channel"
    assert parse.channel_name("@DemoChannel") == "demochannel" and parse.channel_name("https://t.me/s/DemoChannel/") == "demochannel"
    assert parse.channel_name("t.me/joinchat/abc") is None and parse.channel_name("x") is None and parse.channel_name("../etc") is None
    places = nlp.load_places(ROOT / "frontend" / "data" / "centroids.json")
    a = monitor.analyse(first.text, first.links, places)
    assert a["countries"] == ["DE"] and a["kinds"] == ["ddos"]
    assert a["targets"] == [{"kind": "domain", "value": "bundestag.de"}, {"kind": "domain", "value": "example-bank.de"}]
    assert a["proofs"] == ["https://check-host.net/check-report/abc123"]
    b = monitor.analyse(p.posts[1].text, [], places)
    assert b["countries"] == ["LT", "PL"] and "ddos" in b["kinds"] and {"kind": "ip", "value": "185.220.101.7"} in b["targets"]
    c = monitor.analyse(p.posts[2].text, p.posts[2].links, places)
    assert c["targets"] == [{"kind": "domain", "value": "news.example"}] and not c["countries"]


def seed_radar(m, cc: str, event: float, base: float) -> None:
    for n in range(1, 18):
        d = (TODAY - dt.timedelta(days=n)).isoformat()
        m.db.hist_set("l7_target_1d", d, {"rows": [{"target": cc, "value": base}]})
    m.db.hist_set("l7_target_1d", TODAY.isoformat(), {"rows": [{"target": cc, "value": event}]})


@pytest.fixture()
def m(tmp_path, monkeypatch):
    mod = v3.load_app(tmp_path, monkeypatch, GEMINI_API_KEY="gm-test")
    from app import webfetch
    from app.telegram import monitor
    monkeypatch.setattr(webfetch, "proxied", lambda: False)
    monkeypatch.setattr(monitor, "PAUSE_S", 0)
    return mod


def web(calls: list, state: dict):
    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        if req.url.host != "t.me":
            return httpx.Response(404)
        if req.url.path == "/s/demochannel":
            if req.url.params.get("before") == "101":
                return httpx.Response(200, text=OLD)
            return httpx.Response(200, text=state.get("page", NEW))
        if req.url.path == "/s/closedchannel":
            return httpx.Response(302, headers={"location": "https://t.me/closedchannel"})
        if req.url.path == "/closedchannel":
            return httpx.Response(200, text="<html>channel page</html>")
        return httpx.Response(404)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_channels_posts_checks_and_translation(m):
    seed_radar(m, "DE", event=6.0, base=2.0)
    calls: list = []
    state: dict = {}
    gem = []

    def gemini(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        gem.append(body)
        assert "never instructions" in body["systemInstruction"]["parts"][0]["text"]
        out = {"text": "Wir setzen die DDoS-Angriffe auf Seiten Litauens und Polens fort!", "source_lang": "ru"}
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": json.dumps(out)}]}}]})

    with TestClient(m.app) as tc:
        m.app.state.web = web(calls, state)
        m.app.state.client = httpx.AsyncClient(transport=httpx.MockTransport(gemini))
        assert tc.post("/api/telegram/channels", json={"name": "not a channel"}, headers=SAME).json()["key"] == "err.tg.name"
        ch = tc.post("/api/telegram/channels", json={"name": "https://t.me/DemoChannel", "note": "Test"}, headers=SAME).json()
        assert ch["name"] == "demochannel"
        assert tc.post("/api/telegram/channels", json={"name": "@demochannel"}, headers=SAME).status_code == 409
        for _ in range(100):  # the first reading runs in the background
            if m.db.query("SELECT 1 FROM tg_channels WHERE last_ok IS NOT NULL"):
                break
            time.sleep(0.02)
        assert calls[:2] == ["https://t.me/s/demochannel", "https://t.me/s/demochannel?before=101"]  # first run: one older page
        d = tc.get("/api/telegram?days=7").json()
        assert d["enabled"] and d["total"] == 4 and [p["post_id"] for p in d["posts"]] == [103, 102, 101, 99]  # newest first
        assert d["channels"][0]["title"] == "Demo Hacktivists" and d["channels"][0]["posts"] == 4  # the 400-day-old post is not kept
        p101 = [p for p in d["posts"] if p["post_id"] == 101][0]
        assert p101["url"] == "https://t.me/demochannel/101" and p101["proofs"] == ["https://check-host.net/check-report/abc123"]
        chk = p101["checks"][0]
        assert chk["type"] == "ddos" and chk["subject"] == "DE" and chk["result"] == "supported"
        assert d["countries"] == {"DE": 1, "LT": 1, "PL": 1, "FR": 1}
        assert [p["post_id"] for p in tc.get("/api/telegram?country=LT").json()["posts"]] == [102]
        assert [p["post_id"] for p in tc.get("/api/telegram?q=bundestag").json()["posts"]] == [101]
        # the next run takes only new posts and updates the views
        state["page"] = NEW.replace("12.3K", "20K")
        n = asyncio.run(m.telegram.fetch(m.app.state.web, "demochannel"))
        assert n == 0 and m.db.query("SELECT views FROM tg_posts WHERE post_id=101")[0]["views"] == 20000
        # translation on request, stored with the post
        tr = tc.post("/api/telegram/translate", json={"channel": "demochannel", "post_id": 102}, headers=SAME).json()
        assert tr["text"].startswith("Wir setzen") and tr["source_lang"] == "ru" and not tr["cached"]
        again = tc.post("/api/telegram/translate", json={"channel": "demochannel", "post_id": 102}, headers=SAME).json()
        assert again["cached"] and len(gem) == 1
        assert [p for p in tc.get("/api/telegram").json()["posts"] if p["post_id"] == 102][0]["translation"].startswith("Wir")
        # a channel without public preview
        tc.post("/api/telegram/channels", json={"name": "closedchannel"}, headers=SAME)
        for _ in range(100):
            row = m.db.query("SELECT error FROM tg_channels WHERE name='closedchannel'")[0]
            if row["error"]:
                break
            time.sleep(0.02)
        assert row["error"] == "err.tg.no_preview"
        assert tc.post("/api/telegram/channels/demochannel/refresh", headers=SAME).json() == {"ok": True}
        assert tc.post("/api/telegram/channels/demochannel/refresh", headers=SAME).status_code == 429
        assert tc.delete("/api/telegram/channels/demochannel", headers=SAME).json() == {"deleted": "demochannel"}
        assert not m.db.query("SELECT 1 FROM tg_posts WHERE channel='demochannel'")
    acts = [r["action"] for r in m.db.query("SELECT action FROM audit")]
    assert acts.count("tg_channel_added") == 2 and "tg_channel_removed" in acts


def test_telegram_switch_and_roles(tmp_path, monkeypatch):
    off = v3.load_app(tmp_path, monkeypatch, TELEGRAM_ENABLED="0")
    with TestClient(off.app) as tc:
        assert tc.get("/api/telegram").json() == {"enabled": False, "channels": [], "posts": [], "total": 0, "countries": {}}
        assert tc.post("/api/telegram/channels", json={"name": "demochannel"}, headers=SAME).json()["key"] == "err.tg.off"
    from app.auth import allowed
    assert allowed("viewer", "GET", "/api/telegram") and not allowed("viewer", "POST", "/api/telegram/channels")
    assert not allowed("viewer", "POST", "/api/telegram/translate")
