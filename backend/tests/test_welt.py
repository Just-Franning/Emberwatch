"""Tests for the Weltlage (3.2): feed parsing, recognition, grouping, alerts, preview images, actors, API and Gemini.

Feeds are mocked in their documented formats (RSS 2.0 with content:encoded and Media RSS, Atom 1.0 RFC 4287, RSS 1.0/RDF),
the MISP Galaxy cluster in its published JSON structure (clusters/threat-actor.json). DNS checks of the preview-image
fetch are replaced by a stub (public for the sources, private for "internal." hosts).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import sys
from email.utils import format_datetime
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v3 as v3  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)
STATE: dict = {}
PROMPTS: list[str] = []


def rfc822(hours: float) -> str:
    return format_datetime(NOW - dt.timedelta(hours=hours))


def iso(hours: float) -> str:
    return (NOW - dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def galaxy() -> dict:
    vals = [{"value": f"Filler Actor {i:03d}", "uuid": f"u{i}", "meta": {}} for i in range(110)]
    vals += [
        {"value": "APT28", "description": "Russian military intelligence (GRU) unit 26165.", "uuid": "a28",
         "meta": {"country": "RU", "cfr-suspected-state-sponsor": "Russian Federation", "attribution-confidence": "80",
                  "synonyms": ["Fancy Bear", "Sofacy", "STRONTIUM", "Forest Blizzard"], "cfr-type-of-incident": ["Espionage"],
                  "cfr-suspected-victims": ["Germany", "Ukraine"], "cfr-target-category": ["Government"],
                  "refs": ["https://attack.mitre.org/groups/G0007/", "javascript:alert(1)", "http://insecure.example/x"]}},
        {"value": "Volt Typhoon", "uuid": "vt", "meta": {"cfr-suspected-state-sponsor": "China",
                                                         "synonyms": ["Bronze Silhouette", "Vanguard Panda"]}},
        {"value": "Sandworm Team", "uuid": "sw", "meta": {"country": "RU", "synonyms": ["Sandworm", "Voodoo Bear"]}},
    ]
    return {"name": "Threat Actor", "type": "threat-actor", "values": vals}


RECORD = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:media="http://search.yahoo.com/mrss/">
<channel><title>The Record</title>
<item><title>Russian hackers target German government websites in DDoS wave</title>
 <link>https://therecord.media/russian-ddos-germany?utm_source=rss&amp;utm_medium=rss</link>
 <pubDate>{rfc822(5)}</pubDate>
 <description><![CDATA[<p>The group, tracked as <b>Fancy Bear</b>, hit ministries.</p><img src="https://therecord.media/pixel.gif" width="1" height="1">]]></description>
 <enclosure url="https://cdn.therecord.media/img/ddos.jpg" type="image/jpeg" length="1"/>
</item>
<item><title>Fortinet patches FortiOS flaw exploited in attacks (CVE-2026-1000)</title>
 <link>https://therecord.media/fortios-flaw</link><pubDate>{rfc822(3)}</pubDate>
 <description>Fortinet released fixes for an actively exploited vulnerability.</description></item>
<item><title>[Sponsored] Webinar: securing your SOC</title><link>https://therecord.media/webinar</link>
 <pubDate>{rfc822(2)}</pubDate></item>
<item><title>Old story about a breach</title><link>https://therecord.media/old</link><pubDate>{rfc822(24 * 40)}</pubDate></item>
<item><title>Volt Typhoon still lurking in US critical infrastructure networks</title>
 <link>https://therecord.media/volt-typhoon</link><pubDate>{rfc822(30)}</pubDate>
 <content:encoded><![CDATA[<p>Officials said the <i>Volt Typhoon</i> intrusions continue.</p>]]></content:encoded>
 <media:content url="https://cdn.therecord.media/img/vt.png" medium="image"/></item>
<item><title>Phishing campaign spoofs example.de customers</title><link>https://therecord.media/phish</link>
 <pubDate>{rfc822(1)}</pubDate><description>Mails pretend to come from www.example.de support.</description></item>
<item><title>No link at all</title><pubDate>{rfc822(1)}</pubDate></item>
</channel></rss>""".encode()

BLEEPING = f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>BleepingComputer</title>
<entry><title type="html">Russian hackers target German government websites with DDoS attacks</title>
 <link rel="alternate" href="https://www.bleepingcomputer.com/news/security/russian-ddos-germany/"/>
 <link rel="enclosure" href="https://www.bleepingcomputer.com/x.mp3"/>
 <published>{iso(4)}</published><updated>{iso(4)}</updated>
 <summary type="html">&lt;p&gt;Pro-Russian hacktivists claimed the attacks.&lt;/p&gt;</summary></entry>
<entry><title>QakBot botnet returns with new loader</title>
 <link href="https://www.bleepingcomputer.com/news/security/qakbot-returns/"/>
 <published>{iso(6)}</published>
 <content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">The <b>QakBot</b> operators are back.</div></content></entry>
</feed>""".encode()

BSI = f"""<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel rdf:about="https://www.bsi.bund.de/"><title>BSI</title></channel>
<item rdf:about="https://www.bsi.bund.de/DE/Service-Navi/Presse/fortios.html">
 <title>BSI warnt vor ausgenutzter Schwachstelle in FortiOS (CVE-2026-1000)</title>
 <link>https://www.bsi.bund.de/DE/Service-Navi/Presse/fortios.html</link>
 <dc:date>{iso(2)}</dc:date><description>Betreiber sollen sofort patchen.</description></item>
</rdf:RDF>""".encode()

HTML_FORTI = b"""<!doctype html><html><head><title>x</title>
<meta property='og:image' content='https://cdn.therecord.media/img/forti.jpg'>
<meta name="twitter:image" content="https://cdn.therecord.media/img/other.jpg"></head><body>""" + b"x" * 1000


def handler(request: httpx.Request) -> httpx.Response:
    h, path = request.url.host, request.url.path
    if h == "raw.githubusercontent.com" and path.endswith("/clusters/threat-actor.json"):
        STATE["galaxy"] = STATE.get("galaxy", 0) + 1
        return httpx.Response(200, json=galaxy())
    if h == "therecord.media":
        if path == "/feed/":
            STATE.setdefault("record_hdr", []).append(dict(request.headers))
            if request.headers.get("if-none-match") == '"rec-1"':
                return httpx.Response(304)
            return httpx.Response(200, content=RECORD, headers={"content-type": "application/rss+xml", "etag": '"rec-1"'})
        STATE.setdefault("pages", []).append(path)
        if path == "/fortios-flaw":
            return httpx.Response(200, content=HTML_FORTI, headers={"content-type": "text/html; charset=utf-8"})
        if path == "/phish":
            return httpx.Response(302, headers={"location": "https://internal.therecord.media/x"})
        return httpx.Response(404)
    if h == "www.bleepingcomputer.com" and path == "/feed/":
        return httpx.Response(200, content=BLEEPING, headers={"content-type": "application/atom+xml"})
    if h == "www.bsi.bund.de" and path.endswith("RSSNewsfeed_Presse_Veranstaltungen.xml"):
        return httpx.Response(200, content=BSI, headers={"content-type": "application/xml"})
    if h in ("www.bleepingcomputer.com", "www.bsi.bund.de"):
        STATE.setdefault("pages", []).append(h + path)
        if "qakbot" in path:
            return httpx.Response(301, headers={"location": "https://evil.example/og"})
        return httpx.Response(200, content=b"<html><head><title>no image</title></head>", headers={"content-type": "text/html"})
    if h == "krebsonsecurity.com":
        return httpx.Response(503)
    if h == "feeds.certx.example":
        return httpx.Response(302, headers={"location": "https://internal.certx.example/rss"})
    if h in ("evil.example", "internal.therecord.media", "internal.certx.example"):
        STATE.setdefault("forbidden", []).append(str(request.url))
        return httpx.Response(200, content=b"<html><head><meta property='og:image' content='https://evil.example/i.jpg'></head>")
    if h == "generativelanguage.googleapis.com":
        body = json.loads(request.content)
        PROMPTS.append(body["contents"][0]["parts"][0]["text"])
        schema = body["generationConfig"].get("responseSchema", {})
        ans = ({"answer": "Laut BSI.", "charts": [], "caveats": []} if "answer" in schema.get("properties", {}) else
               {"title": "Einordnung", "summary": "- laut Quelle", "findings": [], "charts": [], "caveats": ["automatisch erkannt"]})
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": json.dumps(ans)}]}, "finishReason": "STOP"}]})
    return v3.handler(request)


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture()
def m(tmp_path, monkeypatch):
    mod = v3.load_app(tmp_path, monkeypatch, GEMINI_API_KEY="gm-test", HOME_REGION="DE,AT,CH", LANGUAGE="en",
                      NEWS_DISABLE="ncsc_uk,securityweek,golem",
                      NEWS_FEEDS="certx|CERT-X|https://feeds.certx.example/rss|gov|de;bad id|X|https://a.example/;"
                                 "plain|Plain|http://insecure.example/rss")
    STATE.clear()
    PROMPTS.clear()
    from app import news as news_mod
    from app.tools import ToolError

    async def fake_resolve(host: str, allow_private: bool, family: str = "any") -> list[str]:
        if host.startswith("internal.") and not allow_private:
            raise ToolError("err.tool.private", addr=host)
        return ["93.184.216.34"]
    monkeypatch.setattr(news_mod, "resolve", fake_resolve)
    return mod


def collect(m) -> int:
    c = client()

    async def go():
        await m.actors.collect(c, m.S.user_agent)
        await asyncio.to_thread(m.news.refresh_mine)
        return await m.news.collect(c)
    return asyncio.run(go())


def setup_data(m) -> None:
    v3.feeds(m, v3.mock_client())  # C2 (QakBot …), KEV (CVE-2026-1000 …)
    pid = m.products.add("Fortinet", "FortiOS")
    m.db.insert("INSERT INTO product_cves(product_id, cve, source, first_seen) VALUES(?,?,?,?)", (pid, "CVE-2026-1000", "kev", m.utcnow()))
    m.db.insert("INSERT INTO watchlist(kind, value, label, created_at) VALUES(?,?,?,?)", ("domain", "example.de", None, m.utcnow()))


# ------------------------------------------------------------------------------------------------------------------------
def test_parse_feed_formats_and_xml_safety():
    from app import news
    rss = news.parse_feed(RECORD)
    assert len(rss) == 7 and rss[0]["title"].startswith("Russian hackers")
    assert rss[0]["image"] == "https://cdn.therecord.media/img/ddos.jpg"  # enclosure wins; tracking pixel is never used
    assert rss[0]["date"] and abs((rss[0]["date"] - (NOW - dt.timedelta(hours=5))).total_seconds()) < 2
    assert rss[4]["image"] == "https://cdn.therecord.media/img/vt.png" and "Volt Typhoon" in news.strip_html(rss[4]["content"])
    atom = news.parse_feed(BLEEPING)
    assert atom[0]["link"] == "https://www.bleepingcomputer.com/news/security/russian-ddos-germany/"  # rel=enclosure ignored
    assert "Pro-Russian" in news.strip_html(atom[0]["desc"]) and "QakBot" in atom[1]["content"]
    rdf = news.parse_feed(BSI)
    assert rdf[0]["link"].endswith("fortios.html") and rdf[0]["date"] is not None
    # entity declarations (billion laughs) and external entities (XXE) are refused
    bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><rss><channel><item><title>&b;</title></item></channel></rss>'
    xxe = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&x;</title></item></channel></rss>'
    for doc in (bomb, xxe):
        with pytest.raises(Exception) as exc:
            news.parse_feed(doc)
        assert "Forbidden" in type(exc.value).__name__ or "Entities" in type(exc.value).__name__
    assert news.parse_feed(b"<?xml version='1.0'?><!DOCTYPE rss><rss><channel></channel></rss>") == []
    many = b"<rss><channel>" + b"<item><title>x</title><link>https://a.example/</link></item>" * 500 + b"</channel></rss>"
    assert len(news.parse_feed(many)) == news.MAX_ITEMS_PER_FEED


def test_urls_and_images():
    from app import news
    assert news.clean_url("http://www.example.com/a?utm_source=x&id=5&fbclid=1#top") == "https://www.example.com/a?id=5"
    assert news.clean_url("https://ex.example/a?b=1&c=%20") == "https://ex.example/a?b=1&c=%20"  # untouched without trackers
    for bad in ("javascript:alert(1)", "https://user:pw@ex.example/", "data:image/png;base64,AA", "ftp://ex.example/",
                "https://ex.example/a b", "https://ex.example:99999/", ""):
        assert news.clean_url(bad) is None, bad
    assert news.clean_url("//cdn.example/i.png", image=True) == "https://cdn.example/i.png"
    assert news._img_from_html('<img src="https://x.example/track/1.gif"><img data-src=\'https://cdn.example/a.jpg\' width="640">') \
        == "https://cdn.example/a.jpg"
    assert news._img_from_html('<img src="https://cdn.example/s.gif" width="1" height="1">') is None
    assert news.og_image("<head><meta content='https://cdn.example/o.jpg' property='og:image'></head>") == "https://cdn.example/o.jpg"
    assert news.og_image("<head></head><meta property='og:image' content='https://late.example/i.jpg'>") is None  # head only
    extra = news.parse_extra("ok_1|Name|https://feeds.example.org/rss|gov|DE;x|Bad|https://a.example/;y_2|Y|http://b.example/;"
                             "z_3|Z|https://u:p@c.example/")
    assert [(s.id, s.tier, s.lang, s.domains) for s in extra] == [("ok_1", "gov", "de", ("example.org",))]


def test_recognition(m):
    from app import nlp
    P = m.news.places
    assert nlp.countries("German government warns of Russian hackers", P) == ("RU", ["DE"])
    assert nlp.countries("German automotive group hit by ransomware", P) == (None, ["DE"])
    assert nlp.countries("Russian ransomware gang claims attack on Dutch hospital", P) == ("RU", ["NL"])
    assert nlp.countries("US government agencies breached by Chinese state hackers", P) == ("CN", ["US"])
    assert nlp.countries("Let us know: UK and US warn of North Korean IT workers", P) == (None, ["GB", "US", "KP"])
    assert nlp.countries("BSI warnt vor russischen Hackern: Angriffe auf deutsche Behörden", P) == ("RU", ["DE"])
    assert nlp.countries("Iran-backed hackers target Israeli water utilities", P) == ("IR", ["IL"])
    assert nlp.countries("Pro-Russian hacktivists hit German banks", P) == ("RU", ["DE"])
    assert nlp.countries("Hackers from North Korea steal crypto", P) == ("KP", [])
    assert nlp.countries("Georgia election systems probed", P) == (None, [])  # ambiguous names are skipped
    assert nlp.kinds("Europol takes down botnet; arrests in Germany") == ["botnet", "law"]
    assert nlp.kinds("Dispatcher app update") == []  # "patch" only as a word start
    assert nlp.cves("cve-2026-12345 and CVE-2026-12345, CVE-26-1") == ["CVE-2026-12345"]
    idx = nlp.NameIndex()
    for name, canon in (("APT28", "APT28"), ("Fancy Bear", "APT28"), ("Storm", "X"), ("Cobalt", "Y"), ("Lazarus Group", "Lazarus Group"),
                        ("Kimsuky", "Kimsuky"), ("Iron Tiger", "APT27"), ("Unnamed Actor", "Z"), ("Summit", "S"),
                        ("Guardian of Peace", "Lazarus Group")):
        idx.add(name, canon)
    text = ("Fancy bear and apt28 seen; the kimsuky group; a storm of cobalt; the iron tiger; an unnamed actor at the NATO "
            "Summit; Lazarus Group's Guardian of Peace, Iron Tiger, Fancy Bear")
    assert idx.find(text) == ["APT28", "Lazarus Group", "APT27"]  # lower case, generic words and ambiguous names are skipped
    assert idx.find(text, surface=True) == ["apt28", "Lazarus Group", "Iron Tiger"]
    assert idx.find("Kimsuky targets think tanks") == ["Kimsuky"] and idx.canonical("fancy  BEAR") == "APT28"
    assert nlp.similar(nlp.title_tokens("Russian hackers target German government websites in DDoS wave"),
                       nlp.title_tokens("Russian hackers target German government websites with DDoS attacks"))
    assert not nlp.similar(nlp.title_tokens("Microsoft fixes Exchange zero-day"), nlp.title_tokens("Microsoft fixes Teams bug"))
    rx = nlp.word_matcher(["example.de"], domains=True)
    assert rx.findall("visit www.example.de or example.de.") == ["example.de", "example.de"]
    assert not rx.findall("notexample.de and example.de.evil.com and example.dev")


def test_collect_store_cluster_alerts_images(m):
    setup_data(m)
    assert collect(m) == 7  # 6 + 2 + 1 minus ad, old, linkless
    assert STATE["galaxy"] == 1 and m.actors.count() == 113
    a = m.actors.get("fancy bear")
    assert a["name"] == "APT28" and a["country"] == "RU" and a["refs"] == ["https://attack.mitre.org/groups/G0007/"]
    assert m.actors.get("Vanguard Panda")["country"] == "CN"  # from the CFR state sponsor
    allrows = m.db.query("SELECT * FROM news")
    assert len(allrows) == 7 and not [r for r in allrows if "Sponsored" in r["title"] or "Old story" in r["title"]]
    rows = {r["title"][:20]: r for r in allrows if r["source"] != "bleepingcomputer"}
    rows["QakBot botnet return"] = next(r for r in allrows if r["title"].startswith("QakBot"))
    ddos = rows["Russian hackers targ"]
    assert ddos["url"] == "https://therecord.media/russian-ddos-germany" and ddos["origin"] == "RU" and ddos["origin_by"] == "text"
    assert json.loads(ddos["actors"]) == ["Fancy Bear"] and "ddos" in json.loads(ddos["kinds"])  # as written in the report
    vt = rows["Volt Typhoon still l"]
    assert vt["origin"] == "CN" and vt["origin_by"] == "actor" and json.loads(vt["countries"]) == ["US"]
    qak = rows["QakBot botnet return"]
    assert json.loads(qak["malware"]) == ["QakBot"] and "botnet" in json.loads(qak["kinds"])
    # same event: similar headline (The Record + BleepingComputer), shared CVE (The Record + BSI)
    bleep = next(r for r in allrows if r["source"] == "bleepingcomputer" and "DDoS" in r["title"])
    assert bleep["cluster"] == ddos["cluster"]
    forti = rows["Fortinet patches For"]
    bsi = next(r for r in allrows if r["source"] == "bsi")
    assert bsi["cluster"] == forti["cluster"] and bsi["tier"] == "gov"
    mine = json.loads(forti["mine"])
    assert {x["type"] for x in mine} == {"product", "cve"}  # the vendor of a matched product is not listed twice
    # alerts: domain high, product/CVE medium, the vendor alone none; one alert per event and match
    al = m.db.query("SELECT severity, key, ref, url FROM alerts WHERE source='news' ORDER BY id")
    keys = [(x["severity"], x["key"]) for x in al]
    assert ("high", "news.domain") in keys and ("medium", "news.product") in keys and ("medium", "news.cve") in keys
    assert not [k for k in keys if k[1] == "news.vendor"]
    assert len([k for k in keys if k[1] == "news.cve"]) == 1  # BSI report of the same event does not alert again
    assert all(x["url"].startswith("https://") for x in al)
    # preview images: only from the source's own domain, public addresses, no foreign redirects
    assert m.db.query("SELECT image FROM news WHERE id=?", (forti["id"],))[0]["image"] == "https://cdn.therecord.media/img/forti.jpg"
    assert m.db.query("SELECT image FROM news WHERE id=?", (rows["Phishing campaign sp"]["id"],))[0]["image"] is None
    assert "forbidden" not in STATE  # neither internal.* nor evil.example were contacted
    assert "/fortios-flaw" in STATE["pages"] and len(STATE["pages"]) == 5  # every item without an image, once
    assert m.db.query("SELECT COUNT(*) AS n FROM news WHERE og_tried=1")[0]["n"] == 5
    # status: partial (Krebs 503, CERT-X redirects to a private address); http feed was never configured
    st = {r["source"]: r for r in m.db.statuses()}
    assert st["news"]["ok"] and st["news"]["code"] == "news_partial"
    assert "Krebs" in json.loads(st["news"]["params"])["failed"] and "CERT-X" in json.loads(st["news"]["params"])["failed"]
    assert st["news"]["message"] == "" and m.i18n.render_status(st["news"], "de").startswith("nicht erreichbar: ")
    srcs = {s["id"]: s for s in m.news.source_list()}
    assert set(srcs) == {"bsi", "therecord", "bleepingcomputer", "krebs", "certx"}
    assert srcs["certx"]["ok"] is False and srcs["certx"]["error"] == "redirect_private" and "message" not in srcs["certx"]
    assert srcs["krebs"]["error"] == "http" and srcs["krebs"]["error_params"] == {"status": "503"}
    assert srcs["therecord"]["items_7d"] == 4
    # second run: conditional request, nothing new, no duplicate alerts
    n_alerts = len(al)
    assert collect(m) == 0
    assert STATE["record_hdr"][-1].get("if-none-match") == '"rec-1"'
    assert len(m.db.query("SELECT 1 FROM alerts WHERE source='news'")) == n_alerts and STATE["galaxy"] == 1


def test_overview_detail_and_api(m):
    setup_data(m)
    collect(m)
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        tc.app.state.client = client()
        ov = tc.get("/api/welt", params={"days": 7}).json()
        assert ov["kpis"]["events"] == 5 and ov["kpis"]["items"] == 7 and ov["kpis"]["mine"] == 2
        assert {"origin": "RU", "target": "DE", "n": 1} in ov["pairs"] and ov["home"] == ["AT", "CH", "DE"]
        first = {x["title"][:20]: x for x in ov["items"]}
        dd = first["Russian hackers targ"]
        assert dd["n"] == 2 and set(dd["sources"]) == {"The Record", "BleepingComputer"}
        assert dd["image"] == "https://cdn.therecord.media/img/ddos.jpg"
        fo = next(x for x in ov["items"] if "CVE-2026-1000" in x["cves"])
        assert fo["source"]["tier"] == "gov" and fo["n"] == 2  # the authority heads the event
        assert [x["title"] for x in tc.get("/api/welt", params={"days": 7, "kind": "ddos"}).json()["items"]] == [dd["title"]]
        assert tc.get("/api/welt", params={"days": 7, "origin": "cn"}).json()["kpis"]["events"] == 1
        assert tc.get("/api/welt", params={"days": 7, "country": "DE"}).json()["kpis"]["events"] == 1
        assert tc.get("/api/welt", params={"days": 7, "country": "AT,DE,US"}).json()["kpis"]["events"] == 2
        assert tc.get("/api/welt", params={"days": 7, "country": "DE,XX1"}).status_code == 400
        assert tc.get("/api/welt", params={"days": 7, "mine": "true"}).json()["kpis"]["events"] == 2
        assert tc.get("/api/welt", params={"days": 7, "actor": "apt28"}).json()["kpis"]["events"] == 1
        assert tc.get("/api/welt", params={"days": 7, "tier": "gov"}).json()["kpis"]["events"] == 1
        assert tc.get("/api/welt", params={"days": 7, "confirmed": "true"}).json()["kpis"]["events"] == 2  # DDoS (2 sources), BSI
        assert tc.get("/api/welt", params={"days": 7, "kind": "botnet,ddos"}).json()["kpis"]["events"] == 2
        assert tc.get("/api/welt", params={"days": 7, "q": "qakbot"}).json()["kpis"]["events"] == 1
        assert tc.get("/api/welt", params={"days": 7, "source": "bsi"}).json()["kpis"]["events"] == 1
        for bad in ({"days": 5}, {"kind": "nope"}, {"kind": "ddos,nope"}, {"country": "D1"}, {"source": "unknown_src"}, {"tier": "x"}):
            r = tc.get("/api/welt", params={"days": 7, **bad})
            assert r.status_code in (400, 422), bad
        lst = tc.get("/api/news", params={"days": 30, "limit": 2, "offset": 1}).json()
        assert lst["total"] == 5 and len(lst["items"]) == 2
        det = tc.get(f"/api/news/{fo['id']}").json()
        assert len(det["members"]) == 2 and det["source_countries"] == ["DE", "US"]
        assert det["cve_info"][0]["cve"] == "CVE-2026-1000" and det["cve_info"][0]["kev"] is True and det["cve_info"][0]["ransomware"]
        dd_det = tc.get(f"/api/news/{dd['id']}").json()
        ai = dd_det["actor_info"][0]
        assert (ai["name"], ai["canonical"], ai["confidence"]) == ("Fancy Bear", "APT28", "80") and "APT28" in ai["synonyms"]
        assert ov["actors"][0] == {"name": "Fancy Bear", "canonical": "APT28", "n": 1, "country": "RU"}
        assert dd_det["pair"]["origin"] == "RU" and dd_det["pair"]["target"] == "DE" and len(dd_det["pair"]["labels"]) == 14
        assert sum(dd_det["pair"]["news"]) == 1  # one event, reported twice
        qak = next(x for x in ov["items"] if "QakBot" in x["malware"])
        assert tc.get(f"/api/news/{qak['id']}").json()["malware_info"][0]["c2_30d"] >= 1
        assert tc.get("/api/news/999999").status_code == 404
        # actor object page and search
        page = tc.get("/api/obj", params={"type": "actor", "value": "Fancy Bear"}).json()
        assert page["title"] == "APT28" and page["reports"][0]["id"] == dd["id"]
        assert "ob.f.actor_home" in [f["key"] for f in page["risk"]["reasons"]]
        assert tc.get("/api/obj", params={"type": "actor", "value": "Nobody"}).status_code == 404
        s = tc.get("/api/search", params={"q": "fancy"}).json()
        assert s["actors"][0]["name"] == "APT28"
        assert [x["source"] for x in tc.get("/api/search", params={"q": "cve-2026-1000"}).json()["news"]] == ["BSI", "The Record"]
        assert [x["title"][:6] for x in tc.get("/api/search", params={"q": "QakBot"}).json()["news"]] == ["QakBot"]
        # today: the own domain first (high), then the rest
        today = tc.get("/api/today").json()
        assert today["items"][0]["kind"] == "alert" and today["items"][0]["severity"] == "high"
        assert "example.de" in today["items"][0]["title"]
        st = tc.get("/api/status").json()
        assert st["news"] == {"enabled": True, "images": True, "sources": 5, "actors": 113}
        csp = tc.get("/").headers["content-security-policy"]
        assert "img-src 'self' data: blob: https:;" in csp


def test_gemini_news_and_welt(m):
    setup_data(m)
    collect(m)
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        tc.app.state.client = client()
        ov = tc.get("/api/welt", params={"days": 7}).json()
        ph = next(x for x in ov["items"] if "example.de" in x["title"])
        r = tc.post("/api/ai/news", json={"id": ph["id"]}).json()
        assert r["scope"] == f"news:{ph['id']}" and r["title"] == "Einordnung"
        data = json.loads(PROMPTS[-1].split("<<<\n", 1)[1].rsplit("\n>>>", 1)[0])
        assert data["article"]["title"] == ph["title"] and data["relates_to_own_assets"] is True
        assert "mine" not in json.dumps(data) and "FortiOS" not in json.dumps(data)  # own products are not listed
        assert "laut" in PROMPTS[-1] or "according to" in PROMPTS[-1]
        fu = tc.post("/api/ai/followup", json={"report_id": r["id"], "question": "Wer steckt dahinter?"}).json()
        assert fu["answer"] == "Laut BSI." and ph["title"] in PROMPTS[-1]
        w = tc.post("/api/ai/welt", json={"days": 7}).json()
        assert w["scope"] == "welt:7"
        data = json.loads(PROMPTS[-1].split("<<<\n", 1)[1].rsplit("\n>>>", 1)[0])
        assert data["events_total"] == 5 and data["home_region"] == ["AT", "CH", "DE"]
        assert tc.post("/api/ai/welt", json={"days": 3}).status_code == 400
        assert tc.post("/api/ai/news", json={"id": 999999}).status_code == 404


def test_mine_refresh_retention_and_switches(tmp_path, monkeypatch):
    m = v3.load_app(tmp_path, monkeypatch, NEWS_DISABLE="ncsc_uk,securityweek,golem,krebs", NEWS_IMAGES="0",
                    NEWS_RETENTION_DAYS="7")
    from app import news as news_mod

    async def fake_resolve(host, allow_private, family="any"):
        return ["93.184.216.34"]
    monkeypatch.setattr(news_mod, "resolve", fake_resolve)
    STATE.clear()
    collect(m)
    assert "pages" not in STATE  # NEWS_IMAGES=0: article pages are never fetched
    forti = m.db.query("SELECT id, mine FROM news WHERE title LIKE 'Fortinet%'")[0]
    assert json.loads(forti["mine"]) == []
    m.products.add("Fortinet", "FortiOS")
    assert m.news.refresh_mine() is True and m.news.refresh_mine() is False
    assert {x["type"] for x in json.loads(m.db.query("SELECT mine FROM news WHERE id=?", (forti["id"],))[0]["mine"])} == {"product"}
    assert not m.db.query("SELECT 1 FROM alerts WHERE source='news'")  # re-recognition raises no alerts
    old = (NOW - dt.timedelta(days=9)).strftime("%Y-%m-%dT%H:%M:%SZ")
    m.db.execute("UPDATE news SET published=? WHERE id=?", (old, forti["id"]))
    m.news._prune()
    assert not m.db.query("SELECT 1 FROM news WHERE id=?", (forti["id"],))
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        assert "https:" not in tc.get("/").headers["content-security-policy"].split("img-src", 1)[1].split(";", 1)[0]
        assert all(x["image"] is None for x in tc.get("/api/welt", params={"days": 30}).json()["items"])
    m2 = v3.load_app(tmp_path / "off", monkeypatch, NEWS_ENABLED="0")
    with TestClient(m2.app) as tc:
        assert tc.get("/api/welt").status_code == 404 and tc.get("/api/welt").json()["key"] == "err.news.disabled"
        assert tc.get("/api/today").status_code == 200 and tc.get("/api/search", params={"q": "fancy"}).json()["news"] == []
    asyncio.run(m2.news.collect(client()))
    assert m2.db.query("SELECT COUNT(*) AS n FROM news")[0]["n"] == 0


def test_actor_list_is_not_replaced_by_bad_data(m):
    async def go(payload):
        def h(request):
            return httpx.Response(200, content=payload) if isinstance(payload, bytes) else httpx.Response(200, json=payload)
        async with httpx.AsyncClient(transport=httpx.MockTransport(h)) as c:
            return await m.actors.collect(c, "ua")
    assert asyncio.run(go(galaxy())) == 113
    m.db.meta_set("actors_loaded_at", "2000-01-01T00:00:00Z")
    assert asyncio.run(go({"values": [{"value": "Only One"}]})) == 113  # truncated list keeps the old one
    assert asyncio.run(go(b"not json")) == 113
    assert asyncio.run(go([1, 2])) == 113 and asyncio.run(go({"values": "x"})) == 113
    assert asyncio.run(go({"values": [1, "x", {"value": "Solo", "meta": "bad"}] + galaxy()["values"][:5]})) == 113
    assert m.db.query("SELECT ok FROM source_status WHERE source='misp_actors'")[0]["ok"] == 0


def test_hostile_html_and_broken_redirects_stay_cheap(m):
    """Third-party HTML is parsed with bounded patterns; a broken Location header does not stop a run."""
    import time
    from app import news
    t0 = time.perf_counter()
    assert news._img_from_html("<img " + "a" * 40000 + ">") is None
    assert news._img_from_html(('<img a="' * 30000) + ">") is None
    assert news.og_image("<head><meta " + "a" * 300000 + "></head>") is None
    assert news.parse_feed(b"<rss><channel><item><title>x</title><link>https://a.example/</link><description><![CDATA[<img "
                           + b"a" * 30000 + b">]]></description></item></channel></rss>")[0]["image"] is None
    assert time.perf_counter() - t0 < 2  # quadratic before: about 20 s for the first case alone
    assert news._img_from_html('<p><img alt="" width="640" src="https://cdn.example/a.jpg"></p>') == "https://cdn.example/a.jpg"

    feed = b"<rss><channel><item><title>A report about things</title><link>https://therecord.media/broken</link></item></channel></rss>"

    def h(request):
        if request.url.path == "/feed/":
            return httpx.Response(200, content=feed)
        if request.url.path == "/broken":
            return httpx.Response(302, headers={"location": "https://[zz]/"})
        return httpx.Response(404)
    m.news.sources = [m.news.by_id["therecord"]]
    m.news.by_id = {"therecord": m.news.sources[0]}

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(h)) as c:
            return await m.news.collect(c)
    assert asyncio.run(go()) == 1
    st = {r["source"]: r for r in m.db.statuses()}
    assert st["news"]["ok"] and m.db.query("SELECT og_tried, image FROM news")[0] == {"og_tried": 1, "image": None}


def test_recognition_runs_again_on_the_stored_text(m):
    """Re-recognition (new products, new actor list) sees the same text as the first run, not only the teaser."""
    pid = m.products.add("Fortinet", "FortiOS")
    m.db.insert("INSERT INTO product_cves(product_id, cve, source, first_seen) VALUES(?,?,?,?)", (pid, "CVE-2026-1000", "kev", m.utcnow()))
    desc = ("Officials described a long-running campaign in great detail. " * 5) + "Russian hackers exploited CVE-2026-1000 against Ukrainian targets."
    raw = {"title": "Campaign hits manufacturing sector", "link": "https://therecord.media/x1", "date": None, "desc": desc, "content": "", "image": None}
    assert m.news._store(m.news.by_id["therecord"], raw, m.news._context())
    cols = "origin, countries, cves, mine, length(summary) AS teaser"
    before = m.db.query(f"SELECT {cols} FROM news")[0]
    assert before["origin"] == "RU" and before["cves"] == '["CVE-2026-1000"]' and before["teaser"] <= 262
    m.news.reanalyse(30)
    assert m.db.query(f"SELECT {cols} FROM news")[0] == before
    item = m.news.detail(m.db.query("SELECT id FROM news")[0]["id"])
    assert "body" not in item and len(item["summary"]) <= 262  # the stored text is never served


def test_own_products_and_grouping_rules(m):
    from datetime import timedelta
    from app import nlp
    assert [nlp.distinctive(x) for x in ("FortiOS", "PAN-OS", "Exchange Server", "Firewall", "exchange", "Windows 11")] == \
        [True, True, True, False, False, True]
    m.products.add("Sophos", "Firewall")
    m.products.add("Fortinet", "FortiOS")
    m.products.add("Ivanti", "")
    ctx = m.news._context()
    mine = lambda title: {(x["type"], x["label"]) for x in m.news.analyse(title, "", ctx)["mine"]}  # noqa: E731
    assert mine("New firewall bypass technique published") == set()  # a plain product word alone is no match
    assert mine("Sophos fixes Firewall flaw") == {("product", "Sophos Firewall")}
    assert mine("FortiOS bug exploited") == {("product", "Fortinet FortiOS")}
    assert mine("Ivanti patches Connect Secure") == {("vendor", "Ivanti")}  # vendor-only watch: shown, not alerted
    # grouping: similar headlines more than three days apart are different events
    src = m.news.by_id["therecord"]
    now = dt.datetime.now(dt.timezone.utc)
    base = {"desc": "", "content": "", "image": None}
    assert m.news._store(src, {**base, "title": "Hackers breach water utility in Texas", "link": "https://therecord.media/w1",
                                "date": now - timedelta(days=6)}, ctx)
    assert m.news._store(src, {**base, "title": "Hackers breach water utility in Texas again", "link": "https://therecord.media/w2",
                                "date": now - timedelta(hours=2)}, ctx)
    assert m.news._store(src, {**base, "title": "Hackers breach a water utility in Texas", "link": "https://therecord.media/w3",
                                "date": now - timedelta(hours=1)}, ctx)
    cl = [r["cluster"] for r in m.db.query("SELECT cluster FROM news ORDER BY id")]
    assert cl[0] != cl[1] and cl[1] == cl[2]
    # a patch-day round-up with many CVEs does not glue unrelated reports together
    many = ", ".join(f"CVE-2026-{2000 + i}" for i in range(8))
    assert m.news._store(src, {**base, "title": "Patch day fixes 80 flaws", "link": "https://therecord.media/p1", "date": now,
                                "desc": f"Fixed: {many}."}, ctx)
    assert m.news._store(src, {**base, "title": "Attackers exploit Exchange zero-day", "link": "https://therecord.media/p2", "date": now,
                                "desc": "The flaw CVE-2026-2003 is exploited."}, ctx)
    a, b = m.db.query("SELECT cluster FROM news WHERE url LIKE '%/p_' ORDER BY id")
    assert a["cluster"] != b["cluster"]
    assert m.news._store(src, {**base, "title": "CISA adds Exchange flaw to KEV", "link": "https://therecord.media/p3", "date": now,
                                "desc": "CVE-2026-2003 was added."}, ctx)
    assert m.db.query("SELECT cluster FROM news WHERE url LIKE '%/p3'")[0]["cluster"] == b["cluster"]
    # broken dates and IPv6 hosts
    from app import news
    assert news._date("Mon, 01 Jan 99999 00:00:00 GMT") is None and news._date("not a date") is None
    assert news.clean_url("http://[2001:db8::1]:8443/x") == "https://[2001:db8::1]:8443/x"
    assert [s.lang for s in news.parse_extra("a1|A|https://a.example/f|gov|<s;b2|B|https://b.example/f|press|DE")] == ["en", "de"]


# --- 3.2.1: findings of the independent review --------------------------------------------------------------------------
def test_preview_images_never_point_into_the_lan(m):
    """The browser loads preview images from inside the LAN: address literals, internal names, odd ports and names that
    resolve to private addresses are dropped (feed images, og:image, and images stored by 3.2.0)."""
    from app import news
    for bad in ("https://10.0.0.1/a.jpg", "https://192.168.178.1/cgi-bin/x", "https://[fd00::1]/a", "https://router.lan:8443/x",
                "https://nas/x.png", "https://nas.fritz.box/x.png", "https://0x7f.0.0.1/x", "https://2130706433/x",
                "https://8.8.8.8/x.png", "https://cdn.example:8443/x.png", "https://intranet.corp/i.png"):
        assert news.clean_url(bad, image=True) is None, bad
    assert news.clean_url("http://cdn.example:80/i.png", image=True) == "https://cdn.example/i.png"
    assert news.clean_url("https://10.0.0.1/article") == "https://10.0.0.1/article"  # links are not loaded by the browser
    assert news._img_from_html('<img width="600" src="https://192.168.178.1/cgi-bin/x"><img src="https://cdn.example/b.jpg">') \
        == "https://cdn.example/b.jpg"
    assert news.og_image("<head><meta property='og:image' content='https://10.0.0.1/x.jpg'></head>") is None
    # a public-looking name that resolves to a private address (stub: "internal." hosts are private)
    feed = (b"<rss><channel><item><title>Report with a sneaky image</title><link>https://therecord.media/sneaky</link>"
            b"<enclosure url='https://internal.cdn.example/x.jpg' type='image/jpeg'/></item>"
            b"<item><title>Report with a good image</title><link>https://therecord.media/good</link>"
            b"<enclosure url='https://cdn.therecord.media/g.jpg' type='image/jpeg'/></item>"
            b"<item><title>Report with an og image inside</title><link>https://therecord.media/og-internal</link></item>"
            b"</channel></rss>")
    page = b"<html><head><meta property='og:image' content='https://internal.therecord.media/o.jpg'></head>"

    def h(request):
        if request.url.path == "/feed/":
            return httpx.Response(200, content=feed)
        if request.url.path == "/og-internal":
            return httpx.Response(200, content=page, headers={"content-type": "text/html"})
        return httpx.Response(404)
    m.news.sources = [m.news.by_id["therecord"]]
    m.news.by_id = {"therecord": m.news.sources[0]}
    old = m.db.insert("INSERT INTO news(source, url, title, image, published, fetched_at, lang, tier) VALUES(?,?,?,?,?,?,?,?)",
                      ("therecord", "https://therecord.media/old", "Stored by 3.2.0", "https://10.0.0.1/old.jpg", iso(2), iso(2),
                       "en", "press"))

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(h)) as c:
            return await m.news.collect(c)
    assert asyncio.run(go()) == 3
    img = {r["url"].rsplit("/", 1)[1]: r["image"] for r in m.db.query("SELECT url, image FROM news")}
    assert img == {"sneaky": None, "good": "https://cdn.therecord.media/g.jpg", "og-internal": None, "old": None}
    assert m.db.meta_get("news_images_v2") == "1" and old


def test_own_products_match_whole_words_and_every_watch(m):
    m.products.add("HP", "Printer")
    m.products.add("SAP", "Router")
    m.products.add("Cisco", "Firewall")
    m.products.add("Zyxel", "Firewall")
    ctx = m.news._context()
    mine = lambda title, text="": {(x["type"], x["label"]) for x in m.news.analyse(title, text, ctx)["mine"]}  # noqa: E731
    assert mine("Critical PHP bug lets attackers hijack printer fleets", "Details at https://example.org") == set()
    assert mine("Sapphire Sleet targets router admins") == set()
    assert mine("HP printers hit by flaw") == {("vendor", "HP")}  # "printers" is not the watched word "Printer"
    assert mine("HP Printer firmware flaw exploited") == {("product", "HP Printer")}
    assert mine("Cisco firewall flaw exploited") == {("product", "Cisco Firewall")}  # not hidden by Zyxel Firewall
    assert mine("Zyxel and Cisco firewall flaws") == {("product", "Cisco Firewall"), ("product", "Zyxel Firewall")}
    assert mine("SAP patches NetWeaver") == {("vendor", "SAP")}  # a vendor named without a watched product: no alert


def test_home_region_of_any_size_and_late_reports(tmp_path, monkeypatch):
    region = "DE,AT,CH,FR,NL,BE,LU,PL,CZ,DK,SE,NO,FI,IT"
    m = v3.load_app(tmp_path, monkeypatch, HOME_REGION=region, NEWS_DISABLE="ncsc_uk,securityweek,golem,krebs")
    src = m.news.by_id["therecord"]
    ctx = m.news._context()
    now = dt.datetime.now(dt.timezone.utc)
    base = {"desc": "", "content": "", "image": None}
    assert m.news._store(src, {**base, "title": "Hackers hit Italian water utility", "link": "https://therecord.media/it1",
                               "date": now - dt.timedelta(hours=1)}, ctx)
    assert m.news._store(src, {**base, "title": "Ransomware hits Finnish city", "link": "https://therecord.media/fi1",
                               "date": now - dt.timedelta(hours=2)}, ctx)
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        r = tc.get("/api/welt", params={"days": 7, "country": "region"})
        assert r.status_code == 200 and r.json()["kpis"]["events"] == 2 and r.json()["kpis"]["home"] == 2
        assert tc.get("/api/news", params={"days": 7, "country": "region"}).json()["total"] == 2
        assert tc.get("/api/welt", params={"days": 7, "country": ",".join(region.split(",")[:13])}).status_code == 400
        # ids beyond SQLite integers are bad requests, not server errors
        assert tc.get("/api/news/99999999999999999999").status_code == 422
        assert tc.post("/api/ai/news", json={"id": 10 ** 20}).status_code == 422
        assert tc.get("/api/assets/99999999999999999999").status_code == 400
    # a late report (new source, delayed feed) joins its stored counterpart from four and a half days ago
    assert m.news._store(src, {**base, "title": "Hackers breach water utility in Texas", "link": "https://therecord.media/t1",
                               "date": now - dt.timedelta(days=4, hours=12)}, ctx)
    ctx = m.news._context()
    assert m.news._store(src, {**base, "title": "Hackers breach a water utility in Texas", "link": "https://therecord.media/t2",
                               "date": now - dt.timedelta(days=4)}, ctx)
    t1, t2 = m.db.query("SELECT cluster FROM news WHERE url LIKE '%/t_' ORDER BY id")
    assert t1["cluster"] == t2["cluster"]


def test_validators_are_stored_only_after_a_successful_parse(m):
    """A feed that fails to parse is fetched in full again (no 304 that would hide the error) and its error is a code."""
    bad = b'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY nbsp "&#160;">]><rss><channel><item><title>x&nbsp;</title></item></channel></rss>'
    good = b"<rss><channel><item><title>Fine report</title><link>https://therecord.media/fine</link></item></channel></rss>"
    seen = []
    body = {"v": bad}

    def h(request):
        if request.url.path == "/feed/":
            seen.append(request.headers.get("if-none-match"))
            if request.headers.get("if-none-match") == '"v1"' and body["v"] is good:
                return httpx.Response(304)
            return httpx.Response(200, content=body["v"], headers={"etag": '"v1"'})
        return httpx.Response(404)
    m.news.sources = [m.news.by_id["therecord"]]
    m.news.by_id = {"therecord": m.news.sources[0]}

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(h)) as c:
            return await m.news.collect(c)
    for _ in range(2):
        assert asyncio.run(go()) == 0
        assert m.news.source_list()[0]["ok"] is False and m.news.source_list()[0]["error"] == "entities"
    assert seen == [None, None] and m.db.meta_get("news_etag:therecord") is None
    body["v"] = good
    assert asyncio.run(go()) == 1 and m.db.meta_get("news_etag:therecord") == '"v1"'
    assert asyncio.run(go()) == 0 and seen[-1] == '"v1"' and m.news.source_list()[0]["ok"] is True


def test_outage_detail_and_cable_sentence_are_separated():
    from app import i18n
    pr = {"event": {}, "cables": {"count": 7, "snapshot": "2021-06", "names": ["C-Lion1"]}}
    orig = i18n.render_infra_detail
    try:
        i18n.render_infra_detail = lambda ev, lang: "Submarine cable damaged; Germany; Networks: DTAG"
        p = i18n.render_pattern({"key": "infra.critical", "params": pr, "severity": "medium", "category": "infra"}, "en",
                                lambda cc, lang: cc or "")
    finally:
        i18n.render_infra_detail = orig
    assert "Networks: DTAG. 7 submarine cables land there" in p["detail"]
