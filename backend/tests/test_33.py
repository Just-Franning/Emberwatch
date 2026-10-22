"""Tests for 3.3: comparison with measurements, submarine cables, OONI, GDELT, MITRE ATT&CK, EUVD, public exploits,
URLhaus and platform outages.

Upstream answers are mocked in the documented formats (OONI aggregation API, GDELT DOC 2.0 artlist, STIX 2.1 bundle,
EUVD API, Metasploit module metadata, Nuclei cves.json, URLhaus API v1, RSS/Atom status feeds, Statuspage API v2).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import io
import json
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v3 as v3  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)
TODAY = NOW.date()


def day(n: int) -> str:
    return (TODAY - dt.timedelta(days=n)).isoformat()


def iso(hours: float) -> str:
    return (NOW - dt.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rfc822(hours: float) -> str:
    from email.utils import format_datetime
    return format_datetime(NOW - dt.timedelta(hours=hours))


def run(coro):
    return asyncio.run(coro)


def mock(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture()
def m(tmp_path, monkeypatch):
    mod = v3.load_app(tmp_path, monkeypatch, HOME_REGION="DE,AT,CH", LANGUAGE="en",
                      NEWS_DISABLE="ncsc_uk,securityweek,golem,krebs,bsi,bleepingcomputer,cert_eu,cisa,heise")
    from app import news as news_mod

    async def fake_resolve(host, allow_private, family="any"):
        return ["93.184.216.34"]
    monkeypatch.setattr(news_mod, "resolve", fake_resolve)
    return mod


def store(m, title, desc="", hours=2, source="therecord", **kw):
    src = m.news.by_id[source]
    raw = {"title": title, "link": kw.pop("link", f"https://therecord.media/{abs(hash((title, hours))) % 10**9}"),
           "date": NOW - dt.timedelta(hours=hours), "desc": desc, "content": "", "image": None, **kw}
    assert m.news._store(src, raw, m.news._context())
    return m.db.query("SELECT id FROM news ORDER BY id DESC LIMIT 1")[0]["id"]


# --- configuration and feeds --------------------------------------------------------------------------------------------
def test_sources_disable_and_new_feeds(tmp_path, monkeypatch):
    m = v3.load_app(tmp_path, monkeypatch, SOURCES_DISABLE="ooni, GDELT,unknown,attack")
    assert m.S.sources_disable == frozenset({"ooni", "gdelt", "attack"})
    assert not m.S.source_on("ooni") and m.S.source_on("euvd") and not m.news.web_enabled
    ids = [s.id for s in m.news.sources]
    assert {"cert_eu", "cisa", "heise"} <= set(ids) and "gdelt" not in ids
    srcs = {s.id: s for s in m.news.sources}
    assert srcs["cert_eu"].tier == "gov" and srcs["cisa"].tier == "gov" and srcs["heise"].tier == "press" and srcs["heise"].lang == "de"
    from app import news
    # "gdelt" is reserved and the tier "web" cannot be configured for a feed
    extra = news.parse_extra("gdelt|X|https://a.example/f|gov;own|Own|https://b.example/f|web")
    assert [(x.id, x.tier) for x in extra] == [("gdelt", "gov"), ("own", "press")]
    m2 = v3.load_app(tmp_path / "b", monkeypatch, SOURCES_DISABLE="", NEWS_FEEDS="gdelt|X|https://a.example/f|gov")
    assert m2.news.by_id["gdelt"].tier == "web"  # the reserved id stays the worldwide press


def test_new_kinds_and_cable_names(m):
    from app import nlp
    assert "cable" in nlp.kinds("Subsea cable between Finland and Germany damaged")
    assert "cable" in nlp.kinds("Ostseekabel beschädigt") and "cable" not in nlp.kinds("Kabelfernsehen wird teurer")
    assert "shutdown" in nlp.kinds("Iran imposes internet shutdown during protests")
    cab = m.cables
    found = cab.find("The C-Lion1 cable and the EESF-2 link were damaged; Dunant is fine")
    names = [cab.cables[i]["name"] for i in found]
    assert names[:3] == ["C-Lion1", "Finland-Estonia 2 (EESF-2)", "Dunant"]
    assert cab.find("an ace up the sleeve") == [] and cab.find("C-Lion12") == []  # short forms as written, whole words
    # in reports: only in a report about submarine cables
    i1 = store(m, "Undersea cable C-Lion1 between Finland and Germany damaged", hours=3)
    i2 = store(m, "Dunant wins award for humanitarian work", hours=4)
    rows = {r["id"]: json.loads(r["cables"] or "[]") for r in m.db.query("SELECT id, cables FROM news")}
    assert [m.cables.cables[c]["name"] for c in rows[i1]] == ["C-Lion1"] and rows[i2] == []
    d = m.news.detail(i1)
    assert d["cable_info"][0]["name"] == "C-Lion1" and d["cable_info"][0]["countries"] == ["DE", "FI"]
    # landing points carry the country, not a territory of the same sovereign state (Åland, Greenland, South Georgia)
    assert "C-Lion1" in m.cables.for_country("FI")["cables"] and "C-Lion1" not in m.cables.for_country("AX")["cables"]
    assert m.cables.for_country("GB")["cables"] and not m.cables.for_country("GS")["cables"]
    ov = m.news.overview(7, ["DE"])
    assert list(ov["cables"].values()) == [1]


# --- comparison with measurements --------------------------------------------------------------------------------------
def _radar(m, cc_values: dict[int, float], cc="DE", metric="l7_target_1d"):
    for n in range(0, 20):
        rows = [{"target": "US", "value": 30.0}]
        if n in cc_values:
            rows.append({"target": cc, "value": cc_values[n]})
        m.db.hist_set(metric, day(n), {"rows": rows, "final": 1})


def test_ddos_report_against_cloudflare(m):
    from app import corroborate as cb
    _radar(m, {**{n: 2.0 for n in range(2, 16)}, 0: 6.5, 1: 3.0})  # DE: 2 % for two weeks, 6.5 % today
    _radar(m, {n: 1.0 for n in range(0, 16)}, metric="l3_target_1d")  # flat in L3
    ev = cb.Evidence(m.db)
    c = ev.ddos("DE", TODAY)
    assert c["result"] == cb.SUPPORTED and c["params"]["l7"] == {"value": 6.5, "baseline": 2.0, "entered": False}
    assert c["params"]["l3"]["value"] == 1.0
    assert ev.ddos("FR", TODAY)["result"] == cb.UNCLEAR  # outside the top 25: no judgement
    m.db.execute("DELETE FROM radar_hist")
    _radar(m, {n: 2.0 for n in range(0, 16)})
    _radar(m, {n: 1.0 for n in range(0, 16)}, metric="l3_target_1d")
    assert cb.Evidence(m.db).ddos("DE", TODAY)["result"] == cb.NOT_SUPPORTED
    m.db.execute("DELETE FROM radar_hist")
    _radar(m, {0: 1.2})  # never in the top 25 before: entered
    assert cb.Evidence(m.db).ddos("DE", TODAY)["params"]["l7"]["entered"] is True
    m.db.execute("DELETE FROM radar_hist WHERE day < ?", (day(4),))  # too little history
    assert cb.Evidence(m.db).ddos("DE", TODAY)["result"] == cb.UNCLEAR


def test_checks_are_stored_merged_and_explained(m):
    from app import corroborate as cb
    _radar(m, {**{n: 2.0 for n in range(2, 16)}, 0: 7.0})
    m.db.execmany("INSERT INTO victims(id, victim, grp, country, discovered) VALUES(?,?,?,?,?)",
                  [(f"v{i}", f"victim{i}.example", "akira", "DE", iso(24 * i)) for i in range(1, 4)])
    m.db.execute("INSERT INTO infra_events(id, kind, start_ts, end_ts, countries, asns, cause, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                 ("outage:1", "outage", iso(20), None, '["FI"]', "[]", "CABLE_CUT", iso(1)))
    m.db.meta_set("outages_covered_since", day(30))
    m.db.execute("INSERT INTO kev(cve, vendor, product, name, date_added) VALUES(?,?,?,?,?)",
                 ("CVE-2026-1111", "Acme", "Gate", "x", day(3)))
    ddos = store(m, "Pro-Russian hacktivists claim DDoS attacks on German government sites", hours=2)
    ransom = store(m, "Akira ransomware hits German manufacturer", hours=3)
    cable = store(m, "Undersea cable between Finland and Estonia damaged", hours=5)
    quiet = store(m, "Undersea cable near Portugal damaged, says operator", hours=24 * 3)
    fresh = store(m, "Undersea cable near Malta damaged, says operator", hours=6)
    cve = store(m, "Hackers exploit CVE-2026-1111 in Acme Gate", hours=7)
    plain = store(m, "New guidance on password managers published", hours=8)
    m.news.refresh_checks()
    got = {r["id"]: json.loads(r["checks"]) if r["checks"] else None for r in m.db.query("SELECT id, checks FROM news")}
    assert got[ddos]["verdict"] == cb.SUPPORTED and got[ddos]["checks"][0]["type"] == "ddos"
    assert got[ransom]["checks"][0] == {"type": "ransomware", "subject": "Akira", "result": cb.SUPPORTED,
                                        "params": {"posts": 1, "in_countries": 1}} or got[ransom]["checks"][0]["params"]["posts"] >= 1
    assert got[cable]["verdict"] == cb.SUPPORTED and got[cable]["checks"][0]["params"]["causes"] == ["CABLE_CUT"]
    assert got[quiet]["verdict"] == cb.NOT_SUPPORTED  # outages are covered for the window, none in Portugal
    assert got[fresh]["verdict"] == cb.UNCLEAR  # the window is still open: outages may still be reported
    assert got[cve]["checks"] == [{"type": "cve", "subject": "CVE-2026-1111", "result": cb.SUPPORTED,
                                   "params": {"by": "kev", "since": day(3)}}]
    assert got[plain] is None
    ov = m.news.overview(7, ["DE"])
    assert ov["kpis"]["supported"] == 4
    item = m.news.detail(ddos)
    assert item["checks"]["verdict"] == cb.SUPPORTED
    ctx = m.news.ai_item(item)
    assert ctx["comparison_with_measurements"]["verdict"] == cb.SUPPORTED
    merged = cb.merge([{"checks": [{"type": "ddos", "subject": "DE", "result": cb.NOT_SUPPORTED, "params": {}}]},
                       {"checks": [{"type": "ddos", "subject": "DE", "result": cb.SUPPORTED, "params": {}}]}, None,
                       {"checks": [{"type": "x", "subject": "y", "result": "bogus"}]}])
    assert merged == {"verdict": cb.SUPPORTED, "checks": [{"type": "ddos", "subject": "DE", "result": cb.SUPPORTED, "params": {}}]}
    assert cb.merge([None, {}]) is None


# --- GDELT ---------------------------------------------------------------------------------------------------------------
GDELT_EN = json.dumps({"articles": [
    {"url": "http://news.example/a1", "title": "Russian hackers target German ministries in DDoS wave", "seendate":
     NOW.strftime("%Y%m%dT%H%M%SZ"), "domain": "news.example", "language": "English", "sourcecountry": "United States"},
    {"url": "https://other.example/b", "title": "Ransomware gang hits hospital\x01 chain", "seendate": "bad", "language": "English"},
    {"url": "", "title": "no link"}, "junk",
]}).replace("\\u0001", "\x01").encode()


def test_gdelt_worldwide_press_is_separate(m, monkeypatch):
    from app.sources import gdelt
    monkeypatch.setattr(gdelt, "PAUSE_S", 0)
    assert m.news.web_enabled and "gdelt" in m.news.by_id
    calls = []

    def h(request):
        calls.append(dict(request.url.params))
        if "sourcelang:german" in request.url.params["query"]:
            return httpx.Response(200, content=b"<html>Invalid query</html>", headers={"content-type": "text/html"})
        return httpx.Response(200, content=GDELT_EN, headers={"content-type": "application/json"})
    m.products.add("Fortinet", "FortiOS")
    store(m, "Russian hackers target German ministries in DDoS wave", hours=1)  # the same headline, curated
    assert run(m.news.collect_web(mock(h))) == 2
    assert calls[0]["mode"] == "artlist" and calls[0]["format"] == "json" and int(calls[0]["maxrecords"]) <= 250
    web = m.db.query("SELECT url, tier, image, cluster, id FROM news WHERE source = 'gdelt' ORDER BY id")
    assert [w["url"] for w in web] == ["https://news.example/a1", "https://other.example/b"] and all(w["tier"] == "web" for w in web)
    curated = m.db.query("SELECT cluster FROM news WHERE source = 'therecord'")[0]["cluster"]
    assert web[0]["cluster"] != curated  # never grouped with curated reports
    assert not m.db.query("SELECT 1 FROM alerts WHERE source = 'news'")
    assert m.news.listing(7)["total"] == 1 and m.news.listing(7, tier="web")["total"] == 2
    assert m.news.listing(7, source="gdelt")["total"] == 2
    st = {r["source"]: r for r in m.db.statuses()}
    assert st["gdelt"]["ok"] and st["gdelt"]["count"] == 2
    srcs = {s["id"]: s for s in m.news.source_list()}
    assert srcs["gdelt"]["tier"] == "web" and srcs["gdelt"]["ok"] is True
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        assert tc.get("/api/news", params={"days": 7, "tier": "web"}).json()["total"] == 2
        assert tc.get("/api/welt", params={"days": 7}).json()["kpis"]["events"] == 1
        assert tc.get("/api/search", params={"q": "ministries"}).json()["news"][0]["source"] == "The Record"
    # retention of the web tier
    m.db.execute("UPDATE news SET published = ? WHERE source = 'gdelt'", (iso(24 * 20),))
    m.news._prune()
    assert not m.db.query("SELECT 1 FROM news WHERE tier = 'web'") and m.db.query("SELECT 1 FROM news WHERE tier != 'web'")
    with pytest.raises(ValueError):
        gdelt.parse(b"<html>nope</html>", "en")


def test_gdelt_off_and_failures(tmp_path, monkeypatch):
    m = v3.load_app(tmp_path, monkeypatch, SOURCES_DISABLE="gdelt")
    assert not m.news.web_enabled and "gdelt" not in m.news.by_id
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        assert tc.get("/api/news", params={"days": 7, "tier": "web"}).status_code == 400
    m2 = v3.load_app(tmp_path / "b", monkeypatch, SOURCES_DISABLE="")
    from app.sources import gdelt
    monkeypatch.setattr(gdelt, "PAUSE_S", 0)
    assert run(m2.news.collect_web(mock(lambda r: httpx.Response(503)))) == 0
    assert {s["id"]: s for s in m2.news.source_list()}["gdelt"]["error"] == "other"


# --- OONI ----------------------------------------------------------------------------------------------------------------
def ooni_body(test):
    rows = []
    for n in range(0, 9):
        rows.append({"measurement_start_day": day(n), "probe_cc": "IR", "measurement_count": 400, "anomaly_count": 120,
                     "confirmed_count": 30 if test == "web" else 0, "failure_count": 5, "ok_count": 245})
        rows.append({"measurement_start_day": day(n), "probe_cc": "DE", "measurement_count": 900, "anomaly_count": 9,
                     "confirmed_count": 0, "failure_count": 1, "ok_count": 890})
    rows.append({"measurement_start_day": day(1), "probe_cc": "ZZ", "measurement_count": 5, "anomaly_count": 0,
                 "confirmed_count": 0, "failure_count": 0, "ok_count": 5})
    rows.append({"measurement_start_day": "bad", "probe_cc": "FR", "measurement_count": 1})
    return {"v": 0, "dimension_count": 2, "db_stats": {}, "result": rows}


def test_ooni_collect_summary_and_blocking_api(m):
    from app.sources import ooni
    seen = []

    def h(request):
        p = dict(request.url.params)
        seen.append(p)
        assert request.url.host == "api.ooni.io" and request.url.path == "/api/v1/aggregation"
        return httpx.Response(200, json=ooni_body("web" if p["test_name"] == "web_connectivity" else "im"))
    run(ooni.collect(mock(h), m.db, "ua"))
    assert seen[0]["axis_x"] == "measurement_start_day" and seen[0]["axis_y"] == "probe_cc" and seen[1]["test_name"].startswith("whatsapp")
    assert (TODAY - dt.date.fromisoformat(seen[0]["since"])).days == ooni.FIRST_DAYS
    run(ooni.collect(mock(h), m.db, "ua"))
    assert (TODAY - dt.date.fromisoformat(seen[2]["since"])).days == ooni.UPDATE_DAYS  # later runs: only the last days
    assert not m.db.query("SELECT 1 FROM ooni WHERE cc IN ('ZZ', 'FR')")
    s = {x["cc"]: x for x in ooni.summary(m.db, 7)}
    assert s["IR"]["confirmed"] == 7 * 30 and s["IR"]["anomaly_pct"] == 30.0 and s["IR"]["im_anomaly_pct"] == 30.0
    assert s["DE"]["confirmed"] == 0 and list(s)[0] == "IR"
    st = {r["source"]: r for r in m.db.statuses()}
    assert st["ooni"]["ok"] and st["ooni"]["count"] == 2
    m.db.execute("INSERT INTO infra_events(id, kind, start_ts, end_ts, countries, asns, cause, scope, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                 ("outage:9", "outage", iso(30), None, '["IR"]', "[]", "GOVERNMENT_DIRECTED", "country", iso(1)))
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        b = tc.get("/api/welt/blocking", params={"days": 7}).json()
        assert b["enabled"] and b["countries"][0]["cc"] == "IR" and b["shutdowns"][0]["countries"] == ["IR"]
        assert tc.get("/api/welt/blocking", params={"days": 5}).status_code == 400
    # an OONI check in a report about censorship
    i = store(m, "Iran imposes internet shutdown as protests spread in Iran", hours=2)
    m.news.refresh_checks()
    chk = json.loads(m.db.query("SELECT checks FROM news WHERE id=?", (i,))[0]["checks"])
    assert {c["type"] for c in chk["checks"]} >= {"ooni", "outage"} and chk["verdict"] == "supported"
    run(ooni.collect(mock(lambda r: httpx.Response(500)), m.db, "ua"))
    assert not {r["source"]: r for r in m.db.statuses()}["ooni"]["ok"]


# --- MITRE ATT&CK ----------------------------------------------------------------------------------------------------------
def bundle(extra=0) -> str:
    def ref(eid, kind):
        return [{"source_name": "mitre-attack", "external_id": eid, "url": f"https://attack.mitre.org/{kind}/{eid.replace('.', '/')}"}]
    objs = [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "20.0", "modified": "2026-10-13T12:00:00.000Z"},
        {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "tactic_refs": ["x-mitre-tactic--ia", "x-mitre-tactic--c2"]},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--c2", "name": "Command and Control", "x_mitre_shortname": "command-and-control",
         "external_references": ref("TA0011", "tactics")},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--ia", "name": "Initial Access", "x_mitre_shortname": "initial-access",
         "external_references": ref("TA0001", "tactics")},
        {"type": "intrusion-set", "id": "intrusion-set--apt28", "name": "APT28", "aliases": ["APT28", "Fancy Bear", "Sofacy"],
         "external_references": ref("G0007", "groups")},
        {"type": "intrusion-set", "id": "intrusion-set--old", "name": "Old Group", "revoked": True,
         "external_references": ref("G0999", "groups")},
        {"type": "attack-pattern", "id": "attack-pattern--spear", "name": "Spearphishing Attachment", "x_mitre_is_subtechnique": True,
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
         "external_references": ref("T1566.001", "techniques")},
        {"type": "attack-pattern", "id": "attack-pattern--web", "name": "Web Protocols",
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "command-and-control"}],
         "external_references": ref("T1071.001", "techniques")},
        {"type": "attack-pattern", "id": "attack-pattern--dep", "name": "Deprecated", "x_mitre_deprecated": True,
         "external_references": ref("T1999", "techniques")},
        {"type": "malware", "id": "malware--qakbot", "name": "QakBot", "x_mitre_aliases": ["QakBot", "Qbot"],
         "external_references": ref("S0650", "software")},
        {"type": "tool", "id": "tool--cs", "name": "Cobalt Strike", "external_references": ref("S0154", "software")},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "uses", "source_ref": "intrusion-set--apt28",
         "target_ref": "attack-pattern--spear"},
        {"type": "relationship", "id": "relationship--2", "relationship_type": "uses", "source_ref": "intrusion-set--apt28",
         "target_ref": "attack-pattern--web"},
        {"type": "relationship", "id": "relationship--3", "relationship_type": "uses", "source_ref": "intrusion-set--apt28",
         "target_ref": "tool--cs"},
        {"type": "relationship", "id": "relationship--4", "relationship_type": "uses", "source_ref": "malware--qakbot",
         "target_ref": "attack-pattern--web"},
        {"type": "relationship", "id": "relationship--5", "relationship_type": "uses", "source_ref": "intrusion-set--apt28",
         "target_ref": "attack-pattern--dep"},
        {"type": "relationship", "id": "relationship--6", "relationship_type": "mitigates", "source_ref": "course-of-action--x",
         "target_ref": "attack-pattern--web"},
    ]
    objs += [{"type": "attack-pattern", "id": f"attack-pattern--f{i}", "name": f"Filler {i} with \\\"quotes\\\" ]", "external_references":
              ref(f"T{2000 + i}", "techniques")} for i in range(extra)]
    return json.dumps({"type": "bundle", "id": "bundle--1", "spec_version": "2.1", "objects": objs}, indent=1)


def test_stix_stream_parser_and_actor_pages(m, monkeypatch):
    from app import attack
    text = bundle(extra=600)
    monkeypatch.setattr(attack, "CHUNK", 257)  # objects across many chunk boundaries
    rows, uses, info, order = attack.parse(io.StringIO(text))
    assert info == {"version": "20.0", "year": "2026"} and order == ["x-mitre-tactic--ia", "x-mitre-tactic--c2"]
    ids = {r[2] for r in rows}
    assert {"G0007", "T1566.001", "T1071.001", "S0650", "S0154", "TA0011"} <= ids and not ids & {"G0999", "T1999"}
    assert ("intrusion-set--apt28", "attack-pattern--dep") not in uses and len(uses) == 4
    with pytest.raises(ValueError):
        list(attack.iter_objects(io.StringIO(text[: len(text) // 2])))
    monkeypatch.setattr(attack, "CHUNK", 1 << 20)
    hits = []

    def h(request):
        hits.append(request.headers.get("if-none-match"))
        if request.headers.get("if-none-match") == '"b1"':
            return httpx.Response(304)
        return httpx.Response(200, content=text.encode(), headers={"etag": '"b1"'})
    assert run(m.attack.collect(mock(h), "ua")) is True
    assert run(m.attack.collect(mock(h), "ua")) is False and hits == [None, '"b1"']
    assert not (m.S.data_dir / "attack.download").exists()
    g = m.attack.group_for(["Fancy Bear"])
    assert g["ext_id"] == "G0007"
    used = m.attack.used_by(g["stix_id"])
    assert [t["id"] for t in used["techniques"]] == ["T1566.001", "T1071.001"]  # matrix order of the tactics
    assert used["techniques"][0]["tactics"][0]["name"] == "Initial Access" and used["software"][0]["name"] == "Cobalt Strike"
    assert m.attack.software_for("qbot")["ext_id"] == "S0650"
    # a truncated download does not replace good data
    assert run(m.attack.collect(mock(lambda r: httpx.Response(200, content=text[:5000].encode())), "ua")) is False
    assert m.attack.group_for(["APT28"]) is not None
    # object pages
    m.db.execute("INSERT INTO actors(name, country, synonyms, victims, targets, sectors, refs, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                 ("APT28", "RU", '["Fancy Bear"]', "[]", "[]", "[]", "[]", iso(1)))
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        page = tc.get("/api/obj", params={"type": "actor", "value": "APT28"}).json()
        sec = next(s for s in page["sections"] if s.get("title", "").startswith("Techniques according to MITRE ATT&CK"))
        assert sec["rows"][0][0] == "Initial Access" and sec["rows"][0][1][0]["t"] == "T1566.001 Spearphishing Attachment"
        assert sec["rows"][1][0] == "Command and Control" and "© 2026 The MITRE Corporation" in sec["note"]
        from app.objects import object_context
        ctx = object_context(page)
        assert any(r == ["Initial Access", "T1566.001 Spearphishing Attachment"] for x in ctx["sections"] for r in x.get("rows", []))
        mal = tc.get("/api/obj", params={"type": "malware", "value": "QakBot"}).json()
        assert any((s.get("title") or "").startswith("MITRE ATT&CK (S0650)") for s in mal["sections"])


# --- EUVD and public exploits ---------------------------------------------------------------------------------------------
EUVD = {"items": [
    {"id": "EUVD-2025-11154", "aliases": "CVE-2026-2222\n", "exploitedSince": "Apr 9, 2025, 12:00:00 AM", "baseScore": 9.8,
     "epss": 0.24, "datePublished": "Apr 16, 2025, 7:00:16 AM",
     "enisaIdVendor": [{"id": "x", "vendor": {"name": "Totolink"}}], "enisaIdProduct": [{"id": "y", "product": {"name": "A3700R"}}]},
    {"id": "bogus", "aliases": "CVE-2026-3333"}, {"id": "EUVD-2025-1", "aliases": "no cve"}, "junk",
], "total": 4}


def test_euvd_and_exploits(m):
    from app.sources import euvd, exploits
    pages = []

    def h(request):
        assert request.headers["user-agent"].startswith("emberwatch/")
        pages.append(request.url.params["page"])
        return httpx.Response(200, json=EUVD if request.url.params["page"] == "0" else {"items": [], "total": 4})
    run(euvd.collect(mock(h), m.db, m.S.user_agent))
    assert pages == ["0"]  # fewer items than a page: done
    row = m.db.query("SELECT * FROM euvd")
    assert len(row) == 1 and row[0]["cve"] == "CVE-2026-2222" and row[0]["exploited_since"] == "2025-04-09"
    assert row[0]["vendor"] == "Totolink" and row[0]["score"] == 9.8
    msf = {"exploit_x": {"type": "exploit", "fullname": "exploit/linux/http/acme_rce", "name": "Acme RCE", "rank": 600,
                         "disclosure_date": "2026-01-02", "path": "/modules/exploits/linux/http/acme_rce.rb",
                         "references": ["CVE-2026-2222", "URL-https://x.example"]},
           "aux_y": {"type": "auxiliary", "fullname": "auxiliary/scanner/y", "references": ["CVE-2026-4444"]},
           "evil": {"type": "exploit", "fullname": "exploit/../../etc", "path": "/modules/../../x", "references": ["CVE-2026-5555"]}}
    msf.update({f"exploit_{i}": {"type": "exploit", "fullname": f"exploit/f/{i}", "path": f"/modules/exploits/f/{i}.rb",
                                 "references": [f"CVE-2020-{1000 + i}"], "rank": 300} for i in range(600)})
    nuclei = "\n".join([json.dumps({"ID": "CVE-2026-2222", "Info": {"Name": "Acme check", "Severity": "critical"},
                                    "file_path": "http/cves/2026/CVE-2026-2222.yaml"}),
                        json.dumps({"ID": "CVE-2026-6666", "Info": {}, "file_path": "../../etc/passwd"}), "not json"]
                       + [json.dumps({"ID": f"CVE-2021-{1000 + i}", "Info": {"Severity": "high"}, "file_path": f"http/cves/2021/{i}.yaml"})
                          for i in range(600)])

    def hx(request):
        if "metasploit" in request.url.path:
            return httpx.Response(200, content=json.dumps(msf).encode(), headers={"etag": '"m1"'})
        return httpx.Response(200, content=nuclei.encode(), headers={"etag": '"n1"'})
    run(exploits.collect(mock(hx), m.db, "ua"))
    xp = exploits.for_cve(m.db, "CVE-2026-2222")
    assert [(x["source"], x["rank"], x["severity"]) for x in xp] == [("metasploit", "excellent", None), ("nuclei", None, "critical")]
    assert xp[0]["url"] == "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/acme_rce.rb"
    assert xp[1]["url"].endswith("/http/cves/2026/CVE-2026-2222.yaml")
    assert not exploits.for_cve(m.db, "CVE-2026-4444") and not exploits.for_cve(m.db, "CVE-2026-5555")
    assert not exploits.for_cve(m.db, "CVE-2026-6666")
    assert m.db.meta_get("etag:metasploit") == '"m1"'
    # a broken download keeps the data
    run(exploits.collect(mock(lambda r: httpx.Response(200, content=b"{}")), m.db, "ua"))
    assert exploits.for_cve(m.db, "CVE-2026-2222")
    from fastapi.testclient import TestClient

    async def no_nvd(client, cve):
        return None
    m.products.cve_detail = no_nvd
    with TestClient(m.app) as tc:
        page = tc.get("/api/obj", params={"type": "cve", "value": "CVE-2026-2222"}).json()
        facts = next(s for s in page["sections"] if s["kind"] == "kv")
        assert any(r[0] == "ENISA EUVD" for r in facts["rows"])
        keys = {f["key"] for f in page["risk"]["reasons"]}
        assert {"ob.f.euvd", "ob.f.exploit_msf"} <= keys and "ob.f.exploit_nuclei" not in keys  # one hint, the stronger
        assert any(s.get("title") == "Public exploit and check code" for s in page["sections"])
    i = store(m, "Attackers exploit CVE-2026-2222 in Totolink routers", hours=2)
    d = m.news.detail(i)
    assert d["cve_info"][0]["euvd"] == "EUVD-2025-11154" and d["cve_info"][0]["exploits"] == ["metasploit", "nuclei"]


# --- URLhaus --------------------------------------------------------------------------------------------------------------
def test_urlhaus_into_iocs_and_watchlist(m):
    from app.sources import abusech
    body = {"query_status": "ok", "urls": [
        {"id": "101", "url": "http://shop.example.de/wp/x.exe", "url_status": "online", "host": "shop.example.de",
         "date_added": "2026-10-21 10:00:00 UTC", "threat": "malware_download", "tags": ["exe", "AgentTesla"],
         "urlhaus_reference": "https://urlhaus.abuse.ch/url/101/"},
        {"id": "102", "url": "http://203.0.113.9:8080/bins/mozi.m", "host": "203.0.113.9", "date_added": "2026-10-21 11:00:00 UTC",
         "threat": "malware_download", "tags": None, "urlhaus_reference": "javascript:alert(1)"},
        {"id": "103", "url": "http://notexample.de/a", "host": "notexample.de", "threat": "malware_download"},
        {"url": "missing id"},
    ]}
    seen = []

    def h(request):
        seen.append(request.headers.get("auth-key"))
        return httpx.Response(200, json=body)
    run(abusech.collect_urlhaus(mock(h), m.db, "ua", "key-1"))
    assert seen == ["key-1"]
    rows = {r["id"]: r for r in m.db.query("SELECT * FROM iocs WHERE id LIKE 'urlhaus:%'")}
    assert rows["urlhaus:101"]["host"] == "shop.example.de" and rows["urlhaus:101"]["malware"] == "exe"
    assert rows["urlhaus:102"]["ip"] == "203.0.113.9" and rows["urlhaus:102"]["reference"] == "https://urlhaus.abuse.ch/url/102/"
    m.db.insert("INSERT INTO watchlist(kind, value, label, created_at) VALUES(?,?,?,?)", ("domain", "example.de", None, iso(1)))
    m.db.insert("INSERT INTO watchlist(kind, value, label, created_at) VALUES(?,?,?,?)", ("cidr", "203.0.113.0/24", "lab", iso(1)))
    from app import watchlist
    watchlist.scan(m.db)
    watchlist.scan(m.db)  # once
    al = m.db.query("SELECT key, params FROM alerts WHERE key LIKE 'watch.ioc_%' ORDER BY key")
    assert [a["key"] for a in al] == ["watch.ioc_domain", "watch.ioc_ip"]
    assert json.loads(al[0]["params"])["ioc"] == "http://shop.example.de/wp/x.exe"  # not notexample.de
    run(abusech.collect_urlhaus(mock(h), m.db, "ua", ""))
    st = {r["source"]: r for r in m.db.statuses()}
    assert st["urlhaus"]["code"] == "missing_key"


# --- platform outages -------------------------------------------------------------------------------------------------------
AWS_RSS = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Amazon Web Services Service Status</title>
<item><title>Service impact: Increased Error Rates and Latencies</title><link>https://status.aws.amazon.com/</link>
<pubDate>{rfc822(2)}</pubDate><guid isPermaLink="false">https://status.aws.amazon.com/#multipleservices-us-east-1_1761600000</guid>
<description>We are investigating increased error rates for EC2 APIs in the US-EAST-1 Region.</description></item>
<item><title>Informational message: Increased Error Rates</title><link>https://status.aws.amazon.com/</link>
<pubDate>{rfc822(3)}</pubDate><guid isPermaLink="false">https://status.aws.amazon.com/#multipleservices-us-east-1_1761590000</guid>
<description>We are investigating.</description></item>
<item><title>Service is operating normally: [RESOLVED] Elevated API Errors</title><link>https://status.aws.amazon.com/</link>
<pubDate>{rfc822(5)}</pubDate><guid isPermaLink="false">https://status.aws.amazon.com/#lambda-eu-central-1_1761580000</guid>
<description>Between 1:00 and 2:00 PM PDT Lambda in Europe (Frankfurt) saw errors.</description></item>
<item><title>Service impact: Old</title><link>https://status.aws.amazon.com/</link>
<pubDate>{rfc822(80)}</pubDate><guid isPermaLink="false">https://status.aws.amazon.com/#s3-ap-south-1_1761000000</guid>
<description>old</description></item>
</channel></rss>""".encode()
AZURE_RSS = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>Azure Status</title>
<item><title>Networking – Connectivity issues in West Europe</title><link>https://azure.status.microsoft/en-us/status/history/</link>
<pubDate>{rfc822(1)}</pubDate><description>&lt;p&gt;Starting at 08:00 UTC customers in West Europe and East US 2 may experience
connection failures.&lt;/p&gt;</description></item></channel></rss>""".encode()
GCP_ATOM = f"""<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Google Cloud Service Health</title>
<entry><title>RESOLVED: Cloud Run errors in europe-west3</title><link href="https://status.cloud.google.com/incidents/AbC123xyz"/>
<id>tag:status.cloud.google.com,2026:AbC123xyz-2</id><updated>{iso(1)}</updated><summary>Fixed in europe-west3.</summary></entry>
<entry><title>UPDATE: Cloud Run errors in europe-west3</title><link href="https://status.cloud.google.com/incidents/AbC123xyz"/>
<id>tag:status.cloud.google.com,2026:AbC123xyz-1</id><updated>{iso(3)}</updated><summary>Errors in europe-west3 (Frankfurt).</summary></entry>
</feed>""".encode()
CF = {"page": {"id": "x"}, "incidents": [
    {"id": "cf1", "name": "Frankfurt, Germany - (FRA) Connectivity issues", "status": "investigating", "impact": "minor",
     "created_at": iso(1).replace("Z", ".000Z"), "updated_at": iso(0.5).replace("Z", ".000Z"), "shortlink": "https://stspg.io/abc",
     "incident_updates": [{"body": "We are investigating issues in Frankfurt, Germany."}]},
    {"id": "cf2", "name": "Dashboard errors", "status": "resolved", "impact": "major", "created_at": iso(30), "updated_at": iso(28),
     "shortlink": "javascript:alert(1)", "incident_updates": []},
    {"name": "no id"},
]}


def status_handler(request):
    host = request.url.host
    if host == "status.aws.amazon.com":
        return httpx.Response(200, content=AWS_RSS, headers={"etag": '"a1"'})
    if host == "azure.status.microsoft":
        return httpx.Response(200, content=AZURE_RSS)
    if host == "status.cloud.google.com":
        return httpx.Response(200, content=GCP_ATOM)
    if host == "www.cloudflarestatus.com":
        return httpx.Response(200, json=CF)
    return httpx.Response(404)


def test_platform_outages_regions_and_alerts(m):
    p = m.platforms
    assert p.set_used(["aws", "cloudflare", "bogus"]) == ["aws", "cloudflare"]
    assert run(p.collect(mock(status_handler), "ua")) == 2  # one active AWS incident, one active Cloudflare incident
    assert run(p.collect(mock(status_handler), "ua")) == 0  # no second alert
    inc = {i["id"]: i for i in p.listing(7)}
    aws = inc["aws:multipleservices-us-east-1"]
    assert aws["status"] == "active" and aws["started"] == iso(3)[:16] + aws["started"][16:] and aws["regions"][0]["code"] == "us-east-1"
    assert aws["regions"][0]["precision"] == "region" and aws["used"] is True
    assert inc["aws:lambda-eu-central-1"]["status"] == "resolved" and inc["aws:lambda-eu-central-1"]["regions"][0]["name"] == "Europe (Frankfurt)"
    assert inc["aws:s3-ap-south-1"]["status"] == "resolved"  # stale: no news for more than two days
    az = [i for i in inc.values() if i["provider"] == "azure"][0]
    assert az["status"] == "active" and [r["code"] for r in az["regions"]] == ["westeurope", "eastus2"]
    gcp = inc["gcp:AbC123xyz"]
    assert gcp["status"] == "resolved" and gcp["regions"][0]["code"] == "europe-west3" and gcp["regions"][0]["precision"] == "city"
    cf = inc["cloudflare:cf1"]
    assert cf["status"] == "active" and cf["regions"][0]["cc"] == "DE" and cf["regions"][0]["precision"] == "city"
    assert inc["cloudflare:cf2"]["url"] == "https://www.cloudflarestatus.com/"  # unsafe link replaced by the status page
    al = m.db.query("SELECT key, params, url FROM alerts WHERE source='platform' ORDER BY id")
    assert len(al) == 2 and json.loads(al[0]["params"])["provider"] in ("AWS", "Cloudflare")
    st = {r["source"]: r for r in m.db.statuses()}
    assert all(st[f"status_{x}"]["ok"] for x in ("aws", "azure", "gcp", "cloudflare"))
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        r = tc.get("/api/platforms", params={"active": "true"}).json()
        assert {i["provider"] for i in r["incidents"]} == {"aws", "azure", "cloudflare"} and r["enabled"]
        assert tc.post("/api/platforms/used", json={"providers": ["gcp"]}).json() == {"providers": ["gcp"]}
        assert tc.post("/api/platforms/used", json={"providers": ["x"] * 11}).status_code == 422
    # an unchanged feed (304) still ends incidents without news for two days
    m.db.execute("UPDATE platform_incidents SET updated = ? WHERE id = 'cloudflare:cf1'", (iso(60),))
    m.db.meta_set("status_etag:cloudflare", '"c1"')
    run(p.collect(mock(lambda r: httpx.Response(304) if r.url.host == "www.cloudflarestatus.com" else status_handler(r)), "ua"))
    assert m.db.query("SELECT status FROM platform_incidents WHERE id = 'cloudflare:cf1'")[0]["status"] == "resolved"
    # one broken feed does not stop the others
    def broken(request):
        if request.url.host == "azure.status.microsoft":
            return httpx.Response(200, content=b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><rss>&a;</rss>')
        return status_handler(request)
    m.db.execute("DELETE FROM meta WHERE key LIKE 'status_etag:%'")
    run(p.collect(mock(broken), "ua"))
    st = {r["source"]: r for r in m.db.statuses()}
    assert not st["status_azure"]["ok"] and st["status_gcp"]["ok"]


def test_region_table_resolves_every_region(m):
    from app import platforms
    for prov, rows in platforms.REGIONS.items():
        for code, *_ in rows:
            r = m.platforms.regions[prov][code]
            assert r.get("lat") is not None and r["precision"] in ("city", "region", "country"), (prov, code)
    fra = m.platforms.regions["aws"]["eu-central-1"]
    assert fra["precision"] == "city" and abs(fra["lat"] - 50.1) < 0.2 and abs(fra["lon"] - 8.68) < 0.2


# --- API additions: "supported" filter, exploited vulnerabilities by catalogue ------------------------------------------------
def test_supported_filter_and_kev_catalogues(m):
    _radar(m, {**{n: 2.0 for n in range(2, 16)}, 0: 7.0})
    store(m, "Pro-Russian hacktivists claim DDoS attacks on German government sites", hours=2)
    store(m, "New guidance on password managers published", hours=3)
    m.news.refresh_checks()
    m.db.execmany("INSERT INTO kev(cve, vendor, product, name, date_added) VALUES(?,?,?,?,?)",
                  [("CVE-2026-1111", "Acme", "Gate", "Acme Gate RCE", day(3)), ("CVE-2026-1112", "Acme", "Box", "Acme Box", day(4))])
    m.db.execmany("INSERT INTO euvd(cve, euvd_id, exploited_since, vendor, product, updated_at) VALUES(?,?,?,?,?,?)",
                  [("CVE-2026-1111", "EUVD-2026-1", day(5), "Acme", "Gate", iso(1)),
                   ("CVE-2026-2222", "EUVD-2026-2", day(2), "Totolink", "A3700R", iso(1))])
    m.db.execute("INSERT INTO exploits(cve, source, ref, name, detail, published) VALUES(?,?,?,?,?,?)",
                 ("CVE-2026-1112", "nuclei", "http/cves/2026/CVE-2026-1112.yaml", "x", "high", None))
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        assert tc.get("/api/welt", params={"days": 7}).json()["kpis"]["events"] == 2
        w = tc.get("/api/welt", params={"days": 7, "supported": "true"}).json()
        assert w["kpis"]["events"] == 1 and w["items"][0]["checks"]["verdict"] == "supported"
        assert tc.get("/api/news", params={"days": 7, "supported": "true"}).json()["total"] == 1
        k = tc.get("/api/kev").json()
        rows = {r["cve"]: r for r in k["rows"]}
        assert rows["CVE-2026-1111"]["euvd"] == "EUVD-2026-1" and rows["CVE-2026-1112"]["exploits"] == ["nuclei"]
        assert k["catalog"] == 2 and k["euvd"] is True
        assert [r["cve"] for r in tc.get("/api/kev", params={"exploit": "true"}).json()["rows"]] == ["CVE-2026-1112"]
        e = tc.get("/api/kev", params={"catalog": "euvd", "days": 30, "sort": "epss", "q": "EUVD-2026"}).json()
        assert [r["cve"] for r in e["rows"]] == ["CVE-2026-2222"] and e["catalog"] == 1  # only what KEV does not list
        assert e["rows"][0]["date_added"] == day(2) and e["rows"][0]["due_date"] is None
        assert tc.get("/api/kev", params={"catalog": "x"}).status_code == 422
