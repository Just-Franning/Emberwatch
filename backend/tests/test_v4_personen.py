"""Tests for 4.0 people search: site lists (validation, exclusions, merge, download), the decision rules of both lists,
the bounded checker, profile readers (platform APIs, profile pages, country of a place), a whole search with cases
and the link graph (automatic and manual), export, retention and the switch OSINT_ENABLED."""
from __future__ import annotations

import asyncio
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

WMN = {"license": ["CC BY-SA 4.0"], "authors": [], "categories": [], "sites": [
    {"name": "GitHub (User)", "uri_check": "https://api.github.com/users/{account}", "uri_pretty": "https://github.com/{account}",
     "e_code": 200, "e_string": "\"login\":", "m_string": "Not Found", "m_code": 404, "known": ["a", "b"], "cat": "coding"},
    {"name": "Keybase", "uri_check": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={account}",
     "uri_pretty": "https://keybase.io/{account}", "e_code": 200, "e_string": "\"id\":", "m_string": "\"them\":[null]", "m_code": 200,
     "known": ["a", "b"], "cat": "social"},
    {"name": "Mastodon (mastodon.social)", "uri_check": "https://mastodon.social/@{account}", "e_code": 200,
     "e_string": "profile:username", "m_string": "The page you are looking for isn't here.", "m_code": 404, "known": ["a", "b"], "cat": "social"},
    {"name": "Shy Forum", "uri_check": "https://forum.example/u/{account}", "e_code": 200, "e_string": "user-card",
     "m_string": "", "m_code": 302, "known": ["a", "b"], "cat": "hobby", "protection": ["cloudflare"]},
    {"name": "Poster", "uri_check": "https://post.example/api/check", "uri_pretty": "https://post.example/{account}",
     "post_body": "{\"username\":\"{account}\"}", "headers": {"Content-Type": "application/json", "Host": "evil.internal"},
     "e_code": 200, "e_string": "\"taken\":true", "m_string": "\"taken\":false", "m_code": 200, "known": ["a", "b"], "cat": "tech"},
    # left out: adult, dating, health, political; invalid URLs; switched off
    {"name": "Adult", "uri_check": "https://adult.example/{account}", "e_code": 200, "e_string": "x", "m_string": "y", "m_code": 404,
     "known": [], "cat": "xx NSFW xx"},
    {"name": "Love", "uri_check": "https://love.example/{account}", "e_code": 200, "e_string": "x", "m_string": "y", "m_code": 404,
     "known": [], "cat": "dating"},
    {"name": "Metadata", "uri_check": "http://169.254.169.254/{account}", "e_code": 200, "e_string": "x", "m_string": "y", "m_code": 404,
     "known": [], "cat": "misc"},
    {"name": "Local", "uri_check": "http://localhost/{account}", "e_code": 200, "e_string": "x", "m_string": "y", "m_code": 404,
     "known": [], "cat": "misc"},
    {"name": "Script", "uri_check": "javascript:alert({account})", "e_code": 200, "e_string": "x", "m_string": "y", "m_code": 404,
     "known": [], "cat": "misc"},
    {"name": "Broken", "uri_check": "https://broken.example/{account}", "e_code": 200, "e_string": "x", "m_string": "y", "m_code": 404,
     "known": [], "cat": "misc", "valid": False},
]}
SHERLOCK = {
    "$schema": "data.schema.json",
    "GitHub": {"errorType": "status_code", "url": "https://www.github.com/{}", "urlMain": "https://www.github.com/", "username_claimed": "blue"},
    "Blog": {"errorType": "message", "errorMsg": ["Nobody here"], "url": "https://blog.example/{}", "urlMain": "https://blog.example/",
             "username_claimed": "blue"},
    "Strict": {"errorType": "status_code", "regexCheck": "^[a-z]{2,8}$", "url": "https://strict.example/{}", "urlMain": "x",
               "username_claimed": "blue"},
    "Moved": {"errorType": "response_url", "url": "https://moved.example/{}", "urlMain": "x", "username_claimed": "blue"},
    "Evil Regex": {"errorType": "status_code", "regexCheck": "^(a+)+$", "url": "https://regex.example/{}", "urlMain": "x",
                   "username_claimed": "blue"},
    "Naughty": {"errorType": "status_code", "url": "https://naughty.example/{}", "isNSFW": True, "urlMain": "x", "username_claimed": "blue"},
    "NoPlaceholder": {"errorType": "status_code", "url": "https://discord.com", "urlMain": "x", "username_claimed": "blue"},
}


def run(coro):
    return asyncio.run(coro)


def site_list(tmp_path, wmn=WMN, sherlock=SHERLOCK):
    from app.personen import sites
    d = tmp_path / "osint"
    d.mkdir(parents=True, exist_ok=True)
    (d / "wmn.json").write_text(json.dumps(wmn))
    (d / "sherlock.json").write_text(json.dumps(sherlock))
    (d / "lists.json").write_text(json.dumps({k: {"checked": time.time(), "fetched_at": "2026-10-20T00:00:00Z"} for k in sites.SOURCES}))
    return sites.SiteList(tmp_path, "ua")


# --- site lists -------------------------------------------------------------------------------------------------------
def test_site_lists_validated_and_merged(tmp_path):
    sl = site_list(tmp_path)
    by = {s.name: s for s in sl.sites}
    assert set(by) == {"GitHub (User)", "Keybase", "Mastodon (mastodon.social)", "Shy Forum", "Poster", "Blog", "Strict", "Moved",
                       "Evil Regex"}
    # the same host in both lists: WhatsMyName wins
    assert by["GitHub (User)"].source == "wmn" and "GitHub" not in by
    assert by["GitHub (User)"].url == "https://github.com/{u}" and by["GitHub (User)"].probe == "https://api.github.com/users/{u}"
    p = by["Poster"]
    assert p.method == "POST" and p.probe == "https://post.example/api/check" and p.body == '{"username":"{u}"}'
    assert dict(p.headers) == {"Content-Type": "application/json"}  # no Host header from the list
    assert by["Blog"].method == "GET" and by["Strict"].method == "HEAD" and by["Strict"].regex == "^[a-z]{2,8}$"
    assert by["Evil Regex"].regex is None  # nested quantifiers are not run
    assert sl.info()["counts"] == {"wmn": 5, "sherlock": 5, "total": 9} and not sl.due()


def test_site_list_download(tmp_path):
    from app.personen import sites
    many = {"sites": [{"name": f"Site {i}", "uri_check": f"https://s{i}.example/{{account}}", "e_code": 200, "e_string": "x",
                       "m_string": "y", "m_code": 404, "known": [], "cat": "social"} for i in range(60)]}
    sher = {f"S{i}": {"errorType": "status_code", "url": f"https://h{i}.example/{{}}", "urlMain": "x", "username_claimed": "a"} for i in range(60)}
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append((req.url.host, req.headers.get("if-none-match")))
        if req.headers.get("if-none-match") == '"v1"':
            return httpx.Response(304)
        body = many if "WhatsMyName" in req.url.path else sher
        return httpx.Response(200, json=body, headers={"etag": '"v1"'})

    sl = sites.SiteList(tmp_path, "ua")
    assert sl.due() and not sl.sites
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert run(sl.refresh(client))
    assert sl.info()["counts"] == {"wmn": 60, "sherlock": 60, "total": 120} and all(h == "raw.githubusercontent.com" for h, _ in calls)
    assert not run(sl.refresh(client))  # within a week: nothing is fetched
    calls.clear()
    run(sl.refresh(client, force=True))
    assert [c[1] for c in calls] == [None, None]  # forced: no conditional request
    # a broken or nearly empty list does not replace a working one
    bad = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"sites": []})))
    run(sl.refresh(bad, force=True))
    assert sl.info()["counts"]["total"] == 120 and sl.info()["errors"]


# --- decisions ------------------------------------------------------------------------------------------------------
def test_decision_rules(tmp_path):
    from app.personen import check
    by = {s.name: s for s in site_list(tmp_path).sites}
    gh, kb, shy, blog, strict, moved = (by[n] for n in ("GitHub (User)", "Keybase", "Shy Forum", "Blog", "Strict", "Moved"))
    assert check.decide(gh, 200, '{"login": "x"}') == ("found", "")
    assert check.decide(gh, 404, '{"message": "Not Found"}') == ("missing", "")
    assert check.decide(gh, 429, "rate limited") == ("unsure", "protected")
    assert check.decide(kb, 200, '{"them":[null]}') == ("missing", "")  # same status, the strings decide
    assert check.decide(shy, 302, "") == ("missing", "")  # empty m_string: the status is enough
    assert check.decide(shy, 200, '<script src="/cdn-cgi/challenge-platform/x.js">') == ("unsure", "waf")
    assert check.decide(blog, 200, "Welcome") == ("found", "")
    assert check.decide(blog, 200, "Nobody here") == ("missing", "")
    assert check.decide(blog, 500, "oops") == ("unsure", "unclear")  # Sherlock would call this found
    assert check.decide(strict, 404, "") == ("missing", "") and check.decide(strict, 200, "") == ("found", "")
    assert check.decide(moved, 301, "") == ("missing", "") and check.decide(moved, 200, "") == ("found", "")


def test_checker_against_mocked_sites(tmp_path, monkeypatch):
    from app import webfetch
    from app.personen import check
    monkeypatch.setattr(webfetch, "proxied", lambda: False)
    sl = site_list(tmp_path)
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, str(req.url), req.content, req.headers.get("host")))
        u = str(req.url)
        if u == "https://api.github.com/users/nachtfalke":
            return httpx.Response(200, json={"login": "nachtfalke"})
        if u.startswith("https://keybase.io/_/api"):
            return httpx.Response(200, text='{"them":[{"id":"1"}]}')
        if u == "https://mastodon.social/@nachtfalke":
            return httpx.Response(200, text='<meta property="profile:username" content="nachtfalke">')
        if u == "https://forum.example/u/nachtfalke":
            return httpx.Response(302, headers={"location": "/login"})
        if u == "https://post.example/api/check":
            return httpx.Response(200, text='{"taken":true}')
        if u == "https://blog.example/nachtfalke":
            return httpx.Response(302, headers={"location": "https://blog.example/profile/nachtfalke"})
        if u == "https://blog.example/profile/nachtfalke":
            return httpx.Response(200, text="<h1>My blog</h1>")
        if u == "https://moved.example/nachtfalke":
            return httpx.Response(302, headers={"location": "https://moved.example/"})
        if u == "https://regex.example/nachtfalke":
            return httpx.Response(405) if req.method == "HEAD" else httpx.Response(200)
        return httpx.Response(404)

    web = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = {}

    async def done(c):
        results[c.site.name] = c

    run(check.run(web, sl.sites, "nachtfalke", done))
    st = {k: v.status for k, v in results.items()}
    assert st == {"GitHub (User)": "found", "Keybase": "found", "Mastodon (mastodon.social)": "found", "Shy Forum": "missing",
                  "Poster": "found", "Blog": "found", "Strict": "skipped", "Moved": "missing", "Evil Regex": "found"}
    assert results["GitHub (User)"].url == "https://github.com/nachtfalke" and results["GitHub (User)"].body == b""  # API answer, not the page
    assert results["Mastodon (mastodon.social)"].body.startswith(b"<meta")  # kept for the profile
    post = [s for s in seen if s[0] == "POST"][0]
    assert post[2] == b'{"username":"nachtfalke"}' and post[3] == "post.example"
    assert ("GET", "https://regex.example/nachtfalke", b"", "regex.example") in seen  # HEAD refused: once more with GET
    assert not any("moved.example/" == s[1].split("//")[1] for s in seen)  # response_url: the redirect is not followed
    # a spent time budget ends the search without requests
    results.clear()
    n = len(seen)
    run(check.run(web, sl.sites, "x2", done, budget_s=-1))
    assert {v.reason for v in results.values()} == {"budget"} and len(seen) == n


# --- profiles -------------------------------------------------------------------------------------------------------
def test_profile_readers_and_places(tmp_path, monkeypatch):
    from app import webfetch
    from app.personen import check, profiles
    monkeypatch.setattr(webfetch, "proxied", lambda: False)
    front = ROOT / "frontend" / "data"
    loc = profiles.Locator(front / "centroids.json", front / "places.json")
    assert loc.country("Berlin, Germany") == "DE" and loc.country("🇦🇹 somewhere") == "AT" and loc.country("Zürich") == "CH"
    assert loc.country("München / Bavaria") == "DE" and loc.country("the internet") is None and loc.country(None) is None
    sl = {s.name: s for s in site_list(tmp_path).sites}

    def handler(req: httpx.Request) -> httpx.Response:
        u = str(req.url)
        if u == "https://api.github.com/users/nachtfalke":
            return httpx.Response(200, json={"login": "nachtfalke", "name": "Nacht Falke", "blog": "nachtfalke.example",
                                             "location": "Hamburg, Germany", "twitter_username": "nfalke", "created_at": "2019-04-01T10:00:00Z",
                                             "email": None, "company": "@demo"})
        if u.startswith("https://keybase.io/_/api"):
            return httpx.Response(200, json={"them": [{"basics": {"ctime": 1500000000}, "profile": {"full_name": "N. Falke"},
                                                       "proofs_summary": {"all": [{"service_url": "https://github.com/nachtfalke"},
                                                                                  {"service_url": "javascript:alert(1)"}]}}]})
        if u.startswith("https://mastodon.social/api/v1/accounts/lookup"):
            return httpx.Response(200, json={"display_name": "Falke", "note": "<p>Hi <b>there</b></p>", "created_at": "2022-11-01T00:00:00Z",
                                             "fields": [{"name": "Web", "value": "<a href=\"https://nachtfalke.example\">nachtfalke.example</a>",
                                                         "verified_at": "2023-01-01T00:00:00Z"},
                                                        {"name": "Ort", "value": "Wien"}]})
        return httpx.Response(404)

    web = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    gh = run(profiles.read(web, check.Check(sl["GitHub (User)"], "found", 200, "https://github.com/nachtfalke"), "nachtfalke", loc))
    assert gh.source == "api" and gh.name == "Nacht Falke" and gh.country == "DE" and gh.created == "2019-04-01"
    assert gh.links == ["https://nachtfalke.example", "https://x.com/nfalke"] and gh.company == "@demo"
    kb = run(profiles.read(web, check.Check(sl["Keybase"], "found", 200, "https://keybase.io/nachtfalke"), "nachtfalke", loc))
    assert kb.verified == ["https://github.com/nachtfalke"] and kb.created == "2017-07-14"
    ms = run(profiles.read(web, check.Check(sl["Mastodon (mastodon.social)"], "found", 200, "https://mastodon.social/@nachtfalke"), "nachtfalke", loc))
    assert ms.verified == ["https://nachtfalke.example"] and ms.bio == "Hi there" and ms.country == "AT"
    # a profile page without an API: Open Graph, rel="me", links with the user name
    page = b"""<html><head><meta property="og:title" content="nachtfalke on Blog"><meta name="description" content="Notes."></head>
    <body><a rel="me" href="https://social.example/@other">me</a><a href="https://github.com/nachtfalke">code</a>
    <a href="https://twitter.com/blogplatform">Follow the platform</a><a href="/nachtfalke/posts">own host</a></body></html>"""
    c = check.Check(sl["Blog"], "found", 200, "https://blog.example/nachtfalke", body=page, ctype="text/html")
    bl = run(profiles.read(web, c, "nachtfalke", loc))
    assert bl.source == "page" and bl.name == "nachtfalke on Blog" and bl.bio == "Notes."
    assert bl.links == ["https://social.example/@other", "https://github.com/nachtfalke"]


# --- a whole search -------------------------------------------------------------------------------------------------
@pytest.fixture()
def m(tmp_path, monkeypatch):
    mod = v3.load_app(tmp_path, monkeypatch)
    from app import webfetch
    monkeypatch.setattr(webfetch, "proxied", lambda: False)
    mod.osint_sites.dir = tmp_path / "osint"
    site_list(tmp_path)
    mod.osint_sites.load()
    return mod


def web_mock(calls):
    def handler(req: httpx.Request) -> httpx.Response:
        u = str(req.url)
        calls.append(u)
        if u == "https://api.github.com/users/nachtfalke":
            return httpx.Response(200, json={"login": "nachtfalke", "name": "Nacht Falke", "blog": "https://blog.example/nachtfalke",
                                             "location": "Hamburg, Germany"})
        if u.startswith("https://keybase.io/_/api"):
            return httpx.Response(200, json={"them": [{"id": "1", "profile": {"full_name": "Nacht Falke"},
                                                       "proofs_summary": {"all": [{"service_url": "https://github.com/nachtfalke"}]}}]})
        if u == "https://blog.example/nachtfalke":
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text='<meta property="og:title" content="Nacht Falke"><a rel="me" href="https://github.com/nachtfalke">gh</a>')
        if u == "https://forum.example/u/nachtfalke":
            return httpx.Response(403, text="denied")
        if u == "https://mastodon.social/@nachtfalke":
            return httpx.Response(404, text="The page you are looking for isn't here.")
        if u == "https://post.example/api/check":
            return httpx.Response(200, text='{"taken":false}')
        return httpx.Response(404)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def wait(tc, sid, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        d = tc.get(f"/api/personen/searches/{sid}").json()
        if d["search"]["status"] in ("done", "failed", "cancelled"):
            return d
        time.sleep(0.05)
    raise AssertionError("search did not finish")


def test_search_case_and_graph(m):
    calls = []
    with TestClient(m.app) as tc:
        m.app.state.web = web_mock(calls)
        st = tc.get("/api/personen/status").json()
        assert st["enabled"] and st["lists"]["total"] == 9 and st["retention_days"] == 90
        case = tc.post("/api/personen/cases", json={"name": " Eigene Präsenz ", "note": "Test\x07"}, headers=SAME).json()
        assert case["name"] == "Eigene Präsenz" and case["note"] == "Test"
        cid = case["id"]
        assert tc.post(f"/api/personen/cases/{cid}/searches", json={"kind": "username", "query": "bad name!"}, headers=SAME).json()["key"] == "err.osint.username"
        sid = tc.post(f"/api/personen/cases/{cid}/searches", json={"kind": "username", "query": "nachtfalke"}, headers=SAME).json()["id"]
        d = wait(tc, sid)
        assert d["search"]["status"] == "done" and d["search"]["sites"] == 9 and d["search"]["checked"] == 9
        hits = {h["site"]: h for h in d["hits"]}
        assert {k: h["status"] for k, h in hits.items()} == {"GitHub (User)": "found", "Keybase": "found", "Blog": "found", "Shy Forum": "unsure"}
        assert hits["GitHub (User)"]["operator_cc"] == "US" and hits["GitHub (User)"]["operator_src"] == "list"
        assert hits["GitHub (User)"]["profile"]["country"] == "DE" and hits["Keybase"]["profile"]["verified"] == ["https://github.com/nachtfalke"]
        view = tc.get(f"/api/personen/cases/{cid}").json()
        g = view["graph"]
        nodes = {(n["kind"], n["label"]): n for n in g["nodes"]}
        ids = {k: n["id"] for k, n in nodes.items()}
        assert ("username", "nachtfalke") in nodes and ("name", "Nacht Falke") in nodes and ("location", "DE") in nodes
        e = {(x["src"], x["dst"], x["kind"]): x for x in g["edges"]}
        subj, gh, kb, blog = ids[("username", "nachtfalke")], ids[("account", "GitHub (User)")], ids[("account", "Keybase")], ids[("account", "Blog")]
        forum = ids[("account", "Shy Forum")]
        assert e[(subj, gh, "username")]["strength"] == "confirmed" and e[(subj, forum, "username")]["strength"] == "hint"
        assert (kb, gh, "verified") in e  # proof of Keybase points at the GitHub account of the search
        assert e[(gh, blog, "links_to")]["mutual"] and e[(blog, gh, "links_to")]["mutual"]  # GitHub -> blog and back
        name = ids[("name", "Nacht Falke")]
        assert (gh, name, "states") in e and (kb, name, "states") in e and (blog, name, "states") in e  # one shared name node
        # manual work: a person, a link to it, a label; positions
        pid = tc.post(f"/api/personen/cases/{cid}/nodes", json={"kind": "person", "label": "Max (vermutet)", "note": "aus Gespräch"},
                      headers=SAME).json()["id"]
        assert tc.post(f"/api/personen/cases/{cid}/nodes", json={"kind": "virus", "label": "x"}, headers=SAME).status_code == 400
        eid = tc.post(f"/api/personen/cases/{cid}/edges", json={"src": pid, "dst": gh, "strength": "hint", "label": "gleiches Foto"},
                      headers=SAME).json()["id"]
        assert tc.post(f"/api/personen/cases/{cid}/edges", json={"src": pid, "dst": pid}, headers=SAME).status_code == 400
        tc.patch(f"/api/personen/edges/{eid}", json={"strength": "confirmed"}, headers=SAME)
        tc.patch(f"/api/personen/nodes/{pid}", json={"label": "Max Muster"}, headers=SAME)
        assert tc.put(f"/api/personen/cases/{cid}/layout", json={"positions": [[pid, 10.5, -20], [gh, 1e9, 0]]}, headers=SAME).json() == {"saved": 1}
        g = tc.get(f"/api/personen/cases/{cid}").json()["graph"]
        me = [n for n in g["nodes"] if n["id"] == pid][0]
        assert me["label"] == "Max Muster" and me["manual"] and (me["x"], me["y"]) == (10.5, -20.0) and me["data"]["note"] == "aus Gespräch"
        assert [x for x in g["edges"] if x["id"] == eid][0]["strength"] == "confirmed"
        # a second search in the same case reuses the nodes (same account, same name)
        sid2 = tc.post(f"/api/personen/cases/{cid}/searches", json={"kind": "email", "query": "nachtfalke@mail.example"}, headers=SAME).json()["id"]
        wait(tc, sid2)
        g2 = tc.get(f"/api/personen/cases/{cid}").json()["graph"]
        kinds = [(n["kind"], n["label"]) for n in g2["nodes"]]
        assert kinds.count(("account", "GitHub (User)")) == 1 and ("email", "nachtfalke@mail.example") in kinds
        em = [n for n in g2["nodes"] if n["kind"] == "email"][0]["id"]
        assert any(x["src"] == em and x["dst"] == subj and x["kind"] == "local_part" for x in g2["edges"])
        ex = tc.get(f"/api/personen/cases/{cid}/export")
        assert ex.headers["content-disposition"].startswith("attachment;") and len(ex.json()["searches"]) == 2
        lst = tc.get("/api/personen/cases").json()["cases"]
        assert lst[0]["id"] == cid and lst[0]["found"] >= 3 and lst[0]["expires"] > lst[0]["updated_at"]
        tc.delete(f"/api/personen/nodes/{pid}", headers=SAME)
        assert not [x for x in tc.get(f"/api/personen/cases/{cid}").json()["graph"]["edges"] if x["id"] == eid]
        assert tc.delete(f"/api/personen/cases/{cid}", headers=SAME).json() == {"deleted": cid}
        assert tc.get(f"/api/personen/cases/{cid}").status_code == 404
    for t in ("osint_nodes", "osint_edges", "osint_hits", "osint_searches", "osint_cases"):
        assert not m.db.query(f"SELECT 1 FROM {t}"), t
    acts = [r["action"] for r in m.db.query("SELECT action FROM audit")]
    assert acts.count("osint_search") == 2 and "osint_case_deleted" in acts


def test_stop_retention_and_switch(m, tmp_path, monkeypatch):
    with TestClient(m.app) as tc:
        from app.personen import check as pcheck

        async def slow(web, sites, name, done, **kw):
            await asyncio.sleep(3600)  # runs until the search is stopped
        monkeypatch.setattr(pcheck, "run", slow)
        m.app.state.web = web_mock([])
        cid = tc.post("/api/personen/cases", json={"name": "Stop"}, headers=SAME).json()["id"]
        sid = tc.post(f"/api/personen/cases/{cid}/searches", json={"kind": "username", "query": "abc"}, headers=SAME).json()["id"]
        time.sleep(0.2)
        assert m.searcher.running() == [sid]
        assert tc.delete(f"/api/personen/cases/{cid}", headers=SAME).status_code == 409  # not while a search runs
        assert tc.delete(f"/api/personen/searches/{sid}", headers=SAME).json() == {"stopped": sid}
        d = wait(tc, sid)
        assert d["search"]["status"] == "cancelled"
        assert tc.delete(f"/api/personen/searches/{sid}", headers=SAME).json() == {"deleted": sid}
    # cases without changes for OSINT_RETENTION_DAYS are deleted
    m.db.execute("UPDATE osint_cases SET updated_at='2000-01-01T00:00:00Z'")
    assert [c["name"] for c in m.osint_store.prune()] == ["Stop"] and not m.db.query("SELECT 1 FROM osint_cases")
    off = v3.load_app(tmp_path / "off", monkeypatch, OSINT_ENABLED="0")
    with TestClient(off.app) as tc:
        assert tc.get("/api/personen/status").json()["enabled"] is False
        assert tc.get("/api/personen/cases").json()["key"] == "err.osint.off"
