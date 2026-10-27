"""Tests for 4.0 "who owns this IP": guarded web requests (no internal addresses, redirects, limits), imprint and
schema.org parsing, the evidence chain with confidence, caching, the NDJSON interface and its role check.

Upstream answers are mocked: RDAP in the RIPE format (objectClassName ip network, entities with vCard), websites as
HTML, Nominatim jsonv2."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpcore
import httpx
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v3 as v3  # noqa: E402

IMPRINT = """<!doctype html><html><head><title>Impressum - Muster Technik</title></head><body>
<header><nav><a href="/">Start</a> | <a href="/impressum">Impressum</a></nav></header>
<main><h1>Impressum</h1><p>Angaben gemäß § 5 DDG</p>
<p>Muster Technik GmbH<br>Industriestraße 25<br>91710 Gunzenhausen<br>Deutschland</p>
<p>Vertreten durch: Dr. Max Mustermann, Erika Musterfrau</p>
<h2>Kontakt</h2><p>Telefon: +49 (0) 9831 12345-0<br>Telefax: +49 9831 12345-99<br>E-Mail: info (at) muster-technik.de</p>
<h2>Registereintrag</h2><p>Eintragung im Handelsregister.<br>Registergericht: Amtsgericht Ansbach<br>Registernummer: HRB 1234</p>
<p>Umsatzsteuer-ID gemäß § 27a UStG: DE 123 456 789</p></main>
<footer>© 2026 Muster Technik GmbH · <a href="/datenschutz">Datenschutz</a></footer></body></html>"""

HOME = """<!doctype html><html><head><title>Muster Technik</title>
<script type="application/ld+json">{"@context": "https://schema.org", "@graph": [{"@type": "WebSite", "name": "Muster"},
{"@type": "Organization", "name": "Muster Technik", "telephone": "+49 9831 0", "sameAs": ["https://www.linkedin.com/company/muster"]}]}</script>
</head><body><p>Willkommen</p><footer><a href="/kontakt">Kontakt</a> <a href="https://muster-technik.de/impressum">Impressum</a>
<a href="https://evil.example/impressum">Impressum (fremd)</a></footer></body></html>"""

LD_ONLY = """<html><head><script type="application/ld+json">{"@context":"https://schema.org","@type":"Corporation",
"name":"Example Corp","legalName":"Example Corporation Ltd.","address":{"@type":"PostalAddress","streetAddress":"1 Main Street",
"postalCode":"EC1A 1BB","addressLocality":"London","addressCountry":"GB"},"telephone":"+44 20 7946 0000",
"email":"mailto:hello@example.co.uk"}</script></head><body><p>Hello</p></body></html>"""

RDAP = {
    "objectClassName": "ip network", "handle": "198.51.100.0 - 198.51.100.255", "startAddress": "198.51.100.0",
    "endAddress": "198.51.100.255", "name": "MUSTER-NET", "type": "ASSIGNED PA", "country": "DE",
    "remarks": [{"description": ["Muster Technik Standort Gunzenhausen"]}],
    "entities": [
        {"handle": "ORG-MT1-RIPE", "roles": ["registrant"], "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"], ["fn", {}, "text", "Muster Technik GmbH"],
            ["adr", {"label": "Industriestrasse 25\n91710 Gunzenhausen\nGERMANY"}, "text", ["", "", "", "", "", "", ""]],
            ["email", {}, "text", "noc@muster-technik.de"]]]},
        {"handle": "AR1-RIPE", "roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "ISP Abuse"],
                                                                             ["email", {}, "text", "abuse@isp.example"]]]},
        {"handle": "TC1-RIPE", "roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "ISP NOC"],
                                                                                ["email", {}, "text", "noc@isp.example"]]]},
    ],
}
IP = "198.51.100.7"  # TEST-NET-2 is not public: tests patch the check (see fixture)


def run(coro):
    return asyncio.run(coro)


# --- guarded requests ----------------------------------------------------------------------------------------------
def test_guard_refuses_internal_addresses(monkeypatch):
    from app import webfetch
    backend = webfetch.GuardedBackend()
    for host in ("127.0.0.1", "localhost", "10.1.2.3", "169.254.169.254", "::1", "[::ffff:127.0.0.1]".strip("[]")):
        with pytest.raises(httpcore.ConnectError) as exc:
            run(backend.connect_tcp(host, 80, timeout=3))
        assert webfetch.BLOCKED in str(exc.value), host
    calls = []

    class Fake:
        async def connect_tcp(self, host, port, **kw):
            calls.append((host, port))
            return "stream"

    async def resolve_public(host, port, type=0):
        return [(0, 0, 0, "", ("93.184.216.34", port)), (0, 0, 0, "", ("93.184.216.35", port))]

    backend._inner = Fake()
    loop = asyncio.new_event_loop()
    loop_cls = type(loop)
    loop.close()
    monkeypatch.setattr(loop_cls, "getaddrinfo", lambda self, host, port, type=0: resolve_public(host, port))
    assert run(backend.connect_tcp("example.com", 443)) == "stream"
    assert calls == [("93.184.216.34", 443)]  # connected to the checked address, not the name

    async def mixed(self, host, port, type=0):
        return [(0, 0, 0, "", ("93.184.216.34", port)), (0, 0, 0, "", ("10.0.0.5", port))]
    monkeypatch.setattr(loop_cls, "getaddrinfo", mixed)
    with pytest.raises(httpcore.ConnectError):
        run(backend.connect_tcp("rebind.example", 443))  # one private address is enough to refuse
    # the client really uses the guarded pool (httpx has no switch for it: this breaks loudly on an httpx change)
    monkeypatch.setattr(webfetch, "proxied", lambda: False)
    client = webfetch.make_client("ua")
    pool = client._transport._pool
    assert isinstance(pool._network_backend, webfetch.GuardedBackend)


def test_fetch_redirects_limits_and_text(monkeypatch):
    from app import webfetch
    monkeypatch.setattr(webfetch, "proxied", lambda: False)
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, str(req.url), req.content))
        p = req.url.path
        if p == "/a":
            return httpx.Response(302, headers={"location": "/b"})
        if p == "/b":
            return httpx.Response(301, headers={"location": "https://other.example/c"})
        if p == "/c":
            return httpx.Response(200, headers={"content-type": "text/html; charset=iso-8859-1"}, content="Straße".encode("latin-1"))
        if p == "/loop":
            return httpx.Response(302, headers={"location": "/loop"})
        if p == "/file":
            return httpx.Response(302, headers={"location": "file:///etc/passwd"})
        if p == "/big":
            return httpx.Response(200, content=b"x" * 5000)
        if p == "/meta":
            return httpx.Response(200, headers={"content-type": "text/html"}, content='<meta charset="windows-1252"><p>\x80</p>'.encode("latin-1"))
        return httpx.Response(404)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    page = run(webfetch.fetch(client, "https://site.example/a", method="POST", content=b"q=1"))
    assert page.status == 200 and page.first_status == 302 and page.url == "https://other.example/c" and page.text() == "Straße"
    assert [s[0] for s in seen] == ["POST", "GET", "GET"] and seen[1][2] == b""  # 302 after POST continues with GET
    first = run(webfetch.fetch(client, "https://site.example/a", follow=False))
    assert first.status == 302 and first.headers["location"] == "/b"
    with pytest.raises(webfetch.FetchError) as exc:
        run(webfetch.fetch(client, "https://site.example/loop"))
    assert exc.value.code == "redirect"
    with pytest.raises(webfetch.FetchError) as exc:
        run(webfetch.fetch(client, "https://site.example/file"))
    assert exc.value.code == "scheme"
    cut = run(webfetch.fetch(client, "https://site.example/big", max_bytes=1000))
    assert cut.truncated and len(cut.body) == 1000
    with pytest.raises(webfetch.FetchError) as exc:
        run(webfetch.fetch(client, "https://site.example/big", max_bytes=1000, cut=False))
    assert exc.value.code == "too_large"
    assert run(webfetch.fetch(client, "https://site.example/meta")).text() == "<meta charset=\"windows-1252\"><p>€</p>"
    with pytest.raises(webfetch.FetchError):
        run(webfetch.fetch(client, "ftp://site.example/x"))
    # credentials stay with their origin: a redirect to another host drops Authorization and Cookie
    sent = []

    def keyed(req: httpx.Request) -> httpx.Response:
        sent.append((req.url.host, req.headers.get("authorization"), req.headers.get("cookie"), req.headers.get("accept")))
        if req.url.path == "/v3/p":
            return httpx.Response(302, headers={"location": "/v3/q"})
        if req.url.path == "/v3/q":
            return httpx.Response(302, headers={"location": "https://elsewhere.example/r"})
        return httpx.Response(200, content=b"{}")

    kc = httpx.AsyncClient(transport=httpx.MockTransport(keyed))
    run(webfetch.fetch(kc, "https://api.example/v3/p", headers={"Authorization": "Bearer k", "Cookie": "s=1", "Accept": "application/json"}))
    assert sent == [("api.example", "Bearer k", "s=1", "application/json"), ("api.example", "Bearer k", "s=1", "application/json"),
                    ("elsewhere.example", None, None, "application/json")]
    # behind a proxy the name is checked before each hop
    monkeypatch.setattr(webfetch, "proxied", lambda: True)

    async def private(host):
        raise webfetch.FetchError("blocked", host)
    monkeypatch.setattr(webfetch, "check_host", private)
    with pytest.raises(webfetch.FetchError) as exc:
        run(webfetch.fetch(client, "https://site.example/c"))
    assert exc.value.code == "blocked"


# --- imprint ------------------------------------------------------------------------------------------------------------
def test_parse_imprint_and_jsonld():
    from app.owner import imprint
    d = imprint.parse_imprint(IMPRINT, "muster-technik.de")
    assert (d.company, d.legal_form, d.street, d.postcode, d.city, d.country) == (
        "Muster Technik GmbH", "GmbH", "Industriestraße 25", "91710", "Gunzenhausen", "DE")
    assert d.people == [("Dr. Max Mustermann", "representative"), ("Erika Musterfrau", "representative")]
    assert d.phone == "+49 (0) 9831 12345-0" and d.email == "info@muster-technik.de"
    assert d.register == "Amtsgericht Ansbach, HRB 1234" and d.vat_id == "DE123456789"
    inline = imprint.parse_imprint("<p>Beispiel AG, Hauptstr. 1, 10115 Berlin</p><p>Vorstand: Anna Beispiel</p>")
    assert (inline.company, inline.street, inline.postcode, inline.city) == ("Beispiel AG", "Hauptstr. 1", "10115", "Berlin")
    assert inline.people == [("Anna Beispiel", "board")]
    at = imprint.parse_imprint("<p>Alpen Software e.U.</p><p>Musterweg 3</p><p>A-6020 Innsbruck</p><p>ATU12345678</p>")
    assert (at.street, at.postcode, at.city, at.country, at.vat_id) == ("Musterweg 3", "6020", "Innsbruck", "AT", "ATU12345678")
    assert imprint.parse_imprint("<p>© 2026 Muster GmbH. Alle Rechte vorbehalten.</p>").company is None  # copyright lines are no source
    ld = imprint.org_from_jsonld(imprint.htmlparse.json_ld(imprint.htmlparse.soup(LD_ONLY)))
    assert (ld.company, ld.street, ld.postcode, ld.city, ld.country, ld.email) == (
        "Example Corporation Ltd.", "1 Main Street", "EC1A 1BB", "London", "GB", "hello@example.co.uk")
    links = imprint.htmlparse.links(imprint.htmlparse.soup(HOME), "https://muster-technik.de/")
    assert imprint.find_imprint_link(links, "muster-technik.de") == "https://muster-technik.de/impressum"
    assert imprint.company_domain("*.shop.muster-technik.de") == "muster-technik.de"
    assert imprint.company_domain("user.github.io") is None and imprint.company_domain("10.1.2.3") is None
    assert imprint.company_domain("www.example.co.uk") == "example.co.uk"


# --- the whole lookup -------------------------------------------------------------------------------------------------------
def site(robots: str = "User-agent: *\nDisallow: /intern/\n", calls: list | None = None):
    def handler(req: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(str(req.url))
        host, path = req.url.host, req.url.path
        if host != "muster-technik.de":
            return httpx.Response(404)
        if path == "/robots.txt":
            return httpx.Response(200, text=robots)
        if path == "/":
            return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"}, text=HOME)
        if path == "/impressum":
            return httpx.Response(200, headers={"content-type": "text/html; charset=utf-8"}, text=IMPRINT)
        return httpx.Response(404)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def nominatim(calls: list):
    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(dict(req.url.params))
        assert req.headers["user-agent"].startswith("emberwatch/")
        return httpx.Response(200, json=[{"lat": "49.1153", "lon": "10.7567", "display_name": "Industriestraße 25, 91710 Gunzenhausen, Deutschland",
                                          "addresstype": "building"}])
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture()
def m(tmp_path, monkeypatch):
    mod = v3.load_app(tmp_path, monkeypatch)
    from app import tools, webfetch
    from app.owner import geocode, lookup
    monkeypatch.setattr(webfetch, "proxied", lambda: False)
    monkeypatch.setattr(geocode, "MIN_GAP_S", 0)
    real_check = tools.check_ip
    monkeypatch.setattr(lookup, "check_ip", lambda ip, allow: ip if ip.startswith("198.51.100.") else real_check(ip, allow))

    async def rdap(client, ip):
        return {"summary": tools._rdap_summary(RDAP), "raw": RDAP}

    async def fake_ptr(ip, timeout=1.5):
        return "mail.muster-technik.de"

    async def fake_cert(ip, sni=None, port=443, timeout=6.0):
        return {"o": None, "cn": "muster-technik.de", "l": None, "st": None, "c": None, "issuer": "Let's Encrypt",
                "san": ["muster-technik.de", "www.muster-technik.de", "*.cdn.provider.example"], "not_after": "2027-01-01T00:00:00+00:00"}

    async def here(host, ip):
        return host == "muster-technik.de"

    monkeypatch.setattr(mod.owner.toolkit, "rdap", rdap)
    monkeypatch.setattr(lookup, "ptr", fake_ptr)
    monkeypatch.setattr(lookup, "peer_cert", fake_cert)
    monkeypatch.setattr(lookup, "resolves_to", here)
    monkeypatch.setattr(lookup, "geo_of", lambda geo, ip: {"country": "DE", "city": "Nürnberg", "lat": 49.45, "lon": 11.08,
                                                            "asn": 64500, "as_name": "ISP Example"})
    return mod


def stream(tc, body):
    r = tc.post("/api/owner", json=body, headers={"Origin": "http://testserver"})
    assert r.status_code == 200, r.text
    return [json.loads(x) for x in r.text.splitlines() if x.strip()]


def test_owner_lookup_active(m):
    geo_calls, web_calls = [], []
    with TestClient(m.app) as tc:
        m.app.state.web = site(calls=web_calls)
        m.app.state.client = nominatim(geo_calls)
        evs = stream(tc, {"ip": IP})
        steps = [e.get("step") for e in evs if e["type"] == "step"]
        assert steps == ["rdap", "dns", "tls", "domains", "imprint", "geocode"]
        res = evs[-1]["result"]
        assert evs[-1]["type"] == "result" and res["ip"] == IP and res["active"]
        assert res["network"]["name"] == "MUSTER-NET" and res["network"]["assigned"] and res["network"]["holder"]["name"] == "Muster Technik GmbH"
        assert res["as"] == {"asn": 64500, "name": "ISP Example"} and res["ptr"] == {"name": "mail.muster-technik.de", "generic": False}
        c = res["company"]
        assert c["company"] == "Muster Technik GmbH" and c["source"] == "imprint" and c["city"] == "Gunzenhausen" and c["points_here"]
        assert res["contact"] == {"phone": "+49 (0) 9831 12345-0", "email": "info@muster-technik.de", "web": "https://muster-technik.de/",
                                  "source": "imprint"}
        assert res["abuse"] == {"email": "abuse@isp.example", "source": "rdap"}
        assert res["confidence"] == "high"
        assert res["location"]["precision"] == "address" and res["location"]["lat"] == 49.1153
        assert res["ip_location"]["city"] == "Nürnberg"
        doms = {d["domain"]: d for d in res["domains"]}
        assert doms["muster-technik.de"]["sources"] == ["cert", "ptr", "rdap"] and doms["muster-technik.de"]["points_here"]
        assert doms["isp.example"].get("provider")  # the abuse domain is the provider's, not the user's
        assert "provider.example" in doms and not doms["provider.example"]["points_here"]
        codes = [e["code"] for e in res["evidence"]]
        assert codes[:3] == ["rdap_holder", "rdap_assigned", "as"] and "domain_here" in codes and "imprint" in codes and "geocoded" in codes
        assert geo_calls == [{"q": "Industriestraße 25, 91710 Gunzenhausen", "format": "jsonv2", "limit": "1", "countrycodes": "de"}]
        assert "https://muster-technik.de/robots.txt" in web_calls and not any("evil.example" in u for u in web_calls)
        # stored: the next call answers from the cache, also for reading without a lookup
        n = len(web_calls)
        again = stream(tc, {"ip": IP})
        assert len(again) == 1 and again[0]["result"]["cached"] and len(web_calls) == n
        got = tc.get(f"/api/owner?ip={IP}").json()
        assert got["result"]["company"]["company"] == "Muster Technik GmbH"
        assert tc.get("/api/owner?ip=10.0.0.1").json()["key"] == "err.tool.private"
        assert tc.get("/api/owner?ip=example.com").json()["key"] == "err.owner.ip"
        # the geocoder keeps its answer: a refreshed lookup does not ask Nominatim again
        stream(tc, {"ip": IP, "refresh": True})
        assert len(geo_calls) == 1
    assert any(r["action"] == "owner_lookup" for r in m.db.query("SELECT action FROM audit"))


def test_owner_lookup_passive_and_robots(m):
    geo_calls = []
    with TestClient(m.app) as tc:
        web_calls: list = []
        m.app.state.web = site(calls=web_calls)
        m.app.state.client = nominatim(geo_calls)
        evs = stream(tc, {"ip": IP, "active": False})
        res = evs[-1]["result"]
        assert [e.get("step") for e in evs if e["type"] == "step"] == ["rdap", "dns", "domains", "geocode"]
        assert not web_calls and res["cert"] is None  # passive: neither the address nor the website is contacted
        assert res["company"]["source"] == "rdap" and res["company"]["company"] == "Muster Technik GmbH"
        assert res["confidence"] == "medium" and {"code": "passive"} in res["notes"]
        assert geo_calls[0]["q"] == "Industriestrasse 25, 91710 Gunzenhausen, GERMANY" and geo_calls[0]["countrycodes"] == "de"
        # robots.txt forbids everything: not even the start page is requested
        calls: list = []
        m.app.state.web = site(robots="User-agent: *\nDisallow: /\n", calls=calls)
        res = stream(tc, {"ip": IP, "refresh": True})[-1]["result"]
        failed = [e for e in res["evidence"] if e["code"] == "imprint_failed"]
        assert failed and failed[0]["params"]["reason"] == "robots"
        assert res["company"]["source"] == "rdap"
        own = [u for u in calls if "//muster-technik.de/" in u]
        assert own and all(u.endswith("/robots.txt") for u in own), own  # (hosts without robots.txt may be read)
        # only the imprint is excluded: the start page (schema.org data) is used, the imprint page is not requested
        calls.clear()
        m.app.state.web = site(robots="User-agent: *\nDisallow: /impressum\n", calls=calls)
        res = stream(tc, {"ip": IP, "refresh": True})[-1]["result"]
        assert "https://muster-technik.de/" in calls and not any("/impressum" in u for u in calls)
        assert res["company"]["source"] == "jsonld" and res["company"]["company"] == "Muster Technik"


def test_owner_provider_block_is_marked_shared(m, monkeypatch):
    from app import tools
    from app.owner import lookup
    raw = json.loads(json.dumps(RDAP))
    raw["type"] = "ALLOCATED PA"
    raw["entities"][0]["vcardArray"][1][1] = ["fn", {}, "text", "ISP Example GmbH"]
    raw["entities"][0]["vcardArray"][1][3] = ["email", {}, "text", "lir@isp.example"]

    async def rdap(client, ip):
        return {"summary": tools._rdap_summary(raw), "raw": raw}

    async def generic(ip, timeout=1.5):
        return "static.7-100-51-198.clients.isp.example"

    monkeypatch.setattr(m.owner.toolkit, "rdap", rdap)
    monkeypatch.setattr(lookup, "ptr", generic)
    with TestClient(m.app) as tc:
        m.app.state.web = site()
        m.app.state.client = nominatim([])
        res = stream(tc, {"ip": IP})[-1]["result"]
        assert res["ptr"]["generic"] and res["company"]["company"] == "Muster Technik GmbH"
        assert res["confidence"] == "medium" and {"code": "shared_possible"} in res["notes"]  # certificate only: shared hosting possible
    assert lookup.generic_ptr("ip-198-51-100-7.example.net", "198.51.100.7")
    assert lookup.generic_ptr("dyn-12.pool.example.net", "198.51.100.7")
    assert not lookup.generic_ptr("mail.muster-technik.de", "198.51.100.7")


def test_owner_registry_unreachable_is_not_stored(m, monkeypatch):
    from app.i18n import AppError

    async def down(client, ip):
        raise AppError("err.tool.network", detail="timeout")

    monkeypatch.setattr(m.owner.toolkit, "rdap", down)
    with TestClient(m.app) as tc:
        m.app.state.web = site()
        m.app.state.client = nominatim([])
        res = stream(tc, {"ip": IP, "active": False})[-1]["result"]
        assert res["network"] is None and {"code": "rdap_failed", "params": {"key": "err.tool.network"}} in res["notes"]
        assert not res.get("cached") and tc.get(f"/api/owner?ip={IP}").json()["result"] is None  # temporary: asked again next time


def test_owner_viewer_reads_only(tmp_path, monkeypatch):
    m = v3.load_app(tmp_path, monkeypatch, AUTH_MODE="password", AUTH_PASSWORD="correct horse battery staple")
    from app.auth import allowed
    assert allowed("viewer", "GET", "/api/owner") and not allowed("viewer", "POST", "/api/owner")
    assert m.owner.target(" 2001:4860:4860::8888 ") == "2001:4860:4860::8888"
