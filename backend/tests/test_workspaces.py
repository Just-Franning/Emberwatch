"""Tests for 3.1 (areas, tool box, object pages, own IP).

Third-party APIs are mocked with their documented formats (Globalping API v1, mnemonic PassiveDNS v3, GreyNoise
Community v3, MalwareBazaar API v1, RIPEstat data API, RDAP RFC 9083, Cert Spotter v1, Gemini generateContent).
DNS runs against a local authoritative test server (UDP + TCP incl. AXFR) that every dnspython resolver is pinned to.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import functools
import json
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import dns.asyncresolver
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import dns.zone
import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_v3 as v3  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)
GEMINI_PROMPTS: list[str] = []
GP: dict = {}

ZONE = """
$ORIGIN example.test.
$TTL 300
@        IN SOA   ns1 hostmaster 1 3600 600 86400 300
@        IN NS    ns1
@        IN A     127.0.0.1
@        IN MX    10 mx1
@        IN TXT   "v=spf1 include:_spf.example.test ~all"
_spf     IN TXT   "v=spf1 ip4:192.0.2.0/24 include:_spf2.example.test -all"
_spf2    IN TXT   "v=spf1 a mx -all"
_dmarc   IN TXT   "v=DMARC1; p=none; pct=50"
selector1._domainkey IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
_mta-sts IN TXT   "v=STSv1; id=20261020"
ns1      IN A     127.0.0.1
mx1      IN A     127.0.0.1
mta-sts  IN A     127.0.0.1
"""
ZONE_RDAP = """
$ORIGIN rdap.org.
$TTL 300
@ IN SOA ns hostmaster 1 3600 600 86400 300
@ IN NS  ns
@ IN A   104.16.0.1
"""


class FakeDNS:
    """Minimal authoritative server for the test zones (UDP and TCP, AXFR on TCP)."""

    def __init__(self) -> None:
        self.zones = [dns.zone.from_text(ZONE, relativize=False), dns.zone.from_text(ZONE_RDAP, relativize=False)]
        self.ad = False
        self.axfr = True
        self.stop = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket()
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(16)
        for fn in (self._serve_udp, self._serve_tcp):
            threading.Thread(target=fn, daemon=True).start()

    def answer(self, q: dns.message.Message) -> dns.message.Message:
        r = dns.message.make_response(q)
        r.flags |= dns.flags.AA
        if self.ad:
            r.flags |= dns.flags.AD
        qq = q.question[0]
        zone = next((z for z in self.zones if qq.name.is_subdomain(z.origin)), None)
        if zone is None:
            r.set_rcode(dns.rcode.REFUSED)
            return r
        node = zone.get_node(qq.name)
        if node is None:
            r.set_rcode(dns.rcode.NXDOMAIN)
            return r
        rds = node.get_rdataset(dns.rdataclass.IN, qq.rdtype)
        if rds is not None:
            r.answer.append(dns.rrset.from_rdata_list(qq.name, rds.ttl, list(rds)))
        return r

    def _serve_udp(self) -> None:
        self.udp.settimeout(0.3)
        while not self.stop.is_set():
            try:
                data, addr = self.udp.recvfrom(4096)
            except OSError:
                continue
            try:
                self.udp.sendto(self.answer(dns.message.from_wire(data)).to_wire(), addr)
            except Exception:
                continue

    def _serve_tcp(self) -> None:
        self.tcp.settimeout(0.3)
        while not self.stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                continue
            try:
                conn.settimeout(3)
                ln = struct.unpack("!H", conn.recv(2))[0]
                data = b""
                while len(data) < ln:
                    data += conn.recv(ln - len(data))
                q = dns.message.from_wire(data)
                qq = q.question[0]
                if qq.rdtype == dns.rdatatype.AXFR:
                    r = dns.message.make_response(q)
                    zone = next((z for z in self.zones if z.origin == qq.name), None)
                    if not self.axfr or zone is None:
                        r.set_rcode(dns.rcode.REFUSED)
                    else:
                        soa = zone.find_rrset(zone.origin, dns.rdatatype.SOA)
                        r.answer.append(soa)
                        for name, rds in zone.iterate_rdatasets():
                            if rds.rdtype != dns.rdatatype.SOA:
                                r.answer.append(dns.rrset.from_rdata_list(name, rds.ttl, list(rds)))
                        r.answer.append(soa)
                else:
                    r = self.answer(q)
                wire = r.to_wire()
                conn.sendall(struct.pack("!H", len(wire)) + wire)
            except Exception:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self.stop.set()
        self.udp.close()
        self.tcp.close()


@pytest.fixture()
def fdns(monkeypatch):
    srv = FakeDNS()
    base_set = dns.resolver.BaseResolver.nameservers.fset

    class LocalResolver(dns.asyncresolver.Resolver):
        def __init__(self, filename: str = "/etc/resolv.conf", configure: bool = True) -> None:
            super().__init__(configure=False)
            self.port = srv.port
            base_set(self, ["127.0.0.1"])

        @property
        def nameservers(self):  # pinned to the test server
            return self._nameservers

        @nameservers.setter
        def nameservers(self, value) -> None:
            pass

    monkeypatch.setattr(dns.asyncresolver, "Resolver", LocalResolver)
    monkeypatch.setattr(dns.query, "xfr", functools.partial(dns.query.xfr, port=srv.port))
    yield srv
    srv.close()


def handler(request: httpx.Request) -> httpx.Response:
    v3.CALLS.append(request)
    h, path = request.url.host, request.url.path
    params = dict(request.url.params)
    if h == "api.globalping.io":
        if request.method == "POST":
            body = json.loads(request.content)
            GP["body"] = body
            if GP.get("status") == 429:
                return httpx.Response(429, json={"error": {"type": "rate_limit_exceeded", "message": "limit"}})
            return httpx.Response(202, json={"id": "abc123", "probesCount": 2})
        assert path == "/v1/measurements/abc123"
        return httpx.Response(200, json={"id": "abc123", "type": GP["body"]["type"], "status": "finished", "probesCount": 2, "results": [
            {"probe": {"continent": "EU", "region": "Western Europe", "country": "DE", "state": None, "city": "Frankfurt",
                       "asn": 24940, "network": "Hetzner Online GmbH", "latitude": 50.11, "longitude": 8.68, "tags": [], "resolvers": []},
             "result": {"status": "finished", "rawOutput": "PING ...", "resolvedAddress": "93.184.216.34",
                        "resolvedHostname": "example.com", "timings": [{"rtt": 12.1, "ttl": 55}],
                        "stats": {"min": 11.9, "avg": 12.3, "max": 12.8, "total": 3, "rcv": 3, "drop": 0, "loss": 0}}},
            {"probe": {"continent": "NA", "region": "Northern America", "country": "US", "state": "NY", "city": "New York",
                       "asn": 3356, "network": "Lumen", "latitude": 40.71, "longitude": -74.0, "tags": [], "resolvers": []},
             "result": {"status": "failed", "rawOutput": "ping: unknown host", "resolvedAddress": None, "resolvedHostname": None,
                        "timings": [], "stats": {"min": None, "avg": None, "max": None, "total": 3, "rcv": 0, "drop": 3, "loss": 100}}},
        ]})
    if h == "api.mnemonic.no":
        assert path.startswith("/pdns/v3/") and params["limit"] == "300"
        if "quota" in path:
            return httpx.Response(402, json={"responseCode": 402, "messages": [{"message": "Resource limit exceeded"}]})
        ms = int(NOW.timestamp() * 1000)
        return httpx.Response(200, json={"responseCode": 200, "count": 2, "limit": 300, "offset": 0, "data": [
            {"rrclass": "in", "rrtype": "a", "query": "bad.example.org", "answer": "8.8.4.4", "firstSeenTimestamp": ms - 86400000 * 30,
             "lastSeenTimestamp": ms - 86400000, "times": 12, "tlp": "white"},
            {"rrclass": "in", "rrtype": "cname", "query": "bad.example.org", "answer": "cdn.example.net", "firstSeenTimestamp": ms - 86400000 * 90,
             "lastSeenTimestamp": ms - 86400000 * 40, "times": 3, "tlp": "white"},
        ]})
    if h == "api.greynoise.io":
        ip = path.rsplit("/", 1)[-1]
        if ip == "1.2.3.4":
            return httpx.Response(404, json={"ip": ip, "noise": False, "riot": False, "message": "IP not observed scanning the internet or contained in RIOT data set."})
        return httpx.Response(200, json={"ip": ip, "noise": True, "riot": False, "classification": "malicious", "name": "unknown",
                                         "link": f"https://viz.greynoise.io/ip/{ip}", "last_seen": "2026-10-19", "message": "Success"})
    if h == "mb-api.abuse.ch":
        assert request.headers["auth-key"] == "tf-test"
        form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
        assert form["query"] == "get_info"
        if form["hash"].startswith("0000"):
            return httpx.Response(200, json={"query_status": "hash_not_found"})
        if form["hash"].startswith("ffff"):
            return httpx.Response(200, json={"query_status": "illegal_hash"})
        return httpx.Response(200, json={"query_status": "ok", "data": [{
            "sha256_hash": "a" * 64, "sha1_hash": "b" * 40, "md5_hash": "c" * 32, "first_seen": "2026-10-01 10:00:00",
            "last_seen": None, "file_name": "invoice.xlsm", "file_size": 12345, "file_type_mime": "application/vnd.ms-excel",
            "file_type": "xlsm", "reporter": "abuse_ch", "origin_country": "DE", "signature": "QakBot", "tags": ["qakbot", "xlsm"],
            "delivery_method": "email_attachment", "vendor_intel": {"ReversingLabs": {}, "ANY.RUN": []}}]})
    if h == "stat.ripe.net":
        if path.startswith("/data/rpki-validation/"):
            status = {("64500", "185.199.108.0/24"): "invalid_asn", ("45.67.0.0/22", "3320"): "valid"}.get(
                (params["resource"], params["prefix"]), "valid" if params["prefix"] != "10.0.0.0/8" else "unknown")
            return httpx.Response(200, json={"status": "ok", "data": {"resource": params["resource"], "prefix": params["prefix"],
                                                                      "status": status, "validating_roas": []}})
        if path.startswith("/data/prefix-overview/") and params["resource"].startswith("185.199.108."):
            return httpx.Response(200, json={"data": {"resource": "185.199.108.0/24", "announced": True, "is_less_specific": False,
                                                      "asns": [{"asn": 3320, "holder": "DTAG"}, {"asn": 64500, "holder": "Evil"}]}})
    if h == "rdap.org":
        assert request.headers["accept"].startswith("application/rdap+json")
        return httpx.Response(200, json={
            "objectClassName": "domain", "handle": "D1", "ldhName": "neu-shop.example", "status": ["client transfer prohibited"],
            "events": [{"eventAction": "registration", "eventDate": (NOW - dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")},
                       {"eventAction": "expiration", "eventDate": (NOW + dt.timedelta(days=12)).strftime("%Y-%m-%dT%H:%M:%SZ")}],
            "nameservers": [{"objectClassName": "nameserver", "ldhName": "ns1.example.net"}],
            "entities": [{"objectClassName": "entity", "roles": ["registrar"],
                          "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]]}]})
    if h == "generativelanguage.googleapis.com":
        body = json.loads(request.content)
        prompt = body["contents"][0]["parts"][0]["text"]
        GEMINI_PROMPTS.append(prompt)
        schema = body["generationConfig"].get("responseSchema", {})
        if "answer" in schema.get("properties", {}):
            ans = {"answer": "Weitere Prüfung empfohlen.", "charts": [], "caveats": []}
        else:
            ans = {"title": "Objektbewertung", "summary": "- Punkt", "findings": [{"title": "C2", "detail": "x", "severity": "high"}],
                   "charts": [], "caveats": ["Datenlage"], "recommendations": ["Ports prüfen"]}
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": json.dumps(ans)}]}, "finishReason": "STOP"}]})
    return v3.handler(request)


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture()
def m(tmp_path, monkeypatch):
    mod = v3.load_app(tmp_path, monkeypatch, TOOLS_ALLOW_PRIVATE="1", GEMINI_API_KEY="gm-test", HOME_REGION="DE,AT,CH",
                      HOME_REGION_NAME="DACH", LANGUAGE="en")
    GP.clear()
    GEMINI_PROMPTS.clear()
    from app.toolbox import tools_ident
    tools_ident._pdns_calls.clear()
    return mod


def ctx(m, c, lang: str = "en"):
    from app.toolbox.common import Ctx
    return Ctx(m.S, m.db, m.geo, m.reputation, m.toolkit, m.matcher, m.domains, m.surface, c, lang)


def run(m, tool: str, target: str, params: dict | None = None, consent: bool = False, c=None, lang: str = "en") -> list[dict]:
    spec = m.tbreg.BY_ID[tool]
    c = c or client()
    t, kind, p = m.tbrun.prepare(spec, target, params or {}, consent)

    async def go():
        return [e async for e in m.tbrun.run_tool(ctx(m, c, lang), spec, t, kind, p)]
    return asyncio.run(go())


def result(events: list[dict]) -> dict:
    last = events[-1]
    assert last["type"] == "result", events
    return last["result"]


def keys(res: dict) -> dict[str, str]:
    return {f["key"]: f["sev"] for f in res["findings"]}


def section(res: dict, title_part: str) -> dict:
    return next(s for s in res["sections"] if title_part.lower() in (s.get("title") or "").lower())


def seed(m) -> None:
    c = v3.mock_client()
    v3.feeds(m, c)

    async def more():
        await m.ransomware.collect(c, m.db, m.S.user_agent, m.S.ransomware_live_api_key)
        await m.infra.collect(c, m.db, "cf-test")
        await m.epss.collect(c, m.db, m.S.user_agent)
    asyncio.run(more())
    for kind, value in (("ip", "8.8.8.8"), ("domain", "example.de"), ("cidr", "78.46.2.0/24"), ("asn", "3320")):
        m.db.insert("INSERT INTO watchlist(kind, value, label, created_at) VALUES(?,?,?,?)", (kind, value, None, m.utcnow()))
    m.watchlist.scan(m.db)
    m.matcher.invalidate()


# ------------------------------------------------------------------------------------------------------------------------
# Registry, detection, texts

def test_registry_and_texts(m):
    ids = [t.id for t in m.tbreg.TOOLS]
    assert len(ids) == len(set(ids)) and {"ping", "traceroute", "ipinfo", "globalping", "pathq", "mailhdr"} <= set(ids)
    assert [t.id for t in m.tbreg.TOOLS if t.bar == "main"] == ["ping", "traceroute", "ipinfo"]
    de, en = m.i18n.T["de"], m.i18n.T["en"]
    assert set(de) == set(en)
    for t in m.tbreg.TOOLS:
        for k in (f"tb.tool.{t.id}", f"tb.desc.{t.id}"):
            assert k in de and k in en
        for p in t.params:
            if p.kind != "text":
                assert f"tb.param.{t.id}.{p.name}" in en
    # every literal text key used by the new modules exists in both languages, with the same placeholders
    src = "".join((ROOT / "backend/app" / f).read_text() for f in ("objects.py", "myip.py", "toolbox/runner.py",
                                                                    "toolbox/tools_net.py", "toolbox/tools_ident.py",
                                                                    "toolbox/tools_threat.py", "toolbox/tools_harden.py",
                                                                    "toolbox/tools_mail.py", "toolbox/result.py"))
    used = set(re.findall(r'"((?:tb|ob|err\.tb|err\.obj|err\.myip|myip)\.[a-z0-9_.]+[a-z0-9])"', src))
    alert_keys = {k for k in used if k in ("myip.changed", "myip.listed", "myip.ports")}  # rendered as alert.<key>.title/.detail
    assert alert_keys and all(f"alert.{k}.{x}" in en for k in alert_keys for x in ("title", "detail"))
    missing = sorted(k for k in used - alert_keys if k not in en)
    assert used and not missing, missing
    ph = re.compile(r"\{(\w+)")
    assert not [k for k in en if set(ph.findall(en[k])) != set(ph.findall(de[k]))]
    det = m.tb_detect
    assert det("hxxps://evil[.]example/x")["type"] == "url"
    assert det("AS3320")["type"] == "asn" and det("cve-2024-3400")["value"] == "CVE-2024-3400"
    assert det("Received: from a by b\nSubject: x\n")["type"] == "mailhdr"


def test_plural_forms():
    from app import i18n
    assert i18n.t("en", "tb.s.trace_ok", n=1) == "Target reached after 1 hop"
    assert i18n.t("en", "tb.s.trace_ok", n=12) == "Target reached after 12 hops"
    assert i18n.t("de", "tb.f.cert_expiring", days=1) == "Zertifikat läuft in 1 Tag ab"
    assert i18n.t("de", "tb.s.mail", hops=1, spf="pass", dkim="pass", dmarc="pass", links=0, atts=1).endswith("0 Links · 1 Anhang")
    assert i18n.t("de", "ob.f.asn_c2", n=1).startswith("1 aktiver C2-Server")


def test_input_errors_are_translated(m):
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        r = tc.post("/api/tb/run", json={"tool": "tls", "target": "just some words"}, headers={"Cookie": "ew_lang=de"})
        assert r.status_code == 400 and r.json()["detail"] == "Dieses Werkzeug passt nicht zur Eingabe (erkannt: freier Text)."
        r = tc.post("/api/tb/run", json={"tool": "dns", "target": "example.test", "params": {"axfr": True}})
        assert r.status_code == 400 and r.json()["key"] == "err.tb.consent"
        r = tc.post("/api/tb/run", json={"tool": "cyberchef", "target": "x"})
        assert r.status_code == 400 and r.json()["key"] == "err.tb.client_only"
        r = tc.post("/api/tb/recipe", json={"recipe": "ip", "target": "example.org"})
        assert r.status_code == 400 and r.json()["key"] == "err.tb.recipe_input"
        reg = tc.get("/api/tb/registry").json()
        hashtool = next(t for t in reg["tools"] if t["id"] == "hash")
        assert hashtool["available"] is True and hashtool["third_party"] == "MalwareBazaar (abuse.ch)"


# ------------------------------------------------------------------------------------------------------------------------
# Tools against mocked third parties

def test_globalping(m, fdns):
    res = result(run(m, "globalping", "rdap.org", {"mode": "ping", "limit": 2, "location": "Europe"}))
    assert GP["body"] == {"type": "ping", "target": "rdap.org", "limit": 2, "measurementOptions": {"packets": 3},
                          "locations": [{"magic": "Europe"}]}
    assert res["third_party"] and res["target_sees"] is True
    assert keys(res) == {"tb.f.gp_failed": "medium"}  # 1 of 2 probes failed
    probes = section(res, "probe")["rows"]
    assert probes[0][0] == "Frankfurt, Germany" and probes[0][2]["sev"] == "ok"
    assert len([p for p in res["map"]["points"] if p["kind"] == "probe"]) == 2
    result(run(m, "globalping", "https://rdap.org:8443/x", {"mode": "traceroute"}))
    assert GP["body"]["target"] == "rdap.org"  # host taken from a URL with port
    # private addresses, internal names and names that resolve to private addresses never go to Globalping
    for target in ("10.1.2.3", "nas.fritz.box", "example.test", "https://[fd00::1]:443/"):
        GP["body"] = None
        ev = run(m, "globalping", target, {"mode": "ping"})
        assert ev[-1]["type"] == "error" and ev[-1]["key"] == "err.tb.third_private", (target, ev[-1])
        assert GP["body"] is None
    # names this server cannot resolve (e.g. blocked by a DNS filter) are still measured
    result(run(m, "globalping", "blocked.example.net", {"mode": "ping"}))
    assert GP["body"]["target"] == "blocked.example.net"
    GP["status"] = 429
    assert run(m, "globalping", "rdap.org", {"mode": "http"})[-1]["key"] == "err.tb.gp_limit"
    assert GP["body"]["measurementOptions"] == {"request": {"method": "HEAD", "path": "/"}, "protocol": "HTTPS"}


def test_third_party_privacy(m):
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        fit = tc.get("/api/tb/detect", params={"q": "192.168.1.10"}).json()["tools"]
        assert "greynoise" not in fit and "globalping" not in fit and {"ipinfo", "ping", "dns"} <= set(fit)
        assert "greynoise" in tc.get("/api/tb/detect", params={"q": "45.155.205.9"}).json()["tools"]
        assert "ct" not in tc.get("/api/tb/detect", params={"q": "it@nas.fritz.box"}).json()["tools"]
    for tool, target in (("greynoise", "192.168.1.10"), ("pdns", "nas.fritz.box"), ("rdap", "10.0.0.0/8"),
                         ("bgp", "172.16.0.1"), ("pdns", "srv01.corp"), ("mailsec", "it@mail.intern.lan")):
        with pytest.raises(m.AppError) as exc:
            m.tbrun.prepare(m.tbreg.BY_ID[tool], target, {}, False)
        assert exc.value.key == "err.tb.third_private", (tool, target)
    c = client()

    async def go():  # in a recipe the third-party steps report the reason instead of sending
        val, kind = m.tbrun.prepare_recipe("ip", "10.20.30.40")
        return [e async for e in m.tbrun.run_recipe(ctx(m, c), "ip", val, kind)]
    final = asyncio.run(go())[-1]["result"]
    errs = {s["tool"]: s["error"] for s in final["steps"] if s.get("error")}
    assert set(errs) == {"greynoise", "pdns", "bgp"} and all("not sent to" in e for e in errs.values())
    assert not final["third_party"] or "GreyNoise" not in final["third_party"]


def test_pdns_greynoise_hash(m):
    seed(m)
    res = result(run(m, "pdns", "bad.example.org"))
    assert keys(res) == {"tb.f.pdns_bad": "medium"} and "8.8.4.4" in res["findings"][0]["text"]
    rows = section(res, "passive")["rows"]
    assert rows[0][0] == "A" and rows[0][2]["sev"] == "high" and rows[1][2]["obj"] == {"type": "domain", "value": "cdn.example.net"}
    n = len([c for c in v3.CALLS if c.url.host == "api.mnemonic.no"])
    run(m, "pdns", "bad.example.org")
    assert len([c for c in v3.CALLS if c.url.host == "api.mnemonic.no"]) == n  # cached for 24 h
    assert run(m, "pdns", "quota.example.org")[-1]["key"] == "err.tb.quota"

    gn = result(run(m, "greynoise", "45.155.205.9"))
    assert keys(gn) == {"tb.f.gn_malicious": "high"} and gn["third_party"] == "GreyNoise"
    assert keys(result(run(m, "greynoise", "1.2.3.4"))) == {"tb.f.gn_unseen": "info"}

    hs = result(run(m, "hash", "a" * 64))
    assert keys(hs) == {"tb.f.mb_known": "high"} and {"type": "malware", "value": "QakBot", "label": None} in hs["related"]
    assert keys(result(run(m, "hash", "0" * 64))) == {"tb.f.mb_unknown": "info"}
    assert run(m, "hash", "f" * 64)[-1]["key"] == "err.tb.mb_status"


def test_bgp_rdap_ct_lookalike(m, fdns):
    pre = result(run(m, "bgp", "185.199.108.0/24"))
    assert keys(pre) == {"tb.f.moas": "medium", "tb.f.rpki_invalid": "high"}
    asn = result(run(m, "bgp", "AS3320"))
    assert keys(asn) == {"tb.f.rpki_unknown_n": "low"}
    assert [r[2]["t"] for r in section(asn, "prefix")["rows"]] == ["valid", "no ROA"]

    rd = result(run(m, "rdap", "neu-shop.example"))
    assert keys(rd) == {"tb.f.domain_young": "medium", "tb.f.domain_expiring": "low"}

    cert = {"id": "1", "tbs_sha256": "aa", "dns_names": ["shop.example", "*.shop.example"], "issuer": {"friendly_name": "R11"},
            "not_before": "2026-09-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z"}
    v3.STATE["ct"] = {"": [cert, {**cert, "id": "2", "issuer": {"friendly_name": "E6"}}, {**cert, "id": "3", "issuer": {"friendly_name": "Other CA"}}],
                      "3": []}
    ct = result(run(m, "ct", "shop.example"))
    assert keys(ct) == {"tb.f.ct_issuers": "info", "tb.f.ct_wildcard": "info"}

    reg = {"exampel.de", "examp1e.de"}

    async def exists(self, res, name):
        return False if name.startswith("ew-") else name in reg

    async def details(self, res, name):
        return (name == "examp1e.de", ["198.51.100.10"])
    m.Domains._exists, m.Domains._details = exists, details
    lk = result(run(m, "lookalike", "example.de"))
    assert keys(lk) == {"tb.f.lookalike_mx": "medium"}
    assert sorted(r[0]["t"] for r in section(lk, "look-alike")["rows"]) == ["examp1e.de", "exampel.de"]


def test_dns_deep_and_axfr(m, fdns):
    res = result(run(m, "dns", "example.test", {"resolver": "cloudflare"}))
    types = {r[0] for r in section(res, "record")["rows"]}
    assert {"A", "MX", "NS", "TXT", "SOA"} <= types
    assert keys(res) == {"tb.f.dnssec_off": "low", "tb.f.no_caa": "low"}
    assert res["level"] == "active" and res["target_sees"] is False
    fdns.ad = True
    assert "tb.f.dnssec_off" not in keys(result(run(m, "dns", "example.test", {"resolver": "cloudflare"})))
    ax = result(run(m, "dns", "example.test", {"resolver": "cloudflare", "axfr": True}, consent=True))
    assert ax["level"] == "intrusive" and ax["target_sees"] is True and keys(ax)["tb.f.axfr_open"] == "high"
    sample = next(s["text"] for s in ax["sections"] if s["kind"] == "text")
    assert "mx1.example.test. A 127.0.0.1" in sample and sample.count(" SOA ") == 1
    assert section(ax, "transfer")["rows"][0][2]["t"] == "open: 13 records"
    fdns.axfr = False
    ax2 = result(run(m, "dns", "example.test", {"resolver": "cloudflare", "axfr": True}, consent=True))
    assert "tb.f.axfr_open" not in keys(ax2) and section(ax2, "transfer")["rows"][0][2]["sev"] == "ok"


def test_mailsec(m, fdns):
    res = result(run(m, "mailsec", "info@example.test"))
    k = keys(res)
    assert k["tb.f.spf_soft"] == "low" and k["tb.f.dmarc_none"] == "medium" and k["tb.f.dmarc_pct"] == "low"
    assert k["tb.f.dmarc_rua"] == "info" and k["tb.f.sts_policy_failed"] == "medium" and k["tb.f.dnssec_off"] == "low"
    assert "tb.f.dkim_none" not in k and "tb.f.spf_missing" not in k
    rows = {r[0]: r for r in section(res, "security")["rows"]}
    assert "4" in rows["SPF"][2]  # include + include + a + mx (RFC 7208 4.6.4)
    assert "DKIM (selector1)" in rows and rows["TLS-RPT"][1]["sev"] == "info"
    assert res["object"] == {"type": "domain", "value": "example.test"}


MAIL = """Received: from mx.recv.example (mx.recv.example [192.0.2.10]) by inbox.recv.example with ESMTPS; Tue, 20 Oct 2026 10:00:05 +0000
Received: from out.sender.example (out.sender.example [198.51.100.7]) by mx.recv.example with ESMTP; Tue, 20 Oct 2026 10:00:01 +0000
Authentication-Results: inbox.recv.example; spf=pass smtp.mailfrom=bank.example; dkim=none; dmarc=fail header.from=bank.example
From: "Bank" <service@bank.example>
Reply-To: help@collector.example
To: you@recv.example
Subject: Konto gesperrt – Grüße
Date: Tue, 20 Oct 2026 10:00:00 +0000
Message-ID: <1@bank.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/html; charset="x-unknown-charset"

<p>Bitte <a class="btn" href="https://login.evil.example/x?a=1&amp;b=2">https://www.bank.example/login</a> pr&uuml;fen.</p>
<a href='http://203.0.113.9/p'>hier</a>
--b1
Content-Type: application/octet-stream; name="rechnung.pdf.exe"
Content-Disposition: attachment; filename="rechnung.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA
--b1
Content-Type: application/pdf
Content-Disposition: attachment; filename="Rechnung_März.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQK
--b1
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

Grüße, Ihre Bank: https://bänk-login.example/ö
--b1--
"""


def test_mailhdr(m):
    res = result(run(m, "mailhdr", MAIL))
    k = keys(res)
    assert sorted(f["sev"] for f in res["findings"] if f["key"] == "tb.f.mail_auth") == ["high", "low"]  # dmarc=fail, dkim=none
    assert k["tb.f.mail_replyto"] == "medium" and k["tb.f.mail_mismatch"] == "medium"
    assert k["tb.f.mail_att"] == "high" and res["verdict"]["sev"] == "high"
    path = section(res, "path")["rows"]
    assert [r[2]["t"] if isinstance(r[2], dict) else r[2] for r in path] == ["198.51.100.7", "192.0.2.10"]  # oldest hop first
    links = {r[0]["t"]: r for r in section(res, "links")["rows"]}
    assert "https://login.evil.example/x?a=1&b=2" in links and "http://203.0.113.9/p" in links
    att = section(res, "attachments")["rows"]
    assert att[0][0]["t"] == "rechnung.pdf.exe" and att[0][3]["obj"]["type"] == "hash"
    assert att[1][0] == "Rechnung_März.pdf"  # raw UTF-8 in MIME headers (common) is read correctly
    assert res["target"] == "Konto gesperrt – Grüße" and any("bänk-login.example" in u or "xn--" in u for u in links)
    assert res["target_sees"] is False and res["third_party"] is None  # lookup off: nothing leaves the server


def test_mail_anchor_parsing_is_linear(m):
    from app.toolbox import tools_mail as tm
    html = '<a class="x" href="https://a.example/1">A <b>bold</b></a> <A\nHREF=\'https://b.example\'>B</a ><a href=https://c.example/>C'
    assert tm.anchors(html) == [("https://a.example/1", "A <b>bold</b>"), ("https://b.example", "B"), ("https://c.example/", "C")]
    assert tm.anchors('<a href="https://x.example">one<a name="n">two</a>') == [("https://x.example", "one")]  # <a> ends a link
    assert tm.shown_hosts("https://www.Bank.example/login") == ["www.bank.example"]
    assert tm.shown_hosts("Kontakt: service@bank.example.") == ["bank.example"]
    assert tm.shown_hosts("Version 1.2.3") == [] and tm.shown_hosts("http://203.0.113.9/p") == []

    def mismatch(body: str) -> list:
        mail = f"From: a@b.example\nMIME-Version: 1.0\nContent-Type: text/html\n\n{body}\n"
        return tm._read(mail)["mismatches"]
    real = "https://login.evil.example/x"
    assert mismatch(f'<a href="{real}">https://www.bank.example/</a>') == [("www.bank.example", "login.evil.example")]
    # padding and decoys do not hide the mismatch: long hidden text, a decoy with the real domain first, unquoted href
    pad = '<span style="display:none">' + "x " * 3000 + "</span>"
    assert mismatch(f'<a href="{real}">{pad}https://www.bank.example/</a>')
    assert mismatch(f'<a href="{real}"><span hidden>evil.example</span> www.bank.example</a>')
    assert mismatch(f"<a href={real}>www.bank.example</a>")
    assert mismatch(f'<a href="{real}">Jetzt anmelden</a>') == []

    started = time.perf_counter()
    crafted = ("<a href='https://x.example/'>" * 40000) + ("<a " + "x" * 50) * 20000 + "<" * 200000
    assert all(not tm.shown_hosts(tm.TAG.sub("", inner)) for _, inner in tm.anchors(crafted))
    crafted = ('<a href="https://x.example">' + "a." * 1990 + "1</a>") * 500
    assert all(not tm.shown_hosts(tm.TAG.sub("", inner)) for _, inner in tm.anchors(crafted))
    assert time.perf_counter() - started < 3  # the former patterns needed minutes for these


def test_recipes(m, fdns):
    seed(m)
    c = client()

    async def go(rid, target):
        kind_t = m.tbrun.prepare_recipe(rid, target)
        return [e async for e in m.tbrun.run_recipe(ctx(m, c), rid, *kind_t)]
    ev = asyncio.run(go("ip", "8.8.4.4"))
    final = ev[-1]["result"]
    assert [s["tool"] for s in final["steps"]] == ["ipinfo", "bgp", "pdns", "ioc", "greynoise"]  # registry order
    assert final["verdict"]["sev"] == "high" and final["level"] == "passive" and final["target_sees"] is False
    parties = final["third_party"]
    assert all(p in parties for p in ("GreyNoise", "mnemonic", "RIPEstat"))
    mail = asyncio.run(go("mail", "From: a@b.example\nTo: c@d.example\nSubject: x\n\nbody"))
    assert mail[-1]["type"] == "result" and mail[-1]["result"]["steps"][0]["tool"] == "mailhdr"
    hist = m.tbrun.history(m.db, "ip", "8.8.4.4", 10)
    assert hist and hist[0]["recipe"] == "ip"


# ------------------------------------------------------------------------------------------------------------------------
# Object pages, deep views, Gemini per object

def test_object_pages(m):
    seed(m)
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        tc.app.state.client = client()
        ip = tc.get("/api/obj", params={"type": "ip", "value": "8.8.4.4"}).json()
        assert ip["risk"]["sev"] == "high" and "ob.f.c2" in [f["key"] for f in ip["risk"]["reasons"]]
        assert "ipinfo" in ip["tools"] and "ip" in ip["recipes"]
        own = tc.get("/api/obj", params={"type": "ip", "value": "8.8.8.8"}).json()
        assert own["mine"]["assets"][0]["value"] == "8.8.8.8"
        net = tc.get("/api/obj", params={"type": "cidr", "value": "78.46.2.0/24"}).json()
        assert {f["key"] for f in net["risk"]["reasons"]} >= {"ob.f.net_c2", "ob.f.own"}
        dom = tc.get("/api/obj", params={"type": "domain", "value": "evil.example.com"}).json()
        assert dom["risk"]["sev"] == "high"
        grp = tc.get("/api/obj", params={"type": "group", "value": "akira"}).json()
        assert grp["title"] == "akira" and any(s.get("no_ai") for s in grp["sections"])
        cc = tc.get("/api/obj", params={"type": "country", "value": "de"}).json()
        assert cc["title"] == "Germany" and any(s["kind"] == "chart" for s in cc["sections"])
        asn = tc.get("/api/obj", params={"type": "asn", "value": "AS3320"}).json()
        bgp = [f for f in asn["risk"]["reasons"] if f["key"] == "ob.f.asn_bgp"]
        assert len(bgp) == 1 and "3" in bgp[0]["text"]  # three hijack events, one finding
        ven = tc.get("/api/obj", params={"type": "vendor", "value": "Microsoft"}).json()
        assert ven["type"] == "vendor"
        for bad in ({"type": "ip", "value": "300.1.1.1"}, {"type": "x", "value": "1"}, {"type": "malware", "value": "<b>"},
                    {"type": "cidr", "value": "10.0.0.0/33"}):
            r = tc.get("/api/obj", params=bad)
            assert r.status_code == 400, bad
        kev = tc.get("/api/kev", params={"sort": "epss"}).json()
        assert kev["total"] == kev["catalog"] > 0 and all("watched" in r and "exposed" in r for r in kev["rows"])
        assert tc.get("/api/kev", params={"ransomware": "true"}).json()["total"] <= kev["total"]
        inf = tc.get("/api/infra", params={"days": 30}).json()
        assert inf["total"] >= 1 and all(e["title"] for e in inf["events"])
        assert tc.get("/api/infra", params={"kind": "hijack", "cc": "DE"}).json()["counts"].get("hijack", 0) >= 1


def test_gemini_object_context(m):
    seed(m)
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        tc.app.state.client = client()
        r = tc.post("/api/ai/object", json={"type": "group", "value": "akira"}).json()
        assert r["scope"] == "obj:group:akira" and r["title"] == "Objektbewertung"
        prompt = GEMINI_PROMPTS[-1]
        assert "akira" in prompt and "Firma" not in prompt and "<script" not in prompt  # leak site titles stay local
        r2 = tc.post("/api/ai/object", json={"type": "ip", "value": "8.8.8.8"}).json()
        prompt = GEMINI_PROMPTS[-1]
        data = json.loads(prompt.split("<<<\n", 1)[1].rsplit("\n>>>", 1)[0])
        assert data["object"]["value"] == "8.8.8.8" and data["relates_to_own_assets"] is True
        assert not [x for x in data["risk"]["reasons"] if "assets" in x["text"].lower()]  # own asset names are not sent
        assert "IP info" in data["available_tools"] or "IP-Info" in data["available_tools"] or data["available_tools"]
        fu = tc.post("/api/ai/followup", json={"report_id": r2["id"], "question": "Was tun?"}).json()
        assert fu["answer"] and "8.8.8.8" in GEMINI_PROMPTS[-1]
        assert [x["scope"] for x in tc.get("/api/ai/reports", params={"scope": "obj:ip:8.8.8.8"}).json()] == ["obj:ip:8.8.8.8"]
        n = len(GEMINI_PROMPTS)
        for typ, val in (("ip", "10.0.0.5"), ("domain", "nas.fritz.box"), ("cidr", "192.168.0.0/16"), ("url", "http://192.168.1.1/admin")):
            assert tc.get("/api/obj", params={"type": typ, "value": val}).json()["private"] is True
            r = tc.post("/api/ai/object", json={"type": typ, "value": val})
            assert r.status_code == 400 and r.json()["key"] == "err.tb.third_private", (typ, val)
        assert len(GEMINI_PROMPTS) == n and tc.get("/api/obj", params={"type": "ip", "value": "8.8.8.8"}).json()["private"] is False


def test_object_alerts_whole_values_and_own_products(m):
    from app import alerts
    from app.objects import object_context
    alerts.add(m.db, "syslog", "high", "syslog.hit", {"indicator": "client:1.2.3.4"}, "old")
    for i in range(600):  # a noisy neighbour does not push the object's own (older) alert out
        alerts.add(m.db, "syslog", "low", "syslog.hit", {"indicator": f"1.2.3.4{i % 10}"}, f"n{i}")
    for i, params in enumerate(({"indicator": "1.2.3.45"}, {"indicator": "11.2.3.4"}, {"indicator": "1.2.3.4", "line": "x"},
                                {"asset": "AS13335 (Cloudflare)"}, {"asset": "AS1 (Level3)"}, {"origin": 1, "prefix": "4.0.0.0/9"},
                                {"names": ["www.example.de"]}, {"names": ["www.example.de.evil.example"]})):
        alerts.add(m.db, "syslog", "medium", "syslog.hit", params, f"r{i}")

    def page(t, v):
        return asyncio.run(m.objects.build(t, v, "en", client()))
    assert len(page("ip", "1.2.3.4")["alerts"]) == 2  # not 1.2.3.45, 11.2.3.4 or 1.2.3.40-49
    assert len(page("asn", "AS1")["alerts"]) == 2  # asset label and numeric BGP origin, not AS13335
    assert len(page("domain", "example.de")["alerts"]) == 1  # subdomain yes, look-alike suffix no
    m.db.insert("INSERT INTO products(vendor, product, created_at) VALUES(?,?,?)", ("Sophos", "Firewall XG", m.utcnow()))
    ven = page("vendor", "Sophos")
    assert any("Sophos Firewall XG" in json.dumps(s) for s in ven["sections"])  # shown in the UI ...
    ctx = json.dumps(object_context(ven))
    assert "Firewall XG" not in ctx and json.loads(ctx)["relates_to_own_assets"] is True  # ... but only a flag goes to Gemini


def test_request_body_limits(m):
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        big = tc.post("/api/tb/run", content=b"{}", headers={"Content-Type": "application/json", "Content-Length": str(21 * 1024 * 1024)})
        assert big.status_code == 413 and big.json()["key"] == "err.body_too_large"
        pub = tc.post("/api/myip/report", content=b"x" * (65 * 1024), headers={"Authorization": "Bearer x"})
        assert pub.status_code == 413
        assert tc.post("/api/myip/report", headers={"Authorization": "Bearer x"}).status_code in (400, 401)

        def chunks(total: int):  # without Content-Length (chunked): counted while reading
            yield b'{"tool": "ioc", "target": "8.8.8.8", "params": {"x": "'
            for _ in range(total // 65536):
                yield b"a" * 65536
            yield b'"}}'
        r = tc.post("/api/tb/run", content=chunks(25 * 1024 * 1024), headers={"Content-Type": "application/json"})
        assert r.status_code == 413 and r.json()["key"] == "err.body_too_large"
        r = tc.post("/api/tb/run", content=chunks(65536), headers={"Content-Type": "application/json"})
        assert r.status_code == 200 and json.loads(r.text.strip().splitlines()[-1])["type"] == "result"


def test_dns_resolver_privacy(m, fdns):
    ev = run(m, "dns", "nas.fritz.box")  # default resolver: Cloudflare
    assert ev[-1]["key"] == "err.tb.third_private_dns"
    res = result(run(m, "dns", "example.test"))
    assert res["third_party"] == "Cloudflare DNS (1.1.1.1)"
    assert result(run(m, "dns", "example.test", {"resolver": "system"}))["third_party"] is None


# ------------------------------------------------------------------------------------------------------------------------
# Own IP, reporter, dyndns2, "my network"

def _proxied(m):
    from fastapi.testclient import TestClient
    from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
    return TestClient(ProxyHeadersMiddleware(m.app, trusted_hosts="*"))


def test_myip_flow(m):
    seed(m)
    v3.STATE["internetdb"] = {"84.150.9.10": {"ports": [443, 3389], "vulns": []}}
    with _proxied(m) as tc:
        m.app.state.client = client()
        home = {"X-Forwarded-For": "84.150.1.2"}
        st = tc.get("/api/myip", headers=home).json()
        assert st["you"]["ip"] == "84.150.1.2" and st["you"]["public"] and st["home"]["ip"] is None
        v = tc.post("/api/myip/visit", headers=home).json()
        assert v["suggest"] is True and v["auto_applied"] is False
        assert tc.post("/api/myip/confirm", json={"auto": False}).json()["key"] == "err.myip.private"
        assert tc.post("/api/myip/confirm", json={"auto": False}, headers=home).json() == {"ip": "84.150.1.2", "changed": True}
        assert tc.post("/api/myip/config", json={"dyndns": "bad host!"}).status_code == 400
        assert tc.post("/api/myip/config", json={"dyndns": "home.example.net"}).json()["dyndns"] == "home.example.net"
        tok = tc.post("/api/myip/token").json()["token"]
        assert len(tok) >= 40 and tok not in json.dumps(tc.get("/api/myip").json())
        assert m.db.query("SELECT config FROM myip WHERE kind='home'")[0]["config"].count(tok) == 0  # only the hash is stored

        bearer = {"Authorization": f"Bearer {tok}", "X-Forwarded-For": "84.150.9.10"}
        r = tc.post("/api/myip/report", headers=bearer)
        assert r.status_code == 200 and r.json() == {"status": "ok", "ips": ["84.150.9.10"]}
        assert tc.post("/api/myip/report", headers=bearer).json()["status"] == "nochg"
        r = tc.post("/api/myip/report", params={"ip": "84.150.7.7"}, headers=bearer)
        assert r.status_code == 429 and r.json()["status"] == "wait"  # a second change within 20 s is refused
        assert tc.post("/api/myip/report", params={"ip": "10.0.0.1"}, headers=bearer).status_code == 400
        r = tc.post("/api/myip/report", headers={"Authorization": "Bearer wrong", "X-Forwarded-For": "84.150.9.10"})
        assert r.status_code == 401
        evil = tc.post("/api/myip/report", headers={**bearer, "Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
        assert evil.status_code == 403

        basic = {"Authorization": "Basic " + base64.b64encode(f"router:{tok}".encode()).decode(), "X-Forwarded-For": "84.150.9.10"}
        assert tc.get("/nic/update", params={"myip": "84.150.9.10"}).text == "badauth"
        m.myip._last_report.clear()  # the 20 s spacing between changes is tested above
        r = tc.get("/nic/update", params={"hostname": "x", "myip": "84.150.9.10,2003:e1:1234::1"}, headers=basic)
        assert r.status_code == 200 and r.text == "good 84.150.9.10 2003:e1:1234::1"
        assert tc.get("/nic/update", params={"myip": "84.150.9.10"}, headers=basic).text == "nochg 84.150.9.10"
        # someone sends bad requests in the name of the home address: failures are slowed down ...
        for _ in range(10):
            tc.get("/nic/update", headers={"Authorization": "Basic " + base64.b64encode(b"x:nope").decode(),
                                           "X-Forwarded-For": "84.150.9.10"})
        locked = tc.post("/api/myip/report", headers={"Authorization": "Bearer nope", "X-Forwarded-For": "84.150.9.10"})
        assert locked.status_code == 429 and locked.json()["status"] == "locked"
        # ... but the router with the valid token is never locked out
        assert tc.get("/nic/update", params={"myip": "84.150.9.10"}, headers=basic).text == "nochg 84.150.9.10"
        assert tc.post("/api/myip/report", headers=bearer).json()["status"] == "nochg"
        # IPv6 zone IDs are no addresses to store; devices from the home /64 count as home
        assert tc.post("/api/myip/report", params={"ip": "2003:e1:1234::1%<img src=x>"}, headers=bearer).status_code == 400
        v6 = tc.post("/api/myip/visit", headers={"X-Forwarded-For": "2003:e1:1234::abcd"}).json()
        assert v6["is_home"] is True and v6["suggest"] is False and v6["auto_applied"] is False

        asyncio.run(m.myip.check(client(), "home"))
        st = tc.get("/api/myip").json()
        assert st["home"]["ip"] == "84.150.9.10" and st["home"]["ip6"] == "2003:e1:1234::1"
        assert [h["ip"] for h in st["home"]["history"] if h["family"] == 4][:2] == ["84.150.9.10", "84.150.1.2"]
        assert st["home"]["checks"]["84.150.9.10"]["internetdb"]["ports"] == [443, 3389]
        al = tc.get("/api/alerts", params={"source": "myip"}, headers={"Cookie": "ew_lang=de"}).json()["alerts"]
        titles = [a["title"] for a in al]
        assert "Heimnetz: neue IP 84.150.9.10" in titles
        assert any(t.startswith("Heimnetz-IP 84.150.9.10: kritische Ports") for t in titles)

        ov = tc.get("/api/netz/overview", headers=home).json()
        assert ov["myip"]["home"]["ip"] == "84.150.9.10" and ov["myip_configured"] is True
        assert ov["assets"]["total"] == 4 and sum(ov["assets"]["by_risk"].values()) == 4
        assert ov["assets"]["top"][0]["risk"] == "high" and ov["alerts"]["stats"]["total"] > 0

        assert tc.delete("/api/myip/token").json() == {"ok": True}
        assert tc.post("/api/myip/report", headers={**bearer, "X-Forwarded-For": "84.150.9.11"}).status_code == 401
        assert tc.post("/api/myip/clear", json={"kind": "home"}).json() == {"ok": True}
        assert tc.get("/api/myip").json()["home"]["ip"] is None


def test_myip_auto_asn_and_jobs(m, monkeypatch):
    seed(m)
    monkeypatch.setattr(m.geo, "lookup", lambda ip: {"asn": 3320, "as_name": "DTAG", "country": "DE"} if ip.startswith(("84.", "2003:"))
                        else {"asn": 12345, "as_name": "Mobile", "country": "DE"})
    m.myip.set_ip("home", "84.150.1.2", "confirmed")
    assert m.myip.configure(None, True)["auto_asn"] == 3320
    assert m.myip.visit("80.187.1.1")["auto_applied"] is False  # mobile network: only a sighting
    assert m.myip.visit("84.150.3.3")["auto_applied"] is True
    assert m.myip.current()["home"] == ["84.150.3.3"]
    v6 = m.myip.visit("2003:e1:9999::42")  # same AS over IPv6: the device address is not taken over automatically
    assert v6["auto_applied"] is False and v6["suggest"] is True and m.myip.current()["home"] == ["84.150.3.3"]
    assert m.myip.needs_check("home") is True and m.myip.needs_check("server") is False

    async def origin(c, max_age=0):
        return {"ip": "5.9.1.2"}
    monkeypatch.setattr(m.toolkit, "origin", origin)
    asyncio.run(m.myip.refresh(client()))
    assert m.myip.current()["server"] == ["5.9.1.2"] and m.myip.match("5.9.1.2") == "server"
    page = asyncio.run(m.objects.build("ip", "5.9.1.2", "en", client()))
    assert page["mine"]["myip"] == "server" and "ob.f.myip" in [f["key"] for f in page["risk"]["reasons"]]
    from app.objects import object_context
    assert "5.9.1.2" in json.dumps(object_context(page)) and "ob.f.myip" not in json.dumps(object_context(page))


def test_login_page_assets_public(tmp_path, monkeypatch):
    """With a login, the login page and every module it imports load without a session; the app itself does not."""
    m = v3.load_app(tmp_path, monkeypatch, AUTH_MODE="password", AUTH_PASSWORD="a-long-test-password-123")
    from fastapi.testclient import TestClient
    js = ROOT / "frontend" / "js"
    todo, seen = ["login.js"], set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        todo += re.findall(r'from "\./([\w.-]+\.js)"', (js / f).read_text())
    assert {"login.js", "i18n.js", "texts.js"} <= seen
    with TestClient(m.app) as tc:
        assert tc.get("/login").status_code == 200
        for f in sorted(seen):
            assert tc.get(f"/js/{f}").status_code == 200, f
        assert tc.get("/js/app.js").status_code == 401
        assert tc.get("/api/myip").status_code == 401
        assert tc.post("/api/myip/report").json()["status"] == "badauth"  # public path, token checked by the endpoint
        assert tc.get("/nic/update").text == "badauth"
