"""End-to-end test of the pipeline with mocked API responses (no real network access).

The fixtures follow the documented formats:
- Cloudflare Radar: Python SDK types (top_0 / summary_0 / serie_0)
- Feodo: ipblocklist.json, ThreatFox: get_iocs, ransomware.live PRO: /victims/recent, CISA KEV JSON
Optional: DBIP_TEST_MMDB=<path to dbip-city-lite.mmdb> for real geolocation.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

NOW = datetime.now(timezone.utc)


def ts(hours_ago: float, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    return (NOW - timedelta(hours=hours_ago)).strftime(fmt)


def radar_result(path: str, params: dict) -> dict:
    meta = {"lastUpdated": NOW.isoformat(), "dateRange": [{"startTime": ts(24), "endTime": ts(0)}], "normalization": "PERCENTAGE",
            "confidenceInfo": {"level": 0, "annotations": []}}
    rng = params.get("dateRange")
    if path.endswith("/top/attacks"):
        return {"meta": meta, "top_0": [
            {"originCountryAlpha2": "SG", "originCountryName": "Singapore", "targetCountryAlpha2": "US", "targetCountryName": "United States", "value": "12.5"},
            {"originCountryAlpha2": "ID", "originCountryName": "Indonesia", "targetCountryAlpha2": "DE", "targetCountryName": "Germany", "value": "6.1"},
            {"originCountryAlpha2": "US", "originCountryName": "United States", "targetCountryAlpha2": "BR", "targetCountryName": "Brazil", "value": "4.0"},
        ]}
    if "/top/locations/target" in path:
        de = "14.0" if rng == "1d" else "5.0"  # DE rises -> pattern
        return {"meta": meta, "top_0": [
            {"rank": 1, "targetCountryAlpha2": "US", "targetCountryName": "United States", "value": "30.0"},
            {"rank": 2, "targetCountryAlpha2": "DE", "targetCountryName": "Germany", "value": de},
            {"rank": 3, "targetCountryAlpha2": "BR", "targetCountryName": "Brazil", "value": "8.0"},
        ]}
    if "/top/locations/origin" in path:
        return {"meta": meta, "top_0": [
            {"rank": 1, "originCountryAlpha2": "SG", "originCountryName": "Singapore", "value": "20.0"},
            {"rank": 2, "originCountryAlpha2": "ID", "originCountryName": "Indonesia", "value": "11.0"},
        ]}
    if path.endswith("/summary/VECTOR"):
        return {"meta": meta, "summary_0": {"SYN Flood": "40.0" if rng == "1d" else "30.0", "UDP Flood": "35.0", "ACK Flood": "25.0" if rng == "1d" else "35.0"}}
    if path.endswith("/summary/PROTOCOL"):
        return {"meta": meta, "summary_0": {"TCP": "60.0", "UDP": "38.0", "ICMP": "2.0"}}
    if path.endswith("/summary/MANAGED_RULES"):
        return {"meta": meta, "summary_0": {"HTTP Anomaly": "50.0", "SQLi": "20.0", "XSS": "10.0", "Other": "20.0"}}
    if path.endswith("/summary/MITIGATION_PRODUCT"):
        return {"meta": meta, "summary_0": {"DDOS": "60.0", "WAF": "30.0", "BOT_MANAGEMENT": "10.0"}}
    if path.endswith("/summary/INDUSTRY"):
        return {"meta": meta, "summary_0": {"Information Technology and Services": "25.0", "Gambling & Casinos": "15.0"}}
    if "/timeseries_groups/" in path:
        hours = 168
        tsl = [(NOW - timedelta(hours=hours - i)).isoformat() for i in range(hours)]
        syn = [str(10.0 + (i % 3) * 0.5) for i in range(hours - 24)] + ["10.0"] * 20 + ["45.0"] + ["10.0"] * 3
        return {"meta": meta, "serie_0": {"timestamps": tsl, "SYN Flood": syn, "UDP Flood": ["20.0"] * hours}}
    raise AssertionError(f"unexpected Radar path {path}")


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    host = request.url.host
    if host == "api.cloudflare.com":
        assert request.headers.get("authorization") == "Bearer cf-test"
        path = request.url.path.replace("/client/v4/radar", "")
        return httpx.Response(200, json={"success": True, "errors": [], "result": radar_result(path, dict(request.url.params))})
    if host == "feodotracker.abuse.ch":
        return httpx.Response(200, json=[
            {"ip_address": "8.8.4.4", "port": 443, "status": "online", "hostname": None, "as_number": 15169, "as_name": "GOOGLE",
             "country": "US", "first_seen": ts(200), "last_online": ts(1, "%Y-%m-%d"), "malware": "QakBot"},
            {"ip_address": "78.46.1.1", "port": 8080, "status": "offline", "hostname": None, "as_number": 24940, "as_name": "HETZNER-AS",
             "country": "DE", "first_seen": ts(300), "last_online": ts(48, "%Y-%m-%d"), "malware": "Emotet"},
        ])
    if host == "threatfox-api.abuse.ch":
        assert request.headers.get("auth-key") == "tf-test"
        body = json.loads(request.content)
        assert body["query"] == "get_iocs" and 1 <= body["days"] <= 7
        data = [
            {"id": str(1000 + i), "ioc": f"78.46.2.{i}:443", "threat_type": "botnet_cc", "threat_type_desc": "", "ioc_type": "ip:port",
             "ioc_type_desc": "", "malware": "win.newrat", "malware_printable": "NewRAT", "malware_alias": None, "malware_malpedia": "",
             "confidence_level": 75, "first_seen": ts(2) + " UTC", "last_seen": None, "reporter": "x", "reference": None, "tags": ["c2"]}
            for i in range(1, 7)
        ] + [
            {"id": "2000", "ioc": "evil.example.com", "threat_type": "botnet_cc", "ioc_type": "domain", "malware_printable": "Cobalt Strike",
             "confidence_level": 100, "first_seen": ts(30) + " UTC", "last_seen": None},
            {"id": "3000", "ioc": "http://x.example/p.exe", "threat_type": "payload_delivery", "ioc_type": "url", "malware_printable": "Foo",
             "confidence_level": 50, "first_seen": ts(3) + " UTC"},
        ]
        return httpx.Response(200, json={"query_status": "ok", "data": data})
    if host == "api-pro.ransomware.live":
        assert request.headers.get("x-api-key") == "rl-test"
        victims = [{"id": f"v{i}", "victim": f"Firma {i} <script>alert(1)</script>", "group": "akira" if i % 2 else "qilin",
                    "attackdate": ts(48 + i, "%Y-%m-%d %H:%M:%S.%f"), "discovered": ts(10 + i, "%Y-%m-%d %H:%M:%S.%f"),
                    "country": "DE" if i < 7 else "US", "activity": "Manufacturing", "website": "", "permalink": f"https://www.ransomware.live/id/v{i}"}
                   for i in range(12)]
        return httpx.Response(200, json=victims)
    if host == "raw.githubusercontent.com":
        # simulates an outage of the GitHub mirror; kev.py must fall back to cisa.gov
        return httpx.Response(503, text="unavailable")
    if host == "www.cisa.gov":
        today = NOW.date()
        return httpx.Response(200, json={"vulnerabilities": [
            {"cveID": f"CVE-2026-{1000 + i}", "vendorProject": "Ivanti" if i < 3 else "Microsoft", "product": "Connect Secure",
             "vulnerabilityName": "x", "dateAdded": (today - timedelta(days=i)).isoformat(), "dueDate": (today + timedelta(days=21)).isoformat(),
             "knownRansomwareCampaignUse": "Known" if i == 0 else "Unknown"} for i in range(5)]})
    if host == "download.db-ip.com":
        return httpx.Response(404)
    if host == "generativelanguage.googleapis.com":
        assert request.headers.get("x-goog-api-key") == "gm-test"
        body = json.loads(request.content)
        assert "systemInstruction" in body and body["generationConfig"]["responseMimeType"] == "application/json"
        prompt = body["contents"][0]["parts"][0]["text"]
        assert "<script>" not in prompt and "Firma" not in prompt, "victim names must never reach the prompt"
        answer = {"title": "Lage", "summary": "### Kurz\n- **DE** steigt", "findings": [{"title": "DE", "detail": "14 %", "severity": "high"}],
                  "charts": [{"type": "bar", "title": "Ziele", "unit": "%", "labels": ["US", "DE"], "series": [{"name": "24h", "values": [30, 14]}]},
                             {"type": "bar", "title": "kaputt", "labels": ["a"], "series": [{"name": "x", "values": ["NaN"]}]}],
                  "recommendations": ["Patchen"], "caveats": ["Anteile, keine Zahlen"]}
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": json.dumps(answer)}]}, "finishReason": "STOP"}]})
    raise AssertionError(f"unexpected request {url}")


@pytest.fixture()
def appmod(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("STATIC_DIR", str(ROOT / "frontend"))
    monkeypatch.setenv("CF_API_TOKEN", "cf-test")
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "tf-test")
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "rl-test")
    monkeypatch.setenv("GEMINI_API_KEY", "gm-test")
    monkeypatch.setenv("AI_MIN_INTERVAL_S", "0")
    monkeypatch.setenv("COLLECTORS", "0")
    monkeypatch.setenv("AUTH_MODE", "none")
    monkeypatch.setenv("LANGUAGE", "de")
    monkeypatch.setenv("BGP_LIVE", "0")
    mm = os.getenv("DBIP_TEST_MMDB")
    if mm and Path(mm).exists():
        shutil.copy(mm, tmp_path / "dbip-city-lite.mmdb")
    for m in [m for m in sys.modules if m.startswith("app")]:
        del sys.modules[m]
    return importlib.import_module("app.main")


def test_pipeline(appmod):
    m = appmod
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def run():
        await m.radar.collect(client, m.db, m.S.cf_api_token)
        await m.abusech.collect_feodo(client, m.db, m.geo, m.S.user_agent)
        await m.abusech.collect_threatfox(client, m.db, m.geo, m.S.user_agent, m.S.abusech_auth_key)
        await m.ransomware.collect(client, m.db, m.S.user_agent, m.S.ransomware_live_api_key)
        await m.kev.collect(client, m.db, m.S.user_agent)

    asyncio.run(run())
    st = {s["source"]: s for s in m.db.statuses()}
    assert all(st[k]["ok"] for k in ("cloudflare_radar", "feodo", "threatfox", "ransomware_live", "cisa_kev")), st
    assert st["threatfox"]["count"] == 7  # 6 ip:port + 1 domain botnet_cc; payload_delivery is not a C2
    iocs = m.db.query("SELECT ioc_type, ip, host, threat_type FROM iocs ORDER BY id")
    assert len(iocs) == 8 and {"ioc_type": "url", "ip": None, "host": "x.example", "threat_type": "payload_delivery"} in iocs

    ov = m.overview(force=True)
    assert ov["radar"]["l7_target_1d"]["rows"][1] == {"origin": None, "origin_name": None, "target": "DE", "target_name": "Germany", "value": 14.0}
    assert ov["c2"]["total"] == 9 and ov["c2"]["new_24h"] == 6
    assert ov["ransomware"]["total_7d"] == 12
    assert all("title" not in p for p in ov["patterns"])  # stored language-neutral
    de = [p["title"] for p in m.localized(ov, "de")["patterns"]]
    assert any("Deutschland: Anstieg als Ziel" in t for t in de), de
    assert any("Neue C2-Familie: NewRAT" in t for t in de), de
    assert any("Spike bei DDoS-Vektor" in t and "SYN Flood" in t for t in de), de
    assert any("Häufung KEV: Ivanti" in t for t in de), de
    assert any("Brennpunkte über alle Quellen: Deutschland" in t for t in de), de
    en = [p["title"] for p in m.localized(ov, "en")["patterns"]]
    assert any("Germany: rising as target" in t for t in en), en
    assert any("New C2 family: NewRAT" in t for t in en), en
    assert any("Spike in DDoS vector" in t and "SYN Flood" in t for t in en), en
    assert any("KEV cluster: Ivanti" in t for t in en), en
    assert ov["countries"]["DE"]["ransomware_7d"] == 7
    spike = next(p for p in m.localized(ov, "de")["patterns"] if p["key"] == "spike")
    assert "," in spike["detail"] and "z = " in spike["detail"]  # German decimal comma

    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:  # starts no loops (COLLECTORS=0); replace the HTTP client by the mock
        tc.app.state.client = client
        r = tc.get("/api/overview")
        assert r.status_code == 200 and "Content-Security-Policy" in r.headers
        assert any(p["title"].startswith("Deutschland") for p in r.json()["patterns"])
        r_en = tc.get("/api/overview", headers={"Cookie": "ew_lang=en"}).json()
        assert any(p["title"].startswith("Germany") for p in r_en["patterns"])
        r_al = tc.get("/api/overview", headers={"Accept-Language": "en-US,en;q=0.8"}).json()
        assert r_al["patterns"][0]["category_label"] in ("Region", "Vector", "Spike", "C2", "Ransomware", "Correlation",
                                                        "Vulnerabilities", "Infrastructure", "Alerts")
        g = tc.get("/api/c2?days=30").json()
        assert g["type"] == "FeatureCollection"
        if m.geo.available:
            assert len(g["features"]) == 8  # the domain IOC has no coordinates
        else:
            assert len(g["features"]) == 2  # only Feodo (country -> centroid)
        cd = tc.get("/api/country/de").json()
        assert cd["ransomware_7d"]["total"] == 7 and cd["name"] == "Deutschland"
        assert tc.get("/api/country/de", headers={"Cookie": "ew_lang=en"}).json()["name"] == "Germany"
        bad = tc.get("/api/country/DEU")
        assert bad.status_code == 400 and bad.json()["detail"] == "Ungültiger Ländercode."
        assert tc.get("/api/country/DEU", headers={"Cookie": "ew_lang=en"}).json()["detail"] == "Invalid country code."
        a = tc.post("/api/ai/analyze", json={"scope": "global"})
        assert a.status_code == 200, a.text
        res = a.json()
        assert len(res["charts"]) == 1  # the invalid chart was dropped
        assert tc.post("/api/ai/analyze", json={"scope": "global"}).json()["cached"] is True
        assert tc.post("/api/ai/analyze", json={"scope": "question"}).status_code == 400
        assert tc.post("/api/ai/analyze", json={"scope": "region"}).json()["key"] == "err.region_missing"
        assert tc.get("/api/ai/reports").json()[0]["title"] == "Lage"
        assert tc.get("/").status_code == 200
        st = tc.get("/api/status", headers={"Cookie": "ew_lang=en"}).json()
        kev_msg = next(s["message"] for s in st["sources"] if s["source"] == "cisa_kev")
        assert kev_msg.startswith("Source: cisa.gov (failed before: GitHub")


def test_kev_sources(appmod):
    """KEV: GitHub mirror first, cisa.gov as fallback, clean error when both fail."""
    m = appmod
    catalog = {"catalogVersion": "2026.10.16", "vulnerabilities": [
        {"cveID": "CVE-2026-0001", "vendorProject": "Ivanti", "product": "EPMM", "vulnerabilityName": "x",
         "dateAdded": "2026-10-16", "dueDate": "2026-11-06", "knownRansomwareCampaignUse": "Unknown",
         "forensicTriage": "neues Feld, wird ignoriert"}]}
    calls: list[str] = []

    def make(gh, gov):
        def h(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.host)
            return gh(request) if request.url.host == "raw.githubusercontent.com" else gov(request)
        return httpx.AsyncClient(transport=httpx.MockTransport(h))

    def run(client):
        return asyncio.run(m.kev.collect(client, m.db, m.S.user_agent))

    def st():
        return {s["source"]: s for s in m.db.statuses()}["cisa_kev"]

    def msg():
        return m.i18n.render_status(st(), "en")

    # 1) GitHub delivers: cisa.gov is not asked at all
    assert run(make(lambda r: httpx.Response(200, json=catalog), lambda r: httpx.Response(403))) is True
    assert calls == ["raw.githubusercontent.com"] and st()["ok"] and st()["count"] == 1
    assert msg() == "Source: GitHub cisagov/kev-data"

    # 2) GitHub returns HTML instead of JSON, cisa.gov works
    calls.clear()
    assert run(make(lambda r: httpx.Response(200, text="<html>rate limited</html>"), lambda r: httpx.Response(200, json=catalog))) is True
    assert calls == ["raw.githubusercontent.com", "www.cisa.gov"] and "cisa.gov" in msg()
    assert m.i18n.render_status(st(), "de").startswith("Quelle: cisa.gov (vorher fehlgeschlagen: GitHub")

    # 3) both fail: error status with both causes, old data is kept
    assert run(make(lambda r: httpx.Response(429), lambda r: httpx.Response(403))) is False
    s = st()
    assert not s["ok"] and "GitHub" in s["message"] and "cisa.gov" in s["message"] and "403" in s["message"]
    assert m.db.query("SELECT COUNT(*) AS n FROM kev")[0]["n"] == 1

    # 4) an empty catalog does not count as success
    assert run(make(lambda r: httpx.Response(200, json={"vulnerabilities": []}), lambda r: httpx.Response(403))) is False
