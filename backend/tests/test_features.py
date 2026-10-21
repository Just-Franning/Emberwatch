"""Tests for infrastructure, backfill, timeline, EPSS, watchlist alerts, Matrix, follow-ups, search, exports and tools.

Upstream APIs are mocked with their documented formats (Cloudflare SDK types, FIRST EPSS,
Matrix client-server API v3, ransomware.live Swagger). The network tools run against 127.0.0.1.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import importlib
import json
import os
import shutil
import ssl
import sys
import threading
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_pipeline as base  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)
CALLS: list[httpx.Request] = []


def iso(h: float) -> str:
    return (NOW - dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")


def handler(request: httpx.Request) -> httpx.Response:
    CALLS.append(request)
    h, path = request.url.host, request.url.path
    params = dict(request.url.params)
    if h == "api.cloudflare.com":
        p = path.replace("/client/v4/radar", "")
        if p == "/annotations/outages":
            return ok({"annotations": [
                {"id": "o1", "asns": [3320], "asnsDetails": [{"asn": "3320", "name": "DTAG"}], "dataSource": "ALL",
                 "description": "Seekabel beschädigt", "endDate": None, "entities": [], "eventType": "OUTAGE",
                 "geoIds": [], "linkedUrl": "https://example.org/outage", "locations": ["DE"],
                 "locationsDetails": [{"code": "DE", "name": "Germany"}], "origins": [], "originsDetails": [],
                 "outage": {"outageCause": "CABLE_CUT", "outageType": "REGIONAL"}, "scope": "Rostock",
                 "startDate": iso(5), "tags": []},
                {"id": "o2", "asns": [], "asnsDetails": [], "dataSource": "ALL", "description": None, "endDate": iso(1),
                 "entities": [], "eventType": "OUTAGE", "geoIds": [], "linkedUrl": None, "locations": ["FR"],
                 "locationsDetails": [{"code": "FR", "name": "France"}], "origins": [], "originsDetails": [],
                 "outage": {"outageCause": "POWER_OUTAGE", "outageType": "REGIONAL"}, "scope": None,
                 "startDate": iso(30), "tags": []},
            ]})
        if p == "/bgp/hijacks/events":
            return ok({"asn_info": [{"asn": 64500, "country_code": "RU", "org_name": "Evil"},
                                    {"asn": 3320, "country_code": "DE", "org_name": "DTAG"}],
                       "events": [{"id": 900 + i, "confidence_score": 8, "duration": 10, "event_type": 1, "hijack_msgs_count": 3,
                                   "hijacker_asn": 64500, "hijacker_country": "RU", "is_stale": False,
                                   "max_hijack_ts": iso(1), "max_msg_ts": iso(1), "min_hijack_ts": iso(2),
                                   "on_going_count": 0, "peer_asns": [1], "peer_ip_count": 2,
                                   "prefixes": ["198.51.100.0/24"], "tags": [], "victim_asns": [3320],
                                   "victim_countries": ["DE"]} for i in range(3)],
                       "total_monitors": 10})
        if p == "/bgp/leaks/events":
            return ok({"asn_info": [], "events": [{"id": 77, "countries": ["BR"], "detected_ts": iso(3), "finished": True,
                                                   "leak_asn": 65001, "leak_count": 4, "leak_seg": [65001, 65002],
                                                   "leak_type": 1, "max_ts": iso(2), "min_ts": iso(3), "origin_count": 2,
                                                   "peer_count": 5, "prefix_count": 9}]})
        if p == "/traffic_anomalies":
            return ok({"trafficAnomalies": [{"uuid": "a1", "asnDetails": None, "endDate": None,
                                             "locationDetails": {"code": "IR", "name": "Iran"}, "originDetails": None,
                                             "startDate": iso(4), "status": "VERIFIED", "type": "LOCATION"}]})
        if "dateStart" in params:  # backfill of one calendar day
            assert "dateRange" not in params and params["dateEnd"] > params["dateStart"]
            return ok(base.radar_result(p, {"dateRange": "1d"}))
    if h == "api.first.org":
        cves = params["cve"].split(",")
        assert len(cves) <= 100
        return httpx.Response(200, json={"status": "OK", "status-code": 200, "version": "1.0", "total": len(cves),
                                         "data": [{"cve": c, "epss": "0.97000", "percentile": "0.99900", "date": NOW.date().isoformat()}
                                                  for c in cves]})
    if h == "api-pro.ransomware.live" and path == "/victims/":
        assert "year" in params and "month" in params
        return httpx.Response(200, json=[{"victim": f"alt{i}.example", "group": "akira", "country": "DE", "activity": "Retail",
                                          "discovered": (NOW - dt.timedelta(days=16)).strftime("%Y-%m-%d %H:%M:%S"),
                                          "attackdate": None} for i in range(3)]
                              + [{"victim": "kunde.example.de", "group": "qilin", "country": "DE", "activity": "Retail",
                                  "discovered": (NOW - dt.timedelta(days=9)).strftime("%Y-%m-%d %H:%M:%S")}])
    if h == "matrix.test":
        assert request.method == "PUT"
        assert request.url.raw_path.decode().startswith("/_matrix/client/v3/rooms/%21raum%3Amatrix.test/send/m.room.message/")
        assert request.headers["authorization"] == "Bearer mx-token"
        body = json.loads(request.content)
        assert body["msgtype"] == "m.notice" and body["body"]
        if "formatted_body" in body:
            assert body["format"] == "org.matrix.custom.html" and "<script" not in body["formatted_body"]
        return httpx.Response(200, json={"event_id": "$abc"})
    if h == "generativelanguage.googleapis.com":
        body = json.loads(request.content)
        prompt = body["contents"][0]["parts"][0]["text"]
        schema = body["generationConfig"].get("responseSchema", {})
        if "answer" in schema.get("properties", {}):
            assert "RÜCKFRAGE" in prompt and "BERICHT" in prompt
            ans = {"answer": "**Ja**, DE ist betroffen.", "charts": [], "caveats": ["Anteile"]}
        else:
            ans = {"title": "Tagesbericht" if "täglichen" in prompt else "Lage", "summary": "- Punkt", "findings": [],
                   "charts": [], "caveats": []}
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": json.dumps(ans)}]}, "finishReason": "STOP"}]})
    return base.handler(request)


def ok(result: dict) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "errors": [], "result": result})


@pytest.fixture()
def m(tmp_path, monkeypatch):
    env = {
        "DATA_DIR": str(tmp_path), "STATIC_DIR": str(ROOT / "frontend"), "CF_API_TOKEN": "cf-test",
        "ABUSECH_AUTH_KEY": "tf-test", "RANSOMWARE_LIVE_API_KEY": "rl-test", "GEMINI_API_KEY": "gm-test",
        "AI_MIN_INTERVAL_S": "0", "COLLECTORS": "0", "MATRIX_HOMESERVER": "https://matrix.test",
        "MATRIX_ACCESS_TOKEN": "mx-token", "MATRIX_ROOM_ID": "!raum:matrix.test", "MATRIX_MIN_SEVERITY": "high",
        "DAILY_REPORT_TIME": "00:00", "TOOLS_ALLOW_PRIVATE": "1", "AUTH_MODE": "none", "LANGUAGE": "de", "BGP_LIVE": "0",
        "PING_BIN": os.getenv("PING_BIN_TEST", "/tmp/claude-0/ping2"), "TRACEROUTE_BIN": shutil.which("traceroute") or "/nonexistent",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    for mod in [x for x in sys.modules if x == "app" or x.startswith("app.")]:
        del sys.modules[mod]
    CALLS.clear()
    return importlib.import_module("app.main")


def collect_all(m, client):
    async def run():
        await m.radar.collect(client, m.db, "cf-test")
        await m.radar.backfill(client, m.db, "cf-test", 5)
        await m.infra.collect(client, m.db, "cf-test")
        await m.abusech.collect_feodo(client, m.db, m.geo, m.S.user_agent, "tf-test")
        await m.abusech.collect_threatfox(client, m.db, m.geo, m.S.user_agent, "tf-test")
        await m.ransomware.backfill(client, m.db, m.S.user_agent, "rl-test")
        await m.ransomware.collect(client, m.db, m.S.user_agent, "rl-test")
        await m.kev.collect(client, m.db, m.S.user_agent)
        await m.epss.collect(client, m.db, m.S.user_agent)
    asyncio.run(run())


def test_infra_backfill_epss_patterns(m):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    collect_all(m, client)
    st = {s["source"]: s for s in m.db.statuses()}
    assert st["radar_infra"]["ok"] and st["radar_infra"]["count"] == 2 + 3 + 1 + 1
    assert st["epss"]["ok"] and st["epss"]["count"] == 5
    # backfill: 5 days x 7 metrics, marked as final
    finals = m.db.query("SELECT COUNT(*) AS n FROM radar_hist WHERE json_extract(payload,'$.final')=1")[0]["n"]
    assert finals == 5 * 7
    assert m.db.meta_get("ransomware_backfill") == "done"
    ov = m.localized(m.overview(force=True), "de")
    assert ov["ransomware"]["prev_window_complete"] is True
    assert ov["kev"]["epss_high_14d"] == 5 and ov["kev"]["latest"][0]["epss"] == pytest.approx(0.97)
    assert ov["infra"]["counts_7d"] == {"outage": 2, "hijack": 3, "leak": 1, "anomaly": 1}
    assert ov["countries"]["DE"]["outages_7d"] == 1 and ov["countries"]["DE"]["hijacks_7d"] == 3
    titles = [p["title"] for p in ov["patterns"]]
    cable = next(p for p in ov["patterns"] if p["title"].startswith("Ausfall (Kabelschaden) in Deutschland"))
    assert "(laufend)" in cable["title"] and "Seekabel" in cable["detail"] and "C-Lion1" in cable["detail"]
    assert not any("Stromausfall" in t for t in titles)  # not a critical cause
    en = [p["title"] for p in m.localized(m.overview(), "en")["patterns"]]
    assert any(t.startswith("Outage (cable cut) in Germany (ongoing)") for t in en), en
    assert "BGP hijacks involving Germany" in en
    ev = next(e for e in ov["infra"]["events"] if e["kind"] == "hijack")
    assert ev["title"] == "BGP-Hijack" and "AS64500 Evil (RU)" in ev["detail"] and "198.51.100.0/24" in ev["detail"]
    assert any(t == "BGP-Hijacks mit Bezug zu Deutschland" for t in titles)
    assert any(t.startswith("Deutschland: Störung und steigender Angriffsdruck") for t in titles)
    assert any(t == "Neue KEV mit hoher EPSS" for t in titles)
    # timeline and trends
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        days = tc.get("/api/timeline/days").json()
        yday = (NOW.date() - dt.timedelta(days=1)).isoformat()
        assert yday in days
        tl = tc.get(f"/api/timeline?day={yday}").json()
        assert tl["final"] is True and tl["countries"]["DE"]["l7_target"] == 14.0 and tl["pairs"]
        assert tc.get("/api/timeline?day=2026-13-45").status_code == 400
        tr = tc.get("/api/trends/DE?days=7").json()
        assert len(tr["labels"]) == 7 and tr["series"]["l7_target"][-2] == 14.0
        cd = tc.get("/api/country/DE").json()
        assert "C-Lion1" in cd["cables"]["cables"] and any(e["kind"] == "hijack" for e in cd["infra_events"])
        assert any(e["title"] == "Ausfall (Kabelschaden)" for e in cd["infra_events"])


def matrix_calls() -> int:
    return len([c for c in CALLS if c.url.host == "matrix.test"])


def test_watchlist_matrix_daily_followup(m):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    collect_all(m, client)
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        tc.app.state.client = client
        # normalisation and errors
        assert tc.post("/api/watchlist", json={"value": "AS999999999999"}).status_code == 400
        assert tc.post("/api/watchlist", json={"value": "10.0.0.0/4"}).json()["detail"] == "Netz zu groß (mindestens /8 bzw. /16)."
        assert tc.post("/api/watchlist", json={"value": "bad domain"}).status_code == 400
        before = matrix_calls()
        r1 = tc.post("/api/watchlist", json={"value": "78.46.2.0/24", "label": "Kundennetz"}).json()  # ThreatFox C2 from base
        assert r1["kind"] == "cidr" and r1["new_alerts"] == 6
        r2 = tc.post("/api/watchlist", json={"value": "AS3320"}).json()
        assert r2["new_alerts"] == 4  # 1 outage + 3 hijacks (medium)
        r3 = tc.post("/api/watchlist", json={"value": "198.51.100.7"}).json()
        assert r3["kind"] == "ip" and r3["new_alerts"] == 3  # hijacked prefix overlaps
        r4 = tc.post("/api/watchlist", json={"value": "Example.DE"}).json()
        assert r4["value"] == "example.de" and r4["new_alerts"] == 1  # leak site victim kunde.example.de
        assert tc.post("/api/watchlist", json={"value": "example.de"}).status_code == 409
        assert m.watchlist.scan(m.db) == []  # no duplicates
        assert matrix_calls() == before  # delivery happens in the alerts job, batched
        asyncio.run(m.notifier.alerts(client))
        assert matrix_calls() == before + 1
        body = json.loads(CALLS[-1].content)
        assert body["body"].startswith("Emberwatch: 10 neue Alarm(e)")  # only "high" (MATRIX_MIN_SEVERITY=high)
        asyncio.run(m.notifier.alerts(client))
        assert matrix_calls() == before + 1  # nothing pending any more
        al = tc.get("/api/alerts").json()
        assert al["stats"]["total"] == 14 and al["stats"]["high_7d"] == 10
        titles = [a["title"] for a in al["alerts"]]
        assert "C2-Server in 78.46.2.0/24 (Kundennetz)" in titles and "Leak-Site-Eintrag zu example.de" in titles
        en = tc.get("/api/alerts?source=watch&min_severity=medium", headers={"Cookie": "ew_lang=en"}).json()["alerts"]
        assert "BGP hijack involving AS3320" in [a["title"] for a in en]
        wl = tc.get("/api/watchlist").json()
        assert len(wl["entries"]) == 4 and sum(e["alerts_total"] for e in wl["entries"]) == 14
        assert tc.delete(f"/api/watchlist/{r4['id']}").status_code == 200
        assert tc.get("/api/alerts").json()["stats"]["total"] == 13
        assert tc.delete("/api/watchlist/99999").status_code == 404
        # pattern notification with 24 h cool-down
        n0 = matrix_calls()
        asyncio.run(m.notifier.patterns(client, m.overview(force=True)["patterns"]))
        asyncio.run(m.notifier.patterns(client, m.overview(force=True)["patterns"]))
        assert matrix_calls() == n0 + 1
        assert tc.post("/api/notify/test").json() == {"ok": True}
        # daily report: exactly once per day
        asyncio.run(m._daily_report(client))
        asyncio.run(m._daily_report(client))
        reps = tc.get("/api/ai/reports").json()
        assert [r["scope"] for r in reps].count("daily") == 1 and reps[0]["title"] == "Tagesbericht"
        # follow-up question
        a = tc.post("/api/ai/analyze", json={"scope": "country", "country": "DE"}).json()
        assert a["id"] > 0
        f = tc.post("/api/ai/followup", json={"report_id": a["id"], "question": "Ist DE betroffen?"}).json()
        assert f["answer"].startswith("**Ja**")
        assert tc.get(f"/api/ai/reports/{a['id']}/thread").json()[0]["question"] == "Ist DE betroffen?"
        assert tc.post("/api/ai/followup", json={"report_id": 4242, "question": "x?"}).status_code == 404
        # a second, cached analysis carries the same id
        assert tc.post("/api/ai/analyze", json={"scope": "country", "country": "DE"}).json()["id"] == a["id"]


def test_search_and_export(m):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    collect_all(m, client)
    m.db.execute("UPDATE c2 SET malware='=HYPERLINK(\"x\")' WHERE id=(SELECT id FROM c2 WHERE source='feodo' LIMIT 1)")
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        assert tc.get("/api/search?q=78.46.2.3").json()["c2"][0]["ip"] == "78.46.2.3"
        assert len(tc.get("/api/search?q=78.46.2.0/24").json()["c2"]) == 6
        s_asn = tc.get("/api/search?q=AS3320").json()
        assert s_asn["type"] == "asn" and len(s_asn["infra"]) == 4
        assert tc.get("/api/search?q=cve-2026-1000").json()["kev"][0]["cve"] == "CVE-2026-1000"
        txt = tc.get("/api/search?q=newrat").json()
        assert txt["c2"] and all(r["malware"] == "NewRAT" for r in txt["c2"])
        assert tc.get("/api/search?q=deutsch").json()["countries"][0]["cc"] == "DE"
        assert tc.get("/api/search?q=germany", headers={"Cookie": "ew_lang=en"}).json()["countries"] == [{"cc": "DE", "name": "Germany"}]
        dom = tc.get("/api/search?q=example.com").json()
        assert dom["type"] == "domain" and dom["iocs"][0]["host"] == "evil.example.com"
        vend = tc.get("/api/search?q=ivanti").json()
        assert vend["vendors"][0]["vendor"] == "Ivanti" and vend["vendors"][0]["n"] == 3
        assert tc.get("/api/search?q=%25").status_code == 422  # min_length 2
        assert tc.get("/api/search?q=%25%25").json()["c2"] == []  # % is searched literally
        blk = tc.get("/api/export/c2?fmt=txt&family=NewRAT")
        lines = [ln for ln in blk.text.splitlines() if ln and not ln.startswith("#")]
        assert len(lines) == 6 and "attachment" in blk.headers["content-disposition"]
        csv_body = tc.get("/api/export/c2?fmt=csv").text
        assert "'=HYPERLINK" in csv_body and ",=HYPERLINK" not in csv_body


# --- network tools -------------------------------------------------------------------
def test_tool_parsers():
    from app import tools
    assert tools.parse_trace_line(" 1  172.17.0.1  0.123 ms") == {"type": "hop", "n": 1, "ip": "172.17.0.1", "rtt": 0.123, "note": None}
    assert tools.parse_trace_line(" 7  *")["ip"] is None
    assert tools.parse_trace_line("12  2001:db8::1  10.5 ms !H")["note"] == "!H"
    assert tools.parse_trace_line("traceroute to 1.1.1.1 (1.1.1.1), 30 hops max") is None
    assert tools.parse_ports("443, 80,443") == [443, 80]
    for bad in ("0", "70000", "1-100", ",".join(str(p) for p in range(1, 12))):
        with pytest.raises(tools.ToolError):
            tools.parse_ports(bad)
    for bad in ("-oProxyCommand=x", "a b", "1.1.1.1;ls", "$(id)", "x" * 300, "exa_mple..com"):
        with pytest.raises(tools.ToolError):
            tools.parse_host(bad)
    assert tools.parse_host("Bücher.Example") == ("xn--bcher-kva.example", False)
    with pytest.raises(tools.ToolError):
        asyncio.run(tools.resolve("127.0.0.1", False))
    with pytest.raises(tools.ToolError):
        asyncio.run(tools.resolve("10.1.2.3", False))
    with pytest.raises(tools.ToolError):
        asyncio.run(tools.resolve("224.0.0.1", True))
    for wrapped in ("::127.0.0.1", "64:ff9b::a00:1", "::ffff:10.0.0.1", "169.254.169.254", "100.64.0.1"):
        with pytest.raises(tools.ToolError):
            tools.check_ip(wrapped, False)  # IPv4 hidden in IPv6, metadata service, CGNAT
    assert asyncio.run(tools.resolve("127.0.0.1", True)) == ["127.0.0.1"]


def _tls_server(tmp: Path) -> tuple[int, threading.Event]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(days=1))
            .not_valid_after(NOW + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    (tmp / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    import socket
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp / "c.pem", tmp / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                s = ctx.wrap_socket(conn, server_side=True)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if data:
                    s.sendall(b"HTTP/1.1 200 OK\r\nServer: test/1.0\r\nStrict-Transport-Security: max-age=63072000\r\n"
                              b"X-Content-Type-Options: nosniff\r\nContent-Length: 0\r\n\r\n")
                s.close()
            except Exception:
                conn.close()
        srv.close()
    threading.Thread(target=serve, daemon=True).start()
    return port, stop


def test_tools_live_localhost(m, tmp_path):
    from fastapi.testclient import TestClient
    port, stop = _tls_server(tmp_path)
    try:
        res = asyncio.run(m.toolkit.http_tls(f"https://127.0.0.1:{port}/", "en"))
        assert res["http"]["status"].startswith("HTTP/1.1 200")
        assert res["tls"]["valid"] is False and "self-signed" in res["tls"]["validation"].lower()
        assert res["tls"]["key"] == "EC secp256r1" and res["tls"]["san"] == ["localhost"]
        assert res["security_headers"]["strict-transport-security"] == "max-age=63072000"
        assert res["security_headers"]["content-security-policy"] is None and res["disclosure"]["server"] == "test/1.0"
        pc = asyncio.run(m.toolkit.portcheck("127.0.0.1", [port, 1], "de"))
        assert pc["results"][0]["state"] == "open" and pc["results"][1]["state"] == "closed"
        assert pc["results"][0]["label"] == "offen" and pc["results"][1]["label"] == "geschlossen"
    finally:
        stop.set()
    def run(tc, body, **kw):
        r = tc.post("/api/tb/run", json=body, headers={"Sec-Fetch-Site": "same-origin", **kw.get("headers", {})})
        return r, [json.loads(line) for line in r.text.splitlines() if line.startswith("{")]

    with TestClient(m.app) as tc:
        r, _ = run(tc, {"tool": "ports", "target": "127.0.0.1", "params": {"ports": "1,2,a"}})
        assert r.status_code == 400 and r.json()["key"] == "err.tool.port"
        r, _ = run(tc, {"tool": "http", "target": "ftp://x.example"})
        assert r.status_code == 400 and r.json()["key"] == "err.tb.input"
        if Path(m.S.ping_bin).exists():
            r, events = run(tc, {"tool": "ping", "target": "127.0.0.1", "params": {"count": 2}})
            kinds = [e["type"] for e in events]
            assert r.status_code == 200 and kinds == ["start", "row", "row", "result"]
            res = events[-1]["result"]
            assert res["tool"] == "ping" and res["verdict"]["sev"] == "ok" and res["run_id"] > 0
            assert [row[0] for row in next(s for s in res["sections"] if s["kind"] == "table")["rows"]] == [1, 2]
        if Path(m.S.traceroute_bin).exists():
            r, events = run(tc, {"tool": "traceroute", "target": "127.0.0.1", "params": {"max_hops": 3}})
            hops = [e for e in events if e["type"] == "row" and e["kind"] == "hop"]
            assert hops and hops[0]["ip"] == "127.0.0.1" and hops[0]["private"] is True
            assert events[-1]["type"] == "result" and events[-1]["result"]["verdict"]["sev"] == "ok"
        r, _ = run(tc, {"tool": "ping", "target": "bad host"})
        assert r.status_code == 400 and r.json()["detail"].startswith("Dieses Werkzeug passt nicht")
        r, _ = run(tc, {"tool": "dns", "target": "a b"}, headers={"Cookie": "ew_lang=en"})
        assert r.status_code == 400 and r.json()["detail"].startswith("This tool does not fit the input")
