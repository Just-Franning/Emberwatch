"""Tests for the 3.x features: login, origin checks, i18n, log analysis, syslog, reputation, product watch,
attack surface (passive and active), CT monitoring, typosquatting and live BGP.

All upstream APIs are mocked with their documented formats; active scans run against 127.0.0.1.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import importlib
import json
import socket
import sys
import threading
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_features as feat  # noqa: E402

NOW = dt.datetime.now(dt.timezone.utc)
CALLS: list[httpx.Request] = []
STATE: dict = {}

DROP_V4 = [{"cidr": f"5.{i}.0.0/16", "sblid": f"SBL{1000 + i}", "rir": "ripencc"} for i in range(60)] + [
    {"cidr": "45.0.0.0/8", "sblid": "SBL1", "rir": "arin"},
    {"cidr": "45.155.205.0/24", "sblid": "SBL2", "rir": "ripencc"},
]
TOR = [f"185.220.101.{i}" for i in range(1, 80)]


def iso(h: float) -> str:
    return (NOW - dt.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%S.000")


def nvd_item(cve: str, score: float | None, hours_ago: float, desc: str) -> dict:
    metrics = {}
    if score is not None:
        metrics = {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                                      "cvssData": {"version": "3.1", "baseScore": score, "baseSeverity": "CRITICAL" if score >= 9 else "HIGH"}}]}
    return {"cve": {"id": cve, "published": iso(hours_ago), "lastModified": iso(1), "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": desc}, {"lang": "es", "value": "x"}], "metrics": metrics}}


def handler(request: httpx.Request) -> httpx.Response:
    CALLS.append(request)
    h, path, params = request.url.host, request.url.path, dict(request.url.params)
    if h == "www.spamhaus.org":
        if path.endswith("drop_v4.json"):
            lines = [json.dumps(r) for r in DROP_V4] + [json.dumps({"type": "metadata", "timestamp": 1, "size": 1, "records": 62,
                                                                     "copyright": "(c) Spamhaus", "terms": "x"})]
            return httpx.Response(200, text="\n".join(lines) + "\n")
        return httpx.Response(200, text=json.dumps({"cidr": "2a0e:1d80::/29", "sblid": "SBL3", "rir": "ripencc"}) + "\n")
    if h == "check.torproject.org":
        return httpx.Response(200, text="\n".join(TOR) + "\n")
    if h == "api.abuseipdb.com":
        assert request.headers["key"] == "ab-test" and request.headers["accept"] == "application/json"
        assert params["maxAgeInDays"] == "90"
        return httpx.Response(200, json={"data": {"ipAddress": params["ipAddress"], "isPublic": True, "abuseConfidenceScore": 80,
                                                  "countryCode": "DE", "usageType": "Data Center", "isp": "Hoster",
                                                  "domain": "hoster.example", "isTor": False, "totalReports": 42,
                                                  "numDistinctUsers": 9, "lastReportedAt": "2026-10-19T10:00:00+00:00",
                                                  "isWhitelisted": False}})
    if h == "internetdb.shodan.io":
        ip = path.strip("/")
        data = STATE.get("internetdb", {}).get(ip)
        if data is None:
            return httpx.Response(404, json={"detail": "No information available"})
        return httpx.Response(200, json={"ip": ip, "hostnames": ["host.example"], "tags": ["cloud"], "cpes": ["cpe:/a:x"], **data})
    if h == "services.nvd.nist.gov":
        assert "keywordSearch" in params and int(params["resultsPerPage"]) <= 2000
        for k in ("lastModStartDate", "lastModEndDate", "pubStartDate", "pubEndDate"):
            if k in params:
                assert params[k].endswith(".000") and "Z" not in params[k] and "+" not in params[k]
        items = STATE.get("nvd", [])
        return httpx.Response(200, json={"resultsPerPage": len(items), "startIndex": 0, "totalResults": len(items),
                                         "format": "NVD_CVE", "version": "2.0", "vulnerabilities": items})
    if h == "api.certspotter.com":
        assert params["domain"] and params["include_subdomains"] == "true"
        assert request.url.params.get_list("expand") == ["dns_names", "issuer"]
        pages = STATE.get("ct", {})
        return httpx.Response(200, json=pages.get(params.get("after", ""), []))
    if h == "stat.ripe.net":
        res = params["resource"]
        if path.startswith("/data/prefix-overview/"):
            if res.startswith("193.0.0.0"):
                return httpx.Response(200, json={"data": {"resource": "193.0.0.0/21", "announced": True, "is_less_specific": False,
                                                          "asns": [{"asn": 3333, "holder": "RIPE-NCC-AS"}]}})
            return httpx.Response(200, json={"data": {"resource": res, "announced": False, "asns": []}})
        if path.startswith("/data/announced-prefixes/"):
            return httpx.Response(200, json={"data": {"prefixes": [{"prefix": "45.67.0.0/22", "timelines": []},
                                                                   {"prefix": "10.0.0.0/8", "timelines": []}]}})
    return feat.handler(request)


def load_app(tmp_path: Path, monkeypatch, **extra: str):
    env = {
        "DATA_DIR": str(tmp_path), "STATIC_DIR": str(ROOT / "frontend"), "CF_API_TOKEN": "cf-test",
        "ABUSECH_AUTH_KEY": "tf-test", "RANSOMWARE_LIVE_API_KEY": "rl-test", "COLLECTORS": "0", "AUTH_MODE": "none",
        "LANGUAGE": "en", "BGP_LIVE": "0", "AI_MIN_INTERVAL_S": "0", "ABUSEIPDB_API_KEY": "ab-test",
        "MATRIX_HOMESERVER": "https://matrix.test", "MATRIX_ACCESS_TOKEN": "mx-token", "MATRIX_ROOM_ID": "!raum:matrix.test",
        "MATRIX_MIN_SEVERITY": "high",
    }
    env.update(extra)
    for k in ("AUTH_PASSWORD",):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    for mod in [x for x in sys.modules if x == "app" or x.startswith("app.")]:
        del sys.modules[mod]
    CALLS.clear()
    feat.CALLS.clear()
    STATE.clear()
    return importlib.import_module("app.main")


def mock_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def feeds(m, client) -> None:
    async def run():
        await m.abusech.collect_feodo(client, m.db, m.geo, m.S.user_agent, "tf-test")
        await m.abusech.collect_threatfox(client, m.db, m.geo, m.S.user_agent, "tf-test")
        await m.kev.collect(client, m.db, m.S.user_agent)
        await m.reputation.refresh(client)
    asyncio.run(run())


# Sign-in, sessions, roles and origin checks: test_v4_accounts.py


# --------------------------------------------------------------------------------------------------------------
# Log analysis and syslog

def test_extract():
    from app.logs import extract
    e = extract('Oct 20 fw: SRC=78.46.2.3 DST=192.168.1.10 v1.2.3.4.5 10.0.0.1 2001:db8::1 2a00:1450:4001:80b::200e '
                'GET http://x.example/p.exe?a=1). mail from bob@phish.example.net file svchost.exe at 12:34:56 '
                'host server01.lan aa:bb:cc:dd:ee:ff')
    assert e["ip"] == {"78.46.2.3", "2a00:1450:4001:80b::200e"}
    assert e["url"] == {"http://x.example/p.exe?a=1"}
    assert "phish.example.net" in e["domain"] and "x.example" in e["domain"]
    assert "svchost.exe" not in e["domain"] and "server01.lan" not in e["domain"]
    assert extract("999.1.1.1 1.2.3") == {"ip": set(), "domain": set(), "url": set()}


def test_log_upload_and_syslog(tmp_path, monkeypatch):
    m = load_app(tmp_path, monkeypatch, LOG_MAX_MB="1", LANGUAGE="de")
    client = mock_client()
    feeds(m, client)
    log = "\n".join([
        "Oct 20 10:00:01 fw kernel: IN=eth0 SRC=78.46.2.3 DST=192.168.1.10 PROTO=TCP DPT=443",
        "Oct 20 10:00:02 fw kernel: IN=eth0 SRC=78.46.2.3 DST=192.168.1.11 PROTO=TCP DPT=443",
        "proxy: GET http://x.example/p.exe 200",
        "dns: query beacon.evil.example.com A from 192.168.1.20",
        "sshd: Failed password for root from 185.220.101.7 port 4242",
        "nginx: 45.155.205.9 - - GET / 404",
        "nginx: 1.1.1.1 - - GET / 200",
        "app: loaded svchost.exe version 10.0.19041.1",
    ]) + "\n"
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        r = tc.post("/api/logs/analyze", content=log.encode(), headers={"Content-Type": "application/octet-stream"})
        assert r.status_code == 200, r.text
        res = r.json()
        hits = {h["indicator"]: h for h in res["hits"]}
        assert set(hits) == {"78.46.2.3", "http://x.example/p.exe", "beacon.evil.example.com", "185.220.101.7", "45.155.205.9"}
        assert hits["78.46.2.3"]["count"] == 2 and hits["78.46.2.3"]["severity"] == "high" and hits["78.46.2.3"]["line"] == 1
        assert hits["78.46.2.3"]["labels"] == ["botnet_cc NewRAT (ThreatFox)"]
        assert hits["beacon.evil.example.com"]["severity"] == "high"
        assert hits["http://x.example/p.exe"]["severity"] == "medium"
        assert hits["185.220.101.7"]["labels"] == ["Tor-Exit-Node"] and hits["185.220.101.7"]["severity"] == "low"
        assert hits["45.155.205.9"]["labels"] == ["Spamhaus DROP 45.155.205.0/24"]  # most specific block first
        assert res["lines"] == 8 and res["unique"]["ips"] == 4 and res["bytes"] == len(log.encode())
        assert res["hits"][0]["severity"] == "high" and "x.example" not in [h["indicator"] for h in res["hits"]]
        gz = tc.post("/api/logs/analyze", content=gzip.compress(log.encode()))
        assert gz.status_code == 200 and gz.json()["gzip"] is True and gz.json()["hits_total"] == 5
        big = tc.post("/api/logs/analyze", content=b"x" * (1024 * 1024 + 10))
        assert big.status_code == 413 and big.json()["detail"] == "Datei zu groß (maximal 1 MB)."
        assert tc.post("/api/logs/analyze", content=b"").status_code == 400
        assert not list((tmp_path / "tmp").iterdir())  # uploads are never kept
        assert tc.get("/api/logs/status").json()["indexes"]["tor"] == len(TOR)

    sl = m.SyslogServer(m.S, m.db, m.matcher)
    assert sl.allowed("127.0.0.1") and sl.allowed("::ffff:192.168.1.1") and not sl.allowed("8.8.8.8")
    sl.handle("<34>1 2026-10-20T10:00:00Z fw - - - conn 78.46.2.4:443", "192.168.1.1")
    sl.handle("<34>1 2026-10-20T10:00:05Z fw - - - conn 78.46.2.4:443 again", "192.168.1.1")
    sl.handle("123 <34>Oct 20 10:00:00 fw: tor 185.220.101.9", "192.168.1.1")
    rows = m.alerts.listing(m.db, "en", source="syslog")
    assert len(rows) == 2 and sl.stats["matched"] == 3 and sl.stats["alerts"] == 2
    hi = next(a for a in rows if "78.46.2.4" in a["title"])
    assert hi["severity"] == "high" and hi["title"] == "Known indicator in syslog: 78.46.2.4"
    assert "botnet_cc NewRAT (ThreatFox)" in hi["detail"] and "source 192.168.1.1" in hi["detail"]

    async def udp_roundtrip():
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        s2 = m.SyslogServer(m.S.__class__(**{**m.S.__dict__, "syslog_port": port}), m.db, m.matcher)
        await s2.start()
        try:
            loop = asyncio.get_running_loop()
            tr, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port))
            tr.sendto(b"<13>Oct 20 10:00:00 host app: hello 185.220.101.33\n")
            await asyncio.sleep(0.2)
            tr.close()
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"<13>Oct 20 10:00:00 host app: tcp 185.220.101.34\n")
            await w.drain()
            await asyncio.sleep(0.2)
            w.close()
        finally:
            await s2.stop()
        return s2.stats

    stats = asyncio.run(udp_roundtrip())
    assert stats["received"] == 2 and stats["matched"] == 2


# --------------------------------------------------------------------------------------------------------------
# Reputation, products, attack surface

def test_reputation(tmp_path, monkeypatch):
    m = load_app(tmp_path, monkeypatch)
    client = mock_client()
    feeds(m, client)
    rep = m.reputation
    assert rep.drop_count == 63 and rep.tor_count == len(TOR)
    assert rep.drop_for("45.155.205.9") == {"cidr": "45.155.205.0/24", "sblid": "SBL2"}
    assert rep.drop_for("45.1.2.3") == {"cidr": "45.0.0.0/8", "sblid": "SBL1"}  # nested block found via running max
    assert rep.drop_for("45.200.0.0/16")["cidr"] == "45.0.0.0/8"
    assert rep.drop_for("2a0e:1d80:1::1")["sblid"] == "SBL3" and rep.drop_for("8.8.8.8") is None
    n_calls = len(CALLS)
    asyncio.run(rep.refresh(client))
    assert len(CALLS) == n_calls  # daily / 6-hourly, not on every run
    m.db.execute("INSERT INTO watchlist(kind, value, label, created_at) VALUES('ip','45.155.205.9','web',?)", (m.utcnow(),))
    m.db.execute("INSERT INTO watchlist(kind, value, label, created_at) VALUES('ip','8.8.8.8',NULL,?)", (m.utcnow(),))
    assert asyncio.run(rep.scan_assets(client)) == 3  # DROP + 2x AbuseIPDB (score 80 >= 25)
    assert asyncio.run(rep.scan_assets(client)) == 0
    ab_calls = [c for c in CALLS if c.url.host == "api.abuseipdb.com"]
    assert len(ab_calls) == 2  # second run served from the 24 h cache
    titles = [a["title"] for a in m.alerts.listing(m.db, "en", source="rep")]
    assert "45.155.205.9 on Spamhaus DROP" in titles and "Bad reputation: 8.8.8.8" in titles
    a = next(a for a in m.alerts.listing(m.db, "en", source="rep") if a["key"] == "rep.drop")
    assert a["url"] == "https://www.spamhaus.org/sbl/query/SBL2"
    info = asyncio.run(m.toolkit.ipinfo(client, "185.220.101.7", "en"))
    assert info["reputation"]["tor"] is True and info["reputation"]["abuseipdb"]["score"] == 80


def test_products_and_nvd(tmp_path, monkeypatch):
    m = load_app(tmp_path, monkeypatch)
    client = mock_client()
    feeds(m, client)
    m.products._gap = 0
    from app.products import kev_match
    assert kev_match("Ivanti", "", {"vendor": "Ivanti", "product": "Connect Secure", "name": "x"})
    assert kev_match("ivanti", "connect secure", {"vendor": "Ivanti", "product": "Connect Secure", "name": "x"})
    assert not kev_match("Ivanti", "EPMM", {"vendor": "Ivanti", "product": "Connect Secure", "name": "x"})
    assert not kev_match("Sophos", "", {"vendor": "Ivanti", "product": "x", "name": "y"})
    assert not kev_match("MS", "", {"vendor": "Microsoft", "product": "x", "name": "y"})
    STATE["nvd"] = [nvd_item("CVE-2026-5000", 9.8, 20, "Ivanti Connect Secure auth bypass"),
                    nvd_item("CVE-2026-5002", None, 5, "Ivanti something, awaiting analysis")]
    from fastapi.testclient import TestClient
    with TestClient(m.app) as tc:
        tc.app.state.client = client
        assert tc.post("/api/products", json={"vendor": "  "}).status_code == 400
        pid = tc.post("/api/products", json={"vendor": "Ivanti", "product": ""}).json()["id"]
        assert tc.post("/api/products", json={"vendor": "ivanti"}).status_code == 409
        asyncio.run(m.products.check(client, only=pid))
        lst = tc.get("/api/products").json()["products"]
        assert lst[0]["kev"] == 3 and lst[0]["nvd"] == 2 and lst[0]["critical"] == 1 and lst[0]["baseline"] is True
        assert m.alerts.listing(m.db, "en", source="product") == []  # baseline is silent
        # later: a new critical CVE, an old re-analysed CVE and a new KEV entry
        STATE["nvd"] = [nvd_item("CVE-2026-5001", 10.0, 2, "Ivanti EPMM RCE"),
                        nvd_item("CVE-2019-11510", 10.0, 24 * 2000, "old Pulse Secure"),
                        nvd_item("CVE-2026-5002", 9.1, 5, "Ivanti something, now analysed")]
        m.db.execute("INSERT INTO kev(cve, vendor, product, name, date_added, due_date, ransomware) "
                     "VALUES('CVE-2026-7777','Ivanti','EPMM','Ivanti EPMM Code Injection',?, ?, 'Unknown')",
                     (NOW.date().isoformat(), NOW.date().isoformat()))
        asyncio.run(m.products.check(client, force=True))
        al = {a["key"] + ":" + a["title"].split(":")[1].split("(")[0].strip(): a for a in m.alerts.listing(m.db, "en", source="product")}
        assert set(al) == {"product.cve:CVE-2026-5001", "product.cve:CVE-2026-5002", "product.kev:CVE-2026-7777"}
        assert al["product.cve:CVE-2026-5001"]["detail"].startswith("CVSS 10.0: Ivanti EPMM RCE")
        assert al["product.kev:CVE-2026-7777"]["title"] == "Actively exploited: CVE-2026-7777 (Ivanti)"
        assert al["product.cve:CVE-2026-5002"]["severity"] == "high"
        cves = tc.get(f"/api/products/{pid}/cves").json()["cves"]
        assert cves[0]["kev_name"] and {c["cve"] for c in cves} >= {"CVE-2026-5000", "CVE-2026-7777", "CVE-2019-11510"}
        nvd_req = [c for c in CALLS if c.url.host == "services.nvd.nist.gov"][-1]
        assert nvd_req.url.params["keywordSearch"] == "Ivanti" and "lastModStartDate" in nvd_req.url.params
        # free-text search: NVD (cached) with EPSS and KEV flags
        STATE["nvd"] = [nvd_item("CVE-2026-1001", 9.0, 10, "Ivanti Connect Secure x")]
        s1 = tc.get("/api/search/nvd?q=Ivanti Connect").json()
        assert s1["cached"] is False and s1["cves"][0]["kev"] is True and s1["cves"][0]["epss"] == pytest.approx(0.97)
        assert tc.get("/api/search/nvd?q=ivanti  connect").json()["cached"] is True
        assert tc.delete(f"/api/products/{pid}").status_code == 200
        assert m.alerts.listing(m.db, "en", source="product") == []


def _banner_server(banner: bytes) -> tuple[int, threading.Event]:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                conn.sendall(banner)
            except OSError:
                pass
            conn.close()
        srv.close()
    threading.Thread(target=serve, daemon=True).start()
    return port, stop


def test_surface_passive_and_active_scan(tmp_path, monkeypatch):
    tls_port, stop_tls = feat._tls_server(tmp_path)  # self-signed, valid 30 days
    ssh_port, stop_ssh = _banner_server(b"SSH-2.0-OpenSSH_9.6p1 Debian\r\n")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
    try:
        m = load_app(tmp_path, monkeypatch, TOOLS_ALLOW_PRIVATE="1", SCAN_PORTS=f"{tls_port},{closed_port}",
                     SCAN_TIMEOUT_S="0.5")
        assert m.S.scan_ports == (tls_port, closed_port)
        from app import surface as surface_mod
        surface_mod.TLS_PORTS.add(tls_port)
        client = mock_client()
        feeds(m, client)
        from fastapi.testclient import TestClient
        with TestClient(m.app) as tc:
            tc.app.state.client = client
            # passive: InternetDB baseline, then a diff
            STATE["internetdb"] = {"8.8.8.8": {"ports": [53, 443], "vulns": []}}
            aid = tc.post("/api/watchlist", json={"value": "8.8.8.8", "label": "dns"}).json()["id"]
            asyncio.run(m.surface.passive(client))
            assert m.alerts.listing(m.db, "en", source="surface") == []
            STATE["internetdb"] = {"8.8.8.8": {"ports": [53, 443, 3389], "vulns": ["CVE-2026-1000", "CVE-2099-0001"]}}
            asyncio.run(m.surface.passive(client, force=True))
            sa = {a["title"]: a for a in m.alerts.listing(m.db, "en", source="surface")}
            assert sa["New open port on 8.8.8.8"]["severity"] == "high"  # RDP is risky
            assert sa["Vulnerability on 8.8.8.8: CVE-2026-1000"]["severity"] == "high"  # in KEV
            assert sa["Vulnerability on 8.8.8.8: CVE-2026-1000"]["detail"].startswith("CISA KEV; ")
            assert sa["Vulnerability on 8.8.8.8: CVE-2099-0001"]["severity"] == "medium"
            det = tc.get(f"/api/assets/{aid}").json()
            assert det["surface_rows"][0]["ports"] == [53, 443, 3389] and det["surface_rows"][0]["kev"] == ["CVE-2026-1000"]
            assert det["surface"]["ports"] == [53, 443, 3389]
            # active scan: consent required
            r = tc.post("/api/watchlist", json={"value": "127.0.0.1", "scan": True})
            assert r.status_code == 400 and r.json()["key"] == "err.scan_ack"
            lid = tc.post("/api/watchlist", json={"value": "127.0.0.1", "scan": True, "scan_ack": True}).json()["id"]
            assert tc.post(f"/api/assets/{aid}/scan").json()["key"] == "err.scan_ack"
            run1 = asyncio.run(m.surface.scan_asset(lid))
            d1 = m.surface.last_scan(lid)
            assert d1["run"]["id"] == run1 and d1["run"]["status"] == "done" and len(d1["ports"]) == 1
            p = d1["ports"][0]
            assert p["port"] == tls_port and p["tls"]["subject"] == "CN=localhost" and p["tls"]["valid"] is False
            assert p["http"]["status"].startswith("HTTP/1.1 200") and p["http"]["server"] == "test/1.0"
            assert m.alerts.listing(m.db, "en", source="scan") == []  # baseline; certificate has 30 days left
            # second run: a new service appears
            m.S.__dict__["scan_ports"] = (tls_port, closed_port, ssh_port)
            asyncio.run(m.surface.scan_asset(lid))
            sc = m.alerts.listing(m.db, "en", source="scan")
            assert [a["title"] for a in sc] == [f"New open port 127.0.0.1:{ssh_port}"]
            assert sc[0]["detail"] == "ssh; SSH-2.0-OpenSSH_9.6p1 Debian; Active scan (127.0.0.1)"
            d2 = m.surface.last_scan(lid)
            assert next(x for x in d2["ports"] if x["port"] == ssh_port)["service"] == "ssh"
            # disable scanning: consent is removed
            assert tc.patch(f"/api/watchlist/{lid}", json={"scan": False}).json()["scan_ack"] is None
            assert tc.post(f"/api/assets/{lid}/scan").status_code == 400
            assert tc.post("/api/watchlist", json={"value": "10.0.0.0/16", "scan": True, "scan_ack": True}).status_code == 200
            big = m.db.query("SELECT id FROM watchlist WHERE value='10.0.0.0/16'")[0]["id"]
            r = tc.post(f"/api/assets/{big}/scan")
            assert r.status_code == 400 and r.json()["key"] == "err.scan_too_big"
            # no scannable address (private without TOOLS_ALLOW_PRIVATE): clear error instead of an empty run
            m.S.__dict__["tools_allow_private"] = False
            priv = tc.post("/api/watchlist", json={"value": "192.168.77.10", "scan": True, "scan_ack": True}).json()["id"]
            r = tc.post(f"/api/assets/{priv}/scan", headers={"Accept-Language": "de"})
            assert r.status_code == 400 and r.json()["key"] == "err.scan_no_targets" and "TOOLS_ALLOW_PRIVATE" in r.json()["detail"] and r.json()["detail"].startswith("Keine scanbaren")
            try:
                asyncio.run(m.surface.scan_asset(priv))
                raise AssertionError("scan_asset must refuse an asset without targets")
            except m.AppError as exc:
                assert exc.key == "err.scan_no_targets"
            assert m.db.query("SELECT COUNT(*) AS n FROM scan_runs WHERE asset_id=?", (priv,))[0]["n"] == 0
            m.S.__dict__["tools_allow_private"] = True
            assert tc.delete(f"/api/watchlist/{lid}").status_code == 200
            assert m.db.query("SELECT COUNT(*) AS n FROM scan_runs WHERE asset_id=?", (lid,))[0]["n"] == 0
    finally:
        stop_tls.set()
        stop_ssh.set()


# --------------------------------------------------------------------------------------------------------------
# Domains: CT and typosquatting

def test_ct_and_typosquatting(tmp_path, monkeypatch):
    m = load_app(tmp_path, monkeypatch)
    client = mock_client()
    cert = {"id": "100", "tbs_sha256": "aa", "cert_sha256": "bb", "dns_names": ["example.de", "www.example.de"],
            "pubkey_sha256": "cc", "issuer": {"friendly_name": "Let's Encrypt", "name": "C=US, O=Let's Encrypt, CN=R11"},
            "not_before": "2026-09-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z", "revoked": False}
    STATE["ct"] = {"": [cert], "100": []}
    wid = m.db.insert("INSERT INTO watchlist(kind, value, label, created_at) VALUES('domain','example.de',NULL,?)", (m.utcnow(),))
    assert asyncio.run(m.domains.ct(client)) == 0
    assert m.db.meta_get("ct_baseline:example.de") == "done" and m.db.meta_get("ct_after:example.de") == "100"
    renewal = {**cert, "id": "101", "tbs_sha256": "dd"}
    new = {**cert, "id": "102", "tbs_sha256": "ee", "dns_names": ["vpn.example.de"],
           "issuer": {"friendly_name": "Evil CA"}, "not_after": "2027-01-01T00:00:00Z"}
    STATE["ct"] = {"100": [renewal, new], "102": []}
    assert asyncio.run(m.domains.ct(client)) == 2
    titles = sorted(a["title"] for a in m.alerts.listing(m.db, "en", source="ct"))
    assert titles == ["New certificate authority for example.de", "New certificate for example.de"]
    ct_new = next(a for a in m.alerts.listing(m.db, "en", source="ct") if a["key"] == "ct.new_cert")
    assert ct_new["detail"] == "vpn.example.de; issuer Evil CA" and ct_new["asset_id"] == wid

    registered = {"exampel.de", "examp1e.de"}

    async def fake_exists(self, res, name):
        if name.startswith("ew-"):
            return False
        return name in registered

    async def fake_details(self, res, name):
        return (name == "examp1e.de", ["198.51.100.10"])

    monkeypatch.setattr(m.Domains, "_exists", fake_exists)
    monkeypatch.setattr(m.Domains, "_details", fake_details)
    assert asyncio.run(m.domains.typos()) == 1
    base = m.alerts.listing(m.db, "en", source="typo")
    assert base[0]["title"] == "2 lookalike domains of example.de active"
    registered.add("exarnple.de")
    assert asyncio.run(m.domains.typos()) == 1
    reg = next(a for a in m.alerts.listing(m.db, "en", source="typo") if a["key"] == "typo.registered")
    assert reg["title"] == "Lookalike domain registered: exarnple.de" and reg["detail"] == "Variant of example.de (homoglyph); 198.51.100.10"
    info = m.domains.listing("example.de")
    assert {t["candidate"] for t in info["typos"]} == registered and info["ct_total"] == 3


# --------------------------------------------------------------------------------------------------------------
# Live BGP (message handling without a WebSocket)

def test_bgp_monitor(tmp_path, monkeypatch):
    m = load_app(tmp_path, monkeypatch)
    client = mock_client()
    for kind, value in (("cidr", "193.0.0.0/22"), ("asn", "64496"), ("cidr", "10.0.0.0/8")):
        m.db.execute("INSERT INTO watchlist(kind, value, label, created_at) VALUES(?,?,NULL,?)", (kind, value, m.utcnow()))
    bgp = m.bgp
    bgp.watches = asyncio.run(bgp.plan(client))
    assert set(bgp.watches) == {"193.0.0.0/21", "45.67.0.0/22"}  # private nets are never watched
    assert bgp.watches["193.0.0.0/21"].expected == {3333} and bgp.watches["45.67.0.0/22"].expected == {64496}

    def upd(prefixes, path, peer="192.0.2.1", withdrawals=()):
        return {"type": "ris_message", "data": {"timestamp": 1.0, "peer": peer, "peer_asn": "64999", "id": "x", "host": "rrc00",
                                                "type": "UPDATE", "path": path,
                                                "announcements": [{"next_hop": "192.0.2.1", "prefixes": prefixes}] if prefixes else [],
                                                "withdrawals": list(withdrawals)}}

    bgp.handle(upd(["193.0.0.0/21"], [64999, 1299, 3333]))
    bgp.handle(upd(["45.67.0.0/22"], [64999, 64496]))
    assert bgp.stats["alerts"] == 0 and bgp.stats["relevant"] == 2
    bgp.handle(upd(["193.0.0.0/21"], [64999, 64666]))           # origin hijack
    bgp.handle(upd(["193.0.0.0/24"], [64999, 64666]))           # more specific overlapping the asset
    bgp.handle(upd(["193.0.6.0/24"], [64999, 64666]))           # more specific, but not the asset /22 -> ignored
    bgp.handle(upd(["193.0.0.0/21"], [64999, [3333, 64777]]))   # AS_SET with a foreign member
    bgp.handle(upd(["45.67.1.0/24"], [64999, 64497]))           # ASN watch
    bgp.handle(upd(["193.0.0.0/21"], [64999, 64666]))           # duplicate (same day) -> no new alert
    rows = m.alerts.listing(m.db, "en", source="bgp")
    titles = sorted(a["title"] for a in rows)
    assert titles == ["More specific prefix under 193.0.0.0/21", "More specific prefix under 45.67.0.0/22",
                      "Possible BGP hijack: 193.0.0.0/21", "Possible BGP hijack: 193.0.0.0/21"]
    hij = next(a for a in rows if a["title"] == "Possible BGP hijack: 193.0.0.0/21" and "AS64666" in a["detail"])
    assert hij["detail"] == "Announced by AS64666, expected AS3333; peer AS64999 via rrc00" and hij["severity"] == "high"
    for i in range(30):
        bgp.handle(upd([], [], peer=f"192.0.2.{i}", withdrawals=["193.0.0.0/21"]))
    wd = [a for a in m.alerts.listing(m.db, "en", source="bgp") if a["key"] == "bgp.withdrawn"]
    assert len(wd) == 1 and wd[0]["title"] == "Prefix 193.0.0.0/21 being withdrawn"
    assert bgp.info()["events"][0]["type"] == "withdraw"
    bgp.handle({"type": "ris_error", "data": {"message": "bad subscription"}})
    assert bgp.stats["error"] == "bad subscription"


# --------------------------------------------------------------------------------------------------------------
# Matrix delivery of alerts: no backlog flood, severity filter

def test_alert_delivery_backlog(tmp_path, monkeypatch):
    m = load_app(tmp_path, monkeypatch, MATRIX_MIN_SEVERITY="medium")
    client = mock_client()
    old = (NOW - dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    m.alerts.add(m.db, "watch", "high", "legacy", {"detail": "old"}, "old-1")
    m.db.execute("UPDATE alerts SET created_at=? WHERE ref='old-1'", (old,))
    m.alerts.add(m.db, "watch", "low", "legacy", {"detail": "low"}, "low-1")
    m.alerts.add(m.db, "watch", "medium", "legacy", {"detail": "<b>new</b>"}, "new-1")
    asyncio.run(m.notifier.alerts(client))
    sent = [c for c in feat.CALLS if c.url.host == "matrix.test"]
    assert len(sent) == 1
    body = json.loads(sent[0].content)
    assert "old" not in body["body"] and "low" not in body["body"] and "<b>new</b>" in body["body"]
    assert "&lt;b&gt;new&lt;/b&gt;" in body["formatted_body"]
    assert {r["ref"]: r["notified"] for r in m.db.query("SELECT ref, notified FROM alerts")} == {"old-1": 2, "low-1": 2, "new-1": 1}
