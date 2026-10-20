# Emberwatch

Self-hosted cyber threat picture on a world map: attacks, C2 servers, ransomware, exploited vulnerabilities and internet infrastructure from public sources, plus monitoring of your own assets, products and logs.

**English** · [Deutsch](README.de.md)

![Emberwatch main view](docs/screenshot.webp)

*Screenshots use synthetic demo data.*

## Features

**Global threat picture**
- World map with L7 attack flows (origin → target), country shading by attack share, reported C2 servers, ransomware victims per country, internet outages, BGP hijacks/route leaks, traffic anomalies and submarine cables
- Rankings: target and origin countries (24 h vs. 7 days), DDoS vectors, L7 attack categories, C2 families and hosting networks, ransomware groups and sectors, newly exploited vulnerabilities (CISA KEV with FIRST EPSS)
- Rule-based pattern detection (rising countries and vectors, spikes, new C2 families, KEV clusters, critical outages, correlations) – deterministic and explained, no black box
- Timeline with daily history (up to 90 days) and 30-day trends per country
- C2 blocklist export (TXT/CSV) with filters
- Optional Gemini reports (global, country, home region, free questions with follow-ups), exportable as Markdown or PDF. The model only receives aggregated figures.

**Your own assets** (IPs, networks, AS numbers, domains)
- Matching against C2 servers, ThreatFox IOCs, BGP hijacks/leaks, outages, ransomware leak sites, Spamhaus DROP and AbuseIPDB
- Passive attack surface via Shodan InternetDB: open ports, CVEs (flagged if in CISA KEV), changes become alerts
- Optional active TCP scan of assets you explicitly enabled and confirmed: open ports, TLS certificates (expiry, changes), HTTP server, service banners
- Certificate Transparency monitoring (new names and new certificate authorities) and lookalike domain detection (typosquatting, homoglyphs, IDN, bit flips, TLD swaps)
- Live BGP monitoring of your prefixes via RIPE RIS Live: unexpected origin AS, more specific announcements, mass withdrawals

**Product watch:** search for a vendor or product (e.g. "Sophos") and watch it. Alerts for new CISA KEV entries and new critical CVEs from the NVD.

**Log analysis:** upload firewall, proxy, DNS, web or mail logs (text or .gz). IPs, domains and URLs are checked against C2 servers, ThreatFox IOCs, Tor exit nodes and Spamhaus DROP. The file is not stored. Optionally receive syslog (UDP/TCP) continuously.

**Alerts:** one alert feed for everything that concerns you, with optional Matrix notifications and a daily report.

**Network tools** with live display on the map: ping, traceroute, DNS (incl. SPF/DMARC/DNSSEC flag), whois (RDAP), IP info with reputation, port check, HTTP/TLS check.

**Interface:** German and English, movable and resizable windows with adjustable opacity, keyboard shortcuts, start animation, optional login.

![Asset detail with attack surface and alerts](docs/assets.webp)

## Requirements

- Docker with Docker Compose, or Portainer
- A volume for `/data` (SQLite database, login files, DB-IP geolocation databases). The compose files limit memory to 1 GB.
- Outbound HTTPS to the data sources (see [Data sources](#data-sources-and-licences)); outbound ICMP/UDP for ping and traceroute
- Free API keys for the core sources: Cloudflare (Radar) and abuse.ch. Everything else is optional.

## Installation

### Option A: Portainer with the prebuilt image

1. *Stacks → Add stack → Web editor*, paste [`portainer-stack.yml`](portainer-stack.yml).
2. Under *Environment variables* set at least:
   - `PROXY_NETWORK` – the Docker network of your reverse proxy (Traefik, Nginx Proxy Manager, Pangolin/Newt, …)
   - `CF_API_TOKEN`, `ABUSECH_AUTH_KEY`
   - optionally `LANGUAGE=de`, `AUTH_PASSWORD`, further keys (all variables: [`.env.example`](.env.example))
3. Deploy, then point your reverse proxy to `http://emberwatch:8000`.

The image is published as `ghcr.io/saturdaynetlab/emberwatch` for `linux/amd64` and `linux/arm64`.

### Option B: Docker Compose (build from source)

```bash
git clone https://github.com/SaturdayNetLab/emberwatch.git
cd emberwatch
cp .env.example .env    # add your keys
docker compose up -d --build
```

The interface is then available at `http://127.0.0.1:8000`. For access from other machines use a reverse proxy with TLS (see [Reverse proxy](#reverse-proxy-and-login)).

### Option C: Portainer, build the image yourself

```bash
git clone https://github.com/SaturdayNetLab/emberwatch.git
cd emberwatch
git archive -o emberwatch.tar HEAD
```

In Portainer: *Images → Build a new image → Upload*, select `emberwatch.tar`, image name `emberwatch:latest`. Then deploy the stack as in option A with `EMBERWATCH_IMAGE=emberwatch:latest`.

## Quickstart

1. **Log in.** With the default `AUTH_MODE=password` and no `AUTH_PASSWORD`, a random password is generated on first start:
   ```bash
   docker logs emberwatch 2>&1 | grep "login password"
   docker exec emberwatch cat /data/initial-password.txt
   ```
2. **Wait for data.** The first collection takes a few minutes; the Radar history (30 days by default) is loaded in the background. *Status* shows the state of every source.
3. **Add your assets.** *Assets* (key `A`): IPs, networks, AS numbers or domains. Active scanning is only possible after you confirm that you are authorised to scan the asset.
4. **Watch products.** Search for a vendor, e.g. `Sophos`, and choose *Watch as product*, or add it under *Assets → Products*.
5. **Notifications (optional).** Configure Matrix to receive alerts and the daily report.

Keyboard shortcuts: `[` and `]` toggle the side panels, `T` network tools, `A` assets window, `/` search, `Esc` close. Windows can be moved by their title bar, resized at the bottom right corner and docked again with a double-click on the title bar. Language, window opacity and the start animation are under *Settings* (⚙).

## Configuration

All settings are environment variables; [`.env.example`](.env.example) lists every variable with its default. The most important ones:

| Variable | Default | Purpose |
|---|---|---|
| `LANGUAGE` | `en` | Language of notifications and daily reports (`de`/`en`). The UI language is chosen per browser. |
| `AUTH_MODE` | `password` | `password` = built-in login, `none` = no login (only behind an authenticating proxy) |
| `AUTH_PASSWORD` | – | Login password; empty = generated on first start |
| `CF_API_TOKEN` | – | Cloudflare API token with Radar read permission (attacks, outages, BGP events) |
| `ABUSECH_AUTH_KEY` | – | abuse.ch Auth-Key (ThreatFox) |
| `RANSOMWARE_LIVE_API_KEY` | – | Optional ransomware.live PRO key; without it the free API is used |
| `ABUSEIPDB_API_KEY` | – | Optional, IP reputation (free tier: 1,000 checks per day) |
| `NVD_API_KEY` | – | Optional, faster product checks (50 instead of 5 requests per 30 s) |
| `CERTSPOTTER_API_KEY` | – | Optional, higher Certificate Transparency limits |
| `GEMINI_API_KEY` | – | Optional, AI reports |
| `MATRIX_HOMESERVER`, `MATRIX_ACCESS_TOKEN`, `MATRIX_ROOM_ID` | – | Optional Matrix notifications (bot account in an unencrypted room) |
| `MATRIX_MIN_SEVERITY` | `high` | Minimum severity for notifications |
| `DAILY_REPORT_TIME` | `07:00` | Daily report (local time, `TZ`), empty = off |
| `HOME_REGION`, `HOME_REGION_NAME` | – | Optional home region, e.g. `DE,AT,CH` / `DACH`, adds a region analysis |
| `TOOLS_ALLOW_PRIVATE` | `0` | `1` = tools and active scans may target private addresses |
| `SCAN_ENABLED` | `1` | `0` disables active scans completely |
| `SYSLOG_ENABLED` | `0` | `1` = syslog receiver on `SYSLOG_PORT` (default 5514, UDP and TCP) |
| `BGP_LIVE` | `1` | Live BGP monitoring of your prefixes |

Where to get the keys:
- Cloudflare: *My Profile → API Tokens → Create Token* (custom token with the Radar read permission)
- abuse.ch: <https://auth.abuse.ch/>
- AbuseIPDB: <https://www.abuseipdb.com/account/api>
- NVD: <https://nvd.nist.gov/developers/request-an-api-key>
- Gemini: <https://aistudio.google.com/apikey>

## Reverse proxy and login

- Forward to port 8000 of the container. Keep the `Host` header (default in Traefik, Nginx Proxy Manager and Pangolin). If your proxy rewrites it, add the public host to `TRUSTED_ORIGINS`.
- The network tools use server-sent events; proxies must not buffer `text/event-stream` responses (Emberwatch sends `X-Accel-Buffering: no`).
- `FORWARDED_ALLOW_IPS` defaults to `*` so that client addresses from the proxy are used (login rate limit). If port 8000 is reachable by anything other than the proxy, set it to the proxy address.
- With `AUTH_MODE=none` the login is off. Only use this behind a proxy that authenticates users (e.g. Pangolin, Authelia, Authentik).
- Reset the password: set `AUTH_PASSWORD`, or delete `/data/auth.json` and `/data/initial-password.txt` and restart.

## Security and privacy

- Single-user login: scrypt-hashed password, HMAC-signed session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` on HTTPS), brute-force limit, same-origin checks for all API requests, strict Content Security Policy.
- The container runs as an unprivileged user with a read-only root filesystem, all capabilities dropped and `no-new-privileges`.
- Network tools and scans only reach public addresses unless `TOOLS_ALLOW_PRIVATE=1`; host names are resolved once and every address is checked (no DNS rebinding); no shell is involved.
- **Active scans:** only scan systems you own or are authorised to test. Emberwatch scans an asset only after explicit confirmation and limits hosts, ports and parallelism. Scanning third-party systems can be illegal.
- Uploaded logs are processed in a temporary file and deleted immediately; only the result goes back to the browser. Syslog lines are only kept as alerts for known indicators.
- Gemini only receives aggregated figures and detected patterns: no victim names, no raw IOCs, no assets, no log contents.
- Outbound connections: the data sources listed below, the basemap tiles (OpenFreeMap, loaded by the browser), DB-IP downloads, and the targets you choose in the network tools or scans.
- Backups: everything lives in the `/data` volume (`emberwatch.sqlite`, login files, geolocation databases).

## Architecture

```
Browser (vanilla JS, MapLibre, Chart.js)  ──HTTPS──  reverse proxy  ──  Emberwatch container
                                                                          FastAPI + uvicorn (1 worker)
                                                                          ├─ collectors (asyncio loops) ── public sources
                                                                          ├─ asset monitors: InternetDB, scans, CT, typo, RIS Live
                                                                          ├─ alerts → Matrix
                                                                          ├─ log analysis / syslog receiver
                                                                          └─ SQLite (/data)
```

- Backend: `backend/app` (one module per concern: `sources/` collectors, `analytics.py` patterns, `surface.py` attack surface and scans, `domains.py` CT and lookalikes, `bgp.py` RIS Live, `products.py` KEV/NVD, `logs.py` log analysis and syslog, `reputation.py`, `alerts.py`, `auth.py`, `i18n.py`).
- Texts the backend produces (patterns, alerts, errors) are stored language-neutral and rendered per request in German or English.
- Frontend: `frontend/` without a build step; all dynamic content is inserted as text, never as HTML.

## Data sources and licences

| Source | Used for | Terms |
|---|---|---|
| [Cloudflare Radar](https://radar.cloudflare.com) | attack shares, vectors, outages, BGP hijacks/leaks, anomalies | CC BY-NC 4.0 |
| [abuse.ch](https://abuse.ch) Feodo Tracker, ThreatFox | C2 servers, IOCs | abuse.ch terms of use |
| [Ransomware.live](https://www.ransomware.live) | leak site victims | attribution required, no redistribution of raw data |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | exploited vulnerabilities | public |
| [FIRST EPSS](https://www.first.org/epss/) | exploitation probability | FIRST terms |
| [NVD](https://nvd.nist.gov) | CVEs for watched products | This product uses data from the NVD API but is not endorsed or certified by the NVD. |
| [Shodan InternetDB](https://internetdb.shodan.io) | passive attack surface | free for non-commercial use |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | hijacked networks | free use with attribution to The Spamhaus Project |
| [Tor Project](https://check.torproject.org/torbulkexitlist) | Tor exit nodes | public |
| [AbuseIPDB](https://www.abuseipdb.com) | IP reputation (optional) | AbuseIPDB terms |
| [RIPE NCC RIS Live, RIPEstat](https://ris-live.ripe.net) | live BGP, routing | RIPE NCC terms |
| [Cert Spotter](https://sslmate.com/certspotter/) | Certificate Transparency | SSLMate terms |
| [DB-IP Lite](https://db-ip.com) | IP geolocation and ASN | CC BY 4.0 |
| [TeleGeography](https://www.submarinecablemap.com) | submarine cables (snapshot 2021) | CC BY-NC-SA 3.0 |
| [OpenFreeMap](https://openfreemap.org), OpenMapTiles, OpenStreetMap | basemap | see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) |
| [Natural Earth](https://www.naturalearthdata.com) | country shapes (offline map) | public domain |

Several sources only allow non-commercial use. Emberwatch is meant for private and non-commercial use; see [Licence](#licence).

## Limitations

- Cloudflare values are shares of the traffic Cloudflare sees, not absolute attack counts. Origin is where the attacking IPs are, not who is behind them.
- Geolocation (DB-IP Lite) is approximate.
- InternetDB is updated about weekly; a port opened today may only appear days later. Use the active scan for current results.
- The product watch matches NVD descriptions by keyword; generic names can produce false positives.
- Lookalike detection uses a heuristic for registrable domains (no Public Suffix List) and treats any DNS answer other than NXDOMAIN as registered.
- BGP alerts are heuristics without RPKI validation; a new upstream or a DDoS mitigation service can trigger them.
- Syslog is received unencrypted; restrict senders with `SYSLOG_ALLOW` and your firewall. With Docker's port publishing all senders may appear with the Docker gateway address.
- One user (one password), one instance (SQLite, one worker).

## Development

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest -q tests            # tests use mocked upstream APIs
COLLECTORS=0 AUTH_MODE=none DATA_DIR=../data STATIC_DIR=../frontend uvicorn app.main:app --reload
```

`scripts/` contains the generators for the bundled map data (basemap style, country shapes, submarine cables).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Licence

Emberwatch is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE.md): free for personal and other non-commercial use, no commercial use. Third-party components and data keep their own licences, see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Required Notice: Copyright (c) 2026 SaturdayNetLab (https://github.com/SaturdayNetLab)
