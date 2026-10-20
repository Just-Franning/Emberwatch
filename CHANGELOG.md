# Changelog

## 3.0.1 – 2026-10-20

### Fixed
- Active scan: feedback and errors now appear directly at the scan buttons instead of at the top of the asset view, which was often scrolled out of sight
- Active scan: the view keeps polling until a manually started scan shows up and keeps its scroll position while updating
- Active scan: an asset without scannable addresses (domain does not resolve, only private or reserved addresses) is refused with a clear message instead of an empty run
- Active scan: "Enable" without the authorisation checkbox explains what is missing instead of being a disabled button
- Scan status is translated; a run without open ports says so explicitly
- Errors in background tasks are logged instead of being lost

### Added
- Note that a scan from the same network or server shows the inside view without upstream firewalls

## 3.0.0 – 2026-10-20

First public release under the name Emberwatch (previously a private project called ThreatMap 2.x).

### Added
- German and English interface; server texts (patterns, alerts, errors, notifications) in both languages
- Optional built-in login (`AUTH_MODE=password`, generated password on first start), same-origin checks for all API requests
- Assets window: attack surface via Shodan InternetDB, optional active TCP scan with consent, Certificate Transparency monitoring, lookalike domain detection, live BGP monitoring via RIPE RIS Live, IP reputation (Spamhaus DROP, Tor, AbuseIPDB)
- Product watch for vendors/products against CISA KEV and NVD, directly from the search
- Log analysis (upload, also .gz) and optional syslog receiver
- Unified alert feed with Matrix delivery
- Search for domains, ThreatFox IOCs, KEV vendors and recent NVD CVEs
- Movable and resizable windows with adjustable opacity, settings panel, start animation
- Layer switches in the legend, measured header height
- CI with tests, a smoke test of the hardened container and a multi-arch image on GitHub Container Registry
- Image tags: `latest` and `3`/`3.0`/`3.0.0` for releases, `edge` for the `main` branch; update instructions in the README

### Changed
- Data directory file renamed to `emberwatch.sqlite`; an existing `threatmap.sqlite` in the same volume is taken over automatically
- Watchlist hits became alerts; old hits are migrated
- `FORWARDED_ALLOW_IPS` is configurable (default `*`)
- `compose.yml` uses the prebuilt image by default; build from source with `EMBERWATCH_IMAGE=emberwatch:local`

### Upgrading from ThreatMap 2.x
Mount the existing data volume at `/data`. If the old volume is called `threatmap-data`, declare it in the stack as an external volume
(`volumes: emberwatch-data: {name: threatmap-data, external: true}`) or copy its contents into the new volume.
