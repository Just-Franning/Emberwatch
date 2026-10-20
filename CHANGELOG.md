# Changelog

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
- CI with tests and multi-arch image on GitHub Container Registry

### Changed
- Data directory file renamed to `emberwatch.sqlite`; an existing `threatmap.sqlite` in the same volume is taken over automatically
- Watchlist hits became alerts; old hits are migrated
- `FORWARDED_ALLOW_IPS` is configurable (default `*`)

### Upgrading from ThreatMap 2.x
Mount the existing data volume at `/data`. If the old volume is called `threatmap-data`, declare it in the stack as an external volume
(`volumes: emberwatch-data: {name: threatmap-data, external: true}`) or copy its contents into the new volume.
