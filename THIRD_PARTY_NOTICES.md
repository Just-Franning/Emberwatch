# Third-party notices

Emberwatch itself is licensed under the PolyForm Noncommercial License 1.0.0 (see [LICENSE.md](LICENSE.md)).
The following components and data are included in this repository or the container image and keep their own licences.

## Bundled software

| Component | Version | Licence | Licence text |
|---|---|---|---|
| MapLibre GL JS | 5.24.0 | BSD-3-Clause | `frontend/vendor/maplibre-LICENSE.txt` |
| Chart.js | 4.5.1 | MIT | `frontend/vendor/chartjs-LICENSE.md` |
| Roboto Mono (font) | variable | SIL Open Font License 1.1 | `frontend/vendor/fonts/RobotoMono-OFL-LICENSE.txt` |
| Archivo (font) | variable | SIL Open Font License 1.1 | `frontend/vendor/fonts/Archivo-OFL-LICENSE.txt` |
| OpenFreeMap "dark" style (modified, red accents) | – | code BSD-3-Clause / MIT, design CC BY 4.0 | `frontend/data/basemap-style.LICENSE.md` |

Python dependencies (installed into the image, not part of this repository) are listed in `backend/requirements.txt` and keep their respective licences.

## Bundled data

| Data | Files | Source and licence |
|---|---|---|
| Country shapes and centroids | `frontend/data/countries.geojson`, `frontend/data/centroids.json` | Natural Earth, public domain |
| Submarine cables and landing points (snapshot June 2021) | `frontend/data/cables.geojson`, `frontend/data/landing-points.geojson` | TeleGeography, Submarine Cable Map, CC BY-NC-SA 3.0. These derived files are distributed under the same licence. Country codes of the landing points derived with Natural Earth (public domain). |
| City coordinates for the locations of cloud regions | `frontend/data/places.json` | Natural Earth, Populated Places, public domain (`scripts/build_places.py`) |

## Data loaded at runtime

These data are not part of the repository; each installation fetches them directly. Their terms apply to your use:

- Cloudflare Radar – CC BY-NC 4.0
- abuse.ch Feodo Tracker and ThreatFox – abuse.ch terms of use
- Ransomware.live – "Source: Ransomware.live", no redistribution of raw data
- CISA Known Exploited Vulnerabilities – public
- ENISA European Vulnerability Database (EUVD), exploited vulnerabilities – reproduction authorised provided the source is acknowledged
- Metasploit Framework module metadata (`db/modules_metadata_base.json`, Rapid7) – BSD-3-Clause; only the metadata is downloaded, no exploit code
- Nuclei templates index (`cves.json`, ProjectDiscovery) – MIT; only the index is downloaded
- MITRE ATT&CK Enterprise (STIX bundle) – © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. (The notice with the year of the loaded release is shown wherever ATT&CK data appear.)
- abuse.ch URLhaus – abuse.ch terms of use
- OONI measurement aggregates – CC BY-NC-SA 4.0, © OONI
- GDELT Project DOC 2.0 API (headlines, optional) – free use with citation of and a link to the GDELT Project
- Status pages of AWS, Microsoft Azure, Google Cloud and Cloudflare – public incident information of the providers
- FIRST EPSS – FIRST terms
- NVD – This product uses data from the NVD API but is not endorsed or certified by the NVD.
- Shodan InternetDB – free for non-commercial use
- Spamhaus DROP – free use with attribution to The Spamhaus Project
- Tor Project exit list – public
- AbuseIPDB – AbuseIPDB terms (optional)
- RIPE NCC RIS Live and RIPEstat – RIPE NCC terms
- SSLMate Cert Spotter – SSLMate terms
- DB-IP Lite (IP to City, IP to ASN) – CC BY 4.0, "IP Geolocation by DB-IP"
- MISP Galaxy, cluster "threat-actor" (threat actors, aliases, attributions) – CC0 1.0 / BSD 2-Clause, https://github.com/MISP/misp-galaxy
- Security reports of the world view (NCSC UK, BSI, CERT-EU, CISA, The Record, BleepingComputer, SecurityWeek, Krebs on Security, Golem.de, heise Security and feeds you add) – headlines, teasers and preview images as published in the feeds; the rights stay with the publishers, every report links to its original
- Map tiles: OpenFreeMap, © OpenMapTiles, © OpenStreetMap contributors
- Google Gemini (optional) – Google terms
