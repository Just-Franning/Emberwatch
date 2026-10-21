# Changelog

## 3.2.1 – 2026-10-21

Fixes from an independent review of 3.2.0.

### Security
- Preview images: address literals (also `0x7f.1`, `2130706433`), internal names (`router.lan`, `nas.fritz.box`), ports other than 443 and host names that resolve to private addresses are dropped, because the browser loads the images from inside your network; images stored by 3.2.0 are checked once on the next run

### Fixed
- Own products in reports: vendors only count as whole words ("HP" no longer matches "https" or "PHP", "SAP" not "Sapphire"); a product name watched for several vendors ("Firewall") matches each of them; no extra vendor mention when one of its products matched
- Weltlage with a home region of more than 13 countries: the focus and the key figure no longer fail with an error or leave out countries
- A feed that could not be parsed is fetched in full again on the next run (its ETag was stored before parsing, so the error was hidden behind a 304)
- The Weltlage period no longer jumps back to the C2 period of the Cyberlage when a report is opened or closed; a period carries over only when it was newly chosen in the Cyberlage
- "Load more" in the reports list ignores answers for a filter that changed meanwhile
- The Weltlage legend no longer stays in the Cyberlage after a historical timeline day; the layer switches of the Weltlage follow restored checkbox states
- Reports published late (new source, delayed feed) are grouped with reports on the same event from days before
- Ids beyond 64-bit integers give a bad request instead of a server error
- Feed errors in the source list are shown in the interface language instead of raw error text
- The Gemini briefing and the actor page group up to 90 days of reports off the event loop
- Long entries in the Analysis navigation are no longer cut off
- Outage findings: the event and the sentence about landing submarine cables are separated by a full stop

### Changed
- Recognition texts and the Gemini prompt say "headline and feed text": recognition reads up to 1,500 characters of the feed text, more than the teaser that is shown
- README screenshots use documentation IP ranges

## 3.2.0 – 2026-10-21

The map has two views now: the **Cyberlage** (attack data, red) and the new **Weltlage** (security reports in their geopolitical context, indigo). The map view is tidier: one side panel, layer chips above the map, four key figures below it.

### Added
- Weltlage: reports of government CERTs and specialist media (NCSC UK, BSI, The Record, BleepingComputer, SecurityWeek, Krebs on Security, Golem.de; more via `NEWS_FEEDS`) with headline, teaser, preview image and a link to the original; reports on the same event are grouped
- Automatic recognition from headline and teaser: countries and the named origin, threat actors (MISP Galaxy, loaded weekly), malware known from the C2 data, CVEs, kind of incident; attributions are labelled as statements of the sources
- Weltlage map with country pairs and named countries; filters for corroborated events, law enforcement & sanctions, sources, focus country or home region, period; tabs for reports, actors, country pairs and a Gemini briefing with the status of every source
- "Report in context": classification, the same event in other sources, KEV/EPSS of its CVEs, active C2 servers of its malware, Cloudflare data for the country pair, what concerns your products, CVEs and domains; Gemini assessment of a report with follow-up questions
- Alerts for reports that name your domains (high) or watched products and their CVEs (medium); a plain product word ("Firewall") only counts together with its vendor, a vendor watched without a product is shown on the report but not alerted
- Threat actor object pages (aliases, attributed country, sponsor, confidence, targets, references, reports); search and palette find actors and reports
- "Today" in the Cyberlage: own alerts of the last 48 hours, detected patterns and widely reported events
- Settings `NEWS_ENABLED`, `NEWS_INTERVAL_MIN`, `NEWS_IMAGES`, `NEWS_DISABLE`, `NEWS_FEEDS`, `NEWS_RETENTION_DAYS`

### Changed
- Four areas: Cyberlage, Weltlage, Analyse, Mein Netz (shortcuts `1`–`4`); the selected country and the period carry over between the two map views
- One side panel with tabs (Today, Rankings, Patterns, Gemini) instead of two; `]` toggles it, `[` is gone
- Layer switches as chips above the map; shading, timeline, map tool bar and globe in the same bar; timeline and tool bar open on demand
- Four key figures below the map (your country as attack target, active C2, ransomware in your region, new KEV that concern you) with the map legend above them
- Gemini system prompt: attributions in reports are statements of the sources; Cloudflare origins are still never attributed to states

### Security
- Feeds are parsed with defusedxml (no entity expansion, no external references), size-limited, with conditional requests; redirects must stay on HTTPS and public addresses
- Preview images are only fetched from the source's own domain and public addresses; the browser loads them without a referrer; `NEWS_IMAGES=0` removes `https:` from the image policy
- HTML from feeds and article pages is searched with bounded patterns (no quadratic run time on hostile input)

## 3.1.1 – 2026-10-21

### Fixed
- After an update, browsers could keep the scripts of the previous version from their cache and show an empty interface
  ("null is not an object … this.form"). Scripts, styles and pages are now revalidated on every load. If you updated to
  3.1.0 and see this error: clear the browser cache for Emberwatch once or reload with Ctrl+Shift+R.
- The status panel shows the note of a data source in the text (e.g. "no matching assets" instead of only "0 entries");
  before, it was only a tooltip and not visible on touch devices.

## 3.1.0 – 2026-10-21

The interface is split into three areas: **Situation** (world map), **Analysis** (objects and tools) and **My network**. The map stays lean; depth moved to its own pages.

### Added
- Analysis area with object pages for IPs, networks, AS numbers, domains, URLs, file hashes, CVEs, countries, malware families, ransomware groups and vendors: risk with reasons, local data, relation to your own assets and IPs, related objects, own alerts, tool history, pinning and recently opened objects
- Tool box with input detection (IP, network, AS, domain, URL, e-mail address, hash, CVE, mail header) and tools grouped by question; every tool is labelled passive, active or intrusive, with "target sees you" and the third party that receives the input
- New tools: path quality (traceroute with several probes per hop), Globalping, BGP/RPKI (RIPEstat), passive DNS (mnemonic), certificates (Certificate Transparency for any domain), GreyNoise, file hashes (MalwareBazaar), lookalike domains for any domain, TLS in depth (versions, weak ciphers), HTTP security (redirect chain, headers, cookies, disclosure, CORS), SSH audit (algorithms, Terrapin, vulnerable OpenSSH versions), DNS with DNSSEC/CAA and an optional zone transfer test (needs confirmation), mail security (SPF incl. lookup count, DMARC with organisational fallback, DKIM, MTA-STS, TLS-RPT, DNSSEC, optional STARTTLS), mail header analysis with the delivery path on the map, CyberChef link
- Recipes: server check, domain check, suspicious IP, suspicious mail
- Unified result format for all tools, stored for 90 days (history in the analysis area, JSON download)
- Deep views: exploited vulnerabilities with filters (EPSS, ransomware, "mine"), infrastructure events, C2 servers, ransomware victims
- Gemini assessment per object with follow-up questions; own assets are only sent as a flag, leak site victim names never
- My IP: tracking of the home connection and of this server's egress address with history, checks (Spamhaus DROP, Tor, C2/IOC data, AbuseIPDB, InternetDB ports) and alerts; home IP via visits (confirmation or automatically within the provider's network), DynDNS host name, or a reporter with a token (`/api/myip/report`, dyndns2 `/nic/update`)
- My network overview: own IPs, alerts, assets by risk, products, operation
- Situation view: map tool bar (ping, traceroute, IP info; more: path quality, Globalping, mail hops), "analyse in depth" from the country card, links from rankings to the deep views
- Command palette (`Ctrl+K`), area shortcuts `1` `2` `3`, alert counter in the header
- Settings `GREYNOISE_API_KEY`, `GLOBALPING_TOKEN`, `CYBERCHEF_URL`
- Image tags for feature branches (`feature-<name>`) to test changes before a release

### Changed
- Assets, products, alerts and logs moved from the floating window into *My network*; the keys `A` (assets) and the tools window were replaced by the areas and the map tool bar
- Network tools stream newline-delimited JSON instead of server-sent events (`/api/tb/*` replaces `/api/tools/*`)
- CVE links open the CVE's object page (with KEV, EPSS, NVD and your exposure) instead of the NVD website
- Private addresses and internal names are never sent to third parties (GreyNoise, passive DNS, RDAP, RIPEstat, Certificate Transparency, public DNS resolvers, Gemini); the IP info no longer queries RIPEstat for private addresses
- Request bodies are limited (20 MB with a session, 64 KB without one)
- Gemini analyses are kept as long as alerts (`ALERT_RETENTION_DAYS`, at most 2,000)

### Fixed
- Error messages with an upstream HTTP status (Gemini, RDAP and others) no longer turn into an internal error
- Lists in the interface no longer show the word "null" where an optional block is missing
- The login page loads all its scripts without a session
- Counts in texts use the singular where needed ("1 hop" instead of "1 hops")

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
