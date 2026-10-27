# Changelog

## 4.0.0 – 2026-10-27

Emberwatch gets accounts with roles and a second factor, a third map view for people searches, the company behind an IP address and the Telegram channels of hacktivist groups; the globe turns while nobody uses the map. This release also contains the work of 3.3, which was not released on its own: reports checked against measurements, submarine cables, internet blocking, cloud platform incidents, MITRE ATT&CK, ENISA and public exploit code.

### Upgrade from 3.x
- Sign-in now uses accounts. On the first start the administrator `admin` (another name with `AUTH_USER`) is created with the password you used so far: `AUTH_PASSWORD`, or the generated one of 3.x (`/data/auth.json`). At the first sign-in the second factor is set up with an authenticator app (TOTP); keep the ten recovery codes it shows.
- `AUTH_PASSWORD` only sets the password of this first account; later changes of the variable have no effect. Passwords are changed under *My account*; a lost password or second factor is reset with `docker exec -it emberwatch emberwatch-admin reset-password <name>` or `reset-2fa <name>`.
- Back up the new key file `/data/session.key` together with the database: it encrypts the secrets of the second factor.
- Every session of 3.x ends; everybody signs in again.
- New features are switched on by default: people search (`OSINT_ENABLED`), Telegram channels (`TELEGRAM_ENABLED`, no channels until an administrator adds them) and the geocoding of company addresses via OpenStreetMap Nominatim (`NOMINATIM_URL=off` switches it off).
- With `AUTH_MODE=none` (sign-in at the reverse proxy) every visitor counts as administrator, as before.
- The repository moved to `Just-Franning/Emberwatch`, the image to `ghcr.io/just-franning/emberwatch` (the owner SaturdayNetLab no longer exists, so `ghcr.io/saturdaynetlab/emberwatch` gets no new versions). Change `image:` in your stack or `EMBERWATCH_IMAGE`.

### Added
**Accounts and roles**
- Any number of accounts with the roles *administrator* and *read-only*. Read-only accounts see the cyber and world view, the analysis and my network, but change nothing and start no lookups, tools, scans or Gemini analyses; the people search and the account administration are for administrators only. The server checks the role of every request; the interface hides what a role cannot use
- Sign-in in two steps: user name and password, then the code of an authenticator app (TOTP, RFC 6238, set up with a QR code) or one of ten one-time recovery codes. New accounts get a temporary password that is replaced at the first sign-in
- *My account* (menu at the user name in the header): change the password, set up a new device, create new recovery codes, see and end your sessions
- *Users* (administrators): add accounts, change the role, disable, reset the password or the second factor, end sessions, delete; the last active administrator cannot be removed, disabled or demoted
- *Audit log* (administrators): sign-ins and failed attempts, account changes, people searches, company lookups and Telegram channels, kept for `AUDIT_RETENTION_DAYS` (365)
- `emberwatch-admin` in the container for lost access: `users`, `reset-password`, `reset-2fa`, `create-admin`, `enable`, `disable`

**Who owns this IP?**
- Cyber view, side tab *Company* (also from the search, the IP object page and the command palette): the company that uses a public IP address – holder of the network according to the registry (RDAP), AS, reverse DNS, the certificate on port 443, the domains that point to the address (forward check), imprint and schema.org data of the website, contact (phone, e-mail, website, people, register, VAT ID) and the abuse contact. Each step is listed as evidence, with a confidence (high, medium, low) and notes such as possible shared hosting; the company seat (OpenStreetMap Nominatim) and the location of the address appear on the map
- Without *Contact the address and website* only the registry and DNS are used. Results are kept for 7 days; read-only accounts see stored results

**People search (administrators)**
- A third map view in black and white: a user name, an e-mail address or a name (turned into common user name variants) is checked on several hundred platforms from the site lists of Sherlock and WhatsMyName, loaded at runtime; adult, dating, health and political sites are excluded. Each hit shows whether an account exists (found or unsure), the country of the platform operator and the public profile details (name, place and its country, company, links, links verified by the platform, e-mail) from the platform APIs of GitHub, Keybase, Mastodon, Hacker News, Docker Hub, Codeberg, dev.to, Lichess, Chess.com and Reddit or from the profile page; optionally Gravatar (`GRAVATAR_API_KEY`)
- Searches belong to a case with a name and a purpose; cases are exported as JSON and deleted automatically `OSINT_RETENTION_DAYS` (90) after their last change; every search is in the audit log
- Link graph (window): what connects the accounts – details several profiles state, links between accounts (mutual, verified by the platform); your own nodes (person, organisation, phone, note, …) and lines (confirmed or hint), drag, zoom, keyboard. The side panel lists the same links in words
- Map: countries of the platform operators and countries the profiles state

**Telegram channels in the world view**
- Window *Telegram*: public channels of hacktivist groups that administrators add, read from the web preview `t.me/s/<channel>` without an account. Countries, kinds of attack and targets of a post are recognised automatically (domains and addresses shown defanged), proof links (check-host.net) are listed, and a claimed DDoS attack on a country is compared with Cloudflare Radar as for the reports. Filters for channel, period, country and text; translation with Gemini on request (administrators), stored with the post
- `TELEGRAM_INTERVAL_MIN` (15), `TELEGRAM_RETENTION_DAYS` (90)

**Map**
- The globe turns slowly while nobody uses the map; any input stops it, it turns again after 30 seconds (*Settings → Globe*). The projection (globe or flat) is remembered per browser; the globe is the default

**Reports checked against measurements and more sources (developed as 3.3)**
- Weltlage: every report is compared with Emberwatch's own data – a DDoS with the Cloudflare Radar share of the target country (against the 14 days before), ransomware with the group's leak site posts, cable damage and shutdowns with internet outages (also ongoing ones), blocking with a rise in OONI measurements against the 4 weeks before, CVEs with CISA KEV and ENISA, malware with active C2 servers. The result (supported, not supported, unclear) is shown in the report with the numbers behind it, as a tag in the list and as a filter; Gemini receives it as context
- Weltlage: submarine cables named in reports are recognised by their TeleGeography name, highlighted on the map and listed in the report; new kinds "submarine cable" and "internet blocking"
- Weltlage: layer and tab "Internet blocking" – OONI measurements per country (confirmed blocking, anomalous websites and messengers, compared with the period before) and shutdowns Cloudflare Radar attributes to a government; links to OONI Explorer and IODA
- Weltlage: the worldwide press via GDELT as an optional, unverified source – shown only when chosen, kept at most 14 days and 8,000 headlines, never grouped with the curated reports, no alerts; a curated feed that brings the same article replaces the GDELT entry
- New feeds: CERT-EU security advisories, CISA cybersecurity advisories, heise Security
- Cyberlage: layer "Cloud incidents" with the active incidents of AWS, Azure, Google Cloud and Cloudflare at the documented location of the affected region; analysis view "Platform incidents"; the platforms you use (My network → Products) raise an alert for each new incident (Cloudflare incidents without customer impact excluded)
- MITRE ATT&CK: techniques by tactic and software on actor pages, the ATT&CK entry on malware pages (Enterprise bundle, loaded only when it changed)
- ENISA EUVD: vulnerabilities ENISA lists as exploited, on CVE pages, in reports and in the vulnerability view, which can also list those not in CISA KEV
- Public exploit code: Metasploit modules and Nuclei templates per CVE (metadata only, no exploit code) on CVE pages, in reports and in the vulnerability view, with a filter
- URLhaus: malware URLs under your domains or in your networks raise alerts (one alert per asset for the new indicators of a run)
- `SOURCES_DISABLE` switches optional sources off: `ooni`, `gdelt`, `attack`, `euvd`, `exploits`, `urlhaus`, `cloud_status`
- Status panel: the new sources, the loaded ATT&CK release and the optional sources that are off

### Security
- Pages of third parties (imprints, profiles, Telegram previews) are read through a guarded client: every connection goes to a checked public address (no DNS rebinding), each redirect is checked, size and time are limited, credentials are not passed on to another host; start page and imprint are read only where robots.txt allows it
- Passwords are hashed with scrypt; the TOTP secret is stored encrypted (AES-GCM, key derived from `session.key`), recovery codes only as keyed hashes; a code is accepted once (no replay). Sessions are random tokens stored as hashes on the server; changing the password or the device ends the other sessions, a reset or disabling ends all of them
- If `session.key` is lost or replaced, the sign-in fails closed: a second factor that cannot be decrypted is never replaced with the password alone; an administrator resets it with `emberwatch-admin reset-2fa <name>` (audit log: *2FA unreadable*)
- Failed sign-ins are limited per client, per account and overall; each failed attempt takes the same time whether the name exists or not

### Changed
- Keys `1` to `5` switch the areas (*People* for administrators); *Sign out* moved from the settings to the account menu
- The credits line starts with the map attribution; hovering or focusing it shows every source
- Vulnerability view: choice of catalogue (CISA KEV, or ENISA without KEV), ENISA and exploit tags, the vendor list follows the selection

### Fixed
- Submarine cable data: 125 landing points carried the code of a territory instead of their country (United Kingdom as South Georgia, Denmark as Greenland, Finland as Åland), so country cards and outage findings missed their cables
- Filter rows: checkboxes no longer squeeze their label into several lines
- Small screens: a Weltlage tab opens the collapsed side panel (as in the Cyberlage); the chips of the mode band no longer wrap
- Map style errors outside the basemap are logged in the browser console instead of being swallowed

## 3.2.1 – 2026-10-22

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
