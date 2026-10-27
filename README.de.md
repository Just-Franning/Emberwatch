# Emberwatch

Selbst gehostetes Cyber-Lagebild auf einer Weltkarte: Angriffe, C2-Server, Ransomware, ausgenutzte Schwachstellen, Internet-Infrastruktur und Cloud-Störungen aus öffentlichen Quellen, Sicherheitsmeldungen von Behörden und Fachmedien im geopolitischen Zusammenhang – abgeglichen mit Messdaten –, dazu Überwachung eigener Assets, Produkte und Logs.

[English](README.md) · **Deutsch**

![Emberwatch: Cyberlage](docs/screenshot.webp)

*Die Screenshots zeigen synthetische Demodaten.*

## Funktionen

Emberwatch hat vier Bereiche: **Cyberlage** (die Weltkarte mit Angriffsdaten, rot), **Weltlage** (Sicherheitsmeldungen auf derselben Karte, indigo), **Analyse** (Objekte und Werkzeuge) und **Mein Netz** (eigene IPs, Assets, Produkte und Logs). `Strg+K` öffnet eine Befehlspalette für alles. Das gewählte Land und der Zeitraum gelten in beiden Kartenansichten.

**Cyberlage – globales Lagebild**
- Weltkarte mit L7-Angriffsflüssen (Ursprung → Ziel), Länderflächen nach Angriffsanteil, gemeldeten C2-Servern, Ransomware-Opfern je Land, Internet-Ausfällen, BGP-Hijacks/Route-Leaks, Traffic-Anomalien, Seekabeln und aktiven Störungen bei AWS, Azure, Google Cloud und Cloudflare an der betroffenen Region; die Ebenen schalten die Chips über der Karte
- *Heute wichtig*: das Wenige, das jetzt zählt – deine Alarme der letzten 48 Stunden, erkannte Muster und Ereignisse, über die viele Quellen berichten; vier Kennzahlen unter der Karte (dein Land als Angriffsziel, aktive C2, Ransomware in deiner Region, neue KEV, die dich betreffen)
- Ranglisten: Ziel- und Ursprungsländer (24 h gegenüber 7 Tagen), DDoS-Vektoren, L7-Angriffskategorien, C2-Familien und Hosting-Netze, Ransomware-Gruppen und Branchen, neu ausgenutzte Schwachstellen (CISA KEV mit FIRST EPSS)
- Regelbasierte Mustererkennung (steigende Länder und Vektoren, Spikes, neue C2-Familien, KEV-Häufungen, kritische Ausfälle, Korrelationen), deterministisch und nachvollziehbar
- Zeitachse mit Tageshistorie (bis 90 Tage) bei Bedarf, kompakte Länderkarte mit Sprung zur vollständigen Länderanalyse
- Karten-Werkzeugleiste bei Bedarf: Ping, Traceroute und IP-Info mit Live-Anzeige auf der Karte; unter *Mehr*: Pfad-Qualität (Traceroute mit mehreren Paketen pro Hop), Globalping (Messungen von Messpunkten weltweit) und Mail-Hops (der Zustellweg eines Mail-Headers auf der Karte)
- Optionale Gemini-Berichte (global, Land, Heimatregion, freie Fragen mit Rückfragen), exportierbar als Markdown oder PDF. Das Modell erhält nur aggregierte Kennzahlen.

**Weltlage – Sicherheitsmeldungen im Kontext**
- Meldungen von Behörden-CERTs und Fachmedien (RSS/Atom) mit Überschrift, Anreißer, Vorschaubild und Link zum Original; Meldungen zum selben Ereignis werden zusammengefasst. Optional die Presse weltweit über GDELT: Überschriften von Nachrichtenseiten aus aller Welt, als ungeprüft gekennzeichnet, nur sichtbar, wenn sie als Quelle gewählt ist, getrennt von den geprüften Quellen und ohne Alarme
- Automatisch aus Überschrift und Feed-Text (bis 1.500 Zeichen) erkannt: Länder, die genannte Herkunft, Akteure (MISP Galaxy), Schadsoftware, CVEs, genannte Seekabel und die Art des Vorfalls (Ransomware, DDoS, Spionage, Sabotage, Datenabfluss, Seekabel, Internet-Sperre, Strafverfolgung, Sanktionen, …). Zuschreibungen erscheinen als Aussagen der Quellen und sind als automatisch erkannt gekennzeichnet
- **Abgleich mit Messdaten:** Jede Meldung wird mit den eigenen Daten verglichen – ein DDoS mit dem Cloudflare-Anteil des Ziellands (gegenüber den 14 Tagen davor), Ransomware mit den Veröffentlichungen der Gruppe auf ihrer Leak-Seite, Kabelschäden und Abschaltungen mit Internet-Ausfällen, Sperren mit einem Anstieg in den OONI-Messungen gegenüber den 4 Wochen davor, CVEs mit CISA KEV und ENISA, Schadsoftware mit aktiven C2-Servern. Das Ergebnis (gestützt, nicht gestützt, unklar) steht mit den Zahlen dahinter in der Meldung; ein Filter zeigt nur gestützte Meldungen. Messdaten zeigen Verkehr, Veröffentlichungen und Ausfälle, nicht, wer dahinter steckt
- Karte: Länderpaare (Herkunft → Ziel laut Meldungen), genannte Länder, genannte Seekabel und Internet-Sperren (bestätigte Sperren laut OONI, Abschaltungen, die Cloudflare einer Regierung zuschreibt); Filter für belegte Vorfälle (eine Behörde oder mindestens zwei Quellen), Strafverfolgung & Sanktionen, Quellen, Fokusland oder Heimatregion, Zeitraum
- Reiter *Sperren*: von Regierungen angeordnete Abschaltungen und OONI-Messungen je Land (bestätigte Sperren, auffällige Websites und Messenger, verglichen mit dem Zeitraum davor), mit Links zu OONI Explorer und IODA
- *Meldung im Kontext*: Einordnung, dasselbe Ereignis in anderen Quellen, der Abgleich mit Messdaten, die genannten Seekabel, was die lokalen Daten dazu sagen (KEV, ENISA, EPSS und öffentlicher Exploit-Code der CVEs, aktive C2-Server der Schadsoftware, Cloudflare-Daten zum Länderpaar) und ob sie deine Produkte, CVEs oder Domains betrifft – solche Meldungen lösen auch Alarme aus
- Akteure mit Decknamen, zugeordnetem Land und Auftraggeber, Konfidenz, Quellen und den Meldungen, die sie nennen; optionaler Gemini-Lagebrief für den Zeitraum und Gemini-Einordnung einer einzelnen Meldung

**Analyse – Objekte und Werkzeuge**
- Objektseiten für IPs, Netze, AS-Nummern, Domains, URLs, Datei-Hashes, CVEs, Länder, Malware-Familien, Ransomware-Gruppen, Akteure und Hersteller: Risikobewertung mit Begründung, alles, was die lokalen Daten wissen, Bezug zu den eigenen Assets, Zusammenhänge, deine Alarme dazu, frühere Werkzeug-Läufe und eine optionale Gemini-Bewertung. Akteure und Schadsoftware zeigen ihre Techniken nach Taktik und die genutzte Software laut MITRE ATT&CK; CVEs zeigen, ob ENISA sie als ausgenutzt führt und ob es öffentlichen Exploit-Code (Metasploit-Module) oder Prüf-Templates (Nuclei) gibt
- Werkzeugkasten: beliebige Eingabe einfügen (IP, Netz, AS, Domain, URL, E-Mail-Adresse, Hash, CVE oder Mail-Header); Emberwatch erkennt den Typ und zeigt, welche Werkzeuge passen, gruppiert nach Fragestellung:
  - *Erreichbarkeit:* Ping, Traceroute, Pfad-Qualität, Globalping
  - *Herkunft:* IP-Info, RDAP/Whois, BGP/RPKI (RIPEstat), Passive DNS (mnemonic), Zertifikate (Certificate Transparency)
  - *Bedrohung:* lokale Bedrohungsdaten (C2, ThreatFox, Spamhaus DROP, Tor), GreyNoise, Datei-Hashes (MalwareBazaar), registrierte ähnliche Domains
  - *Absicherung:* Portcheck, TLS (Versionen, schwache Cipher, Zertifikat), HTTP-Sicherheit (Weiterleitungen, Header, Cookies, preisgegebene Versionen), SSH-Audit (Verfahren, Terrapin, bekannt verwundbare OpenSSH-Versionen), DNS/DNSSEC/CAA mit optionalem Zonentransfer-Test, Mail-Sicherheit (MX, SPF inkl. Zahl der Lookups, DMARC, DKIM, MTA-STS, TLS-RPT, DNSSEC, optional STARTTLS)
  - *E-Mail:* Header-Analyse (Absender- und Authentifizierungsprüfungen, Zustellweg, Links, Anhänge)
  - *Umwandeln:* CyberChef (im Browser)
- Jedes Werkzeug ist gekennzeichnet: **passiv** (nur Datenquellen), **aktiv** (harmloser Kontakt mit dem Ziel) oder **Eingriff** (braucht pro Lauf deine Bestätigung); dazu *Ziel sieht dich* und welcher *Dritte* die Eingabe erhält
- Rezepte führen mehrere Werkzeuge in einem Durchgang aus: Server-Check, Domain-Check, verdächtige IP, verdächtige Mail
- Tiefenansichten: ausgenutzte Schwachstellen (CISA KEV, oder laut ENISA ausgenutzt und nicht in KEV; Filter, EPSS, öffentlicher Exploit-Code, markiert, was dich betrifft), Infrastruktur-Ereignisse, C2-Server (mit Blocklisten-Export), Ransomware-Opfer, Plattform-Störungen (AWS, Azure, Google Cloud, Cloudflare, mit Regionen); Verlauf aller Werkzeug-Läufe (90 Tage)

**Mein Netz**
- Übersicht: deine IPs, Alarme der letzten 7 Tage, Assets nach Risiko, Produkte, Betrieb
- **Meine IP:** verfolgt den eigenen Anschluss und die ausgehende Adresse dieses Servers, protokolliert jeden Wechsel und prüft beide gegen Spamhaus DROP, Tor, die C2-/IOC-Daten, AbuseIPDB und Shodan InternetDB (offene Ports). Die Heim-IP kommt aus deinen Aufrufen (mit Bestätigung, optional automatisch im Netz deines Anbieters), einem DynDNS-Hostnamen oder einem Melder: `curl` mit Token oder jeder dyndns2-Client (Router, ddclient)
- Assets (IPs, Netze, AS-Nummern, Domains): Abgleich mit C2-Servern, ThreatFox-IOCs, URLhaus-Schadsoftware-URLs, BGP-Hijacks/-Leaks, Ausfällen, Leak-Sites, Spamhaus DROP und AbuseIPDB; passive Angriffsfläche über Shodan InternetDB; optionaler aktiver TCP-Scan nach ausdrücklicher Bestätigung; Überwachung von Zertifikats-Transparenz und ähnlichen Domains; Live-BGP-Überwachung über RIPE RIS Live
- Produktbeobachtung für Hersteller/Produkte gegen CISA KEV und NVD; die Cloud-Plattformen, die du nutzt (AWS, Azure, Google Cloud, Cloudflare), melden jede neue Störung ihrer Statusseite als Alarm
- Log-Analyse (Upload, auch .gz) und optionaler Syslog-Empfang
- Ein Alarm-Feed mit optionaler Matrix-Benachrichtigung und Tagesbericht

**Oberfläche:** Deutsch und Englisch, eine Seitenleiste auf der Karte (verschiebbar und skalierbar), Tastenkürzel, Start-Animation, optionale Anmeldung.

![Weltlage: eine Meldung im Kontext, abgeglichen mit Messdaten](docs/weltlage.webp)

![Objektseite eines Landes](docs/object.webp)

![Werkzeugkasten](docs/toolbox.webp)

## Voraussetzungen

- Docker mit Docker Compose oder Portainer
- Ein Volume für `/data` (SQLite-Datenbank, Anmeldedateien, DB-IP-Geodatenbanken). Die Compose-Dateien begrenzen den Speicher auf 1 GB.
- Ausgehendes HTTPS zu den Datenquellen (siehe [Datenquellen](#datenquellen-und-lizenzen)), ausgehendes ICMP/UDP für Ping und Traceroute
- Kostenlose API-Keys für die Kernquellen: Cloudflare (Radar) und abuse.ch. Alles andere ist optional.

## Installation

### Variante A: Portainer mit fertigem Image

1. *Stacks → Add stack → Web editor*, [`portainer-stack.yml`](portainer-stack.yml) einfügen.
2. Unter *Environment variables* mindestens setzen:
   - `PROXY_NETWORK` – das Docker-Netzwerk deines Reverse Proxys (Traefik, Nginx Proxy Manager, Pangolin/Newt, …)
   - `CF_API_TOKEN`, `ABUSECH_AUTH_KEY`
   - optional `LANGUAGE=de`, `AUTH_PASSWORD` und weitere Keys (alle Variablen: [`.env.example`](.env.example))
3. Deployen und im Reverse Proxy auf `http://emberwatch:8000` weiterleiten.

### Variante B: Docker Compose mit fertigem Image

```bash
git clone https://github.com/SaturdayNetLab/emberwatch.git
cd emberwatch
cp .env.example .env    # Keys eintragen
docker compose pull
docker compose up -d
```

Die Oberfläche ist dann unter `http://127.0.0.1:8000` erreichbar. Für den Zugriff von anderen Rechnern einen Reverse Proxy mit TLS davorsetzen (siehe [Reverse Proxy](#reverse-proxy-und-anmeldung)).

### Variante C: aus dem Quellcode bauen

Mit Docker Compose: in `.env` `EMBERWATCH_IMAGE=emberwatch:local` setzen, dann

```bash
docker compose up -d --build
```

Mit Portainer: im geklonten Repository `git archive -o emberwatch.tar HEAD` ausführen, dann *Images → Build a new image → Upload*, `emberwatch.tar` auswählen, Image-Name `emberwatch:local`. Den Stack wie in Variante A deployen, mit `EMBERWATCH_IMAGE=emberwatch:local`.

### Image-Tags

Das Image `ghcr.io/saturdaynetlab/emberwatch` wird für `linux/amd64` und `linux/arm64` gebaut.

| Tag | Inhalt |
|---|---|
| `latest` | neuestes Release |
| `3`, `3.2` | neuestes Release innerhalb dieser Haupt- bzw. Nebenversion |
| `3.2.0` | genau dieses Release |
| `edge` | aktueller Stand von `main`, Änderungen zwischen den Releases |
| `feature-<name>` | Test-Build eines Feature-Branches vor dem Zusammenführen (instabil) |
| `sha-<commit>` | ein einzelner Build |

## Aktualisieren

Die Daten bleiben im Volume `/data`. Datenbankänderungen werden beim Start automatisch übernommen; vor einer neuen Hauptversion das [Änderungsprotokoll](CHANGELOG.md) lesen.

- **Docker Compose:** `docker compose pull && docker compose up -d`. Vorher `git pull`, wenn du Änderungen an `compose.yml` und `.env.example` übernehmen willst.
- **Portainer:** *Stacks → emberwatch → Editor → Update the stack*, dabei die Option zum erneuten Ziehen des Images aktivieren.
- **Automatisch:** ein Werkzeug wie Watchtower kann neue Images ziehen. Eine Versionslinie (z. B. `3`) festlegen, wenn nur Updates ohne inkompatible Änderungen kommen sollen.
- **Selbst gebaut:** `git pull`, dann neu bauen.

Neue Versionen stehen auf der [Releases-Seite](https://github.com/SaturdayNetLab/emberwatch/releases); auf GitHub benachrichtigt *Watch → Custom → Releases*.

## Erste Schritte

1. **Anmelden.** Mit dem Standard `AUTH_MODE=password` und ohne `AUTH_PASSWORD` wird beim ersten Start ein Zufallspasswort erzeugt:
   ```bash
   docker logs emberwatch 2>&1 | grep "login password"
   docker exec emberwatch cat /data/initial-password.txt
   ```
2. **Auf Daten warten.** Der erste Abruf dauert einige Minuten, die Radar-Historie (standardmäßig 30 Tage) lädt im Hintergrund. *Status* zeigt den Zustand jeder Quelle.
3. **Assets anlegen.** *Mein Netz → Assets*: IPs, Netze, AS-Nummern oder Domains. Aktive Scans sind erst möglich, nachdem du bestätigt hast, dass du das Asset scannen darfst.
4. **Meine IP einrichten.** *Mein Netz → Meine IP*: die Adresse übernehmen, von der du verbunden bist, einen DynDNS-Hostnamen eintragen oder ein Token für einen Melder erzeugen (siehe [Meine IP](#meine-ip)).
5. **Produkte beobachten.** Nach einem Hersteller suchen, z. B. `Sophos`, und *Als Produkt beobachten* wählen, oder unter *Mein Netz → Produkte* anlegen.
6. **Analysieren.** Unter *Analyse* eine IP, Domain, einen Hash, eine CVE oder einen Mail-Header eingeben, oder überall `Strg+K` drücken.
7. **Weltlage lesen.** Die *Weltlage* füllt sich innerhalb einer halben Stunde nach dem Start. Ein Klick auf ein Land setzt den Fokus, ein Klick auf eine Meldung zeigt sie im Kontext.
8. **Benachrichtigungen (optional).** Matrix einrichten, um Alarme und den Tagesbericht zu erhalten.

Tastenkürzel: `Strg+K` Befehlspalette, `1` `2` `3` `4` Bereiche wechseln, `/` Suche, `T` Karten-Werkzeugleiste (in der Cyberlage; sonst Werkzeugkasten), `]` Seitenleiste ein/aus, `Esc` schließen (auch die Meldung in der Weltlage). Die Seitenleiste lässt sich an der Titelleiste verschieben, an der Ecke unten rechts in der Größe ändern und per Doppelklick auf die Titelleiste wieder andocken. Sprache, Fenster-Deckkraft und Start-Animation stehen unter *Einstellungen* (⚙).

### Meine IP

Die Heim-IP kommt auf einem von drei Wegen (kombinierbar):

1. **Beim Aufruf von Emberwatch**: *Meine IP* zeigt die Adresse, von der du verbunden bist, und übernimmt sie auf Wunsch. Optional wird sie künftig automatisch übernommen, wenn du wieder aus demselben Netz (AS) kommst; Mobilfunk oder Hotels werden so ignoriert (nur IPv4: über IPv6 sieht der Browser die eigene, oft wechselnde Adresse des Geräts; Geräte aus dem Heim-/64 gelten als Zuhause). Dafür braucht es einen Reverse Proxy, der `X-Forwarded-For` setzt.
2. **DynDNS-Hostname**: zeigt ein Hostname auf deinen Anschluss, löst Emberwatch ihn alle 10 Minuten auf.
3. **Melder mit Token** (unter *Meine IP* erzeugt, nur einmal angezeigt, gespeichert wird nur der Hash):
   ```bash
   # Cronjob auf einem Gerät zu Hause: es gilt die Adresse, von der die Anfrage kommt
   curl -fsS -X POST -H "Authorization: Bearer <token>" https://emberwatch.example.org/api/myip/report
   ```
   dyndns2-Clients (Router, ddclient, inadyn) nutzen `https://emberwatch.example.org/nic/update?myip=<ipaddr>` mit HTTP-Basic-Auth (Benutzername beliebig, Passwort = Token).

Beide Pfade melden sich mit dem Token an und sind ohne Sitzung erreichbar. Ein gültiger Token wird nie gesperrt; nach 10 Fehlversuchen in 10 Minuten werden weitere Fehlversuche abgewiesen (HTTP 429 beim curl-Melder). Adresswechsel werden höchstens alle 20 Sekunden je Adressfamilie übernommen. Schützt ein Login oder SSO vor Emberwatch (z. B. Pangolin, Authelia) jeden Pfad, für `/api/myip/report` und `/nic/update` eine Ausnahme anlegen.

## Konfiguration

Alle Einstellungen sind Umgebungsvariablen; [`.env.example`](.env.example) enthält jede Variable mit Standardwert. Die wichtigsten:

| Variable | Standard | Zweck |
|---|---|---|
| `LANGUAGE` | `en` | Sprache von Benachrichtigungen und Tagesberichten (`de`/`en`). Die Sprache der Oberfläche wählt jeder Browser selbst. |
| `AUTH_MODE` | `password` | `password` = eingebaute Anmeldung, `none` = keine Anmeldung (nur hinter einem authentifizierenden Proxy) |
| `AUTH_PASSWORD` | – | Passwort; leer = wird beim ersten Start erzeugt |
| `CF_API_TOKEN` | – | Cloudflare-API-Token mit Leserecht für Radar (Angriffe, Ausfälle, BGP-Ereignisse) |
| `ABUSECH_AUTH_KEY` | – | abuse.ch Auth-Key (ThreatFox, URLhaus, MalwareBazaar) |
| `RANSOMWARE_LIVE_API_KEY` | – | Optionaler ransomware.live-PRO-Key; ohne Key wird die freie API genutzt |
| `ABUSEIPDB_API_KEY` | – | Optional, IP-Reputation (kostenlos: 1.000 Abfragen pro Tag) |
| `NVD_API_KEY` | – | Optional, schnellere Produktprüfung (50 statt 5 Anfragen je 30 s) |
| `CERTSPOTTER_API_KEY` | – | Optional, höhere Limits für die Zertifikats-Transparenz |
| `GREYNOISE_API_KEY` | – | Optional, GreyNoise-Community-Key für das Werkzeug GreyNoise (geht auch ohne Key, mit geringerem Limit) |
| `GLOBALPING_TOKEN` | – | Optional, Globalping-Token (mehr Messungen als ohne) |
| `CYBERCHEF_URL` | öffentliche GCHQ-Instanz | CyberChef für den Werkzeugkasten, z. B. eine selbst gehostete Instanz |
| `GEMINI_API_KEY` | – | Optional, KI-Berichte |
| `MATRIX_HOMESERVER`, `MATRIX_ACCESS_TOKEN`, `MATRIX_ROOM_ID` | – | Optionale Matrix-Benachrichtigung (Bot-Konto in einem unverschlüsselten Raum) |
| `MATRIX_MIN_SEVERITY` | `high` | Mindest-Schwere für Benachrichtigungen |
| `DAILY_REPORT_TIME` | `07:00` | Tagesbericht (Ortszeit, `TZ`), leer = aus |
| `HOME_REGION`, `HOME_REGION_NAME` | – | Optionale Heimatregion, z. B. `DE,AT,CH` / `DACH`, ergänzt eine Regionsanalyse und den Regionsfokus der Weltlage |
| `NEWS_ENABLED` | `1` | `0` schaltet die Weltlage ab (keine Feeds, keine Akteursliste) |
| `NEWS_INTERVAL_MIN` | `30` | Minuten zwischen den Feed-Abrufen (mind. 15; bedingte Anfragen) |
| `NEWS_IMAGES` | `1` | Vorschaubilder der Meldungen; der Browser lädt sie vom Verlag (`0` = keine Bilder, kein `https:` in der Bild-Richtlinie) |
| `NEWS_DISABLE` | – | Eingebaute Quellen abschalten, z. B. `golem,krebs` |
| `NEWS_FEEDS` | – | Weitere Feeds: `id\|Name\|https://feed-url[\|gov\|sprache]`, mehrere mit `;` getrennt (`gov` = Behörde) |
| `NEWS_RETENTION_DAYS` | `90` | Aufbewahrung der Meldungen in Tagen (7–365); die Presse weltweit (GDELT) höchstens 14 Tage und 8.000 Überschriften |
| `SOURCES_DISABLE` | – | Zusatzquellen abschalten, kommagetrennt: `ooni` (Sperrmessungen), `gdelt` (Presse weltweit), `attack` (MITRE ATT&CK), `euvd` (ENISA), `exploits` (Metasploit-/Nuclei-Metadaten), `urlhaus`, `cloud_status` (Plattform-Störungen) |
| `TOOLS_ENABLED` | `1` | `0` schaltet die Netzwerk-Tools und den Werkzeugkasten ab |
| `TOOLS_ALLOW_PRIVATE` | `0` | `1` = Tools und aktive Scans dürfen private Adressen ansprechen |
| `SCAN_ENABLED` | `1` | `0` schaltet aktive Scans vollständig ab |
| `SYSLOG_ENABLED` | `0` | `1` = Syslog-Empfang auf `SYSLOG_PORT` (Standard 5514, UDP und TCP) |
| `BGP_LIVE` | `1` | Live-BGP-Überwachung eigener Präfixe |

Woher die Keys kommen:
- Cloudflare: *My Profile → API Tokens → Create Token* (eigenes Token mit Leserecht für Radar)
- abuse.ch: <https://auth.abuse.ch/> (auch für die Hash-Prüfung über MalwareBazaar)
- AbuseIPDB: <https://www.abuseipdb.com/account/api>
- NVD: <https://nvd.nist.gov/developers/request-an-api-key>
- Gemini: <https://aistudio.google.com/apikey>
- GreyNoise: <https://viz.greynoise.io> (Kontomenü → *My API Key*)
- Globalping: <https://dash.globalping.io> (*Tokens*)

## Reverse Proxy und Anmeldung

- Auf Port 8000 des Containers weiterleiten. Den `Host`-Header beibehalten (Standard bei Traefik, Nginx Proxy Manager und Pangolin). Schreibt dein Proxy ihn um, den öffentlichen Host in `TRUSTED_ORIGINS` eintragen.
- Werkzeug-Ergebnisse werden gestreamt (`application/x-ndjson`); der Proxy darf diese Antworten nicht puffern (Emberwatch sendet `X-Accel-Buffering: no`).
- `FORWARDED_ALLOW_IPS` steht standardmäßig auf `*`, damit die Client-Adressen vom Proxy übernommen werden (Login-Rate-Limit, *Meine IP*). Mit `*` gilt der erste Eintrag in `X-Forwarded-For`; auf die Proxy-Adresse setzen, wenn Port 8000 nicht nur für den Proxy erreichbar ist oder dein Proxy vom Client mitgeschickte Header weiterreicht.
- `/api/myip/report` und `/nic/update` (Melder für *Meine IP*) prüfen ihr eigenes Token und sind ohne Sitzung erreichbar; zu SSO siehe [Meine IP](#meine-ip).
- Mit `AUTH_MODE=none` ist die Anmeldung aus. Nur hinter einem Proxy verwenden, der Benutzer authentifiziert (z. B. Pangolin, Authelia, Authentik).
- Passwort zurücksetzen: `AUTH_PASSWORD` setzen oder `/data/auth.json` und `/data/initial-password.txt` löschen und neu starten.

## Sicherheit und Datenschutz

- Anmeldung für einen Benutzer: Passwort als scrypt-Hash, HMAC-signiertes Sitzungs-Cookie (`HttpOnly`, `SameSite=Strict`, `Secure` bei HTTPS), Schutz gegen Durchprobieren, Same-Origin-Prüfung aller API-Anfragen, strikte Content Security Policy.
- Der Container läuft als unprivilegierter Benutzer mit schreibgeschütztem Root-Dateisystem, ohne Capabilities und mit `no-new-privileges`.
- Netzwerk-Tools und Scans erreichen nur öffentliche Adressen, solange `TOOLS_ALLOW_PRIVATE=1` nicht gesetzt ist; Hostnamen werden einmal aufgelöst und jede Adresse geprüft (kein DNS-Rebinding), es ist keine Shell beteiligt. Private Adressen und interne Namen (Namen ohne Punkt, `.local`, `.lan`, `.internal`, `.home.arpa`, `fritz.box` und ähnliche) gehen nie an Dritte, auch nicht an Gemini; Globalping löst einen Namen zusätzlich vorher lokal auf und lehnt ihn ab, wenn er auf eine private Adresse zeigt. Das DNS-Werkzeug fragt interne Namen nur beim System-Resolver an. Namen unter öffentlichen Domains, die nur intern auflösen (z. B. `dc01.ad.example.com`), sind nicht erkennbar und werden wie öffentliche Namen behandelt.
- Jedes Werkzeug zeigt, ob es passiv, aktiv oder ein Eingriff ist, ob das Ziel die Anfrage sieht und welcher Dritte die Eingabe erhält. Der Zonentransfer-Test braucht pro Lauf eine Bestätigung. Links von außen (Lesezeichen, andere Seiten) öffnen den Werkzeugkasten, starten aber nie selbst einen Lauf.
- **Aktive Scans:** nur Systeme scannen, die dir gehören oder für die du eine Freigabe hast. Emberwatch scannt ein Asset erst nach ausdrücklicher Bestätigung und begrenzt Hosts, Ports und Parallelität. Das Scannen fremder Systeme kann strafbar sein.
- Hochgeladene Logs werden in einer temporären Datei verarbeitet und sofort gelöscht; nur das Ergebnis geht an den Browser. Syslog-Zeilen werden nur als Alarm zu bekannten Indikatoren gespeichert.
- Gemini-Lageberichte erhalten nur aggregierte Kennzahlen und erkannte Muster: keine Opfernamen, keine Roh-IOCs, keine Assets, keine Log-Inhalte. Die Gemini-Bewertung eines Objekts (nur auf Anforderung) sendet das Objekt und die Daten seiner Seite; eigene Assets, IPs und Produkte gehen nur als Hinweis mit, Opfernamen von Leak-Sites gar nicht. Lagebriefe und Einordnungen der Weltlage senden Überschriften, Anreißer, Quellen und die erkannten öffentlichen Angaben; ob eine Meldung dich betrifft, geht nur als Hinweis mit.
- Weltlage: Feeds werden ohne Entity-Auflösung und externe Verweise gelesen (defusedxml), höchstens 5 MB je Feed, mit bedingten Anfragen; Weiterleitungen müssen auf HTTPS und öffentlichen Adressen bleiben. Vorschaubilder kommen aus dem Feed oder von der Artikelseite, die nur von der eigenen Domain der Quelle und von öffentlichen Adressen geholt wird (höchstens 400 KB, drei Weiterleitungen, jede geprüft). Bildadressen brauchen einen öffentlichen Hostnamen auf dem Standardport, der auf öffentliche Adressen auflöst; IP-Adressen und interne Namen werden verworfen, weil dein Browser die Bilder aus deinem Netz heraus lädt. Überschriften und Anreißer werden als Text angezeigt; Links und Bilder nur über HTTPS, Bilder ohne Referrer.
- *Meine IP* speichert die Adressen, von denen die Oberfläche aufgerufen wird (90 Tage), den Verlauf von Heim- und Server-IP und den Hash des Melder-Tokens. Werkzeug-Läufe werden 90 Tage gespeichert (höchstens 3.000) und lassen sich im Verlauf löschen; Gemini-Analysen so lange wie Alarme (`ALERT_RETENTION_DAYS`, höchstens 2.000).
- Anfragen sind in der Größe begrenzt: 20 MB mit Sitzung (Mail-Analyse bis 15 MB), 64 KB ohne (Login, Melder).
- Quellen aus 3.3: Status-Feeds werden wie Nachrichten-Feeds gelesen (defusedxml, Größengrenzen); von Metasploit und Nuclei lädt Emberwatch nur die *Metadaten* (welches Modul oder Template es zu welcher CVE gibt), nie Exploit-Code, und verlinkt nur Pfade innerhalb der beiden GitHub-Repositories; das ATT&CK-Paket und die Exploit-Listen ersetzen die gespeicherten Daten nur, wenn der Download vollständig ist. Von der Presse weltweit (GDELT) werden nur Überschrift und Link gespeichert; Artikelseiten und Bilder werden dafür nicht geholt.
- Ausgehende Verbindungen: die unten genannten Datenquellen, die Kartenkacheln (OpenFreeMap, lädt der Browser), Vorschaubilder der Meldungen (lädt der Browser von den Verlagen, `NEWS_IMAGES=0` schaltet das ab), DB-IP-Downloads, die Ziele, die du in Werkzeugen oder Scans wählst, und die Dritten der Werkzeuge, die du ausführst (in der Oberfläche gekennzeichnet). CyberChef öffnet sich im Browser; die Eingabe steht im URL-Fragment und geht an keinen Server.
- Sicherung: alles liegt im Volume `/data` (`emberwatch.sqlite`, Anmeldedateien, Geodatenbanken).

## Aufbau

```
Browser (Vanilla JS, MapLibre, Chart.js)  ──HTTPS──  Reverse Proxy  ──  Emberwatch-Container
                                                                          FastAPI + uvicorn (1 Worker)
                                                                          ├─ Collectoren (asyncio-Schleifen) ── öffentliche Quellen
                                                                          ├─ Weltlage: Feeds, Erkennung, Akteure (MISP Galaxy)
                                                                          ├─ Asset-Überwachung: InternetDB, Scans, CT, Typo, RIS Live
                                                                          ├─ eigene IPs (Aufrufe, DynDNS, Melder)
                                                                          ├─ Werkzeugkasten (NDJSON-Streams) und Objektseiten
                                                                          ├─ Alarme → Matrix
                                                                          ├─ Log-Analyse / Syslog-Empfang
                                                                          └─ SQLite (/data)
```

- Backend: `backend/app` (ein Modul je Aufgabe: `sources/` Collectoren, `analytics.py` Muster, `surface.py` Angriffsfläche und Scans, `domains.py` CT und ähnliche Domains, `bgp.py` RIS Live, `products.py` KEV/NVD, `logs.py` Log-Analyse und Syslog, `reputation.py`, `alerts.py`, `auth.py`, `i18n.py`, `objects.py` Objektseiten, `myip.py` eigene IPs, `news.py` Feeds und Meldungen, `nlp.py` Erkennung, `actors.py` Akteure, `corroborate.py` Abgleich von Meldungen mit Messdaten, `cables.py` Seekabel, `attack.py` MITRE ATT&CK, `platforms.py` Störungen der Cloud-Plattformen; `sources/ooni.py`, `gdelt.py`, `euvd.py`, `exploits.py` die Quellen aus 3.3).
- Werkzeugkasten: `backend/app/toolbox` – `registry.py` beschreibt jedes Werkzeug (Eingaben, Stufe, Kennzeichen, Parameter) und ist die einzige Quelle für Oberfläche und serverseitige Prüfung; `detect.py` Typerkennung; `result.py` das einheitliche Ergebnisformat; `tools_*.py` die Werkzeuge nach Fragestellung; `runner.py` Läufe, Rezepte und Verlauf.
- Texte des Backends (Muster, Alarme, Fehler) werden sprachneutral gespeichert und je Anfrage auf Deutsch oder Englisch erzeugt.
- Frontend: `frontend/` ohne Build-Schritt; alle dynamischen Inhalte werden als Text eingefügt, nie als HTML. `router.js` (Bereiche), `maptools.js` (Karten-Werkzeugleiste), `welt.js` (Weltlage), `analyse.js` (Objekte, Werkzeugkasten, Ansichten), `netz.js` und `assets.js` (Mein Netz), `result.js` (stellt jedes Werkzeug-Ergebnis dar), `palette.js` (`Strg+K`).

## Datenquellen und Lizenzen

| Quelle | Verwendung | Bedingungen |
|---|---|---|
| [Cloudflare Radar](https://radar.cloudflare.com) | Angriffsanteile, Vektoren, Ausfälle, BGP-Hijacks/-Leaks, Anomalien | CC BY-NC 4.0 |
| [abuse.ch](https://abuse.ch) Feodo Tracker, ThreatFox, URLhaus | C2-Server, IOCs, Schadsoftware-URLs | Nutzungsbedingungen von abuse.ch |
| [Ransomware.live](https://www.ransomware.live) | Opfer auf Leak-Sites | Quellenangabe erforderlich, keine Weitergabe der Rohdaten |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | ausgenutzte Schwachstellen | öffentlich |
| [ENISA EUVD](https://euvd.enisa.europa.eu) | laut ENISA ausgenutzte Schwachstellen | Wiedergabe mit Quellenangabe erlaubt |
| [Metasploit Framework](https://github.com/rapid7/metasploit-framework) (Rapid7), Modul-Metadaten | öffentlicher Exploit-Code je CVE (nur Metadaten) | BSD-3-Clause |
| [Nuclei-Templates](https://github.com/projectdiscovery/nuclei-templates) (ProjectDiscovery), `cves.json` | öffentliche Prüf-Templates je CVE (nur Metadaten) | MIT |
| [MITRE ATT&CK](https://attack.mitre.org) Enterprise | Techniken und Software von Gruppen und Schadsoftware | © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. |
| [FIRST EPSS](https://www.first.org/epss/) | Ausnutzungswahrscheinlichkeit | Bedingungen von FIRST |
| [NVD](https://nvd.nist.gov) | CVEs zu beobachteten Produkten | This product uses data from the NVD API but is not endorsed or certified by the NVD. |
| [Shodan InternetDB](https://internetdb.shodan.io) | passive Angriffsfläche | kostenlos für nicht-kommerzielle Nutzung |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | gekaperte Netze | kostenlos mit Quellenangabe „The Spamhaus Project“ |
| [Tor Project](https://check.torproject.org/torbulkexitlist) | Tor-Exit-Nodes | öffentlich |
| [AbuseIPDB](https://www.abuseipdb.com) | IP-Reputation (optional) | Bedingungen von AbuseIPDB |
| [RIPE NCC RIS Live, RIPEstat](https://ris-live.ripe.net) | Live-BGP, Routing | Bedingungen des RIPE NCC |
| [Cert Spotter](https://sslmate.com/certspotter/) | Zertifikats-Transparenz | Bedingungen von SSLMate |
| [Globalping](https://globalping.io) (jsDelivr) | Messungen von Messpunkten weltweit (Werkzeug, auf Anforderung) | Bedingungen von Globalping |
| [mnemonic PassiveDNS](https://docs.mnemonic.no/api/services/pdns/) | Passive DNS (Werkzeug, auf Anforderung) | Bedingungen von mnemonic |
| [GreyNoise Community API](https://www.greynoise.io) | Internet-Scanner und bekannte Dienste (Werkzeug, auf Anforderung) | Bedingungen von GreyNoise |
| [MalwareBazaar](https://bazaar.abuse.ch) (abuse.ch) | Datei-Hashes (Werkzeug, auf Anforderung) | Nutzungsbedingungen von abuse.ch |
| [rdap.org](https://rdap.org) | RDAP-Bootstrap (Whois-Werkzeug) | öffentlich |
| [MISP Galaxy](https://github.com/MISP/misp-galaxy) (Cluster threat-actor) | Akteure, Decknamen, Zuschreibungen | CC0 1.0 / BSD 2-Clause |
| Feeds der Weltlage: [NCSC UK](https://www.ncsc.gov.uk), [BSI](https://www.bsi.bund.de), [CERT-EU](https://cert.europa.eu), [CISA](https://www.cisa.gov/news-events/cybersecurity-advisories), [The Record](https://therecord.media), [BleepingComputer](https://www.bleepingcomputer.com), [SecurityWeek](https://www.securityweek.com), [Krebs on Security](https://krebsonsecurity.com), [Golem.de](https://www.golem.de), [heise Security](https://www.heise.de/security/) | Überschriften, Anreißer und Vorschaubilder von Sicherheitsmeldungen, verlinkt zum Original | Rechte bleiben bei den Verlagen; Emberwatch zeigt, was die Feeds veröffentlichen, und verlinkt den Artikel |
| [GDELT Project](https://www.gdeltproject.org) (DOC-2.0-API) | Überschriften der Presse weltweit (optional, ungeprüft) | freie Nutzung; Nennung des GDELT Project mit Link erforderlich |
| [OONI](https://ooni.org/data/) (Open Observatory of Network Interference) | Sperrmessungen je Land und Tag | CC BY-NC-SA 4.0 |
| [IODA](https://ioda.inetintel.cc.gatech.edu) (Georgia Tech) | nur Link (keine Daten genutzt: nicht frei lizenziert) | – |
| [AWS Health Dashboard](https://health.aws.amazon.com/health/status), [Azure-Status](https://azure.status.microsoft/en-us/status), [Google Cloud Service Health](https://status.cloud.google.com), [Cloudflare Status](https://www.cloudflarestatus.com) | Plattform-Störungen | öffentliche Statusseiten |
| [CyberChef](https://github.com/gchq/CyberChef) (GCHQ) | Dekodieren im Browser (Link) | Apache 2.0 |
| [DB-IP Lite](https://db-ip.com) | IP-Geolokalisierung und ASN | CC BY 4.0 |
| [TeleGeography](https://www.submarinecablemap.com) | Seekabel (Stand 2021) | CC BY-NC-SA 3.0 |
| [OpenFreeMap](https://openfreemap.org), OpenMapTiles, OpenStreetMap | Kartengrundlage | siehe [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) |
| [Natural Earth](https://www.naturalearthdata.com) | Ländergrenzen (Offline-Karte), Stadtkoordinaten der Cloud-Regionen | gemeinfrei |

Mehrere Quellen erlauben nur nicht-kommerzielle Nutzung. Emberwatch ist für private und nicht-kommerzielle Nutzung gedacht, siehe [Lizenz](#lizenz).

## Einschränkungen

- Cloudflare-Werte sind Anteile am von Cloudflare gesehenen Verkehr, keine absoluten Angriffszahlen. Ursprung ist der Standort der angreifenden IPs, nicht der Täter.
- Weltlage: Die Erkennung arbeitet regelbasiert auf Überschrift und Feed-Text; sie kann Länder, Akteure und Arten übersehen oder falsch lesen (z. B. ein Name, der auch ein gewöhnliches Wort ist). Eine Herkunft ist eine Zuschreibung einer Quelle oder das Land, das die MISP Galaxy dem erkannten Akteur zuordnet, kein Beweis. Die Zahl der Meldungen zeigt die Berichterstattung, die von den Quellen und ihren Sprachen abhängt, nicht das Ausmaß von Angriffen. Vorschaubilder kommen von den Verlagen und können fehlen.
- Abgleich mit Messdaten: nur, was die eigenen Daten zeigen können. Ein Land außerhalb der Top 25 der Angriffsziele bei Cloudflare, eine Gruppe ohne Leak-Seiten-Einträge in den Daten oder ein noch offener Zeitraum ergibt „unklar“, nicht „nicht gestützt“. „Gestützt“ heißt: passt zu den Daten, kein Beweis; wer hinter einem Angriff steckt, lässt sich nicht messen.
- OONI lebt von Freiwilligen: Für manche Länder gibt es wenige Messungen, und eine auffällige Messung kann auch eine technische Störung sein. Die Karte färbt nur bestätigte Sperren (eine bekannte Sperrseite). Der Abgleich sucht eine Veränderung gegenüber den 4 Wochen davor; dauerhafte Zensur allein stützt keine Meldung.
- Die Presse weltweit (GDELT) wird automatisch gesammelt und nicht geprüft; sie kann unpassende oder doppelte Überschriften enthalten.
- Plattform-Störungen: nur, was die Anbieter auf ihren Statusseiten veröffentlichen (Microsoft dort nur Störungen mit breiter Wirkung). Regionen werden im Text erkannt und am dokumentierten Standort gezeigt; nennt der Anbieter nur einen Bundesstaat oder ein Land oder fehlt die Stadt in den mitgelieferten Kartendaten, zeigt die Karte die größte Stadt des Bundesstaats bzw. der Region oder die Landesmitte.
- MITRE ATT&CK wird über Namen und Decknamen zugeordnet; Gruppen, die ATT&CK nicht beschreibt, haben keine Techniken. Öffentlicher Exploit-Code zeigt, dass eine Lücke leicht auszunutzen ist, nicht, dass sie ausgenutzt wird.
- Die Geolokalisierung (DB-IP Lite) ist ungefähr.
- InternetDB wird etwa wöchentlich aktualisiert; ein heute geöffneter Port erscheint eventuell erst Tage später. Für aktuelle Ergebnisse den aktiven Scan nutzen.
- Die Produktbeobachtung findet NVD-Beschreibungen über Schlüsselwörter; allgemeine Namen können Fehltreffer erzeugen.
- Die Erkennung ähnlicher Domains nutzt eine Heuristik für registrierbare Domains (keine Public Suffix List) und wertet jede DNS-Antwort außer NXDOMAIN als registriert.
- BGP-Alarme sind Heuristiken ohne RPKI-Prüfung; ein neuer Upstream oder ein DDoS-Schutzdienst kann sie auslösen.
- Syslog wird unverschlüsselt empfangen; Absender über `SYSLOG_ALLOW` und die Firewall einschränken. Bei Docker-Portfreigaben können alle Absender mit der Adresse des Docker-Gateways erscheinen.
- Werkzeuge mit Drittanbietern haben Rate-Limits (z. B. mnemonic PassiveDNS ohne Key: 10 Anfragen pro Minute); Antworten von Passive DNS, GreyNoise und MalwareBazaar werden 24 Stunden zwischengespeichert.
- *Meine IP* über Aufrufe braucht einen Reverse Proxy, der `X-Forwarded-For` setzt; hinter CGNAT ist die Heim-IP die gemeinsame Adresse des Anbieters.
- Ein Benutzer (ein Passwort), eine Instanz (SQLite, ein Worker).

## Entwicklung

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest -q tests            # Tests nutzen nachgebildete Upstream-APIs
COLLECTORS=0 AUTH_MODE=none DATA_DIR=../data STATIC_DIR=../frontend uvicorn app.main:app --reload
```

`scripts/` enthält die Generatoren für die mitgelieferten Kartendaten (Kartenstil, Ländergrenzen, Seekabel, Stadtkoordinaten der Cloud-Regionen).

## Änderungen

Siehe [CHANGELOG.md](CHANGELOG.md).

## Lizenz

Emberwatch steht unter der [PolyForm Noncommercial License 1.0.0](LICENSE.md): kostenlos für private und andere nicht-kommerzielle Nutzung, keine kommerzielle Nutzung. Komponenten und Daten Dritter behalten ihre eigenen Lizenzen, siehe [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Required Notice: Copyright (c) 2026 SaturdayNetLab (https://github.com/SaturdayNetLab)
