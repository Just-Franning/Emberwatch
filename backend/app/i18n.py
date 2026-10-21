"""Server-side texts in German and English.

Everything the backend shows to a person (patterns, alerts, infrastructure events, errors, notifications)
is stored language-neutral as a key plus parameters and rendered here per request or per setting.
"""
from __future__ import annotations

import json
import string
from typing import Any, Callable

LANGS = ("de", "en")
DEFAULT_LANG = "en"


def norm_lang(v: str | None, default: str = DEFAULT_LANG) -> str:
    s = (v or "").strip().lower()[:2]
    return s if s in LANGS else default


def fnum(v: Any, lang: str, digits: int = 1) -> str:
    """Number with locale decimal separator (no thousands separator to keep it unambiguous)."""
    try:
        s = f"{float(v):.{digits}f}"
    except (TypeError, ValueError):
        return "–"
    return s.replace(".", ",") if lang == "de" else s


def fint(v: Any, lang: str) -> str:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return "–"
    s = f"{n:,}"
    return s.replace(",", ".") if lang == "de" else s


# ---------------------------------------------------------------------------------------------------------
T: dict[str, dict[str, str]] = {
    "de": {
        "sev.high": "Hoch", "sev.medium": "Mittel", "sev.low": "Niedrig", "sev.info": "Info",
        "cat.region": "Region", "cat.vector": "Vektor", "cat.spike": "Spike", "cat.c2": "C2",
        "cat.ransomware": "Ransomware", "cat.correlation": "Korrelation", "cat.vuln": "Schwachstellen",
        "cat.infra": "Infrastruktur", "cat.alerts": "Alarme",
        "layer.l7": "L7-Angriffe", "layer.l3": "DDoS L3/4",
        "dir.target": "Ziel", "dir.origin": "Ursprung", "dir_pl.target": "Zielen", "dir_pl.origin": "Ursprüngen",
        "vec.l3_vector": "DDoS-Vektor", "vec.l7_rule": "L7-Angriffskategorie",
        "veck.l3_vector": "DDoS-Vektor", "veck.l7_rule": "L7-Kategorie",
        "state.ongoing": "laufend", "state.ended": "beendet",
        "q.open": "„", "q.close": "“",
        "list.sep": ", ",
        # Patterns
        "pat.region.new_top.title": "{country} neu in Top-{dir_pl} ({layer})",
        "pat.region.new_top.detail": "{v} % Anteil in 24 h; in 7 Tagen nicht unter den Top 25 (< {base_min} %).",
        "pat.region.rise.title": "{country}: Anstieg als {dir} ({layer})",
        "pat.region.rise.detail": "{v} % in 24 h vs. {b} % im 7-Tage-Zeitraum (+{d} pp).",
        "pat.vector.rise.title": "{vec} {qo}{name}{qc} nimmt zu",
        "pat.vector.rise.detail": "{v} % in 24 h vs. {b} % in 7 Tagen (+{d} pp).",
        "pat.spike.title": "Spike bei {vec} {qo}{name}{qc}",
        "pat.spike.detail": "Spitze {peak} % in den letzten 24 h, Basis {mu} % ± {sd} (z = {z}).",
        "pat.c2.asn_concentration.title": "C2-Konzentration bei AS{asn} {name}",
        "pat.c2.asn_concentration.detail": "{count} von {total} C2-Einträgen ({share} %).",
        "pat.c2.new_family.title": "Neue C2-Familie: {family}",
        "pat.c2.new_family.detail": "{count} C2-Server in 24 h gemeldet, vorher nicht im Bestand.",
        "pat.ransom.country_rise.title": "Mehr Ransomware-Opfer in {country}",
        "pat.ransom.country_rise.detail": "{cur} in 7 Tagen vs. {prev} in den 7 Tagen davor.",
        "pat.ransom.group_rise.title": "Gruppe {group} deutlich aktiver",
        "pat.ransom.group_rise.detail": "{cur} Opfer in 7 Tagen vs. {prev} davor.",
        "pat.corr.hotspots.title": "Brennpunkte über alle Quellen: {countries}",
        "pat.corr.hotspots.detail": "Gleichzeitig Top 10 als L7-Ziel, DDoS-Ziel und bei Ransomware-Opfern. Korrelation, keine Kausalität.",
        "pat.vuln.kev_vendor.title": "Häufung KEV: {vendor}",
        "pat.vuln.kev_vendor.detail": "{count} neu aktiv ausgenutzte CVEs in 14 Tagen (CISA KEV).",
        "pat.vuln.kev_ransom.title": "KEV mit Ransomware-Bezug",
        "pat.vuln.kev_ransom.detail": "{count} der in 30 Tagen ergänzten KEV werden laut CISA in Ransomware-Kampagnen genutzt.",
        "pat.vuln.kev_epss.title": "Neue KEV mit hoher EPSS",
        "pat.vuln.kev_epss.detail": "{count} der in 14 Tagen ergänzten KEV haben EPSS ≥ {thr} (FIRST).",
        "pat.infra.critical.title": "Ausfall ({cause}){where} ({state})",
        "pat.infra.critical.where": " in {country}",
        "pat.infra.critical.cables": "Dort landen {count} Seekabel (Stand {snapshot}), u. a. {names}.",
        "pat.infra.hijack_cluster.title": "BGP-Hijacks mit Bezug zu {country}",
        "pat.infra.hijack_cluster.detail": "{count} Hijack-Ereignisse in 24 h (Opfer- oder Hijacker-Land).",
        "pat.corr.disturbed_rising.title": "{country}: Störung und steigender Angriffsdruck",
        "pat.corr.disturbed_rising.detail": "Infrastruktur-Ereignis (Ausfall oder BGP-Hijack) in 7 Tagen bei gleichzeitigem Anstieg als Angriffsziel. Korrelation, keine Kausalität.",
        "pat.alerts.summary.title": "Alarme: {count} neue Treffer in 7 Tagen",
        "pat.alerts.summary.detail": "Eigene Assets oder beobachtete Produkte tauchen in Bedrohungsdaten auf. Details unter Alarme.",
        # Outage causes (Cloudflare Radar)
        "cause.BLOCKING": "Sperrung", "cause.CABLE_CUT": "Kabelschaden", "cause.CYBERATTACK": "Cyberangriff",
        "cause.DNS": "DNS-Störung", "cause.FIRE": "Brand", "cause.GOVERNMENT_DIRECTED": "staatlich angeordnet",
        "cause.MAINTENANCE": "Wartung", "cause.MECHANICAL": "mechanischer Defekt", "cause.MILITARY_ACTION": "militärische Handlung",
        "cause.MISCONFIGURATION": "Fehlkonfiguration", "cause.NATURAL_DISASTER": "Naturkatastrophe",
        "cause.NETWORK_PROBLEM": "Netzproblem", "cause.POWER_OUTAGE": "Stromausfall", "cause.SOFTWARE": "Softwarefehler",
        "cause.TECHNICAL_PROBLEM": "technisches Problem", "cause.UNKNOWN": "unbekannt", "cause.WEATHER": "Wetter",
        # Infrastructure events
        "infra.outage.title": "Ausfall ({cause})",
        "infra.outage.nets": "Netze: {names}",
        "infra.hijack.title": "BGP-Hijack",
        "infra.hijack.detail": "Hijacker AS{asn} {name} ({cc}); betroffen: {victims}; Präfixe: {prefixes}",
        "infra.leak.title": "BGP-Route-Leak",
        "infra.leak.detail": "Leak durch AS{asn} {name}; {prefixes} Präfixe, {origins} Origins, {peers} Peers; Pfadsegment: {seg}",
        "infra.anomaly.title": "Traffic-Anomalie",
        "infra.anomaly.detail": "{where}; Typ {type}, Status {status}",
        # Alerts
        "alert.watch.c2_ip.title": "C2-Server in {asset}",
        "alert.watch.c2_ip.detail": "{malware} auf {ioc} (abuse.ch)",
        "alert.watch.c2_asn.title": "C2-Server in AS{asn}",
        "alert.watch.c2_asn.detail": "{malware} auf {ioc} (abuse.ch)",
        "alert.watch.c2_domain.title": "C2-Indikator unter {asset}",
        "alert.watch.c2_domain.detail": "{malware}: {ioc} (abuse.ch)",
        "alert.watch.infra_prefix.title": "{event} betrifft {asset}",
        "alert.watch.infra_prefix.detail": "Präfix {prefix} (Cloudflare Radar)",
        "alert.watch.infra_asn.title": "{event} mit Beteiligung von AS{asn}",
        "alert.watch.infra_asn.detail": "{summary}",
        "alert.watch.leak_victim.title": "Leak-Site-Eintrag zu {asset}",
        "alert.watch.leak_victim.detail": "Gruppe {group}: {victim} (Ransomware.live)",
        "alert.surface.new_port.title": "Neuer offener Port auf {ip}",
        "alert.surface.new_port.detail": "Port {port} laut Shodan InternetDB ({asset})",
        "alert.surface.closed_port.title": "Port geschlossen auf {ip}",
        "alert.surface.closed_port.detail": "Port {port} laut Shodan InternetDB nicht mehr offen ({asset})",
        "alert.surface.new_vuln.title": "Schwachstelle auf {ip}: {cve}",
        "alert.surface.new_vuln.detail": "{flags}laut Shodan InternetDB ({asset})",
        "alert.scan.new_port.title": "Neuer offener Port {ip}:{port}",
        "alert.scan.new_port.detail": "{service}{banner}Aktiver Scan ({asset})",
        "alert.scan.closed_port.title": "Port geschlossen {ip}:{port}",
        "alert.scan.closed_port.detail": "Beim letzten aktiven Scan nicht mehr erreichbar ({asset})",
        "alert.scan.cert_expiring.title": "Zertifikat läuft ab: {ip}:{port}",
        "alert.scan.cert_expiring.detail": "Noch {days} Tage gültig ({subject}, {asset})",
        "alert.scan.cert_changed.title": "Neues Zertifikat auf {ip}:{port}",
        "alert.scan.cert_changed.detail": "Aussteller {issuer}, gültig bis {not_after} ({asset})",
        "alert.scan.banner_changed.title": "Dienst geändert auf {ip}:{port}",
        "alert.scan.banner_changed.detail": "{old} → {new} ({asset})",
        "alert.product.kev.title": "Aktiv ausgenutzt: {cve} ({product})",
        "alert.product.kev.detail": "{vendor} {kev_product}: {name}{epss}",
        "alert.product.cve.title": "Kritische CVE: {cve} ({product})",
        "alert.product.cve.detail": "CVSS {cvss}{epss}: {summary}",
        "alert.ct.new_cert.title": "Neues Zertifikat für {domain}",
        "alert.ct.new_cert.detail": "{names}; Aussteller {issuer}",
        "alert.ct.new_issuer.title": "Neue Zertifizierungsstelle für {domain}",
        "alert.ct.new_issuer.detail": "{issuer} hat erstmals ein Zertifikat ausgestellt: {names}",
        "alert.typo.registered.title": "Ähnliche Domain registriert: {candidate}",
        "alert.typo.registered.detail": "Variante von {domain} ({technique}){mx}{ips}",
        "alert.typo.baseline.title": "{count} ähnliche Domains zu {domain} aktiv",
        "alert.typo.baseline.detail": "Erstprüfung: {examples}",
        "alert.bgp.origin.title": "Möglicher BGP-Hijack: {prefix}",
        "alert.bgp.origin.detail": "Angekündigt von AS{origin}, erwartet {expected}; Peer AS{peer_asn} über {host}",
        "alert.bgp.more_specific.title": "Spezifischeres Präfix unter {watched}",
        "alert.bgp.more_specific.detail": "{prefix} angekündigt von AS{origin}, erwartet {expected}; Peer AS{peer_asn} über {host}",
        "alert.bgp.withdrawn.title": "Präfix {prefix} wird zurückgezogen",
        "alert.bgp.withdrawn.detail": "{peers} RIS-Peers haben die Route in 5 Minuten zurückgezogen",
        "alert.syslog.hit.title": "Bekannter Indikator im Syslog: {indicator}",
        "alert.syslog.hit.detail": "{matches}; Quelle {source}; Zeile: {line}",
        "alert.rep.abuseipdb.title": "Schlechter Ruf: {ip}",
        "alert.rep.abuseipdb.detail": "AbuseIPDB-Score {score} ({reports} Meldungen) ({asset})",
        "alert.rep.drop.title": "{ip} auf Spamhaus DROP",
        "alert.rep.drop.detail": "Eintrag {cidr} ({sblid}) ({asset})",
        "alert.legacy.title": "Watchlist-Treffer",
        "alert.legacy.detail": "{detail}",
        # Log matches
        "match.c2": "C2 {malware} ({source})",
        "match.ioc": "{threat} {malware} (ThreatFox)",
        "match.tor": "Tor-Exit-Node",
        "match.drop": "Spamhaus DROP {cidr}",
        # Errors
        "err.bad_request": "Ungültige Anfrage.",
        "err.not_found": "Nicht gefunden.",
        "err.forbidden": "Nicht erlaubt.",
        "err.auth_required": "Anmeldung erforderlich.",
        "err.login_failed": "Passwort falsch.",
        "err.login_locked": "Zu viele Fehlversuche. Bitte {seconds} s warten.",
        "err.csrf": "Anfrage von fremder Seite abgelehnt.",
        "err.invalid_country": "Ungültiger Ländercode.",
        "err.invalid_date": "Ungültiges Datum (JJJJ-MM-TT).",
        "err.country_missing": "Land fehlt.",
        "err.question_missing": "Frage fehlt.",
        "err.report_not_found": "Bericht nicht gefunden.",
        "err.region_missing": "Keine Heimatregion konfiguriert (HOME_REGION).",
        "err.tools_disabled": "Netzwerk-Tools sind deaktiviert (TOOLS_ENABLED).",
        "err.scan_disabled": "Aktive Scans sind deaktiviert (SCAN_ENABLED).",
        "err.timeout": "Zeitlimit überschritten.",
        "err.busy": "Läuft bereits, bitte warten.",
        "err.too_large": "Datei zu groß (maximal {mb} MB).",
        "err.empty": "Keine Daten erhalten.",
        "err.ai": "Gemini: {detail}",
        "err.ai_disabled": "GEMINI_API_KEY ist nicht gesetzt.",
        "err.ai_wait": "Bitte {seconds} s warten (Rate-Limit der App).",
        "err.ai_unreachable": "Gemini nicht erreichbar.",
        "err.ai_http": "Gemini HTTP {status}: {detail}",
        "err.ai_empty": "Leere Antwort von Gemini ({reason}).",
        "err.ai_json": "Gemini-Antwort ist kein gültiges JSON ({reason}).",
        "err.ai_structure": "Gemini-Antwort hat eine unerwartete Struktur.",
        "err.matrix_off": "Matrix ist nicht konfiguriert.",
        "err.matrix_failed": "Matrix-Versand fehlgeschlagen: {detail}",
        "err.watch_empty": "Eintrag leer oder zu lang.",
        "err.watch_ip": "Ungültige IP-Adresse.",
        "err.watch_cidr": "Ungültiges Netz (CIDR).",
        "err.watch_cidr_big": "Netz zu groß (mindestens /8 bzw. /16).",
        "err.watch_asn": "Ungültige AS-Nummer.",
        "err.watch_domain": "Ungültige Domain.",
        "err.watch_kind": "Unbekannter Typ.",
        "err.watch_exists": "Eintrag existiert bereits.",
        "err.watch_limit": "Maximal {max} Einträge.",
        "err.scan_ack": "Bitte bestätigen, dass du dieses Asset scannen darfst.",
        "err.scan_kind": "Nur IPs, Netze und Domains lassen sich scannen.",
        "err.scan_too_big": "Zu viele Adressen für einen Scan ({count}, maximal {max}).",
        "err.scan_no_targets": "Keine scanbaren Adressen: Die Domain löst nicht auf, oder alle Adressen sind privat bzw. reserviert. Private Adressen nur mit TOOLS_ALLOW_PRIVATE=1.",
        "err.product_empty": "Hersteller fehlt.",
        "err.product_exists": "Produkt wird bereits beobachtet.",
        "err.product_limit": "Maximal {max} Produkte.",
        "err.nvd": "NVD nicht erreichbar: {detail}",
        "err.tool.ip": "Ungültige IP-Adresse.",
        "err.tool.multicast": "Multicast- und unspezifizierte Adressen sind nicht erlaubt.",
        "err.tool.private": "{addr} ist keine öffentliche Adresse (private Ziele sind deaktiviert: TOOLS_ALLOW_PRIVATE).",
        "err.tool.target": "Ungültiges Ziel.",
        "err.tool.hostname": "Ungültiger Hostname.",
        "err.tool.resolve": "{host} lässt sich nicht auflösen.",
        "err.tool.resolver": "Unbekannter Resolver.",
        "err.tool.rdap_rate": "RDAP-Ratenlimit, bitte kurz warten.",
        "err.tool.rdap_redirect": "RDAP-Weiterleitung auf unsicheres Ziel.",
        "err.tool.rdap_none": "Kein RDAP-Eintrag gefunden.",
        "err.tool.rdap_429": "RDAP-Server meldet Ratenlimit (429).",
        "err.tool.rdap_http": "RDAP HTTP {status}.",
        "err.tool.rdap_big": "RDAP-Antwort zu groß.",
        "err.tool.rdap_json": "RDAP-Antwort ist kein JSON.",
        "err.tool.rdap_loops": "Zu viele Weiterleitungen.",
        "err.tool.scheme": "Nur http:// oder https:// erlaubt.",
        "err.tool.port": "Ungültiger Port: {port}",
        "err.tool.path": "Ungültiger Pfad.",
        "err.tool.no_ports": "Keine Ports angegeben.",
        "err.tool.max_ports": "Maximal 10 Ports je Prüfung.",
        "err.tool.traceroute_missing": "traceroute nicht verfügbar: {detail}",
        "err.tool.upstream": "Dienst nicht erreichbar ({detail}).",
        "err.internal": "Interner Fehler ({detail}).",
        # Tool stream messages
        "tool.icmp_unavailable": "ICMP nicht verfügbar ({detail}), nutze TCP-Ping.",
        "tool.icmp_failed": "ICMP nicht möglich ({detail}), nutze TCP-Ping.",
        "tool.tcp_unreachable": "TCP 443 und 80 nicht erreichbar, kein Ping möglich.",
        "tool.trace_timeout": "Zeitlimit erreicht, Traceroute abgebrochen.",
        "tool.port.open": "offen", "tool.port.closed": "geschlossen", "tool.port.filtered": "gefiltert (Timeout)",
        "tool.port.error": "Fehler: {detail}",
        "tool.tls_ok": "Kette, Hostname und Zeitraum gültig",
        "tool.tls_check_failed": "Prüfung nicht möglich: {detail}",
        "tool.tls_connect_failed": "TLS-Verbindung fehlgeschlagen: {detail}",
        "tool.http_failed": "HTTP-Anfrage fehlgeschlagen: {detail}",
        "tool.ripestat_failed": "RIPEstat nicht erreichbar: {detail}",
        "tool.dns.none": "keine Einträge", "tool.dns.nxdomain": "NXDOMAIN (Name existiert nicht)",
        "tool.dns.timeout": "Timeout", "tool.dns.servfail": "kein Nameserver antwortet (SERVFAIL?)",
        # Source status
        "status.missing_key": "{var} fehlt",
        "status.no_kev": "noch keine KEV-Daten",
        "status.kev_source": "Quelle: {source}",
        "status.kev_source_fallback": "Quelle: {source} (vorher fehlgeschlagen: {failed})",
        "status.api_pro": "PRO-API",
        "status.api_legacy": "freie API v2",
        "status.batches_failed": "{count} Abfragen fehlgeschlagen",
        "status.disabled": "deaktiviert",
        "status.no_assets": "keine passenden Assets",
        # Notifications
        "notify.test": "Testnachricht. Benachrichtigungen funktionieren.",
        "notify.patterns": "{count} neue Auffälligkeit(en)",
        "notify.alerts": "{count} neue Alarm(e)",
        "notify.daily": "Tagesbericht",
        "notify.daily_fallback_title": "Muster am {date}",
        "notify.daily_fallback_summary": "Gemini ist nicht konfiguriert; hier die erkannten Muster.",
        # Export
        "export.header": "Emberwatch C2-Blockliste, erstellt {ts}",
        "export.source": "Quelle: abuse.ch Feodo Tracker / ThreatFox; Filter: {days} Tage, Quelle={source}, Familie={family}, Konfidenz>={conf}",
        "export.count": "{count} IP-Adressen",
        "export.all": "alle",
        "region.default_name": "Heimatregion",
        "err.refresh_wait": "Bitte {seconds} s warten.",
        "err.scan_unknown": "Unbekannter Scan.",
        "none": "keine",
        "unknown": "unbekannt",
    },
    "en": {
        "sev.high": "High", "sev.medium": "Medium", "sev.low": "Low", "sev.info": "Info",
        "cat.region": "Region", "cat.vector": "Vector", "cat.spike": "Spike", "cat.c2": "C2",
        "cat.ransomware": "Ransomware", "cat.correlation": "Correlation", "cat.vuln": "Vulnerabilities",
        "cat.infra": "Infrastructure", "cat.alerts": "Alerts",
        "layer.l7": "L7 attacks", "layer.l3": "DDoS L3/4",
        "dir.target": "target", "dir.origin": "origin", "dir_pl.target": "targets", "dir_pl.origin": "origins",
        "vec.l3_vector": "DDoS vector", "vec.l7_rule": "L7 attack category",
        "veck.l3_vector": "DDoS vector", "veck.l7_rule": "L7 category",
        "state.ongoing": "ongoing", "state.ended": "ended",
        "q.open": "“", "q.close": "”",
        "list.sep": ", ",
        "pat.region.new_top.title": "{country} newly among top {dir_pl} ({layer})",
        "pat.region.new_top.detail": "{v}% share in 24 h; not in the 7-day top 25 (< {base_min}%).",
        "pat.region.rise.title": "{country}: rising as {dir} ({layer})",
        "pat.region.rise.detail": "{v}% in 24 h vs. {b}% over 7 days (+{d} pp).",
        "pat.vector.rise.title": "{vec} {qo}{name}{qc} increasing",
        "pat.vector.rise.detail": "{v}% in 24 h vs. {b}% over 7 days (+{d} pp).",
        "pat.spike.title": "Spike in {vec} {qo}{name}{qc}",
        "pat.spike.detail": "Peak {peak}% in the last 24 h, baseline {mu}% ± {sd} (z = {z}).",
        "pat.c2.asn_concentration.title": "C2 concentration at AS{asn} {name}",
        "pat.c2.asn_concentration.detail": "{count} of {total} C2 entries ({share}%).",
        "pat.c2.new_family.title": "New C2 family: {family}",
        "pat.c2.new_family.detail": "{count} C2 servers reported in 24 h, not seen before.",
        "pat.ransom.country_rise.title": "More ransomware victims in {country}",
        "pat.ransom.country_rise.detail": "{cur} in 7 days vs. {prev} in the previous 7 days.",
        "pat.ransom.group_rise.title": "Group {group} much more active",
        "pat.ransom.group_rise.detail": "{cur} victims in 7 days vs. {prev} before.",
        "pat.corr.hotspots.title": "Hotspots across all sources: {countries}",
        "pat.corr.hotspots.detail": "Simultaneously top 10 as L7 target, DDoS target and in ransomware victims. Correlation, not causation.",
        "pat.vuln.kev_vendor.title": "KEV cluster: {vendor}",
        "pat.vuln.kev_vendor.detail": "{count} newly exploited CVEs in 14 days (CISA KEV).",
        "pat.vuln.kev_ransom.title": "KEV used in ransomware",
        "pat.vuln.kev_ransom.detail": "{count} of the KEV entries added in 30 days are used in ransomware campaigns according to CISA.",
        "pat.vuln.kev_epss.title": "New KEV with high EPSS",
        "pat.vuln.kev_epss.detail": "{count} of the KEV entries added in 14 days have EPSS ≥ {thr} (FIRST).",
        "pat.infra.critical.title": "Outage ({cause}){where} ({state})",
        "pat.infra.critical.where": " in {country}",
        "pat.infra.critical.cables": "{count} submarine cables land there (as of {snapshot}), including {names}.",
        "pat.infra.hijack_cluster.title": "BGP hijacks involving {country}",
        "pat.infra.hijack_cluster.detail": "{count} hijack events in 24 h (victim or hijacker country).",
        "pat.corr.disturbed_rising.title": "{country}: disruption and rising attack pressure",
        "pat.corr.disturbed_rising.detail": "Infrastructure event (outage or BGP hijack) in 7 days while rising as an attack target. Correlation, not causation.",
        "pat.alerts.summary.title": "Alerts: {count} new hits in 7 days",
        "pat.alerts.summary.detail": "Your assets or watched products appear in threat data. See Alerts for details.",
        "cause.BLOCKING": "blocking", "cause.CABLE_CUT": "cable cut", "cause.CYBERATTACK": "cyberattack",
        "cause.DNS": "DNS failure", "cause.FIRE": "fire", "cause.GOVERNMENT_DIRECTED": "government directed",
        "cause.MAINTENANCE": "maintenance", "cause.MECHANICAL": "mechanical failure", "cause.MILITARY_ACTION": "military action",
        "cause.MISCONFIGURATION": "misconfiguration", "cause.NATURAL_DISASTER": "natural disaster",
        "cause.NETWORK_PROBLEM": "network problem", "cause.POWER_OUTAGE": "power outage", "cause.SOFTWARE": "software failure",
        "cause.TECHNICAL_PROBLEM": "technical problem", "cause.UNKNOWN": "unknown", "cause.WEATHER": "weather",
        "infra.outage.title": "Outage ({cause})",
        "infra.outage.nets": "Networks: {names}",
        "infra.hijack.title": "BGP hijack",
        "infra.hijack.detail": "Hijacker AS{asn} {name} ({cc}); affected: {victims}; prefixes: {prefixes}",
        "infra.leak.title": "BGP route leak",
        "infra.leak.detail": "Leak by AS{asn} {name}; {prefixes} prefixes, {origins} origins, {peers} peers; path segment: {seg}",
        "infra.anomaly.title": "Traffic anomaly",
        "infra.anomaly.detail": "{where}; type {type}, status {status}",
        "alert.watch.c2_ip.title": "C2 server in {asset}",
        "alert.watch.c2_ip.detail": "{malware} at {ioc} (abuse.ch)",
        "alert.watch.c2_asn.title": "C2 server in AS{asn}",
        "alert.watch.c2_asn.detail": "{malware} at {ioc} (abuse.ch)",
        "alert.watch.c2_domain.title": "C2 indicator under {asset}",
        "alert.watch.c2_domain.detail": "{malware}: {ioc} (abuse.ch)",
        "alert.watch.infra_prefix.title": "{event} affects {asset}",
        "alert.watch.infra_prefix.detail": "Prefix {prefix} (Cloudflare Radar)",
        "alert.watch.infra_asn.title": "{event} involving AS{asn}",
        "alert.watch.infra_asn.detail": "{summary}",
        "alert.watch.leak_victim.title": "Leak site entry for {asset}",
        "alert.watch.leak_victim.detail": "Group {group}: {victim} (Ransomware.live)",
        "alert.surface.new_port.title": "New open port on {ip}",
        "alert.surface.new_port.detail": "Port {port} according to Shodan InternetDB ({asset})",
        "alert.surface.closed_port.title": "Port closed on {ip}",
        "alert.surface.closed_port.detail": "Port {port} no longer open according to Shodan InternetDB ({asset})",
        "alert.surface.new_vuln.title": "Vulnerability on {ip}: {cve}",
        "alert.surface.new_vuln.detail": "{flags}according to Shodan InternetDB ({asset})",
        "alert.scan.new_port.title": "New open port {ip}:{port}",
        "alert.scan.new_port.detail": "{service}{banner}Active scan ({asset})",
        "alert.scan.closed_port.title": "Port closed {ip}:{port}",
        "alert.scan.closed_port.detail": "No longer reachable in the last active scan ({asset})",
        "alert.scan.cert_expiring.title": "Certificate expiring: {ip}:{port}",
        "alert.scan.cert_expiring.detail": "{days} days left ({subject}, {asset})",
        "alert.scan.cert_changed.title": "New certificate on {ip}:{port}",
        "alert.scan.cert_changed.detail": "Issuer {issuer}, valid until {not_after} ({asset})",
        "alert.scan.banner_changed.title": "Service changed on {ip}:{port}",
        "alert.scan.banner_changed.detail": "{old} → {new} ({asset})",
        "alert.product.kev.title": "Actively exploited: {cve} ({product})",
        "alert.product.kev.detail": "{vendor} {kev_product}: {name}{epss}",
        "alert.product.cve.title": "Critical CVE: {cve} ({product})",
        "alert.product.cve.detail": "CVSS {cvss}{epss}: {summary}",
        "alert.ct.new_cert.title": "New certificate for {domain}",
        "alert.ct.new_cert.detail": "{names}; issuer {issuer}",
        "alert.ct.new_issuer.title": "New certificate authority for {domain}",
        "alert.ct.new_issuer.detail": "{issuer} issued a certificate for the first time: {names}",
        "alert.typo.registered.title": "Lookalike domain registered: {candidate}",
        "alert.typo.registered.detail": "Variant of {domain} ({technique}){mx}{ips}",
        "alert.typo.baseline.title": "{count} lookalike domains of {domain} active",
        "alert.typo.baseline.detail": "Initial check: {examples}",
        "alert.bgp.origin.title": "Possible BGP hijack: {prefix}",
        "alert.bgp.origin.detail": "Announced by AS{origin}, expected {expected}; peer AS{peer_asn} via {host}",
        "alert.bgp.more_specific.title": "More specific prefix under {watched}",
        "alert.bgp.more_specific.detail": "{prefix} announced by AS{origin}, expected {expected}; peer AS{peer_asn} via {host}",
        "alert.bgp.withdrawn.title": "Prefix {prefix} being withdrawn",
        "alert.bgp.withdrawn.detail": "{peers} RIS peers withdrew the route within 5 minutes",
        "alert.syslog.hit.title": "Known indicator in syslog: {indicator}",
        "alert.syslog.hit.detail": "{matches}; source {source}; line: {line}",
        "alert.rep.abuseipdb.title": "Bad reputation: {ip}",
        "alert.rep.abuseipdb.detail": "AbuseIPDB score {score} ({reports} reports) ({asset})",
        "alert.rep.drop.title": "{ip} on Spamhaus DROP",
        "alert.rep.drop.detail": "Entry {cidr} ({sblid}) ({asset})",
        "alert.legacy.title": "Watchlist hit",
        "alert.legacy.detail": "{detail}",
        "match.c2": "C2 {malware} ({source})",
        "match.ioc": "{threat} {malware} (ThreatFox)",
        "match.tor": "Tor exit node",
        "match.drop": "Spamhaus DROP {cidr}",
        "err.bad_request": "Invalid request.",
        "err.not_found": "Not found.",
        "err.forbidden": "Not allowed.",
        "err.auth_required": "Login required.",
        "err.login_failed": "Wrong password.",
        "err.login_locked": "Too many failed attempts. Please wait {seconds} s.",
        "err.csrf": "Cross-site request rejected.",
        "err.invalid_country": "Invalid country code.",
        "err.invalid_date": "Invalid date (YYYY-MM-DD).",
        "err.country_missing": "Country missing.",
        "err.question_missing": "Question missing.",
        "err.report_not_found": "Report not found.",
        "err.region_missing": "No home region configured (HOME_REGION).",
        "err.tools_disabled": "Network tools are disabled (TOOLS_ENABLED).",
        "err.scan_disabled": "Active scans are disabled (SCAN_ENABLED).",
        "err.timeout": "Time limit exceeded.",
        "err.busy": "Already running, please wait.",
        "err.too_large": "File too large (maximum {mb} MB).",
        "err.empty": "No data received.",
        "err.ai": "Gemini: {detail}",
        "err.ai_disabled": "GEMINI_API_KEY is not set.",
        "err.ai_wait": "Please wait {seconds} s (app rate limit).",
        "err.ai_unreachable": "Gemini unreachable.",
        "err.ai_http": "Gemini HTTP {status}: {detail}",
        "err.ai_empty": "Empty response from Gemini ({reason}).",
        "err.ai_json": "Gemini response is not valid JSON ({reason}).",
        "err.ai_structure": "Gemini response has an unexpected structure.",
        "err.matrix_off": "Matrix is not configured.",
        "err.matrix_failed": "Matrix delivery failed: {detail}",
        "err.watch_empty": "Entry empty or too long.",
        "err.watch_ip": "Invalid IP address.",
        "err.watch_cidr": "Invalid network (CIDR).",
        "err.watch_cidr_big": "Network too large (at least /8 or /16).",
        "err.watch_asn": "Invalid AS number.",
        "err.watch_domain": "Invalid domain.",
        "err.watch_kind": "Unknown type.",
        "err.watch_exists": "Entry already exists.",
        "err.watch_limit": "At most {max} entries.",
        "err.scan_ack": "Please confirm that you are authorized to scan this asset.",
        "err.scan_kind": "Only IPs, networks and domains can be scanned.",
        "err.scan_too_big": "Too many addresses for a scan ({count}, maximum {max}).",
        "err.scan_no_targets": "No scannable addresses: the domain does not resolve, or all addresses are private or reserved. Private addresses only with TOOLS_ALLOW_PRIVATE=1.",
        "err.product_empty": "Vendor missing.",
        "err.product_exists": "Product is already watched.",
        "err.product_limit": "At most {max} products.",
        "err.nvd": "NVD unreachable: {detail}",
        "err.tool.ip": "Invalid IP address.",
        "err.tool.multicast": "Multicast and unspecified addresses are not allowed.",
        "err.tool.private": "{addr} is not a public address (private targets are disabled: TOOLS_ALLOW_PRIVATE).",
        "err.tool.target": "Invalid target.",
        "err.tool.hostname": "Invalid hostname.",
        "err.tool.resolve": "{host} cannot be resolved.",
        "err.tool.resolver": "Unknown resolver.",
        "err.tool.rdap_rate": "RDAP rate limit, please wait a moment.",
        "err.tool.rdap_redirect": "RDAP redirect to an unsafe target.",
        "err.tool.rdap_none": "No RDAP record found.",
        "err.tool.rdap_429": "RDAP server reports rate limit (429).",
        "err.tool.rdap_http": "RDAP HTTP {status}.",
        "err.tool.rdap_big": "RDAP response too large.",
        "err.tool.rdap_json": "RDAP response is not JSON.",
        "err.tool.rdap_loops": "Too many redirects.",
        "err.tool.scheme": "Only http:// or https:// allowed.",
        "err.tool.port": "Invalid port: {port}",
        "err.tool.path": "Invalid path.",
        "err.tool.no_ports": "No ports given.",
        "err.tool.max_ports": "At most 10 ports per check.",
        "err.tool.traceroute_missing": "traceroute not available: {detail}",
        "err.tool.upstream": "Service unreachable ({detail}).",
        "err.internal": "Internal error ({detail}).",
        "tool.icmp_unavailable": "ICMP not available ({detail}), using TCP ping.",
        "tool.icmp_failed": "ICMP not possible ({detail}), using TCP ping.",
        "tool.tcp_unreachable": "TCP 443 and 80 unreachable, ping not possible.",
        "tool.trace_timeout": "Time limit reached, traceroute aborted.",
        "tool.port.open": "open", "tool.port.closed": "closed", "tool.port.filtered": "filtered (timeout)",
        "tool.port.error": "error: {detail}",
        "tool.tls_ok": "Chain, hostname and validity period OK",
        "tool.tls_check_failed": "Check not possible: {detail}",
        "tool.tls_connect_failed": "TLS connection failed: {detail}",
        "tool.http_failed": "HTTP request failed: {detail}",
        "tool.ripestat_failed": "RIPEstat unreachable: {detail}",
        "tool.dns.none": "no records", "tool.dns.nxdomain": "NXDOMAIN (name does not exist)",
        "tool.dns.timeout": "timeout", "tool.dns.servfail": "no name server answers (SERVFAIL?)",
        "status.missing_key": "{var} missing",
        "status.no_kev": "no KEV data yet",
        "status.kev_source": "Source: {source}",
        "status.kev_source_fallback": "Source: {source} (failed before: {failed})",
        "status.api_pro": "PRO API",
        "status.api_legacy": "free API v2",
        "status.batches_failed": "{count} requests failed",
        "status.disabled": "disabled",
        "status.no_assets": "no matching assets",
        "notify.test": "Test message. Notifications are working.",
        "notify.patterns": "{count} new finding(s)",
        "notify.alerts": "{count} new alert(s)",
        "notify.daily": "Daily report",
        "notify.daily_fallback_title": "Patterns on {date}",
        "notify.daily_fallback_summary": "Gemini is not configured; here are the detected patterns.",
        "export.header": "Emberwatch C2 blocklist, created {ts}",
        "export.source": "Source: abuse.ch Feodo Tracker / ThreatFox; filter: {days} days, source={source}, family={family}, confidence>={conf}",
        "export.count": "{count} IP addresses",
        "export.all": "all",
        "region.default_name": "Home region",
        "err.refresh_wait": "Please wait {seconds} s.",
        "err.scan_unknown": "Unknown scan.",
        "none": "none",
        "unknown": "unknown",
    },
}


class _Safe(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


_FMT = string.Formatter()


def t(lang: str, key: str, **params: Any) -> str:
    """Translate key; unknown keys fall back to English, then to the key itself. Missing params stay visible."""
    tpl = T.get(lang, T[DEFAULT_LANG]).get(key) or T[DEFAULT_LANG].get(key) or key
    try:
        return _FMT.vformat(tpl, (), _Safe({k: ("" if v is None else v) for k, v in params.items()}))
    except (ValueError, IndexError):
        return tpl


def has(key: str) -> bool:
    return key in T[DEFAULT_LANG]


class Key(str):
    """A text key used as a parameter value; it is translated when the message is rendered."""


class AppError(Exception):
    """Error with a translatable message. status is the HTTP status when it reaches the API."""

    def __init__(self, key: str, status: int = 400, /, **params: Any) -> None:
        # positional-only, so "status" can also be a text placeholder (e.g. an upstream HTTP status)
        super().__init__(key)
        self.key = key
        self.status = status
        self.params = params

    def render(self, lang: str) -> str:
        return t(lang, self.key, **{k: t(lang, v) if isinstance(v, Key) else v for k, v in self.params.items()})


# ---------------------------------------------------------------------------------------------------------
# Pattern rendering

CountryName = Callable[[str | None, str], str]


def _join(items: list[str], lang: str) -> str:
    return t(lang, "list.sep").join(items)


def render_pattern(p: dict[str, Any], lang: str, cname: CountryName) -> dict[str, Any]:
    """Adds title/detail/category_label to a language-neutral pattern dict (returns a new dict)."""
    k, pr = p["key"], p.get("params") or {}
    n = lambda v, d=1: fnum(v, lang, d)  # noqa: E731
    q = {"qo": t(lang, "q.open"), "qc": t(lang, "q.close")}
    title = detail = ""
    if k in ("region.new_top", "region.rise"):
        args = {"country": cname(pr.get("cc"), lang), "layer": t(lang, f"layer.{pr.get('layer')}"),
                "dir": t(lang, f"dir.{pr.get('dir')}"), "dir_pl": t(lang, f"dir_pl.{pr.get('dir')}"),
                "v": n(pr.get("v")), "b": n(pr.get("b")), "d": n(pr.get("d")), "base_min": n(pr.get("base_min"))}
        title, detail = t(lang, f"pat.{k}.title", **args), t(lang, f"pat.{k}.detail", **args)
    elif k in ("vector.rise", "spike"):
        vec_key = "vec" if k == "vector.rise" else "veck"
        args = {**q, "vec": t(lang, f"{vec_key}.{pr.get('kind')}"), "name": pr.get("name", ""),
                "v": n(pr.get("v")), "b": n(pr.get("b")), "d": n(pr.get("d")),
                "peak": n(pr.get("peak")), "mu": n(pr.get("mu")), "sd": n(pr.get("sd")), "z": n(pr.get("z"))}
        title, detail = t(lang, f"pat.{k}.title", **args), t(lang, f"pat.{k}.detail", **args)
    elif k == "c2.asn_concentration":
        args = {**pr, "share": fnum(pr.get("share"), lang, 0), "count": fint(pr.get("count"), lang),
                "total": fint(pr.get("total"), lang)}
        title, detail = t(lang, f"pat.{k}.title", **args).strip(), t(lang, f"pat.{k}.detail", **args)
    elif k == "infra.critical":
        cc = pr.get("cc")
        args = {"cause": t(lang, f"cause.{pr.get('cause') or 'UNKNOWN'}"),
                "where": t(lang, "pat.infra.critical.where", country=cname(cc, lang)) if cc else "",
                "state": t(lang, "state.ongoing" if pr.get("ongoing") else "state.ended")}
        title = t(lang, "pat.infra.critical.title", **args)
        parts = [render_infra_detail(pr.get("event") or {}, lang)]
        cab = pr.get("cables")
        if cab and cab.get("count"):
            parts.append(t(lang, "pat.infra.critical.cables", count=cab["count"], snapshot=cab.get("snapshot") or "?",
                           names=_join(cab.get("names") or [], lang)))
        detail = " ".join(x for x in parts if x).strip()[:600]
    elif k == "corr.hotspots":
        args = {"countries": _join([cname(c, lang) for c in pr.get("ccs") or []], lang)}
        title, detail = t(lang, f"pat.{k}.title", **args), t(lang, f"pat.{k}.detail", **args)
    else:
        args = dict(pr)
        if "cc" in pr:
            args["country"] = cname(pr.get("cc"), lang)
        if "thr" in pr:
            args["thr"] = fnum(pr["thr"], lang, 2)
        for key in ("count", "cur", "prev"):
            if key in pr:
                args[key] = fint(pr[key], lang)
        title, detail = t(lang, f"pat.{k}.title", **args), t(lang, f"pat.{k}.detail", **args)
    return {**p, "title": title, "detail": detail, "category_label": t(lang, f"cat.{p.get('category')}")}


# ---------------------------------------------------------------------------------------------------------
# Infrastructure events (Cloudflare Radar) – stored with a language-neutral "meta" JSON

def _or(v: Any, default: str = "?") -> Any:
    return default if v is None or v == "" else v


def render_infra_title(kind: str, meta: dict[str, Any], lang: str) -> str:
    if kind == "outage":
        return t(lang, "infra.outage.title", cause=t(lang, f"cause.{meta.get('cause') or 'UNKNOWN'}"))
    return t(lang, f"infra.{kind}.title")


def render_infra_detail(meta: dict[str, Any], lang: str) -> str:
    kind = meta.get("kind")
    if kind == "outage":
        parts = [meta.get("description"), _join(meta.get("locations") or [], lang) or None,
                 t(lang, "infra.outage.nets", names=_join((meta.get("nets") or [])[:5], lang)) if meta.get("nets") else None]
        return "; ".join(p for p in parts if p)[:600]
    if kind == "hijack":
        prefixes = meta.get("prefixes") or []
        pfx = _join(prefixes[:4], lang) + (f" (+{len(prefixes) - 4})" if len(prefixes) > 4 else "")
        victims = _join([f"AS{a} {nm}".strip() for a, nm in (meta.get("victims") or [])[:3]], lang) or "?"
        return t(lang, "infra.hijack.detail", asn=_or(meta.get("asn")), name=meta.get("name") or "", cc=meta.get("cc") or "?",
                 victims=victims, prefixes=pfx).replace("  ", " ")[:600]
    if kind == "leak":
        return t(lang, "infra.leak.detail", asn=_or(meta.get("asn")), name=meta.get("name") or "",
                 prefixes=_or(meta.get("prefix_count")), origins=_or(meta.get("origin_count")),
                 peers=_or(meta.get("peer_count")), seg=" → ".join(f"AS{x}" for x in (meta.get("seg") or [])[:6])).replace("  ", " ")[:600]
    if kind == "anomaly":
        return t(lang, "infra.anomaly.detail", where=meta.get("where") or "?", type=meta.get("type") or "?",
                 status=meta.get("status") or "?")[:600]
    return ""


# ---------------------------------------------------------------------------------------------------------
# Alerts

def render_alert(row: dict[str, Any], params: dict[str, Any], lang: str) -> tuple[str, str]:
    key = row["key"]
    args = dict(params)
    if "event_kind" in args:
        args["event"] = render_infra_title(args["event_kind"], args.get("event_meta") or {}, lang)
    if "event_meta" in args and "summary" not in args:
        args["summary"] = render_infra_detail(args["event_meta"], lang)
    if "epss_v" in args:
        args["epss"] = f", EPSS {fnum(args['epss_v'], lang, 2)}" if args["epss_v"] is not None else ""
    else:
        args.setdefault("epss", "")
    if "cvss" in args:
        args["cvss"] = fnum(args["cvss"], lang, 1)
    if key == "surface.new_vuln":
        flags = []
        if args.get("kev"):
            flags.append("CISA KEV")
        if args.get("epss_v") is not None:
            flags.append(f"EPSS {fnum(args['epss_v'], lang, 2)}")
        args["flags"] = (", ".join(flags) + "; ") if flags else ""
    if key == "scan.new_port":
        args["service"] = f"{args['service']}; " if args.get("service") else ""
        args["banner"] = f"{args['banner']}; " if args.get("banner") else ""
    if key == "typo.registered":
        args["mx"] = "; MX" if args.get("mx") else ""
        ips = args.get("ips") or []
        args["ips"] = f"; {', '.join(ips[:3])}" if ips else ""
    if key == "typo.baseline":
        args["examples"] = ", ".join((args.get("examples") or [])[:8])
    if key == "syslog.hit":
        args["matches"] = _join([render_match(m, lang) if isinstance(m, dict) else str(m)
                                 for m in args.get("matches") or []], lang)
    if isinstance(args.get("names"), list):
        args["names"] = ", ".join(args["names"][:5]) + (" …" if len(args["names"]) > 5 else "")
    if isinstance(args.get("expected"), list):
        args["expected"] = ", ".join(f"AS{a}" for a in args["expected"]) or t(lang, "none")
    if "count" in args:
        args["count"] = fint(args["count"], lang)
    if key.startswith("myip."):
        if args.get("kind") in ("home", "server"):
            args["kind"] = t(lang, f"myip.kind.{args['kind']}")
        if args.get("source") in ("visit", "confirmed", "report", "dyndns", "egress"):
            args["source"] = t(lang, f"myip.src.{args['source']}")
    title = t(lang, f"alert.{key}.title", **args)
    detail = t(lang, f"alert.{key}.detail", **args)
    return title[:300], detail[:800]


def render_match(m: dict[str, Any], lang: str) -> str:
    kind = m.get("kind")
    if kind == "c2":
        return t(lang, "match.c2", malware=m.get("malware") or "?", source=m.get("source") or "abuse.ch")
    if kind == "ioc":
        return t(lang, "match.ioc", threat=m.get("threat") or "", malware=m.get("malware") or "?").strip()
    if kind == "tor":
        return t(lang, "match.tor")
    if kind == "drop":
        return t(lang, "match.drop", cidr=m.get("cidr") or "?")
    return kind or "?"


def render_status(row: dict[str, Any], lang: str) -> str:
    code = row.get("code")
    if not code:
        return row.get("message") or ""
    try:
        params = json.loads(row.get("params") or "{}")
    except ValueError:
        params = {}
    for k in ("source", "failed"):
        if isinstance(params.get(k), str) and params[k].startswith("@"):
            params[k] = t(lang, params[k][1:])
    msg = t(lang, f"status.{code}", **params)
    extra = row.get("message") or ""
    return f"{msg}; {extra}" if extra else msg


# ---------------------------------------------------------------------------------------------------------
# Texts of other modules (tool box, own IPs) are kept next to their code and merged here.

def _merge(extra: dict[str, dict[str, str]]) -> None:
    for lang in LANGS:
        T[lang].update(extra.get(lang, {}))


from .toolbox.texts import TT as _TB  # noqa: E402

_merge(_TB)

from .texts_more import OT as _OT  # noqa: E402

_merge(_OT)
