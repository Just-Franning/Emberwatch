"""Texts of the 3.3 additions (object pages, alerts, status). Merged into i18n.T."""
from __future__ import annotations

T33: dict[str, dict[str, str]] = {
    "de": {
        "status.feed_failed": "Abruf fehlgeschlagen",
        # alerts
        "alert.watch.ioc_domain.title": "Schadsoftware-Indikator unter {asset}",
        "alert.watch.ioc_domain.detail": "{malware}: {ioc} ({threat}, abuse.ch)",
        "alert.watch.ioc_ip.title": "Schadsoftware-Indikator in {asset}",
        "alert.watch.ioc_ip.detail": "{malware}: {ioc} ({threat}, abuse.ch)",
        "alert.platform.incident.title": "Störung bei {provider}: {title}",
        "alert.platform.incident.detail": "Betroffen laut Statusseite: {regions}",
        # CVE page
        "ob.v.euvd": "{id}, ausgenutzt seit {date}",
        "ob.f.euvd": "Wird laut ENISA ausgenutzt (EUVD seit {date}), noch nicht in CISA KEV",
        "ob.f.exploit_msf": "Öffentlicher Exploit-Code: Metasploit-Modul vorhanden",
        "ob.f.exploit_nuclei": "Öffentliches Prüf-Template (Nuclei) vorhanden",
        "ob.sec.exploits": "Öffentlicher Exploit- und Prüfcode",
        "ob.n.exploits": "Metasploit-Module (Rapid7, BSD-3-Clause) sind einsatzfähiger Angriffscode; Nuclei-Templates "
                         "(ProjectDiscovery, MIT) prüfen, ob ein System verwundbar ist. Beides zeigt, dass die Lücke leicht "
                         "auszunutzen ist, belegt aber keine Angriffe (das sagen CISA KEV und ENISA).",
        "ob.c.name": "Name", "ob.c.rating": "Bewertung",
        "ob.v.xp_metasploit": "Metasploit", "ob.v.xp_nuclei": "Nuclei",
        "ob.v.rank_excellent": "Rang: exzellent", "ob.v.rank_great": "Rang: sehr gut", "ob.v.rank_good": "Rang: gut",
        "ob.v.rank_normal": "Rang: normal", "ob.v.rank_average": "Rang: mittel", "ob.v.rank_low": "Rang: niedrig",
        "ob.v.rank_manual": "Rang: manuell",
        "ob.v.sev_critical": "kritisch", "ob.v.sev_high": "hoch", "ob.v.sev_medium": "mittel", "ob.v.sev_low": "niedrig",
        "ob.v.sev_info": "Info", "ob.v.sev_unknown": "unbekannt",
        # MITRE ATT&CK
        "ob.sec.attack_techniques": "Techniken laut MITRE ATT&CK ({id}, {n})",
        "ob.sec.attack_software": "Software laut MITRE ATT&CK ({n})",
        "ob.sec.attack_group": "Gruppe in MITRE ATT&CK",
        "ob.sec.attack_sw": "MITRE ATT&CK ({id})",
        "ob.c.tactic": "Taktik", "ob.c.technique": "Technik",
        "ob.k.attack_sw": "Software", "ob.k.attack_type": "Art", "ob.k.attack_techniques": "Techniken",
        "ob.k.attack_groups": "Genutzt von",
        "ob.v.sw_malware": "Schadsoftware", "ob.v.sw_tool": "Werkzeug",
        "ob.n.attack": "MITRE ATT&CK Enterprise {v}, zugeordnet über Namen und Decknamen. {notice}",
    },
    "en": {
        "status.feed_failed": "fetch failed",
        "alert.watch.ioc_domain.title": "Malware indicator under {asset}",
        "alert.watch.ioc_domain.detail": "{malware}: {ioc} ({threat}, abuse.ch)",
        "alert.watch.ioc_ip.title": "Malware indicator in {asset}",
        "alert.watch.ioc_ip.detail": "{malware}: {ioc} ({threat}, abuse.ch)",
        "alert.platform.incident.title": "Incident at {provider}: {title}",
        "alert.platform.incident.detail": "Affected according to the status page: {regions}",
        "ob.v.euvd": "{id}, exploited since {date}",
        "ob.f.euvd": "Exploited according to ENISA (EUVD since {date}), not yet in CISA KEV",
        "ob.f.exploit_msf": "Public exploit code: a Metasploit module exists",
        "ob.f.exploit_nuclei": "A public check template (Nuclei) exists",
        "ob.sec.exploits": "Public exploit and check code",
        "ob.n.exploits": "Metasploit modules (Rapid7, BSD-3-Clause) are ready-to-use attack code; Nuclei templates "
                         "(ProjectDiscovery, MIT) check whether a system is vulnerable. Both show that the flaw is easy to "
                         "exploit, but prove no attacks (that is what CISA KEV and ENISA say).",
        "ob.c.name": "Name", "ob.c.rating": "Rating",
        "ob.v.xp_metasploit": "Metasploit", "ob.v.xp_nuclei": "Nuclei",
        "ob.v.rank_excellent": "rank: excellent", "ob.v.rank_great": "rank: great", "ob.v.rank_good": "rank: good",
        "ob.v.rank_normal": "rank: normal", "ob.v.rank_average": "rank: average", "ob.v.rank_low": "rank: low",
        "ob.v.rank_manual": "rank: manual",
        "ob.v.sev_critical": "critical", "ob.v.sev_high": "high", "ob.v.sev_medium": "medium", "ob.v.sev_low": "low",
        "ob.v.sev_info": "info", "ob.v.sev_unknown": "unknown",
        "ob.sec.attack_techniques": "Techniques according to MITRE ATT&CK ({id}, {n})",
        "ob.sec.attack_software": "Software according to MITRE ATT&CK ({n})",
        "ob.sec.attack_group": "Group in MITRE ATT&CK",
        "ob.sec.attack_sw": "MITRE ATT&CK ({id})",
        "ob.c.tactic": "Tactic", "ob.c.technique": "Technique",
        "ob.k.attack_sw": "Software", "ob.k.attack_type": "Type", "ob.k.attack_techniques": "Techniques",
        "ob.k.attack_groups": "Used by",
        "ob.v.sw_malware": "malware", "ob.v.sw_tool": "tool",
        "ob.n.attack": "MITRE ATT&CK Enterprise {v}, linked by names and aliases. {notice}",
    },
}
