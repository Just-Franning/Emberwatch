"""Light-weight recognition in news texts (headline and feed text): CVEs, countries (with the attributed origin),
threat actors, malware families, kinds of incident and the user's own products and domains.

Everything here is heuristic and only reads the text of the feed. The results are labelled as "recognised
automatically" in the interface; an attribution in the text is not an attribution by Emberwatch.
All functions are linear in the length of the text (texts come from third parties).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
TOKEN_RE = re.compile(r"[0-9A-Za-zÀ-ÖØ-öø-ÿ][0-9A-Za-zÀ-ÖØ-öø-ÿ.'’_-]*")
MAX_TEXT = 4000

# --- countries --------------------------------------------------------------------------------------------------------
# Demonyms (English, exact word) and German adjective stems (prefix of the word: "russische", "russischen" …) of the
# countries that appear in IT security news. Country names in both languages come from the map's centroid file.
DEMONYMS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "RU": (("russian", "russians", "kremlin"), ("russisch", "kreml")),
    "CN": (("chinese",), ("chinesisch",)),
    "KP": (("north korean", "north koreans", "pyongyang"), ("nordkoreanisch",)),
    "KR": (("south korean", "south koreans"), ("südkoreanisch",)),
    "IR": (("iranian", "iranians", "tehran"), ("iranisch",)),
    "UA": (("ukrainian", "ukrainians", "kyiv"), ("ukrainisch",)),
    "BY": (("belarusian", "belarusians"), ("belarussisch", "weißrussisch")),
    "US": (("american", "americans"), ("amerikanisch", "us-amerikanisch")),
    "GB": (("british", "britons"), ("britisch",)),
    "DE": (("german", "germans"), ("deutsch",)),
    "FR": (("french",), ("französisch",)),
    "IL": (("israeli", "israelis"), ("israelisch",)),
    "PS": (("palestinian", "palestinians"), ("palästinensisch",)),
    "IN": (("indian",), ("indisch",)),
    "PK": (("pakistani", "pakistanis"), ("pakistanisch",)),
    "VN": (("vietnamese",), ("vietnamesisch",)),
    "TR": (("turkish",), ("türkisch",)),
    "PL": (("polish",), ("polnisch",)),
    "NL": (("dutch",), ("niederländisch",)),
    "IT": (("italian", "italians"), ("italienisch",)),
    "ES": (("spanish",), ("spanisch",)),
    "JP": (("japanese",), ("japanisch",)),
    "TW": (("taiwanese",), ("taiwanisch",)),
    "CA": (("canadian", "canadians"), ("kanadisch",)),
    "AU": (("australian", "australians"), ("australisch",)),
    "AT": (("austrian", "austrians"), ("österreichisch",)),
    "CH": (("swiss",), ("schweizerisch",)),
    "BR": (("brazilian", "brazilians"), ("brasilianisch",)),
    "SA": (("saudi",), ("saudisch",)),
    "AE": (("emirati",), ("emiratisch",)),
    "LT": (("lithuanian",), ("litauisch",)),
    "LV": (("latvian",), ("lettisch",)),
    "EE": (("estonian",), ("estnisch",)),
    "FI": (("finnish",), ("finnisch",)),
    "SE": (("swedish",), ("schwedisch",)),
    "NO": (("norwegian",), ("norwegisch",)),
    "DK": (("danish",), ("dänisch",)),
    "CZ": (("czech",), ("tschechisch",)),
    "RO": (("romanian",), ("rumänisch",)),
    "MD": (("moldovan",), ("moldauisch",)),
    "AM": (("armenian",), ("armenisch",)),
    "AZ": (("azerbaijani",), ("aserbaidschanisch",)),
    "KZ": (("kazakh",), ("kasachisch",)),
    "SY": (("syrian",), ("syrisch",)),
    "LB": (("lebanese",), ("libanesisch",)),
    "QA": (("qatari",), ("katarisch",)),
    "EG": (("egyptian",), ("ägyptisch",)),
    "NG": (("nigerian", "nigerians"), ("nigerianisch",)),
    "ZA": (("south african",), ("südafrikanisch",)),
    "MX": (("mexican",), ("mexikanisch",)),
    "AR": (("argentine", "argentinian"), ("argentinisch",)),
    "CO": (("colombian",), ("kolumbianisch",)),
    "VE": (("venezuelan",), ("venezolanisch",)),
    "CU": (("cuban",), ("kubanisch",)),
    "PH": (("philippine", "filipino"), ("philippinisch",)),
    "ID": (("indonesian",), ("indonesisch",)),
    "MY": (("malaysian",), ("malaysisch",)),
    "SG": (("singaporean",), ("singapurisch",)),
    "TH": (("thai",), ("thailändisch",)),
    "BD": (("bangladeshi",), ("bangladeschisch",)),
    "HU": (("hungarian",), ("ungarisch",)),
    "SK": (("slovak",), ("slowakisch",)),
    "BG": (("bulgarian",), ("bulgarisch",)),
    "RS": (("serbian",), ("serbisch",)),
    "HR": (("croatian",), ("kroatisch",)),
    "GR": (("greek",), ("griechisch",)),
    "PT": (("portuguese",), ("portugiesisch",)),
    "BE": (("belgian",), ("belgisch",)),
    "IE": (("irish",), ("irisch",)),
    "NZ": (("new zealand",), ("neuseeländisch",)),
}
# Short names and spellings that are not in the centroid file. Ambiguous names (Georgia, Jordan, Chad, Niger, Turkey
# the bird is accepted) are left out on purpose.
ALIASES = {
    "china": "CN", "usa": "US", "u.s.": "US", "u.s.a.": "US", "america": "US", "united states of america": "US",
    "britain": "GB", "great britain": "GB", "england": "GB", "großbritannien": "GB", "u.k.": "GB",
    "czechia": "CZ", "uae": "AE", "türkiye": "TR", "turkey": "TR", "türkei": "TR", "holland": "NL",
    "the netherlands": "NL", "russian federation": "RU", "south korea": "KR", "north korea": "KP", "dprk": "KP",
    "taiwan": "TW", "hong kong": "HK", "vatican": "VA",
}
CASED = {"US": "US", "UK": "GB"}  # only in capitals (otherwise "us" the pronoun)
AMBIGUOUS = {"georgia", "jordan", "chad", "niger", "guinea", "georgien", "jordanien", "tschad"}
# Words after a country or demonym that mark it as the origin of an operation ("Russian hackers", "chinesische
# Hackergruppe"). Strong cues count up to two words later ("Chinese state hackers"); weak cues only directly after the
# country or after one of the MIDDLE words ("Russian ransomware gang", but not "German automotive group").
# Words like "government", "intelligence" or "military" alone are no cue: "German government websites" is a target.
STRONG_CUES = {
    "hacker", "hackers", "hacking", "state-sponsored", "state-backed", "government-backed", "nation-state", "spies", "spy",
    "cyberspies", "apt", "apts", "operatives", "agents", "gru", "fsb", "svr", "mss", "hacktivists", "hacktivist",
    "cybercriminals", "attackers", "actor", "actors", "espionage", "cyberespionage", "disinformation", "propaganda",
    "hackern", "hackergruppe", "hackergruppen", "hackergruppierung", "hackerangriff", "hackerangriffe", "hackerangriffen",
    "staatshacker", "angreifer", "angreifern", "spione", "spionen", "cyberspione", "akteure", "akteuren", "akteur",
    "hacktivisten", "cyberkriminelle", "cyberkriminellen", "spionage", "cyberspionage", "desinformation",
}
WEAK_CUES = {"group", "groups", "gang", "gangs", "operators", "operation", "campaign", "gruppe", "gruppen", "kampagne"}
MIDDLE = {"ransomware", "threat", "hacker", "hacking", "cyber", "cybercrime", "state", "apt", "espionage", "hacktivist",
          "military", "intelligence", "government", "state-sponsored", "state-backed", "staatliche", "staatlichen"}
ORIGIN_CUES = STRONG_CUES | WEAK_CUES  # for the capitals "US"/"UK", which only look at the next word


def _origin_after(after: list[str]) -> bool:
    if not after:
        return False
    if after[0] in STRONG_CUES or after[0] in WEAK_CUES:
        return True
    return len(after) > 1 and (after[1] in STRONG_CUES or (after[0] in MIDDLE and after[1] in WEAK_CUES))


ORIGIN_SUFFIXES = {"linked", "backed", "nexus", "aligned", "sponsored", "affiliated", "based", "nahe", "nahen",
                   "naher", "gesteuerte", "gesteuerten"}


@dataclass
class Places:
    names: dict[str, str] = field(default_factory=dict)   # lower-case name (1–4 words) -> ISO
    stems: list[tuple[str, str]] = field(default_factory=list)  # German stem -> ISO


def load_places(centroids: Path | None) -> Places:
    p = Places()
    if centroids and centroids.is_file():
        try:
            data = json.loads(centroids.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for cc, v in data.items():
            for key in ("name", "name_en"):
                n = str(v.get(key) or "").strip().lower()
                if n and n not in AMBIGUOUS and len(n.split()) <= 4:
                    p.names.setdefault(n, cc)
    for name, cc in ALIASES.items():
        p.names[name] = cc
    for cc, (en, de) in DEMONYMS.items():
        for d in en:
            p.names[d] = cc
        for s in de:
            p.stems.append((s, cc))
    p.stems.sort(key=lambda x: -len(x[0]))
    return p


def tokens(text: str) -> list[str]:
    return TOKEN_RE.findall(text[:MAX_TEXT])


def _strip(tok: str) -> str:
    return tok.strip(".'’_-").lower()


def _country_of(word: str, places: Places) -> str | None:
    w = word.lower().rstrip(".'’")
    if w.endswith("'s") or w.endswith("’s"):
        w = w[:-2]
    if w in places.names:
        return places.names[w]
    if len(w) >= 6:
        for stem, cc in places.stems:
            if w.startswith(stem):
                return cc
    return None


def countries(text: str, places: Places) -> tuple[str | None, list[str]]:
    """(origin, mentioned): origin = country named as the source of an operation ("Russian hackers", "China-linked",
    "russische Hackergruppe"); mentioned = all other countries in the text, in order of appearance."""
    toks = tokens(text)
    origin: str | None = None
    mentioned: list[str] = []

    def mention(cc: str) -> None:
        if cc not in mentioned:
            mentioned.append(cc)

    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in CASED or tok in ("U.S.", "U.K."):
            cc = CASED.get(tok) or ("US" if tok == "U.S." else "GB")
            if origin is None and _origin_after([_strip(x) for x in toks[i + 1:i + 3]]):
                origin = cc
            mention(cc)
            i += 1
            continue
        # "Russia-linked", "pro-Russian", "China-nexus"
        if "-" in tok:
            parts = [x for x in tok.split("-") if x]
            hit = None
            for j, part in enumerate(parts):
                cc = _country_of(part, places)
                if cc:
                    hit = cc
                    rest = {x.lower() for x in parts[j + 1:]}
                    if (rest & ORIGIN_SUFFIXES or (j > 0 and parts[j - 1].lower() == "pro")) and origin is None:
                        origin = cc
                    break
            if hit:
                mention(hit)
                i += 1
                continue
        # names of up to four words, longest first ("North Korea", "Vereinigte Arabische Emirate")
        found = None
        for n in (4, 3, 2, 1):
            if i + n > len(toks):
                continue
            phrase = " ".join(t.lower() for t in toks[i:i + n]).rstrip(".'’")
            if phrase.endswith("'s") or phrase.endswith("’s"):
                phrase = phrase[:-2]
            cc = places.names.get(phrase) if n > 1 else _country_of(toks[i], places)
            if cc and (n > 1 or len(toks[i]) > 2 or toks[i].isupper()):
                found = (cc, n)
                break
        if found:
            cc, n = found
            before = [_strip(x) for x in toks[max(0, i - 3):i]]
            if origin is None and (_origin_after([_strip(x) for x in toks[i + n:i + n + 2]])
                                   or (before and before[-1] in ("from", "aus") and any(b in STRONG_CUES for b in before[:-1]))):
                origin = cc
            mention(cc)
            i += n
            continue
        i += 1
    if origin in mentioned:
        mentioned.remove(origin)
    return origin, mentioned[:8]


# --- names (actors, malware) ----------------------------------------------------------------------------------------
COMMON_WORDS = {
    # synonyms of threat actors and malware names that are ordinary words in news texts
    "snake", "dragonfly", "turbine", "emissary", "unit", "group", "team", "operation", "hidden", "stone",
    "mustang", "outlaw", "patchwork", "transparent", "magic", "silence", "evil", "dark", "shadow", "storm", "typhoon",
    "blizzard", "sleet", "tempest", "sandstorm", "hurricane", "cyclone", "tsunami", "flood", "rain", "rocket", "kitten",
    "panda", "bear", "spider", "chollima", "tiger", "leopard", "jackal", "elephant", "monkey", "buffalo", "bat",
    "gold", "bronze", "iron", "cobalt", "carbon", "copper", "nickel", "zinc", "tin", "aluminum", "platinum",
    "agent", "trojan", "worm", "loader", "stealer", "rat", "backdoor", "ransomware", "android", "windows", "linux",
    "generic", "unknown", "malware", "phishing", "botnet", "dropper", "downloader", "miner", "crypto", "update",
    "chrome", "office", "teams", "zoom", "signal", "telegram", "discord", "steam", "apple", "google", "amazon",
    "microsoft", "fortinet", "cisco", "ivanti", "citrix", "vmware", "oracle", "sap", "adobe", "github",
}
# Actor names and aliases that are everyday words, brands, chemical elements or generic phrases in news texts (checked
# against the MISP Galaxy, October 2026). They are not recognised on their own; the actor is still found by its other
# names ("Sofacy", "Fancy Bear", "APT28").
AMBIGUOUS_NAMES = set("""
alibaba axiom basin bitter blackfly blackjack blackwood bluebottle buckeye butterfly calypso cardinal castle chrysene
cicada cleaver dogfish dune elbrus eldorado electrum foudre gorilla grayling hexane hogfish honeybee hoodoo icecap
indra jerseymikes kairos kazu krypton labubu lamberts lead leviathan lexus longhorn luder lyceum machete madi makersmark
mask masan mirage monsoon moonlight morpho nazar nian nitro packrat pickaxe pioneer polaris popeye pupa rancor reaper
scarab scimitar siesta silverfish sima slingshot snowglobe springtail strider summit superman swallowtail thor tick
topgear trident venom vermin voyeur watchdog waterbug webmasters whitefly wildcard wraith zarya amoeba
chromium helium iridium mercury oxygen silicon gallium neodymium magnesium sodium potassium calcium boron radium
plutonium polonium tantalum terbium yttrium scandium europium cerium bromine manganese sulphur
""".split()) | {
    "unnamed actor", "hacking team", "pla navy", "the big bang", "social network team", "shadow network", "global group",
    "cyber alliance", "ghost security", "storm cloud", "evil eye", "red eyes", "lucky cat", "brown fox", "common raven",
    "animal farm", "genesis day", "white bear", "st group", "iron group", "beijing group", "team bear", "test panda",
    "the mask", "rotten tomato", "golden eye dog", "sands casino", "space pirates", "dust storm",
}
CONNECTORS = {"of", "and", "the", "el", "de", "la", "del", "da", "al"}
CLEAN_NAME = re.compile(r"^[0-9A-Za-zÀ-ÖØ-öø-ÿ][0-9A-Za-zÀ-ÖØ-öø-ÿ .'’&_-]{2,60}$")


@dataclass
class NameIndex:
    """Phrase (1–4 words, lower case) -> canonical name. In the text, every word of a name must be capitalised or contain a
    digit ("Lazarus Group", "APT28", "Iron Tiger"; not "the iron tiger" or "an unnamed actor"); connecting words like
    "of" may be lower case ("Guardian of Peace")."""
    phrases: dict[str, str] = field(default_factory=dict)
    single_ok: set[str] = field(default_factory=set)

    def add(self, phrase: str, canonical: str) -> None:
        p = " ".join(phrase.replace("’", "'").split()).strip()
        if not p or not CLEAN_NAME.match(p):
            return
        low = p.lower()
        words = low.split()
        if len(words) > 4 or low in AMBIGUOUS_NAMES:
            return
        if len(words) == 1:
            if low in COMMON_WORDS or len(low) < 4:
                return
            self.single_ok.add(low)
        self.phrases.setdefault(low, canonical)

    def canonical(self, name: str) -> str | None:
        return self.phrases.get(" ".join(name.replace("’", "'").lower().split()))

    def find(self, text: str, limit: int = 6, surface: bool = False) -> list[str]:
        """Canonical names found in the text, or with surface=True the names as written there (one per canonical name:
        "Salt Typhoon" rather than the galaxy's main name for it)."""
        toks = tokens(text)
        out: list[str] = []
        seen: set[str] = set()
        i = 0
        while i < len(toks) and len(out) < limit:
            hit = None
            for n in (4, 3, 2, 1):
                if i + n > len(toks):
                    continue
                words = [x.rstrip(".,'’") for x in toks[i:i + n]]
                phrase = " ".join(w.lower() for w in words)
                if phrase.endswith("'s"):
                    phrase = phrase[:-2]
                name = self.phrases.get(phrase)
                if not name:
                    continue
                if n == 1 and phrase not in self.single_ok:
                    continue
                if not all(w[:1].isupper() or any(c.isdigit() for c in w) or (k and w in CONNECTORS)
                           for k, w in enumerate(words)):
                    continue
                hit = (name, n, " ".join(words[:-1] + [words[-1][:-2] if words[-1].endswith(("'s", "’s")) else words[-1]]))
                break
            if hit:
                if hit[0] not in seen:
                    seen.add(hit[0])
                    out.append(hit[2] if surface else hit[0])
                i += hit[1]
            else:
                i += 1
        return out


# --- kinds ----------------------------------------------------------------------------------------------------------
KINDS: dict[str, tuple[str, ...]] = {
    "ransomware": ("ransom", "erpressungstrojaner", "erpressersoftware", "lockbit", "akira", "clop", "blackcat"),
    "ddos": ("ddos", "denial-of-service", "denial of service", "überlastungsangriff"),
    "espionage": ("espionage", "spionage", "cyberspy", "cyber-spy", "spies", "spying", "spione", "ausspäh"),
    "sabotage": ("wiper", "sabotage", "destructive attack", "zerstörerisch"),
    "phishing": ("phishing", "smishing", "vishing", "quishing"),
    "breach": ("breach", "leaked", "data leak", "stolen data", "data theft", "exfiltrat", "datenleck", "datenpanne",
               "daten gestohlen", "datendiebstahl"),
    "vulnerability": ("vulnerab", "zero-day", "0-day", "exploit", "sicherheitslücke", "schwachstelle", "lücke", "patch",
                      "cve-"),
    "supply_chain": ("supply chain", "supply-chain", "lieferkette"),
    "botnet": ("botnet",),
    "disinfo": ("disinformation", "desinformation", "influence operation", "einflussnahme", "propaganda"),
    "law": ("arrest", "indict", "charged", "extradit", "sentenced", "takedown", "dismantl", "seized", "festnahme",
            "festgenommen", "anklage", "angeklagt", "verhaftet", "zerschlagen", "beschlagnahm", "razzia", "verurteilt"),
    "sanctions": ("sanction", "sanktion"),
    "policy": ("regulation", "legislation", "directive", "nis2", "nis-2", "cyber resilience act", "gesetz", "richtlinie",
               "verordnung"),
    # 3.3: physical internet infrastructure and state interference with the internet
    "cable": ("submarine cable", "undersea cable", "subsea cable", "seabed cable", "seekabel", "unterseekabel",
              "ostseekabel", "datenkabel in der ostsee"),
    "shutdown": ("internet shutdown", "internet blackout", "internet outage ordered", "internetsperre", "internet-sperre",
                 "internetabschaltung", "internet-abschaltung", "netzsperre", "censorship", "zensur", "blocked access to"),
}
_KIND_RE = {k: re.compile(r"(?<![0-9a-zà-öø-ÿ])(?:" + "|".join(re.escape(w) for w in v) + ")", re.I) for k, v in KINDS.items()}


def kinds(text: str) -> list[str]:
    t = text[:MAX_TEXT]
    return [k for k, rx in _KIND_RE.items() if rx.search(t)]


def cves(text: str) -> list[str]:
    out: list[str] = []
    for y, n in CVE_RE.findall(text[:MAX_TEXT]):
        c = f"CVE-{y}-{n}"
        if c not in out:
            out.append(c)
    return out[:10]


def word_matcher(words: Iterable[str], domains: bool = False, min_len: int = 3) -> re.Pattern[str] | None:
    """Case-insensitive whole-word matcher for product and domain names (the user's own data). Domains also match as
    the end of a longer host name (www.example.de). Vendors use min_len=2 (HP, F5)."""
    ws = sorted({w.strip() for w in words if w and len(w.strip()) >= min_len}, key=len, reverse=True)
    if not ws:
        return None
    before = r"(?<![0-9A-Za-zÀ-ÖØ-öø-ÿ-])" if domains else r"(?<![0-9A-Za-zÀ-ÖØ-öø-ÿ.-])"
    return re.compile(before + "(" + "|".join(re.escape(w) for w in ws[:500]) + r")(?![0-9A-Za-zÀ-ÖØ-öø-ÿ-]|\.[0-9A-Za-z])",
                      re.I)


def distinctive(name: str) -> bool:
    """A product name that is unlikely to be an ordinary word: several words, a digit, a hyphen, or capitals inside the
    word ("FortiOS", "NetScaler", "PAN-OS", "Exchange Server"), as the user entered it."""
    n = name.strip()
    return len(n.split()) > 1 or any(c.isdigit() or c == "-" for c in n) or any(c.isupper() for c in n[1:])


def summary(text: str, limit: int = 260) -> str:
    t = " ".join(text.split())
    if len(t) <= limit:
        return t
    cut = t[:limit]
    sp = cut.rfind(" ")
    return (cut[:sp] if sp > limit * 0.6 else cut).rstrip(" ,.;:-") + " …"


STOP = set("""the and for with from that this have has had are was were will been into over about after more than their
their they them its it's new news says said report reports warns warning amid also could would should which while
der die das und mit von für auf ist sind wird werden nach über eine einer einen einem ein dem den des auch noch wie bei
aus zum zur als nicht neue neuer neues neuen""".split())


def title_tokens(title: str) -> set[str]:
    return {w for w in (_strip(t) for t in tokens(title)) if len(w) >= 4 and w not in STOP}


def similar(a: set[str], b: set[str]) -> bool:
    if not a or not b:
        return False
    common = len(a & b)
    return common >= 3 and common / min(len(a), len(b)) >= 0.6


def as_list(raw: Any) -> list[Any]:
    if isinstance(raw, list):
        return raw
    try:
        v = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return v if isinstance(v, list) else []
