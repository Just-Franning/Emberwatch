"""Company data from a website: the imprint (German "Impressum", legally required details of a commercial website,
§ 5 DDG / § 25 MedienG / Art. 3 UWG) and schema.org data (JSON-LD "Organization").

Persons, phone, e-mail, register and VAT number are found with patterns for the usual imprint wording, the company
name in the first line that ends with a legal form and the postal address near it. Fetched are only robots.txt, the
start page and the imprint page, each page only if robots.txt allows it (also after a redirect to another host).
Everything runs through webfetch (public addresses only, size limits).
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib import robotparser
from urllib.parse import urljoin, urlsplit

import httpx

from .. import htmlparse, webfetch
from ..domains import registrable

ROBOTS_AGENT = "Emberwatch"
MAX_PAGE = 1_500_000
LINK_WORDS = ("impressum", "imprint", "legal notice", "legal-notice", "anbieterkennzeichnung", "mentions légales",
              "mentions-legales", "colofon", "aviso legal", "note legali", "legal")
FALLBACK_PATHS = ("/impressum", "/impressum/", "/imprint", "/de/impressum")

# Platforms, directories and site builders: such a domain does not belong to the company
PLATFORM_DOMAINS = frozenset({
    "facebook.com", "fb.com", "instagram.com", "linkedin.com", "xing.com", "twitter.com", "x.com", "youtube.com",
    "tiktok.com", "pinterest.com", "google.com", "google.de", "goo.gl", "g.page", "business.site", "jimdosite.com",
    "jimdo.com", "jimdofree.com", "wixsite.com", "wix.com", "wordpress.com", "blogspot.com", "blogspot.de", "weebly.com",
    "webnode.page", "webnode.com", "site123.me", "strikingly.com", "squarespace.com", "github.io", "linktr.ee", "wa.me",
    "gelbeseiten.de", "dasoertliche.de", "dastelefonbuch.de", "11880.com", "yelp.de", "yelp.com", "tripadvisor.de",
    "tripadvisor.com", "booking.com", "cylex.de", "meinestadt.de", "wlw.de", "werliefertwas.de", "kununu.com",
    "indeed.com", "t-online.de", "gmx.de", "web.de", "bit.ly", "tinyurl.com", "tumblr.com", "cloudflare.com",
    "cloudflare.net", "cloudfront.net", "amazonaws.com", "azurewebsites.net", "herokuapp.com", "netlify.app",
    "vercel.app", "pages.dev", "workers.dev", "fastly.net", "akamaiedge.net", "akamaitechnologies.com",
})

_ROLE_PATTERNS = (
    ("director", r"gesch(?:ä|ae)ftsf(?:ü|ue)hr(?:er(?:in)?|ung|ende[rn]?)"),
    ("owner", r"inhaber(?:in)?"),
    ("representative", r"vertreten\s+durch|vertretungsberechtigt(?:e[rn]?)?(?:\s+gesellschafter)?"),
    ("board", r"vorstand|vorst(?:ä|ae)nde"),
    ("partner", r"partner(?:in)?"),
    ("director", r"managing\s+directors?|ceo|director"),
)
_ROLE_RE = re.compile(r"(?P<role>" + "|".join(p for _, p in _ROLE_PATTERNS) + r")\s*(?:\(.*?\))?\s*[:\-–]?\s*(?P<rest>.*)", re.I)
_PHONE_RE = re.compile(r"(?:tel(?:efon)?|fon|phone|fernsprecher)\.?\s*(?:\(.*?\))?\s*[:\-]?\s*(\+?[0-9][0-9 ()/.\-]{5,24}[0-9])", re.I)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
_REGISTER_RE = re.compile(r"\b(HRB|HRA|GnR|PR|VR|FN)\s*[:.]?\s*(\d{1,7}\s?[A-Za-z]?)\b")
_COURT_RE = re.compile(r"Amtsgericht\s+([A-ZÄÖÜ][A-Za-zÄÖÜäöüß.\- ]{2,40}?)(?=\s*(?:[,;\n|]|HRB|HRA|$))")
_VAT_RE = re.compile(r"\b(DE\s?\d{3}\s?\d{3}\s?\d{3}|ATU\s?\d{8}|CHE[-\s]?\d{3}[.\s]?\d{3}[.\s]?\d{3})\b")
_NAME_WORD = re.compile(r"^(?:Dr\.|Prof\.|Dipl\.-[A-Za-z]+\.?|[A-ZÄÖÜ][a-zäöüß]+(?:-[A-ZÄÖÜ][a-zäöüß]+)?|von|van|de|zu|der)$")
_STOP_WORDS = ("gmbh", "ag", "kg", "ohg", "mbh", "ug", "e.k", "straße", "str.", "telefon", "registergericht")

# company name: a line that ends with a legal form
LEGAL_FORMS = (r"GmbH\s*&\s*Co\.?\s*KGaA|GmbH\s*&\s*Co\.?\s*KG|AG\s*&\s*Co\.?\s*KG|SE\s*&\s*Co\.?\s*KG|UG\s*\(haftungsbeschränkt\)"
               r"|gGmbH|GmbH|mbH|KGaA|AG|SE|UG|KG|OHG|GbR|PartG(?:\s*mbB)?|e\.\s?K\.|e\.\s?Kfm\.|e\.\s?V\.|eG"
               r"|S\.\s?A\.\s?S\.?|SAS|S\.\s?A\.?|SA|S\.à\s?r\.l\.|S\.\s?r\.\s?l\.|Srl|S\.p\.A\.|SpA|B\.\s?V\.|BV|N\.\s?V\.|NV"
               r"|Ltd\.?|Limited|LLC|L\.L\.C\.|Inc\.?|Corp\.?|Corporation|PLC|plc|LLP|Oy|Oyj|AB|ASA|A/S|ApS"
               r"|Sp\.\s?z\s?o\.\s?o\.|s\.\s?r\.\s?o\.|a\.\s?s\.|Kft\.|Zrt\.|d\.o\.o\.")
_COMPANY_RE = re.compile(rf"^(?P<name>[^\n|]{{1,100}}?\s(?P<form>{LEGAL_FORMS}))(?:\s*$|\s*[,;(|])")
# lines that name other parties or only mention the company (copyright, register, hoster, web designer)
_COMPANY_SKIP = re.compile(r"©|\(c\)|\bcopyright\b|registergericht|amtsgericht|handelsregister|umsatzsteuer|\bust\.?-?id|"
                           r"vertreten|gesch(?:ä|ae)ftsf|sitz der|inhaltlich|verantwortlich|haftung(?!sbeschr)|datenschutz|gemäß|according to|"
                           r"powered by|\b(?:hosting|webhosting|webdesign|realisierung|realisiert|konzept|gestaltung|fotos?|bilder|"
                           r"bildnachweis|design|umsetzung)\b\s*(?::|von\b|by\b|durch\b)", re.I)
# postal address: postcode and town (DE 5 digits, AT/CH 4 digits, optionally with a country prefix)
_ZIP_RE = re.compile(r"^(?:(?P<cp>D|A|CH|DE|AT)\s?[-–]\s?)?(?P<zip>\d{4,5})\s+(?P<city>[A-ZÄÖÜ][\wÄÖÜäöüß .'/()\-]{1,40}?)\s*$")
_INLINE_ADDR = re.compile(r"(?P<street>[A-ZÄÖÜ][^,|·\n]{2,60}?\s\d{1,4}\s?[a-zA-Z]?(?:\s?[-/]\s?\d{1,4}\s?[a-zA-Z]?)?)\s*[,|·]\s*"
                          r"(?:(?:D|A|CH|DE|AT)\s?[-–]\s?)?(?P<zip>\d{4,5})\s+(?P<city>[A-ZÄÖÜ][\wÄÖÜäöüß .'\-]{1,40}?)\s*(?:$|[,|·])")
_STREET_RE = re.compile(r"(straße|strasse|str\.|weg|platz|allee|gasse|ring|damm|ufer|chaussee|markt|steig|pfad|zeile|kai|"
                        r"hof\b|park\b|tor\b|graben|brücke|road|street|avenue|lane|\bpostfach\b)|\s\d{1,4}\s?[a-zA-Z]?$", re.I)
COUNTRY_WORDS = {"deutschland": "DE", "germany": "DE", "österreich": "AT", "austria": "AT", "schweiz": "CH",
                 "switzerland": "CH", "suisse": "CH", "liechtenstein": "LI", "luxemburg": "LU", "luxembourg": "LU",
                 "niederlande": "NL", "netherlands": "NL", "frankreich": "FR", "france": "FR", "belgien": "BE",
                 "belgium": "BE", "italien": "IT", "italy": "IT", "spanien": "ES", "spain": "ES", "polen": "PL", "poland": "PL",
                 "united kingdom": "GB", "vereinigtes königreich": "GB", "usa": "US", "united states": "US"}


@dataclass
class Imprint:
    url: str | None = None
    source: str = "imprint"  # imprint | jsonld
    company: str | None = None
    legal_form: str | None = None
    street: str | None = None
    postcode: str | None = None
    city: str | None = None
    country: str | None = None
    people: list[tuple[str, str]] = field(default_factory=list)  # (name, role key)
    phone: str | None = None
    email: str | None = None
    register: str | None = None
    vat_id: str | None = None

    def useful(self) -> bool:
        return bool(self.company or self.street or self.phone or self.email)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["people"] = [list(p) for p in self.people]
        return d


def company_domain(host: str | None) -> str | None:
    """Registrable domain of a host name, None for IPs, invalid names and platform domains."""
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    if not h or "." not in h or not re.fullmatch(r"[a-z0-9.-]{3,253}", h) or re.fullmatch(r"[\d.]+", h):
        return None
    name, suffix = registrable(h)
    dom = f"{name}.{suffix}" if suffix else None
    return None if not dom or dom in PLATFORM_DOMAINS else dom


# --- parsing --------------------------------------------------------------------------------------------------------
def _clean_name(candidate: str) -> str | None:
    candidate = re.sub(r"\s+", " ", candidate).strip(" ,;:.-–")
    if not candidate or len(candidate) > 60 or any(ch.isdigit() for ch in candidate):
        return None
    lowered = candidate.lower()
    if any(word in lowered for word in _STOP_WORDS) or "@" in candidate:
        return None
    words = candidate.split(" ")
    if not 2 <= len(words) <= 5 or not all(_NAME_WORD.match(w) for w in words) or not words[-1][0].isupper():
        return None
    return candidate


def _split_names(text: str) -> list[str]:
    out = []
    for part in re.split(r",|;|\bund\b|\band\b|&|/|\s{2,}", text):
        name = _clean_name(part)
        if name and name not in out:
            out.append(name)
    return out


def _deobfuscate(text: str) -> str:
    text = re.sub(r"\s*[\(\[\{]\s*(?:at|ät)\s*[\)\]\}]\s*", "@", text, flags=re.IGNORECASE)
    return re.sub(r"\s*[\(\[\{]\s*(?:dot|punkt)\s*[\)\]\}]\s*", ".", text, flags=re.IGNORECASE)


_LABEL_RE = re.compile(r"^(?:firma|firmenname|unternehmen|anbieter|diensteanbieter|betreiber|herausgeber|inhaber|company|"
                       r"operator|publisher|provider)\s*:\s*", re.I)


def _company(lines: list[str]) -> tuple[str | None, str | None, int]:
    """(name, legal form, line index) of the first line that names a company with its legal form."""
    for i, raw in enumerate(lines[:150]):
        line = _LABEL_RE.sub("", raw)
        if len(line) > 110 or _COMPANY_SKIP.search(line):
            continue
        m = _COMPANY_RE.match(line)
        if m:
            name = m.group("name").strip(" ,;:")
            if len(name) - len(m.group("form")) >= 2:
                return name, re.sub(r"\s+", " ", m.group("form")), i
    return None, None, -1


def _address(lines: list[str], start: int) -> tuple[str | None, str | None, str | None, str | None]:
    """(street, postcode, city, country) near the company line (or anywhere if there is none)."""
    order = list(range(max(0, start), min(len(lines), start + 12))) if start >= 0 else []
    order += [i for i in range(min(len(lines), 200)) if i not in order]
    for i in order:
        line = lines[i]
        m = _INLINE_ADDR.search(line)
        if m:
            return m.group("street").strip(), m.group("zip"), m.group("city").strip(), _country_after(lines, i, m.group("zip"))
        z = _ZIP_RE.match(line)
        if z and i > 0 and _STREET_RE.search(lines[i - 1]) and len(lines[i - 1]) <= 70:
            cc = {"D": "DE", "DE": "DE", "A": "AT", "AT": "AT", "CH": "CH"}.get((z.group("cp") or "").upper())
            return lines[i - 1].strip(" ,"), z.group("zip"), z.group("city").strip(), cc or _country_after(lines, i, z.group("zip"))
    return None, None, None, None


def _country_after(lines: list[str], i: int, zip_code: str) -> str | None:
    for line in lines[i: i + 2]:
        for word, cc in COUNTRY_WORDS.items():
            if re.search(rf"\b{re.escape(word)}\b", line.lower()):
                return cc
    return None


def parse_imprint(html: str | bytes, domain: str | None = None) -> Imprint:
    s = htmlparse.soup(html)
    mailtos = []
    for link in s.find_all("a", href=True):
        href = str(link["href"]).strip()
        if href.lower().startswith("mailto:"):
            address = href[7:].split("?")[0].strip()
            if _EMAIL_RE.fullmatch(address):
                mailtos.append(address)
    lines = [_deobfuscate(x) for x in htmlparse.text_lines(s)]
    if not lines:
        lines = [_deobfuscate(x) for x in htmlparse.text_lines(htmlparse.soup(html), layout=True)]
    data = Imprint()
    data.company, data.legal_form, at = _company(lines)
    data.street, data.postcode, data.city, data.country = _address(lines, at)
    for index, line in enumerate(lines):
        match = _ROLE_RE.search(line)
        if not match or match.start() > 3:
            continue
        role_text = match.group("role").lower()
        role = next((label for label, pattern in _ROLE_PATTERNS if re.fullmatch(pattern, role_text, re.I)), "director")
        rest = re.sub(r"^(?:den|die|der|das|durch)\s+", "", match.group("rest").strip(), flags=re.I)
        inner = _ROLE_RE.match(rest)
        if inner:  # "Vertreten durch den Geschäftsführer Max Mustermann"
            rest = inner.group("rest").strip()
        candidates = _split_names(rest) if rest else []
        if not candidates and index + 1 < len(lines):
            candidates = _split_names(lines[index + 1])
        for name in candidates:
            if all(name != existing for existing, _ in data.people):
                data.people.append((name, role))
    data.people = data.people[:6]
    flat = "\n".join(lines)
    phone = _PHONE_RE.search(flat)
    if phone:
        data.phone = re.sub(r"\s+", " ", phone.group(1)).strip()
    emails = [e.strip(".") for e in mailtos + _EMAIL_RE.findall(flat) if not e.lower().endswith((".png", ".jpg", ".gif", ".webp"))]
    if emails:
        preferred = [e for e in emails if domain and e.lower().endswith("@" + domain)]
        data.email = (preferred or emails)[0][:254]
    register = _REGISTER_RE.search(flat)
    if register:
        court = _COURT_RE.search(flat)
        value = f"{register.group(1)} {register.group(2).strip()}"
        data.register = (f"Amtsgericht {court.group(1).strip()}, {value}" if court else value)[:200]
    vat = _VAT_RE.search(flat)
    if vat:
        data.vat_id = re.sub(r"[\s]", "", vat.group(1))
    return data


def org_from_jsonld(objs: list[dict[str, Any]]) -> Imprint | None:
    """Company data of a schema.org Organization (or LocalBusiness, Corporation, ...)."""
    kinds = ("Organization", "Corporation", "LocalBusiness", "Company", "NGO", "GovernmentOrganization",
             "EducationalOrganization", "OnlineBusiness", "ProfessionalService", "Store")
    for o in objs:
        if not (htmlparse.ld_types(o) & set(kinds)) and not any(t.endswith(("Business", "Organization")) for t in htmlparse.ld_types(o)):
            continue
        name = htmlparse.ld_str(o.get("legalName")) or htmlparse.ld_str(o.get("name"))
        if not name:
            continue
        d = Imprint(source="jsonld", company=name[:120])
        addr = o.get("address")
        if isinstance(addr, list):
            addr = addr[0] if addr else None
        if isinstance(addr, dict):
            d.street = htmlparse.ld_str(addr.get("streetAddress"), 120)
            d.postcode = htmlparse.ld_str(addr.get("postalCode"), 16)
            d.city = htmlparse.ld_str(addr.get("addressLocality"), 80)
            c = htmlparse.ld_str(addr.get("addressCountry"), 60) or ""
            d.country = c.upper() if re.fullmatch(r"[A-Za-z]{2}", c) else COUNTRY_WORDS.get(c.lower())
        d.phone = htmlparse.ld_str(o.get("telephone"), 40)
        email = htmlparse.ld_str(o.get("email"), 254) or ""
        d.email = email[7:] if email.lower().startswith("mailto:") else (email or None)
        d.vat_id = htmlparse.ld_str(o.get("vatID"), 40)
        return d
    return None


def merge(primary: Imprint, extra: Imprint | None) -> Imprint:
    """Fills gaps of the imprint with schema.org data (the imprint wins where both have a value)."""
    if not extra:
        return primary
    for k in ("company", "street", "postcode", "city", "country", "phone", "email", "vat_id"):
        if not getattr(primary, k) and getattr(extra, k):
            setattr(primary, k, getattr(extra, k))
    return primary


def find_imprint_link(links: list[dict[str, Any]], domain: str) -> str | None:
    best: tuple[int, str] | None = None
    for ln in links:
        url = ln["url"]
        if url.startswith(("mailto:", "tel:")):
            continue
        label, target = ln["label"].lower(), url.lower()
        score = 3 if ("impressum" in label or "impressum" in target) else 2 if ("imprint" in label or "imprint" in target) else \
            1 if any(w in label or w in target for w in LINK_WORDS) else 0
        if not score or company_domain(urlsplit(url).hostname) != domain:
            continue
        if best is None or score > best[0]:
            best = (score, url)
    return best[1] if best else None


# --- fetching -------------------------------------------------------------------------------------------------------
class Robots:
    """robots.txt per host (one fetch per host and lookup). A host whose robots.txt cannot be fetched at all (no
    connection, timeout, non-public address) counts as unreachable: its pages are not requested either."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self._seen: dict[str, robotparser.RobotFileParser | None] = {}
        self._down: set[str] = set()

    @staticmethod
    def _key(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}"

    async def allowed(self, url: str) -> bool:
        key = self._key(url)
        if key not in self._seen:
            rp = None
            try:
                page = await webfetch.fetch(self.client, key + "/robots.txt", max_bytes=200_000, timeout=6)
                if page.status == 200:
                    rp = robotparser.RobotFileParser()
                    rp.parse(page.text().splitlines())
            except webfetch.FetchError as exc:
                if exc.code in ("network", "timeout", "blocked"):
                    self._down.add(key)
                rp = None  # no robots.txt: everything is allowed
            self._seen[key] = rp
        rp = self._seen[key]
        return True if rp is None else rp.can_fetch(ROBOTS_AGENT, url)

    def reachable(self, url: str) -> bool:
        return self._key(url) not in self._down


async def _get_html(client: httpx.AsyncClient, url: str) -> webfetch.Page | None:
    try:
        page = await webfetch.fetch(client, url, headers={"Accept": "text/html,application/xhtml+xml"}, max_bytes=MAX_PAGE, timeout=8)
    except webfetch.FetchError:
        return None
    return page if page.status == 200 and page.html and page.body else None


async def fetch_imprint(client: httpx.AsyncClient, domain: str) -> tuple[Imprint | None, dict[str, Any]]:
    """(company data or None, info {"home", "imprint", "error"}). error: unreachable | robots | none."""
    info: dict[str, Any] = {"domain": domain}
    robots = Robots(client)
    home = None
    excluded = False
    for cand in (f"https://{domain}/", f"https://www.{domain}/", f"http://{domain}/"):
        if not await robots.allowed(cand):
            excluded = True
            continue
        if not robots.reachable(cand):
            continue
        home = await _get_html(client, cand)
        if home:
            break
    if not home:
        return None, {**info, "error": "robots" if excluded else "unreachable"}
    info["home"] = home.url
    site = company_domain(urlsplit(home.url).hostname) or domain  # the site may redirect to its main domain
    if not await robots.allowed(home.url):  # after a redirect: the rules of the final host
        return None, {**info, "error": "robots"}

    def scan_home() -> tuple[list[dict[str, Any]], Imprint | None]:
        s = htmlparse.soup(home.body)
        ld = org_from_jsonld(htmlparse.json_ld(s))
        return htmlparse.links(s, home.url), ld

    links, ld = await asyncio.to_thread(scan_home)
    link = find_imprint_link(links, site)
    candidates = [link] if link else [urljoin(home.url, p) for p in FALLBACK_PATHS]
    for url in candidates[:4]:
        if not await robots.allowed(url):
            continue
        page = await _get_html(client, url)
        if not page:
            continue
        data = await asyncio.to_thread(parse_imprint, page.body, site)
        if data.useful():
            data.url = page.url
            info["imprint"] = page.url
            return merge(data, ld), info
    if ld:
        ld.url = home.url
        return ld, info
    return None, {**info, "error": "none"}
