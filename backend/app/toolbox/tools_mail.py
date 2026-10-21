"""Mail analysis: headers or a complete .eml. Delivery path (Received hops on the map), SPF/DKIM/DMARC results,
sender consistency, links and attachments against the threat data. Nothing is executed or opened; attachments are only
hashed. Optional: attachment hashes against MalwareBazaar (third party)."""
from __future__ import annotations

import asyncio
import email
import hashlib
import html as htmllib
import ipaddress
import re
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

from ..domains import registrable
from ..logs import URL_RE, _norm_url
from ..tools import ToolError
from .common import Ctx, geo_of, ip_cell, is_global, loc_text
from .detect import is_domain, norm_host, url_host
from .registry import ToolSpec
from .result import Result, cell
from .tools_threat import mb_lookup

MAX_PART = 5 * 1024 * 1024
MAX_URLS = 200
RISKY_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "lnk", "iso", "img",
             "vhd", "vhdx", "msi", "ps1", "jar", "cpl", "reg", "chm", "one", "xll", "appx", "msix", "dll", "sys"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam", "potm", "sldm"}
HTML_EXT = {"htm", "html", "shtml", "xhtml", "svg"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "ace", "cab", "arj", "z", "xz", "bz2", "tgz"}
IP_BRACKET = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]{3,45})\]")
IPV4_ANY = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
# Links in HTML, in one linear pass (crafted mails are the use case, so no pattern may backtrack over the whole body):
# opening tags, their href (quoted or unquoted) and closing tags are found separately. Like a browser, a new <a> ends
# the previous link. A single pattern with a lazy body (<a …>(.*?)</a>) needs quadratic time on unclosed tags.
ANCHOR_TAG = re.compile(r"<a\s[^<>]*>", re.I)
# attributes one after another, so "href" inside another attribute (data-href=…, title="href=…") is not taken
ATTR = re.compile(r"""([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`=]+)))?""")
LINK_TEXT_MAX = 32 * 1024  # visible text of one link that is checked: start and end (the address is usually there)
LINK_TEXT_BUDGET = 1024 * 1024  # visible link text checked per part
# file names in link texts ("agb.pdf herunterladen") are no host names; only extensions that are no top-level domain
FILE_EXT = {"pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "odt", "ods", "odp", "rtf", "txt",
            "csv", "jpg", "jpeg", "png", "gif", "bmp", "svg", "webp", "tif", "tiff", "exe", "msi", "dll", "bat", "cmd", "ps1",
            "vbs", "js", "html", "htm", "php", "asp", "aspx", "jsp", "json", "xml", "log", "ics", "vcf", "eml", "msg", "mp3",
            "mp4", "wav", "avi", "mkv", "iso", "img", "rar", "7z", "gz", "tar", "tgz", "jar", "apk", "dmg", "lnk", "hta",
            "cfg", "ini"}
ANCHOR_CLOSE = re.compile(r"</a\s*>", re.I)
MAX_ANCHORS = 20000
TAG = re.compile(r"<[^<>]*>")
AR_RE = re.compile(r"\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)", re.I)


MAX_HEADER = 4000  # characters of a header value that are decoded


def _dec(v: Any) -> str:
    """Decoded header value (RFC 2047), at most 1000 characters. Cut before decoding: decode_header needs quadratic
    time on headers made of many encoded words."""
    if v is None:
        return ""
    raw = str(v)[:MAX_HEADER]
    try:
        return str(make_header(decode_header(raw)))[:1000]
    except Exception:  # malformed encoded words (email.errors.HeaderParseError is no ValueError)
        return raw[:1000]


def _domain_of(addr: str) -> str | None:
    if "@" not in addr:
        return None
    return norm_host(addr.rsplit("@", 1)[1].strip(" <>"))


def _org(d: str | None) -> str | None:
    if not d:
        return None
    name, sfx = registrable(d)
    return f"{name}.{sfx}" if sfx else d


def _first_ip(text: str) -> str | None:
    for m in IP_BRACKET.findall(text):
        try:
            return str(ipaddress.ip_address(m))
        except ValueError:
            continue
    for m in IPV4_ANY.findall(text):
        try:
            return str(ipaddress.ip_address(m))
        except ValueError:
            continue
    return None


def parse_received(v: str) -> dict[str, Any]:
    v = " ".join(v.split())
    body, _, date = v.rpartition(";") if ";" in v else (v, "", "")
    m_from = re.search(r"\bfrom\s+(.*?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|$)", body, re.I)
    m_by = re.search(r"\bby\s+(\S+)", body, re.I)
    m_with = re.search(r"\bwith\s+(\S+)", body, re.I)
    from_part = m_from.group(1) if m_from else ""
    ts = None
    if date.strip():
        try:
            ts = parsedate_to_datetime(date.strip())
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            ts = None
    return {"from": from_part.split()[0][:120] if from_part else None, "from_raw": from_part[:200],
            "ip": _first_ip(from_part), "by": m_by.group(1)[:120] if m_by else None,
            "with": m_with.group(1)[:30] if m_with else None, "ts": ts}


def _ext(name: str) -> list[str]:
    parts = name.lower().rsplit("/", 1)[-1].split(".")
    return parts[1:] if len(parts) > 1 else []


def anchors(html: str) -> list[tuple[str, str]]:
    """(href, inner HTML) of the links in an HTML text, linear in its length. A link ends at its closing tag, at the
    next opening <a> or at the end of the text; links without href are skipped."""
    out: list[tuple[str, str]] = []
    closes = ANCHOR_CLOSE.finditer(html)
    close = next(closes, None)
    cur: tuple[str, int] | None = None  # (href, start of the inner HTML) of the open link

    def finish(stop: int) -> None:
        nonlocal close
        assert cur is not None
        while close is not None and close.start() < cur[1]:
            close = next(closes, None)
        end = min(close.start(), stop) if close is not None else stop
        out.append((cur[0], html[cur[1]:end]))

    for m in ANCHOR_TAG.finditer(html):
        if cur is not None:
            finish(m.start())
            if len(out) >= MAX_ANCHORS:
                return out
        cur = None
        for a in ATTR.finditer(m.group(0), 2):  # after "<a"; the first href counts, as in a browser
            if a.group(1).lower() == "href":
                val = next((g for g in a.groups()[1:] if g is not None), None)
                cur = (val, m.end()) if val is not None else None
                break
    if cur is not None:
        finish(len(html))
    return out


SCHEME = re.compile(r"^[a-z][a-z0-9+.-]{0,15}:(?://)?", re.I)
ASCII_HOST = re.compile(r"(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}", re.I)


def shown_hosts(text: str, limit: int = 20) -> list[str]:
    """Domains in the visible text of a link ("www.bank.example", "https://bank.example/login", "x@bank.example").
    All of them, so hidden decoy text in front of the visible address does not hide a mismatch. Token by token instead
    of one search pattern: a pattern like (?:[\\w-]+\\.)+tld needs polynomial time on texts such as "a.a.a.a…1"."""
    out: list[str] = []
    for tok in text.split():
        if "." not in tok or len(tok) > 2100:  # no host in it; skip cheaply (long link texts are attacker-controlled)
            continue
        if tok.rstrip(".,;:!?)]}\"'»").rsplit(".", 1)[-1].lower() in FILE_EXT:  # a file name
            continue
        tok = SCHEME.sub("", tok.strip(".,;:!?()[]{}<>\"'«»"))
        host = tok.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[-1].strip(".,;:!?()[]{}<>\"'«»")
        if host.isascii():
            h = host.lower() if ASCII_HOST.fullmatch(host) else None
        else:
            h = norm_host(host)
        if h and is_domain(h) and h not in out:
            out.append(h)
            if len(out) >= limit:
                break
    return out


def _link_target(href: str) -> str:
    """The URL a browser opens for an href value: entities decoded, tabs and line breaks removed, backslashes as
    slashes (https:\\\\host\\path)."""
    return re.sub(r"[\t\r\n]", "", htmllib.unescape(href)).strip().replace("\\", "/")


def _scan_body(msg: Message) -> tuple[dict[str, str], list[tuple[str, str]], list[dict[str, Any]]]:
    """Links, shown-vs-real link mismatches and attachment hashes. CPU-bound on large mails: runs in a worker thread."""
    urls: dict[str, str] = {}
    mismatches: list[tuple[str, str]] = []
    atts: list[dict[str, Any]] = []
    budget = 15 * 1024 * 1024
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = _dec(part.get_filename()) if part.get_filename() else None
        disp = part.get_content_disposition() or ""
        ctype = part.get_content_type()
        try:
            payload = part.get_payload(decode=True) or b""
        except (ValueError, TypeError, AssertionError):
            payload = b""
        if budget <= 0:
            break
        payload = payload[:MAX_PART]
        budget -= len(payload)
        if fname or disp.startswith("attachment"):
            atts.append({"name": fname or "?", "type": ctype, "size": len(payload),
                         "sha256": hashlib.sha256(payload).hexdigest(), "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest()})
            continue
        if ctype in ("text/plain", "text/html"):
            raw = part.get_payload()
            cte = str(part.get("Content-Transfer-Encoding") or "").strip().lower()
            if isinstance(raw, str) and cte not in ("base64", "quoted-printable", "x-uuencode", "uuencode", "x-uue"):
                body = raw[:MAX_PART]  # 7bit/8bit text arrives already decoded (the mail is parsed from text)
            else:
                try:
                    body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                except LookupError:  # unknown charset name in the mail
                    body = payload.decode("utf-8", errors="replace")
            plain = htmllib.unescape(body) if ctype == "text/html" else body  # https&#58;// and similar entities
            for u in URL_RE.findall(plain):
                n = _norm_url(u)
                if n and len(urls) < MAX_URLS:
                    urls.setdefault(n, ctype)
            if ctype == "text/html":
                text_budget = LINK_TEXT_BUDGET
                for raw_href, inner in anchors(body):
                    href = _link_target(raw_href)
                    n = _norm_url(href) if href.lower().startswith(("http://", "https://")) else None
                    if n and len(urls) < MAX_URLS:
                        urls.setdefault(n, ctype)  # also links URL_RE cannot see (backslashes, entities)
                    hh = url_host(href)
                    if not hh or len(mismatches) >= 50 or text_budget <= 0:
                        continue
                    if len(inner) > 2 * LINK_TEXT_MAX:
                        inner = inner[:LINK_TEXT_MAX] + " " + inner[-LINK_TEXT_MAX:]
                    text_budget -= len(inner)
                    real = _org(norm_host(hh) or hh)
                    for sh in shown_hosts(htmllib.unescape(TAG.sub("", inner))):
                        if _org(sh) != real:
                            mismatches.append((sh, hh))
                            break
    return urls, mismatches, atts


def _read(text: str) -> dict[str, Any]:
    """Everything that only reads the mail: parsing, header values, Received hops, links and attachments. No lookups.
    CPU-bound on large or crafted mails, so it runs in a worker thread."""
    msg: Message = email.message_from_string(text)
    h = {name: _dec(msg.get(name)) for name in ("Subject", "From", "Return-Path", "Reply-To", "To", "Date", "Message-ID")}
    h["X-Mailer"] = _dec(msg.get("X-Mailer") or msg.get("User-Agent"))
    urls, mismatches, atts = _scan_body(msg)
    return {
        "h": h,
        "auth": [_dec(v) for v in (msg.get_all("Authentication-Results") or [])[:3]],
        "spf": _dec((msg.get_all("Received-SPF") or [""])[0]),
        "received": [parse_received(_dec(v)) for v in (msg.get_all("Received") or [])[:40]],
        "urls": urls, "mismatches": mismatches, "atts": atts,
        "has_body": msg.is_multipart() or bool(msg.get_payload()),
    }


async def mailhdr(ctx: Ctx, spec: ToolSpec, target: str, params: dict[str, Any]) -> dict[str, Any]:
    text = params.get("text") or ""
    if not text.strip():
        raise ToolError("err.tb.mail_empty")
    # The browser hands over the mail as text (UTF-8 decoded). Parsing it as text keeps raw UTF-8 in headers readable
    # (filename="Rechnung_März.pdf"); as bytes, Python returns such headers as Header objects with replacement characters.
    # Lone surrogates from the JSON input are replaced first. Parsing up to 15 MB is CPU work: off the event loop.
    text = text.encode("utf-8", errors="replace").decode("utf-8")
    mail = await asyncio.to_thread(_read, text)
    hd = mail["h"]
    res = Result("mailhdr", ctx.lang, hd["Subject"][:120] or "E-Mail")
    ctx.matcher.ensure()
    own_typos = {r["candidate"]: r["domain"] for r in ctx.db.query("SELECT candidate, domain FROM typo WHERE registered=1")}

    # --- sender ---------------------------------------------------------------------------------------------------
    from_raw = hd["From"]
    from_name, from_addr = (getaddresses([from_raw]) or [("", "")])[0]
    from_dom = _domain_of(from_addr)
    rp = getaddresses([hd["Return-Path"]])
    rp_dom = _domain_of(rp[0][1]) if rp and rp[0][1] else None
    rt = getaddresses([hd["Reply-To"]])
    rt_dom = _domain_of(rt[0][1]) if rt and rt[0][1] else None
    mid = hd["Message-ID"]
    mid_dom = norm_host(mid.strip("<> ").rsplit("@", 1)[1]) if "@" in mid else None
    res.kv(res.t("tb.sec.sender"), [
        (res.t("tb.k.subject"), hd["Subject"]), ("From", from_raw), ("Return-Path", hd["Return-Path"]),
        ("Reply-To", hd["Reply-To"]), ("To", hd["To"][:300]), (res.t("tb.k.date"), hd["Date"]),
        ("Message-ID", cell(mid, mono=True) if mid else None),
        ("X-Mailer", hd["X-Mailer"] or None)])
    if from_dom:
        res.rel("domain", from_dom)
        if from_dom in own_typos:
            res.find("high", "tb.f.mail_lookalike", domain=from_dom, own=own_typos[from_dom])
        if ctx.matcher.match("domain", from_dom):
            res.find("high", "tb.f.mail_from_ioc", domain=from_dom)
    if rt_dom and from_dom and _org(rt_dom) != _org(from_dom):
        res.find("medium", "tb.f.mail_replyto", "tb.fd.mail_replyto", rt=rt_dom, frm=from_dom)
    if rp_dom and from_dom and _org(rp_dom) != _org(from_dom):
        res.find("low", "tb.f.mail_returnpath", rp=rp_dom, frm=from_dom)
    if from_name:
        shown = re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", from_name)
        if shown and from_dom and any(_org(norm_host(d) or d) != _org(from_dom) for d in shown):
            res.find("medium", "tb.f.mail_display", name=from_name[:80], frm=from_dom)
    if mid_dom and from_dom and _org(mid_dom) != _org(from_dom):
        res.find("info", "tb.f.mail_msgid", mid=mid_dom)

    # --- authentication ---------------------------------------------------------------------------------------------
    ars = mail["auth"]
    auth: dict[str, str] = {}
    for v in ars[:1]:  # the topmost header comes from the receiving system
        for k, val in AR_RE.findall(v):
            auth.setdefault(k.lower(), val.lower())
    rspf = mail["spf"].split(" ", 1)[0].lower()
    if "spf" not in auth and rspf:
        auth["spf"] = rspf
    arow = []
    for k in ("spf", "dkim", "dmarc", "arc"):
        val = auth.get(k)
        if not val:
            arow.append([k.upper(), cell(res.t("tb.v.not_present"), sev="info")])
            continue
        sev = "ok" if val == "pass" else "high" if (k == "dmarc" and val == "fail") else "medium" if val in ("fail", "permerror") else "low"
        arow.append([k.upper(), cell(val, sev=sev)])
        if val != "pass" and k in ("spf", "dkim", "dmarc"):
            res.find(sev if sev != "ok" else "info", "tb.f.mail_auth", mech=k.upper(), val=val)
    res.table(res.t("tb.sec.auth"), [res.t("tb.c.check"), res.t("tb.c.result")], arow,
              note=res.t("tb.n.auth") if ars else res.t("tb.n.auth_none"))
    if ars:
        res.text(res.t("tb.sec.auth_raw"), "\n\n".join(ars[:3]), mono=True)

    # --- delivery path ----------------------------------------------------------------------------------------------
    recv = mail["received"]
    hops = list(reversed(recv))
    rows = []
    coords = []
    prev = None
    for i, h in enumerate(hops, 1):
        ip = h["ip"]
        g = geo_of(ctx, ip) if ip and is_global(ip) else None
        sev = None
        if ip and is_global(ip):
            hits = ctx.matcher.match("ip", ip)
            if any(x["kind"] in ("c2", "ioc", "drop") for x in hits):
                sev = "high"
                res.find("high", "tb.f.mail_hop_bad", ip=ip, n=i)
            elif any(x["kind"] == "tor" for x in hits):
                sev = "medium"
                res.find("medium", "tb.f.mail_hop_tor", ip=ip, n=i)
            res.rel("ip", ip)
        delay = None
        if prev is not None and h["ts"] is not None:
            delay = int((h["ts"] - prev).total_seconds())
        if h["ts"] is not None:
            prev = h["ts"]
        rows.append([i, cell(h["from"] or "–", mono=True), ip_cell(ip, sev=sev) if ip else "–", loc_text(ctx, g) or "–",
                     cell(h["by"] or "–", mono=True), h["with"] or "",
                     h["ts"].strftime("%Y-%m-%d %H:%M:%S %z") if h["ts"] else "–",
                     cell(f"{delay} s", sev="low" if delay is not None and (delay < -60 or delay > 3600) else None) if delay is not None else ""])
        if g and g.get("lat") is not None:
            res.point(g, "mail", str(i), ip, sev=sev)
            coords.append((g["lon"], g["lat"]))
    res.table(res.t("tb.sec.path"), ["#", res.t("tb.c.from"), "IP", res.t("tb.c.place"), res.t("tb.c.by"), "with",
                                      res.t("tb.c.date"), res.t("tb.c.delay")], rows, note=res.t("tb.n.received"),
              empty=res.t("tb.v.no_received"))
    res.path(coords)
    if hops and hops[0]["ts"] and hops[-1]["ts"]:
        total = int((hops[-1]["ts"] - hops[0]["ts"]).total_seconds())
        if total > 6 * 3600:
            res.find("low", "tb.f.mail_slow", h=round(total / 3600, 1))
    date_hdr = hd["Date"]
    if date_hdr:
        try:
            dts = parsedate_to_datetime(str(date_hdr))
            if dts.tzinfo and (dts - datetime.now(timezone.utc)).total_seconds() > 86400:
                res.find("low", "tb.f.mail_future")
        except (TypeError, ValueError, IndexError):
            pass

    # --- body: links and attachments ----------------------------------------------------------------------------------
    urls, mismatches, atts = mail["urls"], mail["mismatches"], mail["atts"]
    urows = []
    for u in list(urls)[:MAX_URLS]:
        host = url_host(u) or ""
        hits = ctx.matcher.match("url", u) + ctx.matcher.match("domain", host)
        if host and not norm_host(host):
            hits += ctx.matcher.match("ip", host)
        sev = None
        note = ""
        if hits:
            sev = "high"
            note = ", ".join(sorted({x.get("malware") or x.get("kind") for x in hits if x}))[:80]
            res.find("high", "tb.f.mail_url_ioc", host=host)
        elif host in own_typos:
            sev = "high"
            note = res.t("tb.v.lookalike_of", own=own_typos[host])
            res.find("high", "tb.f.mail_lookalike", domain=host, own=own_typos[host])
        elif host and not norm_host(host):
            sev = "low"
            note = res.t("tb.v.ip_link")
        urows.append([cell(u[:200], mono=True, sev=sev), cell(host, obj=("domain", host) if norm_host(host) else None), note])
        if host and norm_host(host):
            res.rel("domain", host)
    res.table(res.t("tb.sec.links", n=len(urls)), ["URL", res.t("tb.c.host"), res.t("tb.c.note")], urows,
              note=res.t("tb.n.links"), empty=res.t("tb.v.no_links") if mail["has_body"] else None)
    for shown, hh in mismatches[:5]:
        res.find("medium", "tb.f.mail_mismatch", "tb.fd.mail_mismatch", shown=shown, host=hh)
    lookup = bool(params.get("lookup")) and bool(ctx.s.abusech_auth_key)
    if lookup and atts:
        res.third_party = "MalwareBazaar (abuse.ch)"
    arows = []
    for a in atts[:30]:
        ext = _ext(a["name"])
        sev = None
        why = ""
        if ext and ext[-1] in RISKY_EXT:
            sev, why = "high", res.t("tb.v.att_exec")
        elif ext and ext[-1] in MACRO_EXT:
            sev, why = "medium", res.t("tb.v.att_macro")
        elif ext and ext[-1] in HTML_EXT:
            sev, why = "medium", res.t("tb.v.att_html")
        elif ext and ext[-1] in ARCHIVE_EXT:
            sev, why = "low", res.t("tb.v.att_archive")
        if len(ext) >= 2 and ext[-2] in ("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt") and ext[-1] in RISKY_EXT:
            sev, why = "high", res.t("tb.v.att_double")
        mb = ""
        if lookup:
            try:
                r = await mb_lookup(ctx, a["sha256"])
                if r["status"] == "ok":
                    sev = "high"
                    mb = r["data"].get("signature") or res.t("tb.v.mb_known")
                else:
                    mb = res.t("tb.v.mb_unknown_short")
            except ToolError as exc:
                mb = exc.render(ctx.lang)
        if sev:
            res.find(sev, "tb.f.mail_att", name=a["name"][:80], why=why or mb)
        arows.append([cell(a["name"][:120], sev=sev), a["type"], a["size"], cell(a["sha256"], mono=True, obj=("hash", a["sha256"])),
                      why, mb])
    res.table(res.t("tb.sec.attachments", n=len(atts)), [res.t("tb.c.file"), res.t("tb.c.type"), res.t("tb.c.size"), "SHA-256",
                                                         res.t("tb.c.note"), "MalwareBazaar" if lookup else ""], arows,
              note=res.t("tb.n.attachments"))
    summary = res.t("tb.s.mail", hops=len(hops), spf=auth.get("spf", "–"), dkim=auth.get("dkim", "–"),
                    dmarc=auth.get("dmarc", "–"), links=len(urls), atts=len(atts))
    return res.done(spec, summary)
