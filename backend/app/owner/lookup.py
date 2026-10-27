"""Who owns - and who uses - a public IP address: an evidence chain from the registry to a company and its contact.

1. RDAP (rdap.org -> regional internet registry): network name, holder, type of the block (assigned to an end
   customer or allocated to a provider), contacts including the abuse address.
2. Local data: AS and location of the address (DB-IP), reverse DNS (PTR).
3. Active steps (can be switched off): the TLS certificate the address presents on port 443 (organisation of OV/EV
   certificates, host names) and the websites of the domains found: imprint and schema.org data (address, contact).
4. Domains come from the certificate, the PTR name and the e-mail addresses of the holder; each is checked forward
   (does it resolve to this address?). Names of the provider (generic PTR names, the abuse domain) are left out.
5. Address -> coordinates (Nominatim); without an address the town of the certificate or of the registry entry,
   finally the location of the IP itself (DB-IP).

Registry holder and AS operator are often the hosting provider, not the company that uses the address. The result
keeps them apart and rates the user with a confidence: high (company data of a domain that resolves to this address),
medium (company data without that confirmation, certificate organisation, customer entry of the registry),
low (only the provider is known).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import ssl
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator

import dns.asyncresolver
import httpx

from ..db import DB, utcnow
from ..geo import Geo
from ..i18n import AppError
from ..tools import ToolKit, check_ip, geo_of, ptr
from .geocode import Geocoder
from .imprint import company_domain, fetch_imprint

CACHE_DAYS = 7
MAX_FORWARD = 12
MAX_IMPRINTS = 3
_GENERIC_WORDS = {"dyn", "dynamic", "dsl", "adsl", "vdsl", "pool", "dialup", "dial", "ppp", "customer", "customers", "cust",
                  "clients", "client", "static", "broadband", "residential", "dhcp", "subscriber", "cable", "cgn", "ftth",
                  "fttx", "fiber", "fibre", "cpe"}
_GENERIC_LABEL = re.compile(r"^(?:dyn|dynamic|dsl|adsl|vdsl|pool|dialup|ppp|cust|customer|static|client|host|broadband|ip|rev|"
                            r"reverse|vps|srv|nat|mobile|fiber|ftth|cgn|cpe|dhcp|subscriber|ec2)[-.]?\d", re.I)


def generic_ptr(name: str, ip: str) -> bool:
    """A PTR name the provider generates for its address range (embedded address, dynamic/static pools)."""
    n = name.lower().rstrip(".")
    labels = n.split(".")
    if _GENERIC_LABEL.match(labels[0]) or any(lb in _GENERIC_WORDS for lb in labels[:-2]):
        return True
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        o = str(addr).split(".")
        forms = ["-".join(o), "-".join(reversed(o)), ".".join(reversed(o)), "_".join(o), "".join(f"{int(x):02x}" for x in o)]
        return any(f in n for f in forms) or ".".join(o) in n
    full = addr.exploded.replace(":", "")
    return full in n.replace("-", "").replace(".", "") or str(addr).replace(":", "-") in n


def network_info(rd: dict[str, Any]) -> dict[str, Any]:
    """Network block from an RDAP answer (summary of tools._rdap_summary plus the raw remarks)."""
    s = rd.get("summary") or {}
    raw = rd.get("raw") or {}
    ents = s.get("entities") or []

    def role(r: str) -> list[dict[str, Any]]:
        return [e for e in ents if r in (e.get("roles") or [])]

    holder = next(iter(role("registrant")), None) or next((e for e in ents if (e.get("org") or e.get("fn"))
                                                           and "abuse" not in (e.get("roles") or [])), None)
    abuse = next((e.get("email") for e in role("abuse") if e.get("email")), None)
    descr = []
    for rem in raw.get("remarks") or []:
        if isinstance(rem, dict):
            for line in rem.get("description") or []:
                if isinstance(line, str) and line.strip() and len(descr) < 3:
                    descr.append(line.strip()[:120])
    contacts = []
    for r in ("administrative", "technical"):
        for e in role(r)[:2]:
            if e.get("fn") or e.get("email"):
                contacts.append({"role": r, "name": (e.get("org") or e.get("fn") or "")[:120] or None,
                                 "email": e.get("email"), "phone": e.get("tel")})
    rtype = str(s.get("type") or "")
    return {
        "name": s.get("name"), "handle": s.get("handle"), "range": s.get("range"), "country": s.get("country"),
        "type": rtype or None, "assigned": "ASSIGN" in rtype.upper(), "descr": descr,
        "holder": None if not holder else {"name": (holder.get("org") or holder.get("fn") or "")[:160] or None,
                                           "handle": holder.get("handle"), "address": holder.get("adr"),
                                           "email": holder.get("email"), "phone": holder.get("tel")},
        "abuse": abuse, "contacts": contacts[:4],
    }


def cert_fields(der: bytes) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    cert = x509.load_der_x509_certificate(der)

    def attr(name: Any, oid: Any) -> str | None:
        vals = name.get_attributes_for_oid(oid)
        return str(vals[0].value)[:160] if vals else None

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    subj = cert.subject
    return {"o": attr(subj, NameOID.ORGANIZATION_NAME), "cn": attr(subj, NameOID.COMMON_NAME),
            "l": attr(subj, NameOID.LOCALITY_NAME), "st": attr(subj, NameOID.STATE_OR_PROVINCE_NAME),
            "c": attr(subj, NameOID.COUNTRY_NAME), "issuer": attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            "san": [str(x)[:253] for x in san[:100]], "not_after": cert.not_valid_after_utc.isoformat()}


async def peer_cert(ip: str, sni: str | None = None, port: int = 443, timeout: float = 6.0) -> dict[str, Any] | None:
    """The certificate the address presents (not verified: only its contents are read)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni), timeout=timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError):
        return None
    try:
        der = w.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        w.close()
    if not der:
        return None
    try:
        return cert_fields(der)
    except Exception:  # malformed certificate of a third party
        return None


async def resolves_to(host: str, ip: str) -> bool:
    res = dns.asyncresolver.Resolver()
    res.lifetime = 3.0
    want = ipaddress.ip_address(ip)
    for name in (host, f"www.{host}"):
        try:
            ans = await res.resolve(name, "AAAA" if want.version == 6 else "A")
        except Exception:
            continue
        if any(ipaddress.ip_address(r.to_text()) == want for r in ans):
            return True
    return False


NATIONAL_TLDS = {"de", "at", "ch", "li", "lu", "nl", "be", "fr", "it", "es", "pl", "cz", "dk", "se", "no", "fi", "uk", "ie", "pt",
                 "hu", "sk", "si", "hr", "ro", "bg", "gr"}


def _country(c: dict[str, Any]) -> str | None:
    """Country of the company for the geocoder: stated, else a national domain ending (.de, .at, ...)."""
    cc = c.get("country")
    if isinstance(cc, str) and re.fullmatch(r"[A-Za-z]{2}", cc):
        return cc.upper()
    tld = (c.get("domain") or "").rsplit(".", 1)[-1]
    return ("GB" if tld == "uk" else tld.upper()) if tld in NATIONAL_TLDS else None


def _addr_query(c: dict[str, Any]) -> str:
    parts = [c.get("street"), " ".join(x for x in (c.get("postcode"), c.get("city")) if x)]
    return ", ".join(x for x in parts if x)


class Owner:
    def __init__(self, db: DB, geo: Geo, toolkit: ToolKit, geocoder: Geocoder) -> None:
        self.db = db
        self.geo = geo
        self.toolkit = toolkit
        self.geocoder = geocoder
        self.sem = asyncio.Semaphore(2)

    @staticmethod
    def target(raw: str) -> str:
        """Only single public addresses (no networks, no names)."""
        try:
            ip = str(ipaddress.ip_address((raw or "").strip().strip("[]")))
        except ValueError as exc:
            raise AppError("err.owner.ip") from exc
        return check_ip(ip, False)

    def cached(self, ip: str, active: bool | None = None) -> dict[str, Any] | None:
        """Stored result of the last 7 days (of the given mode, else the newest)."""
        sql = "SELECT payload, fetched_at FROM owner_cache WHERE ip=?" + ("" if active is None else " AND active=?")
        rows = self.db.query(sql + " ORDER BY fetched_at DESC LIMIT 1", (ip,) if active is None else (ip, int(active)))
        if not rows:
            return None
        cutoff = (datetime.now(timezone.utc) - timedelta(days=CACHE_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if rows[0]["fetched_at"] < cutoff:
            return None
        try:
            return {**json.loads(rows[0]["payload"]), "cached": True}
        except ValueError:
            return None

    def prune(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=CACHE_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.db.execute("DELETE FROM owner_cache WHERE fetched_at < ?", (cutoff,))
        old = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.db.execute("DELETE FROM web_cache WHERE fetched_at < ?", (old,))

    async def lookup(self, client: httpx.AsyncClient, web: httpx.AsyncClient, ip: str, active: bool) -> AsyncIterator[dict[str, Any]]:
        """Events: {"type": "step", "step": ...} while it runs, finally {"type": "result", "result": {...}}."""
        ev: list[dict[str, Any]] = []
        notes: list[dict[str, Any]] = []
        out: dict[str, Any] = {"ip": ip, "active": active, "fetched_at": utcnow(), "network": None, "as": None, "ptr": None,
                               "cert": None, "domains": [], "company": None, "contact": None, "abuse": None,
                               "location": None, "ip_location": None, "confidence": "low", "evidence": ev, "notes": notes}

        # 1) registry
        yield {"type": "step", "step": "rdap"}
        net: dict[str, Any] | None = None
        try:
            net = network_info(await self.toolkit.rdap(client, ip))
        except AppError as exc:
            notes.append({"code": "rdap_failed", "params": {"key": exc.key}})
        out["network"] = net
        if net:
            if net["holder"] and net["holder"]["name"]:
                ev.append({"code": "rdap_holder", "params": {"name": net["holder"]["name"], "type": net["type"] or "?"}})
            if net["assigned"]:
                ev.append({"code": "rdap_assigned", "params": {"type": net["type"]}})
            if net["abuse"]:
                out["abuse"] = {"email": net["abuse"], "source": "rdap"}

        # 2) local data and reverse DNS
        yield {"type": "step", "step": "dns"}
        g = geo_of(self.geo, ip) or {}
        if g.get("asn"):
            out["as"] = {"asn": g["asn"], "name": g.get("as_name")}
            ev.append({"code": "as", "params": {"asn": g["asn"], "name": g.get("as_name") or "?"}})
        if g.get("lat") is not None:
            out["ip_location"] = {"lat": g["lat"], "lon": g["lon"], "city": g.get("city"), "country": g.get("country")}
        name = await ptr(ip, timeout=2.5)
        generic = bool(name) and generic_ptr(name, ip)
        if name:
            out["ptr"] = {"name": name, "generic": generic}
            ev.append({"code": "ptr_generic" if generic else "ptr", "params": {"host": name}})

        # 3) certificate of the address
        cert = None
        if active:
            yield {"type": "step", "step": "tls"}
            cert = await peer_cert(ip) or (await peer_cert(ip, sni=name) if name and not generic else None)
            out["cert"] = cert
            if cert and cert.get("o"):
                ev.append({"code": "cert_org", "params": {"org": cert["o"], "town": cert.get("l") or "", "country": cert.get("c") or ""}})
            elif cert:
                ev.append({"code": "cert_names", "params": {"n": len(cert["san"]), "first": (cert.get("cn") or (cert["san"] or ["?"])[0])}})
        else:
            notes.append({"code": "passive"})

        # 4) domains and the forward check
        yield {"type": "step", "step": "domains"}
        provider: set[str] = set()
        if net and net["abuse"] and "@" in net["abuse"]:
            # the abuse mailbox belongs to the provider - unless the holder uses the same domain (own address space)
            holder_mail = (net["holder"] or {}).get("email") or ""
            own = company_domain(holder_mail.rsplit("@", 1)[1]) if "@" in holder_mail else None
            abuse_dom = company_domain(net["abuse"].rsplit("@", 1)[1])
            if abuse_dom and abuse_dom != own:
                provider.add(abuse_dom)
        cands: dict[str, set[str]] = {}

        def add(host: str | None, source: str) -> None:
            d = company_domain(host)
            if d and len(cands) < 40:
                cands.setdefault(d, set()).add(source)

        if cert:
            for h in [cert.get("cn"), *cert["san"]]:
                add(h, "cert")
        if name:
            if generic:
                provider.add(company_domain(name) or "")
            else:
                add(name, "ptr")
        if net:
            for e in [net["holder"] or {}, *net["contacts"]]:
                if e.get("email") and "@" in e["email"]:
                    add(e["email"].rsplit("@", 1)[1], "rdap")
        doms = [d for d in cands if d not in provider][:MAX_FORWARD]
        here = await asyncio.gather(*(resolves_to(d, ip) for d in doms))
        rows = []
        for d, ok in zip(doms, here):
            rows.append({"domain": d, "sources": sorted(cands[d]), "points_here": ok})
            if ok:
                ev.append({"code": "domain_here", "params": {"domain": d}})
        rows.sort(key=lambda r: -(4 * r["points_here"] + 2 * ("cert" in r["sources"]) + ("ptr" in r["sources"]) + ("rdap" in r["sources"])))
        out["domains"] = rows + [{"domain": d, "sources": sorted(cands.get(d, [])), "points_here": False, "provider": True}
                                 for d in sorted(x for x in provider if x)]

        # 5) imprint and schema.org data of the best domains
        company: dict[str, Any] | None = None
        if active:
            for r in rows[:MAX_IMPRINTS]:
                yield {"type": "step", "step": "imprint", "domain": r["domain"]}
                data, info = await fetch_imprint(web, r["domain"])
                if data and data.company:
                    company = {**data.to_dict(), "domain": r["domain"], "points_here": r["points_here"]}
                    ev.append({"code": "imprint" if data.source == "imprint" else "jsonld",
                               "params": {"domain": r["domain"], "url": data.url or ""}})
                    break
                ev.append({"code": "imprint_failed", "params": {"domain": r["domain"], "reason": info.get("error") or "none"}})
        if company is None and cert and cert.get("o"):
            company = {"source": "cert", "company": cert["o"], "city": cert.get("l"), "country": cert.get("c"),
                       "domain": next((r["domain"] for r in rows if "cert" in r["sources"]), None)}
        if company is None and net and net["assigned"] and net["holder"] and net["holder"]["name"]:
            company = {"source": "rdap", "company": net["holder"]["name"], "address": net["holder"]["address"],
                       "country": net["country"], "email": net["holder"]["email"], "phone": net["holder"]["phone"]}
        out["company"] = company
        if company:
            web_url = f"https://{company['domain']}/" if company.get("domain") else None
            contact = {"phone": company.get("phone"), "email": company.get("email"), "web": web_url,
                       "source": company["source"]}
            out["contact"] = contact if any(contact[k] for k in ("phone", "email", "web")) else None
            srcs = set(next((r["sources"] for r in rows if r["domain"] == company.get("domain")), []))
            if company["source"] in ("imprint", "jsonld"):
                # high: the domain resolves to the address AND the address side names it too (PTR, registry contact)
                # or the block is assigned to an end customer; a certificate alone can be shared hosting
                strong = company.get("points_here") and (srcs & {"ptr", "rdap"} or (net and net["assigned"]))
                out["confidence"] = "high" if strong else "medium"
            else:
                out["confidence"] = "medium"
            if company["source"] != "rdap" and not (net and net["assigned"]) and not srcs & {"ptr", "rdap"}:
                notes.append({"code": "shared_possible"})

        # 6) coordinates
        yield {"type": "step", "step": "geocode"}
        loc = None
        if company and self.geocoder.enabled:
            cc = _country(company)
            queries: list[tuple[str, str]] = []
            if company.get("street") and (company.get("postcode") or company.get("city")):
                queries.append((_addr_query(company), "address"))
            if company.get("address"):
                queries.append((str(company["address"]), "address"))
            if company.get("city"):
                queries.append((" ".join(x for x in (company.get("postcode"), company.get("city")) if x), "city"))
            for q, precision in queries:
                hit = await self.geocoder.search(client, q, cc)
                if hit:
                    loc = {**hit, "precision": precision, "source": "nominatim"}
                    ev.append({"code": "geocoded", "params": {"label": hit["label"]}})
                    break
        if loc is None and out["ip_location"]:
            loc = {**out["ip_location"], "label": ", ".join(x for x in (out["ip_location"].get("city"), out["ip_location"].get("country")) if x),
                   "precision": "ip", "source": "dbip"}
        out["location"] = loc
        self.db.execute("INSERT INTO owner_cache(ip, active, fetched_at, payload) VALUES(?,?,?,?) "
                        "ON CONFLICT(ip, active) DO UPDATE SET fetched_at=excluded.fetched_at, payload=excluded.payload",
                        (ip, int(active), out["fetched_at"], json.dumps(out)))
        yield {"type": "result", "result": out}
