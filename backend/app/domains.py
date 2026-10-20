"""Domain monitoring for watchlist domains.

Certificate Transparency (SSLMate Cert Spotter API v1, free tier without key, optional CERTSPOTTER_API_KEY):
new certificates for the domain and its subdomains. Renewals (same names, known issuer) stay silent; alerts are
raised for names never seen in a certificate before and for a certificate authority never used before.

Lookalike domains: typosquatting permutations (omission, repetition, transposition, adjacent keys QWERTY/QWERTZ,
ASCII and Cyrillic homoglyphs, hyphenation, vowel swap, bit flips, addition, TLD swap) are checked via DNS.
NXDOMAIN = not registered; any other answer = registered. TLDs with wildcard DNS are skipped.

The first run of each domain is a baseline: CT silently records history, typosquatting reports one summary.
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from . import alerts
from .config import Settings
from .db import DB, utcnow

log = logging.getLogger("domains")

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CT_MAX_PAGES = 5
SLD_SUFFIXES = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "ltd", "plc", "nhs", "gv"}
TLD_SWAP = ("com", "net", "org", "de", "eu", "info", "biz", "co", "io", "app", "online", "shop", "site", "xyz", "at",
            "ch", "us", "cc", "top", "live", "support", "cloud", "co.uk")
KEYS_QWERTY = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
KEYS_QWERTZ = ["1234567890-", "qwertzuiop", "asdfghjkl", "yxcvbnm"]
HOMO_ASCII = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"], "m": ["rn", "nn"], "w": ["vv"],
              "d": ["cl"], "g": ["q"], "q": ["g"], "u": ["v"], "v": ["u"], "e": ["3"], "a": ["4"], "s": ["5"], "b": ["8"]}
HOMO_MULTI = {"rn": "m", "vv": "w", "cl": "d", "nn": "m"}
HOMO_CYRILLIC = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і", "j": "ј", "s": "ѕ"}
VOWELS = "aeiou"
LDH = set("abcdefghijklmnopqrstuvwxyz0123456789-")


def registrable(domain: str) -> tuple[str, str]:
    """(name, suffix) of the registrable domain, e.g. shop.example.co.uk -> (example, co.uk). Heuristic, no PSL."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and labels[-2] in SLD_SUFFIXES and len(labels[-1]) == 2:
        return labels[-3], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[-2], labels[-1]
    return labels[0], ""


def _adjacent(layout: list[str]) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = {}
    for r, row in enumerate(layout):
        for c, ch in enumerate(row):
            near = set()
            for dr in (-1, 0, 1):
                rr = r + dr
                if 0 <= rr < len(layout):
                    for dc in (-1, 0, 1):
                        cc = c + dc
                        if (dr or dc) and 0 <= cc < len(layout[rr]):
                            near.add(layout[rr][cc])
            adj.setdefault(ch, set()).update(near)
    return adj


ADJ = _adjacent(KEYS_QWERTY)
for _k, _v in _adjacent(KEYS_QWERTZ).items():
    ADJ.setdefault(_k, set()).update(_v)


def _valid_label(s: str) -> bool:
    return 0 < len(s) <= 63 and set(s) <= LDH and not s.startswith("-") and not s.endswith("-") and "--" not in s[2:4]


def permutations(domain: str, limit: int) -> list[tuple[str, str]]:
    """Lookalike candidates as (domain, technique), most plausible techniques first."""
    name, suffix = registrable(domain)
    if not suffix:
        return []
    out: dict[str, str] = {}

    def add(label: str, technique: str, sfx: str = suffix) -> None:
        if label.startswith("xn--") or _valid_label(label):
            cand = f"{label}.{sfx}"
            if cand != f"{name}.{suffix}" and cand not in out:
                out[cand] = technique

    n = name
    for i in range(len(n)):  # omission
        add(n[:i] + n[i + 1:], "omission")
    for i in range(len(n) - 1):  # transposition
        if n[i] != n[i + 1]:
            add(n[:i] + n[i + 1] + n[i] + n[i + 2:], "transposition")
    for i, ch in enumerate(n):  # adjacent key replacement
        for k in sorted(ADJ.get(ch, ())):
            add(n[:i] + k + n[i + 1:], "replacement")
    for i, ch in enumerate(n):  # repetition
        add(n[:i] + ch + n[i:], "repetition")
    for i, ch in enumerate(n):  # ASCII homoglyphs
        for h in HOMO_ASCII.get(ch, []):
            add(n[:i] + h + n[i + 1:], "homoglyph")
    for seq, rep in HOMO_MULTI.items():
        idx = n.find(seq)
        while idx >= 0:
            add(n[:idx] + rep + n[idx + len(seq):], "homoglyph")
            idx = n.find(seq, idx + 1)
    for t in TLD_SWAP:  # TLD swap
        if t != suffix:
            add(n, "tld", t)
    for i in range(1, len(n)):  # hyphenation
        add(n[:i] + "-" + n[i:], "hyphenation")
    for i, ch in enumerate(n):  # vowel swap
        if ch in VOWELS:
            for v in VOWELS:
                if v != ch:
                    add(n[:i] + v + n[i + 1:], "vowel-swap")
    for ch in "abcdefghijklmnopqrstuvwxyz0123456789":  # addition
        add(n + ch, "addition")
    for i, ch in enumerate(n):  # bitsquatting
        for b in range(8):
            f = chr(ord(ch) ^ (1 << b))
            if f in LDH and f != "-":
                add(n[:i] + f + n[i + 1:], "bitsquatting")
    for i, ch in enumerate(n):  # Cyrillic homoglyph (IDN), one character
        cy = HOMO_CYRILLIC.get(ch)
        if cy:
            try:
                add((n[:i] + cy + n[i + 1:]).encode("idna").decode("ascii"), "idn-homoglyph")
            except UnicodeError:
                continue
    return list(out.items())[:limit]


class Domains:
    def __init__(self, s: Settings, db: DB) -> None:
        self.s = s
        self.db = db
        self._ct_blocked_until = 0.0

    # --- Certificate Transparency ------------------------------------------------------------------
    async def _ct_page(self, client: httpx.AsyncClient, domain: str, after: str | None) -> list[dict[str, Any]] | None:
        params: list[tuple[str, str]] = [("domain", domain), ("include_subdomains", "true"),
                                         ("expand", "dns_names"), ("expand", "issuer")]
        if after:
            params.append(("after", after))
        headers = {"User-Agent": self.s.user_agent, "Accept": "application/json"}
        if self.s.certspotter_api_key:
            headers["Authorization"] = f"Bearer {self.s.certspotter_api_key}"
        r = await client.get(CERTSPOTTER_URL, params=params, headers=headers, timeout=30)
        if r.status_code == 429:
            try:
                wait = int(r.headers.get("Retry-After", "3600"))
            except ValueError:
                wait = 3600
            self._ct_blocked_until = asyncio.get_running_loop().time() + min(max(wait, 60), 24 * 3600)
            return None
        r.raise_for_status()
        body = r.json()
        return body if isinstance(body, list) else []

    async def ct(self, client: httpx.AsyncClient, only: int | None = None) -> int:
        domains = self.db.query("SELECT id, kind, value, label FROM watchlist WHERE kind='domain'"
                                + (" AND id=?" if only else "") + " ORDER BY id", (only,) if only else ())
        if not domains:
            if not only:
                self.db.status("certspotter", True, code="no_assets")
            return 0
        new = 0
        errors: list[str] = []
        for w in domains:
            if asyncio.get_running_loop().time() < self._ct_blocked_until:
                errors.append("rate limit (429)")
                break
            try:
                new += await self._ct_domain(client, w)
            except Exception as exc:
                errors.append(f"{w['value']}: {exc.__class__.__name__}")
        total = self.db.query("SELECT COUNT(*) AS n FROM ct_certs")[0]["n"]
        self.db.status("certspotter", not errors, "; ".join(errors)[:300], total)
        return new

    async def _ct_domain(self, client: httpx.AsyncClient, w: dict[str, Any]) -> int:
        domain = w["value"]
        key_after, key_base = f"ct_after:{domain}", f"ct_baseline:{domain}"
        after = self.db.meta_get(key_after)
        baseline = self.db.meta_get(key_base) != "done"
        known_names: set[str] = set()
        known_issuers: set[str] = set()
        for r in self.db.query("SELECT names, issuer FROM ct_certs WHERE domain=?", (domain,)):
            known_names.update(json.loads(r["names"] or "[]"))
            if r["issuer"]:
                known_issuers.add(r["issuer"])
        new = 0
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for _ in range(CT_MAX_PAGES):
            page = await self._ct_page(client, domain, after)
            if page is None:
                return new  # rate limited, continue next run
            if not page:
                if baseline:
                    self.db.meta_set(key_base, "done")
                break
            for it in page:
                if not isinstance(it, dict) or not it.get("id"):
                    continue
                after = str(it["id"])[:64]
                tbs = str(it.get("tbs_sha256") or it.get("cert_sha256") or after)[:128]
                names = sorted({str(n).lower()[:253] for n in (it.get("dns_names") or []) if isinstance(n, str)})[:100]
                iss = it.get("issuer") or {}
                issuer = str(iss.get("friendly_name") or iss.get("name") or "")[:120] if isinstance(iss, dict) else ""
                not_after = str(it.get("not_after") or "")[:25]
                inserted = self.db.insert(
                    "INSERT OR IGNORE INTO ct_certs(domain, tbs_sha256, cert_id, names, issuer, not_before, not_after, first_seen) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (domain, tbs, after, json.dumps(names), issuer or None, str(it.get("not_before") or "")[:25], not_after, now))
                if not inserted:
                    continue
                fresh_names = [n for n in names if n not in known_names]
                fresh_issuer = bool(issuer) and issuer not in known_issuers and bool(known_issuers)
                if not baseline and not_after >= now[:10]:
                    url = f"https://crt.sh/?q={domain}"
                    if fresh_issuer:
                        new += alerts.add(self.db, "ct", "medium", "ct.new_issuer",
                                          {"domain": domain, "issuer": issuer, "names": names[:10]},
                                          f"{domain}:issuer:{issuer}", asset_id=w["id"], url=url)
                    if fresh_names:
                        new += alerts.add(self.db, "ct", "low", "ct.new_cert",
                                          {"domain": domain, "issuer": issuer or "?", "names": fresh_names[:10]},
                                          f"{domain}:{tbs}", asset_id=w["id"], url=url)
                known_names.update(names)
                if issuer:
                    known_issuers.add(issuer)
            self.db.meta_set(key_after, after or "")
        return new

    # --- Typosquatting --------------------------------------------------------------------------------
    async def _exists(self, res: dns.asyncresolver.Resolver, name: str) -> bool | None:
        try:
            await res.resolve(name, "A")
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            return True
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            return None
        except dns.exception.DNSException:
            return None

    async def _details(self, res: dns.asyncresolver.Resolver, name: str) -> tuple[bool, list[str]]:
        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                ips += [r.to_text() for r in await res.resolve(name, rtype)]
            except dns.exception.DNSException:
                continue
        try:
            mx = bool(await res.resolve(name, "MX"))
        except dns.exception.DNSException:
            mx = False
        return mx, ips[:6]

    async def typos(self, only: int | None = None) -> int:
        domains = self.db.query("SELECT id, kind, value, label FROM watchlist WHERE kind='domain'"
                                + (" AND id=?" if only else "") + " ORDER BY id", (only,) if only else ())
        if not domains:
            if not only:
                self.db.status("typosquatting", True, code="no_assets")
                self.db.execute("DELETE FROM typo")
            return 0
        res = dns.asyncresolver.Resolver()
        res.lifetime = 4.0
        sem = asyncio.Semaphore(16)
        new = 0
        checked = 0
        done_bases: set[str] = set()
        for w in domains:
            name, suffix = registrable(w["value"])
            base = f"{name}.{suffix}"
            if base in done_bases or not suffix:
                continue
            done_bases.add(base)
            cands = permutations(base, self.s.typo_max)
            wildcard: dict[str, bool] = {}
            for sfx in {c.split(".", 1)[1] for c, _ in cands}:
                wildcard[sfx] = bool(await self._exists(res, f"ew-{secrets.token_hex(6)}.{sfx}"))
            prev = {r["candidate"]: r for r in self.db.query("SELECT * FROM typo WHERE domain=?", (base,))}
            baseline = self.db.meta_get(f"typo_baseline:{base}") != "done"
            now = utcnow()
            results: list[tuple[str, str, bool, bool, list[str]]] = []

            async def one(cand: str, tech: str) -> None:
                if wildcard.get(cand.split(".", 1)[1]):
                    return
                async with sem:
                    ex = await self._exists(res, cand)
                    if ex is None:
                        return
                    mx, ips = await self._details(res, cand) if ex else (False, [])
                results.append((cand, tech, ex, mx, ips))

            await asyncio.gather(*(one(c, t) for c, t in cands))
            checked += len(results)
            registered_now = []
            for cand, tech, ex, mx, ips in results:
                old = prev.get(cand)
                first = old["first_seen"] if old and old["registered"] else (now if ex else None)
                self.db.execute(
                    "INSERT INTO typo(domain, candidate, technique, registered, mx, ips, first_seen, last_checked) "
                    "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(domain, candidate) DO UPDATE SET registered=excluded.registered, "
                    "mx=excluded.mx, ips=excluded.ips, first_seen=excluded.first_seen, last_checked=excluded.last_checked",
                    (base, cand, tech, int(ex), int(mx), json.dumps(ips), first, now))
                if ex:
                    registered_now.append(cand)
                    if not baseline and not (old and old["registered"]):
                        new += alerts.add(self.db, "typo", "high" if mx else "medium", "typo.registered",
                                          {"candidate": cand, "domain": base, "technique": tech, "mx": mx, "ips": ips},
                                          f"{base}:{cand}:{now[:10]}", asset_id=w["id"],
                                          url=f"https://rdap.org/domain/{cand}")
            if baseline:
                if registered_now:
                    new += alerts.add(self.db, "typo", "medium", "typo.baseline",
                                      {"domain": base, "count": len(registered_now), "examples": sorted(registered_now)[:8]},
                                      f"{base}:baseline", asset_id=w["id"])
                self.db.meta_set(f"typo_baseline:{base}", "done")
        if done_bases and not only:
            self.db.execute(f"DELETE FROM typo WHERE domain NOT IN ({','.join('?' * len(done_bases))})", list(done_bases))
        self.db.status("typosquatting", True, "", checked)
        return new

    def listing(self, domain: str) -> dict[str, Any]:
        name, suffix = registrable(domain)
        base = f"{name}.{suffix}"
        typos = self.db.query("SELECT candidate, technique, mx, ips, first_seen, last_checked FROM typo "
                              "WHERE domain=? AND registered=1 ORDER BY first_seen DESC, candidate LIMIT 300", (base,))
        for t in typos:
            t["ips"] = json.loads(t["ips"] or "[]")
            t["mx"] = bool(t["mx"])
        certs = self.db.query("SELECT tbs_sha256, cert_id, names, issuer, not_before, not_after, first_seen FROM ct_certs "
                              "WHERE domain=? ORDER BY not_before DESC LIMIT 100", (domain,))
        for c in certs:
            c["names"] = json.loads(c["names"] or "[]")
        checked = self.db.query("SELECT COUNT(*) AS n, MAX(last_checked) AS t FROM typo WHERE domain=?", (base,))[0]
        return {"base": base, "typos": typos, "typo_checked": checked["n"], "typo_last": checked["t"],
                "typo_baseline": self.db.meta_get(f"typo_baseline:{base}") == "done",
                "certs": certs, "ct_baseline": self.db.meta_get(f"ct_baseline:{domain}") == "done",
                "ct_total": self.db.query("SELECT COUNT(*) AS n FROM ct_certs WHERE domain=?", (domain,))[0]["n"]}
