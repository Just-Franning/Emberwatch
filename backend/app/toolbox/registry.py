"""Tool registry. The single description of every tool: the web interface builds the map tool bar, the actions on object
pages, the tool box and the command palette from it; the server validates every run against it.

Levels:   passive   = only data sources / databases, the target does not notice anything
          active    = harmless contact with the target (ping, DNS, HTTP request, TLS handshake)
          intrusive = goes further than normal use (zone transfer); needs explicit consent per run
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from .. import i18n
from ..config import Settings

GROUPS = ("reach", "identity", "threat", "hardening", "mail", "convert")
LEVELS = ("passive", "active", "intrusive")


@dataclass(frozen=True)
class Param:
    name: str
    kind: str  # int | str | choice | bool | text
    default: Any = None
    min: int | None = None
    max: int | None = None
    choices: tuple[str, ...] = ()
    maxlen: int = 200


@dataclass(frozen=True)
class ToolSpec:
    id: str
    group: str
    inputs: tuple[str, ...]
    level: str
    target_sees: bool
    third_party: str | None
    map: bool = False
    stream: bool = False
    params: tuple[Param, ...] = ()
    needs: str | None = None          # Settings attribute that must be set (API key)
    client_only: bool = False         # runs in the browser (no server call)
    bar: str | None = None            # "main" or "more": shown in the map tool bar of the situation view
    consent: str | None = None        # name of the bool param that requires consent (intrusive part)
    timeout: int = 90
    aliases: tuple[str, ...] = field(default_factory=tuple)


TOOLS: tuple[ToolSpec, ...] = (
    # --- reachable? which path? ---------------------------------------------------------------------------------
    ToolSpec("ping", "reach", ("ip", "domain"), "active", True, None, map=True, stream=True, bar="main",
             params=(Param("count", "int", 5, 1, 20),), timeout=70, aliases=("ping",)),
    ToolSpec("traceroute", "reach", ("ip", "domain"), "active", True, None, map=True, stream=True, bar="main",
             params=(Param("max_hops", "int", 30, 1, 40),), timeout=150, aliases=("trace", "traceroute", "tr")),
    ToolSpec("pathq", "reach", ("ip", "domain"), "active", True, None, map=True, stream=True, bar="more",
             params=(Param("probes", "int", 5, 3, 10), Param("max_hops", "int", 30, 1, 40)), timeout=180,
             aliases=("mtr", "pathq")),
    ToolSpec("globalping", "reach", ("ip", "domain", "url"), "active", True, "Globalping (jsDelivr)", map=True,
             stream=True, bar="more",
             params=(Param("mode", "choice", "ping", choices=("ping", "traceroute", "mtr", "http", "dns")),
                     Param("location", "str", "world", maxlen=80), Param("limit", "int", 8, 1, 25)),
             timeout=70, aliases=("gp", "globalping")),
    # --- who is behind it? -------------------------------------------------------------------------------------
    ToolSpec("ipinfo", "identity", ("ip", "domain"), "passive", False, "RIPEstat, AbuseIPDB", map=True, bar="main",
             aliases=("ip", "ipinfo", "info")),
    ToolSpec("rdap", "identity", ("ip", "cidr", "asn", "domain"), "passive", False, "rdap.org",
             aliases=("whois", "rdap")),
    ToolSpec("bgp", "identity", ("ip", "cidr", "asn"), "passive", False, "RIPEstat", aliases=("bgp", "rpki")),
    ToolSpec("pdns", "identity", ("ip", "domain"), "passive", False, "mnemonic Passive DNS", aliases=("pdns",)),
    ToolSpec("ct", "identity", ("domain",), "passive", False, "Cert Spotter (SSLMate)", aliases=("ct", "certs")),
    # --- dangerous? ----------------------------------------------------------------------------------------------
    ToolSpec("ioc", "threat", ("ip", "domain", "url"), "passive", False, None, aliases=("ioc",)),
    ToolSpec("greynoise", "threat", ("ip",), "passive", False, "GreyNoise", aliases=("gn", "greynoise")),
    ToolSpec("hash", "threat", ("hash",), "passive", False, "MalwareBazaar (abuse.ch)", needs="abusech_auth_key",
             aliases=("hash", "mb")),
    ToolSpec("lookalike", "threat", ("domain",), "passive", False, None, timeout=150, aliases=("typo", "lookalike")),
    # --- how well is it secured? -------------------------------------------------------------------------------
    ToolSpec("ports", "hardening", ("ip", "domain"), "active", True, None, map=True,
             params=(Param("ports", "str", "22,80,443", maxlen=80),), aliases=("ports", "port")),
    ToolSpec("tls", "hardening", ("domain", "ip", "url"), "active", True, None,
             params=(Param("port", "int", 443, 1, 65535),), aliases=("tls", "ssl")),
    ToolSpec("http", "hardening", ("url", "domain", "ip"), "active", True, None, aliases=("http", "headers")),
    ToolSpec("ssh", "hardening", ("ip", "domain"), "active", True, None,
             params=(Param("port", "int", 22, 1, 65535),), aliases=("ssh",)),
    ToolSpec("dns", "hardening", ("domain", "ip"), "active", False, "Cloudflare/Google/Quad9 DNS", map=True,
             params=(Param("resolver", "choice", "cloudflare", choices=("cloudflare", "google", "quad9", "system")),
                     Param("axfr", "bool", False)),
             consent="axfr", aliases=("dns", "dig")),
    ToolSpec("mailsec", "hardening", ("domain", "email"), "active", True, "Cloudflare DNS (1.1.1.1)",
             params=(Param("starttls", "bool", False),), aliases=("mail", "spf", "dmarc")),
    # --- mail ----------------------------------------------------------------------------------------------------
    ToolSpec("mailhdr", "mail", ("mailhdr",), "passive", False, None, map=True, bar="more",
             params=(Param("text", "text", "", maxlen=15 * 1024 * 1024), Param("lookup", "bool", False)),
             aliases=("eml", "header")),
    # --- convert -------------------------------------------------------------------------------------------------
    ToolSpec("cyberchef", "convert", ("text", "ip", "domain", "url", "email", "hash", "cve", "cidr", "asn"),
             "passive", False, "CyberChef", client_only=True, aliases=("chef", "cyberchef")),
)

BY_ID = {t.id: t for t in TOOLS}

RECIPES: dict[str, tuple[str, ...]] = {
    "server": ("ip", "domain"),
    "domain": ("domain", "email"),
    "ip": ("ip",),
    "mail": ("mailhdr",),
}


def available(spec: ToolSpec, s: Settings) -> tuple[bool, str | None]:
    if not s.tools_enabled and not spec.client_only:
        return False, "tb.na.disabled"
    if spec.needs and not getattr(s, spec.needs, None):
        return False, f"tb.na.key.{spec.needs}"
    return True, None


def third_party(spec: ToolSpec, s: Settings) -> str | None:
    """Third parties that actually receive the input with the current configuration."""
    if spec.id == "ipinfo":
        return "RIPEstat, AbuseIPDB" if s.abuseipdb_api_key else "RIPEstat"
    return spec.third_party


def describe(spec: ToolSpec, s: Settings, lang: str) -> dict[str, Any]:
    ok, why = available(spec, s)
    return {
        "id": spec.id, "group": spec.group, "inputs": list(spec.inputs), "level": spec.level,
        "target_sees": spec.target_sees, "third_party": third_party(spec, s), "map": spec.map, "stream": spec.stream,
        "client_only": spec.client_only, "bar": spec.bar, "consent": spec.consent, "aliases": list(spec.aliases),
        "name": i18n.t(lang, f"tb.tool.{spec.id}"), "desc": i18n.t(lang, f"tb.desc.{spec.id}"),
        "available": ok, "reason": i18n.t(lang, why) if why else None,
        "params": [{"name": p.name, "kind": p.kind, "default": p.default, "min": p.min, "max": p.max,
                    "choices": list(p.choices), "label": i18n.t(lang, f"tb.param.{spec.id}.{p.name}")}
                   for p in spec.params if p.kind != "text"],
    }


def recipe_info(rid: str, lang: str) -> dict[str, Any]:
    return {"id": rid, "inputs": list(RECIPES[rid]), "name": i18n.t(lang, f"tb.recipe.{rid}"),
            "desc": i18n.t(lang, f"tb.recipe_desc.{rid}")}


def effective_type(det: dict[str, Any]) -> str:
    """Input type a detection result stands for when tools are chosen: URLs count as their host (IP or domain)."""
    t = det.get("type", "text")
    if t == "url" and det.get("host"):
        try:
            ipaddress.ip_address(det["host"])
            return "ip"
        except ValueError:
            return "domain"
    return t


def applicable(det: dict[str, Any]) -> list[str]:
    """Tool ids that accept this input (URLs also feed the tools for their host, e-mail addresses the domain tools)."""
    t = det.get("type", "text")
    host_t = effective_type(det)
    out = []
    for spec in TOOLS:
        if t in spec.inputs or (t == "url" and host_t in spec.inputs):
            out.append(spec.id)
        elif t == "email" and spec.id in ("mailsec", "dns", "lookalike", "ioc", "rdap", "ct", "cyberchef"):
            out.append(spec.id)
    return out


def recipes_for(det: dict[str, Any]) -> list[str]:
    t = det.get("type", "text")
    if t == "email":
        return ["domain"]
    host_t = effective_type(det)
    return [r for r, inputs in RECIPES.items() if host_t in inputs]


def coerce_params(spec: ToolSpec, raw: dict[str, Any] | None) -> dict[str, Any]:
    """Validates parameters against the spec; unknown parameters are ignored. Raises ValueError with the name."""
    raw = raw or {}
    out: dict[str, Any] = {}
    for p in spec.params:
        v = raw.get(p.name, p.default)
        if v is None:
            v = p.default
        if p.kind == "int":
            if isinstance(v, bool):
                raise ValueError(p.name)
            try:
                v = int(v)
            except (TypeError, ValueError) as exc:
                raise ValueError(p.name) from exc
            if (p.min is not None and v < p.min) or (p.max is not None and v > p.max):
                raise ValueError(p.name)
        elif p.kind == "bool":
            if isinstance(v, str):
                v = v.lower() in ("1", "true", "yes", "on")
            v = bool(v)
        elif p.kind == "choice":
            if v not in p.choices:
                raise ValueError(p.name)
        else:  # str / text
            v = "" if v is None else str(v)
            if len(v) > p.maxlen:
                raise ValueError(p.name)
        out[p.name] = v
    return out
