"""Hostname checks shared by discovery and verification.

Fetches and SMTP probes refuse loopback, link-local, and private addresses.
That keeps a company-domain lookup from being turned into an internal scan
when a page, redirect, or MX record points at one. Addresses in 198.18.0.0/15
are the exception when the resolver returns only those: they mean a transparent
fake-IP DNS proxy, and the connection stays on the hostname.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from openhunter.errors import InputError

Resolve = Callable[[str, int | None], list[tuple[object, object, object, tuple[str, int]]]]

# RFC 2544 benchmarking range. Some egress paths publish only these addresses
# from DNS (a transparent fake-IP proxy). They are not a LAN the caller can scan.
_BENCHMARK = ipaddress.ip_network("198.18.0.0/15")

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_COMPANY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .&'+-]{0,80}")


@dataclass(frozen=True)
class ParsedQuery:
    kind: Literal["domain", "company", "invalid"]
    domain: str | None = None
    company: str | None = None
    reason: str | None = None


def normalize_domain(value: str) -> str:
    """Return the bare registrable-looking hostname from a domain or pasted URL."""
    if not isinstance(value, str) or not value.strip():
        raise InputError("A domain is required.")
    raw = value.strip()
    if any(character.isspace() for character in raw):
        raise InputError(f"{value!r} is not a domain.")
    if "://" in raw or "/" in raw:
        parts = urlsplit(raw if "://" in raw else f"https://{raw}")
        if parts.username or parts.password:
            raise InputError("The domain URL must not include credentials.")
        if parts.scheme not in {"http", "https"}:
            raise InputError("The domain must be a hostname.")
        candidate = parts.hostname or ""
    else:
        candidate = raw
    candidate = candidate.strip().lower().rstrip(".")
    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]
    if candidate.startswith("www."):
        candidate = candidate[4:]
    if not candidate:
        raise InputError("A domain is required.")
    _reject_special_host(candidate)
    if not _DOMAIN_RE.match(candidate):
        raise InputError(f"{value!r} is not a public domain.")
    return candidate


def parse_query(value: str) -> ParsedQuery:
    raw = value.strip()
    if not raw:
        return ParsedQuery("invalid", reason="A domain or company name is required.")
    try:
        return ParsedQuery("domain", domain=normalize_domain(raw))
    except InputError as exc:
        if _looks_like_domain_attempt(raw):
            return ParsedQuery("invalid", reason=str(exc))
        if _COMPANY_RE.fullmatch(raw):
            return ParsedQuery("company", company=raw)
        return ParsedQuery("invalid", reason=str(exc))


@dataclass(frozen=True)
class HostRoute:
    """How to open a connection without turning DNS into an internal scan.

    ``pin`` connects to the listed global addresses. ``hostname`` lets the OS
    resolve again, which is required for fake-IP DNS (198.18.0.0/15) and when
    OPENHUNTER_TRUST_RESOLVER is set. ``blocked`` is a private or local target.
    """

    mode: Literal["pin", "hostname", "blocked"]
    addresses: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.mode != "blocked"


def trust_resolver_enabled() -> bool:
    """True when OPENHUNTER_TRUST_RESOLVER asks us to skip the public-IP check."""
    raw = os.environ.get("OPENHUNTER_TRUST_RESOLVER", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def host_is_public(
    host: str,
    *,
    resolve: Resolve | None = None,
    trust_resolver: bool | None = None,
) -> bool:
    return host_route(host, resolve=resolve, trust_resolver=trust_resolver).allowed


def is_public_unicast(value: str) -> bool:
    """True when ``value`` is a literal global address outside 198.18.0.0/15.

    Implicit MX (an A/AAAA record used because the domain published no MX) may
    use only these addresses. Hostnames are not addresses and return False.
    Private, loopback, link-local, shared, and benchmark ranges are not mail
    hosts, including the 198.18.0.1 answers a fake-IP resolver returns for
    every name.
    """
    parsed = _parse_ip(value.strip().rstrip("."))
    if parsed is None:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return bool(parsed.is_global and not _is_benchmark(parsed))


def public_addresses(
    host: str,
    *,
    resolve: Resolve | None = None,
    trust_resolver: bool | None = None,
) -> list[str]:
    """Global addresses to pin, IPv4 first. Empty when the connection stays on the hostname."""
    route = host_route(host, resolve=resolve, trust_resolver=trust_resolver)
    if route.mode != "pin":
        return []
    return list(route.addresses)


def host_route(
    host: str,
    *,
    resolve: Resolve | None = None,
    trust_resolver: bool | None = None,
) -> HostRoute:
    """Decide whether a host may be contacted, and whether to pin the address.

    Real private ranges (10/8, 172.16/12, 192.168/16, 127/8, link-local) stay
    blocked. 198.18.0.0/15 is allowed only when every answer from the resolver
    is in that range, and the caller must then connect by hostname so a
    transparent fake-IP proxy can see the original name. A literal benchmark
    address in a URL is still refused. OPENHUNTER_TRUST_RESOLVER=1 skips this
    check and always connects by hostname.
    """
    if trust_resolver is None:
        trust_resolver = trust_resolver_enabled()
    cleaned = host.strip().lower().rstrip(".")
    if not cleaned:
        return HostRoute("blocked")
    if trust_resolver and not _is_special_name(cleaned):
        return HostRoute("hostname")
    if _is_special_name(cleaned):
        return HostRoute("blocked")
    literal = _parse_ip(cleaned)
    if literal is not None:
        if literal.is_global and not _is_benchmark(literal):
            return HostRoute("pin", (str(literal),))
        return HostRoute("blocked")
    parsed = _resolve_ips(cleaned, resolve)
    if parsed is None:
        return HostRoute("blocked")
    global_ips = [ip for ip in parsed if ip.is_global and not _is_benchmark(ip)]
    if global_ips:
        ipv4 = [str(ip) for ip in global_ips if ip.version == 4]
        ipv6 = [str(ip) for ip in global_ips if ip.version == 6]
        deduped = list(dict.fromkeys([*ipv4, *ipv6]))
        return HostRoute("pin", tuple(deduped))
    if parsed and all(_is_benchmark(ip) for ip in parsed):
        return HostRoute("hostname")
    return HostRoute("blocked")


def validate_fetch_url(url: str, *, domain: str, resolve: Resolve | None = None) -> str | None:
    """Return a reason to refuse the URL, or None when it is safe to fetch."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        return "Only https URLs are fetched."
    if parts.username or parts.password:
        return "URLs with credentials are not fetched."
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return "The URL has no host."
    if host != domain and not host.endswith("." + domain):
        return "The host is outside the company domain."
    if not host_is_public(host, resolve=resolve):
        return "The host does not resolve to a public address."
    return None


def same_site(host: str, domain: str) -> bool:
    cleaned = host.strip().lower().rstrip(".")
    return cleaned == domain or cleaned.endswith("." + domain)


def _is_special_name(host: str) -> bool:
    return (
        host == "localhost"
        or host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
    )


def _is_benchmark(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return isinstance(ip, ipaddress.IPv4Address) and ip in _BENCHMARK


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None


def _resolve_ips(
    host: str, resolve: Resolve | None
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address] | None:
    resolver = resolve or _resolve
    try:
        infos = resolver(host, None)
    except socket.gaierror:
        return None
    found: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        # getaddrinfo returns (family, type, proto, canonname, sockaddr).
        # The sockaddr is the last item; indexing [3] reads the canonname.
        try:
            sockaddr = info[-1]
            raw = sockaddr[0]
            if not isinstance(raw, str):
                continue
            parsed = _parse_ip(raw)
        except (IndexError, TypeError, ValueError):
            continue
        if parsed is not None and parsed not in found:
            found.append(parsed)
    return found


def _reject_special_host(host: str) -> None:
    if (
        host in {"localhost", "localhost.localdomain"}
        or host.endswith(".local")
        or host.endswith(".internal")
        or host.endswith(".localhost")
    ):
        raise InputError(f"{host} is not a public domain.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise InputError(f"{host} is not a public address.")
    raise InputError("Use a domain name, not an IP address.")


def _looks_like_domain_attempt(raw: str) -> bool:
    lowered = raw.lower()
    if "://" in lowered or "/" in lowered or lowered.startswith("www."):
        return True
    host = lowered.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "." in host
    return True


def _resolve(host: str, port: int | None) -> list[tuple[object, object, object, tuple[str, int]]]:
    return socket.getaddrinfo(host, port)
