"""Hostname checks shared by discovery and verification.

Fetches and SMTP probes refuse loopback, link-local, and private addresses.
That keeps a company-domain lookup from being turned into an internal scan
when a page, redirect, or MX record points at one.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from openhunter.errors import InputError

Resolve = Callable[[str, int | None], list[tuple[object, object, object, tuple[str, int]]]]

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


def host_is_public(host: str, *, resolve: Resolve | None = None) -> bool:
    return bool(public_addresses(host, resolve=resolve))


def public_addresses(host: str, *, resolve: Resolve | None = None) -> list[str]:
    """Global addresses for a host, IPv4 first.

    One private or unreadable record does not hide a public one. Callers connect
    to an address from this list instead of asking the OS to resolve again, so a
    broken IPv6 answer or a mixed DNS reply cannot turn a public host into a miss
    or a private one into a target.
    """
    cleaned = host.strip().lower().rstrip(".")
    if (
        not cleaned
        or cleaned == "localhost"
        or cleaned.endswith(".localhost")
        or cleaned.endswith(".local")
        or cleaned.endswith(".internal")
    ):
        return []
    try:
        literal = ipaddress.ip_address(cleaned)
    except ValueError:
        literal = None
    if literal is not None:
        return [cleaned] if literal.is_global else []
    resolver = resolve or _resolve
    try:
        infos = resolver(cleaned, None)
    except socket.gaierror:
        return []
    ipv4: list[str] = []
    ipv6: list[str] = []
    for info in infos:
        # getaddrinfo returns (family, type, proto, canonname, sockaddr).
        # The sockaddr is the last item; indexing [3] reads the canonname.
        try:
            sockaddr = info[-1]
            raw = sockaddr[0]
            if not isinstance(raw, str):
                continue
            parsed = ipaddress.ip_address(raw.split("%", 1)[0])
        except (IndexError, TypeError, ValueError):
            continue
        if not parsed.is_global:
            continue
        text = str(parsed)
        bucket = ipv4 if parsed.version == 4 else ipv6
        if text not in bucket:
            bucket.append(text)
    return [*ipv4, *ipv6]


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
