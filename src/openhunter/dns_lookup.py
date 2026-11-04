"""MX lookup through the system resolver and DNS-over-HTTPS.

A zero-preference exchange of ``.`` is a null MX (RFC 7505): the domain does
not accept mail. When there is no MX and no error, public A/AAAA addresses are
returned so the verifier can apply the implicit-MX fallback itself.

Addresses in private, shared, or benchmark ranges (including 198.18.0.0/15)
are not mail hosts. Sandboxed resolvers often answer MX with NoAnswer and then
an A record of 198.18.0.1. ``OPENHUNTER_DNS_MODE=auto`` (the default) treats
NoAnswer, a timeout, or that kind of address as inconclusive and repeats the
query over DNS-over-HTTPS, Cloudflare first and Google second.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, assert_never
from urllib.parse import urlencode

import dns.exception
import dns.resolver
import httpx

from openhunter.net import is_public_unicast
from openhunter.verifier import MxLookup

DnsMode = Literal["system", "doh", "auto"]
RecordQuery = Callable[[str, str, float], tuple[list[str], str | None]]
DohFetch = Callable[[str, float], Mapping[str, Any] | None]

CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"
GOOGLE_DOH = "https://dns.google/resolve"
DEFAULT_DOH_ENDPOINTS: tuple[str, ...] = (CLOUDFLARE_DOH, GOOGLE_DOH)

_MX = 15
_A = 1
_AAAA = 28


def interpret_mx(
    records: list[tuple[int, str]],
    addresses: list[str],
    error: str | None,
) -> MxLookup:
    if error:
        return MxLookup(error=error)
    hosts: list[str] = []
    for preference, exchange in sorted(records, key=lambda item: item[0]):
        del preference
        stripped = exchange.strip()
        host = stripped.rstrip(".").lower()
        if stripped == "." or host == "":
            return MxLookup(null_mx=True)
        if host not in hosts:
            hosts.append(host)
    if hosts:
        return MxLookup(hosts=tuple(hosts))
    usable: list[str] = []
    for address in addresses:
        cleaned = address.strip()
        if not is_public_unicast(cleaned) or cleaned in usable:
            continue
        usable.append(cleaned)
    if usable:
        return MxLookup(hosts=tuple(usable), implicit_a=True)
    return MxLookup()


def dns_mode_from_env() -> DnsMode:
    """Return ``OPENHUNTER_DNS_MODE``. Unknown values use ``auto``."""
    raw = os.environ.get("OPENHUNTER_DNS_MODE", "auto").strip().lower()
    if raw == "system":
        return "system"
    if raw == "doh":
        return "doh"
    return "auto"


@dataclass(frozen=True)
class Resolution:
    """One resolver's answer, before a second resolver is allowed to replace it."""

    lookup: MxLookup
    no_answer: bool = False
    untrusted_addresses: bool = False

    def public_result(self) -> MxLookup:
        """Drop literal addresses that must not be used as a mail host."""
        looked = self.lookup
        if looked.error or looked.null_mx:
            return looked
        if not looked.hosts:
            if self.untrusted_addresses:
                return MxLookup(error="untrusted-dns")
            return looked
        kept = tuple(host for host in looked.hosts if not _literal_unusable(host))
        if not kept:
            return MxLookup(error="untrusted-dns")
        if kept == looked.hosts:
            return looked
        return MxLookup(hosts=kept, implicit_a=looked.implicit_a)


class DnspythonResolver:
    def __init__(self, timeout: float = 5.0, query: RecordQuery | None = None) -> None:
        self.timeout = timeout
        self._query = query or _dnspython_query

    def resolve(self, domain: str) -> Resolution:
        return _resolve_system(self._query, domain, self.timeout)

    def lookup(self, domain: str) -> MxLookup:
        return self.resolve(domain).public_result()


class DohResolver:
    def __init__(
        self,
        timeout: float = 5.0,
        fetch: DohFetch | None = None,
        endpoints: Sequence[str] = DEFAULT_DOH_ENDPOINTS,
    ) -> None:
        self.timeout = timeout
        self._fetch = fetch or _fetch_doh_json
        self._endpoints = tuple(endpoints)

    def resolve(self, domain: str) -> Resolution:
        return _resolve_doh(self._fetch, self._endpoints, domain, self.timeout)

    def lookup(self, domain: str) -> MxLookup:
        return self.resolve(domain).public_result()


class DnsResolver:
    """MX resolver selected by ``OPENHUNTER_DNS_MODE``."""

    def __init__(
        self,
        *,
        system: DnspythonResolver | None = None,
        doh: DohResolver | None = None,
        mode: DnsMode | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.mode: DnsMode = dns_mode_from_env() if mode is None else mode
        self.system = system if system is not None else DnspythonResolver(timeout=timeout)
        self.doh = doh if doh is not None else DohResolver(timeout=timeout)

    def lookup(self, domain: str) -> MxLookup:
        mode = self.mode
        if mode == "system":
            return self.system.resolve(domain).public_result()
        if mode == "doh":
            return self.doh.resolve(domain).public_result()
        if mode == "auto":
            return self._auto(domain)
        assert_never(mode)

    def _auto(self, domain: str) -> MxLookup:
        system = self.system.resolve(domain)
        if not _needs_doh(system):
            return system.public_result()
        doh = self.doh.resolve(domain)
        # A DNS answer from DoH replaces the system answer, including a real
        # "no MX". A transport failure does not: keep a public system fallback
        # when one exists, and otherwise report the DoH failure.
        if doh.lookup.error is None:
            return doh.public_result()
        salvaged = system.public_result()
        if salvaged.hosts or salvaged.null_mx:
            return salvaged
        return doh.public_result()


def resolver_from_env(timeout: float = 5.0) -> DnsResolver:
    return DnsResolver(timeout=timeout)


def _needs_doh(result: Resolution) -> bool:
    looked = result.lookup
    if looked.error == "timeout":
        return True
    if result.no_answer or result.untrusted_addresses:
        return True
    return bool(looked.hosts) and all(_literal_unusable(host) for host in looked.hosts)


def _resolve_system(query: RecordQuery, domain: str, timeout: float) -> Resolution:
    records, error = query(domain, "MX", timeout)
    if error == "nxdomain":
        return Resolution(MxLookup())
    if error == "timeout":
        return Resolution(MxLookup(error="timeout"))
    if error == "servfail":
        return Resolution(MxLookup(error="servfail"))
    if error not in {None, "no_answer"}:
        return Resolution(MxLookup(error="dns"))
    parsed = _parsed_mx(records)
    if error is None and parsed:
        return Resolution(interpret_mx(parsed, [], None))
    addresses, address_timeout = _collect_addresses(query, domain, timeout)
    if address_timeout and not addresses:
        return Resolution(MxLookup(error="timeout"), no_answer=True)
    looked = interpret_mx([], addresses, None)
    return Resolution(
        looked,
        no_answer=True,
        untrusted_addresses=_untrusted_address_fallback(addresses, looked),
    )


def _resolve_doh(
    fetch: DohFetch,
    endpoints: Sequence[str],
    domain: str,
    timeout: float,
) -> Resolution:
    saw_response = False
    saw_no_mx = False
    last_error = "timeout"
    for endpoint in endpoints:
        payload = fetch(_doh_url(endpoint, domain, "MX"), timeout)
        if payload is None:
            continue
        status = _dns_status(payload)
        if status is None:
            last_error = "dns"
            continue
        saw_response = True
        if status == 3:
            return Resolution(MxLookup())
        if status != 0:
            last_error = "servfail"
            continue
        parsed = _parsed_mx(_answer_data(payload, _MX))
        if parsed:
            return Resolution(interpret_mx(parsed, [], None))
        saw_no_mx = True
    if not saw_no_mx:
        if not saw_response and last_error == "timeout":
            return Resolution(MxLookup(error="timeout"))
        if not saw_response:
            return Resolution(MxLookup(error=last_error))
        return Resolution(MxLookup(error="servfail"))
    addresses = _doh_addresses(fetch, endpoints, domain, timeout)
    looked = interpret_mx([], addresses, None)
    return Resolution(
        looked,
        no_answer=True,
        untrusted_addresses=_untrusted_address_fallback(addresses, looked),
    )


def _collect_addresses(query: RecordQuery, domain: str, timeout: float) -> tuple[list[str], bool]:
    found: list[str] = []
    timed_out = False
    for record_type in ("A", "AAAA"):
        texts, error = query(domain, record_type, timeout)
        if error == "timeout":
            timed_out = True
            continue
        if error:
            continue
        found.extend(texts)
    return found, timed_out


def _doh_addresses(
    fetch: DohFetch,
    endpoints: Sequence[str],
    domain: str,
    timeout: float,
) -> list[str]:
    found: list[str] = []
    for record_name, record_type in (("A", _A), ("AAAA", _AAAA)):
        for endpoint in endpoints:
            payload = fetch(_doh_url(endpoint, domain, record_name), timeout)
            if payload is None:
                continue
            status = _dns_status(payload)
            if status == 3:
                break
            if status != 0:
                continue
            found.extend(_answer_data(payload, record_type))
            break
    return found


def _parsed_mx(records: Sequence[str]) -> list[tuple[int, str]]:
    parsed: list[tuple[int, str]] = []
    for text in records:
        item = _parse_mx_rdata(text)
        if item is not None:
            parsed.append(item)
    return parsed


def _parse_mx_rdata(data: str) -> tuple[int, str] | None:
    parts = data.strip().split(None, 1)
    if len(parts) != 2:
        return None
    try:
        preference = int(parts[0])
    except ValueError:
        return None
    if preference < 0:
        return None
    return preference, parts[1].strip()


def _untrusted_address_fallback(addresses: Sequence[str], looked: MxLookup) -> bool:
    if looked.hosts or looked.null_mx or looked.error:
        return False
    return any(address.strip() and not is_public_unicast(address) for address in addresses)


def _literal_unusable(host: str) -> bool:
    """True for a literal address that is not a public unicast mail host.

    Hostnames return False so a real exchange such as ``aspmx.l.google.com``
    is kept even when this process cannot resolve it.
    """
    cleaned = host.strip().rstrip(".")
    if not cleaned:
        return True
    try:
        ipaddress.ip_address(cleaned.split("%", 1)[0])
    except ValueError:
        return False
    return not is_public_unicast(cleaned)


def _dnspython_query(domain: str, record_type: str, timeout: float) -> tuple[list[str], str | None]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answer = resolver.resolve(domain, record_type)
    except dns.resolver.NXDOMAIN:
        return [], "nxdomain"
    except dns.resolver.NoAnswer:
        return [], "no_answer"
    except dns.resolver.NoNameservers:
        return [], "servfail"
    except dns.exception.Timeout:
        return [], "timeout"
    except dns.exception.DNSException:
        return [], "dns"
    return [record.to_text() for record in answer], None


def _fetch_doh_json(url: str, timeout: float) -> dict[str, Any] | None:
    try:
        response = httpx.get(
            url,
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "openhunter/0.1 (dns-over-https)",
            },
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
        )
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _doh_url(endpoint: str, name: str, record_type: str) -> str:
    return f"{endpoint}?{urlencode({'name': name, 'type': record_type})}"


def _dns_status(payload: Mapping[str, Any]) -> int | None:
    raw = payload.get("Status")
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.isdigit():
        return int(raw)
    return None


def _answer_data(payload: Mapping[str, Any], record_type: int) -> list[str]:
    answer = payload.get("Answer")
    if not isinstance(answer, list):
        return []
    found: list[str] = []
    for item in answer:
        if not isinstance(item, dict):
            continue
        if _as_int(item.get("type")) != record_type:
            continue
        data = item.get("data")
        if isinstance(data, str) and data.strip():
            found.append(data.strip())
    return found


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None

