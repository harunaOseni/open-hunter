"""MX lookup via dnspython.

A zero-preference exchange of ``.`` is a null MX (RFC 7505): the domain does
not accept mail. When there is no MX and no error, A/AAAA addresses are
returned so the verifier can apply the implicit-MX fallback itself.
"""

from __future__ import annotations

import dns.exception
import dns.resolver

from openhunter.verifier import MxLookup


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
    unique: list[str] = []
    for address in addresses:
        if address not in unique:
            unique.append(address)
    if unique:
        return MxLookup(hosts=tuple(unique), implicit_a=True)
    return MxLookup()


class DnspythonResolver:
    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def lookup(self, domain: str) -> MxLookup:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout
        resolver.timeout = self.timeout
        try:
            answer = resolver.resolve(domain, "MX")
        except dns.resolver.NXDOMAIN:
            return MxLookup()
        except dns.resolver.NoAnswer:
            return interpret_mx([], _addresses(resolver, domain), None)
        except dns.resolver.NoNameservers:
            return MxLookup(error="servfail")
        except dns.exception.Timeout:
            return MxLookup(error="timeout")
        except dns.exception.DNSException:
            return MxLookup(error="dns")
        records = [(int(record.preference), str(record.exchange)) for record in answer]
        return interpret_mx(records, [], None)


def _addresses(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    found: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(domain, record_type)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except dns.exception.DNSException:
            continue
        found.extend(record.to_text() for record in answer)
    return found
