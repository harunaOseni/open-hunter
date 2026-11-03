"""Domain parsing and the public-host guard used before any outbound fetch."""

from __future__ import annotations

import pytest

from openhunter.errors import InputError
from openhunter.http_client import pinned_url
from openhunter.net import (
    host_is_public,
    host_route,
    normalize_domain,
    parse_query,
    public_addresses,
    trust_resolver_enabled,
    validate_fetch_url,
)


def test_normalize_domain_accepts_pasted_urls() -> None:
    assert normalize_domain("HTTPS://WWW.Example.COM/team") == "example.com"
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("example.com:443") == "example.com"


@pytest.mark.parametrize(
    "value",
    [
        "localhost",
        "localhost.localdomain",
        "printer.local",
        "db.internal",
        "127.0.0.1",
        "http://169.254.169.254/latest",
        "https://user:pass@example.com/secret",
        "https://10.1.2.3/",
        "not a domain",
        "",
        "http://",
    ],
)
def test_normalize_domain_rejects_non_public_targets(value: str) -> None:
    with pytest.raises(InputError):
        normalize_domain(value)


def test_parse_query_distinguishes_company_names_from_domains() -> None:
    domain = parse_query(" https://www.runpod.io/about ")
    assert domain.kind == "domain"
    assert domain.domain == "runpod.io"
    company = parse_query("Runpod")
    assert company.kind == "company"
    assert company.company == "Runpod"
    invalid = parse_query("localhost")
    assert invalid.kind == "invalid"


def test_host_is_public_uses_the_injected_resolver() -> None:
    def resolve(host: str, port: int | None):
        del port
        mapping = {
            "public.example": "1.1.1.1",
            "loop.example": "127.0.0.1",
            "meta.example": "169.254.169.254",
            "lan.example": "10.0.0.8",
        }
        # Same 5-tuple shape as socket.getaddrinfo.
        return [(0, 0, 0, "", (mapping[host], 0))]

    assert host_is_public("public.example", resolve=resolve) is True
    assert host_is_public("1.1.1.1", resolve=resolve) is True
    assert host_is_public("loop.example", resolve=resolve) is False
    assert host_is_public("meta.example", resolve=resolve) is False
    assert host_is_public("lan.example", resolve=resolve) is False
    assert host_is_public("127.0.0.1", resolve=resolve) is False
    assert host_is_public("192.168.1.9", resolve=resolve) is False
    assert host_is_public("localhost", resolve=resolve) is False


def test_public_addresses_prefer_ipv4_and_ignore_private_records() -> None:
    def resolve(host: str, port: int | None):
        del host, port
        return [
            (0, 0, 0, "", ("not-an-ip", 0)),
            (0, 0, 0, "", ("10.0.0.8", 0)),
            (0, 0, 0, "", ("2606:4700::1", 0)),
            (0, 0, 0, "", ("1.1.1.1", 0)),
        ]

    assert public_addresses("mixed.example", resolve=resolve) == ["1.1.1.1", "2606:4700::1"]
    assert host_is_public("mixed.example", resolve=resolve) is True


def test_pinned_url_targets_the_validated_address() -> None:
    assert pinned_url("https://api.github.com/orgs/runpod?x=1", "1.2.3.4") == "https://1.2.3.4/orgs/runpod?x=1"
    assert pinned_url("https://example.com/a", "2606:4700::1") == "https://[2606:4700::1]/a"


def test_validate_fetch_url_stays_on_the_company_site() -> None:
    assert (
        validate_fetch_url(
            "https://www.runpod.io/team",
            domain="runpod.io",
            resolve=lambda host, port: [(0, 0, 0, "", ("1.1.1.1", 0))],
        )
        is None
    )
    reason = validate_fetch_url(
        "https://evil.example/team",
        domain="runpod.io",
        resolve=lambda host, port: [(0, 0, 0, "", ("1.1.1.1", 0))],
    )
    assert reason is not None
    assert (
        validate_fetch_url(
            "http://runpod.io/team",
            domain="runpod.io",
            resolve=lambda host, port: [(0, 0, 0, "", ("1.1.1.1", 0))],
        )
        is not None
    )
    assert (
        validate_fetch_url(
            "https://runpod.io/team",
            domain="runpod.io",
            resolve=lambda host, port: [(0, 0, 0, "", ("10.0.0.1", 0))],
        )
        is not None
    )


def _answers(*addresses: str):
    def resolve(host: str, port: int | None):
        del host, port
        return [(0, 0, 0, "", (address, 0)) for address in addresses]

    return resolve


def test_benchmark_dns_uses_the_hostname_and_is_allowed() -> None:
    resolve = _answers("198.18.0.1", "198.19.255.1")
    route = host_route("api.github.com", resolve=resolve)
    assert route.mode == "hostname"
    assert route.addresses == ()
    assert host_is_public("api.github.com", resolve=resolve) is True
    assert public_addresses("api.github.com", resolve=resolve) == []
    assert (
        validate_fetch_url("https://www.runpod.io/team", domain="runpod.io", resolve=resolve) is None
    )


def test_literal_benchmark_address_stays_blocked() -> None:
    assert host_route("198.18.0.1").mode == "blocked"
    assert host_is_public("198.18.0.1") is False
    assert host_route("198.19.1.8").mode == "blocked"


@pytest.mark.parametrize(
    "host",
    ["10.1.2.3", "172.16.5.5", "172.31.255.255", "192.168.1.9", "127.0.0.1", "169.254.169.254"],
)
def test_real_private_ranges_stay_blocked(host: str) -> None:
    assert host_route(host, trust_resolver=False).mode == "blocked"
    assert host_is_public(host, trust_resolver=False) is False


def test_mixed_benchmark_and_global_pins_only_the_global_address() -> None:
    resolve = _answers("198.18.0.1", "1.1.1.1", "10.0.0.8")
    route = host_route("api.github.com", resolve=resolve)
    assert route.mode == "pin"
    assert route.addresses == ("1.1.1.1",)


def test_mixed_benchmark_and_private_is_blocked() -> None:
    resolve = _answers("198.18.0.1", "10.0.0.8")
    assert host_route("api.github.com", resolve=resolve).mode == "blocked"
    assert host_is_public("api.github.com", resolve=resolve) is False


def test_mapped_benchmark_address_is_hostname_mode() -> None:
    route = host_route("api.github.com", resolve=_answers("::ffff:198.18.0.1"))
    assert route.mode == "hostname"


def test_trust_resolver_skips_the_public_ip_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENHUNTER_TRUST_RESOLVER", raising=False)
    assert trust_resolver_enabled() is False
    assert host_route("10.1.2.3").mode == "blocked"
    monkeypatch.setenv("OPENHUNTER_TRUST_RESOLVER", "1")
    assert trust_resolver_enabled() is True
    route = host_route("10.1.2.3")
    assert route.mode == "hostname"
    assert host_is_public("192.168.1.9", trust_resolver=True) is True
    assert host_is_public("172.16.0.1", trust_resolver=True) is True
    assert host_route("127.0.0.1", trust_resolver=True).mode == "hostname"
    assert host_route("localhost", trust_resolver=True).mode == "blocked"
    assert host_route("db.internal", trust_resolver=True).mode == "blocked"
    monkeypatch.setenv("OPENHUNTER_TRUST_RESOLVER", "yes")
    assert trust_resolver_enabled() is True
    monkeypatch.setenv("OPENHUNTER_TRUST_RESOLVER", "0")
    assert trust_resolver_enabled() is False
