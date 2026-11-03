"""Domain parsing and the public-host guard used before any outbound fetch."""

from __future__ import annotations

import pytest

from openhunter.errors import InputError
from openhunter.http_client import pinned_url
from openhunter.net import host_is_public, normalize_domain, parse_query, public_addresses, validate_fetch_url


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
