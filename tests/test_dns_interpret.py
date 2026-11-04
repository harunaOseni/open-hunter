"""MX interpretation, including the null-MX convention and address fallback."""

from __future__ import annotations

import pytest

from openhunter.dns_lookup import interpret_mx


def test_orders_mx_hosts_and_strips_trailing_dots() -> None:
    looked = interpret_mx([(20, "mx2.example.com."), (10, "mx1.example.com.")], [], None)
    assert looked.hosts == ("mx1.example.com", "mx2.example.com")
    assert looked.null_mx is False
    assert looked.error is None


def test_null_mx_means_the_domain_does_not_accept_mail() -> None:
    looked = interpret_mx([(0, ".")], ["1.1.1.1"], None)
    assert looked.null_mx is True
    assert looked.hosts == ()


def test_address_fallback_when_no_mx_exists() -> None:
    looked = interpret_mx([], ["1.1.1.1", "1.1.1.1"], None)
    assert looked.hosts == ("1.1.1.1",)
    assert looked.implicit_a is True


def test_public_address_is_kept_beside_a_fake_ip() -> None:
    looked = interpret_mx([], ["198.18.0.1", "1.1.1.1", "1.1.1.1"], None)
    assert looked.hosts == ("1.1.1.1",)
    assert looked.implicit_a is True


@pytest.mark.parametrize(
    "address",
    [
        "198.18.0.1",
        "198.19.255.1",
        "10.0.0.8",
        "172.16.0.1",
        "192.168.1.9",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "::ffff:198.18.0.1",
    ],
)
def test_private_and_fake_ip_addresses_are_not_mail_hosts(address: str) -> None:
    looked = interpret_mx([], [address], None)
    assert looked.hosts == ()
    assert looked.implicit_a is False
    assert looked.null_mx is False


def test_dns_error_is_preserved() -> None:
    looked = interpret_mx([], [], "timeout")
    assert looked.error == "timeout"
    assert looked.hosts == ()
