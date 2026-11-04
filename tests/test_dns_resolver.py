"""DNS-over-HTTPS fallback when the system resolver cannot be trusted.

These tests mock both resolvers. They do not send DNS or SMTP traffic.
"""

from __future__ import annotations

import pytest

from openhunter.dns_lookup import (
    CLOUDFLARE_DOH,
    GOOGLE_DOH,
    DnsResolver,
    DnspythonResolver,
    DohResolver,
    dns_mode_from_env,
    resolver_from_env,
)
from openhunter.verifier import SmtpReply, verify_email

ANTHROPIC_MX = {
    "Status": 0,
    "Answer": [
        {"name": "anthropic.com.", "type": 15, "TTL": 300, "data": "1 aspmx.l.google.com."},
        {"name": "anthropic.com.", "type": 15, "TTL": 300, "data": "5 alt1.aspmx.l.google.com."},
        {"name": "anthropic.com.", "type": 15, "TTL": 300, "data": "5 alt2.aspmx.l.google.com."},
        {"name": "anthropic.com.", "type": 15, "TTL": 300, "data": "10 alt3.aspmx.l.google.com."},
        {"name": "anthropic.com.", "type": 15, "TTL": 300, "data": "10 alt4.aspmx.l.google.com."},
    ],
}

GOOGLE_HOSTS = (
    "aspmx.l.google.com",
    "alt1.aspmx.l.google.com",
    "alt2.aspmx.l.google.com",
    "alt3.aspmx.l.google.com",
    "alt4.aspmx.l.google.com",
)


class ScriptedSmtp:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def probe_mailbox(self, mx_hosts: list[str], recipient: str, *, timeout: float, port: int = 25) -> SmtpReply:
        del mx_hosts, timeout, port
        self.calls.append(recipient)
        if recipient.startswith("zz-no-such-mailbox-"):
            return SmtpReply(550, "no such user", None)
        return SmtpReply(250, "ok", None)


def _sandbox_query(domain: str, record_type: str, timeout: float) -> tuple[list[str], str | None]:
    del domain, timeout
    if record_type == "MX":
        return [], "no_answer"
    if record_type == "A":
        return ["198.18.0.1"], None
    return [], "no_answer"


def _system(query=_sandbox_query) -> DnspythonResolver:
    return DnspythonResolver(timeout=1, query=query)


def _doh(payloads: dict[str, dict] | None = None, *, fail: bool = False) -> tuple[DohResolver, list[str]]:
    urls: list[str] = []

    def fetch(url: str, timeout: float) -> dict | None:
        del timeout
        urls.append(url)
        if fail:
            return None
        if payloads is not None:
            for needle, payload in payloads.items():
                if needle in url:
                    return payload
            return {"Status": 2}
        if "type=MX" in url or "type=A" in url:
            return ANTHROPIC_MX if "type=MX" in url else {"Status": 0, "Answer": []}
        return {"Status": 2}

    return DohResolver(timeout=1, fetch=fetch), urls


def test_dns_mode_defaults_to_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENHUNTER_DNS_MODE", raising=False)
    assert dns_mode_from_env() == "auto"
    assert resolver_from_env(timeout=1).mode == "auto"
    monkeypatch.setenv("OPENHUNTER_DNS_MODE", "DOH")
    assert dns_mode_from_env() == "doh"
    monkeypatch.setenv("OPENHUNTER_DNS_MODE", "system")
    assert dns_mode_from_env() == "system"
    monkeypatch.setenv("OPENHUNTER_DNS_MODE", "bogus")
    assert dns_mode_from_env() == "auto"


def test_auto_replaces_fake_ip_fallback_with_google_mx() -> None:
    doh, urls = _doh()
    resolver = DnsResolver(system=_system(), doh=doh, mode="auto")
    looked = resolver.lookup("anthropic.com")
    assert looked.hosts == GOOGLE_HOSTS
    assert looked.implicit_a is False
    assert looked.error is None
    assert "198.18.0.1" not in looked.hosts
    assert urls
    assert urls[0].startswith(CLOUDFLARE_DOH + "?")
    assert "name=anthropic.com" in urls[0]
    assert "type=MX" in urls[0]
    assert all("dns.google" not in url for url in urls)


def test_anthropic_style_mx_is_what_smtp_probes() -> None:
    doh, _urls = _doh()
    resolver = DnsResolver(system=_system(), doh=doh, mode="auto")
    prober = ScriptedSmtp()
    result = verify_email(
        "Researcher@Anthropic.com",
        resolver=resolver,
        prober=prober,
        host_checker=lambda host: True,
    )
    assert result.email == "researcher@anthropic.com"
    assert result.mx_hosts == GOOGLE_HOSTS
    assert result.mx_valid is True
    assert result.status == "valid"
    assert result.reason is None
    assert result.smtp_code == 250
    assert prober.calls[0] == "researcher@anthropic.com"
    assert prober.calls[1].startswith("zz-no-such-mailbox-")
    assert "198.18.0.1" not in result.mx_hosts


def test_system_mode_does_not_call_doh_and_drops_the_fake_ip() -> None:
    def fetch(url: str, timeout: float) -> dict:
        del timeout
        raise AssertionError(url)

    resolver = DnsResolver(system=_system(), doh=DohResolver(timeout=1, fetch=fetch), mode="system")
    looked = resolver.lookup("anthropic.com")
    assert looked.hosts == ()
    assert looked.error == "untrusted-dns"
    prober = ScriptedSmtp()
    result = verify_email(
        "researcher@anthropic.com",
        resolver=resolver,
        prober=prober,
        host_checker=lambda host: True,
    )
    assert result.status == "unknown"
    assert result.reason == "untrusted-dns"
    assert result.mx_valid is False
    assert result.mx_hosts == ()
    assert prober.calls == []
    assert result.status != "valid"


def test_doh_mode_does_not_consult_the_system_resolver() -> None:
    def query(domain: str, record_type: str, timeout: float) -> tuple[list[str], str | None]:
        del domain, record_type, timeout
        raise AssertionError("system resolver was used")

    doh, urls = _doh()
    resolver = DnsResolver(system=_system(query), doh=doh, mode="doh")
    assert resolver.lookup("anthropic.com").hosts == GOOGLE_HOSTS
    assert urls[0].startswith(CLOUDFLARE_DOH)


def test_auto_keeps_a_trustworthy_system_mx() -> None:
    def query(domain: str, record_type: str, timeout: float) -> tuple[list[str], str | None]:
        del domain, timeout
        if record_type != "MX":
            raise AssertionError(record_type)
        return ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."], None

    def fetch(url: str, timeout: float) -> dict:
        del timeout
        raise AssertionError(url)

    resolver = DnsResolver(system=_system(query), doh=DohResolver(timeout=1, fetch=fetch), mode="auto")
    looked = resolver.lookup("anthropic.com")
    assert looked.hosts == ("aspmx.l.google.com", "alt1.aspmx.l.google.com")
    assert looked.error is None


def test_nxdomain_is_not_retried_over_doh() -> None:
    def query(domain: str, record_type: str, timeout: float) -> tuple[list[str], str | None]:
        del domain, record_type, timeout
        return [], "nxdomain"

    def fetch(url: str, timeout: float) -> dict:
        del timeout
        raise AssertionError(url)

    resolver = DnsResolver(system=_system(query), doh=DohResolver(timeout=1, fetch=fetch), mode="auto")
    looked = resolver.lookup("missing.example")
    assert looked.hosts == ()
    assert looked.error is None
    assert looked.null_mx is False


def test_cloudflare_failure_uses_google() -> None:
    def fetch(url: str, timeout: float) -> dict | None:
        del timeout
        if url.startswith(CLOUDFLARE_DOH):
            return None
        if url.startswith(GOOGLE_DOH) and "type=MX" in url:
            return ANTHROPIC_MX
        return {"Status": 2}

    resolver = DnsResolver(system=_system(), doh=DohResolver(timeout=1, fetch=fetch), mode="auto")
    assert resolver.lookup("anthropic.com").hosts == GOOGLE_HOSTS


def test_cloudflare_no_mx_still_checks_google_before_address_fallback() -> None:
    def fetch(url: str, timeout: float) -> dict:
        del timeout
        if url.startswith(CLOUDFLARE_DOH):
            return {"Status": 0, "Answer": []}
        return ANTHROPIC_MX

    resolver = DnsResolver(system=_system(), doh=DohResolver(timeout=1, fetch=fetch), mode="doh")
    looked = resolver.lookup("anthropic.com")
    assert looked.hosts == GOOGLE_HOSTS
    assert looked.implicit_a is False


def test_fake_mx_exchange_is_replaced_by_doh() -> None:
    def query(domain: str, record_type: str, timeout: float) -> tuple[list[str], str | None]:
        del domain, timeout
        if record_type == "MX":
            return ["10 198.18.0.1."], None
        raise AssertionError(record_type)

    doh, _urls = _doh()
    resolver = DnsResolver(system=_system(query), doh=doh, mode="auto")
    looked = resolver.lookup("anthropic.com")
    assert looked.hosts == GOOGLE_HOSTS
    assert "198.18.0.1" not in looked.hosts


def test_doh_timeout_does_not_revive_a_fake_ip() -> None:
    doh, _urls = _doh(fail=True)
    resolver = DnsResolver(system=_system(), doh=doh, mode="auto")
    looked = resolver.lookup("anthropic.com")
    assert looked.hosts == ()
    assert looked.error == "timeout"
    prober = ScriptedSmtp()
    result = verify_email("ada@anthropic.com", resolver=resolver, prober=prober, host_checker=lambda host: True)
    assert result.status == "unknown"
    assert result.reason == "dns_timeout"
    assert result.mx_valid is False
    assert prober.calls == []


def test_doh_timeout_keeps_a_public_system_address() -> None:
    def query(domain: str, record_type: str, timeout: float) -> tuple[list[str], str | None]:
        del domain, timeout
        if record_type == "MX":
            return [], "no_answer"
        if record_type == "A":
            return ["198.18.0.1", "1.1.1.1"], None
        return [], "no_answer"

    doh, _urls = _doh(fail=True)
    resolver = DnsResolver(system=_system(query), doh=doh, mode="auto")
    looked = resolver.lookup("example.com")
    assert looked.hosts == ("1.1.1.1",)
    assert looked.implicit_a is True
    assert "198.18.0.1" not in looked.hosts


def test_doh_address_fallback_ignores_private_answers() -> None:
    def fetch(url: str, timeout: float) -> dict:
        del timeout
        if "type=MX" in url:
            return {"Status": 0, "Answer": []}
        if "type=A" in url and url.startswith(CLOUDFLARE_DOH):
            return {"Status": 0, "Answer": [{"type": 1, "data": "198.18.0.1"}, {"type": 1, "data": "8.8.8.8"}]}
        return {"Status": 0, "Answer": []}

    resolver = DnsResolver(system=_system(), doh=DohResolver(timeout=1, fetch=fetch), mode="doh")
    looked = resolver.lookup("example.com")
    assert looked.hosts == ("8.8.8.8",)
    assert looked.implicit_a is True
    assert looked.error is None


def test_null_mx_from_doh_means_the_domain_does_not_accept_mail() -> None:
    def fetch(url: str, timeout: float) -> dict:
        del timeout
        return {"Status": 0, "Answer": [{"type": 15, "data": "0 ."}]}

    resolver = DnsResolver(system=_system(), doh=DohResolver(timeout=1, fetch=fetch), mode="doh")
    looked = resolver.lookup("example.com")
    assert looked.null_mx is True
    assert looked.hosts == ()


def test_system_timeout_falls_through_to_doh() -> None:
    def query(domain: str, record_type: str, timeout: float) -> tuple[list[str], str | None]:
        del domain, record_type, timeout
        return [], "timeout"

    doh, urls = _doh()
    resolver = DnsResolver(system=_system(query), doh=doh, mode="auto")
    assert resolver.lookup("anthropic.com").hosts == GOOGLE_HOSTS
    assert urls
