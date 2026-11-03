"""Connection target: pin real public addresses, keep the hostname for fake-IP DNS."""

from __future__ import annotations

import httpx
import pytest

from openhunter.http_client import LiveHttp
from openhunter.net import HostRoute


def _client(handler, monkeypatch: pytest.MonkeyPatch, route: HostRoute, *, trust_resolver: bool = False) -> LiveHttp:
    monkeypatch.setattr("openhunter.http_client.host_route", lambda host, **kwargs: route)
    http = LiveHttp(delay=0, trust_resolver=trust_resolver)
    http._client.close()
    http._client = httpx.Client(transport=httpx.MockTransport(handler), trust_env=trust_resolver)
    return http


def test_fake_ip_dns_connects_by_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="ok")

    http = _client(handler, monkeypatch, HostRoute("hostname"))
    result = http.get_text("https://api.github.com/orgs/runpod")
    assert result.status == 200
    assert result.text == "ok"
    assert seen == ["https://api.github.com/orgs/runpod"]
    http._client.close()


def test_public_dns_pins_the_validated_address(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "1.2.3.4"
        assert request.url.path == "/orgs/runpod"
        assert request.headers["host"] == "api.github.com"
        return httpx.Response(200, text="pinned")

    http = _client(handler, monkeypatch, HostRoute("pin", ("1.2.3.4",)))
    result = http.get_text("https://api.github.com/orgs/runpod")
    assert result.status == 200
    assert result.final_url == "https://api.github.com/orgs/runpod"
    http._client.close()


def test_pin_falls_through_to_the_next_address(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "1.2.3.4":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, text="second")

    http = _client(handler, monkeypatch, HostRoute("pin", ("1.2.3.4", "5.6.7.8")))
    result = http.get_text("https://api.github.com/orgs/runpod")
    assert result.status == 200
    assert seen == ["1.2.3.4", "5.6.7.8"]
    http._client.close()


def test_redirect_to_a_private_host_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def route(host: str, **kwargs: object) -> HostRoute:
        del kwargs
        if host == "10.1.2.3":
            return HostRoute("blocked")
        return HostRoute("hostname")

    monkeypatch.setattr("openhunter.http_client.host_route", route)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://10.1.2.3/secret"})

    http = LiveHttp(delay=0, trust_resolver=False)
    http._client.close()
    http._client = httpx.Client(transport=httpx.MockTransport(handler))
    result = http.get_text("https://api.github.com/orgs/runpod")
    assert result.status == 0
    assert result.error == "host is not public"
    assert seen == ["https://api.github.com/orgs/runpod"]
    http._client.close()


def test_trust_resolver_client_honors_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENHUNTER_TRUST_RESOLVER", raising=False)
    plain = LiveHttp(delay=0)
    assert plain.trust_resolver is False
    assert plain._client.trust_env is False
    plain._client.close()

    monkeypatch.setenv("OPENHUNTER_TRUST_RESOLVER", "on")
    trusted = LiveHttp(delay=0)
    assert trusted.trust_resolver is True
    assert trusted._client.trust_env is True
    trusted._client.close()


def test_blocked_route_never_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        raise AssertionError("blocked hosts must not be fetched")

    http = _client(handler, monkeypatch, HostRoute("blocked"))
    result = http.get_text("https://10.1.2.3/latest")
    assert result.error == "host is not public"
    http._client.close()
