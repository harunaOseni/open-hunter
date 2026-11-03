"""Polite HTTPS client. Redirects are followed only while the next host is public."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import assert_never
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from openhunter.net import HostRoute, host_route, trust_resolver_enabled

USER_AGENT = "openhunter/0.1 (public contact research)"


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: int
    text: str
    final_url: str
    headers: dict[str, str]
    content_type: str
    error: str | None = None
    body: bytes = b""


class LiveHttp:
    def __init__(
        self,
        delay: float = 0.2,
        timeout: float = 10.0,
        *,
        trust_resolver: bool | None = None,
    ) -> None:
        self.delay = delay
        self.timeout = timeout
        # trust_env stays off unless OPENHUNTER_TRUST_RESOLVER is set, so an
        # inherited HTTP(S)_PROXY cannot black-hole GitHub on a normal network.
        # The opt-in connects by hostname and honors that proxy. Fake-IP DNS
        # (198.18.0.0/15) also connects by hostname, but still ignores the proxy.
        self.trust_resolver = trust_resolver_enabled() if trust_resolver is None else trust_resolver
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=self.trust_resolver,
        )
        self._last = 0.0

    def get_text(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> FetchResult:
        self._pace()
        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json,text/plain;q=0.9,*/*;q=0.8",
        }
        if headers:
            request_headers.update(headers)
        current = url
        for _ in range(4):
            reason = _unsafe(current)
            if reason:
                return FetchResult(url, 0, "", current, {}, "", reason)
            host = urlsplit(current).hostname or ""
            route = host_route(host, trust_resolver=self.trust_resolver)
            if route.mode == "blocked":
                return FetchResult(url, 0, "", current, {}, "", "host is not public")
            try:
                response = self._open(current, request_headers, timeout, route)
            except httpx.TimeoutException:
                return FetchResult(url, 0, "", current, {}, "", "timeout")
            except httpx.HTTPError:
                return FetchResult(url, 0, "", current, {}, "", "network")
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    break
                # Join against the hostname URL. response.url is the pinned IP.
                current = urljoin(current, location)
                continue
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            raw = response.content[:1_000_000]
            return FetchResult(
                url=url,
                status=response.status_code,
                text=response.text[:1_000_000],
                final_url=current,
                headers=response_headers,
                content_type=response_headers.get("content-type", ""),
                body=raw,
            )
        return FetchResult(url, 0, "", current, {}, "", "redirects")

    def _open(
        self,
        url: str,
        headers: dict[str, str],
        timeout: float,
        route: HostRoute,
    ) -> httpx.Response:
        mode = route.mode
        if mode == "hostname":
            return self._client.get(url, headers=headers, timeout=timeout)
        if mode == "pin":
            return self._open_pinned(url, headers, timeout, route.addresses)
        if mode == "blocked":
            raise httpx.HTTPError("host is not public")
        assert_never(mode)

    def _open_pinned(
        self,
        url: str,
        headers: dict[str, str],
        timeout: float,
        addresses: tuple[str, ...],
    ) -> httpx.Response:
        host = urlsplit(url).hostname or ""
        last: httpx.HTTPError | None = None
        for address in addresses[:2]:
            pinned_headers = dict(headers)
            pinned_headers["Host"] = host
            try:
                return self._client.get(
                    pinned_url(url, address),
                    headers=pinned_headers,
                    timeout=timeout,
                    extensions={"sni_hostname": host},
                )
            except httpx.HTTPError as exc:
                last = exc
        if last is not None:
            raise last
        raise httpx.HTTPError("no public address")

    def _pace(self) -> None:
        if self.delay <= 0:
            return
        elapsed = time.monotonic() - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.monotonic()


def pinned_url(url: str, address: str) -> str:
    """Rewrite a URL so the connection target is a specific address."""
    parts = urlsplit(url)
    host = f"[{address}]" if ":" in address else address
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


def _unsafe(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        return "only https URLs are fetched"
    if parts.username or parts.password:
        return "credentials are not fetched"
    if not parts.hostname:
        return "host is not public"
    return None
