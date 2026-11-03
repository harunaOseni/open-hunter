"""Polite HTTPS client. Redirects are followed only while the next host is public."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from openhunter.net import host_is_public, public_addresses

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
    def __init__(self, delay: float = 0.2, timeout: float = 10.0) -> None:
        self.delay = delay
        self.timeout = timeout
        # trust_env is off so an inherited HTTP(S)_PROXY cannot black-hole GitHub
        # while a direct client still reaches it. Connections are pinned to a
        # validated public address for the same reason.
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            trust_env=False,
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
        last_error = "network"
        for _ in range(4):
            reason = _unsafe(current)
            if reason:
                return FetchResult(url, 0, "", current, {}, "", reason)
            parts = urlsplit(current)
            host = parts.hostname or ""
            addresses = public_addresses(host)
            if not addresses:
                return FetchResult(url, 0, "", current, {}, "", "host is not public")
            response = None
            for address in addresses[:2]:
                pinned_headers = dict(request_headers)
                pinned_headers["Host"] = host
                try:
                    response = self._client.get(
                        pinned_url(current, address),
                        headers=pinned_headers,
                        timeout=timeout,
                        extensions={"sni_hostname": host},
                    )
                    break
                except httpx.TimeoutException:
                    last_error = "timeout"
                    response = None
                except httpx.HTTPError:
                    last_error = "network"
                    response = None
            if response is None:
                return FetchResult(url, 0, "", current, {}, "", last_error)
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
        return FetchResult(url, 0, "", current, {}, "", "redirects" if last_error == "network" else last_error)

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
    host = parts.hostname or ""
    if not host or not host_is_public(host):
        return "host is not public"
    return None
