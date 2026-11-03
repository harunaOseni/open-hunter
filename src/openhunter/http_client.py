"""Polite HTTPS client. Redirects are followed only while the next host is public."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from openhunter.net import host_is_public

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


class LiveHttp:
    def __init__(self, delay: float = 0.2, timeout: float = 10.0) -> None:
        self.delay = delay
        self.timeout = timeout
        self._client = httpx.Client(timeout=httpx.Timeout(timeout), follow_redirects=False)
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
            try:
                response = self._client.get(current, headers=request_headers, timeout=timeout)
            except httpx.TimeoutException:
                return FetchResult(url, 0, "", current, {}, "", "timeout")
            except httpx.HTTPError:
                return FetchResult(url, 0, "", current, {}, "", "network")
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    break
                current = urljoin(str(response.url), location)
                continue
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            return FetchResult(
                url=url,
                status=response.status_code,
                text=response.text[:1_000_000],
                final_url=str(response.url),
                headers=response_headers,
                content_type=response_headers.get("content-type", ""),
            )
        return FetchResult(url, 0, "", current, {}, "", "redirects")

    def _pace(self) -> None:
        if self.delay <= 0:
            return
        elapsed = time.monotonic() - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.monotonic()


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
