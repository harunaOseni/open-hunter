"""HTTP stand-ins for discovery tests. Not used in production."""

from __future__ import annotations

from openhunter.http_client import FetchResult


class PrefixHttp:
    """Return the longest matching prefix route, otherwise 404."""

    def __init__(self, routes: list[tuple[str, int, str, dict[str, str] | None]]) -> None:
        self.routes = sorted(routes, key=lambda item: len(item[0]), reverse=True)
        self.calls: list[str] = []

    def get_text(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> FetchResult:
        del headers, timeout
        self.calls.append(url)
        for prefix, status, body, response_headers in self.routes:
            if url.startswith(prefix):
                hdrs = response_headers or {}
                content_type = hdrs.get("content-type", "text/html; charset=utf-8")
                return FetchResult(
                    url=url,
                    status=status,
                    text=body,
                    final_url=url,
                    headers=hdrs,
                    content_type=content_type,
                )
        return FetchResult(
            url=url,
            status=404,
            text="",
            final_url=url,
            headers={},
            content_type="text/html",
        )
