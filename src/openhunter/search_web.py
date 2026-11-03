"""Find public pages that mention a company mailbox, then read those pages.

The default backend is the DuckDuckGo HTML endpoint, which needs no API key.
When SEARXNG_URL or BRAVE_SEARCH_API_KEY is set, that backend is used instead,
and DuckDuckGo is only a fallback if the configured backend cannot be reached.
Result pages are fetched only when they are public HTTPS URLs and robots.txt
does not disallow them.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from urllib.parse import parse_qs, quote_plus, unquote, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from openhunter.extract import extract_page
from openhunter.http_client import USER_AGENT, FetchResult
from openhunter.models import Person, merge_people
from openhunter.net import host_is_public, same_site

MAX_QUERIES = 3
MAX_RESULTS_PER_QUERY = 5
MAX_PAGES = 6


@dataclass(frozen=True)
class SearchFindings:
    people: list[Person]
    notes: list[str]
    lookup_failed: bool = False


class WebSearchSource:
    def __init__(
        self,
        http: object,
        *,
        brave_key: str | None = None,
        searxng_url: str | None = None,
        host_ok: Callable[[str], bool] | None = None,
        max_pages: int = MAX_PAGES,
    ) -> None:
        self.http = http
        self.brave_key = brave_key.strip() if brave_key else None
        self.searxng_url = searxng_url.rstrip("/") if searxng_url else None
        self.host_ok = host_ok or host_is_public
        self.max_pages = max_pages
        self._robots: dict[str, RobotFileParser | None] = {}

    @classmethod
    def from_env(cls, http: object) -> WebSearchSource:
        return cls(
            http,
            brave_key=os.environ.get("BRAVE_SEARCH_API_KEY") or os.environ.get("BRAVE_API_KEY"),
            searxng_url=os.environ.get("SEARXNG_URL"),
        )

    def discover(self, domain: str) -> SearchFindings:
        queries = (
            f"@{domain}",
            f"\"{domain}\" email",
            f"\"{domain}\" (speaker OR podcast OR interview OR press)",
        )
        backend = "searxng" if self.searxng_url else "brave" if self.brave_key else "duckduckgo"
        urls, failed, notes = self._collect(backend, queries)
        if failed and not urls and backend != "duckduckgo":
            notes.append(f"{backend} search failed; falling back to DuckDuckGo.")
            extra, extra_failed, extra_notes = self._collect("duckduckgo", queries)
            urls.extend(extra)
            notes.extend(extra_notes)
            failed = extra_failed and not extra
        people: list[Person] = []
        fetched = 0
        page_errors = 0
        for url in _unique(urls):
            if fetched >= self.max_pages:
                break
            if same_site(urlsplit(url).hostname or "", domain):
                continue
            reason = self._block_reason(url)
            if reason:
                notes.append(f"Skipped search result {url}: {reason}")
                continue
            result = self._get(url)
            fetched += 1
            if result.status == 0 or result.status >= 400 or not result.text:
                page_errors += 1
                if result.status == 0 and page_errors <= 3:
                    notes.append(f"Could not fetch search result {url} ({result.error or 'no response'}).")
                continue
            page = extract_page(result.text, result.final_url or url, domain)
            people.extend(replace(person, source="web_search") for person in page.people)
        label = _backend_label(backend if urls or backend == "duckduckgo" else "duckduckgo")
        page_word = "page" if fetched == 1 else "pages"
        notes.insert(
            0,
            f"Searched {label} for @{domain}, \"{domain}\" email, and talk/press mentions. Fetched {fetched} {page_word}.",
        )
        lookup_failed = failed and not people and fetched == 0
        return SearchFindings(merge_people(people), notes, lookup_failed)

    def _collect(self, backend: str, queries: tuple[str, ...]) -> tuple[list[str], bool, list[str]]:
        found: list[str] = []
        notes: list[str] = []
        failures = 0
        for query in queries[:MAX_QUERIES]:
            urls, detail = self._query(backend, query)
            if detail:
                failures += 1
                notes.append(detail)
                continue
            for url in urls[:MAX_RESULTS_PER_QUERY]:
                if url not in found:
                    found.append(url)
        return found, failures == len(queries[:MAX_QUERIES]), notes

    def _query(self, backend: str, query: str) -> tuple[list[str], str | None]:
        if backend == "brave":
            return self._brave(query)
        if backend == "searxng":
            return self._searxng(query)
        return self._duckduckgo(query)

    def _duckduckgo(self, query: str) -> tuple[list[str], str | None]:
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        result = self._get(url, headers={"Accept": "text/html"})
        if result.status not in {200, 202} or not result.text:
            return [], f"DuckDuckGo search for {query!r} failed ({result.error or f'HTTP {result.status}'})."
        urls = _duckduckgo_urls(result.text)
        if not urls and result.status != 200:
            return [], f"DuckDuckGo search for {query!r} failed (HTTP {result.status})."
        return urls, None

    def _brave(self, query: str) -> tuple[list[str], str | None]:
        url = f"https://api.search.brave.com/res/v1/web/search?q={quote_plus(query)}&count={MAX_RESULTS_PER_QUERY}"
        result = self._get(
            url,
            headers={"Accept": "application/json", "X-Subscription-Token": self.brave_key or ""},
        )
        if result.status != 200 or not result.text:
            return [], f"Brave search failed ({result.error or f'HTTP {result.status}'})."
        return _json_urls(result.text, ("web", "results"), "url"), None

    def _searxng(self, query: str) -> tuple[list[str], str | None]:
        base = self.searxng_url or ""
        url = f"{base}/search?q={quote_plus(query)}&format=json&categories=general"
        result = self._get(url, headers={"Accept": "application/json"})
        if result.status != 200 or not result.text:
            return [], f"SearXNG search failed ({result.error or f'HTTP {result.status}'})."
        return _json_urls(result.text, ("results",), "url"), None

    def _block_reason(self, url: str) -> str | None:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            return "only public https pages are fetched."
        if not self.host_ok(parts.hostname):
            return "host is not public."
        robots = self._robots_for(parts.hostname)
        if robots is not None and not robots.can_fetch(USER_AGENT, url):
            return "robots.txt disallows it."
        return None

    def _robots_for(self, host: str) -> RobotFileParser | None:
        if host in self._robots:
            return self._robots[host]
        result = self._get(f"https://{host}/robots.txt")
        if result.status != 200 or not result.text.strip():
            self._robots[host] = None
            return None
        parser = RobotFileParser()
        parser.parse(result.text.splitlines())
        parser.modified()
        self._robots[host] = parser
        return parser

    def _get(self, url: str, headers: dict[str, str] | None = None) -> FetchResult:
        getter = getattr(self.http, "get_text")
        request_headers = {"User-Agent": USER_AGENT, "Accept": "text/html, application/json;q=0.9"}
        if headers:
            request_headers.update(headers)
        return getter(url, headers=request_headers, timeout=15)


def _duckduckgo_urls(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    hrefs = [str(anchor.get("href") or "") for anchor in soup.find_all("a", href=True)]
    return _clean_urls(hrefs)


def _clean_urls(hrefs: list[str]) -> list[str]:
    found: list[str] = []
    for href in hrefs:
        url = _unwrap(href)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or not host:
            continue
        if host.endswith("duckduckgo.com") or host.endswith("google.com") or host.endswith("brave.com"):
            continue
        canonical = urlunsplit(("https", host, parts.path or "/", parts.query, ""))
        if canonical not in found:
            found.append(canonical)
    return found


def _unwrap(href: str) -> str:
    if href.startswith("//"):
        href = "https:" + href
    parts = urlsplit(href)
    uddg = parse_qs(parts.query).get("uddg")
    if uddg and uddg[0]:
        return unquote(uddg[0])
    return href


def _json_urls(text: str, path: tuple[str, ...], field: str) -> list[str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    current: object = payload
    for key in path:
        if not isinstance(current, dict):
            return []
        current = current.get(key)
    if not isinstance(current, list):
        return []
    hrefs: list[str] = []
    for item in current:
        if isinstance(item, dict) and isinstance(item.get(field), str):
            hrefs.append(str(item[field]))
    return _clean_urls(hrefs)


def _unique(values: list[str]) -> list[str]:
    found: list[str] = []
    for value in values:
        if value not in found:
            found.append(value)
    return found


def _backend_label(backend: str) -> str:
    if backend == "brave":
        return "Brave"
    if backend == "searxng":
        return "SearXNG"
    return "DuckDuckGo"
