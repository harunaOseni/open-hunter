"""Fetch a company's public pages and collect addresses those pages show.

robots.txt is honored. A missing robots.txt is treated as "no extra rules",
which is the usual failure mode when the file is absent. Pages are capped so
a link farm cannot turn one lookup into an open-ended crawl.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from openhunter.extract import extract_page, extract_pdf, parse_sitemap_locs
from openhunter.http_client import USER_AGENT, FetchResult
from openhunter.models import Person, merge_people
from openhunter.net import same_site

WEBSITE_PATHS: tuple[str, ...] = (
    "/sitemap.xml",
    "/",
    "/.well-known/security.txt",
    "/security.txt",
    "/humans.txt",
    "/about",
    "/team",
    "/contact",
    "/careers",
    "/blog",
    "/press",
    "/newsroom",
    "/news",
    "/jobs",
    "/company",
    "/leadership",
    "/people",
    "/our-team",
    "/about-us",
    "/contact-us",
)
MAX_PAGES = 12
MAX_PDFS = 3
MAX_SITEMAP_LOCS = 40
_INTEREST = ("team", "about", "people", "contact", "blog", "press", "news", "career", "job", "staff")


@dataclass(frozen=True)
class WebsiteFindings:
    people: list[Person]
    github_orgs: list[str]
    company_name: str | None
    notes: list[str]
    lookup_failed: bool = False


class WebsiteSource:
    def __init__(self, http: object) -> None:
        self.http = http

    def discover(self, domain: str) -> WebsiteFindings:
        notes: list[str] = []
        people: list[Person] = []
        orgs: list[str] = []
        company: str | None = None
        robots = self._robots(domain)
        if robots is not None and not robots.can_fetch(USER_AGENT, f"https://{domain}/"):
            notes.append("robots.txt disallows crawling this site.")
            return WebsiteFindings([], [], None, notes)
        queue = [f"https://{domain}{path}" for path in WEBSITE_PATHS]
        seen: set[str] = set()
        html_fetched = 0
        pdf_fetched = 0
        sitemap_children = 0
        saw_success = False
        saw_transport_error = False
        while queue and (html_fetched < MAX_PAGES or pdf_fetched < MAX_PDFS):
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            is_pdf = _is_pdf(url)
            if is_pdf and pdf_fetched >= MAX_PDFS:
                continue
            if not is_pdf and html_fetched >= MAX_PAGES:
                continue
            if robots is not None and not robots.can_fetch(USER_AGENT, url):
                continue
            result = self._get(url)
            if is_pdf:
                pdf_fetched += 1
            else:
                html_fetched += 1
            if result.status == 0:
                saw_transport_error = True
                if len([note for note in notes if note.startswith("Could not fetch")]) < 4:
                    notes.append(f"Could not fetch {url} ({result.error or 'no response'}).")
                if _is_apex_home(url, domain):
                    www = f"https://www.{domain}/"
                    if www not in seen:
                        queue.insert(0, www)
                continue
            if result.status >= 400 or not result.text:
                continue
            final_host = (urlsplit(result.final_url or url).hostname or "").lower()
            if not same_site(final_host, domain):
                notes.append(f"Skipped {url} after it redirected off the company site.")
                continue
            saw_success = True
            if _is_sitemap(url, result.content_type):
                queued = self._queue_sitemap(
                    result.text, domain, robots, seen, queue, notes, sitemap_children
                )
                sitemap_children += queued
                continue
            if is_pdf or "pdf" in result.content_type.lower():
                people.extend(extract_pdf(result.text, result.body, result.final_url or url, domain))
                continue
            page = extract_page(result.text, result.final_url or url, domain)
            people.extend(page.people)
            for org in page.github_orgs:
                if org not in orgs:
                    orgs.append(org)
            if page.company_name and company is None:
                company = page.company_name
            self._insert(queue, seen, page.follow_links)
            self._insert(queue, seen, page.pdf_links)
        if not people and saw_success:
            notes.append(f"Crawled the company site ({html_fetched} pages, {pdf_fetched} PDFs) and found no on-domain addresses there.")
        return WebsiteFindings(
            merge_people(people),
            orgs,
            company,
            notes,
            lookup_failed=saw_transport_error and not saw_success,
        )

    def _queue_sitemap(
        self,
        text: str,
        domain: str,
        robots: RobotFileParser | None,
        seen: set[str],
        queue: list[str],
        notes: list[str],
        children_queued: int,
    ) -> int:
        locs = parse_sitemap_locs(text)[:MAX_SITEMAP_LOCS]
        interesting: list[str] = []
        rest: list[str] = []
        child_sitemaps: list[str] = []
        for loc in locs:
            parts = urlsplit(loc)
            if parts.scheme != "https":
                continue
            host = (parts.hostname or "").lower()
            if not same_site(host, domain):
                continue
            canonical = urlunsplit(("https", host, parts.path or "/", "", ""))
            if robots is not None and not robots.can_fetch(USER_AGENT, canonical):
                continue
            lowered = parts.path.lower()
            if lowered.endswith(".xml") and "sitemap" in lowered:
                if children_queued + len(child_sitemaps) < 2:
                    child_sitemaps.append(canonical)
                continue
            if any(token in lowered for token in _INTEREST):
                interesting.append(canonical)
            else:
                rest.append(canonical)
        added = self._insert(queue, seen, child_sitemaps)
        self._insert(queue, seen, interesting)
        self._insert(queue, seen, rest[:10])
        if locs:
            notes.append(f"Read a sitemap with {len(locs)} locations.")
        return added

    def _insert(self, queue: list[str], seen: set[str], links: list[str]) -> int:
        added = 0
        at = 0
        for link in links:
            if link in seen or link in queue:
                continue
            queue.insert(at, link)
            at += 1
            added += 1
        return added

    def _robots(self, domain: str) -> RobotFileParser | None:
        result = self._get(f"https://{domain}/robots.txt")
        if result.status != 200 or not result.text.strip():
            return None
        parser = RobotFileParser()
        parser.parse(result.text.splitlines())
        # parse() alone leaves last_checked at 0, and can_fetch() then refuses
        # every URL. modified() records that the file was actually loaded.
        parser.modified()
        return parser

    def _get(self, url: str) -> FetchResult:
        getter = getattr(self.http, "get_text")
        return getter(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html, application/pdf, text/plain;q=0.9"})


def _is_pdf(url: str) -> bool:
    return urlsplit(url).path.lower().endswith(".pdf")


def _is_sitemap(url: str, content_type: str) -> bool:
    path = urlsplit(url).path.lower()
    if path.endswith(".xml") and "sitemap" in path:
        return True
    return "xml" in content_type.lower() and path.endswith(".xml")


def _is_apex_home(url: str, domain: str) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    return host == domain and path in {"", "/"}
