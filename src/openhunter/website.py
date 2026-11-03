"""Fetch a company's public pages and collect addresses those pages show.

robots.txt is honored. A missing robots.txt is treated as "no extra rules",
which is the usual failure mode when the file is absent. Pages are capped so
a link farm cannot turn one lookup into an open-ended crawl.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

from openhunter.extract import extract_page
from openhunter.http_client import USER_AGENT, FetchResult
from openhunter.models import Person, merge_people
from openhunter.net import same_site

WEBSITE_PATHS: tuple[str, ...] = (
    "/",
    "/about",
    "/about-us",
    "/company",
    "/team",
    "/our-team",
    "/people",
    "/leadership",
    "/contact",
    "/contact-us",
    "/careers",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
)
MAX_PAGES = 12


@dataclass(frozen=True)
class WebsiteFindings:
    people: list[Person]
    github_orgs: list[str]
    company_name: str | None
    notes: list[str]


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
        fetched = 0
        while queue and fetched < MAX_PAGES:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if robots is not None and not robots.can_fetch(USER_AGENT, url):
                continue
            result = self._get(url)
            fetched += 1
            if result.status >= 400 or result.status == 0 or not result.text:
                continue
            final_host = (urlsplit(result.final_url or url).hostname or "").lower()
            if not same_site(final_host, domain):
                notes.append(f"Skipped {url} after it redirected off the company site.")
                continue
            page = extract_page(result.text, result.final_url or url, domain)
            people.extend(page.people)
            for org in page.github_orgs:
                if org not in orgs:
                    orgs.append(org)
            if page.company_name and company is None:
                company = page.company_name
            insert_at = 0
            for link in page.follow_links:
                if link not in seen:
                    queue.insert(insert_at, link)
                    insert_at += 1
        return WebsiteFindings(merge_people(people), orgs, company, notes)

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
        return getter(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html, text/plain;q=0.9"})
