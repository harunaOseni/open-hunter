"""Pull people, mailbox addresses, and GitHub org links out of a public page."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from openhunter.models import Person
from openhunter.names import split_name
from openhunter.net import same_site
from openhunter.roles import is_role_address, role_label
from openhunter.syntax import check_syntax

_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})(?![A-Za-z0-9._%+-])"
)
_OBFUSCATED_RE = re.compile(
    r"\b([A-Za-z0-9._%+-]{1,64})\s*(?:\[at\]|\(at\)|\{at\}|\sat\s)\s*"
    r"([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)\s*(?:\[dot\]|\(dot\)|\{dot\}|\sdot\s)\s*"
    r"([A-Za-z]{2,24})\b",
    re.IGNORECASE,
)
_OBFUSCATED_PLAIN_DOMAIN_RE = re.compile(
    r"\b([A-Za-z0-9._%+-]{1,64})\s*(?:\[at\]|\(at\)|\{at\}|\sat\s)\s*"
    r"((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b",
    re.IGNORECASE,
)
_GITHUB_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)(?:/([A-Za-z0-9_.-]+))?",
    re.IGNORECASE,
)
_FILE_TLDS = frozenset({"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico", "woff", "woff2"})
_RESERVED_GITHUB = frozenset(
    {
        "features",
        "about",
        "topics",
        "sponsors",
        "marketplace",
        "apps",
        "settings",
        "login",
        "signup",
        "explore",
        "collections",
        "customer-stories",
        "orgs",
        "organizations",
        "sites",
        "readme",
        "pricing",
        "enterprise",
        "security",
        "team",
        "pulls",
        "issues",
        "notifications",
        "new",
        "codespaces",
        "account",
    }
)
_FOLLOW_TOKENS = ("team", "about", "people", "leadership", "contact", "staff", "company")
_NAME_STOP = frozenset(
    {"the", "team", "email", "contact", "say", "hello", "mail", "reach", "click", "here", "our", "us"}
)


@dataclass(frozen=True)
class PageExtract:
    people: list[Person]
    github_orgs: list[str]
    company_name: str | None
    follow_links: list[str]


def extract_page(text: str, url: str, domain: str) -> PageExtract:
    path = urlsplit(url).path.lower()
    if path.endswith("security.txt"):
        return PageExtract(_security_contacts(text, url, domain), [], None, [])
    if path.endswith("humans.txt"):
        people = _emails_from_text(text, url, domain, source="humans_txt", confidence=0.6)
        return PageExtract(people, [], None, [])
    return _from_html(text, url, domain)


def _from_html(text: str, url: str, domain: str) -> PageExtract:
    soup = BeautifulSoup(text, "html.parser")
    found: dict[str, Person] = {}
    company = _structured_people(soup, url, domain, found)
    for anchor in soup.find_all("a", href=True):
        href = str(anchor.get("href") or "")
        if href.lower().startswith("mailto:"):
            for address in _mailto_addresses(href):
                name = _anchor_name(anchor.get_text(" ", strip=True))
                _add_email(found, address, url, domain, "website_mailto", 0.8 if name else 0.6, name)
    for address in _obfuscated_addresses(soup.get_text(" ", strip=True)):
        _add_email(found, address, url, domain, "website_text", 0.6, None)
    for address in _plain_addresses(text):
        _add_email(found, address, url, domain, "website_text", 0.6, None)
    return PageExtract(
        list(found.values()),
        _github_orgs(text),
        company,
        _follow_links(soup, url, domain),
    )


def _structured_people(
    soup: BeautifulSoup, url: str, domain: str, found: dict[str, Person]
) -> str | None:
    company: str | None = None
    for script in soup.find_all("script"):
        script_type = " ".join(script.get("type") or []) if isinstance(script.get("type"), list) else str(script.get("type") or "")
        if "ld+json" not in script_type.lower():
            continue
        raw = script.string or script.get_text()
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        company = _walk_jsonld(payload, url, domain, found, company)
    return company


def _walk_jsonld(
    node: object,
    url: str,
    domain: str,
    found: dict[str, Person],
    company: str | None,
) -> str | None:
    if isinstance(node, list):
        for item in node:
            company = _walk_jsonld(item, url, domain, found, company)
        return company
    if not isinstance(node, dict):
        return company
    types = _type_names(node.get("@type"))
    if "Organization" in types and company is None:
        name = node.get("name")
        if isinstance(name, str) and name.strip():
            company = name.strip()
    if "Person" in types:
        _add_structured_person(node, url, domain, found)
    for value in node.values():
        if isinstance(value, (dict, list)):
            company = _walk_jsonld(value, url, domain, found, company)
    return company


def _add_structured_person(node: dict[str, object], url: str, domain: str, found: dict[str, Person]) -> None:
    name = node.get("name") if isinstance(node.get("name"), str) else None
    title = node.get("jobTitle")
    role = title if isinstance(title, str) else None
    if isinstance(title, list):
        role = next((item for item in title if isinstance(item, str)), None)
    emails = node.get("email")
    addresses = emails if isinstance(emails, list) else [emails]
    for address in addresses:
        if not isinstance(address, str):
            continue
        cleaned = address.strip()
        if cleaned.lower().startswith("mailto:"):
            cleaned = cleaned.split(":", 1)[1]
        _add_email(found, cleaned, url, domain, "website_structured", 0.9, name.strip() if isinstance(name, str) else None, role)


def _security_contacts(text: str, url: str, domain: str) -> list[Person]:
    found: dict[str, Person] = {}
    for line in text.splitlines():
        if not line.lower().startswith("contact:"):
            continue
        value = line.split(":", 1)[1].strip()
        if value.lower().startswith("mailto:"):
            for address in _mailto_addresses(value):
                _add_email(found, address, url, domain, "security_txt", 0.7, None)
    return list(found.values())


def _emails_from_text(text: str, url: str, domain: str, source: str, confidence: float) -> list[Person]:
    found: dict[str, Person] = {}
    for address in _plain_addresses(text):
        _add_email(found, address, url, domain, source, confidence, None)
    return list(found.values())


def _add_email(
    found: dict[str, Person],
    address: str,
    url: str,
    domain: str,
    source: str,
    confidence: float,
    name: str | None,
    role: str | None = None,
) -> None:
    syntax = check_syntax(address)
    if not syntax.ok or syntax.normalized is None:
        return
    host = syntax.normalized.split("@", 1)[1]
    if host != domain:
        return
    if host.split(".")[-1] in _FILE_TLDS:
        return
    role_address = is_role_address(syntax.normalized)
    if role_address and name is None and source in {"website_text", "website_mailto"}:
        confidence = min(confidence, 0.55)
    person = _make_person(
        syntax.normalized,
        url,
        source,
        confidence,
        name,
        role or (role_label(syntax.normalized) if role_address else None),
        role_address,
    )
    current = found.get(syntax.normalized)
    if current is None or person.confidence > current.confidence:
        found[syntax.normalized] = person


def _make_person(
    email: str,
    url: str,
    source: str,
    confidence: float,
    name: str | None,
    role: str | None,
    role_address: bool,
) -> Person:
    first, last = split_name(name) if name else (None, None)
    return Person(
        name=name,
        first_name=first,
        last_name=last,
        role=role,
        email=email,
        source=source,
        source_url=url,
        confidence=confidence,
        notes=(),
        is_role=role_address,
    )


def _mailto_addresses(href: str) -> list[str]:
    raw = unquote(href)
    if ":" in raw:
        raw = raw.split(":", 1)[1]
    raw = raw.split("?", 1)[0]
    return [part.strip() for part in raw.split(",") if part.strip()]


def _plain_addresses(text: str) -> list[str]:
    found: list[str] = []
    for local, host in _EMAIL_RE.findall(text):
        if host.split(".")[-1].lower() in _FILE_TLDS:
            continue
        found.append(f"{local}@{host}")
    return found


def _obfuscated_addresses(text: str) -> list[str]:
    found: list[str] = []
    for local, host, tld in _OBFUSCATED_RE.findall(text):
        found.append(f"{local}@{host}.{tld}")
    for local, host in _OBFUSCATED_PLAIN_DOMAIN_RE.findall(text):
        found.append(f"{local}@{host}")
    return found


def _anchor_name(text: str) -> str | None:
    parts = text.split()
    if not 2 <= len(parts) <= 4:
        return None
    for part in parts:
        if part.lower() in _NAME_STOP or not re.fullmatch(r"[A-Z][a-zA-Z'’-]+", part):
            return None
    return " ".join(parts)


def _github_orgs(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for first, second in _GITHUB_RE.findall(text):
        login = second if first.lower() == "orgs" and second else first
        if login.lower() in _RESERVED_GITHUB:
            continue
        key = login.lower()
        if key not in seen:
            seen.add(key)
            found.append(login)
    return found


def _follow_links(soup: BeautifulSoup, url: str, domain: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        href = str(anchor.get("href") or "")
        if href.startswith(("mailto:", "javascript:", "#")):
            continue
        absolute = urljoin(url, href)
        parts = urlsplit(absolute)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or not same_site(host, domain):
            continue
        path = parts.path or "/"
        if not any(token in path.lower() for token in _FOLLOW_TOKENS):
            continue
        canonical = urlunsplit(("https", host, path, "", ""))
        if canonical not in seen:
            seen.add(canonical)
            found.append(canonical)
    return found


def _type_names(value: object) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()
