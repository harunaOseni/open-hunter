"""The operations shared by the CLI and the MCP server."""

from __future__ import annotations

import os
from pathlib import Path

from openhunter.dns_lookup import DnsResolver
from openhunter.errors import InputError
from openhunter.github_api import GitHubSource
from openhunter.http_client import LiveHttp
from openhunter.models import Person, merge_people, to_plain
from openhunter.names import split_name
from openhunter.net import host_is_public, normalize_domain, parse_query
from openhunter.outcomes import (
    rerank,
    Outcome,
    exclusions_for,
    make_outcome,
    read_outreach_sheet,
    weigh_patterns,
)
from openhunter.patterns import KnownEmail, PatternInference, PatternVote, generate_candidates, infer_pattern
from openhunter.roles import is_role_address
from openhunter.search_web import SearchFindings, WebSearchSource
from openhunter.smtp_probe import LiveSmtpProber, configured_smtp_port
from openhunter.store import Store
from openhunter.syntax import check_syntax
from openhunter.verifier import Verification, verify_email
from openhunter.website import WebsiteSource

SEARCH_TTL_SECONDS = 7 * 24 * 60 * 60
VERIFY_TTL_SECONDS = 24 * 60 * 60
HARD_CAP = 100


class OpenHunter:
    def __init__(
        self,
        store: Store,
        website: WebsiteSource,
        github: GitHubSource,
        verify,
        search: WebSearchSource | None = None,
        http: object | None = None,
    ) -> None:
        self.store = store
        self.website = website
        self.github = github
        self.verify = verify
        self.search = search
        self._http = http

    def close(self) -> None:
        closer = getattr(self._http, "close", None)
        if closer is not None:
            closer()

    def domain_search(self, query: str, limit: int = 25, refresh: bool = False) -> dict[str, object]:
        bounded = max(1, min(int(limit), HARD_CAP))
        parsed = parse_query(query)
        if parsed.kind == "invalid":
            raise InputError(parsed.reason or "That query is not a domain or a company name.")
        notes: list[str] = []
        hints: list[str] = []
        if parsed.kind == "company":
            resolution = self.github.resolve_company(parsed.company or query.strip())
            notes.extend(resolution.notes)
            if not resolution.domain:
                return {
                    "query": query.strip(),
                    "domain": None,
                    "company": parsed.company,
                    "people": [],
                    "pattern": None,
                    "from_cache": False,
                    "truncated": False,
                    "emails_found": 0,
                    "notes": notes,
                    "suggestions": resolution.suggestions,
                }
            domain = resolution.domain
            hints.extend(resolution.org_hints)
        else:
            domain = parsed.domain or ""
        if not refresh:
            cached = self.store.get_cache("domain_search", domain)
            if cached is not None:
                return _slice(cached, bounded, from_cache=True)
        website = self.website.discover(domain)
        notes.extend(website.notes)
        search = self.search.discover(domain) if self.search is not None else SearchFindings([], [])
        notes.extend(search.notes)
        for org in [*website.github_orgs, *hints]:
            if org not in hints:
                hints.append(org)
        # The domain stem is always tried first inside GitHub discovery. Hints
        # from the website are extra names, not a replacement for that stem.
        github_hints = list(dict.fromkeys([*website.github_orgs, *hints]))
        github = self.github.discover(domain, github_hints)
        notes.extend(github.notes)
        fresh = merge_people([*website.people, *search.people, *github.people])
        self.store.upsert_addresses([_observation(person) for person in fresh])
        indexed = [_person_from_index(row) for row in self.store.addresses_for_domain(domain)]
        people = merge_people([*fresh, *indexed])
        known = [
            KnownEmail(person.email, person.first_name, person.last_name, person.name)
            for person in people
            if person.email
        ]
        inference = infer_pattern(domain, known)
        lookup_failed = bool(
            getattr(website, "lookup_failed", False)
            or getattr(github, "lookup_failed", False)
            or search.lookup_failed
        )
        fresh_emails = any(person.email for person in fresh)
        if lookup_failed and not fresh_emails:
            notes.append("This lookup was not cached because a source could not be reached.")
        if not people and not lookup_failed:
            notes.append("No public people or addresses were found in the sources that responded.")
        payload: dict[str, object] = {
            "query": query.strip(),
            "domain": domain,
            "company": website.company_name,
            "people": [to_plain(person) for person in people[:HARD_CAP]],
            "pattern": to_plain(inference),
            "from_cache": False,
            "truncated": False,
            "emails_found": sum(1 for person in people if person.email),
            "index_count": len(indexed),
            "notes": notes,
            "suggestions": [],
        }
        if not (lookup_failed and not fresh_emails):
            self.store.put_cache("domain_search", domain, payload, SEARCH_TTL_SECONDS)
        return _slice(payload, bounded, from_cache=False)

    def email_pattern(self, domain: str, refresh: bool = False) -> dict[str, object]:
        found = self.domain_search(domain, limit=HARD_CAP, refresh=refresh)
        if not found.get("domain"):
            detail = found.get("notes")
            message = detail[0] if isinstance(detail, list) and detail else "Could not resolve a domain."
            raise InputError(str(message))
        pattern = found.get("pattern")
        result = dict(pattern) if isinstance(pattern, dict) else {}
        result["from_cache"] = found["from_cache"]
        result["weighted_patterns"] = self._weighted(str(found["domain"]), result)
        return result

    def email_finder(self, first_name: str, last_name: str, domain: str) -> dict[str, object]:
        found = self.domain_search(domain, limit=1)
        if not found.get("domain"):
            raise InputError("email_finder needs a domain that resolved to a website.")
        resolved = str(found["domain"])
        inference = _inference_from(found.get("pattern"), resolved)
        pool = generate_candidates(first_name, last_name, resolved, inference, limit=64)
        pattern = found.get("pattern")
        weighted = self._weighted(resolved, pattern if isinstance(pattern, dict) else {})
        outcomes = self._outcomes(resolved)
        excluded = exclusions_for(first_name, last_name, resolved, outcomes)
        candidates = rerank(pool, weighted, excluded.emails, excluded.patterns)[:8]
        return {
            "domain": resolved,
            "first_name": first_name.strip(),
            "last_name": last_name.strip(),
            "pattern": pattern,
            "weighted_patterns": weighted,
            "excluded": {"emails": sorted(excluded.emails), "patterns": sorted(excluded.patterns)},
            "candidates": [to_plain(candidate) for candidate in candidates],
        }

    def record_outcome(
        self,
        email: str,
        status: str,
        name: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> dict[str, object]:
        outcome = make_outcome(email, status, name=name, first_name=first_name, last_name=last_name)
        self.store.record_outcomes([outcome], source="record_outcome")
        return {"email": outcome.email, "domain": outcome.domain, "status": outcome.status,
                "first_name": outcome.first_name, "last_name": outcome.last_name}

    def import_outcomes(self, path: str, sheet: str = "Outreach") -> dict[str, object]:
        outcomes = read_outreach_sheet(Path(path).expanduser(), sheet=sheet)
        self.store.record_outcomes(outcomes, source=f"xlsx:{Path(path).name}")
        counts = {"delivered": 0, "bounced": 0}
        for outcome in outcomes:
            counts[outcome.status] += 1
        return {"path": str(path), "sheet": sheet, "imported": len(outcomes), **counts}

    def _outcomes(self, domain: str) -> list[Outcome]:
        return [
            Outcome(str(row["email"]), str(row["status"]), row.get("first_name"), row.get("last_name"))
            for row in self.store.outcomes_for_domain(domain)
        ]

    def _weighted(self, domain: str, pattern: dict[str, object]) -> list[dict[str, object]]:
        votes = [
            PatternVote(str(item["pattern"]), int(item["matched_count"]))
            for item in pattern.get("alternates") or []
            if isinstance(item, dict)
        ]
        return [to_plain(row) for row in weigh_patterns(domain, self._outcomes(domain), votes)]

    def email_verifier(self, email: str, refresh: bool = False) -> dict[str, object]:
        syntax = check_syntax(email)
        normalized = syntax.normalized
        if syntax.ok and normalized and not refresh:
            cached = self.store.get_cache("verify", normalized)
            if cached is not None:
                cached = dict(cached)
                cached["from_cache"] = True
                return cached
        verified = self.verify(email)
        payload = to_plain(verified)
        if not isinstance(payload, dict):
            raise InputError("Verification did not return a result.")
        if normalized:
            payload["email"] = normalized
        payload["from_cache"] = False
        if syntax.ok and normalized:
            self.store.put_cache("verify", normalized, payload, VERIFY_TTL_SECONDS)
        return payload

    def save_lead(
        self,
        *,
        email: str | None = None,
        name: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        role: str | None = None,
        company: str | None = None,
        domain: str | None = None,
        source_url: str | None = None,
        confidence: float | None = None,
        notes: str | None = None,
    ) -> dict[str, object]:
        if not any((email, name, first_name, last_name)):
            raise InputError("A lead needs an email or a name.")
        if name and not first_name and not last_name:
            first_name, last_name = split_name(name)
        full_name = name or " ".join(part for part in (first_name, last_name) if part) or None
        normalized_domain = domain
        if domain:
            try:
                normalized_domain = normalize_domain(domain)
            except InputError:
                normalized_domain = domain.strip().lower()
        normalized_email = email
        if email:
            syntax = check_syntax(email)
            normalized_email = syntax.normalized or email.strip().lower()
        return self.store.save_lead(
            email=normalized_email,
            full_name=full_name,
            first_name=first_name,
            last_name=last_name,
            role=role,
            company=company,
            domain=normalized_domain,
            source_url=source_url,
            confidence=confidence,
            notes=notes,
        )

    def list_leads(self, domain: str | None = None, limit: int = 100) -> dict[str, object]:
        normalized = normalize_domain(domain) if domain else None
        rows = self.store.list_leads(domain=normalized, limit=limit)
        return {"leads": rows, "count": len(rows)}

    def export_leads(self, path: str, domain: str | None = None) -> dict[str, object]:
        if "\x00" in path:
            raise InputError("The export path is not valid.")
        normalized = normalize_domain(domain) if domain else None
        count = self.store.export_csv(Path(path), domain=normalized)
        return {"path": str(Path(path)), "count": count}

    @classmethod
    def from_env(cls) -> OpenHunter:
        http = LiveHttp(delay=0.2)
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        return cls(
            Store(default_db_path()),
            WebsiteSource(http),
            GitHubSource(http, token=token),
            _live_verifier(),
            search=WebSearchSource.from_env(http),
            http=http,
        )


def default_db_path() -> Path:
    configured = os.environ.get("OPENHUNTER_DB")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".local" / "share" / "openhunter" / "openhunter.db"


def _observation(person: Person) -> dict[str, object]:
    return {
        "email": person.email,
        "source": person.source,
        "source_url": person.source_url,
        "name": person.name,
        "first_name": person.first_name,
        "last_name": person.last_name,
        "role": person.role,
        "confidence": person.confidence,
    }


def _person_from_index(row: dict[str, object]) -> Person:
    email = str(row.get("email") or "")
    name = row.get("name") if isinstance(row.get("name"), str) else None
    role = row.get("role") if isinstance(row.get("role"), str) else None
    return Person(
        name=name,
        first_name=row.get("first_name") if isinstance(row.get("first_name"), str) else None,
        last_name=row.get("last_name") if isinstance(row.get("last_name"), str) else None,
        role=role,
        email=email or None,
        source=str(row.get("source") or "index"),
        source_url=str(row.get("source_url") or ""),
        confidence=float(row.get("confidence") or 0),
        notes=(),
        is_role=is_role_address(email) if email else False,
        first_seen=str(row.get("first_seen") or "") or None,
        last_seen=str(row.get("last_seen") or "") or None,
    )


def _slice(payload: dict[str, object], limit: int, *, from_cache: bool) -> dict[str, object]:
    result = dict(payload)
    people = list(result.get("people") or [])
    result["people"] = people[:limit]
    result["truncated"] = len(people) > limit
    result["from_cache"] = from_cache
    return result


def _inference_from(payload: object, domain: str) -> PatternInference | None:
    if not isinstance(payload, dict) or not payload.get("pattern"):
        return None
    alternates = []
    raw_alternates = payload.get("alternates") or []
    if isinstance(raw_alternates, list):
        for item in raw_alternates:
            if isinstance(item, dict) and item.get("pattern"):
                alternates.append(PatternVote(str(item["pattern"]), int(item.get("matched_count") or 0)))
    notes = payload.get("notes") or []
    return PatternInference(
        domain=str(payload.get("domain") or domain),
        pattern=str(payload["pattern"]),
        confidence=float(payload.get("confidence") or 0),
        sample_count=int(payload.get("sample_count") or 0),
        matched_count=int(payload.get("matched_count") or 0),
        alternates=tuple(alternates),
        method=str(payload.get("method") or "named"),
        notes=tuple(str(note) for note in notes) if isinstance(notes, list) else (),
    )


def _live_verifier():
    timeout = _float_env("OPENHUNTER_SMTP_TIMEOUT", 5.0)
    port = configured_smtp_port()
    smtp_enabled = os.environ.get("OPENHUNTER_SMTP", "1").lower() not in {"0", "false", "no", "off"}
    resolver = DnsResolver(timeout=timeout)
    prober = LiveSmtpProber(timeout=timeout, host_checker=host_is_public)
    extra = _disposable_file()

    def verify(email: str) -> Verification:
        return verify_email(
            email,
            resolver=resolver,
            prober=prober,
            host_checker=host_is_public,
            disposable_domains=extra,
            smtp_enabled=smtp_enabled,
            timeout=timeout,
            smtp_port=port,
        )

    return verify


def _disposable_file() -> list[str]:
    configured = os.environ.get("OPENHUNTER_DISPOSABLE_FILE")
    if not configured:
        return []
    path = Path(configured).expanduser()
    if not path.is_file():
        return []
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default
