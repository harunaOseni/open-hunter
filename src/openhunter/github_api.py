"""GitHub organization members, public profile emails, and commit authors.

Uses the official REST API only. GitHub noreply addresses are not company
mailboxes, and commits from bots are ignored. An unauthenticated call is
fine until the IP hits the 60-request hourly limit; GITHUB_TOKEN raises that
ceiling. A rate-limit response stops the walk and is reported, with whatever
people were already found.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from urllib.parse import quote

from openhunter.errors import InputError
from openhunter.http_client import USER_AGENT, FetchResult
from openhunter.models import Person, merge_people
from openhunter.names import split_name, strip_accents
from openhunter.net import normalize_domain
from openhunter.roles import is_role_address, role_label

_API = "https://api.github.com"
_MAX_REPOS = 5
_MAX_COMMITS = 15
_MAX_PROFILES = 12
_BOTS = frozenset({"dependabot", "renovate", "github-actions"})
_LOGIN_NAME_NOTE = "Git author string has no family name, so it was not used as pattern evidence."
_PROFILE_NAME_NOTE = "Name taken from the public GitHub profile; the address is from a public commit."


@dataclass(frozen=True)
class GitHubFindings:
    people: list[Person]
    notes: list[str]
    org_login: str | None
    lookup_failed: bool = False


@dataclass(frozen=True)
class CompanyResolution:
    domain: str | None
    org_hints: list[str]
    notes: list[str]
    suggestions: list[str]


class GitHubSource:
    def __init__(self, http: object, token: str | None) -> None:
        self.http = http
        self.token = token.strip() if token else None

    def discover(self, domain: str, org_hints: list[str]) -> GitHubFindings:
        notes: list[str] = []
        attempts: list[str] = []
        slugs = _slug_list(org_hints, domain)
        hinted = {slug.lower() for slug in org_hints}
        org: dict[str, object] | None = None
        failed = False
        for slug in slugs:
            payload, status, detail, failed_request = self._org_payload(slug, attempts)
            failed = failed or failed_request
            if detail and "rate limit" in detail.lower():
                notes.append(detail)
                notes.extend(attempts)
                return GitHubFindings([], notes, None, lookup_failed=True)
            if isinstance(payload, dict) and _accept_org(payload, domain, slug, slug in hinted):
                org = payload
                break
            if isinstance(payload, dict):
                attempts.append(_rejected_org(payload, domain, slug))
        if org is None:
            notes.append(f"No GitHub organization found for {domain}.")
            notes.extend(attempts)
            if not slugs:
                notes.append("No GitHub organization name could be derived from the domain.")
            return GitHubFindings([], notes, None, lookup_failed=failed)
        return self._from_org(org, domain, notes)

    def resolve_company(self, name: str) -> CompanyResolution:
        notes: list[str] = []
        suggestions: list[str] = []
        attempts: list[str] = []
        tried: set[str] = set()
        resolved = self._resolve_slugs(_company_slugs(name), tried, attempts, suggestions)
        if isinstance(resolved, CompanyResolution):
            return resolved
        if any("rate limit" in note.lower() for note in attempts):
            notes.extend(attempts)
            return CompanyResolution(None, [], notes, suggestions)
        resolved = self._resolve_slugs(self._search_logins(name, attempts), tried, attempts, suggestions)
        if isinstance(resolved, CompanyResolution):
            return resolved
        notes.extend(attempts)
        if not any("rate limit" in note.lower() for note in notes):
            notes.append(f"Could not resolve a public website for {name}. Pass a domain instead.")
        return CompanyResolution(None, [], notes, suggestions)

    def _resolve_slugs(
        self,
        slugs: list[str],
        tried: set[str],
        attempts: list[str],
        suggestions: list[str],
    ) -> CompanyResolution | None:
        for slug in slugs:
            if slug.lower() in tried:
                continue
            tried.add(slug.lower())
            payload, _status, detail, _failed = self._org_payload(slug, attempts)
            if detail and "rate limit" in detail.lower():
                attempts.append(detail)
                return None
            if not isinstance(payload, dict):
                continue
            domain = _blog_domain(payload) or _email_domain(_string(payload.get("email")))
            login = _string(payload.get("login")) or slug
            if domain:
                return CompanyResolution(
                    domain=domain,
                    org_hints=[login],
                    notes=["Resolved the company website from the GitHub organization profile."],
                    suggestions=[],
                )
            suggestions.append(login)
            attempts.append(f"GitHub org {login} has no public website or company email.")
        return None

    def _from_org(self, org: dict[str, object], domain: str, notes: list[str]) -> GitHubFindings:
        login = _string(org.get("login")) or ""
        people: list[Person] = []
        org_email = _string(org.get("email"))
        if org_email and org_email.lower().endswith("@" + domain):
            people.append(
                _person(
                    name=_string(org.get("name")) or login,
                    email=org_email.lower(),
                    role="organization",
                    source="github_org",
                    source_url=_string(org.get("html_url")) or f"https://github.com/{login}",
                    confidence=0.8,
                    notes=(),
                )
            )
        members, member_note = self._list(f"{_API}/orgs/{login}/public_members?per_page=100")
        if member_note:
            notes.append(member_note)
            return GitHubFindings(merge_people(people), notes, login)
        member_logins = [
            _string(item.get("login"))
            for item in members
            if isinstance(item, dict) and _string(item.get("login")) and not _is_bot(_string(item.get("login")))
        ]
        repos, repo_note = self._list(
            f"{_API}/orgs/{login}/repos?type=public&sort=pushed&per_page={_MAX_REPOS}"
        )
        if repo_note:
            notes.append(repo_note)
            repos = []
        commit_logins: list[str] = []
        email_logins: dict[str, str] = {}
        for repo in repos:
            if not isinstance(repo, dict) or repo.get("fork") or repo.get("archived"):
                continue
            full_name = _string(repo.get("full_name"))
            if not full_name:
                continue
            commits, commit_note = self._list(f"{_API}/repos/{full_name}/commits?per_page={_MAX_COMMITS}")
            if commit_note:
                notes.append(commit_note)
                break
            for commit in commits:
                person, author_login = _person_from_commit(commit, domain)
                if author_login and not _is_bot(author_login):
                    commit_logins.append(author_login)
                if person is not None:
                    people.append(person)
                    if author_login and person.email:
                        email_logins.setdefault(person.email, author_login)
        profiles = self._profiles(_unique(member_logins + commit_logins)[:_MAX_PROFILES], notes)
        member_set = {item.lower() for item in member_logins if item}
        for member in member_logins:
            if not member:
                continue
            profile = profiles.get(member.lower())
            people.append(_person_from_profile(member, profile, domain, is_member=True))
        for author in commit_logins:
            if author.lower() in member_set:
                continue
            profile = profiles.get(author.lower())
            if profile is None:
                continue
            # A non-member is kept only when a commit already contributed an
            # on-domain address. The profile can still replace a login-shaped name.
            enriched = _person_from_profile(author, profile, domain, is_member=False)
            if enriched.email and enriched.email.endswith("@" + domain):
                people.append(enriched)
        people.extend(_profile_names_for_commits(people, profiles, email_logins))
        return GitHubFindings(_annotate_login_names(merge_people(people)), notes, login or None)

    def _profiles(self, logins: list[str], notes: list[str]) -> dict[str, dict[str, object]]:
        found: dict[str, dict[str, object]] = {}
        for login in logins:
            payload, status, note = self._get_json(f"{_API}/users/{login}")
            if note and "rate limit" in note.lower():
                notes.append(note)
                break
            if status == 200 and isinstance(payload, dict):
                found[login.lower()] = payload
        return found

    def _list(self, url: str) -> tuple[list[object], str | None]:
        payload, status, note = self._get_json(url)
        if note:
            return [], note
        if status == 200 and isinstance(payload, list):
            return payload, None
        return [], None

    def _org_payload(
        self, slug: str, attempts: list[str]
    ) -> tuple[dict[str, object] | None, int, str | None, bool]:
        url = f"{_API}/orgs/{slug}"
        payload, status, detail = self._get_json(url)
        failed = _transport_failure(status, detail)
        if isinstance(payload, dict):
            return payload, status, detail, failed
        if detail and "rate limit" in detail.lower():
            return None, status, detail, True
        attempts.append(f"Tried GitHub organization '{slug}' at {url}: {detail or f'HTTP {status}'}.")
        return None, status, detail, failed

    def _search_logins(self, name: str, attempts: list[str]) -> list[str]:
        query = quote(f"{name} type:org")
        url = f"{_API}/search/users?q={query}&per_page=5"
        payload, status, detail = self._get_json(url)
        if detail and "rate limit" in detail.lower():
            attempts.append(detail)
            return []
        if not isinstance(payload, dict):
            attempts.append(f"Tried GitHub org search for {name!r}: {detail or f'HTTP {status}'}.")
            return []
        logins: list[str] = []
        items = payload.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    login = _string(item.get("login"))
                    if login:
                        logins.append(login)
        if logins:
            attempts.append(f"GitHub org search for {name!r} returned {', '.join(logins)}.")
        else:
            attempts.append(f"GitHub org search for {name!r} returned no organizations.")
        return logins

    def _get_json(self, url: str) -> tuple[object | None, int, str | None]:
        getter = getattr(self.http, "get_text")
        result: FetchResult = getter(url, headers=_headers(self.token), timeout=15)
        headers = {key.lower(): value for key, value in result.headers.items()}
        if result.status in {403, 429} or headers.get("x-ratelimit-remaining") == "0":
            return None, result.status, "GitHub API rate limit reached; set GITHUB_TOKEN for a higher quota."
        if result.status != 200 or not result.text:
            detail = result.error or (f"HTTP {result.status}" if result.status else "no response")
            return None, result.status, detail
        try:
            return json.loads(result.text), result.status, None
        except json.JSONDecodeError:
            return None, result.status, "GitHub returned a response that was not JSON."

def _headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _accept_org(org: dict[str, object], domain: str, slug: str, hinted: bool) -> bool:
    if hinted:
        return True
    if _blog_domain(org) == domain:
        return True
    if _email_domain(_string(org.get("email"))) == domain:
        return True
    login = (_string(org.get("login")) or slug).lower()
    sld = domain.split(".")[0]
    return len(sld) >= 3 and login == sld


def _person_from_commit(commit: object, domain: str) -> tuple[Person | None, str | None]:
    if not isinstance(commit, dict):
        return None, None
    github_user = commit.get("author") if isinstance(commit.get("author"), dict) else {}
    login = _string(github_user.get("login")) if isinstance(github_user, dict) else None
    if _is_bot(login):
        return None, login
    inner = commit.get("commit") if isinstance(commit.get("commit"), dict) else {}
    author = inner.get("author") if isinstance(inner, dict) and isinstance(inner.get("author"), dict) else {}
    email = _string(author.get("email")).lower() if isinstance(author, dict) else ""
    name = _string(author.get("name")) if isinstance(author, dict) else None
    if not email or _is_noreply(email) or not email.endswith("@" + domain):
        return None, login
    source_url = _string(commit.get("html_url")) or ""
    return (
        _person(name or login, email, None, "github_commit", source_url, 0.75, ()),
        login,
    )


def _person_from_profile(
    login: str, profile: dict[str, object] | None, domain: str, *, is_member: bool
) -> Person:
    name = _string(profile.get("name")) if profile else None
    html_url = (_string(profile.get("html_url")) if profile else None) or f"https://github.com/{login}"
    email = _string(profile.get("email")).lower() if profile and _string(profile.get("email")) else ""
    notes: tuple[str, ...] = ()
    if email and (_is_noreply(email) or _is_bot(login)):
        email = ""
    if email and email.endswith("@" + domain):
        return _person(name or login, email, None, "github_profile", html_url, 0.95, notes)
    if email and is_member:
        return _person(
            name or login,
            email,
            None,
            "github_profile",
            html_url,
            0.5,
            ("Public email is not on the company domain.",),
        )
    return _person(name or login, None, None, "github_member" if is_member else "github_profile", html_url, 0.7 if is_member else 0.4, notes)


def _profile_names_for_commits(
    people: list[Person],
    profiles: dict[str, dict[str, object]],
    email_logins: dict[str, str],
) -> list[Person]:
    """Pair a commit mailbox with the author's public profile name.

    The added record is scored below the commit so the commit URL remains the
    evidence for the address. Merge then keeps that source and adopts the name.
    """
    extra: list[Person] = []
    for person in people:
        if not person.email or person.first_name or person.last_name:
            continue
        login = email_logins.get(person.email)
        if not login:
            continue
        profile = profiles.get(login.lower())
        if profile is None:
            continue
        real_name = _string(profile.get("name"))
        if " " not in real_name:
            continue
        html_url = _string(profile.get("html_url")) or f"https://github.com/{login}"
        extra.append(
            _person(real_name, person.email, None, "github_profile", html_url, 0.7, (_PROFILE_NAME_NOTE,))
        )
    return extra


def _annotate_login_names(people: list[Person]) -> list[Person]:
    annotated: list[Person] = []
    for person in people:
        unnamed_commit = (
            person.source == "github_commit"
            and bool(person.email)
            and not (person.first_name and person.last_name)
        )
        if unnamed_commit and _LOGIN_NAME_NOTE not in person.notes:
            annotated.append(replace(person, notes=(*person.notes, _LOGIN_NAME_NOTE)))
        else:
            annotated.append(person)
    return annotated


def _person(
    name: str | None,
    email: str | None,
    role: str | None,
    source: str,
    source_url: str,
    confidence: float,
    notes: tuple[str, ...],
) -> Person:
    # A single-token GitHub login is not a given/family name.
    first, last = split_name(name) if name and " " in name else (None, None)
    normalized = email.lower() if email else None
    role_address = bool(normalized and is_role_address(normalized))
    resolved_role = role or (role_label(normalized) if role_address and normalized else None)
    return Person(
        name=name,
        first_name=first,
        last_name=last,
        role=resolved_role,
        email=normalized,
        source=source,
        source_url=source_url,
        confidence=confidence,
        notes=notes,
        is_role=role_address,
    )


def _blog_domain(org: dict[str, object]) -> str | None:
    blog = _string(org.get("blog"))
    if not blog:
        return None
    candidate = blog if "://" in blog else f"https://{blog}"
    try:
        return normalize_domain(candidate)
    except InputError:
        return None


def _email_domain(email: str) -> str | None:
    if "@" not in email:
        return None
    try:
        return normalize_domain(email.rsplit("@", 1)[1])
    except InputError:
        return None


def _company_slugs(name: str) -> list[str]:
    cleaned = strip_accents(name).lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", cleaned).strip("-")
    slugs: list[str] = []
    if cleaned:
        slugs.append(cleaned)
    for suffix in ("-inc", "-llc", "-ltd", "-corp", "-labs", "-io", "-hq"):
        if cleaned.endswith(suffix) and len(cleaned) - len(suffix) >= 3:
            trimmed = cleaned[: -len(suffix)]
            if trimmed not in slugs:
                slugs.append(trimmed)
    return slugs


def _slug_list(hints: list[str], domain: str) -> list[str]:
    """Domain stem first, then page hints. The stem is never crowded out."""
    slugs: list[str] = []

    def add(value: str) -> None:
        cleaned = value.strip().lower()
        if cleaned and re.fullmatch(r"[a-z0-9_.-]+", cleaned) and cleaned not in slugs:
            slugs.append(cleaned)

    stem = domain.split(".")[0]
    if len(stem) >= 3:
        add(stem)
    for hint in hints:
        add(hint)
    if not slugs:
        return []
    return [slugs[0], *slugs[1:6]]


def _rejected_org(org: dict[str, object], domain: str, slug: str) -> str:
    login = _string(org.get("login")) or slug
    blog = _blog_domain(org) or "none"
    email_domain = _email_domain(_string(org.get("email"))) or "none"
    return (
        f"GitHub organization {login} (from /orgs/{slug}) was not accepted for {domain}: "
        f"blog {blog}, email domain {email_domain}."
    )


def _transport_failure(status: int, detail: str | None) -> bool:
    if status == 0:
        return True
    if not detail:
        return False
    lowered = detail.lower()
    return any(token in lowered for token in ("timeout", "network", "not public", "no response", "redirects"))


def _is_bot(login: str | None) -> bool:
    if not login:
        return False
    lowered = login.lower()
    return lowered.endswith("[bot]") or lowered in _BOTS


def _is_noreply(email: str) -> bool:
    host = email.rsplit("@", 1)[-1].lower()
    return host in {"users.noreply.github.com", "noreply.github.com"}


def _string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _unique(values: list[str | None]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value:
            continue
        key = value.lower()
        if key not in seen:
            seen.add(key)
            found.append(value)
    return found
