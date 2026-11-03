"""Orchestration: merge, cache, pattern, finder, verifier, leads."""

from __future__ import annotations

from openhunter.github_api import CompanyResolution, GitHubFindings
from openhunter.models import Person
from openhunter.service import OpenHunter
from openhunter.store import Store
from openhunter.verifier import Verification
from openhunter.website import WebsiteFindings


class FakeWebsite:
    def __init__(self, people: list[Person], orgs: list[str] | None = None) -> None:
        self.people = people
        self.orgs = orgs or []
        self.calls: list[str] = []

    def discover(self, domain: str) -> WebsiteFindings:
        self.calls.append(domain)
        return WebsiteFindings(
            people=list(self.people),
            github_orgs=list(self.orgs),
            company_name="Example",
            notes=["site ok"],
        )


class FakeGitHub:
    def __init__(self, people: list[Person]) -> None:
        self.people = people
        self.hints: list[list[str]] = []

    def discover(self, domain: str, org_hints: list[str]) -> GitHubFindings:
        del domain
        self.hints.append(list(org_hints))
        return GitHubFindings(people=list(self.people), notes=["github ok"], org_login="acme")

    def resolve_company(self, name: str) -> CompanyResolution:
        assert name == "Example"
        return CompanyResolution(
            domain="example.com",
            org_hints=["acme"],
            notes=["resolved from GitHub org website"],
            suggestions=[],
        )


def _person(email: str, name: str, role: str | None, source: str, confidence: float) -> Person:
    first, last = name.split(" ", 1)
    return Person(
        name=name,
        first_name=first,
        last_name=last,
        role=role,
        email=email,
        source=source,
        source_url=f"https://example.com/{source}",
        confidence=confidence,
        notes=(),
    )


def test_domain_search_merges_caches_and_infers_before_limiting(tmp_path) -> None:
    website = FakeWebsite(
        [
            _person("ada.lovelace@example.com", "Ada Lovelace", None, "website_mailto", 0.8),
            _person("alan.turing@example.com", "Alan Turing", "Researcher", "website_structured", 0.9),
        ],
        orgs=["acme"],
    )
    github = FakeGitHub(
        [
            _person("ada.lovelace@example.com", "Ada Lovelace", "Engineer", "github_profile", 0.95),
            _person("grace.hopper@example.com", "Grace Hopper", "Admiral", "github_commit", 0.75),
        ]
    )
    service = OpenHunter(Store(tmp_path / "db.sqlite"), website, github, verify=lambda email: _unused(email))
    first = service.domain_search("example.com", limit=1)
    assert first["from_cache"] is False
    assert first["company"] == "Example"
    assert first["truncated"] is True
    assert len(first["people"]) == 1
    assert first["people"][0]["email"] == "ada.lovelace@example.com"
    assert first["people"][0]["role"] == "Engineer"
    assert first["people"][0]["confidence"] == 0.95
    assert first["people"][0]["source"] == "github_profile"
    assert first["pattern"]["pattern"] == "first.last"
    assert first["pattern"]["sample_count"] == 3
    assert first["emails_found"] == 3
    assert github.hints == [["acme"]]
    assert "site ok" in first["notes"] and "github ok" in first["notes"]

    second = service.domain_search("example.com", limit=10)
    assert second["from_cache"] is True
    assert len(second["people"]) == 3
    assert website.calls == ["example.com"]


def test_pattern_and_finder_reuse_discovery(tmp_path) -> None:
    website = FakeWebsite(
        [
            _person("ada.lovelace@example.com", "Ada Lovelace", "Engineer", "website_structured", 0.9),
            _person("grace.hopper@example.com", "Grace Hopper", "Admiral", "website_structured", 0.9),
        ]
    )
    service = OpenHunter(
        Store(tmp_path / "db.sqlite"),
        website,
        FakeGitHub([]),
        verify=lambda email: _unused(email),
    )
    pattern = service.email_pattern("example.com")
    assert pattern["pattern"] == "first.last"
    assert pattern["from_cache"] is False
    found = service.email_finder("Grace", "Hopper", "example.com")
    assert found["candidates"][0]["email"] == "grace.hopper@example.com"
    assert found["pattern"]["pattern"] == "first.last"
    assert website.calls == ["example.com"]


def test_company_query_uses_the_resolved_domain(tmp_path) -> None:
    website = FakeWebsite([])
    service = OpenHunter(
        Store(tmp_path / "db.sqlite"),
        website,
        FakeGitHub([]),
        verify=lambda email: _unused(email),
    )
    result = service.domain_search("Example")
    assert result["domain"] == "example.com"
    assert website.calls == ["example.com"]


def test_verifier_results_are_cached(tmp_path) -> None:
    calls = {"n": 0}

    def verify(email: str) -> Verification:
        calls["n"] += 1
        return Verification(
            email=email,
            status="unknown",
            score=40,
            syntax_ok=True,
            is_disposable=False,
            is_role=False,
            mx_hosts=("mx.example.com",),
            smtp_code=None,
            smtp_error="timeout",
            catch_all=None,
            notes=("outbound port 25 was unreachable",),
        )

    service = OpenHunter(Store(tmp_path / "db.sqlite"), FakeWebsite([]), FakeGitHub([]), verify=verify)
    first = service.email_verifier("Ada@Example.com")
    second = service.email_verifier("ada@example.com")
    assert calls["n"] == 1
    assert first["from_cache"] is False
    assert second["from_cache"] is True
    assert second["status"] == "unknown"
    assert second["email"] == "ada@example.com"


def test_leads_round_trip_through_the_service(tmp_path) -> None:
    service = OpenHunter(
        Store(tmp_path / "db.sqlite"),
        FakeWebsite([]),
        FakeGitHub([]),
        verify=lambda email: _unused(email),
    )
    saved = service.save_lead(
        email="ada@example.com",
        name="Ada Lovelace",
        role="Engineer",
        domain="example.com",
        source_url="https://example.com/team",
        confidence=0.9,
        notes="met at a meetup",
    )
    assert saved["first_name"] == "Ada"
    listed = service.list_leads(domain="example.com")
    assert listed["count"] == 1
    destination = tmp_path / "leads.csv"
    exported = service.export_leads(str(destination))
    assert exported["count"] == 1
    assert destination.read_text(encoding="utf-8").count("ada@example.com") == 1


def _unused(email: str) -> Verification:
    raise AssertionError(email)
