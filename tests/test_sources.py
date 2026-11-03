"""Website and GitHub discovery against a scripted HTTP client."""

from __future__ import annotations

import json

from openhunter.github_api import GitHubSource
from openhunter.website import WebsiteSource
from tests.fakes import PrefixHttp

HOME = """
<html><head>
<script type="application/ld+json">
{"@type":"Organization","name":"Example","employee":[
  {"@type":"Person","name":"Ada Lovelace","jobTitle":"Engineer","email":"ada.lovelace@example.com"}
]}
</script>
</head>
<body>
<a href="/company/team">Team</a>
<a href="https://github.com/acme/widgets">GitHub</a>
</body></html>
"""

ROBOTS_PARTIAL = "User-agent: *\nDisallow: /team\n"
ROBOTS_ALL = "User-agent: *\nDisallow: /\n"


def test_website_respects_robots_and_follows_same_site_team_links() -> None:
    http = PrefixHttp(
        [
            ("https://example.com/robots.txt", 200, ROBOTS_PARTIAL, {"content-type": "text/plain"}),
            ("https://example.com/company/team", 200, "<p>ada@example.com</p>", None),
            ("https://example.com/", 200, HOME, None),
        ]
    )
    found = WebsiteSource(http).discover("example.com")
    assert "https://example.com/team" not in http.calls
    assert "https://example.com/" in http.calls
    assert "https://example.com/company/team" in http.calls
    emails = {person.email for person in found.people}
    assert "ada.lovelace@example.com" in emails
    assert "ada@example.com" in emails
    assert found.github_orgs == ["acme"]
    assert found.company_name == "Example"
    assert len([call for call in http.calls if call != "https://example.com/robots.txt"]) <= 12


def test_website_records_a_note_when_robots_disallows_the_whole_site() -> None:
    http = PrefixHttp(
        [("https://example.com/robots.txt", 200, ROBOTS_ALL, {"content-type": "text/plain"})]
    )
    found = WebsiteSource(http).discover("example.com")
    assert http.calls == ["https://example.com/robots.txt"]
    assert found.people == []
    assert any("robots" in note.lower() for note in found.notes)


ORG = {
    "login": "runpod",
    "name": "Runpod",
    "blog": "https://www.runpod.io",
    "email": "press@runpod.io",
    "html_url": "https://github.com/runpod",
}
MEMBERS = [{"login": "ada", "html_url": "https://github.com/ada"}]
REPOS = [{"name": "containers", "full_name": "runpod/containers", "fork": False, "archived": False}]
COMMITS = [
    {
        "sha": "abc",
        "html_url": "https://github.com/runpod/containers/commit/abc",
        "commit": {"author": {"name": "Grace Hopper", "email": "grace.hopper@runpod.io"}},
        "author": {"login": "grace"},
    },
    {
        "sha": "bot",
        "html_url": "https://github.com/runpod/containers/commit/bot",
        "commit": {
            "author": {
                "name": "dependabot",
                "email": "49699333+dependabot[bot]@users.noreply.github.com",
            }
        },
        "author": {"login": "dependabot[bot]"},
    },
    {
        "sha": "ext",
        "html_url": "https://github.com/runpod/containers/commit/ext",
        "commit": {"author": {"name": "External Person", "email": "external@gmail.com"}},
        "author": {"login": "external"},
    },
    {
        "sha": "dan",
        "html_url": "https://github.com/runpod/containers/commit/dan",
        "commit": {"author": {"name": "danstotts-ops", "email": "dan.stotts@runpod.io"}},
        "author": {"login": "danstotts-ops"},
    },
    {
        "sha": "loginonly",
        "html_url": "https://github.com/runpod/containers/commit/loginonly",
        "commit": {"author": {"name": "loginonly", "email": "login.only@runpod.io"}},
        "author": {"login": "loginonly"},
    },
]
USERS = {
    "ada": {
        "login": "ada",
        "name": "Ada Lovelace",
        "email": "ada.lovelace@runpod.io",
        "company": "@runpod",
        "html_url": "https://github.com/ada",
    },
    "grace": {
        "login": "grace",
        "name": "Grace Hopper",
        "email": None,
        "company": "Runpod",
        "html_url": "https://github.com/grace",
    },
    "external": {
        "login": "external",
        "name": "External Person",
        "email": "external@gmail.com",
        "company": "Elsewhere",
        "html_url": "https://github.com/external",
    },
    "danstotts-ops": {
        "login": "danstotts-ops",
        "name": "Dan Stotts",
        "email": None,
        "company": "Runpod",
        "html_url": "https://github.com/danstotts-ops",
    },
    "loginonly": {
        "login": "loginonly",
        "name": "loginonly",
        "email": None,
        "html_url": "https://github.com/loginonly",
    },
}


def _github_http() -> PrefixHttp:
    return PrefixHttp(
        [
            ("https://api.github.com/orgs/runpod/public_members", 200, json.dumps(MEMBERS), None),
            ("https://api.github.com/orgs/runpod/repos", 200, json.dumps(REPOS), None),
            ("https://api.github.com/orgs/runpod", 200, json.dumps(ORG), None),
            (
                "https://api.github.com/repos/runpod/containers/commits",
                200,
                json.dumps(COMMITS),
                None,
            ),
            ("https://api.github.com/users/ada", 200, json.dumps(USERS["ada"]), None),
            ("https://api.github.com/users/grace", 200, json.dumps(USERS["grace"]), None),
            ("https://api.github.com/users/external", 200, json.dumps(USERS["external"]), None),
            ("https://api.github.com/users/danstotts-ops", 200, json.dumps(USERS["danstotts-ops"]), None),
            ("https://api.github.com/users/loginonly", 200, json.dumps(USERS["loginonly"]), None),
        ]
    )


def test_github_keeps_public_company_emails_and_drops_bots_and_outsiders() -> None:
    http = _github_http()
    found = GitHubSource(http, token=None).discover("runpod.io", org_hints=["runpod"])
    by_email = {person.email: person for person in found.people if person.email}
    assert "grace.hopper@runpod.io" in by_email
    assert "ada.lovelace@runpod.io" in by_email
    assert "press@runpod.io" in by_email
    assert "external@gmail.com" not in by_email
    assert all("noreply.github.com" not in (person.email or "") for person in found.people)
    grace = by_email["grace.hopper@runpod.io"]
    assert grace.source == "github_commit"
    assert grace.confidence == 0.75
    assert grace.source_url.endswith("/commit/abc")
    ada = by_email["ada.lovelace@runpod.io"]
    assert ada.source == "github_profile"
    assert ada.confidence == 0.95
    assert ada.name == "Ada Lovelace"
    press = by_email["press@runpod.io"]
    assert press.source == "github_org"
    assert press.confidence == 0.8
    dan = by_email["dan.stotts@runpod.io"]
    assert dan.name == "Dan Stotts"
    assert dan.first_name == "Dan"
    assert dan.last_name == "Stotts"
    assert dan.source == "github_commit"
    assert dan.confidence == 0.75
    assert dan.source_url.endswith("/commit/dan")
    assert any("public GitHub profile" in note for note in dan.notes)
    assert not any("no family name" in note for note in dan.notes)
    login_only = by_email["login.only@runpod.io"]
    assert login_only.first_name is None
    assert any("no family name" in note for note in login_only.notes)


def test_github_rate_limit_returns_a_note_instead_of_raising() -> None:
    http = PrefixHttp(
        [
            (
                "https://api.github.com/orgs/runpod",
                403,
                json.dumps({"message": "API rate limit exceeded"}),
                {"x-ratelimit-remaining": "0"},
            )
        ]
    )
    found = GitHubSource(http, token=None).discover("runpod.io", org_hints=[])
    assert found.people == []
    assert any("rate limit" in note.lower() for note in found.notes)
    assert not any("/repos" in call for call in http.calls)


def test_domain_stem_is_queried_before_unrelated_github_hints() -> None:
    http = PrefixHttp([("https://api.github.com/orgs/runpod", 200, json.dumps(ORG), None)])
    hints = [f"sponsor{index}" for index in range(6)]
    found = GitHubSource(http, token=None).discover("runpod.io", hints)
    assert http.calls[0].startswith("https://api.github.com/orgs/runpod")
    assert any(person.email == "press@runpod.io" for person in found.people)
    assert not found.lookup_failed


def test_github_transport_failure_names_the_org_it_tried() -> None:
    http = PrefixHttp([("https://api.github.com/orgs/runpod", 0, "", None)])
    found = GitHubSource(http, token=None).discover("runpod.io", org_hints=[])
    text = " ".join(found.notes)
    assert found.people == []
    assert found.lookup_failed is True
    assert "No GitHub organization found for runpod.io" in text
    assert "Tried GitHub organization 'runpod'" in text
    assert "https://api.github.com/orgs/runpod" in text
    assert not any("/repos" in call for call in http.calls)


def test_company_name_uses_org_search_when_the_obvious_slug_is_missing() -> None:
    org = {
        "login": "runpod-inc",
        "name": "Runpod",
        "blog": "https://www.runpod.io",
        "email": None,
        "html_url": "https://github.com/runpod-inc",
    }
    http = PrefixHttp(
        [
            ("https://api.github.com/orgs/runpod-inc", 200, json.dumps(org), None),
            ("https://api.github.com/orgs/runpod", 404, "", None),
            (
                "https://api.github.com/search/users",
                200,
                json.dumps({"items": [{"login": "runpod-inc"}]}),
                None,
            ),
        ]
    )
    resolved = GitHubSource(http, token=None).resolve_company("Runpod")
    assert resolved.domain == "runpod.io"
    assert resolved.org_hints == ["runpod-inc"]
    assert any(call.startswith("https://api.github.com/search/users") for call in http.calls)


def test_unresolved_company_says_what_was_tried() -> None:
    http = PrefixHttp([])
    resolved = GitHubSource(http, token=None).resolve_company("Runpod")
    text = " ".join(resolved.notes)
    assert resolved.domain is None
    assert "Tried GitHub organization 'runpod'" in text
    assert "GitHub org search" in text
    assert "Could not resolve a public website for Runpod" in text


def test_company_name_resolves_through_the_org_website() -> None:
    http = PrefixHttp(
        [("https://api.github.com/orgs/runpod", 200, json.dumps(ORG), None)]
    )
    resolved = GitHubSource(http, token=None).resolve_company("Runpod")
    assert resolved.domain == "runpod.io"
    assert "runpod" in resolved.org_hints
    assert not any("search/users" in call for call in http.calls)


SITEMAP = """<urlset>
<url><loc>https://example.com/press/launch</loc></url>
<url><loc>https://example.com/files/team.pdf</loc></url>
</urlset>"""


def test_sitemap_and_pdf_addresses_are_collected() -> None:
    http = PrefixHttp(
        [
            ("https://example.com/sitemap.xml", 200, SITEMAP, {"content-type": "application/xml"}),
            (
                "https://example.com/press/launch",
                200,
                "<p>Press ada.lovelace@example.com</p><a href='/files/team.pdf'>PDF</a>",
                None,
            ),
            (
                "https://example.com/files/team.pdf",
                200,
                "Team roster grace.hopper@example.com",
                {"content-type": "application/pdf"},
            ),
            ("https://example.com/", 200, "<html></html>", None),
        ]
    )
    found = WebsiteSource(http).discover("example.com")
    emails = {person.email for person in found.people}
    assert "ada.lovelace@example.com" in emails
    assert "grace.hopper@example.com" in emails
    pdf = next(person for person in found.people if person.email == "grace.hopper@example.com")
    assert pdf.source == "website_pdf"
    assert pdf.source_url == "https://example.com/files/team.pdf"


def test_website_tries_www_when_the_apex_does_not_answer() -> None:
    http = PrefixHttp(
        [
            (
                "https://www.example.com/",
                200,
                "<p>ada@example.com</p><a href='https://github.com/acme'>GitHub</a>",
                None,
            ),
            ("https://example.com/", 0, "", None),
        ]
    )
    found = WebsiteSource(http).discover("example.com")
    assert any(person.email == "ada@example.com" for person in found.people)
    assert found.github_orgs == ["acme"]
    assert any("Could not fetch https://example.com/" in note for note in found.notes)
    assert found.lookup_failed is False
