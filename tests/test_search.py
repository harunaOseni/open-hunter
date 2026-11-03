"""Web search discovery against a scripted HTTP client."""

from __future__ import annotations

import json

from openhunter.search_web import WebSearchSource
from tests.fakes import PrefixHttp

DDG = """
<html><body>
<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnews.example%2Fstory&amp;rut=1">Story</a>
</body></html>
"""
STORY = "<p>Talk to grace.hopper@runpod.io or other@gmail.com today</p>"


def test_duckduckgo_pages_yield_only_on_domain_addresses() -> None:
    http = PrefixHttp(
        [
            ("https://html.duckduckgo.com/html/", 200, DDG, None),
            ("https://news.example/robots.txt", 200, "User-agent: *\nAllow: /\n", None),
            ("https://news.example/story", 200, STORY, None),
        ]
    )
    found = WebSearchSource(http, host_ok=lambda host: True).discover("runpod.io")
    assert {person.email for person in found.people} == {"grace.hopper@runpod.io"}
    assert found.people[0].source_url == "https://news.example/story"
    assert found.lookup_failed is False
    assert any("DuckDuckGo" in note for note in found.notes)


def test_brave_is_used_when_a_key_is_configured() -> None:
    http = PrefixHttp(
        [
            (
                "https://api.search.brave.com/res/v1/web/search",
                200,
                json.dumps({"web": {"results": [{"url": "https://talks.example/runpod"}]}}),
                {"content-type": "application/json"},
            ),
            ("https://talks.example/robots.txt", 404, "", None),
            ("https://talks.example/runpod", 200, "<p>ada.lovelace@runpod.io</p>", None),
        ]
    )
    found = WebSearchSource(http, brave_key="test-key", host_ok=lambda host: True).discover("runpod.io")
    assert any("api.search.brave.com" in call for call in http.calls)
    assert not any("duckduckgo.com" in call for call in http.calls)
    assert any(person.email == "ada.lovelace@runpod.io" for person in found.people)


def test_search_skips_pages_disallowed_by_robots() -> None:
    http = PrefixHttp(
        [
            ("https://html.duckduckgo.com/html/", 200, '<a href="https://news.example/secret">x</a>', None),
            ("https://news.example/robots.txt", 200, "User-agent: *\nDisallow: /\n", None),
            ("https://news.example/secret", 200, "ada@runpod.io", None),
        ]
    )
    found = WebSearchSource(http, host_ok=lambda host: True).discover("runpod.io")
    assert "https://news.example/secret" not in http.calls
    assert found.people == []
    assert any("robots" in note.lower() for note in found.notes)
