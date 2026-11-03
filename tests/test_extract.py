"""Pure HTML and security.txt extraction. No network."""

from __future__ import annotations

from openhunter.extract import extract_page

TEAM_HTML = """
<html>
<head>
  <title>Ignored title | Marketing site</title>
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "Runpod",
    "employee": [
      {
        "@type": "Person",
        "name": "Ada Lovelace",
        "jobTitle": "Engineer",
        "email": "ada.lovelace@runpod.io"
      }
    ]
  }
  </script>
</head>
<body>
  <a href="mailto:hello@runpod.io">Say hello</a>
  <a href="mailto:grace.hopper@runpod.io">Grace Hopper</a>
  <p>Reach security at security [at] runpod [dot] io</p>
  <a href="https://github.com/runpod/containers">Code</a>
  <a href="https://github.com/orgs/runpod/people">People</a>
  <a href="https://github.com/features">Not an org</a>
  <a href="/company/team">Team</a>
  <a href="https://evil.example/team">Offsite</a>
  <img src="logo@2x.png">
</body>
</html>
"""


def test_extracts_structured_mailto_obfuscated_and_github_orgs() -> None:
    page = extract_page(TEAM_HTML, "https://runpod.io/", "runpod.io")
    by_email = {person.email: person for person in page.people}
    assert set(by_email) == {
        "ada.lovelace@runpod.io",
        "hello@runpod.io",
        "grace.hopper@runpod.io",
        "security@runpod.io",
    }
    ada = by_email["ada.lovelace@runpod.io"]
    assert ada.name == "Ada Lovelace"
    assert ada.role == "Engineer"
    assert ada.source == "website_structured"
    assert ada.confidence == 0.9
    grace = by_email["grace.hopper@runpod.io"]
    assert grace.name == "Grace Hopper"
    assert grace.first_name == "Grace"
    assert grace.source == "website_mailto"
    assert grace.confidence == 0.8
    hello = by_email["hello@runpod.io"]
    assert hello.name is None
    assert hello.is_role is True
    security = by_email["security@runpod.io"]
    assert security.source == "website_text"
    assert security.role == "security"
    assert page.github_orgs == ["runpod"]
    assert page.company_name == "Runpod"
    assert page.follow_links == ["https://runpod.io/company/team"]


def test_security_txt_contact_is_a_role_mailbox() -> None:
    body = "Contact: mailto:security@runpod.io\nContact: https://runpod.io/security\n"
    page = extract_page(body, "https://runpod.io/.well-known/security.txt", "runpod.io")
    assert len(page.people) == 1
    person = page.people[0]
    assert person.email == "security@runpod.io"
    assert person.source == "security_txt"
    assert person.role == "security"
    assert person.confidence == 0.7
