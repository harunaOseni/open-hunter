"""Delivery outcomes: recording, xlsx import, weighted patterns, finder exclusions."""

from __future__ import annotations

import pytest

from openhunter.errors import InputError
from openhunter.outcomes import (
    SEED_PATTERNS,
    exclusions_for,
    make_outcome,
    read_outreach_sheet,
    weigh_patterns,
)
from openhunter.patterns import PatternVote
from openhunter.service import OpenHunter
from openhunter.store import Store
from test_service import FakeGitHub, FakeWebsite


def _service(tmp_path):
    return OpenHunter(Store(tmp_path / "db.sqlite"), FakeWebsite([]), FakeGitHub([]), verify=lambda email: None)


def test_make_outcome_normalizes_status_and_splits_name():
    outcome = make_outcome(" Mudit.Garg@Qventus.com ", "Sent", name="Mudit Garg")
    assert outcome.email == "mudit.garg@qventus.com"
    assert outcome.status == "delivered"
    assert (outcome.first_name, outcome.last_name) == ("Mudit", "Garg")
    assert make_outcome("a@b.co", "Bounced").status == "bounced"
    with pytest.raises(InputError):
        make_outcome("a@b.co", "maybe")
    with pytest.raises(InputError):
        make_outcome("not-an-email", "delivered")


def test_domain_supports_several_weighted_patterns():
    outcomes = [
        make_outcome("bmorris@anthropic.com", "delivered", name="Benjamin Morris"),
        make_outcome("royarsan@anthropic.com", "delivered", name="Roy Arsan"),
        make_outcome("boris@anthropic.com", "delivered", name="Boris Cherny"),
        make_outcome("jess.rossman@anthropic.com", "bounced", name="Jess Rossman"),
    ]
    rows = weigh_patterns("anthropic.com", outcomes, seeds={})
    weights = {row.pattern: row.weight for row in rows}
    assert weights["flast"] == weights["firstlast"] == weights["first"] == 1.0
    assert weights["first.last"] < 0


def test_delivered_evidence_outranks_seed_and_public_votes():
    outcomes = [make_outcome("mudit.garg@qventus.com", "delivered", name="Mudit Garg"),
                make_outcome("ian@qventus.com", "delivered", name="Ian Christopher"),
                make_outcome("ian@qventus.com".replace("ian", "kelly"), "bounced", name="Kelly Sheridan")]
    rows = weigh_patterns("qventus.com", outcomes, public_votes=[PatternVote("first_last", 1)])
    order = [row.pattern for row in rows]
    assert order[:2] == ["first.last", "first"] or order[:2] == ["first", "first.last"]
    first = next(row for row in rows if row.pattern == "first")
    assert first.delivered == 1 and first.bounced == 1 and first.seeded
    assert order.index("first_last") > order.index("first.last")


def test_seed_data_matches_todays_results():
    assert SEED_PATTERNS["buildwithfern.com"] == ("first",)
    assert SEED_PATTERNS["midjourney.com"] == ("first",)
    assert SEED_PATTERNS["withmoment.com"] == ("first",)
    assert set(SEED_PATTERNS["qventus.com"]) == {"first.last", "first"}
    assert set(SEED_PATTERNS["anthropic.com"]) == {"flast", "firstlast", "first"}
    assert "handle" in SEED_PATTERNS["lightning.engineering"]


def test_exclusions_are_per_person():
    outcomes = [
        make_outcome("jess.rossman@anthropic.com", "bounced", name="Jess Rossman"),
        make_outcome("jrossman@anthropic.com", "bounced", name="Jess Rossman"),
        make_outcome("lkandola@anthropic.com", "bounced", name="Lovedeep Kandola"),
    ]
    jess = exclusions_for("Jess", "Rossman", "anthropic.com", outcomes)
    assert jess.emails == {"jess.rossman@anthropic.com", "jrossman@anthropic.com"}
    assert jess.patterns == {"first.last", "flast"}
    other = exclusions_for("Sid", "Bidasaria", "anthropic.com", outcomes)
    assert not other.emails and not other.patterns


def test_record_outcome_then_finder_skips_bounced_and_ranks_observed(tmp_path):
    service = _service(tmp_path)
    service.record_outcome("sbidasaria@anthropic.com", "delivered", name="Sid Bidasaria")
    service.record_outcome("jess.rossman@anthropic.com", "bounced", name="Jess Rossman")
    service.record_outcome("jrossman@anthropic.com", "bounced", name="Jess Rossman")
    service.record_outcome("jessrossman@anthropic.com", "bounced", name="Jess Rossman")
    result = service.email_finder("Jess", "Rossman", "anthropic.com")
    emails = [candidate["email"] for candidate in result["candidates"]]
    assert "jrossman@anthropic.com" not in emails
    assert "jess.rossman@anthropic.com" not in emails
    assert "jessrossman@anthropic.com" not in emails
    assert emails[0] == "jess@anthropic.com"
    assert result["weighted_patterns"][0]["pattern"] == "flast"
    assert result["excluded"]["patterns"] == ["first.last", "firstlast", "flast"]


def test_bounce_is_not_overwritten_by_delivered(tmp_path):
    service = _service(tmp_path)
    service.record_outcome("ian_christopher@qventus.com", "bounced", name="Ian Christopher")
    service.record_outcome("ian_christopher@qventus.com", "delivered", name="Ian Christopher")
    rows = service.store.outcomes_for_domain("qventus.com")
    assert rows[0]["status"] == "bounced"


def test_email_pattern_reports_weighted_patterns(tmp_path):
    service = _service(tmp_path)
    service.record_outcome("dylan@withmoment.com", "delivered", name="Dylan Parker")
    result = service.email_pattern("withmoment.com")
    top = result["weighted_patterns"][0]
    assert top["pattern"] == "first" and top["delivered"] == 1 and top["seeded"] is True
    assert top["weight"] == 2.0


def _workbook(path):
    openpyxl = pytest.importorskip("openpyxl")
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Outreach"
    sheet.append([None] * 9)
    sheet.append(["Qventus", "Mudit Garg", "mudit.garg@qventus.com", "CEO", None, "Sent"])
    sheet.append(["Qventus", "Ian Christopher", "ian.christopher@qventus.com", "", None, "Bounced"])
    sheet.append(["Qventus", "Ian Christopher", "ian@qventus.com", "", None, "Sent"])
    sheet.append(["Qventus", "Kelly Sheridan", "kelly@qventus.com", "", None, "Sent"])
    sheet.append(["Qventus", "Kelly Sheridan", "kelly@qventus.com", "", None, "Bounced"])
    sheet.append(["Qventus", "Nobody", "no-address", "", None, "Sent"])
    sheet.append(["Qventus", "Draft Only", "draft@qventus.com", "", None, "Drafted"])
    workbook.save(path)


def test_read_outreach_sheet(tmp_path):
    path = tmp_path / "tracker.xlsx"
    _workbook(path)
    outcomes = {outcome.email: outcome for outcome in read_outreach_sheet(path)}
    assert set(outcomes) == {
        "mudit.garg@qventus.com",
        "ian.christopher@qventus.com",
        "ian@qventus.com",
        "kelly@qventus.com",
    }
    assert outcomes["mudit.garg@qventus.com"].status == "delivered"
    assert outcomes["kelly@qventus.com"].status == "bounced"
    assert outcomes["ian.christopher@qventus.com"].status == "bounced"


def test_import_outcomes_feeds_finder(tmp_path):
    path = tmp_path / "tracker.xlsx"
    _workbook(path)
    service = _service(tmp_path)
    summary = service.import_outcomes(str(path))
    assert summary == {"path": str(path), "sheet": "Outreach", "imported": 4, "delivered": 2, "bounced": 2}
    result = service.email_finder("Kelly", "Sheridan", "qventus.com")
    emails = [candidate["email"] for candidate in result["candidates"]]
    assert "kelly@qventus.com" not in emails
    assert emails[0] == "kelly.sheridan@qventus.com"


def test_import_rejects_missing_sheet(tmp_path):
    path = tmp_path / "tracker.xlsx"
    _workbook(path)
    with pytest.raises(InputError):
        read_outreach_sheet(path, sheet="Nope")


def test_cli_import_and_record(tmp_path, monkeypatch, capsys):
    from openhunter import cli

    path = tmp_path / "tracker.xlsx"
    _workbook(path)
    monkeypatch.setenv("OPENHUNTER_DB", str(tmp_path / "cli.sqlite"))
    assert cli.main(["outcomes", "import", str(path), "--json"]) == 0
    assert '"imported": 4' in capsys.readouterr().out
    assert cli.main(["outcomes", "record", "abhinav@qventus.com", "bounced", "--name", "Abhinav Mittal", "--json"]) == 0
    assert '"status": "bounced"' in capsys.readouterr().out
